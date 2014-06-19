#!/usr/bin/python

from datetime import datetime
import dns.dnssec
import fcntl
import logging
import subprocess
import socket
import sys
import systemd.daemon
import systemd.journal
import sqlite3
import time

import ipalib
from ipapython.dn import DN
from ipapython.ipa_log_manager import root_logger, standard_logging_setup
from ipapython import ipaldap
from ipapython import ipautil
from ipaserver.plugins.ldap2 import ldap2

DAEMONNAME = 'ipadnssecd'
PRINCIPAL = None  # not initialized yet
CONFDIR = '/etc/ipa'
WORKDIR = '/var/opendnssec/tmp'
KEYTAB_FB = '%s/%s.keytab' % (CONFDIR, DAEMONNAME)

ODS_SE_MAXLINE = 1024  # from ODS common/config.h
ODS_DB_PATH = '/var/opendnssec/kasp.db'
ODS_DB_LOCK_PATH = '/var/opendnssec/kasp.db.our_lock'

def sql2datetime(sql_time):
    return datetime.strptime(sql_time, "%Y-%m-%d %H:%M:%S")

def datetime2ldap(dt):
    return "%sZ" % dt.strftime(ipalib.constants.LDAP_GENERALIZED_TIME_FORMAT)

def sql2datetimes(row):
    row2key_map = {'generate': 'idnsSecKeyCreated',
                   'publish': 'idnsSecKeyPublish',
                   'active': 'idnsSecKeyActivate',
                   'retire': 'idnsSecKeyInactive',
                   'dead': 'idnsSecKeyDelete'}
    times = {}
    for column, key in row2key_map.iteritems():
        if row[column] is not None:
            times[key] = sql2datetime(row[column])
    return times

def sql2ldap_algorithm(sql_algorithm):
    return {"idnsSecAlgorithm": dns.dnssec.algorithm_to_text(sql_algorithm)}

def ksmutil(params):
    """Call ods-ksmutil with given parameters and return stdout + stderr.

    Raises CalledProcessError if returncode != 0.
    """

    global log

    cmd = ['ods-ksmutil'] + params
    log.debug('Executing: %s', cmd)
    ksmutil = subprocess.Popen(
        cmd, close_fds=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)
    stdout, ignore = ksmutil.communicate()
    if ksmutil.returncode != 0:
        ex = subprocess.CalledProcessError(ksmutil.returncode, cmd, stdout)
        log.exception(ex)
        log.error("Command output: %s", stdout)
        raise ex
    return stdout

class ods_db_lock(object):
    def __enter__(self):
        self.f = open(ODS_DB_LOCK_PATH, 'w')
        fcntl.lockf(self.f, fcntl.LOCK_EX)

    def __exit__(self, *args):
        fcntl.lockf(self.f, fcntl.LOCK_UN)
        self.f.close()

def get_ldap_zone(ldap, dns_base, name):
    zone_names = ["%s." % name, name]

    # find zone object: name can optionally end with period
    ldap_zone = None
    for zone_name in zone_names:
        zone_base = DN("idnsname=%s" % zone_name, dns_base)
        try:
            ldap_zone = ldap.get_entry(dn=zone_base,
                                       attrs_list=["idnsname"])
            break
        except ipalib.errors.NotFound:
            continue

    assert ldap_zone is not None, 'DNS zone "%s" should exist in LDAP' % name

    return ldap_zone

def get_ldap_keys_dn(zone_dn):
    """Container DN"""
    return DN("cn=keys", zone_dn)

def get_ldap_keys(ldap, zone_dn):
    """Keys objects"""
    # find zone object: name can optionally end with period
    keys_dn = get_ldap_keys_dn(zone_dn)
    ldap_filter = ldap.make_filter_from_attr('objectClass', 'idnsSecKey')
    ldap.conn.deref = 3
    ldap_keys = ldap.get_entries(base_dn=keys_dn, filter=ldap_filter)

    return ldap_keys

def get_ods_keys(zone_name):
    # Open DB directly and read key timestamps etc.
    with ods_db_lock():
        db = sqlite3.connect(ODS_DB_PATH, isolation_level="EXCLUSIVE")
        db.row_factory = sqlite3.Row
        db.execute('BEGIN')

        # get zone ID
        cur = db.execute("SELECT id FROM zones WHERE LOWER(name)=LOWER(?)",
                         (zone_name,))
        rows = cur.fetchall()
        assert len(rows) == 1, "exactly one DNS zone should exist in ODS DB"
        zone_id = rows[0][0]

        # get all keys for given zone ID
        cur = db.execute("SELECT kp.HSMkey_id, kp.generate, kp.algorithm, dnsk.publish, dnsk.active, dnsk.retire, dnsk.dead, dnsk.keytype "
                 "FROM keypairs AS kp JOIN dnsseckeys AS dnsk ON kp.id = dnsk.id "
                 "WHERE dnsk.zone_id = ?", (zone_id,))
        keys = {}
        for row in cur:
            key_data = sql2datetimes(row)
            if 'idnsSecKeyDelete' in key_data \
                and key_data['idnsSecKeyDelete'] > datetime.now():
                    continue  # ignore deleted keys

            key_data.update(sql2ldap_algorithm(row['algorithm']))
            key_id = "%s" % (row['HSMkey_id'])
            keys[key_id] = key_data

        return keys


log = logging.getLogger('root')
log.addHandler(systemd.journal.JournalHandler())
log.setLevel(level=logging.DEBUG)

fds = systemd.daemon.listen_fds()
assert len(fds) == 1

sck = socket.fromfd(fds[0], socket.AF_UNIX, socket.SOCK_STREAM)

conn, addr = sck.accept()
log.debug('accepted new connection %s', repr(conn))

# this implements cmdhandler_handle_cmd() logic
cmd = conn.recv(ODS_SE_MAXLINE)
cmd = cmd.strip()
log.info(cmd)

if not cmd.startswith('update '):
    conn.send('Command "%s" is not supported by IPA, ignoring\n' % cmd)
    sys.exit(0)

log.info('processing command: "%s"', cmd)

# Reply & close connection early. This is necessary to let Enforcer to unlock
# the DB.
conn.send('Request queued\n')
conn.shutdown(socket.SHUT_RDWR)

# ODS stores zone name without trailing period
zone_name = cmd[7:].strip()
if len(zone_name) > 1 and zone_name[-1] == '.':
    zone_name = zone_name[:-1]

ods_keys = get_ods_keys(zone_name)
ods_keys_id = set(ods_keys.keys())

# connect to LDAP

# IPA framework initialization
ipalib.api.bootstrap()
ipalib.api.finalize()

# Kerberos initialization
PRINCIPAL = str('%s/%s' % (DAEMONNAME, ipalib.api.env.host))
log.debug('Kerberos principal: %s', PRINCIPAL)
ipautil.kinit_hostprincipal(KEYTAB_FB, WORKDIR, PRINCIPAL)

# LDAP initialization
dns_dn = DN(ipalib.api.env.container_dns, ipalib.api.env.basedn)

ldap = ipalib.api.Backend[ldap2]
# fixme
ldap.connect(ccache="%s/ccache" % WORKDIR)

ldap_zone = get_ldap_zone(ldap, dns_dn, zone_name)
zone_dn = ldap_zone.dn

keys_dn = get_ldap_keys_dn(zone_dn)
try:
    ldap_keys = get_ldap_keys(ldap, zone_dn)
except ipalib.errors.NotFound:
    # cn=keys container does not exist, create it
    ldap_keys = []
    ldap_keys_container = ldap.make_entry(keys_dn,
                                          objectClass=['nsContainer'])
    try:
        ldap.add_entry(ldap_keys_container)
    except ipalib.errors.DuplicateEntry:
        # ldap.get_entries() do not distinguish non-existent base DN
        # from empty result set so addition can fail because container
        # itself exists already
        pass

ldap_keys_dict = {}
for ldap_key in ldap_keys:
    cn = ldap_key['cn'][0]
    ldap_keys_dict[cn] = ldap_key

ldap_keys = ldap_keys_dict  # shorthand
ldap_keys_id = set(ldap_keys.keys())

new_keys_id = ods_keys_id - ldap_keys_id
log.info('new keys from ODS: %s', new_keys_id)
for key_id in new_keys_id:
    cn = "cn=%s" % key_id
    key_dn = DN(cn, keys_dn)
    log.debug('adding key "%s" to LDAP', key_dn)
    ldap_key = ldap.make_entry(key_dn,
                               objectClass=['idnsSecKey'], idnsSecKeyRef='cn=FIXME', **ods_keys[key_id])
    ldap.add_entry(ldap_key)

deleted_keys_id = ldap_keys_id - ods_keys_id
log.info('deleted keys in LDAP: %s', deleted_keys_id)
for key_id in deleted_keys_id:
    cn = "cn=%s" % key_id
    key_dn = DN(cn, keys_dn)
    log.debug('deleting key "%s" from LDAP', key_dn)
    ldap.delete_entry(key_dn)

update_keys_id = ldap_keys_id.intersection(ods_keys_id)
log.info('keys in LDAP & ODS: %s', update_keys_id)
for key_id in update_keys_id:
    ldap_key = ldap_keys[key_id]
    ods_key = ods_keys[key_id]
    log.debug('updating key "%s" in LDAP', ldap_key.dn)
    ldap_key.update(ods_key)
    try:
        ldap.update_entry(ldap_key)
    except ipalib.errors.EmptyModlist:
        continue

