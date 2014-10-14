#!/usr/bin/python

import binascii
from datetime import datetime
import dns.dnssec
import fcntl
import logging
import os
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
from ipaplatform.paths import paths

from abshsm import sync_pkcs11_metadata
from ldaphsm import LDAPHSM
from localhsm import LocalHSM
import ipapkcs11

DAEMONNAME = 'ipa-ods-exporter'
PRINCIPAL = None  # not initialized yet
WORKDIR = os.path.join(paths.OPENDNSSEC_VAR_DIR ,'tmp')
KEYTAB_FB = paths.IPA_ODS_EXPORTER_KEYTAB

ODS_SE_MAXLINE = 1024  # from ODS common/config.h
ODS_DB_PATH = '/var/opendnssec/kasp.db'
ODS_DB_LOCK_PATH = '/var/opendnssec/kasp.db.our_lock'

# DNSKEY flag constants
dnskey_flag_by_value = {
    0x0001: 'SEP',
    0x0080: 'REVOKE',
    0x0100: 'ZONE'
}

def dnskey_flags_to_text_set(flags):
    """Convert a DNSKEY flags value to set texts
    @rtype: set([string])"""

    flags_set = set()
    mask = 0x1
    while mask <= 0x8000:
        if flags & mask:
            text = dnskey_flag_by_value.get(mask)
            if not text:
                text = hex(mask)
            flags_set.add(text)
        mask <<= 1
    return flags_set

def datetime2ldap(dt):
    return dt.strftime(ipalib.constants.LDAP_GENERALIZED_TIME_FORMAT)

def sql2datetime(sql_time):
    return datetime.strptime(sql_time, "%Y-%m-%d %H:%M:%S")

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

def sql2ldap_flags(sql_flags):
    dns_flags = dnskey_flags_to_text_set(sql_flags)
    ldap_flags = {}
    for flag in dns_flags:
        attr = 'idnsSecKey%s' % flag
        ldap_flags[attr] = 'TRUE'
    return ldap_flags

def sql2ldap_keyid(sql_keyid):
    assert len(sql_keyid) % 2 == 0
    assert len(sql_keyid) > 0
    # TODO: this is huge hack. BIND has some problems with % notation in URIs.
    # Workaround: OpenDNSSEC uses same value for ID also for label (but in hex).
    uri = "pkcs11:object=%s" % sql_keyid
    #uri += '%'.join(sql_keyid[i:i+2] for i in range(0, len(sql_keyid), 2))
    return {"idnsSecKeyRef": uri}

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
    keys_dn = get_ldap_keys_dn(zone_dn)
    ldap_filter = ldap.make_filter_from_attr('objectClass', 'idnsSecKey')
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

            key_data.update(sql2ldap_flags(row['keytype']))
            log.debug("%s", key_data)
            assert key_data.get('idnsSecKeyZONE', None) == 'TRUE', \
                    'unexpected key type 0x%x' % row['keytype']
            if key_data.get('idnsSecKeySEP', 'FALSE') == 'TRUE':
                key_type = 'KSK'
            else:
                key_type = 'ZSK'

            key_data.update(sql2ldap_algorithm(row['algorithm']))
            key_id = "%s-%s-%s" % (key_type,
                                   datetime2ldap(key_data['idnsSecKeyCreated']),
                                   row['HSMkey_id'])

            key_data.update(sql2ldap_keyid(row['HSMkey_id']))
            keys[key_id] = key_data

        return keys

def ldap2master_replica_keys_sync(log, ldaphsm, localhsm):
    """LDAP=>master's local HSM replica key synchronization"""
    # import new replica keys from LDAP
    new_replica_keys = set(ldaphsm.replica_pubkeys.keys()) \
            - set(localhsm.replica_pubkeys.keys())
    log.info("new replica keys in LDAP: %s", hex_set(new_replica_keys))
    for key_id in new_replica_keys:
        new_key = ldaphsm.replica_pubkeys[key_id]
        localhsm.p11.import_public_key(label=new_key.single_value['ipk11label'],
                id=new_key.single_value['ipk11id'],
                data=new_key.single_value['ipapublickey'], cka_wrap=True)

    # set CKA_WRAP = FALSE for all replica keys removed from LDAP
    removed_replica_keys = set(localhsm.replica_pubkeys.keys()) \
            - set(ldaphsm.replica_pubkeys.keys())
    log.info("obsolete replica keys in local HSM: %s",
            hex_set(removed_replica_keys))
    for key_id in removed_replica_keys:
        localhsm.replica_pubkeys[key_id]['ipk11wrap'] = False

    # synchronize replica key attributes from LDAP to local HSM
    existing_replica_keys = set(localhsm.replica_pubkeys.keys()).intersection(
            set(ldaphsm.replica_pubkeys.keys()))
    log.info("replica keys in local HSM & LDAP: %s",
            hex_set(existing_replica_keys))
    for key_id in existing_replica_keys:
        sync_pkcs11_metadata(ldaphsm.replica_pubkeys[key_id],
                localhsm.replica_pubkeys[key_id])

def hex_set(s):
    out = set()
    for i in s:
        out.add(binascii.hexlify(i))
    return out


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
conn.close()

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
log.debug('Got TGT')

# LDAP initialization
dns_dn = DN(ipalib.api.env.container_dns, ipalib.api.env.basedn)

ldap = ipalib.api.Backend[ldap2]
# fixme
log.debug('Connecting to LDAP')
ldap.connect(ccache="%s/ccache" % WORKDIR)
log.debug('Connected')


### DNSSEC master: key synchronization
ldaphsm = LDAPHSM(log, ldap, DN("cn=keys", "cn=sec", dns_dn))
log.debug("replica pub keys in LDAP: %s", hex_set(ldaphsm.replica_pubkeys))
localhsm = LocalHSM('/usr/lib64/pkcs11/libsofthsm2.so', 0, open('/var/lib/ipa/dnssec/softhsm_pin').read())
log.debug("replica pub keys in SoftHSM: %s", hex_set(localhsm.replica_pubkeys))

ldap2master_replica_keys_sync(log, ldaphsm, localhsm)

## master key -> LDAP synchronization
# export new master keys to LDAP
new_master_keys = set(localhsm.master_keys.keys()) \
        - set(ldaphsm.master_keys.keys())
log.info("master keys in local HSM: %s", hex_set(localhsm.master_keys.keys()))
log.info("master keys in LDAP HSM: %s", hex_set(ldaphsm.master_keys.keys()))
log.info("new master keys in local HSM: %s", hex_set(new_master_keys))
for mkey_id in new_master_keys:
    mkey = localhsm.master_keys[mkey_id]
    ldaphsm.import_keys([(mkey, ipapkcs11.KEY_CLASS_SECRET_KEY)])

sys.exit(0)

# set CKA_WRAP = FALSE for all replica keys removed from LDAP
removed_replica_keys = set(localhsm.replica_pubkeys.keys()) \
        - set(ldaphsm.replica_pubkeys.keys())
log.info("obsolete replica keys in local HSM: %s", hex_set(removed_replica_keys))
for key_id in removed_replica_keys:
    localhsm.replica_pubkeys[key_id]['ipk11wrap'] = False

# synchronize replica key attributes from LDAP to local HSM
existing_replica_keys = set(localhsm.replica_pubkeys.keys()).intersection(
        set(ldaphsm.replica_pubkeys.keys()))
log.info("replica keys in local HSM & LDAP: %s", hex_set(existing_replica_keys))
for key_id in existing_replica_keys:
    sync_pkcs11_metadata(ldaphsm.replica_pubkeys[key_id],
            localhsm.replica_pubkeys[key_id])






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
        # ldap.get_entries() does not distinguish non-existent base DN
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
                               objectClass=['idnsSecKey'],
                               **ods_keys[key_id])
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

