#!/usr/bin/python

from datetime import datetime
import dns.dnssec

import logging
import os
import subprocess
import sys
import systemd.journal
import sqlite3

from ipalib import api
from ipapython.dn import DN
from ipapython.ipa_log_manager import root_logger, standard_logging_setup
from ipapython import ipaldap
from ipapython import ipautil
from ipaserver.plugins.ldap2 import ldap2
from ipaplatform import paths

DAEMONNAME = 'ipa-ods-exporter'
PRINCIPAL = None  # not initialized yet
CONFDIR = '/etc/ipa'
WORKDIR = os.path.join(paths.OPENDNSSEC_VAR_DIR, 'tmp')
KEYTAB_FB = paths.IPA_ODS_EXPORTER_KEYTAB

def sql2ldap_time(sql_time):
    dt = datetime.strptime(sql_time, "%Y-%m-%d %H:%M:%S")
    return "%sZ" % dt.strftime("%Y%m%d%H%M%S")

def sql2ldap_times(row):
    row2key_map = {'generate': 'Created',
                   'publish': 'Publish',
                   'active': 'Activate',
                   'retire': 'Inactive',
                   'dead': 'Delete'}
    times = {}
    for column, key in row2key_map.iteritems():
        if row[column] is not None:
            times[key] = sql2ldap_time(row[column])
    return times

def sql2ldap_algorithm(sql_algorithm):
    return {"Algorithm": dns.dnssec.algorithm_to_text(sql_algorithm)}


logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger('root')
log.addHandler(systemd.journal.JournalHandler())

db = sqlite3.connect('/var/opendnssec/kasp.db', isolation_level="EXCLUSIVE")
db.row_factory = sqlite3.Row
db.execute('BEGIN')

# ODS stores zone name without trailing period
zone_name = sys.argv[1]
if len(zone_name) > 1 and zone_name[-1] == '.':
    zone_name = zone_name[:-1]

# get zone ID
cur = db.execute("SELECT id FROM zones WHERE LOWER(name)=LOWER(?)", (zone_name,))
rows = cur.fetchall()
assert len(rows) == 1, "exactly one DNS zone should exist in ODS DB"
zoneid = rows[0][0]

# get all keys for given zone ID
cur = db.execute("SELECT kp.HSMkey_id, kp.generate, kp.algorithm, dnsk.publish, dnsk.active, dnsk.retire, dnsk.dead, dnsk.keytype "
                 "FROM keypairs AS kp JOIN dnsseckeys AS dnsk ON kp.id = dnsk.id "
                 "WHERE dnsk.zone_id = ?", (zoneid,))

# connect to LDAP

# IPA framework initialization
api.bootstrap()
api.finalize()

# Kerberos initialization
PRINCIPAL = str('%s/%s' % (DAEMONNAME, api.env.host))
log.debug('Kerberos principal: %s', PRINCIPAL)
ipautil.kinit_hostprincipal(KEYTAB_FB, WORKDIR, PRINCIPAL)

# LDAP initialization
basedn = DN(api.env.container_dns, api.env.basedn)



ldap = api.Backend[ldap2]
ldap.connect(ccache="%s/ccache" % WORKDIR)

ldap_zone_filter = ldap.make_filter_from_attr("idnsname", [zone_name, "%s." % zone_name])
log.debug('LDAP search filter: "%s"', ldap_zone_filter)
ldap_zone = ldap.find_entries(filter=ldap_zone_filter)
assert len(ldap_zone) == 1
print ldap_zone

print ldap.get_entry(DN('idnsname=ipa.example.,cn=dns,dc=ipa,dc=example'))

print ldap.conn.conn

sys.exit(0)

for row in cur:
    ldap = {}
    ldap.update(sql2ldap_times(row))
    ldap.update(sql2ldap_algorithm(row['algorithm']))
    print ldap
