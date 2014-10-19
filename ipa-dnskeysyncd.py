#!/usr/bin/python

import sys
import ldap
import ldapurl
import logging
import os
import signal
import systemd.journal
import time

from ipalib import api
from ipapython.dn import DN
from ipapython.ipa_log_manager import root_logger, standard_logging_setup
from ipapython import ipaldap
from ipapython import ipautil
from ipaserver.plugins.ldap2 import ldap2
from ipaplatform.paths import paths

from keysyncer import KeySyncer

DAEMONNAME = 'ipa-dnskeysyncd'
PRINCIPAL = None  # not initialized yet
WORKDIR = '/tmp' # private temp
KEYTAB_FB = paths.IPA_DNSKEYSYNCD_KEYTAB

# Shutdown handler
def commenceShutdown(signum, stack):
    # Declare the needed global variables
    global watcher_running, ldap_connection, log
    log.info('Signal %s received: Shutting down!', signum)

    # We are no longer running
    watcher_running = False

    # Tear down the server connection
    if ldap_connection:
        ldap_connection.close_db()
        del ldap_connection

    # Shutdown
    sys.exit(0)


os.umask(007)

# Global state
watcher_running = True
ldap_connection = False

# Signal handlers
signal.signal(signal.SIGTERM, commenceShutdown)
signal.signal(signal.SIGINT, commenceShutdown)

# IPA framework initialization
api.bootstrap()
api.finalize()
standard_logging_setup(verbose=True, debug=api.env.debug)
log = root_logger
#log.addHandler(systemd.journal.JournalHandler())

# Kerberos initialization
PRINCIPAL = str('%s/%s' % (DAEMONNAME, api.env.host))
log.debug('Kerberos principal: %s', PRINCIPAL)
ipautil.kinit_hostprincipal(KEYTAB_FB, WORKDIR, PRINCIPAL)

# LDAP initialization
basedn = DN(api.env.container_dns, api.env.basedn)
ldap_url = ldapurl.LDAPUrl(api.env.ldap_uri)
ldap_url.dn = str(basedn)
ldap_url.scope = ldapurl.LDAP_SCOPE_SUBTREE
ldap_url.filterstr = '(|(objectClass=idnsZone)(objectClass=idnsSecKey))'
log.debug('LDAP URL: %s', ldap_url.unparse())

# Real work
while watcher_running:
    # Prepare the LDAP server connection (triggers the connection as well)
    ldap_connection = KeySyncer(ldap_url.initializeUrl(), ipa_api=api)

    # Now we login to the LDAP server
    try:
        log.info('LDAP bind...')
        ldap_connection.sasl_interactive_bind_s("", ipaldap.SASL_GSSAPI)
    except ldap.INVALID_CREDENTIALS, e:
        log.exception('Login to LDAP server failed: %s', e)
        sys.exit(1)
    except ldap.SERVER_DOWN, e:
        log.exception('LDAP server is down, going to retry: %s', e)
        time.sleep(5)
        continue

    # Commence the syncing
    log.info('Commencing sync process')
    ldap_search = ldap_connection.syncrepl_search(
        ldap_url.dn,
        ldap_url.scope,
        mode='refreshAndPersist',
        attrlist=ldap_url.attrs,
        filterstr=ldap_url.filterstr
    )

    while ldap_connection.syncrepl_poll(all=1, msgid=ldap_search):
        pass