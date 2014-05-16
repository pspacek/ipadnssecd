#!/usr/bin/python

import sys
import ldap
import ldapurl
import logging
import signal
import time

from keysyncer import KeySyncer

# Shutdown handler
def commenceShutdown(signum, stack):
    # Declare the needed global variables
    global watcher_running, ldap_connection, log
    log.info('Shutting down!')

    # We are no longer running
    watcher_running = False

    # Tear down the server connection
    if ldap_connection:
        ldap_connection.close_db()
        del ldap_connection

    # Shutdown
    sys.exit(0)

# Time to actually begin execution
log_format = '%(name)-16s %(levelname)-8s %(message)s'
logging.basicConfig(level=logging.DEBUG, format=log_format)
log = logging.getLogger("app")

# Global state
watcher_running = True
ldap_connection = False

# Install our signal handlers
signal.signal(signal.SIGTERM, commenceShutdown)
signal.signal(signal.SIGINT, commenceShutdown)

try:
    ldap_url = ldapurl.LDAPUrl(sys.argv[1])
except IndexError, e:
    print 'Usage:'
    print sys.argv[0], '<LDAP URL> <pathname of database>'
    print sys.argv[0], '\'ldap://127.0.0.1/cn=users,dc=test'\
                       '?*'\
                       '?sub'\
                       '?(objectClass=*)'\
                       '?bindname=uid=admin%2ccn=users%2cdc=test,'\
                       'X-BINDPW=password\''
    sys.exit(1)
except ValueError, e:
    print 'Error parsing command-line arguments:', str(e)
    sys.exit(1)

while watcher_running:
    # Prepare the LDAP server connection (triggers the connection as well)
    ldap_connection = KeySyncer(ldap_url.initializeUrl())

    log.info('Connecting to LDAP server now...')
    # Now we login to the LDAP server
    try:
        ldap_connection.simple_bind_s(ldap_url.who, ldap_url.cred)
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
        ldap_url.dn or '',
        ldap_url.scope or ldap.SCOPE_SUBTREE,
        mode='refreshAndPersist',
        attrlist=ldap_url.attrs,
        filterstr=ldap_url.filterstr or '(objectClass=*)'
    )

    try:
        while ldap_connection.syncrepl_poll(all=1, msgid=ldap_search):
            pass
    except KeyboardInterrupt:
        # User asked to exit
        commenceShutdown()
        pass
    except Exception, e:
        # Handle any exception
        if watcher_running:
            log.error('Encountered a problem, going to retry. Error:')
            log.exception(e)
            time.sleep(5)
        pass
