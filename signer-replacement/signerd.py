#!/usr/bin/python

import fcntl
import logging
import subprocess
import socket
import sys
import systemd.daemon
import systemd.journal
import sqlite3
import time

ODS_SE_MAXLINE = 1024  # from ODS common/config.h
ODS_DB_PATH = '/var/opendnssec/kasp.db'
ODS_DB_LOCK_PATH = '/var/opendnssec/kasp.db.our_lock'

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


#logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger('root')
log.addHandler(systemd.journal.JournalHandler())
log.setLevel(level=logging.DEBUG)

fds = systemd.daemon.listen_fds()
assert len(fds) == 1

sck = socket.fromfd(fds[0], socket.AF_UNIX, socket.SOCK_STREAM)

conn, addr = sck.accept()
log.debug('accepted new connection %s', repr(conn))

#time.sleep(20)

# this implements cmdhandler_handle_cmd() logic
cmd = conn.recv(ODS_SE_MAXLINE)
cmd = cmd.strip()
log.info(cmd)

if not cmd.startswith('update '):
    conn.send('Command "%s" is not supported by IPA, ignoring\n' % cmd)
    sys.exit(0)

log.info('processing command: "%s"', cmd)
zone = cmd[7:].strip()

# Reply & close connection early. This is necessary to let Enforcer to unlock
# the DB.
conn.send('Request queued\n')
conn.shutdown(socket.SHUT_RDWR)

# Open DB directly and read key timestamps etc.
with ods_db_lock():
    #log.info(ksmutil(['key', 'list', '-v']))
    db = sqlite3.connect(ODS_DB_PATH)

log.info('Update terminated !!!')
