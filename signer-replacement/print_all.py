#!/usr/bin/python

import logging
import subprocess
import sys
import systemd.journal

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


logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger('root')
log.addHandler(systemd.journal.JournalHandler())
log.info(sys.argv)

zonelist = ksmutil(['zone', 'list'])
log.info(zonelist)

keylist = ksmutil(['key', 'list', '-v'])
log.info(keylist)

