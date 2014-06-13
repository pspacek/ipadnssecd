import fcntl

class ods_db_lock(object):
    def __init__(self):
        self.our_lock = '/var/opendnssec/kasp.db.our_lock'

    def __enter__(self):
        self.f = open(self.our_lock, 'w')
        fcntl.lockf(self.f, fcntl.LOCK_EX)

    def __exit__(self):
        fcntl.lockf(self.f, fcntl.LOCK_UN)
        self.f.close()
