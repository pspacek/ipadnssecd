#!/usr/bin/python

from datetime import datetime
import dns.name
import errno
import os
import logging
import shutil
import stat
import subprocess

from ipalib import api
import ipalib.constants
from ipapython.dn import DN
from ipapython import ipa_log_manager
from ipaplatform.paths import paths

from temp import TemporaryDirectory

# TODO
zone_dir_template = '/var/named/dyndb-ldap/ipa/master/%s'
time_bindfmt = '%Y%m%d%H%M%S'

# this daemon should run under ods:named user:group
# user has to be ods because ODSMgr.py sends signal to ods-enforcerd
FILE_PERM = (stat.S_IRUSR | stat.S_IRGRP | stat.S_IWGRP | stat.S_IWUSR)
DIR_PERM = (stat.S_IRWXU | stat.S_IRWXG)

class BINDMgr(object):
    """BIND key manager. It does LDAP->BIND key files synchronization.

    One LDAP object with idnsSecKey object class will produce
    single pair of BIND key files.
    """
    def __init__(self, api):
        self.api = api
        self.log = ipa_log_manager.log_mgr.get_logger(self)
        self.ldap_keys = {}

    def util(self, cmd, cwd=None):
        """Call given command and return stdout + stderr.

        Raises CalledProcessError if returncode != 0.
        """
        self.log.debug('Executing: %s', cmd)
        util = subprocess.Popen(
            cmd, close_fds=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, cwd=cwd)
        stdout, ignore = util.communicate()
        if util.returncode != 0:
            ex = subprocess.CalledProcessError(util.returncode, cmd, stdout)
            self.log.exception(ex)
            self.log.error("Command output: %s", stdout)
            raise ex
        return stdout

    def notify_zone(self, zone):
        cmd = ['rndc', 'loadkeys', zone]
        output = self.util(cmd)
        self.log.info(output)

    def dn2zone_name(self, dn):
        """cn=KSK-20140813162153Z-cede9e182fc4af76c4bddbc19123a565,cn=keys,idnsname=test,cn=dns,dc=ipa,dc=example"""
        # verify that metadata object is under DNS sub-tree
        dn = DN(dn)
        container = DN(self.api.env.container_dns, self.api.env.basedn)
        idx = dn.rfind(container)
        assert idx != -1, 'Metadata object %s is not inside %s' % (dn, container)
        assert len(dn[idx - 1]) == 1, 'Multi-valued RDN as zone name is not supported'
        return dns.name.from_text(dn[idx - 1]['idnsname'])

    def time_ldap2bindfmt(self, str_val):
        dt = datetime.strptime(str_val, ipalib.constants.LDAP_GENERALIZED_TIME_FORMAT)
        return dt.strftime(time_bindfmt)

    def dates2params(self, ldap_attrs):
        attr2param = {'idnsseckeypublish': '-P',
                'idnsseckeyactivate': '-A',
                'idnsseckeyinactive': '-I',
                'idnsseckeydelete': '-D'}

        params = []
        for attr, param in attr2param.items():
            if attr in ldap_attrs:
                params.append(param)
                assert len(ldap_attrs[attr]) == 1, 'Timestamp %s is expected to be single-valued' % attr
                params.append(self.time_ldap2bindfmt(ldap_attrs[attr][0]))

        return params

    def ldap_event(self, op, uuid, attrs):
        """Record single LDAP event - key addition or deletion.

        Change is only recorded to memory.
        self.sync() has to be called to synchronize change to BIND."""
        assert op == 'add' or op == 'del'
        zone = self.dn2zone_name(attrs['dn'])
        zone_keys = self.ldap_keys.setdefault(zone, {})
        if op == 'add':
            self.log.info('Key metadata %s added to zone %s' % (attrs['dn'], zone))
            zone_keys[uuid] = attrs
        elif op == 'del':
            self.log.info('Key metadata %s deleted from zone %s' % (attrs['dn'], zone))
            zone_keys.pop(uuid)

    def install_key(self, zone, uuid, attrs, workdir):
        """Run dnssec-keyfromlabel on given LDAP object.
        
        :returns: base file name of output files, e.g. Kaaa.test.+008+19719"""
        self.log.info('attrs: %s', attrs)
        assert attrs.get('idnsseckeyzone', ['FALSE'])[0] == 'TRUE', \
            'object %s is not a DNS zone key' % attrs['dn']

        uri = "%s;pin-source=%s" % (attrs['idnsSecKeyRef'][0], paths.SOFTHSM_PIN)
        # TODO: path?
        cmd = ['dnssec-keyfromlabel-pkcs11', '-K', workdir, '-a', attrs['idnsSecAlgorithm'][0], '-l', uri]
        cmd += self.dates2params(attrs)
        if attrs.get('idnsSecKeySep', ['FALSE'])[0].upper() == 'TRUE':
            cmd += ['-f', 'KSK']
        if attrs.get('idnsSecKeyRevoke', ['FALSE'])[0].upper() == 'TRUE':
            cmd += ['-R', datetime.now().strftime(time_bindfmt)]
        cmd.append(zone.to_text())

        # keys has to be readable by ODS & named
        basename = self.util(cmd).strip()
        private_fn = "%s/%s.private" % (workdir, basename)
        os.chmod(private_fn, FILE_PERM)
        # this is useful mainly for debugging
        with open("%s/%s.uuid" % (workdir, basename), 'w') as uuid_file:
            uuid_file.write(uuid)
        with open("%s/%s.dn" % (workdir, basename), 'w') as dn_file:
            dn_file.write(attrs['dn'])

    def sync_zone(self, zone):
        # TODO: ipa.paths.zone_dir_template
        self.log.info('Synchronizing zone %s' % zone)
        zone_path = zone_dir_template % zone.to_text(omit_final_dot=True)
        try:
            os.makedirs(zone_path)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise e

        # fix HSM permissions
        # TODO: move out
        for prefix, dirs, files in os.walk(paths.SOFTHSM_TOKENS_DIR, topdown=True):
            for name in files:
                os.chmod(os.path.join(prefix, name), FILE_PERM)
            for name in dirs:
                os.chmod(os.path.join(prefix, name), DIR_PERM | stat.S_ISGID)
        # TODO: move out

        with TemporaryDirectory(zone_path) as tempdir:
            for uuid, attrs in self.ldap_keys[zone].items():
                self.install_key(zone, uuid, attrs, tempdir)
            # keys were generated in a temporary directory, swap directories
            target_dir = "%s/keys" % zone_path
            try:
                shutil.rmtree(target_dir)
            except OSError as e:
                if e.errno != errno.ENOENT:
                    raise e
            shutil.move(tempdir, target_dir)
            os.chmod(target_dir, DIR_PERM)

        # TODO: path
        cmd = ['rndc', 'loadkeys', zone.to_text()]
        self.log.info(self.util(cmd).strip())

            
    def sync(self):
        """Synchronize list of zones in LDAP with BIND."""
        self.log.debug('!!!!!!!! Keys in LDAP: %s' % self.ldap_keys)
        for zone in self.ldap_keys.keys():
            self.sync_zone(zone)

        return
        zl_ods = self.get_ods_zonelist()
        self.log.debug("ODS zones: %s", zl_ods.mapping)
        removed = self.diff_zl(zl_ods, self.zl_ldap)
        self.log.info("Zones removed from LDAP: %s", removed)
        added = self.diff_zl(self.zl_ldap, zl_ods)
        self.log.info("Zones added to LDAP: %s", added)
        for (uuid, name) in removed:
            self.del_ods_zone(name)
        for (uuid, name) in added:
            self.add_ods_zone(uuid, name)

    def diff_zl(self, s1, s2):
        """Compute zones present in s1 but not present in s2.

        Returns: List of (uuid, name) tuples with zones present only in s1."""
        s1_extra = s1.uuids - s2.uuids
        removed = [(uuid, name) for (uuid, name) in s1.mapping.items()
                   if uuid in s1_extra]
        return removed


if __name__ == '__main__':
    ipa_log_manager.standard_logging_setup(debug=True)
    bind = BINDMgr()
