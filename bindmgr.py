#!/usr/bin/python

from datetime import datetime
import dns.name
import errno
import os
import logging
import shutil
import subprocess

from ipalib import api
import ipalib.constants
from ipapython.dn import DN
from ipapython import ipa_log_manager

from temp import TemporaryDirectory

# TODO
zone_dir_template = '/var/named/dyndb-ldap/ipa/%s'
time_bindfmt = '%Y%m%d%H%M%S'

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
        assert attrs.get('idnsseckeyzone', ['FALSE'])[0] == 'TRUE', \
            'object %s is not a DNS zone key' % attrs['dn']

        # TODO: PIN file path
        uri = "%s;pin-source=/tmp/pin" % attrs['idnsSecKeyRef'][0]
        cmd = ['dnssec-keyfromlabel', '-K', workdir, '-a', attrs['idnsSecAlgorithm'][0], '-l', uri]
        cmd += self.dates2params(attrs)
        if attrs.get('idnsSecKeySep', ['FALSE'])[0].upper() == 'TRUE':
            cmd += ['-f', 'KSK']
        if attrs.get('idnsSecKeyRevoke', ['FALSE'])[0].upper() == 'TRUE':
            cmd += ['-R', datetime.now().strftime(time_bindfmt)]
        cmd.append(zone.to_text())
        # TODO: file permissions
        basename = self.util(cmd).strip()
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
            os.makedirs(zone_path, mode=700)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise e

        with TemporaryDirectory(zone_path) as tempdir:
            for uuid, attrs in self.ldap_keys[zone].items():
                self.install_key(zone, uuid, attrs, tempdir)
            # keys were generated in a temporary directory, swap directories
            shutil.rmtree("%s/keys" % zone_path)
            shutil.move(tempdir, "%s/keys" % zone_path)

            
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
