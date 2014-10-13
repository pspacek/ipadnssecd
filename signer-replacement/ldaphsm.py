#!/usr/bin/python

import sys
import time

import ipalib
from ipapython.dn import DN
from ipapython import ipaldap
from ipapython import ipautil
from ipaserver.plugins.ldap2 import ldap2
from ipaplatform.paths import paths


class LDAPHSM(object):
    def __init__(self, ldap, base_dn):
        self.ldap = ldap
        self.base_dn = base_dn
        self.cache_replica_pubkeys = None

    def _get_key_dict(self, ldap_filter):
        try:
            objs = self.ldap.get_entries(base_dn=self.base_dn,
                    filter=ldap_filter)
        except ipalib.errors.NotFound:
            return {}

        keys = {}
        for o in objs:
            print type(o)
            assert 'ipk11id' in o, 'key is missing ipk11Id in %s' % o.dn
            o_id = o.single_value['ipk11id']
            assert o_id not in keys, 'duplicate ipk11Id="%s" in "%s" and "%s"'\
                % (o_id, o.dn, keys[o_id].dn)
            assert 'ipk11label' in o, 'key "%s" is missing ipk11Label' % o.dn
            keys[o_id] = o

        return keys

    @property
    def replica_pubkeys(self):
        if self.cache_replica_pubkeys:
            return self.cache_replica_pubkeys

        keys = self._get_key_dict(
                '(&(objectClass=ipk11PublicKey)(ipk11Wrap=TRUE)(objectClass=ipaPublicKeyObject))')
        for key in keys.itervalues():
            assert key.single_value['ipk11label'].startswith('replica:'), \
                'public key "%s" with ipk11Wrap = TRUE does not have ' \
                '"replica:" prefix in key label' % key.dn

        self.cache_replica_pubkeys = keys
        return keys

