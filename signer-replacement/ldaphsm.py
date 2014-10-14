#!/usr/bin/python

import binascii
import collections
import sys
import time

import ipalib
from ipapython.dn import DN
from ipapython import ipaldap
from ipapython import ipautil
from ipaserver.plugins.ldap2 import ldap2
from ipaplatform.paths import paths

from abshsm import attrs_name2id, attrs_id2name, bool_attr_names

def ldap_bool(val):
    if val == 'TRUE' or val is True:
        return True
    elif val == 'FALSE' or val is False:
        return False
    else:
        raise AssertionError('invalid LDAP boolean "%s"' % val)

class Key(collections.MutableMapping):
    def __init__(self, entry):
        self.entry = entry

    def __getitem__(self, key):
        val = self.entry.single_value[key]
        if key.lower() in bool_attr_names:
            val = ldap_bool(val)
        return val

    def __setitem__(self, key, value):
        self.entry[key] = value

    def __delitem__(self, key):
        del self.entry[key]

    def __iter__(self):
        """generates list of ipa names of all PKCS#11 attributes present in the object"""
        for ipa_name in self.entry.keys():
            lowercase = ipa_name.lower()
            if lowercase in attrs_name2id:
                yield lowercase

    def __len__(self):
        return len(self.entry)

    def __str__(self):
        return str(self.entry)


class LDAPHSM(object):
    def __init__(self, log, ldap, base_dn):
        self.ldap = ldap
        self.base_dn = base_dn
        self.cache_replica_pubkeys = None
        self.log = log

    def get_default_attrs(self, object_classes):
        # object class -> default attribute values mapping
        defaults = {
            u'ipk11publickey': {
                'ipk11copyable': True,
                'ipk11derive': False,
                'ipk11encrypt': False,
                'ipk11local': True,
                'ipk11modifiable': True,
                'ipk11private': True,
                'ipk11trusted': False,
                'ipk11verify': True,
                'ipk11verifyrecover': True,
                'ipk11wrap': False
            },
            u'ipk11privatekey': {
                'ipk11alwaysauthenticate': False,
                'ipk11alwayssensitive': True,
                'ipk11copyable': True,
                'ipk11decrypt': False,
                'ipk11derive': False,
                'ipk11extractable': True,
                'ipk11local': True,
                'ipk11modifiable': True,
                'ipk11neverextractable': True,
                'ipk11private': True,
                'ipk11sensitive': True,
                'ipk11sign': True,
                'ipk11signrecover': True,
                'ipk11unwrap': False,
                'ipk11wrapwithtrusted': False
            },
            u'ipk11secretkey': {
                'ipk11copyable': True,
                'ipk11decrypt': False,
                'ipk11derive': False,
                'ipk11encrypt': False,
                'ipk11extractable': True,
                'ipk11modifiable': True,
                'ipk11private': True,
                'ipk11sensitive': False,
                'ipk11sign': False,
                'ipk11unwrap': True,
                'ipk11verify': False,
                'ipk11wrap': True,
                'ipk11wrapwithtrusted': False
            }
        }

        # get set of supported object classes
        present_clss = set()
        for cls in object_classes:
            present_clss.add(cls.lower())
        present_clss.intersection_update(set(defaults.keys()))
        if len(present_clss) <= 0:
            raise AssertionError('none of "%s" object classes are supported' %
                    object_classes)

        result = {}
        for cls in present_clss:
            result.update(defaults[cls])
        return result

    def _get_key_dict(self, ldap_filter):
        if self.cache_replica_pubkeys:
            return self.cache_replica_pubkeys

        try:
            objs = self.ldap.get_entries(base_dn=self.base_dn,
                    filter=ldap_filter)
        except ipalib.errors.NotFound:
            return {}

        keys = {}
        for o in objs:
            # add default values not present in LDAP
            key = Key(o)
            default_attrs = self.get_default_attrs(key.entry['objectclass'])
            for attr in default_attrs:
                key.setdefault(attr, default_attrs[attr])

            assert 'ipk11id' in o, 'key is missing ipk11Id in %s' % key.entry.dn
            key_id = key['ipk11id']
            assert key_id not in keys, 'duplicate ipk11Id=0x%s in "%s" and "%s"' % (binascii.hexlify(key_id), key.entry.dn, keys[key_id].dn)
            assert 'ipk11label' in key, 'key "%s" is missing ipk11Label' % key.entry.dn
            assert 'objectclass' in key.entry, 'key "%s" is missing objectClass attribute' % key.entry.dn

            keys[key_id] = key

        self.cache_replica_pubkeys = keys
        self.update_keys()
        return keys

    def _update_key(self, key):
        """remove default values from LDAP entry and write back changes"""
        default_attrs = self.get_default_attrs(key.entry['objectclass'])
        empty = object()
        for attr in default_attrs:
            if key.get(attr, empty) == default_attrs[attr]:
                del key[attr]

        try:
            self.ldap.update_entry(key.entry)
        except ipalib.errors.EmptyModlist:
            pass

    def update_keys(self):
        if self.cache_replica_pubkeys:
            for key in self.cache_replica_pubkeys.itervalues():
                self._update_key(key)

    @property
    def replica_pubkeys(self):
        if self.cache_replica_pubkeys:
            return self.cache_replica_pubkeys

        keys = self._get_key_dict(
                '(&(objectClass=ipk11PublicKey)(ipk11Wrap=TRUE)(objectClass=ipaPublicKeyObject))')
        for key in keys.itervalues():
            prefix = 'dnssec-replica:'
            assert key['ipk11label'].startswith(prefix), \
                'public key dn="%s" ipk11id=0x%s ipk11label="%s" with ipk11Wrap = TRUE does not have '\
                '"%s" prefix in key label' % (
                    key.dn,
                    binascii.hexlify(key['ipk11id']),
                    str(key['ipk11label']),
                    prefix)

        self.cache_replica_pubkeys = keys
        return keys

