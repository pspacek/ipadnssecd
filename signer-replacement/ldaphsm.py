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

from abshsm import attrs_name2id, attrs_id2name, bool_attr_names, populate_pkcs11_metadata
import ipapkcs11
import random

def ldap_bool(val):
    if val == 'TRUE' or val is True:
        return True
    elif val == 'FALSE' or val is False:
        return False
    else:
        raise AssertionError('invalid LDAP boolean "%s"' % val)

def get_default_attrs(object_classes):
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



class Key(collections.MutableMapping):
    """abstraction to hide LDAP entry weirdnesses:
        - non-normalized attribute names
        - boolean attributes returned as strings
    """
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

    def _cleanup_key(self):
        """remove default values from LDAP entry"""
        default_attrs = get_default_attrs(self.entry['objectclass'])
        empty = object()
        for attr in default_attrs:
            if self.get(attr, empty) == default_attrs[attr]:
                del self[attr]


class LDAPHSM(object):
    def __init__(self, log, ldap, base_dn):
        self.ldap = ldap
        self.base_dn = base_dn
        self.cache_replica_pubkeys = None
        self.log = log
        self.cache_masterkeys = None

    def _get_key_dict(self, ldap_filter):
        try:
            objs = self.ldap.get_entries(base_dn=self.base_dn,
                    filter=ldap_filter)
        except ipalib.errors.NotFound:
            return {}

        keys = {}
        for o in objs:
            # add default values not present in LDAP
            key = Key(o)
            default_attrs = get_default_attrs(key.entry['objectclass'])
            for attr in default_attrs:
                key.setdefault(attr, default_attrs[attr])

            assert 'ipk11id' in o, 'key is missing ipk11Id in %s' % key.entry.dn
            key_id = key['ipk11id']
            assert key_id not in keys, 'duplicate ipk11Id=0x%s in "%s" and "%s"' % (binascii.hexlify(key_id), key.entry.dn, keys[key_id].dn)
            assert 'ipk11label' in key, 'key "%s" is missing ipk11Label' % key.entry.dn
            assert 'objectclass' in key.entry, 'key "%s" is missing objectClass attribute' % key.entry.dn

            keys[key_id] = key

        self.update_keys()
        return keys

    def _update_key(self, key):
        """remove default values from LDAP entry and write back changes"""
        key._cleanup_key()

        try:
            self.ldap.update_entry(key.entry)
        except ipalib.errors.EmptyModlist:
            pass

    def update_keys(self):
        for cache in [self.cache_masterkeys, self.cache_replica_pubkeys]:
            if cache:
                for key in cache.itervalues():
                    self._update_key(key)

    def import_keys(self, source_keys):
        """import keys from Key-compatible objects
        
        multiple source keys can be imported into single LDAP object
        
        :param: source_keys is iterable of (Key object, PKCS#11 object class)"""
        obj_classes = ['ipk11Object']

        for source_key, pkcs11_class in source_keys:
            if pkcs11_class == ipapkcs11.KEY_CLASS_SECRET_KEY:
                obj_classes.append('ipk11SecretKey')
            else:
                raise AssertionError('unsupported object class %s' % pkcs11_class)

            uniqid = binascii.hexlify("".join(chr(random.randint(0, 256))
                        for _ in xrange(0, 16)))
            entry_dn = DN('ipk11UniqueId=%s' % uniqid, self.base_dn)
            entry = self.ldap.make_entry(entry_dn, objectClass=obj_classes)
            entry['ipk11uniqueid'] = uniqid

            new_key = Key(entry)
            populate_pkcs11_metadata(source_key, new_key)
            new_key._cleanup_key()

            while True:
                try:
                    self.ldap.add_entry(new_key.entry)
                except ipalib.errors.DuplicateEntry:
                    # generate new uniq ID and try again
                    uniqid = binascii.hexlify("".join(chr(random.randint(0, 256))
                        for _ in xrange(0, 16)))
                    new_key.entry['ipk11uniqueid'] = uniqid
                    new_key.entry.dn = DN('ipk11UniqueId=%s' % uniqid, self.base_dn)
                    continue

                break

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
                    key.entry.dn,
                    binascii.hexlify(key['ipk11id']),
                    str(key['ipk11label']),
                    prefix)

        self.cache_replica_pubkeys = keys
        return keys

    @property
    def master_keys(self):
        if self.cache_masterkeys:
            return self.cache_masterkeys

        keys = self._get_key_dict(
                '(&(objectClass=ipk11SecretKey)(|(ipk11UnWrap=TRUE)(!(ipk11UnWrap=*)))(ipk11Label=dnssec-master))')
        for key in keys.itervalues():
            prefix = 'dnssec-master'
            assert key['ipk11label'] == prefix, \
                'secret key dn="%s" ipk11id=0x%s ipk11label="%s" with ipk11UnWrap = TRUE does not have '\
                '"%s" key label' % (
                    key.entry.dn,
                    binascii.hexlify(key['ipk11id']),
                    str(key['ipk11label']),
                    prefix)

        self.cache_masterkeys = keys
        return keys
