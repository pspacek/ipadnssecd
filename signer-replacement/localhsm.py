#!/usr/bin/python

from binascii import hexlify
import collections
import logging
from pprint import pprint
import sys
import time

import ipapkcs11
from abshsm import attrs_name2id, attrs_id2name, AbstractHSM

class Key(collections.MutableMapping):
    def __init__(self, p11, handle):
        self.p11 = p11
        self.handle = handle
        # sanity check CKA_ID and CKA_LABEL
        try:
            cka_id = self.p11.get_attribute(handle, ipapkcs11.CKA_ID)
            assert len(cka_id) != 0, 'ipk11id length should not be 0'
        except ipapkcs11.NotFound:
            raise ipapkcs11.NotFound('key without ipk11id: handle %s' % handle)

        try:
            cka_label = self.p11.get_attribute(handle, ipapkcs11.CKA_LABEL)
            assert len(cka_label) != 0, 'ipk11label length should not be 0'

        except ipapkcs11.NotFound:
            raise ipapkcs11.NotFound('key without ipk11label: id 0x%s'
                    % hexlify(cka_id))

    def __getitem__(self, key):
        try:
            return self.p11.get_attribute(self.handle, attrs_name2id[key])
        except ipapkcs11.NotFound:
            raise KeyError()

    def __setitem__(self, key, value):
        return self.p11.set_attribute(self.handle, attrs_name2id[key], value)

    def __delitem__(self, key):
        raise ipapkcs11.Exception('__delitem__ is not supported')

    def __iter__(self):
        """generates list of ipa names of all attributes present in the object"""
        for pkcs11_id, ipa_name in attrs_id2name.iteritems():
            try:
                self.p11.get_attribute(self.handle, pkcs11_id)
            except ipapkcs11.NotFound:
                continue

            yield ipa_name

    def __len__(self):
        cnt = 0
        for attr in self:
            cnt += 1
        return cnt

    def __str__(self):
        d = {}
        for ipa_name, value in self.iteritems():
            d[ipa_name] = value

        return str(d)

    def __repr__(self):
        return self.__str__()

class LocalHSM(AbstractHSM):
    def __init__(self, library, slot, pin):
        self.cache_replica_pubkeys = None
        self.p11 = ipapkcs11.IPA_PKCS11()
        self.p11.initialize(slot, pin, library)
        self.log = logging.getLogger()

    def __del__(self):
        self.p11.finalize()

    def find_keys(self, **kwargs):
        """Return dict with Key objects matching given criteria.

        CKA_ID is used as key so all matching objects have to have unique ID."""

        # this is a hack for old p11-kit URI parser
        # see https://bugs.freedesktop.org/show_bug.cgi?id=85057
        if 'uri' in kwargs:
            kwargs['uri'] = kwargs['uri'].replace('type=', 'object-type=')

        handles = self.p11.find_keys(**kwargs)
        keys = {}
        for h in handles:
            key = Key(self.p11, h)
            o_id = key['ipk11id']
            assert o_id not in keys, 'duplicate ipk11Id = 0x%s; keys = %s' % (
                    hexlify(o_id), keys)
            keys[o_id] = key

        return keys

    @property
    def replica_pubkeys(self):
        return self._filter_replica_keys(
                self.find_keys(objclass=ipapkcs11.KEY_CLASS_PUBLIC_KEY))


    @property
    def replica_pubkeys_wrap(self):
        return self._filter_replica_keys(
                self.find_keys(objclass=ipapkcs11.KEY_CLASS_PUBLIC_KEY,
                cka_wrap=True))

    @property
    def master_keys(self):
        """Get all usable DNSSEC master keys"""
        keys = self.find_keys(objclass=ipapkcs11.KEY_CLASS_SECRET_KEY, label=u'dnssec-master', cka_unwrap=True)

        for key in keys.itervalues():
            prefix = 'dnssec-master'
            assert key['ipk11label'] == prefix, \
                'secret key ipk11id=0x%s ipk11label="%s" with ipk11UnWrap = TRUE does not have '\
                '"%s" key label' % (hexlify(key['ipk11id']),
                        str(key['ipk11label']), prefix)

        return keys

    def import_public_key(self, source, data):
        h = self.p11.import_public_key(
                label = source['ipk11label'],
                id = source['ipk11id'],
                data = data,
                cka_copyable = source['ipk11copyable'],
                cka_derive = source['ipk11derive'],
                cka_encrypt = source['ipk11encrypt'],
                cka_modifiable = source['ipk11modifiable'],
                cka_private = source['ipk11private'],
                cka_verify = source['ipk11verify'],
                cka_verify_recover = source['ipk11verifyrecover'],
                cka_wrap = source['ipk11wrap']
                )
        return Key(self.p11, h)


if __name__ == '__main__':
    localhsm = LocalHSM('/usr/lib64/pkcs11/libsofthsm2.so', 0, open('/var/lib/ipa/dnssec/softhsm_pin').read())

    print 'replica public keys: CKA_WRAP = TRUE'
    print '===================================='
    for pubkey_id, pubkey in localhsm.replica_pubkeys_wrap.iteritems():
        print hexlify(pubkey_id)
        pprint(pubkey)

    print ''
    print 'replica public keys: all'
    print '========================'
    for pubkey_id, pubkey in localhsm.replica_pubkeys.iteritems():
        print hexlify(pubkey_id)
        pprint(pubkey)

    print ''
    print 'master keys'
    print '==========='
    for mkey_id, mkey in localhsm.master_keys.iteritems():
        print hexlify(mkey_id)
        pprint(mkey)
