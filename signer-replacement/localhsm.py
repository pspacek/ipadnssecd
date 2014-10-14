#!/usr/bin/python

import binascii
import collections
from pprint import pprint
import sys
import time

import ipapkcs11
from abshsm import attrs_name2id, attrs_id2name

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
                    % binascii.hexlify(cka_id))

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

class LocalHSM(object):
    def __init__(self, library, slot, pin):
        self.cache_replica_pubkeys = None
        self.p11 = ipapkcs11.IPA_PKCS11()
        self.p11.initialize(slot, pin, library)

    def __del__(self):
        self.p11.finalize()

    def _get_keys_dict(self, *args, **kwargs):
        handles = self.p11.find_keys(*args, **kwargs)
        keys = {}
        for h in handles:
            key = Key(self.p11, h)
            o_id = key['ipk11id']
            assert o_id not in keys, 'duplicate ipk11Id=0x%s' % binascii.hexlify(o_id)
            keys[o_id] = key

        return keys

    @property
    def replica_pubkeys(self):
        keys = self._get_keys_dict(ipapkcs11.KEY_CLASS_PUBLIC_KEY, cka_wrap=True)

        for key in keys.itervalues():
            prefix = 'dnssec-replica:'
            assert key['ipk11label'].startswith(prefix), \
                'public key ipk11id=0x%s ipk11label="%s" with ipk11Wrap = TRUE does not have '\
                '"%s" prefix in key label' % (binascii.hexlify(key['ipk11id']),
                        str(key['ipk11label']), prefix)

        return keys

    @property
    def master_keys(self):
        """Get all usable DNSSEC master keys"""
        keys = self._get_keys_dict(ipapkcs11.KEY_CLASS_SECRET_KEY, label=u'dnssec-master', cka_unwrap=True)

        for key in keys.itervalues():
            prefix = 'dnssec-master'
            assert key['ipk11label'] == prefix, \
                'secret key ipk11id=0x%s ipk11label="%s" with ipk11UnWrap = TRUE does not have '\
                '"%s" key label' % (binascii.hexlify(key['ipk11id']),
                        str(key['ipk11label']), prefix)

        return keys


if __name__ == '__main__':
    print 'test'
    localhsm = LocalHSM('/usr/lib64/pkcs11/libsofthsm2.so', 0, open('/var/lib/ipa/dnssec/softhsm_pin').read())
    pprint(localhsm.replica_pubkeys)
