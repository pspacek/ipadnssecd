#!/usr/bin/python

import binascii
from pprint import pprint
import sys
import time

import ipapkcs11

attrs_id2name = {
    #ipapkcs11.CKA_ALLOWED_MECHANISMS: 'ipk11allowedmechanisms',
    ipapkcs11.CKA_ALWAYS_AUTHENTICATE: 'ipk11alwaysauthenticate',
    ipapkcs11.CKA_ALWAYS_SENSITIVE: 'ipk11alwayssensitive',
    #ipapkcs11.CKA_CHECK_VALUE: 'ipk11checkvalue',
    ipapkcs11.CKA_COPYABLE: 'ipk11copyable',
    ipapkcs11.CKA_DECRYPT: 'ipk11decrypt',
    ipapkcs11.CKA_DERIVE: 'ipk11derive',
    #ipapkcs11.CKA_DESTROYABLE: 'ipk11destroyable',
    ipapkcs11.CKA_ENCRYPT: 'ipk11encrypt',
    #ipapkcs11.CKA_END_DATE: 'ipk11enddate',
    ipapkcs11.CKA_EXTRACTABLE: 'ipk11extractable',
    ipapkcs11.CKA_ID: 'ipk11id',
    #ipapkcs11.CKA_KEY_GEN_MECHANISM: 'ipk11keygenmechanism',
    #ipapkcs11.CKA_KEY_TYPE: 'ipk11keytype',
    ipapkcs11.CKA_LABEL: 'ipk11label',
    ipapkcs11.CKA_LOCAL: 'ipk11local',
    ipapkcs11.CKA_MODIFIABLE: 'ipk11modifiable',
    ipapkcs11.CKA_NEVER_EXTRACTABLE: 'ipk11neverextractable',
    ipapkcs11.CKA_PRIVATE: 'ipk11private',
    #ipapkcs11.CKA_PUBLIC_KEY_INFO: 'ipapublickey',
    #ipapkcs11.CKA_PUBLIC_KEY_INFO: 'ipk11publickeyinfo',
    ipapkcs11.CKA_SENSITIVE: 'ipk11sensitive',
    ipapkcs11.CKA_SIGN: 'ipk11sign',
    ipapkcs11.CKA_SIGN_RECOVER: 'ipk11signrecover',
    #ipapkcs11.CKA_START_DATE: 'ipk11startdate',
    #ipapkcs11.CKA_SUBJECT: 'ipk11subject',
    ipapkcs11.CKA_TRUSTED: 'ipk11trusted',
    ipapkcs11.CKA_UNWRAP: 'ipk11unwrap',
    #ipapkcs11.CKA_UNWRAP_TEMPLATE: 'ipk11unwraptemplate',
    ipapkcs11.CKA_VERIFY: 'ipk11verify',
    ipapkcs11.CKA_VERIFY_RECOVER: 'ipk11verifyrecover',
    ipapkcs11.CKA_WRAP: 'ipk11wrap',
    #ipapkcs11.CKA_WRAP_TEMPLATE: 'ipk11wraptemplate',
    ipapkcs11.CKA_WRAP_WITH_TRUSTED: 'ipk11wrapwithtrusted',
}

attrs_name2id = dict(zip(attrs_id2name.values(), attrs_id2name.keys()))

class Key(object):
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
        return self.p11.get_attribute(self.handle, attrs_name2id[key])

    def __setitem__(self, key, value):
        return self.p11.set_attribute(self.handle, attrs_name2id[key], value)

    def iteritems(self):
        for pkcs11_id, ipa_name in attrs_id2name.iteritems():
            try:
                value = self.p11.get_attribute(self.handle, pkcs11_id)
            except ipapkcs11.NotFound:
                continue

            yield (ipa_name, value)

        raise StopIteration()

    def __iter__(self):
        """generates list of ipa names of all attributes present in the object"""
        return self.iteritems()

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

if __name__ == '__main__':
    print 'test'
    localhsm = LocalHSM('/usr/lib64/pkcs11/libsofthsm2.so', 0, open('/var/lib/ipa/dnssec/softhsm_pin').read())
    pprint(localhsm.replica_pubkeys)
