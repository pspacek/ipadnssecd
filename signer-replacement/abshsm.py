import _ipap11helper

attrs_id2name = {
    #_ipap11helper.CKA_ALLOWED_MECHANISMS: 'ipk11allowedmechanisms',
    _ipap11helper.CKA_ALWAYS_AUTHENTICATE: 'ipk11alwaysauthenticate',
    _ipap11helper.CKA_ALWAYS_SENSITIVE: 'ipk11alwayssensitive',
    #_ipap11helper.CKA_CHECK_VALUE: 'ipk11checkvalue',
    _ipap11helper.CKA_COPYABLE: 'ipk11copyable',
    _ipap11helper.CKA_DECRYPT: 'ipk11decrypt',
    _ipap11helper.CKA_DERIVE: 'ipk11derive',
    #_ipap11helper.CKA_DESTROYABLE: 'ipk11destroyable',
    _ipap11helper.CKA_ENCRYPT: 'ipk11encrypt',
    #_ipap11helper.CKA_END_DATE: 'ipk11enddate',
    _ipap11helper.CKA_EXTRACTABLE: 'ipk11extractable',
    _ipap11helper.CKA_ID: 'ipk11id',
    #_ipap11helper.CKA_KEY_GEN_MECHANISM: 'ipk11keygenmechanism',
    #_ipap11helper.CKA_KEY_TYPE: 'ipk11keytype',
    _ipap11helper.CKA_LABEL: 'ipk11label',
    _ipap11helper.CKA_LOCAL: 'ipk11local',
    _ipap11helper.CKA_MODIFIABLE: 'ipk11modifiable',
    _ipap11helper.CKA_NEVER_EXTRACTABLE: 'ipk11neverextractable',
    _ipap11helper.CKA_PRIVATE: 'ipk11private',
    #_ipap11helper.CKA_PUBLIC_KEY_INFO: 'ipapublickey',
    #_ipap11helper.CKA_PUBLIC_KEY_INFO: 'ipk11publickeyinfo',
    _ipap11helper.CKA_SENSITIVE: 'ipk11sensitive',
    _ipap11helper.CKA_SIGN: 'ipk11sign',
    _ipap11helper.CKA_SIGN_RECOVER: 'ipk11signrecover',
    #_ipap11helper.CKA_START_DATE: 'ipk11startdate',
    #_ipap11helper.CKA_SUBJECT: 'ipk11subject',
    _ipap11helper.CKA_TRUSTED: 'ipk11trusted',
    _ipap11helper.CKA_UNWRAP: 'ipk11unwrap',
    #_ipap11helper.CKA_UNWRAP_TEMPLATE: 'ipk11unwraptemplate',
    _ipap11helper.CKA_VERIFY: 'ipk11verify',
    _ipap11helper.CKA_VERIFY_RECOVER: 'ipk11verifyrecover',
    _ipap11helper.CKA_WRAP: 'ipk11wrap',
    #_ipap11helper.CKA_WRAP_TEMPLATE: 'ipk11wraptemplate',
    _ipap11helper.CKA_WRAP_WITH_TRUSTED: 'ipk11wrapwithtrusted',
}

attrs_name2id = dict(zip(attrs_id2name.values(), attrs_id2name.keys()))

bool_attr_names = set([
    'ipk11alwaysauthenticate',
    'ipk11alwayssensitive',
    'ipk11copyable',
    'ipk11decrypt',
    'ipk11derive',
    'ipk11encrypt',
    'ipk11extractable',
    'ipk11local',
    'ipk11modifiable',
    'ipk11neverextractable',
    'ipk11private',
    'ipk11sensitive',
    'ipk11sign',
    'ipk11signrecover',
    'ipk11trusted',
    'ipk11unwrap',
    'ipk11verify',
    'ipk11verifyrecover',
    'ipk11wrap',
    'ipk11wrapwithtrusted',
])

modifiable_attrs_id2name = {
    _ipap11helper.CKA_DECRYPT: 'ipk11decrypt',
    _ipap11helper.CKA_DERIVE: 'ipk11derive',
    _ipap11helper.CKA_ENCRYPT: 'ipk11encrypt',
    _ipap11helper.CKA_EXTRACTABLE: 'ipk11extractable',
    _ipap11helper.CKA_ID: 'ipk11id',
    _ipap11helper.CKA_LABEL: 'ipk11label',
    _ipap11helper.CKA_SENSITIVE: 'ipk11sensitive',
    _ipap11helper.CKA_SIGN: 'ipk11sign',
    _ipap11helper.CKA_SIGN_RECOVER: 'ipk11signrecover',
    _ipap11helper.CKA_UNWRAP: 'ipk11unwrap',
    _ipap11helper.CKA_VERIFY: 'ipk11verify',
    _ipap11helper.CKA_VERIFY_RECOVER: 'ipk11verifyrecover',
    _ipap11helper.CKA_WRAP: 'ipk11wrap',
}

modifiable_attrs_name2id = dict(zip(modifiable_attrs_id2name.values(),
    modifiable_attrs_id2name.keys()))

def sync_pkcs11_metadata(source, target):
    """sync ipk11 metadata from source object to target object"""

    # iterate over list of modifiable PKCS#11 attributes - this prevents us
    # from attempting to set read-only attributes like CKA_LOCAL
    for attr in modifiable_attrs_name2id:
        if attr in source:
            target[attr] = source[attr]

def populate_pkcs11_metadata(source, target):
    """populate all ipk11 metadata attributes in target object from source object"""
    for attr in attrs_name2id:
        if attr in source:
            target[attr] = source[attr]


class AbstractHSM(object):
    def _filter_replica_keys(self, all_keys):
        replica_keys = {}
        for key_id, key in all_keys.iteritems():
            if not key['ipk11label'].startswith('dnssec-replica:'):
                continue
            replica_keys[key_id] = key
        return replica_keys

    def _filter_zone_keys(self, all_keys):
        zone_keys = {}
        for key_id, key in all_keys.iteritems():
            if key['ipk11label'] == u'dnssec-master' \
                or key['ipk11label'].startswith('dnssec-replica:'):
                continue
            zone_keys[key_id] = key
        return zone_keys

