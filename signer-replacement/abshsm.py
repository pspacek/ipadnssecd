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
    ipapkcs11.CKA_DECRYPT: 'ipk11decrypt',
    ipapkcs11.CKA_DERIVE: 'ipk11derive',
    ipapkcs11.CKA_ENCRYPT: 'ipk11encrypt',
    ipapkcs11.CKA_EXTRACTABLE: 'ipk11extractable',
    ipapkcs11.CKA_ID: 'ipk11id',
    ipapkcs11.CKA_LABEL: 'ipk11label',
    ipapkcs11.CKA_SENSITIVE: 'ipk11sensitive',
    ipapkcs11.CKA_SIGN: 'ipk11sign',
    ipapkcs11.CKA_SIGN_RECOVER: 'ipk11signrecover',
    ipapkcs11.CKA_UNWRAP: 'ipk11unwrap',
    ipapkcs11.CKA_VERIFY: 'ipk11verify',
    ipapkcs11.CKA_VERIFY_RECOVER: 'ipk11verifyrecover',
    ipapkcs11.CKA_WRAP: 'ipk11wrap',
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

