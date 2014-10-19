#!/usr/bin/python
"""
Download keys from LDAP to local HSM.

This program should be run only on replicas, not on DNSSEC masters.
"""

from binascii import hexlify
from datetime import datetime
import dns.dnssec
import fcntl
import logging
import os
from pprint import pprint
import subprocess
import socket
import sys
import systemd.daemon
import systemd.journal
import time

import ipalib
from ipapython.dn import DN
from ipapython.ipa_log_manager import root_logger, standard_logging_setup
from ipapython import ipaldap
from ipapython import ipautil
from ipaserver.plugins.ldap2 import ldap2
from ipaplatform.paths import paths

from abshsm import sync_pkcs11_metadata, ldap2p11helper_api_params, wrappingmech_name2id
from ldapkeydb import LdapKeyDB
from localhsm import LocalHSM
import _ipap11helper

DAEMONNAME = 'ipa-dnskeysyncd'
PRINCIPAL = None  # not initialized yet
WORKDIR = '/tmp'

def hex_set(s):
    out = set()
    for i in s:
        out.add("0x%s" % hexlify(i))
    return out

def update_metadata_set(log, source_set, target_set):
    """sync metadata from source key set to target key set

    Keys not present in both sets are left intact."""
    log = log.getChild('sync_metadata')
    matching_keys = set(source_set.keys()).intersection(set(target_set.keys()))
    log.info("keys in local HSM & LDAP: %s", hex_set(matching_keys))
    for key_id in matching_keys:
        sync_pkcs11_metadata(log, source_set[key_id], target_set[key_id])


def find_unwrapping_key(log, localhsm, wrapping_key_uri):
    wrap_keys = localhsm.find_keys(uri=wrapping_key_uri)
    # find usable unwrapping key with matching ID
    for key_id, key in wrap_keys.iteritems():
        unwrap_keys = localhsm.find_keys(id=key_id, cka_unwrap=True)
        if len(unwrap_keys) > 0:
            return unwrap_keys.popitem()[1]

def ldap2replica_master_keys_sync(log, ldapkeydb, localhsm):
    ## LDAP -> replica master key synchronization
    # import new master keys from LDAP
    new_keys = set(ldapkeydb.master_keys.keys()) \
            - set(localhsm.master_keys.keys())
    log.debug("master keys in local HSM: %s", hex_set(localhsm.master_keys.keys()))
    log.debug("master keys in LDAP HSM: %s", hex_set(ldapkeydb.master_keys.keys()))
    log.debug("new master keys in LDAP HSM: %s", hex_set(new_keys))
    for mkey_id in new_keys:
        mkey_ldap = ldapkeydb.master_keys[mkey_id]
        for wrapped_ldap in mkey_ldap.wrapped_entries:
            unwrapping_key = find_unwrapping_key(log, localhsm,
                    wrapped_ldap.single_value['ipaWrappingKey'])
            if unwrapping_key:
                break

        # TODO: Could it happen in normal cases?
        assert unwrapping_key is not None, "Local HSM does not contain suitable unwrapping key for master key 0x%s" % hexlify(mkey_id)

        params = ldap2p11helper_api_params(mkey_ldap)
        params['data'] = wrapped_ldap.single_value['ipaSecretKey']
        params['unwrapping_key'] = unwrapping_key.handle
        params['wrapping_mech'] = wrappingmech_name2id[wrapped_ldap.single_value['ipaWrappingMech']]
        log.debug('Importing new master key: 0x%s %s', hexlify(mkey_id), params)
        localhsm.p11.import_wrapped_secret_key(**params)

    # synchronize metadata about master keys in LDAP 
    update_metadata_set(log, ldapkeydb.master_keys, localhsm.master_keys)

def ldap2replica_zone_keys_sync(log, ldapkeydb, localhsm):
    ## LDAP -> replica zone key synchronization
    # import new zone keys from LDAP
    new_keys = set(ldapkeydb.zone_keypairs.keys()) \
            - set(localhsm.zone_privkeys.keys())

    log.debug("zone keys in local HSM: %s", hex_set(localhsm.master_keys.keys()))
    log.debug("zone keys in LDAP HSM: %s", hex_set(ldapkeydb.master_keys.keys()))
    log.debug("new zone keys in LDAP HSM: %s", hex_set(new_keys))
    for zkey_id in new_keys:
        zkey_ldap = ldapkeydb.zone_keypairs[zkey_id]
        log.debug('Looking for unwrapping key "%s" for zone key 0x%s',
                zkey_ldap['ipaWrappingKey'], hexlify(zkey_id))
        unwrapping_key = find_unwrapping_key(log, localhsm,
                zkey_ldap['ipaWrappingKey'])
        assert unwrapping_key is not None, \
                "Local HSM does not contain suitable unwrapping key for ' \
                'zone key 0x%s" % hexlify(zkey_id)

        log.debug('Importing zone key pair 0x%s', hexlify(zkey_id))
        localhsm.import_private_key(zkey_ldap, zkey_ldap['ipaPrivateKey'],
                unwrapping_key)
        localhsm.import_public_key(zkey_ldap, zkey_ldap['ipaPublicKey'])

    # synchronize metadata about zone keys in LDAP & local HSM
    update_metadata_set(log, ldapkeydb.master_keys, localhsm.master_keys)

    # delete keys removed from LDAP
    deleted_keys = set(localhsm.zone_privkeys.keys()) \
                - set(ldapkeydb.zone_keypairs.keys())

    for zkey_id in deleted_keys:
        localhsm.p11.delete_key(localhsm.zone_pubkeys[zkey_id].handle)
        localhsm.p11.delete_key(localhsm.zone_privkeys[zkey_id].handle)


# IPA framework initialization
ipalib.api.bootstrap()
ipalib.api.finalize()
standard_logging_setup(verbose=True, debug = True)#debug=ipalib.api.env.debug)
log = root_logger
log.setLevel(level=logging.DEBUG)

# Kerberos initialization
PRINCIPAL = str('%s/%s' % (DAEMONNAME, ipalib.api.env.host))
log.debug('Kerberos principal: %s', PRINCIPAL)
ipautil.kinit_hostprincipal(paths.IPA_DNSKEYSYNCD_KEYTAB, WORKDIR, PRINCIPAL)
log.debug('Got TGT')

# LDAP initialization
dns_dn = DN(ipalib.api.env.container_dns, ipalib.api.env.basedn)
ldap = ipalib.api.Backend[ldap2]
# fixme
log.debug('Connecting to LDAP')
ldap.connect(ccache="%s/ccache" % WORKDIR)
log.debug('Connected')


### DNSSEC master: key synchronization
# TODO: move to api.env
ldapkeydb = LdapKeyDB(log, ldap, DN("cn=keys", "cn=sec", dns_dn))

# TODO: slot number could be configurable
localhsm = LocalHSM(paths.LIBSOFTHSM2_SO, 0,
        open(paths.DNSSEC_SOFTHSM_PIN).read())

ldap2replica_master_keys_sync(log, ldapkeydb, localhsm)
ldap2replica_zone_keys_sync(log, ldapkeydb, localhsm)

sys.exit(0)
