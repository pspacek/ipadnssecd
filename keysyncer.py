#!/usr/bin/python

import logging
import ldap.dn

from syncrepl import SyncReplConsumer
from odsmgr import ODSMgr
from bindmgr import BINDMgr

SIGNING_ATTR = 'idnsSecInlineSigning'
OBJCLASS_ATTR = 'objectClass'


class KeySyncer(SyncReplConsumer):
    def __init__(self, *args, **kwargs):
        # hack
        self.api = kwargs['ipa_api']
        del kwargs['ipa_api']

        self.odsmgr = ODSMgr()
        self.bindmgr = BINDMgr(self.api)
        self.init_done = False
        SyncReplConsumer.__init__(self, *args, **kwargs)

    def _get_objclass(self, attrs):
        """Get object class.

        Given set of attributes has to have exactly one supported object class.
        """
        supported_objclasses = set(['idnszone', 'idnsseckey'])
        present_objclasses = set([o.lower() for o in attrs[OBJCLASS_ATTR]]).intersection(supported_objclasses)
        assert len(present_objclasses) == 1, attrs[OBJCLASS_ATTR]
        return present_objclasses.pop()

    def __get_signing_attr(self, attrs):
        """Get SIGNING_ATTR from dictionary with LDAP zone attributes.

        Returned value is normalized to TRUE or FALSE, defaults to FALSE."""
        values = attrs.get(SIGNING_ATTR, ['FALSE'])
        assert len(values) == 1, '%s is expected to be single-valued' \
            % SIGNING_ATTR
        return values[0].upper()

    def __is_dnssec_enabled(self, attrs):
        """Test if LDAP DNS zone with given attributes is DNSSEC enabled."""
        return self.__get_signing_attr(attrs) == 'TRUE'

    def application_add(self, uuid, dn, newattrs):
        objclass = self._get_objclass(newattrs)
        if objclass == 'idnszone':
            self.zone_add(uuid, dn, newattrs)
        elif objclass == 'idnsseckey':
            self.key_meta_add(uuid, dn, newattrs)

    def application_del(self, uuid, dn, oldattrs):
        objclass = self._get_objclass(oldattrs)
        if objclass == 'idnszone':
            self.zone_del(uuid, dn, oldattrs)
        elif objclass == 'idnsseckey':
            self.key_meta_del(uuid, dn, oldattrs)

    def application_sync(self, uuid, dn, newattrs, oldattrs):
        olddn = ldap.dn.str2dn(oldattrs['dn'])
        newdn = ldap.dn.str2dn(newattrs['dn'])
        assert olddn == newdn, 'modrdn operation is not supported'

        oldval = self.__get_signing_attr(oldattrs)
        newval = self.__get_signing_attr(newattrs)
        if oldval != newval:
            if self.__is_dnssec_enabled(newattrs):
                self.zone_add(olddn, uuid, newattrs)
            else:
                self.zone_del(olddn, uuid, oldattrs)

    def syncrepl_refreshdone(self):
        self.log.info('Initial LDAP dump is done, sychronizing with ODS and BIND')
        self.init_done = True
        self.odsmgr.sync()
        self.bindmgr.sync()

    # idnsSecKey wrapper
    def key_meta_add(self, uuid, dn, newattrs):
        self.bindmgr.ldap_event('add', uuid, newattrs)
        self.bindmgr_sync()

    def key_meta_del(self, uuid, dn, oldattrs):
        self.bindmgr.ldap_event('del', uuid, oldattrs)
        self.bindmgr_sync()

    def bindmgr_sync(self):
        if self.init_done:
            self.bindmgr.sync()

    # idnsZone wrapper
    def zone_add(self, uuid, dn, newattrs):
        if self.__is_dnssec_enabled(newattrs):
            self.odsmgr.ldap_event('add', uuid, newattrs)
        self.ods_sync()

    def zone_del(self, uuid, dn, oldattrs):
        if self.__is_dnssec_enabled(oldattrs):
            self.odsmgr.ldap_event('del', uuid, oldattrs)
        self.ods_sync()

    def ods_sync(self):
        if self.init_done:
            self.odsmgr.sync()
