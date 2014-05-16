#!/usr/bin/python

import logging

from syncrepl import SyncReplConsumer
from odsmgr import ODSMgr

SIGNING_ATTR = 'idnsSecInlineSigning'


class KeySyncer(SyncReplConsumer):
    def __init__(self, *args, **kwargs):
        self.odsmgr = ODSMgr()
        SyncReplConsumer.__init__(self, *args, **kwargs)

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
        if self.__is_dnssec_enabled(newattrs):
            self.odsmgr.ldap_event('add', uuid, newattrs)

    def application_del(self, uuid, dn, oldattrs):
        if self.__is_dnssec_enabled(oldattrs):
            self.odsmgr.ldap_event('del', uuid, oldattrs)

    def application_sync(self, uuid, dn, newattrs, oldattrs):
        oldval = self.__get_signing_attr(oldattrs)
        newval = self.__get_signing_attr(newattrs)
        if oldval != newval:
            if self.__is_dnssec_enabled(newattrs):
                self.odsmgr.ldap_event('add', uuid, newattrs)
            else:
                self.odsmgr.ldap_event('del', uuid, oldattrs)
