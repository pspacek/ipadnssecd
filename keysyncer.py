#!/usr/bin/python

import logging

from syncrepl import SyncReplConsumer
from zonelistreader import ODSZoneListReader, LDAPZoneListReader

SIGNING_ATTR = 'idnsSecInlineSigning'

class KeySyncer(SyncReplConsumer):
    def __init__(self, *args, **kwargs):
        self.zl_ldap = LDAPZoneListReader()
        SyncReplConsumer.__init__(self, *args, **kwargs)

    def __get_signing_attr(self, attrs):
        values = attrs.get(SIGNING_ATTR, ['FALSE'])
        assert len(values) == 1, '%s is expected to be single-valued' \
            % SIGNING_ATTR
        return values[0].upper()

    def __is_dnssec_enabled(self, attrs):
        """Test if LDAP DNS zone with given attributes is DNSSEC enabled."""
        return self.__get_signing_attr(attrs) == 'TRUE'

    def application_add(self, uuid, dn, newattrs):
        if self.__is_dnssec_enabled(newattrs):
            self.zl_ldap.process_ipa_zone('add', uuid, newattrs)
        self.log.debug(self.zl_ldap.zones)

    def application_del(self, uuid, dn, oldattrs):
        if self.__is_dnssec_enabled(oldattrs):
            self.zl_ldap.process_ipa_zone('del', uuid, oldattrs)
        self.log.debug(self.zl_ldap.zones)

    def application_sync(self, uuid, dn, newattrs, oldattrs):
        oldval = self.__get_signing_attr(oldattrs)
        newval = self.__get_signing_attr(newattrs)
        if oldval != newval:
            if self.__is_dnssec_enabled(newattrs):
                self.application_add(uuid, dn, newattrs)
            else:
                self.application_del(uuid, dn, oldattrs)


