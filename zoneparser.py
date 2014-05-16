#!/usr/bin/python

import logging
from lxml import etree
import dns.name


class ZoneListReader(object):
    def __init__(self):
        self.zone_names = set()  # dns.name
        self.zone_uuids = set()  # UUID strings
        self.zones = set()       # tuples (dns.name, UUID)

    def _add_zone(self, name, zid):
        # detect duplicate zone names
        name = dns.name.from_text(name)
        assert name not in self.zone_names, \
            'duplicate name (%s, %s) vs. %s' % (name, zid, self.zones)
        # duplicate non-None zid is not allowed
        assert not zid or zid not in self.zone_uuids, \
            'duplicate UUID (%s, %s) vs. %s' % (name, zid, self.zones)

        self.zone_names.add(name)
        self.zone_uuids.add(zid)
        self.zones.add((name, zid))


class ODSZoneListReader(ZoneListReader):
    def __init__(self, zonelist_fn):
        super(ODSZoneListReader, self).__init__()
        self.log = logging.getLogger(__name__)
        # hack: zone object UUID is stored as path to imaginary zone file
        self.entryUUID_prefix = "/var/lib/ipa/dns/zone/entryUUID/"
        self.entryUUID_prefix_len = len(self.entryUUID_prefix)
        xml = etree.parse(open('zonelist.xml', 'r'))
        self._parse_zonelist(xml)

    def _parse_zonelist(self, xml):
        """iterate over Zone elements with attribute 'name' and
        add IPA zones to self.zones"""
        for zone_xml in xml.xpath('/ZoneList/Zone[@name]'):
            name, zid = self._parse_ipa_zone(zone_xml)
            self._add_zone(name, zid)

    def _parse_ipa_zone(self, zone_xml):
        """Extract zone name, input adapter and detect IPA zones.

        IPA zones have contains Adapters/Input/Adapter element with
        attribute type = "File" and with value prefixed with entryUUID_prefix.

        Returns:
            tuple (zone name, ID) if zone is IPA zone
            tuple (zone name, None) otherwise
        """
        name = zone_xml.get('name')
        in_adapters = zone_xml.xpath(
            'Adapters/Input/Adapter[@type="File" '
            'and starts-with(text(), "%s")]' % self.entryUUID_prefix)
        if len(in_adapters) != 1:
            # zone without input adapter 'File' is not IPA zone for sure
            return (name, None)

        path = in_adapters[0].text
        # strip prefix from path
        zid = path[self.entryUUID_prefix_len:]
        return (name, zid)

logging.basicConfig(level=logging.DEBUG)
zl = ODSZoneListReader('/tmp/zonelist.xml')
print zl.zones
