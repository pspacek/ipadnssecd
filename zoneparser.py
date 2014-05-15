#!/usr/bin/python

from lxml import etree


class ODSZoneListReader(object):
    def __init__(self, zonelist_fn):
        self.ods_zones = {}
        # hack: zone object UUID is stored as path to imaginary zone file
        self.entryUUID_prefix = "/var/lib/ipa/dns/zone/entryUUID/"
        self.entryUUID_prefix_len = len(self.entryUUID_prefix)
        xml = etree.parse(open('zonelist.xml', 'r'))
        self.__parse_zonelist(xml)

    def __parse_zonelist(self, xml):
        """iterate over Zone elements with attribute 'name' and
        add IPA zones to self.ods_zones"""
        for zone_xml in xml.xpath('/ZoneList/Zone[@name]'):
            name, zid = self.__parse_ipa_zone(zone_xml)
            self.__add_zone(name, zid)

    def __parse_ipa_zone(self, zone_xml):
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
        path = path[self.entryUUID_prefix_len:]
        return (name, path)

    def __add_zone(self, name, zid):
        # Duplicate zone name should not ever pop up.
        assert name not in self.ods_zones
        self.ods_zones[name] = zid


zl = ODSZoneListReader('/tmp/zonelist.xml')
print zl.ods_zones
