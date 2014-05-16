#!/usr/bin/python

import logging
from lxml import etree
import dns.name
import subprocess


class ZoneListReader(object):
    def __init__(self):
        self.zone_names = set()  # dns.name
        self.zone_uuids = set()  # UUID strings
        self.zones = set()       # tuples (dns.name, UUID)

    def _add_zone(self, name, zid):
        """Add zone & UUID to internal structures.

        Zone with given name and UUID must not exist."""
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

    def _del_zone(self, name, zid):
        """Remove zone & UUID from internal structures.

        Zone with given name and UUID must exist.
        """
        name = dns.name.from_text(name)
        assert zid is not None
        assert name in self.zone_names, \
            'name (%s, %s) does not exist in %s' % (name, zid, self.zones)
        assert zid in self.zone_uuids, \
            'UUID (%s, %s) does not exist in %s' % (name, zid, self.zones)
        assert (name, zid) in self.zones, \
            'pair (%s, %s) does not exist in %s' % (name, zid, self.zones)

        self.zone_names.remove(name)
        self.zone_uuids.remove(zid)
        self.zones.remove((name, zid))


class ODSZoneListReader(ZoneListReader):
    """One-shot parser for ODS zonelist.xml."""
    def __init__(self, zonelist_text):
        super(ODSZoneListReader, self).__init__()
        self.log = logging.getLogger(__name__)
        # hack: zone object UUID is stored as path to imaginary zone file
        self.entryUUID_prefix = "/var/lib/ipa/dns/zone/entryUUID/"
        self.entryUUID_prefix_len = len(self.entryUUID_prefix)
        xml = etree.fromstring(zonelist_text)
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
            tuple (zone name, ID)
        """
        name = zone_xml.get('name')
        in_adapters = zone_xml.xpath(
            'Adapters/Input/Adapter[@type="File" '
            'and starts-with(text(), "%s")]' % self.entryUUID_prefix)
        assert len(in_adapters) == 1, 'only IPA zones are supported: %s' \
            % etree.tostring(zone_xml)

        path = in_adapters[0].text
        # strip prefix from path
        zid = path[self.entryUUID_prefix_len:]
        return (name, zid)


class LDAPZoneListReader(ZoneListReader):
    def __init__(self):
        super(LDAPZoneListReader, self).__init__()
        self.log = logging.getLogger(__name__)

    def process_ipa_zone(self, op, uuid, zone_ldap):
        assert (op == 'add' or op == 'del'), 'unsupported op %s' % op
        assert uuid is not None
        assert 'idnsname' in zone_ldap, \
            'LDAP zone UUID %s without idnsName' % uuid
        assert len(zone_ldap['idnsname']) == 1, \
            'LDAP zone UUID %s with len(idnsname) != 1' % uuid

        if op == 'add':
            self._add_zone(zone_ldap['idnsname'][0], uuid)
        elif op == 'del':
            self._del_zone(zone_ldap['idnsname'][0], uuid)


def get_ods_zonelist(log):
    cmd = ['ods-ksmutil', 'zonelist', 'export']
    ksmutil = subprocess.Popen(
        cmd, close_fds=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    stdout, ignore = ksmutil.communicate()
    if ksmutil.returncode != 0:
        e = subprocess.CalledProcessError(ksmutil.returncode, cmd, stdout)
        log.exception(e)
        log.error("Command output: %s", stdout)
        raise e

    reader = ODSZoneListReader(stdout)
    return reader


class ODSMgr(object):
    """OpenDNSSEC zone manager. It does LDAP->ODS synchronization.

    Zones with idnsSecInlineSigning attribute = TRUE in LDAP are added
    or deleted from ODS as necessary. ODS->LDAP key synchronization
    has to be solved seperatelly.
    """
    def __init__(self):
        self.zl_ldap = LDAPZoneListReader()

    def ldap_event(self, op, uuid, attrs):
        """Process single LDAP event - zone addition or deletion."""
        self.zl_ldap.process_ipa_zone(op, uuid, attrs)
        print self.zl_ldap.zones

    pass

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    reader = get_ods_zonelist(logging.getLogger('test'))
    print reader.zones
