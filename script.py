#!/usr/bin/python

from ipalib import api
from ipapython.dn import DN
from ipapython import ipautil
from ipaserver.plugins.ldap2 import ldap2

ccache_dir = '/tmp'
ccache_fn = '%s/ccache' % ccache_dir

api.bootstrap()
api.finalize()

ipautil.kinit_hostprincipal('dns.keytab', ccache_dir, 'DNS/vm-151.idm.lab.eng.brq.redhat.com')

basedn = DN(api.env.container_dns, api.env.basedn)
print basedn

ldap = api.Backend[ldap2]
ldap.connect(ccache=ccache_fn)

print ldap.get_entry(DN('idnsname=ipa.example,cn=dns,dc=ipa,dc=example'))

print ldap.conn.conn
