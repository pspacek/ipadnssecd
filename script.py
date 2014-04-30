from ipalib import api
from ipapython.dn import DN
from ipaserver.plugins.ldap2 import ldap2

api.bootstrap()
api.finalize()

ldap = api.Backend[ldap2]
ldap.connect()

#print ldap.get_entry(DN('cn=config'))

print ldap.conn.conn
