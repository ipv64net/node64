#!/bin/sh
# OpenLDAP mit zwei Datenbanken: dc=mo (memberof-Overlay, groupOfNames) und dc=plain (ohne memberOf)
set -e
. /env/pw
S=/etc/openldap/schema
SV=$(slappasswd -s "$SVCPW"); UP=$(slappasswd -s "$USERPW")
mkdir -p /var/lib/ldap/mo /var/lib/ldap/plain /run/openldap
cat > /tmp/slapd.conf <<CONF
include $S/core.schema
include $S/cosine.schema
include $S/inetorgperson.schema
include $S/nis.schema
modulepath /usr/lib/openldap
moduleload back_mdb.so
moduleload memberof.so
moduleload refint.so
pidfile /run/openldap/slapd.pid
TLSCertificateFile /certs/ldap1.crt
TLSCertificateKeyFile /certs/ldap1.key
TLSCACertificateFile /certs/ca.crt
database mdb
suffix "dc=mo,dc=lan"
rootdn "cn=root,dc=mo,dc=lan"
rootpw $SV
directory /var/lib/ldap/mo
overlay memberof
memberof-group-oc groupOfNames
memberof-member-ad member
memberof-memberof-ad memberOf
memberof-refint TRUE
access to attrs=userPassword by self write by anonymous auth by * none
access to * by dn.exact="cn=svc,dc=mo,dc=lan" read by self read by * none
database mdb
suffix "dc=plain,dc=lan"
rootdn "cn=root,dc=plain,dc=lan"
rootpw $SV
directory /var/lib/ldap/plain
access to attrs=userPassword by self write by anonymous auth by * none
access to * by dn.exact="cn=svc,dc=plain,dc=lan" read by self read by * none
CONF
for b in mo plain; do
cat > /tmp/$b.ldif <<LDIF
dn: dc=$b,dc=lan
objectClass: dcObject
objectClass: organization
o: $b
dc: $b

dn: cn=svc,dc=$b,dc=lan
objectClass: person
cn: svc
sn: svc
userPassword: $SV

dn: ou=people,dc=$b,dc=lan
objectClass: organizationalUnit
ou: people

dn: ou=groups,dc=$b,dc=lan
objectClass: organizationalUnit
ou: groups

dn: uid=bob,ou=people,dc=$b,dc=lan
objectClass: inetOrgPerson
uid: bob
cn: Bob Bauer
sn: Bauer
mail: bob@$b.lan
userPassword: $UP

dn: uid=jürgen,ou=people,dc=$b,dc=lan
objectClass: inetOrgPerson
uid: jürgen
cn: Jürgen Müller
sn: Müller
displayName: Jürgen Müller
userPassword: $UP

dn: cn=staff,ou=groups,dc=$b,dc=lan
objectClass: groupOfNames
cn: staff
member: uid=bob,ou=people,dc=$b,dc=lan
member: uid=jürgen,ou=people,dc=$b,dc=lan

dn: cn=admins,ou=groups,dc=$b,dc=lan
objectClass: groupOfUniqueNames
cn: admins
uniqueMember: uid=bob,ou=people,dc=$b,dc=lan

dn: cn=posix,ou=groups,dc=$b,dc=lan
objectClass: posixGroup
cn: posix
gidNumber: 5000
memberUid: bob
LDIF
done
slapadd -f /tmp/slapd.conf -b dc=mo,dc=lan -l /tmp/mo.ldif
# slapadd umgeht Overlays: memberOf fuer dc=mo ueber ldapmodify bei laufendem Server nachziehen
slapadd -f /tmp/slapd.conf -b dc=plain,dc=lan -l /tmp/plain.ldif
slapd -f /tmp/slapd.conf -h "ldap:/// ldaps:///" -d 0 &
sleep 2
for g in staff; do
  printf "dn: cn=$g,ou=groups,dc=mo,dc=lan\nchangetype: modify\ndelete: member\n-\nadd: member\nmember: uid=bob,ou=people,dc=mo,dc=lan\nmember: uid=jürgen,ou=people,dc=mo,dc=lan\n" \
    | ldapmodify -x -H ldap:/// -D cn=root,dc=mo,dc=lan -w "$SVCPW" >/dev/null
done
touch /env/slapd.ready
wait
