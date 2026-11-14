#!/bin/bash
# Testumgebung vollstaendig entfernen (Container, Images, Netz, /root/ldapit)
docker rm -f ldapit-dc ldapit-ldap 2>/dev/null
docker rmi ldapit-samba ldapit-slapd 2>/dev/null
docker network rm ldapit 2>/dev/null
rm -rf /root/ldapit
