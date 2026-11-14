#!/bin/bash
# Testumgebung auf agentbox aufbauen (alles unter /root/ldapit, Netz ldapit, Container ldapit-*); Abbau mit down.sh
set -e
cd /root/ldapit
mkdir -p certs env
gen() { echo "$(openssl rand -base64 15 | tr -d '/+=')Aa1!"; }
[ -f env/pw ] || { echo "ADMINPW='$(gen)'"; echo "SVCPW='$(gen)'"; echo "USERPW='$(gen)'"; } > env/pw
docker network inspect ldapit >/dev/null 2>&1 || docker network create ldapit >/dev/null
docker build -q -t ldapit-samba -f Dockerfile.samba . >/dev/null
docker build -q -t ldapit-slapd -f Dockerfile.slapd . >/dev/null
[ -f certs/ca.crt ] || docker run --rm -v $PWD/certs:/certs -v $PWD/certs.sh:/certs.sh:ro ldapit-slapd sh /certs.sh
docker run -d --name ldapit-dc --hostname dc1 --network ldapit --network-alias dc1.n64test.lan --cap-add SYS_ADMIN \
  -v $PWD/certs:/certs:ro -v $PWD/env:/env -v $PWD/samba.sh:/samba.sh:ro ldapit-samba bash /samba.sh >/dev/null
docker run -d --name ldapit-ldap --hostname ldap1 --network ldapit --network-alias ldap1.n64test.lan \
  -v $PWD/certs:/certs:ro -v $PWD/env:/env -v $PWD/slapd.sh:/slapd.sh:ro ldapit-slapd sh /slapd.sh >/dev/null
for i in $(seq 1 90); do [ -f env/samba.ready ] && [ -f env/slapd.ready ] && break; sleep 2; done
ls env; docker ps --filter name=ldapit- --format '{{.Names}} {{.Status}}'
