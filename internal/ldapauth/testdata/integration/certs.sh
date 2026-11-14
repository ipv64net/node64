#!/bin/sh
# Eigene Test-CA mit Server-Zertifikaten (SAN) fuer dc1 und ldap1
set -e
cd /certs
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=ldapit Test CA" -keyout ca.key -out ca.crt 2>/dev/null
for h in dc1 ldap1; do
  openssl req -newkey rsa:2048 -nodes -subj "/CN=$h.n64test.lan" -keyout $h.key -out $h.csr 2>/dev/null
  printf "subjectAltName=DNS:%s.n64test.lan\nextendedKeyUsage=serverAuth\n" $h > $h.ext
  openssl x509 -req -in $h.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 -extfile $h.ext -out $h.crt 2>/dev/null
done
chmod 600 *.key; chmod 644 *.crt
