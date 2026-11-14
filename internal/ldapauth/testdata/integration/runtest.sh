#!/bin/bash
# Integrationstest im Netz ldapit laufen lassen (Quellen in /root/ldapit/src)
cd /root/ldapit
. env/pw
docker run --rm --network ldapit -v $PWD/src:/src -v $PWD/certs/ca.crt:/ca.crt:ro -v n64gomod:/go/pkg/mod -v n64gocache:/root/.cache/go-build -w /src \
  -e LDAPIT_CA=/ca.crt -e LDAPIT_SVCPW="$SVCPW" -e LDAPIT_USERPW="$USERPW" -e LDAPIT_ANNA_GUID="$(cat env/anna.guid)" \
  golang:1.27 go test -count=1 -tags integration "$@" ./internal/ldapauth/
