# Integrationstest ldapauth (Samba-AD-DC und OpenLDAP)

Wegwerf-Umgebung fuer `integration_test.go` auf der Testbox (Docker, Netz `ldapit`, Container `ldapit-*`):

    scp internal/ldapauth/testdata/integration/* agentbox:/root/ldapit/
    ssh agentbox bash /root/ldapit/up.sh          # CA, Samba-AD n64test.lan, OpenLDAP dc=mo/dc=plain
    # Quellbaum nach /root/ldapit/src kopieren, dann:
    ssh agentbox bash /root/ldapit/runtest.sh -v  # go test -tags integration ./internal/ldapauth/
    ssh agentbox bash /root/ldapit/down.sh        # alles wieder entfernen

Passwoerter werden zufaellig erzeugt (`/root/ldapit/env/pw`) und nie ausgegeben.
