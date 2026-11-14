# IPAM64 – Änderungen

## 0.1.0 – unveröffentlicht

Neu (Grundlage aus dem Entwurf von UlrichSchwarz, Community):

- IP-Adressverwaltung für IPv4 und IPv6: Präfixe mit Status (Container, Aktiv, Reserviert, Veraltet), VLAN, Rolle, Tags, DNS-Zone und „gilt als voll“; die Hierarchie ergibt sich aus den Präfixen.
- Feste Adressen mit Status, Rechnername, Rolle (Gateway, DNS-Server, VIP, Anycast), MAC, Beschreibung und Tags; Adressbereiche für feste Adressen und zum Freihalten.
- Zusammengeführt aus DHCP-Netzen, Reservierungen und Leases von DNS64, lokalen A/AAAA-Einträgen, Monitor64, Healthchecks, PROXY64 und der Nachbartabelle (ARP und NDP); Konflikt bei zwei MAC-Adressen an einer IP.
- Übersicht mit Präfix-Baum und Auslastung, Präfix-Seite mit Raster (IPv4 bis /22), Liste mit freien Blöcken und Adressbereichen, „Nächste freie Adresse“.
- Netz-Scan nur in privaten IPv4-Netzen bis /22, an denen die Node hängt, im Hintergrund; je Präfix abschaltbar.
- Cluster: Präfixe, Adressbereiche und feste Adressen werden abgeglichen; Export/Import der Node.
- API `/api/ipam64/…` (Präfixe, Adressbereiche, Adressen, freie Adressen samt Vergabe am Stück, Scan), CSV-Export, Dashboard-Karte, Audit-Bereich „IPAM64“.
