# IPAM64 – Änderungen

## 0.2.0 – unveröffentlicht

Neu:

- DHCP und DNS aus IPAM64: An jeder Adresse lassen sich ein lokaler DNS-Eintrag (A bzw. AAAA, optional PTR; Zone an der Adresse oder vom Präfix) und eine feste Zuweisung im DHCP-Server von DNS64 einschalten. IPAM64 legt sie gekennzeichnet in DNS64 an; eine gleiche Reservierung bzw. ein gleicher Eintrag von Hand wird übernommen.
- Feste Adressen im DHCP-Adressbereich ohne Reservierung nimmt DNS64 automatisch aus der Vergabe aus.
- Lehnt DNS64 ab (z. B. MAC schon vergeben, CNAME auf dem Namen), bleibt alles beim alten Stand; die Meldung sagt, warum.
- Karte „Wirkung in DNS64“ an der Adresse: was entsteht bzw. vorhanden ist, mit Abgleich gegen DNS64.
- Abgleich alle 10 Minuten: fehlende oder abweichende Einträge werden repariert, verwaiste entfernt (behutsam, damit im Cluster nichts pendelt).
- „An DNS64 übergeben“: Kennzeichen entfernen, die Einträge bleiben in DNS64 frei bearbeitbar (z. B. vor dem Abschalten).
- Löschen einer Adresse entfernt auch ihre Einträge in DNS64.
- Brotkrumen zeigen Präfix bzw. Adresse; die Präfix-Tabelle der Übersicht passt besser auf schmale Bildschirme.
- API: Felder `dns`, `dns_zone`, `ptr`, `dhcp` an Adressen.

## 0.1.0 – unveröffentlicht

Neu (Grundlage aus dem Entwurf von UlrichSchwarz, Community):

- IP-Adressverwaltung für IPv4 und IPv6: Präfixe mit Status (Container, Aktiv, Reserviert, Veraltet), VLAN, Rolle, Tags, DNS-Zone und „gilt als voll“; die Hierarchie ergibt sich aus den Präfixen.
- Feste Adressen mit Status, Rechnername, Rolle (Gateway, DNS-Server, VIP, Anycast), MAC, Beschreibung und Tags; Adressbereiche für feste Adressen und zum Freihalten.
- Zusammengeführt aus DHCP-Netzen, Reservierungen und Leases von DNS64, lokalen A/AAAA-Einträgen, Monitor64, Healthchecks, PROXY64 und der Nachbartabelle (ARP und NDP); Konflikt bei zwei MAC-Adressen an einer IP.
- Übersicht mit Präfix-Baum und Auslastung, Präfix-Seite mit Raster (IPv4 bis /22), Liste mit freien Blöcken und Adressbereichen, „Nächste freie Adresse“.
- Netz-Scan nur in privaten IPv4-Netzen bis /22, an denen die Node hängt, im Hintergrund; je Präfix abschaltbar.
- Cluster: Präfixe, Adressbereiche und feste Adressen werden abgeglichen; Export/Import der Node.
- API `/api/ipam64/…` (Präfixe, Adressbereiche, Adressen, freie Adressen samt Vergabe am Stück, Scan), CSV-Export, Dashboard-Karte, Audit-Bereich „IPAM64“.
