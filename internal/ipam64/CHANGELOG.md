# IPAM64 – Änderungen

## 0.5.0 – unveröffentlicht

Neu:

- CSV-Import mit Vorschau: Präfixe oder Adressen (samt Schaltern DNS/DHCP), Komma oder Semikolon, vorhandene Einträge werden ergänzt; der eigene Export lässt sich wieder einlesen.
- Prometheus unter `/api/metrics`: `node64_ipam64_*` – Belegung, Auslastung und Konflikte je Präfix, freie Adressen im DHCP-Adressbereich, Konflikte, Hinweise, unbekannte Geräte, letzter Scan.
- MCP (lesend): neuer Bereich IPAM64 mit `ipam64_overview`, `ipam64_addresses`, `ipam64_conflicts`, `ipam64_available`.
- API: `GET /api/ipam64/conflicts` (Konflikte, Hinweise, unbekannte Geräte).
- Anleitung in docs/IPAM64.md, Abschnitt im README.

## 0.4.0 – unveröffentlicht

Neu:

- Seite „Scan & Konflikte“: Konflikte (doppelte Adresse, fremdes Gerät an einer festen Adresse, Lease gegen feste Adresse) und Hinweise (fest eingestelltes Gerät im DHCP-Adressbereich, feste Adresse mit DNS-Eintrag lange nicht gesehen, fremder DHCP-Server aus DNS64), dazu unbekannte Geräte aus der Nachbartabelle zum Übernehmen oder Ignorieren.
- Weniger Fehlalarme: Zwei MAC-Adressen an einer IP sind nur ein Konflikt, wenn beide abwechselnd antworten (ein Gerätetausch zählt nicht); eine fremde MAC an einer festen Adresse erst nach 5 Minuten.
- Benachrichtigungen über die Standardkanäle: neue Konflikte (Standard an) und neue Geräte (Standard aus, erst eine Stunde nach dem Start).
- Hersteller zur MAC (Herstellerliste der IEEE, erzeugt mit `go run gen.go` in `internal/ipam64/oui`), zufällige MACs werden erkannt.

## 0.3.0 – unveröffentlicht

Neu:

- „Einrichten aus dem Bestand“: schlägt Präfixe aus den DHCP-Netzen von DNS64 und den Netzen der Node vor und übernimmt feste Adressen und A/AAAA-Einträge, die in DNS64 von Hand stehen – mit passend gesetzten Schaltern, gekennzeichnet statt doppelt. Was nicht passt, bleibt von Hand und steht mit Grund in der Liste.
- Dynamische IPv6-Präfixe: Ein Präfix vom Provider lässt sich als „dynamisch“ markieren. Wechselt es, zieht IPAM64 die Präfixe darin (Präfix-ID bleibt), die Adressen und ihre AAAA-Einträge in DNS64 nach; erkannt über die Adressen der Node, Prüfung alle 2 Minuten oder auf Knopfdruck.
- Übersicht: letzter Wechsel des IPv6-Präfixes und Ziele in PROXY64, Monitor64 und Healthchecks, die noch auf das alte Präfix zeigen.
- API: Feld `dynamic` an Präfixen.

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
