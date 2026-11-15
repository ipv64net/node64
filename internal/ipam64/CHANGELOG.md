# IPAM64 – Änderungen

## 0.6.0 – unveröffentlicht

Neu:

- Präfix-Seite: Raster und Liste auf einer Seite (Reiter „Adressen“), Adressbereiche als eigener Reiter. Klick auf ein belegtes Feld markiert die Zeile in der Liste, Zeigen auf eine Zeile hebt ihr Feld hervor; Filter und Suche heben die Treffer im Raster hervor, die Suche filtert schon beim Tippen.
- Große Netze (IPv4 größer als /22, IPv6): Blockübersicht mit höchstens 256 Feldern (IPv4 je /24, sonst 8 Bit tiefer), eingefärbt nach Belegung; Klick zeigt nur diesen Block in der Liste, eigene Präfixe darin führen zu ihrer Seite. Bei /22 und /23 zeigt die Liste den gewählten Abschnitt des Rasters.

## 0.5.1 – unveröffentlicht

Behoben (Praxistest im Labor):

- IPv6 vom Provider im Cluster: Eine Node, die den Präfixwechsel über den Cluster bekommt und noch eine Adresse im alten Präfix hat, nummeriert nicht mehr zurück. Umnummeriert wird nur, wenn die Node selbst im bisherigen Präfix lag.
- Nodes des Clusters erscheinen als bekannte Geräte (Quelle „Cluster“) statt als unbekannt.
- Die Reserve-Node des DHCP sieht die Leases (aus dem Cluster-Abgleich), auch solange ihr DHCP-Server nicht vergibt.
- Großer CSV-Import rund zehnmal schneller (10.000 Adressen mit DNS-Eintrag in gut 30 s statt 6 Minuten): DNS64 baut DHCP und lokale Einträge bei Import, Assistent, IPv6-Wechsel und Abgleich nur einmal am Ende neu auf, und der Browser wartet auf das Ergebnis, statt abzubrechen.
- Cluster-Abgleich von IPAM64 gleich ab dem Start der Node.

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
