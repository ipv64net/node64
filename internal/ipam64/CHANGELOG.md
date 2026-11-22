# IPAM64 – Änderungen

## 0.6.4 – 2026-11-22

- Übernahme aus DNS64: Der Name einer DHCP-Reservierung von Hand (z. B. „Tablet Lea“) bleibt erhalten, wenn die Adresse keinen Rechnernamen hat.
- Speichern einer Adresse mit gesperrtem DHCP-Schalter löscht ihre Reservierung nicht mehr.
- CSV-Import: Aus dem eigenen Export werden nur fest eingetragene Adressen übernommen; Leases und Sichtungen werden übergangen und erzeugen keine Ausnahmen im DHCP-Bereich mehr.
- Die Rückfrage beim Entfernen einer Adresse sagt richtig, dass ihre Einträge in DNS64 mit gelöscht werden.
- Die Meldung nach Import und Einrichtung nennt höchstens zehn fehlgeschlagene Zeilen; bei vielen Fehlern ging sie vorher verloren.
- Blockübersicht: Felder eines größeren Kind-Präfixes führen zu diesem Präfix.
- Ausnahmen fester Adressen im DHCP-Bereich bleiben, auch wenn das DHCP-Netz auf dieser Node aus ist (im Cluster vergibt eine andere Node).
- Cluster: Getauschte Adressen gelten nicht mehr als Doppelvergabe, wenn die Änderungen in anderer Reihenfolge ankommen.
- „Nächste freie Adresse“ und Lückenliste: Router-Adresse, Kind-Präfixe und reservierte Bereiche zählen nicht mehr als frei; Lücken werden an den Grenzen des DHCP-Bereichs geteilt.
- Hinweis „unbekanntes Gerät im DHCP-Bereich“ und Meldung „neues Gerät“ nur noch für gerade gesehene Geräte, nicht mehr für gegangene Clients nach Ablauf der Lease.
- Die Rückkehr zu einer früher gesehenen MAC (z. B. VIP-Failover) ist kein Konflikt mehr.
- Der Speicher für Sichtungen wird bei lange laufenden Nodes aufgeräumt.

## 0.6.3 – 2026-11-19

- Präfix und Adresse bearbeiten: Beim Feld „Tags“ werden die schon vergebenen Tags vorgeschlagen (#193).
- Adressen ohne Namen (nur in der Nachbartabelle gesehen, z. B. wenn die FRITZ!Box DHCP macht) bekommen den Rechnernamen, den DNS64 beim Router erfragt – wie in der Geräteliste von DNS64. Eigene Namen gehen vor (Forum 5228).

## 0.6.2 – 2026-11-15

- Eigenes Logo (hell und dunkel) in der Übersicht, auf dem Dashboard und unter Einstellungen → Module.

## 0.6.1 – 2026-11-15

Behoben (Code-Review):

- Kind-Präfixe in einem DHCP-Netz übernehmen dessen Adressbereich und Zone: Adressen im Pool bekommen ihre Ausnahme, „Nächste freie Adresse“ vergibt keine Pool-Adressen mehr, und reservierte Bereiche des Eltern-Präfixes gelten auch im Kind. Adressbereiche eines Kind-Präfixes verhindern nicht mehr, dass das Eltern-Präfix freie Adressen findet.
- DNS64 prüft eine Adresse jetzt vor dem Schreiben ganz; scheitert sie trotzdem, wird ein dabei übernommener Eintrag von Hand freigegeben statt gelöscht (auch bei Import und Assistent).
- „An DNS64 übergeben“ gilt im ganzen Cluster: Die anderen Nodes geben ihre Einträge ebenfalls frei, statt sie zu löschen. Übergebene Adressen bekommen keine Ausnahme im Pool mehr (keine Fehlermeldung alle 10 Minuten); schaltet man DNS oder DHCP wieder ein, verwaltet IPAM64 die Adresse wieder.
- Abgleich mit DNS64: Gleicht eine andere Node DNS64 ab, aber nicht die Adressen von IPAM64, löscht er deren Einträge nicht mehr (kein Hin und Her). Verwaiste Einträge, die eine Adresse braucht (dieselbe Adresse auf zwei Nodes vergeben), ersetzt er im selben Lauf – ohne Lücke und ohne Fehler.
- Dieselbe Adresse auf zwei Nodes gleichzeitig vergeben: Die verdrängte eigene Adresse erscheint 24 Stunden als Konflikt unter „Scan & Konflikte“ und wird gemeldet. „Nächste freie Adresse“ vergibt nur je Node am Stück; im Cluster daher auf einer Node vergeben.
- IPv6 vom Provider: Als neue Adresse zählen nur Adressen auf der Schnittstelle, auf der die Node im Präfix lag – eine globale Adresse von WireGuard, Docker oder einem zweiten Anschluss führt nicht mehr zu falschem oder ausbleibendem Umnummerieren (auch bei Präfixen ohne Kinder). Umnummeriert wird am Stück; scheitert es, bleibt der alte Stand.
- Konflikt „doppelte Adresse“ erst, wenn sich die Sichtungen zweier MAC-Adressen über 5 Minuten überschneiden – ein Gerätetausch ist kein Konflikt mehr.
- CSV-Import: Eine kaputte Zeile ist ein Fehler dieser Zeile; der Rest wird weiter gelesen.
- Ziele mit Namen (Healthchecks, PROXY64) hängen immer an derselben Adresse (IPv4 vor IPv6).
- Übersicht: Die Auswahl „Automatischer Scan“ speichert wieder beim Ändern; der automatische Scan zeigt kein „invalid Prefix“ mehr. Dashboard-Karte: Belegung nur aus IPv4-Präfixen, nie über 100 %.
- CSV-Export: alle Zellen gegen Formeln in Tabellenprogrammen geschützt.
- Schneller: Sichtungen in einer Transaktion je Runde und nur bei Änderungen, Adressen der Node einmal je Lauf, Präfixe beim Import einmal statt je Adresse, Abgleich ohne quadratischen Aufwand.

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
