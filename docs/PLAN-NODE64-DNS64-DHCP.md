# Plan: DHCP-Server in DNS64

Stand 2026-11-09, **Entscheidungen von Dennis eingearbeitet (siehe unten). Umgesetzt: D1+D2 als DNS64 1.36.0, D3–D6 als DNS64 1.37.0, Review-Fixes 1.37.1 und 1.38.1, Prometheus 1.38.0. Import fester Adressen entfällt (Dennis, 2026-11-09).** Anlass: DHCP wird auf GitHub und im Forum immer wieder gewünscht
(Pi-hole und AdGuard Home haben ihn). Ziel: ein leichter DHCP-Server für Homelab und kleine bis mittlere Firmen, der
Hand in Hand mit dem lokalen DNS arbeitet. Grundlagen: [PLAN-NODE64-DNS64-LOKAL.md](PLAN-NODE64-DNS64-LOKAL.md),
[PLAN-NODE64-DNS64-GRUPPEN.md](PLAN-NODE64-DNS64-GRUPPEN.md), [CLUSTER.md](CLUSTER.md).

## Leitlinien

- **Leicht:** nur IPv4-DHCP (RFC 2131/2132), keine DHCPv6, kein ISC-Failover-Protokoll und keine freien
  Boot-Skripte. Was ein Router-DHCP kann, plus die Verbindung zum DNS. Mehr kommt nicht hinein.
- **Teil von DNS64, kein eigenes Modul** (wie der lokale DNS-Server), aber **opt-in:** Standard aus, und solange
  DHCP aus ist, belegt DNS64 **keinen Port** (kein Socket auf 67/udp, kein DISCOVER ins Netz). Ein zweiter
  DHCP-Server im Netz macht Ärger. Deshalb erst einschalten, wenn kein fremder Server mehr antwortet, oder bewusst
  bestätigen.
- **Einfach für Heimanwender:** Beim Einschalten reichen Schnittstelle und Adressbereich. Router, DNS, Maske und
  Domain schlägt die Node vor. Alles Weitere (PXE, NTP, Lease-Zeit, autoritativ) steht unter „Erweitert“.
- **Mehrere Netze von Anfang an im Datenmodell** (ein „Netz“ = Schnittstelle + Subnetz + Adressbereich), damit eine
  Node mit zwei, drei Schnittstellen bzw. VLANs (z. B. LAN, Gäste-WLAN, IoT) mehrere DHCP-Netze bedient. In der
  Oberfläche zuerst ein Netz, mehrere ab D4.
- Node64 legt **keine Schnittstellen und VLANs an** und ändert nichts an der Netzkonfiguration des Hosts. Was der Host
  hat (eth0, eth0.20, br-iot …), kann ein DHCP-Netz bekommen.
- Eigenes Paket `internal/dns64/dhcp` (Server, Lease-Speicher, ohne Abhängigkeit zu `internal/dns64`). DNS64 hängt
  das Paket ein, wie bei `upstream`, `groups` und `localnet`.
- Wortwahl: In der Oberfläche heißt es „Netz“ (technisch `scope`), nie „Bereich“. Den Begriff hat schon der Cluster.

## Voraussetzungen und Grenzen

- **Host-Netz oder macvlan/ipvlan nötig.** DHCP läuft über Broadcasts. Im Docker-Bridge-Netz kommen sie nicht an.
  `localnet.Bridge()` erkennt das. Dann ist DHCP gesperrt, mit Hinweis und Beispiel `network_mode: host`.
- Port 67/udp: `cap_net_bind_service` ist im Image. Für das Binden an eine Schnittstelle (`SO_BINDTODEVICE`) und für
  die ARP-Probe braucht es `cap_net_raw`, auch das ist im Image (setcap im Dockerfile).
- Nur Linux (Node64 wird nur für Linux gebaut).
- Die Node braucht eine feste IPv4 im jeweiligen Netz. Liegt keine Adresse der Schnittstelle im Subnetz des
  DHCP-Netzes: Fehler beim Speichern. Ausnahme: Relay (D4).

## Bausteine

**Pakete auswerten:** `github.com/insomniacslk/dhcp/dhcpv4`, nur das Paket zum Lesen und Bauen der Pakete
(BSD-3, Grundlage von CoreDHCP, gut getestet). Die Server-Schleife ist eigener Code: ein UDP-Socket je Schnittstelle
mit `SO_BINDTODEVICE` und `SO_BROADCAST` über `x/sys/unix`. Antworten gehen per Broadcast an Clients ohne Adresse,
sonst per Unicast. So braucht es keinen Raw-Socket für Ethernet-Frames. Alternative: eigener Parser (~400 Zeilen),
das bedeutet aber mehr Pflege. Siehe offene Entscheidung 1.

**Datenbank** (Migration `0016_dhcp.sql`, node64.db):

| Tabelle | Inhalt |
|---|---|
| `dns64_dhcp_scopes` | id, Name, Schnittstelle, Subnetz, Bereich von–bis, Router, DNS-Server (leer = diese Node), Domain, Lease-Zeit, NTP, autoritativ, an/aus, nur diese Node |
| `dns64_dhcp_reservations` | scope_id, MAC, IP, Name, Kommentar, Gerätegruppe (optional), an/aus |
| `dns64_dhcp_leases` | scope_id, MAC, IP, Hostname (vom Client), Name (bereinigt), Beginn, Ablauf, Zustand (angeboten/vergeben/abgelehnt/frei) |

Leases liegen zusätzlich im Speicher. Geschrieben wird bei jedem ACK/RELEASE/DECLINE. Abgelaufene Leases bleiben
24 h sichtbar: Kommt der Client wieder, bekommt er dieselbe IP.

## Phasen

**D1 Kern (ein Netz, ohne Oberfläche außer Schalter)**
- DISCOVER/OFFER, REQUEST/ACK/NAK, RELEASE, DECLINE, INFORM.
- Optionen: 1 Netzmaske, 3 Router, 6 DNS (Standard: IP dieser Node), 15 Domain, 119 Suchdomain, 42 NTP (optional),
  51 Lease-Zeit, 54 Server-ID, 58/59 Erneuern.
- Vergabe: Reservierung → bisherige IP des Clients (auch abgelaufen) → gewünschte IP (Option 50), wenn frei → nächste
  freie. Vor dem Angebot eine kurze ARP-Probe. Antwortet jemand, gilt die Adresse als belegt und wird markiert.
- **Autoritativ** (Standard an): Anfragen nach fremden Adressen bekommen NAK. So holen sich Clients nach dem Umstieg
  vom Router sofort eine neue Adresse.
- **Fremde DHCP-Server erkennen:** Beim Einschalten und dann alle 10 min ein eigenes DISCOVER senden und sehen, wer
  antwortet. Erkennt die Node einen fremden Server, gibt es einen Hinweis plus Benachrichtigung („Router-DHCP
  abschalten“).
- **Probelauf** (nur beobachten): Die Node hört mit und zeigt, welche Geräte DHCP anfragen und was sie bekommen
  würden, antwortet aber nicht. Für den sicheren Umstieg vom Router.

**D2 Oberfläche: eigener Menüpunkt „DHCP“ in der linken Navigation** (Unterpunkt von DNS64 wie „Lokaler DNS“, Pfad `/dns64/dhcp`)
- Karte je Netz: Schnittstelle, Subnetz, Bereich, Auslastung als Balken (vergeben/reserviert/frei), Schalter,
  Probelauf, Hinweise (Bridge-Netz, fremder Server, Pool fast voll).
- Lease-Tabelle: Name, IP, MAC, läuft ab, Herkunft (Lease/Reservierung). Suche wie bei den Einträgen. „Reservieren“
  per Klick aus einem Lease, „Freigeben“.
- **PXE/Netboot** je Netz unter „Erweitert“: Boot-Server (Option 66/`siaddr`) und Boot-Datei (Option 67), getrennt
  für BIOS und UEFI (Option 93 des Clients), z. B. netboot.xyz. Keine freien Optionen.
- Reservierungen: MAC → IP, Name, Kommentar, Gerätegruppe. (Import aus dnsmasq/Pi-hole und CSV-Import/-Export
  entfallen – Entscheidung Dennis 2026-11-09.)
- API v1 der Node (`/api/v1/dns64/dhcp/…`) wie bei Einträgen und Zonen, im Backup/Export enthalten.
- Prometheus: Leases je Netz (vergeben/frei), Anfragen nach Art, NAKs, Konflikte. Benachrichtigungen: Pool zu 90 %
  voll, fremder DHCP-Server, Adresskonflikt.

**D3 Hand in Hand mit DNS**
- **Namen automatisch:** Jedes Lease bekommt `<name>.<Domain des Netzes>` als A-Eintrag plus PTR. Der Name kommt aus
  der Reservierung, sonst aus Option 12/81 des Clients, bereinigt auf `a-z0-9-`. Die Einträge laufen wie
  dynamische Einträge (eigene Herkunft `origin='dhcp'`, nur lesen) und verschwinden mit dem Lease.
- Vorrang: eigene Einträge vor Reservierung vor Client-Name. Ist ein Name schon von einer anderen MAC belegt, gibt
  es keinen DNS-Eintrag, aber einen Hinweis am Lease. Kein `name-2`, das ändert sich sonst ständig.
- Ist die Domain des Netzes eine lokale Zone in DNS64, kommen die Namen dort hinein (SOA/NS passen). Sonst schlägt
  DHCP beim Anlegen vor, die Zone anzulegen.
- **Gerätenamen:** DHCP wird die erste Quelle in `names.go` (vor Gruppe, PTR, Router, mDNS). Das Abfrage-Log und die
  Top-Listen zeigen damit fast immer Namen.
- **Gerätegruppen:** Die MAC kennt DHCP sicher, auch dort, wo die ARP-Tabelle sie nicht zeigt. Eine Reservierung mit
  Gruppe macht die MAC zum Mitglied. Gruppenregeln greifen damit auch, wenn sich die IP ändert.

**D4 Mehrere Netze und VLANs**
- Mehrere DHCP-Netze (bis 8), je an eine Schnittstelle gebunden (eth0, eth0.20, br-gast …). Die Schnittstelle wird
  aus der Liste des Hosts gewählt, mit ihren IPv4-Adressen.
- **Relay** (giaddr): Für Netze hinter einem Router mit DHCP-Relay (VLANs im Mittelstand) wählt die Node das Netz
  über das giaddr und antwortet per Unicast an das Relay. Eine eigene Schnittstelle in dem Netz braucht es dann
  nicht.
- Je Netz eigene DNS-/Router-/Domain-Optionen. Damit bekommt z. B. das Gäste-WLAN eine andere Domain und kann über
  die Gerätegruppen (Netz als Mitglied) eigene Filterregeln bekommen.

**D5 Cluster: abgleichen, nicht doppelt vergeben**
- Neue Cluster-Bereiche in `cluster.go`, wie bei den anderen Standard aus:

| Bereich | Inhalt | nicht dabei |
|---|---|---|
| DHCP-Netze | Subnetz, Bereich, Optionen, Lease-Zeit, Domain | Schnittstelle, Schalter an/aus, Probelauf, Netze mit „nur diese Node“ |
| DHCP-Reservierungen | MAC → IP, Name, Gruppe | |

- Der Schalter „DHCP an“ bleibt **je Node** und wird nicht abgeglichen. Das passt zur Entscheidung, dass die
  Cluster-Schalter je Node bleiben.
- Option 6 (DNS) bietet im Cluster wahlweise **alle DNS64-Nodes** an (diese zuerst). Fällt eine Node aus, fragen
  die Clients die zweite. Das ist die eigentliche Ausfallsicherheit für das Heimnetz, auch ohne DHCP-Failover.
- Schutz vor zwei aktiven Servern: Sind zwei Nodes im Cluster für dasselbe Subnetz aktiv (ohne Reserve aus D6),
  zeigt die Cluster-Seite einen Fehler, und die zweite Node bleibt im Probelauf.

**D6 Reserve-Node (beschlossen, nach D5)**
- Eine zweite Node mit demselben Netz läuft als „Reserve“. Jede Vergabe geht sofort über den Cluster an die Reserve
  (Leases als eigener Kanal, nicht als Bereich).
- Die Reserve antwortet nur, wenn die Haupt-Node wirklich weg ist: kein Mitglied mit dem Bereich „DHCP-Netze“
  im Cluster erreichbar (2 Minuten) **und** keines hat in den letzten 3 Minuten als DHCP-Server geantwortet (die
  Reserve sucht jede Minute). Ohne Mitglied mit diesem Bereich bleibt sie still. Das `secs`-Feld zählt bei der
  Umsetzung nicht mit: Viele Geräte senden dort immer 0, die Reserve spränge dann nie ein. Doppelte Vergaben fangen
  ARP-Probe und DECLINE ab.

## Stand der Umsetzung (1.36.0)

- Paket `internal/dns64/dhcp` (Vergabe, Sockets mit `SO_BINDTODEVICE`, ARP-Probe per `AF_PACKET`, Suche nach fremden
  Servern über Port 68 mit 6 s Wartezeit, weil dnsmasq/ISC vor dem Angebot bis 3 s pingen), DNS64-Teil in
  `dhcp.go`/`dhcp_ui.go`, Seite `templates/pages/dhcp.html`, Menüpunkt in `internal/web/view.go`.
- Schalter `dns64.dhcp` (off/observe/on) je Node; DHCP läuft neben dem DNS-Dienst und startet nur bei Änderungen an
  Netzen/festen Adressen neu (Anfragen, Sperren und Funde bleiben dabei erhalten).
- Benachrichtigung `dns64_dhcp`: fremder DHCP-Server, Netz zu 90 % belegt.
- Getestet: Einheitstests, echte Sockets im Test-Container (veth + Namensraum, Client udhcpc, fremder Server dnsmasq),
  Oberfläche lokal (Desktop und Handy).

## Stand D3–D6 (1.37.0)

- D3: Namen aus Vergaben und festen Adressen nur im Speicher (`dhcp_names.go`), gebaut aus node64.db – also auch auf
  Nodes ohne eigenen DHCP-Server. Reihenfolge in `Lookup`: eigene Einträge, DHCP-Namen, Platzhalter, dann Zonen.
  Client-Namen: Gruppe, PTR (auch DHCP), sonst Name vom Gerät. MAC/IP der Vergaben gehen an `groups.Resolver`
  (`SetLeases`). Gerätegruppe beim Anlegen einer festen Adresse = normales Gruppen-Mitglied (MAC).
- D4: Relay-Netze ohne eigene Adresse im Netz (Schalter „Netz hinter einem DHCP-Relay“, Spalte `relay`, Migration
  0017): Server-ID = Adresse der Node auf der Schnittstelle, keine ARP-Prüfung, mehrere je Schnittstelle.
- D5: Bereiche `dhcp_scopes` (s:<Netz>), `dhcp_reservations` (r:<Netz>|<MAC>), `dhcp_leases` (l:<Netz>|<MAC>) in
  `dhcp_cluster.go`; neue Netze aus dem Cluster kommen aus und mit erratener Schnittstelle an. Netz je Node nur einmal.
  DNS leer: nach dieser Node die anderen Nodes mit dem Bereich „DHCP-Netze“ in diesem Netz (Adresse aus der URL).
- D6: Rolle `dns64.dhcp_role` (primary/reserve) je Node. Jede Node meldet ihren DHCP-Zustand als `n:<Node-ID>` im
  Bereich „DHCP-Netze“ (Rolle, Schalter, Server-ID je eingeschaltetem Netz, IPv4-Adressen mit DNS64 auf Port 53;
  Tabelle `dns64_dhcp_nodes`, Migration 0018). `Server.Standby(Netz)`: still, solange eine Haupt-Node für genau
  dieses Netz lebt (im Cluster erreichbar oder ihre Server-ID antwortete in den letzten 3 Minuten); ohne Haupt-Node
  für das Netz ebenfalls still; 10 s zwischengespeichert. Zwei Haupt-Nodes im selben Netz: Hinweis und
  Benachrichtigung. Vergaben aus dem Cluster mit Altersvergleich (`clApplyLease`), Löschungen per `Server.Forget`.
  Prüf-DISCOVER tragen Option 60 `node64-probe`: andere Nodes antworten, merken sich aber nichts.

## Bewusst nicht dabei (vorerst)

- DHCPv6 und Router Advertisements: IPv6 läuft im Heimnetz über SLAAC des Routers. Den DNS-Server dafür verteilt
  der Router (RDNSS). Kann später als „RA mit RDNSS“ kommen, falls gefragt.
- Freie DHCP-Optionen (nur die festen Felder inkl. PXE).
- Option 82 (Relay-Agent-Info), Klassen/Vendor-Regeln, DDNS an fremde DNS-Server (dafür gibt es RFC 2136 an DNS64),
  MAC-Herstellerliste.
- Online-Teil: Leases bleiben lokal. ipv64.net bekommt höchstens Zähler (Netze, Leases), falls gewünscht.

## Versionen und Doku

- D1+D2 als DNS64 1.36.0 (Probelauf und Schalter in derselben Version), D3 1.37.0, D4/D5 danach.
- Changelog DNS64 DE/EN, öffentlicher CHANGELOG, Hilfe-Texte DE/EN. Der Webseiten-Sitzung den Commit melden
  (node64.de: Docs DNS64 → DHCP, API).
- Doku muss die Docker-Vorgabe deutlich zeigen: DHCP geht nur mit `network_mode: host` (oder macvlan).

## Entscheidungen (Dennis, 2026-11-09)

1. Paket `insomniacslk/dhcp/dhcpv4` für das Paketformat: ja.
2. DHCP bekommt einen eigenen Menüpunkt in der linken Navigation (kein Reiter unter Lokaler DNS).
3. Reserve-Node (D6): ja, sie antwortet nur, wenn die andere Node wirklich weg ist.
4. PXE/Netboot gleich in D2.
5. Kein eigenes Modul, sondern Teil von DNS64; opt-in, Standard aus, ohne Einschalten kein Port.
