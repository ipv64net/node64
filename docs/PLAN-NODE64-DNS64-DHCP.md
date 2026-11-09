# Plan: DHCP-Server in DNS64 (unter „Lokaler DNS“)

Stand 2026-11-09, **nur Plan, nichts umgesetzt.** Anlass: DHCP wird auf GitHub und im Forum immer wieder gewünscht
(Pi-hole und AdGuard Home haben ihn). Ziel: ein leichter DHCP-Server für Homelab und kleine bis mittlere Firmen, der
Hand in Hand mit dem lokalen DNS arbeitet. Grundlagen: [PLAN-NODE64-DNS64-LOKAL.md](PLAN-NODE64-DNS64-LOKAL.md),
[PLAN-NODE64-DNS64-GRUPPEN.md](PLAN-NODE64-DNS64-GRUPPEN.md), [CLUSTER.md](CLUSTER.md).

## Leitlinien

- **Leicht:** nur IPv4-DHCP (RFC 2131/2132), keine DHCPv6, kein ISC-Failover-Protokoll und keine freien
  Boot-Skripte. Was ein Router-DHCP kann, plus die Verbindung zum DNS. Mehr kommt nicht hinein.
- **Standard aus.** Ein zweiter DHCP-Server im Netz macht Ärger. Deshalb erst einschalten, wenn kein fremder Server
  mehr antwortet, oder bewusst bestätigen.
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

**Datenbank** (Migration `0016_dhcp.sql`, DNS64-SQLite):

| Tabelle | Inhalt |
|---|---|
| `dhcp_scopes` | id, Name, Schnittstelle, Subnetz, Bereich von–bis, Router, DNS-Server (leer = diese Node), Domain, Lease-Zeit, NTP, autoritativ, an/aus, nur diese Node |
| `dhcp_reservations` | scope_id, MAC, IP, Name, Kommentar, Gerätegruppe (optional), an/aus |
| `dhcp_leases` | scope_id, MAC, IP, Hostname (vom Client), Name (bereinigt), Beginn, Ablauf, Zustand (angeboten/vergeben/abgelehnt/frei) |

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

**D2 Oberfläche: Reiter „DHCP“ unter Lokaler DNS** (neben Zonen und Weiterleitungen in `localTabs`)
- Karte je Netz: Schnittstelle, Subnetz, Bereich, Auslastung als Balken (vergeben/reserviert/frei), Schalter,
  Probelauf, Hinweise (Bridge-Netz, fremder Server, Pool fast voll).
- Lease-Tabelle: Name, IP, MAC, läuft ab, Herkunft (Lease/Reservierung). Suche wie bei den Einträgen. „Reservieren“
  per Klick aus einem Lease, „Freigeben“.
- Reservierungen: MAC → IP, Name, Kommentar, Gerätegruppe. Import aus dnsmasq/Pi-hole (`dhcp-host=…`) und CSV,
  Export als CSV.
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

**D6 Reserve-Node (später, eigener Schritt)**
- Eine zweite Node mit demselben Netz läuft als „Reserve“. Jede Vergabe geht sofort über den Cluster an die Reserve
  (Leases als eigener Kanal, nicht als Bereich).
- Die Reserve antwortet nur, wenn die Haupt-Node im Cluster nicht erreichbar ist **oder** der Client laut
  `secs`-Feld schon ≥ 10 s wartet. Das ist der bekannte Kniff aus ISC dhcpd und kommt ohne Failover-Protokoll aus.
  Doppelte Vergaben fangen ARP-Probe und DECLINE ab.
- Erst bauen, wenn D1–D5 im Einsatz sind und danach gefragt wird.

## Bewusst nicht dabei (vorerst)

- DHCPv6 und Router Advertisements: IPv6 läuft im Heimnetz über SLAAC des Routers. Den DNS-Server dafür verteilt
  der Router (RDNSS). Kann später als „RA mit RDNSS“ kommen, falls gefragt.
- PXE/Netboot (Optionen 66/67) und freie Optionen. Siehe offene Entscheidung 3.
- Option 82 (Relay-Agent-Info), Klassen/Vendor-Regeln, DDNS an fremde DNS-Server (dafür gibt es RFC 2136 an DNS64),
  MAC-Herstellerliste.
- Online-Teil: Leases bleiben lokal. ipv64.net bekommt höchstens Zähler (Netze, Leases), falls gewünscht.

## Versionen und Doku

- D1+D2 als DNS64 1.36.0 (Probelauf und Schalter in derselben Version), D3 1.37.0, D4/D5 danach.
- Changelog DNS64 DE/EN, öffentlicher CHANGELOG, Hilfe-Texte DE/EN. Der Webseiten-Sitzung den Commit melden
  (node64.de: Docs DNS64 → DHCP, API).
- Doku muss die Docker-Vorgabe deutlich zeigen: DHCP geht nur mit `network_mode: host` (oder macvlan).

## Offene Entscheidungen (Dennis)

1. Paket `insomniacslk/dhcp/dhcpv4` für das Paketformat oder eigener Parser? Empfehlung: das Paket.
2. Reserve-Node (D6) gleich mitplanen oder erst nach Rückmeldungen? Empfehlung: erst später. D5 (Abgleich + alle
   DNS-Nodes in Option 6) deckt das Meiste ab.
3. PXE/Netboot (Optionen 66/67, z. B. netboot.xyz) schon in D2 als einfache Felder je Netz? Im Homelab gern
   gefragt, kostet wenig. Empfehlung: ja, als zwei optionale Felder, aber keine freien Optionen.
