# Plan: IPAM64 (IP-Adressverwaltung)

Stand 2026-11-14, **Entwurf, noch nichts umgesetzt; wartet auf Dennis' Entscheidungen (unten).** Anlass: Das
Community-Mitglied UlrichSchwarz hat ein Modul IPAM64 gebaut (Repo `UlrichSchwarz/node64-redesign`, Zweig
`claude/inspiring-hamilton-dpu6g9`, 2 Commits auf Basis 1.5.9). Vorbild ist der IP-Teil von Netbox. Räume, Racks und
Geräteinventar gehören nicht dazu. IPAM64 soll nahtlos mit DNS64 (Filter), dem lokalen DNS und dem DHCP-Server von DNS64
zusammenarbeiten. Grundlagen: [PLAN-NODE64-DNS64-DHCP.md](PLAN-NODE64-DNS64-DHCP.md),
[PLAN-NODE64-DNS64-LOKAL.md](PLAN-NODE64-DNS64-LOKAL.md), [PLAN-NODE64-CLUSTER-MODULE.md](PLAN-NODE64-CLUSTER-MODULE.md).

Klickbare Vorschau (Beispieldaten, nicht gebaut): https://claude.ai/artifact/8DJdoWH7ioX463yxdJpq4g

## Leitlinien

- **Keine zweite Liste.** DHCP-Reservierungen, Leases und lokale DNS-Einträge bleiben in DNS64. IPAM64 legt nur das
  ab, was DNS64 nicht hat: Präfixe, Adressbereiche, Status, Rolle, Beschreibung, Tags und Sichtungen. Schlüssel ist die
  IP. Eine Reservierung, die man in DNS64 anlegt, erscheint sofort als IPAM-Adresse, und umgekehrt.
- **IPAM64 schreibt in DNS64, aber nur über dessen öffentliche Funktionen** (`AddDHCPReservation`, `AddRecord` …).
  Dadurch laufen Prüfung, Neustart des DHCP-Servers, Cluster-Abgleich und Audit wie bisher. Eigene DNS-Einträge
  bekommen `origin = 'ipam64'` (wie `docker`). In DNS64 tragen sie dann den Hinweis „IPAM64“ und verweisen zum
  Bearbeiten auf IPAM64.
- **Eigenes Modul** `internal/ipam64` (Order 45, direkt nach DNS64), Standard aus. Ohne DNS64 läuft es nur
  anzeigend (Netze, Adressen, Scan).
- Wortwahl wie in DNS64: „Netz“ für ein DHCP-Netz, „Adressbereich“ statt „Bereich“ (der Begriff gehört dem Cluster).
- Nur was ein Heimnetz oder eine kleine Firma braucht (Maßstab Netbox, siehe unten). Kein DCIM.

## Bestand

### Community-Zweig (gelesen, nicht ausgeführt)

- **Daten:** `ipam_networks` (Subnetz, Name, VLAN, Schnittstelle, Router, Adressbereich eines fremden DHCP-Servers),
  `ipam_addresses` (IP, MAC, Name, Kommentar), `ipam_seen` (IP, MAC, erstmals und zuletzt gesehen, 30 Tage). Nur
  IPv4, Netze /20 bis /30.
- **Zusammenführung zur Laufzeit** (`merge.go`) mit festem Rang der Quellen: von Hand, Node selbst, DHCP-Reservierungen
  und Leases, lokale A-Einträge, Monitor64-Hosts, Healthchecks, PROXY64-Ziele, ARP. Konflikt: zwei MACs in 15 Min. oder
  MAC passt nicht zur Zuweisung.
- **Nachbartabelle** per Netlink (`neigh.go`/`neigh_linux.go`), ohne Zusatzpaket, mit Test.
- **Scan:** UDP-Paket an Port 9 je Adresse, danach Nachbartabelle lesen. Keine Rechte nötig. Nur in Netzen, an denen
  die Node eine Adresse hat. Läuft synchron im Request, ein Scan zur Zeit.
- **Oberfläche:** eine Seite `/ipam64` (KPIs, Netzliste, Adresskarte, Liste mit Filter), CSV-Export mit Schutz gegen
  Formel-Injektion, Dashboard-Karte. **API:** nur lesend (Netze, Adressen) plus Scan.
- **Konventionen:** `module.Info`, Modul-Changelogs, Root-Changelog, Audit-Bereich `ipam64`, i18n DE/EN vollständig,
  OpenAPI, CSS über gemeinsame Variablen. Prepared Statements, CSRF, Eingabeprüfung über `netip`/`net.ParseMAC`.
- **Lücken:** schreibt nichts in DNS64 (Reservieren landet nur in der eigenen Tabelle), kein Cluster-Abgleich, kein
  `Exporter`, kein IPv6, keine Präfix-Hierarchie, keine Status, kein Cache (`Snapshot` holt bei jedem Aufruf alle
  Quellen neu), nicht an einem echten Netz geprüft. Basis 29 Commits hinter `main` (kleine Konflikte in
  `audit_areas.go`, `storetest.go`, `main.go`).
- **Risiken:** Scan nimmt auch öffentliche Netze an (VPS mit `network_mode: host` würde Nachbarn beim Hoster
  ansprechen); ein /20-Scan erzeugt 4094 Nachbareinträge, mehr als `gc_thresh3` (1024) des Hosts; Fehlalarme bei
  Konflikten (DHCP-Wechsel, Repeater mit MAC-NAT).

### Node64 heute (DNS64 1.40.1)

- **DHCP:** `dns64_dhcp_scopes` (ein Netz je Schnittstelle, **ein** Adressbereich, keine Ausnahmen, nur IPv4),
  `dns64_dhcp_reservations` (Netz, MAC, IP, Name), `dns64_dhcp_leases` (ein Datensatz je Netz und MAC, keine
  Historie). Kein DHCPv6, nur RA mit RDNSS/DNSSL. Cluster-Abgleich für Netze, Reservierungen und Leases vorhanden.
- **Lokaler DNS:** `dns64_records` (A, AAAA, CNAME, TXT, MX, SRV, PTR, CAA; `no_ptr`, `origin`), `dns64_zones`.
  PTR entsteht automatisch aus A/AAAA. DHCP-Namen liegen nur im Speicher (A + PTR, kein AAAA).
- **Geräte:** `groups.Resolver` (Nachbartabelle alle 30 s, MAC ↔ IP), Abfrage-Log mit Client-Namen, `NetDevices`.
  Keine Herstellerliste (OUI).
- **Weitere Adressen als Freitext:** `m64_hosts.address`, `cdn64.Host.TargetHost`, `cdn64.Stream.TargetHost`,
  `healthchecks.Check.Target`.
- **Rechte:** Rollen Administrator und „Nur lesen“; `Guards.Auth` sperrt schreibende Methoden zentral, `app.js` graut
  Formulare aus. Module brauchen dafür nichts Eigenes.
- **Fehlende öffentliche Getter in DNS64:** Leases (`dhcpActiveLeases`), DHCP-Namen (`dhcpDNSName`), Pool-Belegung.

### Maßstab Netbox (nur IP-Teil)

| Muss (v1) | Kann (später) | Weglassen |
|---|---|---|
| Präfixe mit automatischer Hierarchie, Status Container/Aktiv/Reserviert/Veraltet, „gilt als voll“ | VRF bzw. Namensraum für überlappende Netze | Aggregates/RIRs, ASNs, Route Targets |
| Adressbereiche (DHCP-Pool zählt als belegt) | NAT innen/außen, Services aus Healthchecks/PROXY64 | FHRP-Gruppen als Objekt (Rolle VIP genügt) |
| Adressen: Status, DNS-Name, MAC, Rolle, Tags, Beschreibung | Custom Fields, Tenants | Zuordnung zu Interfaces/Geräten (DCIM) |
| VLAN-Feld am Präfix, Auslastung rekursiv, freie Blöcke | VLAN-Gruppen | |
| „Nächste freie Adresse“ in Oberfläche und API (atomar) | Import aus phpIPAM/Netbox | |
| Verlauf je Objekt (über das Audit), CSV-Export und -Import | | |

Was Netbox nicht hat und ein Heimnetz braucht: Erkennung (Nachbartabelle, „zuletzt gesehen“), Abgleich mit
DHCP-Leases, DNS-Eintrag automatisch, Konflikterkennung, Hersteller aus der MAC und **IPv6 mit wechselndem
Provider-Präfix**. Gerade das Letzte hat kein anderes IPAM und wäre ein Alleinstellungsmerkmal.

## Bewertung: übernehmen, umbauen oder neu bauen

**Empfehlung: den Community-Code als Grundlage übernehmen und umbauen, nicht neu bauen.** Die Architektur
(Zusammenführung zur Laufzeit, nur lesende Eingriffe in bestehende Module, Standard aus) passt zu Node64. Der Code ist
sauber, getestet und hält die Konventionen weitgehend ein. Weiterverwenden: `neigh*.go`, `merge.go`, `store.go`
(Prüfung), `cmd/node64/ipam.go` (Verdrahtung), `DHCPLeases()`/`ProxyTargets()`, Template mit Adresskarte, i18n, Tests.
Neu bzw. umzubauen: Datenmodell (Präfixe, Adressbereiche, Status, IPv6), schreibende Verzahnung, Cluster,
Scan-Grenzen. Grob die Hälfte des Codes bleibt, die andere Hälfte kommt neu dazu.

Übernahme sauber im Container-Baum: Dateien von Hand auf aktuellen `main` übertragen (kein Merge des fremden Repos),
Urheber in den Commits als `Co-Authored-By` und im Modul-Changelog nennen. Lizenz des fremden Repos vorher prüfen
(Spiegel von Node64, gleiche Lizenz erwartet).

## Phasen

### I1 Übernahme und Härtung (IPAM64 0.1.0, nur IPv4, lesend)
- Code auf `main` übertragen, Konflikte lösen, Audit-Bereich, `storetest`-Scope.
- Scan nur in privaten Netzen (RFC 1918, CGNAT 100.64/10, Link-Local), höchstens /22; asynchron mit Fortschritt statt
  im Request; `Snapshot` 15 s zwischenspeichern.
- Cluster: `peer.Provider` für Netze und Adressen (nicht für Sichtungen, die bleiben je Node); `module.Exporter`.
- Prüfung an einem echten Netz (agentbox, Host-Netz), Checkliste aus der Anleitung des Community-Zweigs.

### I2 Verzahnung mit DNS64 (schreibend)
- DNS64: öffentliche Getter für Leases, DHCP-Namen und Pool-Belegung; `origin = 'ipam64'` für Einträge.
- Adresse anlegen/ändern: DHCP-Reservierung über `AddDHCPReservation`, A + PTR (und AAAA) über `AddRecord`; Seite
  „Beim Speichern passiert“ zeigt die Folgen vorher an (wie in der Vorschau).
- Lease → feste Adresse mit einem Klick (gibt es in DNS64 schon als `leases/reserve`, hier mit Name und DNS).
- DNS64-Seiten: Hinweis „IPAM64“ an verwalteten Einträgen und Reservierungen, Link zum Bearbeiten.
- **Neu in DNS64:** Ausnahmen im Adressbereich (feste Adresse im Pool, Konflikt „Lease gegen feste Adresse“).
  Betrifft auch den Cluster-Abgleich der DHCP-Netze. Eigene DNS64-Version.
- Konflikte: doppelte Adresse, Lease gegen feste Adresse, statische Adresse im Pool, DNS-Eintrag ohne Gerät, fremder
  DHCP-Server (aus DNS64). Dämpfung gegen Fehlalarme (DHCP-Wechsel, Repeater).

### I3 Präfixe und IPv6
- Präfix-Hierarchie aus den CIDRs, Status, VLAN-Feld, Adressbereiche, Auslastung rekursiv (IPv6 in /64-Zählung),
  freie Blöcke in Baum und Liste, „nächste freie Adresse“ (UI und `POST /api/ipam64/prefixes/{id}/available-ips`).
- IPv6 relativ: Präfix-ID + Interface-ID; aktuelles Provider-Präfix aus DynDNS64 bzw. der Schnittstelle. Beim Wechsel
  AAAA, PROXY64-Ziele, Monitor64-Hosts und Healthchecks nachziehen (Audit „IPv6-Präfix gewechselt“).

### I4 Komfort
- Herstellerliste (OUI) im Image, zufällige MACs erkennen; Benachrichtigung bei neuen Geräten und Konflikten;
  CSV-Import mit Vorschau; Verlauf je Adresse; MCP (lesend) und Prometheus.

## Offene Entscheidungen für Dennis

1. **Übernehmen und umbauen** (Empfehlung) oder neu bauen?
2. **Menü:** eigenes Modul nach DNS64 (Vorschau) oder Unterpunkt von DNS64 neben „Lokaler DNS“ und „DHCP“?
3. **Ausnahmen im DHCP-Adressbereich** in DNS64 einbauen (nötig für feste Adressen im Pool)?
4. **Aktiver Scan** (UDP-Sweep) ja, oder nur passiv über Nachbartabelle, Leases und Abfrage-Log?
5. **IPv6 relativ** schon in v1 oder erst in I3?
6. **Herstellerliste (OUI):** rund 1–2 MB im Image vertretbar?
7. **Umgang mit dem Community-Mitglied:** Übernahme mit Nennung als Co-Autor; wer meldet sich bei ihm (nicht diese
   Sitzung)?
