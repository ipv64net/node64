# Änderungen – DNS64

## 1.31.1 – 2026-10-30

### Behoben
- Klassische DNS-Server mit Link-Local-Adresse und Zone (`fe80::1%eth0`) als Upstream oder Weiterleitung funktionieren;
  vorher scheiterten alle Anfragen an sie still.
- Seite Verschlüsselt: Aufruf über eine IPv6-Adresse ohne Port (`[fd00::5]`) ergibt wieder gültige DoH-/DoQ-Adressen und
  ein gültiges iOS-Profil.
- Rückwärtssuche für die globalen IPv6-Adressen des eigenen Heimnetzes geht an den Router statt an öffentliche
  Upstreams (wenn ein Router bekannt ist); `fc00::/8` und `::1` gelten ebenfalls als lokal.
- DoH/DoQ über Link-Local-Adressen: Gruppenregeln greifen wieder.
- Eigene AAAA-Einträge mit Zone oder `::ffff:`-Adresse werden abgelehnt.
- Netze in Gruppen und weitere Client-Netze als `::ffff:`-Präfix werden in IPv4-Netze umgerechnet (trafen vorher nie).
- Einstellungen: Hinweis, wenn eine feste Adresse eingetragen ist – Geräte der anderen IP-Familie bekommen dann kein DNS.
- Anzeige des Router-DNS ohne eckige Klammern bei IPv6.

## 1.31.0 – 2026-10-28

### Behoben
- Eigener CNAME und Umschreiben, die aufeinander zeigen, beenden den Dienst nicht mehr (SERVFAIL).
- DNSSEC-Abfragen zu Top-Level-Domains (DS/DNSKEY/NS/SOA, z. B. „com“) gehen an die Upstreams; Gerätenamen ohne Punkt
  gehen weiter an den Router.
- Neustart nach Einstellungen lässt DNS nicht mehr aus, wenn das Stoppen hängt oder die Anfrage abbricht.
- Cache: CD-Bit getrennt, NXDOMAIN/NODATA hinter CNAME nur kurz (SOA, höchstens 5 Minuten), Speicher-Budget, Antworten
  über 16 KB werden nicht gespeichert.
- Unverschlüsselte Upstreams (dns://) bekommen eine zufällige Anfrage-ID.
- Dynamische Updates (RFC 2136) werden ganz oder gar nicht angewendet; Cluster meldet keine falschen Löschungen mehr.

## 1.30.0 – 2026-10-26

### Geändert
- Upstream-Betriebsart „Schnellste“: gleichzeitig gefragt werden jetzt wahlweise 1–6 Server (bisher 1–3, Standard
  bleibt 2).

## 1.29.1 – 2026-10-26

### Geändert
- Handy: Abfrage-Log, Upstream-Liste in den Einstellungen, eigene DNS-Einträge, Weiterleitungen, Umschreiben, Geräte
  und Mitglieder der Gruppen zeigen je Eintrag eine Karte statt einer breiten Tabelle;
  die Upstream-Karten der Übersicht brechen IP-Adressen und URL um, statt aus dem Bild zu laufen.


## 1.29.0 – 2026-10-26

### Neu
- Eigene Sperrliste: Domains (samt Subdomains) selbst sperren – mit dem Knopf „Blockieren“ im Abfrage-Log oder in der
  neuen Karte unter „Freigegebene Domains“. Sie gilt für alle Geräte zusätzlich zu den Blocklisten; eine Freigabe
  derselben Domain hebt die Sperre auf, eine genauere Freigabe (z. B. cdn.example.com) gewinnt. Im Cluster als eigener
  Bereich abgleichbar, im Export enthalten.
- Eigener Upstream als einfacher DNS-Server: nur die IP-Adresse eintragen (z. B. 8.8.8.8, Port 53, oder IP:Port).
  In der Liste als „DNS (unverschlüsselt)“ gekennzeichnet.
- „Anfragen im Zeitverlauf“ mit eigenem Zeitraum am Diagramm: 30 min, 6 h, 24 h, 7 Tage.

### Geändert
- Abfrage-Log: Fragt ein Gerät eine öffentliche Domain mit angehängter lokaler Suchdomain an (z. B.
  example.com.home.local), steht dabei „Suchdomain vom Gerät angehängt“. Das macht das Gerät selbst, meist nachdem die
  eigentliche Anfrage scheiterte (z. B. SERVFAIL, weil die Upstreams kurz nicht antworteten) – DNS64 hängt nichts an.

## 1.28.1 – 2026-10-24

### Neu
- Docker-Bridge-Netz: DNS64 prüft über das Docker-Gateway, ob seine Ports auf dem Host veröffentlicht sind (Prüfname
  per UDP, TCP, DoT, DoQ bzw. DoH an Gateway:Port – ein veröffentlichter Port führt zurück in den Container). Fehlt
  einer, steht das in der Port-Übersicht und als Warnung auf Übersicht, Abfrage-Log, Einstellungen und Verschlüsselung,
  mit Beispiel für `docker run` (`-p 53:53/udp -p 53:53/tcp`) und `compose` (`ports:`) bzw. `network_mode: host`.
  Geprüft kurz nach dem Start und alle 30 Minuten; im Host-Netz entfällt die Prüfung.
- Abfrage-Log: Hinweise, warum Client-Adressen fehlen oder gleich aussehen – Anfragen mit der Adresse des
  Docker-Gateways (Docker ersetzt den Absender), abgewiesene Anfragen aus nicht erlaubten Netzen (stehen nicht im Log,
  z. B. weiteres VLAN oder im Bridge-Netz das öffentliche IPv6 des Heimnetzes) und gekürzte bzw. nicht gespeicherte
  Client-Adressen.

## 1.28.0 – 2026-10-23

### Geändert
- Übersicht, Dashboard-Karte und Geräteliste bleiben auch bei Millionen Log-Einträgen schnell: Beim Schreiben des
  Abfrage-Logs führt DNS64 Zähler je Minute und Häufigkeiten je Domain und Client je Stunde mit; Kennzahlen, Verlauf
  und Top-Listen lesen nur noch diese (vorher bei jedem Aufruf alle Einträge des Zeitraums gezählt, mit „context
  canceled“ und langen Ladezeiten). Beim Update baut DNS64 die Zähler einmal aus dem vorhandenen Log.
- Die Log-Seite zählt Treffer höchstens bis 100.000 und zeigt dann „100.000+“.

## 1.27.4 – 2026-10-23

### Behoben
- Anfragen des Routers selbst (1.27.2): Auch über Umschreiben, eigene CNAME-Einträge, SafeSearch und geteilten DNS
  geht ein lokales Ziel nicht mehr an den Router zurück (sonst konnte die Anfrage kreisen).

## 1.27.3 – 2026-10-23

### Behoben
- Router-Suche (1.27.2): Prüfnamen `*.node64-probe.invalid` von fremden Geräten werden weiter sofort beantwortet, aber
  nicht mehr gemerkt – nur die gerade selbst verschickten (sonst wuchs der Speicher mit jeder solchen Anfrage).

## 1.27.2 – 2026-10-23

### Behoben
- Docker im Bridge-Netz mit veröffentlichtem Port 53: Die Router-Suche fand das Docker-Gateway (z. B. 172.17.0.1),
  das die Anfrage aber zurück in den Container leitete – lokale Namen und die Rückwärtssuche der Client-Namen (PTR)
  liefen dadurch endlos im Kreis (Millionen PTR-Anfragen von 172.17.0.1, volle CPU, langsames Dashboard). Die Suche
  erkennt jetzt mit einem Prüfnamen, wenn der Kandidat die Node selbst ist, und nimmt ihn nicht.
- Allgemeiner Schleifenschutz: Anfragen, die vom Router selbst kommen (z. B. Router mit Node64 als Upstream), gehen
  für lokale Namen nicht wieder an den Router zurück.

## 1.27.1 – 2026-10-22

### Behoben
- Import vieler Einträge (Hosts-Datei, CSV, JSON, Zonendatei) in einer Transaktion: 5000 Einträge in Sekundenbruchteilen
  statt Minuten (vorher je Eintrag alles neu geladen; ein Import von 3000 brach nach 20 s mit dem Client ab).
- Cluster mit tausenden Einträgen: Die liefernde Node gibt den Stand aus dem zuletzt gemeldeten Stand, die
  übernehmende schreibt gezielt und baut die DNS-Tabelle gebündelt neu – 3000 Einträge in 0,2 s statt rund 45 s.

## 1.27.0 – 2026-10-22

### Neu
- Eigener Menüpunkt **„Lokaler DNS“** unter DNS64 (Reiter Zonen und Weiterleitungen); DNS64 selbst bleibt der
  Werbeblocker. Die alten Adressen `/dns64/records` und `/dns64/forwards` leiten weiter.
- Zonen-Ansicht (L5): Zonen links mit Zahl der Einträge, „Alle Einträge“ und „Ohne Zone“; Einträge der gewählten
  Zone rechts, Name relativ zur Zone (`@` = die Zone selbst). Je Zone einstellbar: Standard-TTL, SOA (Refresh, Retry,
  Expire, TTL für „nicht vorhanden“, verantwortliche Mail). Ein Netz wie `192.168.1.0/24` wird zur Rückwärtszone.
- Zonendatei (L6): Export je Zone im BIND-Format (`$ORIGIN`, `$TTL`, SOA, NS, relative Namen, Kommentare); Import von
  Zonendateien (z. B. aus Bind, Technitium, Windows-DNS) über denselben Import wie Hosts-Datei/CSV/JSON – SOA-Werte
  gehen an die Zone, NS und nicht unterstützte Typen werden übersprungen.
- Dynamische Updates nach RFC 2136 (L7): je Zone einschaltbar mit TSIG-Schlüssel (HMAC-SHA256, von der Node erzeugt,
  erneuerbar). DHCP-Server wie pfSense, OPNsense oder Kea tragen Namen selbst ein (A, AAAA, CNAME, TXT, PTR, SRV, MX,
  DHCID); Vorbedingungen und Löschen nach RFC, alles oder nichts. Ohne gültigen Schlüssel, außerhalb der Zone oder für
  SOA/NS wird abgelehnt. Per Update angelegte Einträge sind markiert; der Schlüssel bleibt auf der Node (nie in API,
  Export oder Cluster).
- API: `GET /api/dns64/zones/{id}/zonefile`, `POST /api/dns64/records/import?zone=…` (auch Zonendateien).

## 1.26.0 – 2026-10-22

### Neu
- DNS64 im Cluster (Phase L4): Unter „Cluster“ erscheint DNS64 mit sieben Schaltern, alle ohne Einstellung aus –
  Einstellungen (Upstreams, Modus, Blockier-Art, Cache, Anonymisierung, Aufbewahrung, Firefox, Meldungen),
  Blocklisten, Freigaben, eigene Einträge samt lokalen Zonen, Weiterleitungen samt Umschreiben, Gerätegruppen
  (Regeln, Kategorien, Kinderschutz, Domains, Zeitpläne, Sperren/Frei) und die Mitglieder der Gruppen (gehören zum
  Standort). Ein Bereich wird nur mit Nodes abgeglichen, bei denen er ebenfalls an ist; die jüngere Änderung gewinnt.
- „Nur diese Node“ je eigenem Eintrag und je Weiterleitung: wird nie abgeglichen, und ein gleicher Eintrag einer
  anderen Node überschreibt ihn nicht.
- Nie abgeglichen: Ports, Schnittstellen, Router, DoH/DoT/DoQ, Namen und Zertifikat, Client-Netze, Pause, Abfrage-Log.
- Gruppen haben eine Cluster-Kennung (`uid`); gibt es dieselbe Gruppe (gleicher Name) schon auf beiden Nodes, wird
  sie beim ersten Abgleich zusammengeführt.
- Eine Node übernimmt die Einträge auch, solange DNS64 bei ihr (noch) aus ist.

## 1.25.0 – 2026-10-22

### Neu
- Lokale Zonen (Phase L2, Karte „Lokale Zonen“ unter „Eigene Einträge“): Namen unter einer Zone wie `home.lan`
  beantwortet DNS64 selbst – eigene Einträge, SOA/NS der Zone und, wenn die Zone „zuständig“ ist, NXDOMAIN mit SOA
  für unbekannte Namen (sonst weiter an Weiterleitungen und Router).
- Gerätenamen: Geräte der Gerätegruppen mit Bezeichnung erscheinen als `<name>.<zone>` (z. B. „Tablet Lea“ →
  `tablet-lea.home.lan`) mit ihrer aktuellen IP aus der Nachbartabelle (MAC) bzw. der eingetragenen IP, samt
  Rückwärtssuche; je Zone abschaltbar. Die Karte zeigt die Namen mit ihren Adressen.
- Export/Import der Konfiguration nimmt die Zonen mit.
- API: `GET|POST /api/dns64/zones`, `PUT|DELETE /api/dns64/zones/{id}`, `POST /api/dns64/zones/{id}/enable|disable`, `GET /api/dns64/device-names`.

## 1.24.0 – 2026-10-22

### Neu
- Weiterleitungen (Phase L3, neuer Reiter „Weiterleitungen“): Domain → eigene DNS-Server, z. B. `firma.local` an den
  VPN-DNS oder `192.168.0.0/16` (wird zur Rückwärtszone) an den Router. Server als IP, IP:Port, `tls://`, `https://`
  oder `quic://`, der Reihe nach mit Ausfall auf den nächsten; die längste passende Domain gewinnt.
  Blocklisten und Gruppenregeln gelten weiter, außer für lokale Namen und die private Rückwärtssuche. Antwortet kein
  Server, gibt es SERVFAIL – der Name geht nie an die öffentlichen Upstreams. Testknopf je Weiterleitung (SOA),
  Statistik je Server, Grund „Weiterleitung … über …“ im Abfrage-Log.
- Umschreiben: Ein Name (auch `*.domain`) antwortet wie ein anderer; DNS64 löst das Ziel selbst auf und antwortet
  unter dem gefragten Namen ohne CNAME. Ketten werden verfolgt, Schleifen ergeben SERVFAIL.
- Export/Import der Konfiguration nimmt Weiterleitungen und Umschreiben mit.
- Prometheus: `node64_dns64_forward_up`, `node64_dns64_forward_requests_total`, `node64_dns64_forward_errors_total` (`domain`, `server`).
- API: `GET|POST /api/dns64/forwards`, `PUT|DELETE /api/dns64/forwards/{id}`, `POST /api/dns64/forwards/{id}/enable|disable|test`,
  `GET|POST /api/dns64/rewrites`, `PUT|DELETE /api/dns64/rewrites/{id}`, `POST /api/dns64/rewrites/{id}/enable|disable`.

## 1.23.0 – 2026-10-22

### Neu
- Eigene Einträge als lokaler DNS-Server (Phase L1, Plan `docs/PLAN-NODE64-DNS64-LOKAL.md`):
  - Weitere Typen TXT, MX, SRV, PTR (Name darf die IP sein) und CAA; Werte werden geprüft und vereinheitlicht.
  - Bearbeiten im selben Formular, Kommentar je Eintrag, Rückwärtssuche (PTR) je A/AAAA-Eintrag abschaltbar.
  - Import aus Hosts-Datei, CSV oder JSON (Text oder Datei; localhost- und 0.0.0.0-Zeilen werden übersprungen),
    Export als Hosts-Datei, CSV oder JSON; Suche in der Liste.
  - API: `PUT /api/dns64/records/{id}`, `POST /api/dns64/records/import`, `GET /api/dns64/records/export?format=hosts|csv|json`.

## 1.22.3 – 2026-10-22

### Behoben
- Start hing (ganze Node ohne Oberfläche), wenn DNS64 beim Start eine Route am gemeinsamen Eingang anmeldete
  (Hinweisseite einer Gruppe mit Zeitplan „Internet aus“, DoH über Port 443) und der Eingang dafür Port 80/443 erst
  öffnen musste: seine Port-Prüfung fragte DNS64 und wartete auf den laufenden Start. Die Port-Übersicht liest den
  Stand jetzt ohne diese Sperre.

## 1.22.2 – 2026-10-21

### Behoben
- Blocklisten: Dateien entfernter Listen unter `/data/dns64/lists/` werden beim Start gelöscht und sammeln sich
  nicht mehr an (eingestellte Listen, auch ausgeschaltete und die der Gruppen, bleiben).
- Port-Übersicht (Einstellungen › Ports): DNS, DoH, DoT und DoQ melden ihren Startfehler (z. B. „permission denied“ oder Zertifikat fehlt).

## 1.22.1 – 2026-10-21

### Behoben
- Startseiten-Karte: „Blockieren pausiert bis“ zeigt die Uhrzeit in der Zeitzone der Node (vorher die des Containers,
  meist UTC), an einem anderen Tag mit Datum.

## 1.22.0 – 2026-10-21

### Geändert
- Standard-Upstreams für neue Installationen: Cloudflare und Quad9 (DoH) und dazu dnsforge per DoQ und DoH (Server nur in Deutschland). Bestehende Installationen behalten ihre Auswahl; dnsforge lässt sich dort unter *Upstream-Server* anhaken.

## 1.21.0 – 2026-10-20

### Neu
- Europäische Upstream-Vorlagen, jeweils die ungefilterte Variante (DNS64 filtert selbst):
  - DNS4EU (Whalebone, Tschechien, von der EU kofinanziert): DoH und DoT, `unfiltered.joindns4.eu`;
  - dnsforge (adminForge, Server nur in Deutschland): DoH, DoT und DoQ, Variante „Blank“ `blank.dnsforge.de`;
  - Freifunk München (Deutschland, zweiter Standort Wien): DoH, DoT und DoQ (`doh.ffmuc.net`, `dot.ffmuc.net`, `doq.ffmuc.net`);
  - Digitalcourage (Deutschland): nur DoT, `dns3.digitalcourage.de`.
- Die Vorlagen erscheinen bei bestehenden Installationen ausgeschaltet; der Standard für neue Installationen bleibt Cloudflare + Quad9. DNS0.EU fehlt, weil der Dienst eingestellt ist.

## 1.20.0 – 2026-10-19

### Neu
- Gerätegruppen, Phase G5:
  - Prometheus: `node64_dns64_group_queries_total{group,status}`, `node64_dns64_group_internet_off{group}`, `node64_dns64_group_free{group}`, `node64_dns64_group_members{group}`.
  - Export/Import der Konfiguration nimmt die Gruppen mit (Mitglieder, Regeln, Freigaben/Sperren, Zeitpläne; ohne Knopf-Zustand). Eine Gruppe gleichen Namens auf der neuen Node bleibt, wie sie ist.
  - Dashboard-Karte: Zahl der Gruppen und davon gerade gesperrte.
  - API: `GET /api/dns64/groups` liefert je Gruppe den Zustand (`state`: internet_off, free, by_button, until_released, until, schedule), z. B. für Home Assistant.
- Damit ist der Plan Gerätegruppen und Kinderschutz (G1–G5) umgesetzt.

## 1.19.0 – 2026-10-19

### Neu
- Zeitpläne je Gerätegruppe (Phase G4): an gewählten Wochentagen von–bis (auch über Mitternacht oder ganztägig, in der Zeitzone der Node) entweder „Internet aus“ oder zusätzliche Kategorien sperren; einzeln an- und ausschaltbar.
- Sofort-Knöpfe je Gruppe: „Sperren“ (30 Min., 1 oder 2 Std., bis morgen früh 7:00, bis zum Aufheben) wirkt wie „Internet aus“; „Frei“ (30 Min., 1 oder 2 Std.) setzt Zeitpläne und Kategorien aus, Blocklisten gelten weiter; „Aufheben“ beendet beides. Der Zustand steht im Kopf der Gruppe.
- „Internet aus“: Es gehen nur lokale Namen, eigene Einträge und die Freigaben der Gruppe; alle anderen Namen bekommen die Adresse der Node (TTL 10 s). Ruft das Gerät eine Seite per http:// auf, zeigt der gemeinsame Eingang auf Port 80 eine Hinweisseite (Gruppe, Grund, bis wann); bei https:// zeigt der Browser nur einen Zertifikatsfehler. Port 80 wird dafür nur geöffnet, solange eine Gruppe gesperrt sein kann.
- Abfrage-Log: Gründe „Internet aus“ bzw. „Zeitplan …: Internet aus“. API: `POST /api/dns64/groups/{id}/hold`, `POST /api/dns64/groups/{id}/schedules`, `POST /api/dns64/groups/schedules/{id}/enable|disable`, `DELETE /api/dns64/groups/schedules/{id}`.

## 1.18.0 – 2026-10-19

### Neu
- SafeSearch je Gerätegruppe (Phase G3): ein Schalter leitet Google (alle Länderendungen), Bing und DuckDuckGo per CNAME auf ihre SafeSearch-Adressen und YouTube in den eingeschränkten Modus (streng, mittel oder aus). Gilt auch, wenn die Gruppe die Domain freigegeben hat; HTTPS bleibt unberührt.
- Schutz gegen Umgehen je Gruppe: schaltet die Liste HaGeZi DoH/VPN/Proxy Bypass für die Gruppe ein und beantwortet `mask.icloud.com`/`mask-h2.icloud.com` (iCloud Private Relay) sowie `use-application-dns.net` (Firefox-DoH) mit NXDOMAIN.
- Firefox nutzt DNS64: `use-application-dns.net` wird global mit NXDOMAIN beantwortet, damit Firefox sein eingebautes DoH abschaltet (wie Pi-hole, standardmäßig an, unter *Einstellungen* abschaltbar).
- Abfrage-Log: Gründe „SafeSearch → …“, „Firefox-DoH abgeschaltet“, „iCloud Private Relay aus“. API: `safesearch`, `youtube`, `bypass` in `PUT /api/dns64/groups/{id}/rules`, `firefox_canary` in den Einstellungen.

## 1.17.0 – 2026-10-19

### Neu
- Regeln je Gerätegruppe (Phase G2), unter *Gruppen → Regeln*:
  - Blocklisten wie für alle Geräte oder eine eigene Auswahl aus allen Vorlagen und eigenen Listen;
  - Kategorien sperren: Soziale Netzwerke, Spiele und Streaming (kleine, von Node64 gepflegte Listen, u. a. TikTok, Instagram, Roblox, Fortnite, YouTube, Netflix), Glücksspiel und Erwachseneninhalte (schalten HaGeZi Gambling bzw. HaGeZi NSFW für die Gruppe ein);
  - eigene Freigaben und Sperren je Gruppe (samt Subdomains). Reihenfolge: Freigabe der Gruppe vor Sperre der Gruppe vor Kategorien vor Blocklisten.
- Geladen werden die global eingeschalteten Listen plus die, die eine Gruppe zusätzlich nutzt – jede Liste nur einmal; welche für wen gilt, steht je Regel als Bitmaske (höchstens 64 Listen).
- Abfrage-Log: Grund „Sperre der Gruppe“ bzw. „Kategorie …“.
- API: `PUT /api/dns64/groups/{id}/rules`, `POST /api/dns64/groups/{id}/domains`, `DELETE /api/dns64/groups/domains/{id}`; `GET /api/dns64/groups` liefert die Regeln mit.

### Geändert
- Versteckte Tracker hinter CNAMEs werden auch bei Antworten aus dem Cache geprüft (der Cache ist für alle Gruppen gemeinsam).
- Die globale Pause setzt Blocklisten und Kategorien aus, nicht die eigenen Sperren einer Gruppe.

## 1.16.0 – 2026-10-19

### Neu
- Gerätegruppen (Phase G1): neuer Reiter „Gruppen“. Gruppen anlegen, umbenennen, sortieren (Reihenfolge = Vorrang) und Geräte zuordnen – zuerst per MAC-Adresse aus der Nachbartabelle des Hosts (IPv4 und IPv6, per Netlink), sonst per IP-Adresse oder Netz. So bleibt ein Gerät in seiner Gruppe, auch wenn es eine neue IPv6- oder IPv4-Adresse bekommt. Ein Gerät gehört zu höchstens einer Gruppe.
- Geräte der letzten 24 Stunden (aus dem Abfrage-Log, mit Name vom Router und MAC) lassen sich per Klick einer Gruppe zuordnen.
- Abfrage-Log: Gruppe am Client und Filter nach Gruppe (auch „ohne Gruppe“); API `GET /api/dns64/log?group=`.
- API: `GET|POST /api/dns64/groups`, `PUT|DELETE /api/dns64/groups/{id}`, `POST /api/dns64/groups/{id}/move`, `POST /api/dns64/groups/{id}/members`, `DELETE /api/dns64/groups/members/{id}`, `GET /api/dns64/devices`; jede Änderung im Audit-Log.
- Noch gelten für alle Gruppen dieselben Regeln; Listen, SafeSearch und Zeitpläne je Gruppe folgen (Plan: docs/PLAN-NODE64-DNS64-GRUPPEN.md).

## 1.15.0 – 2026-10-19

### Neu
- 20 weitere Blocklisten-Vorlagen (alle aus, am 19.10.2026 auf Pflege geprüft): HaGeZi Pro++, Ultimate und Pop-up Ads, Peter Lowe's Ad Servers; Sicherheit: HaGeZi Fake (Fake-Shops, Abo-Fallen), HaGeZi Badware Hoster, Phishing Filter von malware-filter (CC0); Umgehen: HaGeZi DoH/VPN/Proxy Bypass (fremde DoH-Server, VPNs, Proxys); Geräte-Tracking: HaGeZi Native Tracker für Samsung, LG webOS, Amazon, Apple, Windows/Office, Xiaomi, Huawei, TikTok und Roku; Kinderschutz: HaGeZi Gambling, HaGeZi NSFW, OISD NSFW.
- Vorlagen tragen ein Kategorie-Abzeichen (Werbung, Tracking, Sicherheit, Geräte-Tracking, Umgehen, Kinderschutz).
- Listen: Zeilen der Form `*.example.com` gelten für die Domain samt Subdomains (Peter Lowe nutzt sie); `*.com` allein sperrt nie eine ganze Endung.

## 1.14.1 – 2026-10-19

### Neu
- Hilfe-Links: Auf allen DNS64-Seiten und an den wichtigsten Karten und Feldern (Upstreams, Betriebsart, Blocklisten, Freigaben, eigene Einträge, Verschlüsselung, Zertifikat, Geräte, Client-Netze, Router, Benachrichtigungen) öffnet ein Fragezeichen die passende Stelle der Doku auf node64.de in der Sprache der Oberfläche.

## 1.14.0 – 2026-10-19

### Neu
- Prometheus: Anfragen je Ergebnis und Protokoll, Antwortzeiten, abgewiesene Anfragen, Cache, Blocklisten,
  Zustand und Fehler je Upstream sowie Pause unter `GET /api/metrics` (siehe docs/PROMETHEUS.md).
- Konfiguration exportieren/importieren: Das Zertifikat aus der Zertifikatsverwaltung wird mitgenommen und auf der neuen Node zugeordnet (Export mit Passwort, der die Zertifikate enthält).

### Behoben
- Übersicht: Zeitverlauf, Top-Clients und Top-Domains blieben leer (Fehler „disk I/O error“), sobald das Abfrage-Log groß genug war, dass SQLite beim Sortieren Zwischendateien anlegen wollte. Im Container gibt es dafür kein Verzeichnis; Zwischenergebnisse bleiben jetzt im Speicher.
- Darstellung: DNS64-Logo im dunklen Design hell.
- Port-Übersicht (Einstellungen → Ports): DoH/DoT/DoQ gelten nur als aktiv, wenn der Dienst tatsächlich gestartet ist (bisher auch bei Zertifikatsfehler).

## 1.13.0 – 2026-10-18

### Neu
- Internationalisierte Domainnamen (IDN): Einträge wie `bücher.example` auf Blocklisten (hosts, Domain je Zeile, Adblock), in Freigaben und eigenen Einträgen werden in Punycode (`xn--bcher-kva.example`) umgewandelt und greifen; bisher wurden sie als ungültig übergangen.

### Geändert
- Abfrage-Log: Abgelaufene Einträge werden in Stücken zu 5.000 Zeilen gelöscht, dazwischen läuft das Schreiben weiter. Ein großer Rückstand (z. B. nach kürzerer Aufbewahrung) sperrt die Datenbank nicht mehr am Stück, und es gehen keine Log-Einträge verloren.

## 1.12.0 – 2026-10-16

### Neu
- Happy Eyeballs zu den Upstream-Servern (DoH, DoT, DoQ): IPv6- und IPv4-Bootstrap-Adressen abwechselnd, der nächste Versuch startet nach 250 ms oder sofort bei einem Fehler, die zuletzt erfolgreiche Familie zuerst. Eine hängende Adresse (IPv6 ohne Route, gesperrtes IPv4) kostet so höchstens 250 ms statt 2 s je Verbindung.
- Router für lokale Namen auch über IPv6: Gibt es kein IPv4-Gateway mit DNS, nimmt DNS64 das IPv6-Default-Gateway (Link-local mit Schnittstelle, z. B. `fe80::1%eth0`). Eintragen lässt sich der Router jetzt auch als IPv6-Adresse mit Zone bzw. `[IPv6]:Port`.

### Geändert
- Hinweise unter Einstellungen nennen IPv4 und IPv6 (Adresse „alle Adressen (IPv4 und IPv6)“, Router).
- Test: DNS über UDP, TCP und DoT antwortet über 127.0.0.1 und ::1, auch für AAAA.

## 1.11.0 – 2026-10-16

### Entfernt
- Eigene Let's-Encrypt-Anbindung von DNS64 (Abruf und Erneuerung per DNS-01, Formular auf der Seite Verschlüsselung, `GET|POST /api/dns64/acme`, `POST /api/dns64/acme/renew`, Meldung „DNS64-Zertifikat“). Zertifikate holt und erneuert die zentrale Zertifikatsverwaltung, Fehler und Ablauf meldet sie. Der ipv64-API-Key wird in DNS64 nicht mehr gebraucht.

### Geändert
- Nicht umgezogene Installationen (z. B. fehlende Zustimmung zu den Nutzungsbedingungen) liefern das bisherige Let's-Encrypt-Zertifikat weiter aus, bis der Umzug klappt; die Seite Verschlüsselung zeigt den Grund. Der Umzug liest dafür weiter `acme/` und die Einstellungen `dns64.acme_*`.

## 1.10.0 – 2026-10-16

### Neu
- Zertifikate aus der zentralen Zertifikatsverwaltung: Unter *Verschlüsselung → Zertifikat* lässt sich jedes gültige Zertifikat der Verwaltung wählen („Aus der Zertifikatsverwaltung“). Erneuert die Verwaltung es, übernimmt DNS64 es sofort ohne Neustart; die Liste dort zeigt „benutzt von: DNS64“.
- Die Heimnetz-CA liegt in der Verwaltung; das Server-Zertifikat stellt sie für DNS64 aus und neu aus, wenn sich Namen oder private IPs ändern.

### Geändert
- Einmaliger Umzug beim ersten Start: die eigene Heimnetz-CA (gleicher Schlüssel, Geräte vertrauen ihr weiter) und ein vorhandenes Let's-Encrypt-Zertifikat samt Schlüssel gehen in die Verwaltung, die ab dann erneuert; die Zustimmung zu den Nutzungsbedingungen wird übernommen. Danach steht der Modus auf „Aus der Zertifikatsverwaltung“. Scheitert etwas, bleibt alles wie bisher und der Umzug wird beim nächsten Start wieder versucht. Die bisherigen Dateien bleiben als Rückfall liegen.
- Neue Let's-Encrypt-Zertifikate legt man in der Zertifikatsverwaltung an; der eigene Abruf in DNS64 bleibt nur noch als Rückfall für nicht umgezogene Installationen und entfällt in einer späteren Version.

## 1.9.0 – 2026-10-16

### Neu
- Upstream-Betriebsart „Schnellste (automatisch)“: Jede Anfrage geht nur an die gerade schnellsten Server (einstellbar 1–3, Standard 2) gleichzeitig, die erste gute Antwort gewinnt. Die Rangfolge ergibt sich laufend aus den echten Antwortzeiten; Server, die gerade nicht gefragt werden, werden alle 30 s mit einer kleinen Anfrage nachgemessen (hält auch ihre Verbindung warm). Antworten die ersten nicht rechtzeitig (das Vierfache ihrer üblichen Zeit, 0,3–1,5 s), kommt der nächste dazu; scheitern alle, werden die übrigen gefragt. Statt 5–6 Anfragen nach draußen wie bei „Parallel“ sind es so meist 2.
- Übersicht: Die gerade genutzten Server tragen „wird gefragt“; API `GET /api/dns64/upstreams` liefert `count` und je Server `active`, Einstellungen `upstream_count`.

### Geändert
- Neue Installationen starten mit „Schnellste (automatisch)“; gespeicherte Einstellungen bleiben, wie sie sind.

## 1.8.0 – 2026-10-15

### Geändert
- Freigabeliste gehärtet: „Weitere Client-Netze“ lehnen 0.0.0.0/0 und ::/0 ab (alte Einträge dieser Art gelten nicht mehr). Netze an den eigenen Schnittstellen zählen nur noch, wenn sie privat sind oder ein IPv6-/64 (bzw. kleiner); ein öffentliches IPv4-Netz auf einem gemieteten Server gab sonst die Nachbarn im Rechenzentrum frei.

### Neu
- DoH über den gemeinsamen Eingang des Kerns: Ist der DoH-Port der HTTPS-Port des Eingangs (Standard 443), öffnet DNS64 keinen eigenen Listener mehr, sondern meldet `/dns-query` auf seinen Namen und für Aufrufe per IP an. DoH und CDN64 teilen sich so Port 443; der Eingang lässt nur Geräte aus den erlaubten Netzen durch (echte Gegenstelle, sonst neutrales 404), öffnet für DoH keinen Port 80 und bietet DoH auch über HTTP/3 an. Gehört ein Name schon einem Proxy-Host, fällt nur dieser Name für DoH weg. Ein anderer DoH-Port läuft wie bisher über einen eigenen Listener.
- Warnung in den Einstellungen bei öffentlichen Netzen in der Freigabeliste.
- Abgelehnte Anfragen von fremden Adressen werden gezählt (Einstellungen: Anzahl, zuletzt welche Adresse) und höchstens einmal je Stunde ins Log geschrieben, damit eine versehentliche Freigabe auffällt.

## 1.7.2 – 2026-10-15

### Behoben
- Unter Last konnte ein Neustart oder Abschalten kurz nach dem Start den DNS-Port (und DoT) belegt lassen: Der Dienst startete erst nach dem Stopp und lief weiter, ein neuer Start scheiterte dann an „address in use“. Start wartet jetzt, bis der Dienst läuft.

## 1.7.1 – 2026-10-15

### Geändert
- Audit-Log: Änderungen per API-Key tragen die Herkunft jetzt im Feld „Herkunft“ (Key-Name), der Zusatz „(api)“ in den Details entfällt.

## 1.7.0 – 2026-10-14

### Neu
- Alles aus der Oberfläche auch per API: Let's Encrypt einrichten, holen und erneuern (`GET|POST /api/dns64/acme`, `POST /api/dns64/acme/renew`), eigene Einträge an/aus (`POST /api/dns64/records/{id}/enable|disable`), Freigaben übernehmen (`POST /api/dns64/allowlist/import`), CA und iOS-/macOS-Profil (`GET /api/dns64/ca.crt`, `GET /api/dns64/mobileconfig`), eigene Upstreams und Listen einzeln (`POST|DELETE /api/dns64/upstreams`, `POST|DELETE /api/dns64/lists`).
- Jede Änderung (Einstellungen, Upstreams, Listen, Freigaben, eigene Einträge, Verschlüsselung, Let's Encrypt samt Zustimmung zu den Nutzungsbedingungen, Pause, Cache leeren) steht im Audit-Log, aus Oberfläche und API (Akteur und IP wie im Kern, auch hinter einem Proxy).
- OpenAPI mit Schemas für Anfragen und Antworten aller DNS64-Endpunkte.

### Behoben
- Neustart nach geänderten Einstellungen und gleichzeitiges Abschalten des Moduls konnten DNS-Port und DoH/DoT/DoQ offen lassen; Start, Stopp und Neustart laufen jetzt nacheinander.
- Hängt das Stoppen, werden die Upstream-Verbindungen trotzdem geschlossen und das Abfrage-Log danach.
- Fehler beim Speichern der Zustimmung zu den Nutzungsbedingungen wurden verschluckt.

## 1.6.0 – 2026-10-14

### Neu
- Blockieren pausieren: Knopf oben rechts auf allen DNS64-Seiten, für 10 Minuten oder bis zum Wiedereinschalten. Der DNS-Dienst läuft weiter, nur Blocklisten greifen nicht; eigene Einträge, lokale Namen und Freigaben bleiben. Im Abfrage-Log steht, was sonst blockiert worden wäre; die Dashboard-Karte zeigt die Pause.
- API: `POST /api/dns64/pause` (`{"minutes": 10}`, 0 = bis zum Wiedereinschalten) und `POST /api/dns64/resume`; Stand in `GET /api/dns64/status` (`blocking`).

## 1.5.0 – 2026-10-14

### Neu
- Let's Encrypt: öffentlich gültiges Zertifikat für einen Namen unter einer ipv64-Domain (z. B. dns.<domain>), bestätigt per DNS-01 über die ipv64-API mit dem zentralen API-Key; DNS64 wartet, bis die ipv64-Nameserver den TXT-Record ausliefern, und löscht ihn danach. Damit klappen DoH/DoT/DoQ auf allen Geräten ohne CA-Installation, auch Android „Privates DNS“.
- Automatische Verlängerung 30 Tage vor Ablauf; das neue Zertifikat gilt sofort, ohne Neustart der Dienste. Bis zum ersten Abruf laufen die Dienste mit der eigenen Heimnetz-CA.
- Der Name wird auf Wunsch als eigener Eintrag auf die IP der Node im Heimnetz gelegt; Testumgebung von Let's Encrypt wählbar.
- Benachrichtigung `dns64_cert`, wenn Abruf oder Verlängerung scheitert.

## 1.4.0 – 2026-10-14

### Neu
- Benachrichtigungen über die Standardkanäle: Upstream-Server länger als 3 Minuten gestört und wieder erreichbar, Blockliste dreimal hintereinander nicht ladbar; abschaltbar unter Einstellungen. Webhook-Arten `dns64_upstream`, `dns64_upstream_ok`, `dns64_lists`.
- Freigaben übernehmen: Liste einfügen (eine Domain je Zeile, z. B. allowlist.txt des alten DNS64-Containers oder Pi-hole-Whitelist).

## 1.3.0 – 2026-10-14

### Neu
- Verschlüsselt im Heimnetz: Geräte fragen DNS64 selbst per DNS-over-HTTPS (RFC 8484, GET und POST, eigener Port, Standard 443), DNS-over-TLS (RFC 7858, 853/TCP) und DNS-over-QUIC (RFC 9250, 853/UDP); jeder Dienst einzeln einschaltbar, ein belegter Port stoppt nur diesen Dienst.
- Eigene Heimnetz-CA (10 Jahre, darf nur private Adressen bestätigen) stellt das Server-Zertifikat aus: alle privaten IPs der Node und die eingestellten Namen, 800 Tage, wird bei neuen Namen/IPs oder kurz vor Ablauf neu ausgestellt. Alternativ das Zertifikat der Weboberfläche.
- Neuer Reiter „Verschlüsselung“ mit Zustand je Dienst, Verbindungsdaten für Geräte, CA-Zertifikat und Profil für iPhone/iPad/Mac (DoH oder DoT) zum Herunterladen.
- Abfrage-Log zeigt das Protokoll (TCP, DoH, DoT, DoQ).

## 1.2.0 – 2026-10-14

### Neu
- Upstream-Server auch über DNS-over-TLS (`tls://name[:853]`, RFC 7858) und DNS-over-QUIC (`quic://name[:853]`, RFC 9250); Vorlagen für Cloudflare, Quad9, Google, AdGuard und Mullvad über DoT sowie AdGuard über DoQ, eigene Server mit allen drei Protokollen.
- Zertifikatsprüfung auf den Namen des Servers bei allen Protokollen; Verbindungen werden wiederverwendet (DoT: bis zu 4 offene Verbindungen, DoQ: eine QUIC-Verbindung mit einem Stream je Anfrage).
- Protokoll je Server in Übersicht und Einstellungen sichtbar, `proto` in `GET /api/dns64/upstreams`.

## 1.1.0 – 2026-10-14

### Neu
- Upstream-Server wählbar: Cloudflare, Quad9, Google, AdGuard, Mullvad oder eigene DoH-Server mit Bootstrap-IPs; Betriebsart parallel (schnellste Antwort) oder der Reihe nach (Ausweichen bei Fehler).
- Blocklisten an- und abschaltbar, weitere Vorlagen (OISD Big, HaGeZi Pro, HaGeZi Threat Intelligence) und eigene Listen-URLs; Aktualisierung alle 6, 12, 24 oder 48 Stunden.
- Eigene DNS-Einträge (A, AAAA, CNAME, Wildcards wie *.home.lan) mit automatischer Rückwärtssuche (PTR); gelten sofort, vor Blocklisten und nie ins Internet. Neuer Reiter „Eigene Einträge“.
- Antwort bei Blockierung wählbar: 0.0.0.0/:: oder NXDOMAIN.
- Cache-Größe einstellbar; Client-Adressen im Abfrage-Log vollständig, gekürzt (IPv4 /24, IPv6 /48) oder gar nicht speichern.
- Weitere erlaubte Client-Netze (z. B. öffentliches IPv6-Präfix, VPN).
- API: `GET|PUT /api/dns64/settings`, `GET|POST /api/dns64/records`, `DELETE /api/dns64/records/{id}`; Export/Import enthält alle Einstellungen und die eigenen Einträge.

### Geändert
- Gründe im Abfrage-Log (freigegeben, abgelaufen) erscheinen in der Sprache der Oberfläche.
- Blocklisten liegen nach URL benannt im Datenverzeichnis; vorhandene Dateien werden übernommen.

## 1.0.0 – 2026-10-14

Übernahme des eigenständigen DNS64-Containers als Modul von Node64.

### Neu
- Lokaler DNS-Resolver fürs Heimnetz (UDP und TCP, Standard Port 53), antwortet nur privaten und direkt angeschlossenen Netzen (kein offener Resolver).
- Blockieren von Werbung, Trackern und Malware über 6 Blocklisten (StevenBlack, AdGuard DNS, OISD Small, HaGeZi Multi, EasyPrivacy, URLhaus), alle 24 Stunden aktualisiert; Tracker hinter CNAMEs werden erkannt.
- Anfragen ins Internet verschlüsselt über DNS-over-HTTPS (Cloudflare und Quad9 parallel, schnellste gültige Antwort gewinnt).
- Optimistischer Cache (20.000 Einträge): häufige Domains werden vor Ablauf erneuert, abgelaufene bis 1 Stunde sofort ausgeliefert.
- Lokale Namen (z. B. fritz.box, .lan, einzelne Hostnamen, Reverse privater IPs) gehen nur an den Router; Gerätenamen der Clients per PTR.
- Seiten Übersicht (Kennzahlen, Zeitverlauf, Upstreams, Cache, Top-Listen), Abfrage-Log (Filter, Suche, Live, Freigeben per Klick) sowie Freigaben und Blocklisten.
- Einstellungen: DNS-Port und -Adresse, Router für lokale Namen, Aufbewahrung des Abfrage-Logs.
- Lokale API `/api/dns64/*`; Export/Import der Einstellungen und Freigaben.
- Ausgeschaltet laufen keine Prozesse und kein Port ist offen.
