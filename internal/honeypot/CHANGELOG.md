# Änderungen – Honeypot64

## 0.15.1 – 2026-10-27

### Geändert
- Live-Karte: Die Angabe „Bögen gerade“ in der Leiste unter der Karte entfällt (Container und ipv64.net).

## 0.15.0 – 2026-10-27

### Neu
- Lokale Sperrliste: Neuer Haken „Erkannte Angreifer in PROXY64 sperren“, im einfachen und im Expertenmodus,
  Standard an. IPs, die der Honeypot als Angreifer erkennt (Login-Versuche, Exploits, Port-Scans, Scanner), sperrt
  PROXY64 sofort für alle Hosts und Streams. Das wirkt auch ohne Meldung an ipv64, so schützt der Honeypot den eigenen
  Proxy direkt. Private Adressen und Ausnahmen werden nie gesperrt; Dauer (Standard 24 Stunden) und Liste mit
  „Freigeben“ stehen unter PROXY64 → Zugriffslisten. Läuft PROXY64 nicht, weist die Einstellung darauf hin.

## 0.14.6 – 2026-10-27

### Behoben
- Meldung an ipv64: Mit der Vorlage „Nur über PROXY64“ (`proxy`, Voreinstellung) lehnte ipv64.net die Meldung ab
  („sensor.profile must be one of …“, 422). Das Portal nimmt `proxy` jetzt an (Portal-Datei `api_v2_honeypot.php`).
- Log-Sensor: Jede eingetragene Datei bzw. jedes Muster hat jetzt einen Knopf „Entfernen“ (Papierkorb), der die Zeile
  entfernt und gleich speichert. Bisher ging das nur, indem man die Zeile leerte.
- Der letzte Fehler der Meldung steht in der Übersicht und den Einstellungen nur noch, solange danach keine Meldung
  angenommen wurde.

## 0.14.5 – 2026-10-27

### Neu
- Firewall-Helfer (Modus ohne Oberfläche): Ohne `NODE64_IPV64_LIST_TOKEN` holt Node64 das Listen-Token beim Start über
  `NODE64_IPV64_KEY`. Berechtigte Accounts (Beitragende und alle Klassen außer Standard) bekommen so automatisch die
  Live-Fassung der v64 Blocklist, sonst den Tagesstand.

## 0.14.4 – 2026-10-27

### Geändert
- Firewall-Helfer (Modus ohne Oberfläche): Die v64 Blocklist ist nur noch eine Liste; frühere Teillisten in
  `NODE64_FIREWALL_LISTS` (z. B. `v64_ssh`) gelten als `v64`.

## 0.14.3 – 2026-10-27

### Behoben
- Live-Karte: Der feste Bogen eines ausgewählten Herkunftslands war nur eine Haarlinie; jetzt in voller Breite.
- Beschriftungskästen fangen keine Klicks mehr ab – der Klick auf ein Land (Filter der Ereignisse) geht wieder durch.
- „Anhalten“ stoppt auch Bögen, die gerade erst geplant waren; nach schnellem Fortsetzen bleibt die Hervorhebung des
  eigenen Lands richtig. Bei einem Wechsel des Standorts bleibt das alte Land nicht mehr hervorgehoben.
- Die Beschriftung des eigenen Lands bleibt stehen, solange noch Bögen ankommen (vorher flackerte sie).
- Wiederholungen älterer Angriffe nur in einem Takt ohne neue Angriffe (wie beschrieben), nie doppelt.
- Kleinstaat als Standort (z. B. Singapur): Der Zielpunkt leuchtet, solange Bögen ankommen.
- Tuvalu lag rechts außerhalb der Karte.
- Einstellungen: Die Länderauswahl ist nach Sprache sortiert (Österreich bei O, nicht hinter Zypern), und die Seite
  wartet nicht mehr bis zu 6 Sekunden, während die Node ihre öffentliche IPv4 abfragt.
- Modus ohne Oberfläche: Hinweis „IP-Länderdaten: DB-IP.com“ an Karte und Länderliste der Info-Seite.

## 0.14.2 – 2026-10-26

### Verbessert
- Live-Karte: Beschriftung kleiner und in einem dunkelgrauen, halbtransparenten Kasten; Schrift immer 10 px, egal
  wie groß die Karte gerade ist (vorher im Vollbild sehr groß).

## 0.14.1 – 2026-10-26

### Verbessert
- Live-Karte beschriftet: Flagge und Ländercode an Quelle und Ziel jedes Bogens (blendet aus, wenn sie sich
  überdecken würden), schwache Ländernamen der aktiven Länder, das eigene Land leuchtet, solange Bögen ankommen.
- Kompakte Zahlen unter der Karte auch ohne Vollbild: Angriffe der letzten Stunde, Herkunftsländer, Top-3-Herkunft
  mit Flagge, häufigste Art und Bögen gerade.

## 0.14.0 – 2026-10-26

### Neu
- Live-Karte im Vollbild (Knopf neben „Live“, Esc beendet): Karte über den ganzen Bildschirm, Seitenleiste mit den
  Bögen, die gerade zu sehen sind, und den häufigsten Herkunftsländern der letzten Stunde. Ein Klick auf ein Land
  zeigt den Bogen fest und die Arten der Angriffe von dort. Node64-Logo in der Kartenecke.
- Mehrere Bögen gleichzeitig (bis zu drei neue je Takt, höchstens zwölf auf der Karte), nur aus echten Angriffen;
  Wiederholungen bleiben blasser und als Wiederholung markiert.
- Standort des Sensors einstellbar („Standort des Sensors“: automatisch oder Land wählen; ohne Oberfläche
  `NODE64_HONEYPOT_COUNTRY`), z. B. für Server eines Hosters im Ausland. Ziel der Bögen hier und – mit der Meldung an
  ipv64 – auf der Live-Karte von ipv64.net. Nur Anzeige, nicht für die Bewertung.
- Kleine Länder ohne Fläche auf der Karte (Singapur, Hongkong, Malta, Liechtenstein, Monaco u. a.) bekommen einen
  festen Punkt: Bögen von und nach dort werden jetzt gezeichnet.
- Länderdaten nach Standort: ipv64.net liefert die Länder jetzt aus DB-IP (Standort der Adresse statt Firmensitz des
  Inhabers, Lücken aus den RIR-Daten). Hinweis „IP-Länderdaten: DB-IP.com“ an der Karte.

## 0.13.0 – 2026-10-26

### Neu
- Einfacher Modus und Expertenmodus (Umschalter oben in den Einstellungen). Der einfache Modus ist Standard: Vorlage
  wählen (empfohlen: „Nur über PROXY64“), dazu die Liste der Ports, die im Router an die Node weiterzuleiten sind
  (z. B. 22/tcp, 161/udp), Startseite der Web-Falle, Benachrichtigung und Meldung an ipv64. Alle bisherigen
  Einstellungen (einzelne Dienste und Ports, Profile, Zertifikat, Limits, Log-Sensor, Syslog, Anmeldung) stehen im
  Expertenmodus.
- Handy: „Letzte Ereignisse“ zeigt je Ereignis eine Karte statt einer breiten Tabelle.
- Frühwarnung mit Details: Jeder Treffer sagt, warum die Adresse aufgefallen ist – je Herkunft (Honeypot, Log, Syslog),
  Dienst, Port, Art und Regel mit Anzahl, dazu Sensoren, Accounts, Ereignisse und Listen (letzte 14 Tage, nie
  Sensoren oder Inhalte). In der Liste der letzten Treffer und in der Benachrichtigung (braucht den aktuellen Stand
  von ipv64.net; ältere Treffer ohne Details).
- Startseite der Web-Falle wählbar: Gateway-Terminal im Matrix-Stil (Standard) oder schlichtes Anmeldeformular. Gilt
  auch für Bots, die PROXY64 an den Honeypot gibt.

- Live-Karte: Auf der Länderkarte der Übersicht fliegen Bögen von der Quelle eines Angriffs zu deinem Sensor (Farbe
  je Art, Ziel pulsiert, Infos beim Überfahren), darunter die letzten Angriffe als Liste. Neue Angriffe zuerst; ist
  gerade nichts Neues da, werden ältere aus der letzten Stunde blasser wiederholt (nur auf der Karte). Knopf „Live“
  zum Anhalten, ohne Animation bei „Bewegung reduzieren“. Ziel ist das Land der öffentlichen IPv4 der Node. API
  `GET /api/honeypot/live`.

### Geändert
- „An ipv64 melden“ ist für neue Einrichtungen standardmäßig an (wirkt, sobald der zentrale API-Key eingetragen ist;
  gemeldet wird ab dem ersten Durchlauf, nichts von vorher). Ohne Key bleibt der Schalter beim Speichern unverändert.


## 0.12.0 – 2026-10-26

### Geändert
- Neue Startseite der Web-Falle (`/`, auch für Bots, die PROXY64 an den Köder gibt): ein fiktives Gateway-Terminal
  („NODE-07 // Gateway“) statt des schlichten Formulars. Das Formular sendet echt (POST username/password), die
  Zugangsdaten werden wie bisher erfasst; nach einem Versuch erscheint „ACCESS DENIED“. Keine fremden Marken, keine
  externen Quellen. Die übrigen Köder (WordPress, phpMyAdmin, Admin) bleiben schlicht.

## 0.11.0 – 2026-10-25

### Neu
- Vorlage „Nur über PROXY64“ neben Minimal, Standard und Voll: Der Honeypot öffnet keine eigenen Ports und bekommt nur,
  was PROXY64 weitergibt – Anfragen, die keinem Host zuzuordnen sind, und als schädlich erkannte (Blocklisten, gemeldete
  Angreifer, Exploit-Muster, KI-Bots). Welche Arten, stellt man bei PROXY64 unter Zugriffslisten → Honeypot64 ein.

### Geändert
- „Nur über PROXY64“ ist die neue Voreinstellung. Wer schon eine Vorlage oder eigene Auswahl gespeichert hat, behält sie.

## 0.10.0 – 2026-10-22

### Neu
- Optional zeigen die HTTPS-Fallen mit Webserver-Profil und die neuen Mail-Fallen mit TLS (SMTPS 465, IMAPS 993,
  POP3S 995) ein gültiges Zertifikat aus der Zertifikatsverwaltung. Es lässt sich direkt für glaubwürdige Köder-Namen
  anlegen (DNS-01 über ipv64, auf Wunsch mit A/AAAA- oder CNAME-Records). Profile, die im Original selbst signiert
  sind (Proxmox, Webmin, NAS …), bleiben selbst signiert. Der angefragte Name (SNI) steht an jedem Ereignis.
- Überwachung der eigenen Node64-Anmeldung (Regel `node64/login@1`): ab 5 Fehlversuchen in 10 Minuten je öffentlicher
  IP (einstellbar) ein Ereignis ohne Zugangsdaten, mit Benachrichtigung, Sofort-Sperre über PROXY64 (mit deren Opt-in)
  und Meldung an ipv64. Gezählt werden Passwort, TOTP, Passkey, SSO, API- und MCP-Key. Neue Zeile in der Übersicht.
- Modus ohne Oberfläche: `NODE64_HONEYPOT_PERSONAS`, `NODE64_HONEYPOT_HOSTNAME`, `NODE64_NAME`.

## 0.9.0 – 2026-10-22

### Neu
- Dienst-Profile je Port: SSH als OpenSSH Debian 12, Ubuntu 24.04 oder Dropbear (Banner, Algorithmen und
  Host-Schlüssel RSA/ECDSA/Ed25519 passend), Telnet als BusyBox- oder Linux-Login, MySQL 8.0 (caching_sha2_password)
  oder MariaDB 10.11/11.4, Web als nginx, Apache, Proxmox VE, Webmin, Home Assistant, Grafana, NAS oder Elasticsearch
  (Kopfzeilen, Status, API-Antworten ohne Anmeldung, Zertifikat wie das Original, ohne Logos).
- Standard je Port (8006 Proxmox, 10000 Webmin, 8123 Home Assistant, 3000 Grafana, 5000/5001 NAS, 9200 Elasticsearch,
  sonst nginx), Auswahl in der Tabelle der Fallen-Dienste, Hostname der Fallen einstellbar.
- Hostname, Versionen und Zertifikatsdaten variieren stabil je Sensor (aus der Sensor-Kennung), damit nicht alle
  Sensoren denselben Fingerabdruck haben. Geräte-Logins mit eigenem Profil antworten nur noch auf dessen Port.

## 0.8.1 – 2026-10-21

### Behoben
- Port-Übersicht (Einstellungen › Ports): Fallen-Dienste und Syslog-Empfänger melden, warum ein Port nicht offen ist; ein Syslog-Port, den inzwischen ein anderer Teil belegt, erscheint als eingestellt mit Fehler statt gar nicht.

## 0.8.0 – 2026-10-20

### Neu
- Länderkarte auf der Übersicht: Weltkarte, Länder nach Ereignissen im gewählten Zeitraum in fünf Stufen eingefärbt (logarithmisch, hell/dunkel), Tooltip mit Flagge, Name, Ereignissen und Quell-IPs, Legende. Klick auf ein Land filtert die Ereignisliste nach diesem Land (ohne JavaScript). Kartendaten Natural Earth 1:110m (public domain) eingebettet, kein Nachladen aus dem Netz. Dieselbe Karte (7 Tage) auf der Info-Seite des Modus ohne Oberfläche.
- Filter nach Land: `GET /api/honeypot/events?country=DE`, in der Oberfläche `/honeypot?country=DE`.
- Startseiten-Karte mit mehr Informationen: Ereignisse 24 Std. mit Trend gegenüber den 24 Std. davor, Top-3-Länder als Flaggen, meistangegriffener Dienst, Meldung an ipv64 (aus/ok/Fehler mit Zeitpunkt), fehlerhafte Fallen-Dienste mit Hinweis, Anfragen über PROXY64.

## 0.7.0 – 2026-10-20

### Neu
- Flaggen auch unter Windows: kleine Flaggen-Schrift (Twemoji, CC-BY 4.0) in der Oberfläche, die nur für Länderflaggen greift.
- Herkunft der Angreifer: Flagge (Emoji), Ländercode und Name im Tooltip an jeder IP in Ereignisliste und Top-Quellen, in der Benachrichtigung über neue Angreifer und auf der Info-Seite des Modus ohne Oberfläche. Neue Rangliste „Herkunft nach Land“ mit farbigen Balken (Ereignisse und Quell-IPs je Land). Länderdaten von ipv64.net (`country_ranges.txt.gz`, täglich, nur bei Änderung geladen, Zwischenspeicher `/data/geoip/`), nur solange Honeypot64 läuft; ohne Daten läuft alles ohne Länder weiter.
- „Was wurde angegriffen“ farbig: Balken je Dienst, Port und Art, aufgeteilt nach Login/Bruteforce, Exploit, Scan, Sondierung und Log/Syslog; Köder und erkannte Geräte als eigene kleine Rangliste.
- API: `country` an Ereignissen und Top-Quellen, `by_country`, `country_unknown` und `by_decoy` in der Statistik. Prometheus `node64_honeypot_events_by_country_total{country}`.

## 0.6.0 – 2026-10-20

### Neu
- Dienste-Auswahl als Katalog: alle Fallen-Dienste mit Schalter, änderbarem Port, Köder-Auswahl und Zustand („frei“, „belegt von …“, „offen“); Vorlagen Minimal/Standard/Voll, „Alle freien einschalten“, „Alle aus“, weitere Einträge für Mehrfach-Dienste; die Textliste bleibt unter „Erweitert“. API `GET /api/honeypot/catalog`. Doppelte Ports werden je Protokoll geprüft (161/udp und 161/tcp sind kein Konflikt).
- Zusammenarbeit mit PROXY64 (Opt-in in PROXY64): Köder für Anfragen ohne passenden Host, Auswertung der Zugriffe mit Regeln `proxy64/*@1`, Sofort-Sperre auffälliger IPs in PROXY64. Zeile in der Übersicht und Prometheus `node64_honeypot_proxy_*`.

## 0.5.0 – 2026-10-20

Phase H6.

### Neu
- Login-Fallen für Datenbanken und Fernzugriff: PostgreSQL (5432, Passwort im Klartext), MySQL (3306, Wechsel auf Klartext-Passwort, sonst nur Benutzer), MSSQL (1433), Redis (6379, dazu Befehle, die die Konfiguration ändern würden, als Angriff), RDP (3389, Benutzername aus dem Verbindungsaufbau), VNC (5900, Anmeldeversuch).
- MikroTik-API (8728, mit TLS 8729), SNMP (UDP 161, Community-Strings, antwortet nie) und SIP (UDP 5060, Scanner und Digest-Anmeldungen, kurze Antworten nie größer als die Anfrage).
- Fingerabdrücke der Angriffswerkzeuge: JA4 (HTTPS und TLS am TCP-Port) und HASSH (SSH) in Ereignisliste, Rangliste und Meldung an ipv64.
- Profile nutzen die neuen Fallen statt einfacher TCP-Ports; UDP-Dienste werden in der Port-Verwaltung als UDP geführt.

## 0.4.0 – 2026-10-20

### Neu
- Login-Fallen für FTP (21), SMTP (25/587, AUTH PLAIN/LOGIN, kein Relay, Relay-Versuche werden gemeldet), POP3 (110), IMAP (143) und MQTT (1883): erfassen Benutzername und Passwort und lehnen jede Anmeldung ab. Auch als eigene Dienste wählbar (`ftp 21`, `smtp 587`, …) und im Modus ohne Oberfläche per `NODE64_HONEYPOT_SERVICES`.
- Profile: `standard` mit FTP, SMTP, IMAP, MQTT und weiteren Ports (3306, 6379, 8006, 8123, 8291), `full` mit vielen weiteren Ports gängiger Web-Oberflächen und Dienste.
- Web-Köder erkennen die Login-Aufrufe verbreiteter Geräte und Oberflächen (Router wie FRITZ!Box, Speedport und OpenWrt, Firewalls und SSL-VPN, NAS, UniFi, Home Assistant, Proxmox, Grafana, Jenkins, Webmin, Portainer) und antworten mit einer schlichten Ablehnung im passenden Format; Benutzername und Passwort werden erfasst, das Gerät steht im Detail (`device=…`).
- Zugangsdaten aller Login-Fallen gehen in die Meldung an ipv64 (bisher nur SSH, Telnet, HTTP/HTTPS).

## 0.3.0 – 2026-10-20

Log-Sensor, Syslog-Empfänger und Frühwarnung für eigene Netze (Phase H5).

### Neu
- Frühwarnung (Reiter „Frühwarnung“): eigene Netze verwalten (gespeichert bei ipv64), DynDNS-IPs des Accounts automatisch überwacht; Treffer werden alle 30 Minuten abgeholt und gebündelt gemeldet. Netze ohne Nachweis melden nur IPs, die auf der v64 Blocklist stehen, DynDNS-IPs jede Sichtung. Braucht den zentralen API-Key, nicht die Meldung an ipv64.
- Log-Sensor: liest Logs echter Dienste (sshd, nginx/Apache/Caddy, Postfix/Dovecot, Proxmox, Nextcloud, Vaultwarden, Gitea/Forgejo, Home Assistant) und erkennt Angriffe mit mitgelieferten, versionierten Regeln ab einer Schwelle. Dateien mit Format unter Einstellungen › „Log-Sensor und Syslog“, Vorschläge für gängige Pfade per Knopf; erlaubt sind Pfade unter `/host/log`, `/var/log` und `/data/logs` (Mount `-v /var/log:/host/log:ro`, für `auth.log` zusätzlich `--group-add 4`).
- Syslog-Empfänger auf UDP und TCP (ein Port, z. B. 514) für Router und Firewalls (MikroTik, OPNsense/pfSense, FortiGate, Sophos, UniFi); nur erlaubte Absender (Standard private Netze und localhost). Der Port wird wie die Fallen über die Port-Verwaltung geprüft (UDP und TCP).
- Aus echten Logs werden nur IP, Art, Dienst, Port, Anzahl und Regel gespeichert und gemeldet – keine Benutzernamen, Passwörter, Pfade, User-Agents oder Inhalte. Proben in der Meldung an ipv64 stammen nur aus dem Honeypot; Quellen tragen `source` (`honeypot`, `log`, `syslog`) und die Regel.
- Zustand je Datei (z. B. „keine Leserechte – Container braucht --group-add 4“) und des Syslog-Empfängers in den Einstellungen, auf der Übersicht und unter `GET /api/honeypot/status` (`logs`).
- Ereignisliste mit Sensor (Honeypot, Log, Syslog) und Regel, Filter nach Sensor (auch `GET /api/honeypot/events?source=`); Statistik mit Rangliste der Sensoren (`by_source`).
- Prometheus: `node64_honeypot_events_total{kind,source}` mit echter Quelle, `node64_honeypot_log_lines_total`, `node64_honeypot_log_file_ok{path}`, `node64_honeypot_syslog_messages_total`, `node64_honeypot_syslog_denied_total`.
- Modus ohne Oberfläche: `NODE64_HONEYPOT_LOGS`, `NODE64_HONEYPOT_SYSLOG_PORT`, `NODE64_HONEYPOT_SYSLOG_ALLOW`; Zustand auf der Info-Seite. Kein Profil schaltet den Log-Sensor von selbst ein.
- Export/Import der Einstellungen mit Log-Sensor und Syslog; ist der Syslog-Port auf der Ziel-Node belegt, bleibt Syslog aus.

## 0.2.1 – 2026-10-20

### Behoben
- Beim ersten Einschalten öffnete das Modul kurz die Ports des Standardprofils, bevor eine eigene Auswahl galt. Jetzt
  bleibt alles zu, bis die Einstellungen einmal gespeichert sind.

## 0.2.0 – 2026-10-20

Meldung an ipv64 (Phase H2).

### Neu
- Schalter „An ipv64 melden“ (Standard aus, braucht den zentralen ipv64-API-Key): alle 10 Minuten gehen Quell-IPs mit Art, Dienst, Port und Anzahl sowie Proben (Zugangsdaten aus dem Honeypot, Pfade, User-Agents, Payload-Anfang mit SHA-256) im Format `schema: 1` an ipv64. Die Daten fließen in die v64 Blocklist ein, sobald die Auswertung bei ipv64 läuft.
- Nie gemeldet werden die eigene IP und Quellen aus privaten oder reservierten Netzen (RFC 1918, CGNAT, Loopback, Link-Local, ULA, Doku-Netze); sie bleiben lokal sichtbar.
- Gemeldet wird der Zeitraum seit der letzten erfolgreichen Meldung (höchstens 7 Tage, in Stücken zu höchstens einer Stunde, beim Nachholen von mehr als einem Tag zu sechs Stunden, gzip, höchstens eine Meldung je 2 Minuten); nach einem Ausfall wird nachgeholt, bei Fehlern mit Backoff (Retry-After wird beachtet). Ohne Ereignisse geht ein kurzes Lebenszeichen, damit ipv64 aktive Sensoren zählen kann. Beim Einschalten beginnt der Zeitraum neu.
- Feste Sensor-Kennung je Installation (UUID); Version, Profil und Modus werden mitgeschickt.
- Zustand (letzte Meldung, letzter Fehler, nächster Versuch, gemeldete Quell-IPs heute/seit Start, zuletzt von ipv64 abgelehnte Quellen mit Grund) auf der Übersicht, in den Einstellungen und unter `GET /api/honeypot/status` (`report`).
- Prometheus: `node64_honeypot_report_last_success_timestamp`, `node64_honeypot_report_errors_total`, `node64_honeypot_report_sources_total`.
- Modus ohne Oberfläche: Meldung an, wenn `NODE64_IPV64_KEY` gesetzt ist (abschalten mit `NODE64_HONEYPOT_REPORT=0`); Zustand auf der Info-Seite und unter `/metrics`.

## 0.1.0 – 2026-10-20

Erste Fassung (Phase H1): leichter Low-Interaction-Honeypot als Modul mit Oberfläche.

### Neu
- Fallen-Dienste SSH, Telnet, HTTP/HTTPS (neutrale Login-Köder) und beliebige TCP-Ports: Logins werden angenommen und immer abgelehnt, nichts wird ausgeführt, keine ausgehenden Verbindungen.
- Profile `minimal`, `standard` und `full` oder eigene Auswahl (Dienst, Port, Köder); Port-Scan-Erkennung und Limits je Quell-IP.
- Port-Prüfung über die Port-Verwaltung der Node: Ports, die PROXY64, DNS64, Streams oder die Oberfläche offen haben, sind bei eigener Auswahl ein Fehler am Feld; ein Profil lässt sie weg und weist darauf hin.
- Seite Honeypot64: Zustand der Dienste, Zahlen 24 Stunden und 7 Tage (Ereignisse, Quell-IPs, Logins), Verlauf, Ranglisten (Quell-IPs, Arten, Ports, Dienste, Benutzernamen, Passwörter, Zugangsdaten, Pfade, User-Agents) und die letzten Ereignisse mit Payload als Text und Hex.
- Speicherung in der Datenbank der Node: Aufbewahrung (Standard 7 Tage) und Obergrenze einstellbar, Daten löschen.
- Benachrichtigung bei neuen Angreifern (Standard aus): höchstens eine gebündelte Meldung je Stunde mit Anzahl und den ersten IPs.
- API `/api/honeypot/status`, `/stats`, `/events`, `/config` (GET/PUT), `DELETE /api/honeypot/events`; Änderungen im Audit-Log.
- Prometheus: `node64_honeypot_connections_total{service,port}`, `node64_honeypot_logins_total{service}`, `node64_honeypot_events_total{kind,source}`, `node64_honeypot_unique_sources`, `node64_honeypot_listen_errors{port}`, `node64_honeypot_buffer_events`, `node64_honeypot_dropped_total`.
- Export/Import der Einstellungen; Dashboard-Karte.
- Ist das Modul aus, ist kein Port offen und es läuft nichts.
