# Änderungen – Honeypot64

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
