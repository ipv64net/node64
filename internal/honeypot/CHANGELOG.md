# Änderungen – Honeypot64

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
