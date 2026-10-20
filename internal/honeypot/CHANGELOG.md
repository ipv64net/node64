# Änderungen – Honeypot64

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
