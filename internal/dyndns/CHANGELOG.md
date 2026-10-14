# Änderungen – DynDNS-Updater

## 1.0.0 – 2026-10-14

Erste vollständige Fassung, auf der Testbox und der Dev-Node live abgenommen (IPv4 und IPv6).

### Neu
- Modul *DynDNS* ersetzt den Platzhalter; ausgeschaltet laufen keine Goroutinen und es gibt keine Tabellen.
- Öffentliche IPv4/IPv6 und /64-Präfix über `ipv4.ipv64.net` / `ipv6.ipv64.net` (Verbindung auf die Familie festgelegt), Rückfall API v2 `/ip`, optional eigene Prüf-URL; Prüftakt 1–60 min (Standard 5).
- Hinweis bei möglichem CGNAT (100.64.0.0/10) oder DS-Lite (192.0.0.1) über die ersten Stationen ins Internet, mit Links zu Artikel, FAQ und Portmapper.
- Ziele aus dem Account auswählen (zentraler ipv64-API-Key in den Einstellungen) oder von Hand anlegen; je Name wählbar, was aktualisiert wird; Ziele unter ihrer Domain gruppiert.
- Immer der sicherste Token: Record-Token vor Domain-Token, im HTTP-Header, verschlüsselt gespeichert, nie ausgegeben.
- IPv6-Modi: Adresse dieses Hosts, nur Präfix (zonenweit), Präfix + Interface-ID, Interface (stabile Adresse), fest, aus.
- Updater: meldet nur bei Abweichung (zuletzt gemeldet und direkte Abfrage der ipv64-Nameserver), nur die geänderte Familie, mindestens 5 s Abstand, Backoff bei Cooldown, Tageslimit, 3 min Schonfrist nach einem Update.
- Automatische Pausen mit Erklärung: Token abgelehnt, Name unbekannt, Konflikt (CNAME/CDN), bei ipv64 ignoriert, wird woanders geändert.
- Verlauf aller Updates und IP-Prüfungen mit Filtern, Aufbewahrung einstellbar; Update-Limit des Accounts mit eigenem Zähler und Warnung ab 80 %.
- Benachrichtigungen (Adresswechsel, Fehler/Pause, Limit) über die Standardkanäle; ipv64-Mail/-SMS direkt über die API, nicht über die hubs.
- Lokale API `/api/dyndns/*` mit OpenAPI-Doku; Export/Import ohne Tokens (Import holt sie mit dem API-Key).

### Behoben während der Abnahme
- `success` mit `ip.ipv4 = ignore`/`cdn` wurde als Erfolg gewertet; das Ziel pausiert jetzt.
- Zweiter Aufruf kurz nach einem Update, solange die Nameserver noch den alten Stand liefern.
- Bei fehlgeschlagener Prüfung einer Familie wurde die zuletzt bekannte, veraltete Adresse gemeldet.
- Fehlermeldung auch bei „Jetzt aktualisieren“ (jetzt nur bei automatischen Läufen).
