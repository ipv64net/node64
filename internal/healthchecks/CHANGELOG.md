# Änderungen – Healthchecks

## 2.0.0 – 2026-10-14

Healthchecks 2.0: erste vollständige Fassung in Node64, lokal und zusammen mit den ipv64-hubs.

### Neu
- Check-Arten HTTP(S), Schlüsselwort, Ping, TCP-Port, DNS, Zertifikatsablauf, Push und Docker-Container (Socket/TCP); Port nur im Port-Feld, host:port im Ziel wird übernommen.
- Messstellen je Check: Lokal, Online (ipv64-hubs), Hybrid und mehrere messende Nodes; Anzeige, wo ein Check gemessen wird (Online, Hybrid, Lokal, Andere Node).
- Healthchecks-Sync mit ipv64: Verknüpfung per Code oder mit einem Klick über den API-Key, Postausgang und Konflikte, alles von jeder Node änderbar (Checks, Kanäle, Wartung, Jetzt prüfen über den hub).
- Online-Checks auch ohne Sync direkt über die ipv64 API v2 (nur API-Key).
- Tageskontingent der Online-Checks wie im alten System: Vorschau im Formular, Hochrechnung im Dashboard, Benachrichtigung beim Erreichen.
- Übersicht mit Ziel-Badges, Gruppen, Filtern, Massenaktionen und Countdown bis zur nächsten Messung; Ansicht für Handy und Tablet.
- Detailseite mit Diagramm je Messstelle (Legende filtert), Ereignissen mit Grund- und HTTP-Code, Störungen und Wartungsfenstern.
- Verlauf fremder Messstellen wird vom hub nachgeladen (Einzelmessungen 2 Tage, Stundenwerte 90 Tage).
- Benachrichtigungen über die Kanäle des Kerns, Browser-Benachrichtigungen; Datenhaltung und Diagramm-Auflösung einstellbar.
- Lokale API `/api/healthchecks/*` mit OpenAPI-Doku; Export/Import.

### Behoben während der Abnahme
- Online-Checks und Checks anderer Nodes kamen in den lokalen Scheduler.
- Historie fremder Messstellen ging beim Ändern der Messstellen verloren.
- Besitz eines Checks blieb bei einer Node, die ihn nicht mehr misst; er geht jetzt an die erste messende Node.
