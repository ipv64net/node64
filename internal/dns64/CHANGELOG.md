# Änderungen – DNS64

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
