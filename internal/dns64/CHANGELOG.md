# Änderungen – DNS64

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
