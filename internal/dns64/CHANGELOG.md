# Änderungen – DNS64

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
