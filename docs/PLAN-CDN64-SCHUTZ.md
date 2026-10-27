# Plan: CDN64 Schutz-Statistik und leichte WAF (srv07/srv08)

Stand 2026-10-27, vierte Fassung mit Dennis' Entscheidungen. Noch nichts umgesetzt.

**Leitlinie (Dennis):** Die Statistik ist das Verkaufsargument („CDN64 schützt dich, bringt dich weiter“). Die WAF
gibt es in **allen drei Modi**, aber nur leichtgewichtig und performant. **Nur eigene Daten** (Honeypot64), keine
externe Datenbank.

## 1. Kennzahlen (je Host und für das Konto, alle Modi)

1. **Abgewehrt** – Verbindungen/Anfragen, die das Ziel nie erreicht haben, nach Grund: Blocklisten ·
   Zugriffsliste · Überlast · WAF-Muster · Angriffs-Werkzeug (JA4/HASSH).
2. **Gesperrte IP-Adressen** – Anzahl verschiedener Angreifer-IPs (IPv6 je /64), keine IP-Listen gespeichert.
3. **Überlast abgefangen** – Verbindungen/Anfragen über den Grenzen (Verbindungen je IP, Verbindungsrate,
   Anfrage-Limit).
4. **Anschluss verborgen** – Verbindungen über CDN64 (eigene IP unsichtbar), davon über IPv4 erreicht
   (DS-Lite/IPv6-only: „ohne CDN64 nicht erreichbar gewesen“).

## 2. Erfassung auf den Servern

- Schutz vor TLS (Blocklisten, Überlast) zählt heute nur gesamt. Neu, ohne Zusatzkosten bei einer Flut:
  - **Blocklisten:** vor dem Schließen kurz SNI (443) bzw. Host (80) lesen (höchstens 1 s, 4 KB) → beim Host zählen.
  - **Überlast:** kein zusätzliches Lesen; je IP den zuletzt angefragten Host merken und dort zählen.
  - Ohne erkennbaren Host → nur Gesamtzahl.
- **Zugriffsliste, Anfrage-Limit, WAF:** Host ist bekannt.
- **IP-Adressen:** je Host und Minute nur die Anzahl verschiedener IPs (Menge höchstens 1000).

## 3. Leichte WAF – drei Bausteine, alle Modi

| Baustein | Modi | Wo/wann | Kosten |
|---|---|---|---|
| **JA4** (TLS-ClientHello) | 1, 2, 3 | Port 443, einmal je Verbindung; die Server lesen das ClientHello ohnehin (`handle443`) | Mikrosekunden je Verbindung |
| **HASSH** (SSH-Client) | 1, 2, 3 (Portmapper) | TCP-Portmapper: die ersten Bytes vom Besucher werden beim Durchreichen mitgelesen (höchstens 8 KB, nichts gepuffert, keine Verzögerung); passt der KEXINIT auf die Liste → Verbindung zu | nur für Portmapper-Verbindungen, einmal je Verbindung |
| **WAF-Muster** (HTTP) | 2, 3 | je Anfrage, einfache Textvergleiche ohne reguläre Ausdrücke: Pfade (`/.git/`, `/.env`, `/.svn/`, `/.htpasswd`, `/wp-config.php`, `/.aws/`, `/.ssh/`, `/phpinfo.php`, `/etc/passwd`, `../`) und Scanner-User-Agents (`sqlmap`, `nikto`, `nuclei`, `masscan`, `zgrab`, `wpscan`, `acunetix`, `nessus`, `dirbuster`, `gobuster`) | Mikrosekunden je Anfrage |

- **Berechnung:** JA4 und HASSH mit der vorhandenen, getesteten Honeypot64-Funktion (`internal/honeypot/sensor_fp.go`),
  in ein gemeinsames Paket (z. B. `internal/fingerprint`) verschoben – Honeypot64 und Server nutzen dieselbe.
- **Kein Request-Body, keine regulären Ausdrücke, kein JA4H, kein OWASP CRS.**
- **Standard:** WAF je Host **an** (alle drei Bausteine), je Host abschaltbar. Treffer → Modus 1/Portmapper:
  Verbindung zu; Modus 2/3: 403 mit der vorhandenen Fehlerseite (bei JA4 schon vor TLS: Verbindung zu).
- **Sicherer Start:** die erste Woche nach dem Ausrollen global „nur zählen“ (Schalter bei ipv64), dann sperren –
  so sieht man vorher, ob ein Fingerabdruck harmlose Besucher trifft.

## 4. Eigene Liste aus Honeypot64 (ipv64)

- ipv64 erzeugt aus der vorhandenen Rangliste (`hp_samples_fps`, `honeypot/hp_stats_lib.php`, gleiche Schwelle)
  die Datei `ipv64_blocklist_fp.txt`: eine Zeile je Fingerabdruck, `ja4:<…>` bzw. `hassh:<md5>`, Kommentare mit `#`.
- Ausnahmeliste (von Dennis gepflegt, klein): Fingerabdrücke von Browsern und verbreiteten Bibliotheken
  (curl, Python, Go, Monitoring) kommen nie auf die Liste – Werte aus den eigenen CDN64-Zahlen der ersten Woche.
- Erzeugt im vorhandenen Blocklisten-Job (keine neue Cron-Zeile), veröffentlicht unter `/blocklists/`, die Server
  laden sie wie `spamhaus_drop` (alle 30 min, nur bei Änderung).
- Abstimmung mit der Allgemein-Sitzung (Honeypot64 gehört dort): wer den Generator baut.

## 5. Datenweg

```
srv07/srv08 ──edge/report (jede Minute, Differenzen)──▶ ipv64
                                                          cdn64o_traffic: neue Spalten je Host und Tag
                                                          cdn64o_fp: Treffer je Host, Tag, Fingerabdruck (höchstens 20 je Host und Tag)
                     GET /cdn64o (protection, 30 Tage) ─────────┤
                     GET /cdn64o/protection?days=… ─────────────┘
                              │                         │
                   PROXY64 Tab „CDN64 Statistik“    Portal ipv64.net/cdn64: nur 4 Zahlen + Hinweis auf den Tab
```

- **SQL (eine Datei):** `cdn64o_traffic` + `blocked_list`, `blocked_acl`, `blocked_flood`, `blocked_waf`,
  `blocked_fp`, `blocked_ips`, `conns_v4`; neue Tabelle `cdn64o_fp`; WAF-Schalter je Host in `cdn64o_hosts`
  (`waf` tinyint, Standard 1). Aufräumen nach 30 Tagen im vorhandenen Job.
- Das vorhandene `rejected` (Anfrage-Limit) zählt zu „Überlast“. Alte Server melden die neuen Felder nicht.

## 6. Neuer Tab „CDN64 Statistik“ in PROXY64 – das Verkaufsargument

Eigener Reiter (`/cdn64/protection`), nur sichtbar mit CDN64-Namen. Botschaft: **CDN64 hilft, schützt dich,
bringt dich weiter.**

- **Kopf:** die 4 Kennzahlen für das Konto, Zeitraum 24 h / 7 / 30 Tage.
- **Diagramm:** Abgewehrtes je Tag, gestapelt nach Grund.
- **Tabelle je Host:** 4 Zahlen und Modus, Klick führt zum Host.
- **Top Angriffs-Werkzeuge:** häufigste JA4/HASSH-Treffer (aus der eigenen Honeypot-Liste).
- **Kasten „Ohne CDN64“:** „Deine IP-Adresse wäre X-mal sichtbar gewesen“, „Y Besucher kamen über IPv4“ (bei
  DS-Lite/IPv6-only sonst nicht erreichbar), ein Satz je Modus, was geschützt wird.

## 7. Phasen

| Phase | Inhalt | Aufwand |
|---|---|---|
| S1 | Zähler + Zuordnung zum Host, Meldung, SQL, `protection` in GET /cdn64o, 4 Zahlen im Portal | 2 Tage |
| S2 | WAF-Muster (Modus 2/3), Schalter je Host | ½–1 Tag |
| S3 | JA4/HASSH: gemeinsames Paket, Liste `ipv64_blocklist_fp.txt` bei ipv64, Laden/Zählen/Sperren auf den Servern (443 und Portmapper) | 2 Tage |
| S4 | Tab „CDN64 Statistik“ in PROXY64 inkl. `/cdn64o/protection` | 1½ Tage |

Ausrollen: cdn64-edge 0.19.0 + Portal (eine SQL-Datei, `api_v2_cdn64o.php`, Blocklisten-Job, `cdn64.php`) +
PROXY64 – jeweils nur auf Dennis' Ansage.
