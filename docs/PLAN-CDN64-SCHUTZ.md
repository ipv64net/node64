# Plan: CDN64 Schutz-Statistik mit Mini-WAF (srv07/srv08)

Stand 2026-10-27, dritte Fassung nach Dennis' Rückmeldung: Schwerpunkt sind die **Statistiken** („so schützt dich
CDN64“) mit eigenem Tab, die WAF nur in der kleinsten Form, dazu JA4 aus der Honeypot64-Liste. Noch nichts
umgesetzt.

## 1. Kennzahlen (vier kleine Kacheln je Host, 30 Tage, alle Modi)

1. **Abgewehrt** – Verbindungen/Anfragen, die das Ziel nie erreicht haben (Tooltip: Blocklisten · Zugriffsliste ·
   Überlast · Mini-WAF).
2. **Gesperrte IP-Adressen** – Anzahl verschiedener Angreifer-IPs (IPv6 je /64).
3. **Überlast abgefangen** – Verbindungen/Anfragen über den Grenzen (Verbindungen je IP, Verbindungsrate,
   Anfrage-Limit).
4. **Anschluss verborgen** – Verbindungen über CDN64 (eigene IP unsichtbar), davon über IPv4 erreicht
   (DS-Lite/IPv6-only: „ohne CDN64 nicht erreichbar gewesen“).

Modus 1 liefert 1–4 ohne den WAF-Anteil (kein Einblick in HTTP); JA4 (Abschnitt 5) zählt in allen Modi.

## 2. Erfassung auf den Servern

- Heute zählt der Schutz vor TLS (Blocklisten, Überlast) nur gesamt, weil er vor dem Namen greift. Neu, ohne
  Zusatzkosten bei einer Flut:
  - **Blocklisten:** vor dem Schließen noch kurz SNI (443) bzw. Host (80) lesen (höchstens 1 s, 4 KB) und beim Host
    zählen.
  - **Überlast:** kein zusätzliches Lesen; der Server merkt sich je IP den zuletzt angefragten Host und zählt dort.
  - Ohne erkennbaren Host → nur Gesamtzahl.
- **Zugriffsliste, Anfrage-Limit, Mini-WAF:** Host ist bekannt.
- **IP-Adressen:** je Host und Meldung nur die Anzahl verschiedener IPs (kleine Menge, höchstens 1000 je Minute) –
  keine IP-Listen speichern.

## 3. Datenweg

```
srv07/srv08 ──edge/report (jede Minute, Differenzen)──▶ ipv64: cdn64o_traffic (neue Spalten je Host und Tag)
                                                              │
                         GET /cdn64o → host_out.protection (30 Tage)
                                   │                     │
                         PROXY64: 4 Kacheln je Host   Portal ipv64.net/cdn64: dieselben 4 Zahlen (klein)
```

- **SQL (eine Datei):** `ALTER TABLE cdn64o_traffic ADD COLUMN` `blocked_list`, `blocked_acl`, `blocked_flood`,
  `blocked_waf`, `blocked_ips`, `conns_v4`. Das vorhandene `rejected` (Anfrage-Limit) zählt zu „Überlast“.
  Keine neue Tabelle, kein neuer Job.
- `blocked_ips` ist die Summe der verschiedenen IPs je Minute – über den Tag leicht überzählt, als „gesperrte
  Adressen“ aber ehrlich genug. Exakt ginge nur mit gespeicherten IPs (bewusst weggelassen).
- Alte Edges melden die neuen Felder einfach nicht.

## 4. Mini-WAF (nur Modus 2 und 3, je Host abschaltbar, Standard an)

Nur einfache Textvergleiche, keine regulären Ausdrücke, kein Request-Body, keine Fingerabdrücke:

- **Pfade**, die nie zu einer normalen Seite gehören (kleingeschrieben, enthält/endet auf): `/.git/`, `/.env`,
  `/.svn/`, `/.htpasswd`, `/wp-config.php`, `/.aws/`, `/.ssh/`, `/phpinfo.php`, `/etc/passwd`, `../`.
- **User-Agents** bekannter Angriffs-Scanner (enthält): `sqlmap`, `nikto`, `nuclei`, `masscan`, `zgrab`,
  `wpscan`, `acunetix`, `nessus`, `dirbuster`, `gobuster`.
- Treffer → 403 mit der vorhandenen Fehlerseite, Zählung „Mini-WAF“.

Kosten: zwei kurze Schleifen über Zeichenketten je Anfrage (Mikrosekunden), kein Einfluss auf Modus 1 und
Portmapper. Erweiterbar später (Liste von ipv64 statt fest im Code).

## 5. JA4 (alle Modi, auch Modus 1)

- **Berechnung:** Die Server lesen auf 443 ohnehin den Anfang jedes TLS-Aufbaus (`handle443`). JA4 rechnet die
  vorhandene, getestete Honeypot64-Funktion (`internal/honeypot/sensor_fp.go`, in ein gemeinsames Paket
  verschoben) – einmal je Verbindung, Mikrosekunden. HTTP/3 (QUIC) nicht; Browser kommen vorher immer über TCP.
- **Liste „v64 JA4“ aus Honeypot64:** ipv64 erzeugt sie aus der vorhandenen Rangliste der Fingerabdrücke
  (`hp_samples_fps`, `honeypot/hp_stats_lib.php`) – Schwelle wie dort, ohne Fingerabdrücke von Browsern und
  verbreiteten Bibliotheken (kleine Ausnahmeliste, von Dennis gepflegt). Veröffentlicht wie die Blocklisten
  (`ipv64_blocklist_ja4.txt`, im vorhandenen Job), die Server laden sie wie `spamhaus_drop`.
- **Öffentliche Quelle (optional):** ja4db.com (FoxIO) ordnet Fingerabdrücke Programmen zu (z. B. sqlmap, Sliver).
  Die Lizenz der Datenbank ist nicht geklärt → nur als Namensgeber für die Anzeige („Werkzeug: …“) und zum Prüfen
  der Ausnahmeliste nutzen, nicht weiterverteilen; vorher bei FoxIO nachfragen.
- **Je Host:** aus / nur zählen (Standard) / sperren. Gesperrt wird beim Verbindungsaufbau (Modus 1: Verbindung zu,
  Modus 2/3: vor TLS). Treffer zählen unter „Abgewehrt · Angriffs-Werkzeug“, je Fingerabdruck gezählt (höchstens
  20 je Host und Minute).

## 6. Neuer Tab „CDN64 Statistik“ in PROXY64 (Node64)

Eigener Reiter neben Proxy-Hosts/Streams/Zugriffslisten (`/cdn64/protection`), nur sichtbar mit CDN64-Namen.
Ziel: den Mehrwert zeigen.

- **Kopf:** die 4 Kennzahlen für das ganze Konto, Zeitraum 24 h / 7 / 30 Tage.
- **Diagramm:** Abgewehrtes je Tag, gestapelt nach Grund (Blocklisten, Zugriffsliste, Überlast, Mini-WAF,
  Angriffs-Werkzeug/JA4).
- **Tabelle je Host:** die 4 Zahlen und der Modus, Klick führt zum Host.
- **Top Angriffs-Werkzeuge:** die häufigsten gesperrten bzw. gezählten JA4 (mit Programmname, falls bekannt).
- **Kasten „Ohne CDN64“:** „Deine IP-Adresse wäre X-mal sichtbar gewesen“, „Y Besucher kamen über IPv4“ (bei
  DS-Lite/IPv6-only sonst nicht erreichbar), mit einem Satz je Modus, was geschützt wird.
- Das Portal (ipv64.net/cdn64) bleibt schlank: nur die 4 Zahlen und ein Hinweis auf den Tab in Node64.

Daten: neuer Endpunkt `GET /cdn64o/protection?days=30` (je Tag und Host, Summen, Top-JA4). Für die JA4-Zählung
eine kleine Tabelle `cdn64o_ja4` (host_id, day, ja4, hits; höchstens 20 je Host und Tag, 30 Tage).

## 7. Phasen

| Phase | Inhalt | Aufwand |
|---|---|---|
| S1 | Zähler + Zuordnung zum Host, Meldung, SQL, `protection` in GET /cdn64o, 4 Zahlen im Portal | 2 Tage |
| S2 | Mini-WAF (Modus 2/3) mit Schalter je Host | ½–1 Tag |
| S3 | JA4: gemeinsames Paket, Liste „v64 JA4“ aus Honeypot64 bei ipv64, Laden/Zählen/Sperren auf den Servern, Schalter je Host | 1½–2 Tage |
| S4 | Tab „CDN64 Statistik“ in PROXY64 inkl. Endpunkt `/cdn64o/protection` | 1½ Tage |

Ausrollen: cdn64-edge 0.19.0 + Portal (eine SQL-Datei + `api_v2_cdn64o.php`, Blocklisten-Job, ggf. `cdn64.php`)
+ PROXY64.

## 8. Offene Fragen an Dennis

1. Mini-WAF standardmäßig an (Modus 2/3)?
2. JA4 je Host standardmäßig „nur zählen“ – oder gleich „sperren“?
3. ja4db.com nur für Programmnamen nutzen (nach Rückfrage bei FoxIO) – oder ganz weglassen?
