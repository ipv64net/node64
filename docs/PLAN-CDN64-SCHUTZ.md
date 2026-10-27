# Plan: CDN64 Schutz-Statistik und leichte WAF (srv07/srv08)

Stand 2026-10-27, Vorschlag für Dennis – noch nichts umgesetzt oder ausgerollt.

Ziel: Kunden sehen in wenigen Zahlen, wovor CDN64 sie geschützt hat (alle Modi, auch Modus 1), und die Server
bekommen einen sehr leichten Angriffsfilter – kein OWASP-CRS.

## 1. Was die Server heute schon wissen

| Stelle | Was | je Host? |
|---|---|---|
| `guard` (alle Modi, vor TLS) | Blocklisten (spamhaus_drop), Verbindungen je IP, neue Verbindungen je IP/s, Verbindungen gesamt | **nein** – nur Gesamtzähler (Prometheus), weil vor dem Namen geprüft wird |
| Zugriffsliste (IP) | Modus 1/2/3, Portmapper, QUIC | ja, wird aber nicht gezählt |
| Anfrage-Limit | Modus 2/3 (`Rejected`) | ja, geht schon als `rejected` an ipv64 (`cdn64o_traffic`) |
| Verkehr | Bytes rein/raus, Verbindungen, Anfragen | ja (`cdn64o_traffic`, je Tag) |

Die Node (PROXY64) filtert in Modus 1/2 zusätzlich selbst (Blocklisten, Honeypot, Länder, KI-Bots,
Exploit-Muster) – das zählt sie lokal schon (Statistik „abgewiesen/an Honeypot“).

## 2. Kennzahlen (vier kleine Kacheln je Host, 30 Tage)

1. **Abgewehrt** – Verbindungen/Anfragen, die das Ziel nie erreicht haben. Aufschlüsselung im Tooltip:
   Blocklisten · Zugriffsliste · Überlast · Angriffsmuster (WAF).
2. **Gesperrte IP-Adressen** – Zahl verschiedener Angreifer-IPs (IPv6 je /64), dazu die Top 5 mit Treffern.
3. **Überlast abgefangen** – Verbindungen und Anfragen über den Grenzen (Verbindungen je IP, Verbindungsrate,
   Anfrage-Limit), dazu die größte Spitze (Anfragen/s bzw. neue Verbindungen/s) des Zeitraums.
4. **Anschluss verborgen** – Verbindungen, bei denen die eigene IP nicht sichtbar war (= alle über CDN64), davon
   über IPv4 erreicht (wichtig für DS-Lite/IPv6-only: „ohne CDN64 nicht erreichbar gewesen“).

Alle vier gibt es in jedem Modus. Modus 1 hat keine WAF-Zahl (kein Einblick in HTTP), dafür ggf. JA4 (Abschnitt 4).

### Zuordnung zum Host (neu nötig)

- **Blocklisten:** Statt die Verbindung sofort zu schließen, liest der Server bei 443 noch das ClientHello (SNI) bzw.
  bei 80 die erste Zeile + Host (höchstens 1 s, höchstens 4 KB) und zählt dann beim Host. Kein Name erkennbar →
  „ohne Host“ (nur Gesamtzahl).
- **Überlast (Verbindungen je IP, Rate):** kein zusätzliches Lesen (das wäre bei einer Flut teuer). Der Server merkt
  sich je IP den zuletzt angefragten Host (im vorhandenen `gstate`) und zählt dort; neue IPs ohne Vorgeschichte →
  „ohne Host“.
- **Zugriffsliste, Anfrage-Limit, WAF:** Name ist schon bekannt.
- **IP-Adressen:** je Host und Meldeintervall eine begrenzte Menge (höchstens 1000 IPs mit Trefferzahl).

## 3. Datenweg

```
srv07/srv08  hostStat + neue Zähler ──(edge/report, jede Minute, Differenzen)──▶ ipv64 API v2
             (blocked_blocklist, blocked_acl, blocked_flood, blocked_limit,      cdn64o_traffic (neue Spalten, je Tag)
              blocked_waf, conns_v4, peak_rps, blocked_ips[{ip,hits}])            cdn64o_blocked_ips (host, Tag, IP, Treffer)
                                                                                         │
                       GET /cdn64o (host_out.protection, 30 Tage)  ◀─────────────────────┘
                                │                         │
                      PROXY64 (Node64)              Portal ipv64.net/cdn64
                      4 Kacheln je Host,            nur die 4 Zahlen je Host
                      Top-IPs, Verlauf              (schlank)
```

- **SQL (eine Datei an Dennis):** `ALTER TABLE cdn64o_traffic ADD COLUMN` für `blocked_blocklist`, `blocked_acl`,
  `blocked_flood`, `blocked_limit`, `blocked_waf`, `conns_v4`, `peak_rps`. Neue Tabelle `cdn64o_blocked_ips`
  (host_id, day, ip, hits, PK host_id+day+ip), höchstens 1000 je Host und Tag, Aufräumen nach 30 Tagen im
  vorhandenen Job (`honeypot_cron.php`, keine neue Cron-Zeile).
- **Bestehendes bleibt:** `rejected` (Anfrage-Limit) wird zu `blocked_limit` gezählt; alte Edges melden einfach
  nichts Neues.
- **Datenschutz:** Angreifer-IPs nur 30 Tage, nur zum eigenen Host sichtbar.

## 4. Leichte WAF – Optionen

| Option | Modi | Aufwand | Einschätzung |
|---|---|---|---|
| **A. PROXY64-Regeln auf die Server** (gemeinsames Paket aus `internal/cdn64`: Exploit-Muster wie NPM `block-exploits` + `.git`/`.env`, schlechte User-Agents, KI-Bots aus der v64-Liste) | 2, 3 | 1–2 Tage | **Empfohlen als Start.** Regeln sind erprobt, gleiches Verhalten Node/Server, je Host abschaltbar. |
| **B. Scanner-Bremse** (viele 404/403 einer IP in kurzer Zeit → IP für 10 min gesperrt, je Host) | 2, 3 | 1 Tag | Sehr wirksam gegen Pfad-Scanner, praktisch keine Fehlalarme. |
| **C. JA4-Fingerabdruck** des TLS-ClientHello | **1**, 2, 3 | 3–5 Tage | Einziges Leichte für Modus 1. Honeypot64 berechnet JA4 schon selbst (`internal/honeypot/sensor_fp.go`) und ipv64 sammelt die Fingerabdrücke der Angreifer (`hp_samples_fps`) – daraus eine Liste „v64 JA4“. Vorsicht: curl, Python, Go-Clients teilen sich Fingerabdrücke mit harmlosen Monitoring-/API-Clients → nur Fingerabdrücke, die nie von Browsern kommen; erst „nur zählen“, dann je Host „sperren“. |
| D. JA4H (HTTP-Fingerabdruck) | 2, 3 | – | Go `net/http` liefert die Reihenfolge der Kopfzeilen nicht; nur mit eigenem HTTP-Parser. **Nicht empfohlen.** |
| E. Coraza + OWASP CRS | 2, 3 | 3+ Tage + Pflege | Zu schwer für 2 vCPU, viele Fehlalarme, Regelpflege. **Nicht empfohlen**, höchstens später als „Streng“-Stufe für Business. |

Fremdbibliotheken für JA4 in Go gibt es (z. B. ja4plus, tlsfingerprint), sie sind aber jung; die eigene
Honeypot-Implementierung (mit Tests) in ein gemeinsames Paket zu verschieben ist sicherer.

Einstellungen je Host (bei ipv64, `cdn64o_hosts`, an die Server über `edge/config`): WAF an/aus (Standard an in
Modus 2/3), Scanner-Bremse an/aus, JA4 aus/zählen/sperren. Treffer zählen in „Abgewehrt · Angriffsmuster“.

## 5. Phasen und Aufwand

| Phase | Inhalt | Aufwand |
|---|---|---|
| S1 | Zähler auf den Servern inkl. Zuordnung zum Host, Meldung, SQL, API `protection`, 4 Kacheln in PROXY64 und Portal | 2–3 Tage |
| S2 | WAF Option A + B (Modus 2/3), Schalter je Host | 2–3 Tage |
| S3 | JA4 auf den Servern (zählen), Liste „v64 JA4“ aus den Honeypot-Daten, danach „sperren“ je Host | 3–5 Tage |

Ausrollen je Phase: Edges (cdn64-edge 0.19.x) + Portal (SQL + `api_v2_cdn64o.php`) + Node (PROXY64).

## 6. Fragen an Dennis

1. Sollen Kunden die gesperrten IPs selbst sehen (Top 5) oder nur die Anzahl?
2. Aufbewahrung der Angreifer-IPs: 30 Tage in Ordnung?
3. WAF (A/B) in Modus 2/3 standardmäßig an?
4. JA4 (S3) gleich mit einplanen oder erst nach S1/S2?
5. Anzeige im Portal (ipv64.net/cdn64) zusätzlich zu PROXY64 – ja?
