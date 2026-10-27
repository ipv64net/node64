# Plan: CDN64 Schutz-Statistik mit Mini-WAF (srv07/srv08)

Stand 2026-10-27, zweite Fassung nach Dennis' Rückmeldung: Schwerpunkt sind die **Statistiken** („so schützt dich
CDN64“), die WAF nur in der kleinsten, einfachsten Form ohne spürbaren Leistungsverlust. Noch nichts umgesetzt.

## 1. Kennzahlen (vier kleine Kacheln je Host, 30 Tage, alle Modi)

1. **Abgewehrt** – Verbindungen/Anfragen, die das Ziel nie erreicht haben (Tooltip: Blocklisten · Zugriffsliste ·
   Überlast · Mini-WAF).
2. **Gesperrte IP-Adressen** – Anzahl verschiedener Angreifer-IPs (IPv6 je /64).
3. **Überlast abgefangen** – Verbindungen/Anfragen über den Grenzen (Verbindungen je IP, Verbindungsrate,
   Anfrage-Limit).
4. **Anschluss verborgen** – Verbindungen über CDN64 (eigene IP unsichtbar), davon über IPv4 erreicht
   (DS-Lite/IPv6-only: „ohne CDN64 nicht erreichbar gewesen“).

Modus 1 liefert 1–4 ohne den WAF-Anteil (kein Einblick in HTTP).

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
Portmapper. Erweiterbar später (Liste von ipv64 statt fest im Code), JA4 bewusst nicht in diesem Plan.

## 5. Phasen

| Phase | Inhalt | Aufwand |
|---|---|---|
| S1 | Zähler + Zuordnung zum Host, Meldung, SQL, `protection` in GET /cdn64o, 4 Kacheln in PROXY64 und Portal | 2 Tage |
| S2 | Mini-WAF (Modus 2/3) mit Schalter je Host | ½–1 Tag |

Ausrollen: cdn64-edge 0.19.0 + Portal (SQL + `api_v2_cdn64o.php`, ggf. `cdn64.php`) + PROXY64.

## 6. Offene Fragen an Dennis

1. Anzeige zusätzlich im Portal (ipv64.net/cdn64) – ja?
2. Mini-WAF standardmäßig an (Modus 2/3)?
