# Cluster (Node64) – technische Referenz

Stand 2026-10-19 (node64 0.11.117-dev, Healthchecks 2.16.0). Beschreibt, wie die Nodes eines Clusters miteinander
sprechen: Ports, Ablauf, Zeiten, Grenzen und was passiert, wenn eine Node weg ist. Bedienung und Hintergrund für
Anwender: node64.de unter `/docs/cluster/`. Entscheidungen und Commits: [PLAN-NODE64-CLUSTER.md](PLAN-NODE64-CLUSTER.md),
Healthchecks-Ablauf im Detail: [LOKALE-GRUPPE.md](LOKALE-GRUPPE.md). Code: `internal/peer`.

## Port und Verbindung

| Was | Wert |
|---|---|
| Port | normaler Web-Port `NODE64_HTTP_PORT` (Standard 8080, spricht per Dualport auch TLS); ist `NODE64_HTTPS_PORT` gesetzt, dieser |
| Protokoll | nur HTTPS (TLS 1.2+); Klartext-HTTP an `/peer/*` → `426 Upgrade Required` |
| Zertifikat | wird nicht geprüft (selbst signiert genügt), kein Pinning – ein Zertifikatswechsel ändert nichts |
| Richtung | jede Node fragt die anderen ab (Pull); beide Seiten müssen die jeweils andere unter ihrer Mitglieds-Adresse erreichen |
| Proxy dazwischen | nur ohne TLS-Aufbruch (TCP-Weiterleitung, Portfreigabe, VPN); ein TLS-terminierender Proxy bricht die Bindung → `tls_binding` |
| Uhrzeit | Hosts per NTP; erlaubte Abweichung ±5 min |
| Andere Ports | keine; ausgehend zu ipv64 nur, wenn eine Node verknüpft ist (unabhängig vom Cluster) |

## Endpunkte (auf dem Web-Port, ohne Sitzung/CSRF)

| Methode | Pfad | Zweck |
|---|---|---|
| POST | `/peer/v1/pair` | Beitritt mit Code (HMAC über Code und TLS-Bindung, Code geht nie im Klartext) |
| GET | `/peer/v1/ping` | Erreichbarkeit, Version, Account, eingeschaltete Bereiche (`sync`) |
| POST | `/peer/v1/members` | Mitglieder weitergeben (Beitritt, Entfernen, Austritt) |
| GET | `/peer/v1/changes?since=&items=` | Protokoll Healthchecks/Benachrichtigungen (checks, maintenance, settings) |
| POST | `/peer/v1/poke` | „bei mir gibt es Neues“ → sofort abholen |
| GET | `/peer/v1/measurements` | Messwerte der anderen Node (Healthchecks) |
| GET | `/peer/v1/relay` | hub-Daten einer verknüpften Node für nicht verknüpfte |
| GET | `/peer/v2/sync?since=&items=` | allgemeiner Abgleich der übrigen Module (Zertifikate; später PROXY64, DNS64) |

## Sicherheit

- Jede Node hat ein Ed25519-Schlüsselpaar (privater Schlüssel verschlüsselt in der DB, Einstellung `peer.key`).
- **Anfrage** signiert über: Methode, Pfad, Zeit, Account, Nonce, TLS-Exporter (RFC 5705/8446, Label
  `EXPORTER-node64-cluster`, 32 Byte) und SHA-256 des Bodys. **Antwort** ebenso signiert (Status, Nonce, Node,
  Exporter, Body). Ein Mittelsmann hat zu beiden Seiten andere Exporter → Ablehnung, bevor Daten fließen.
- Anfragen mit Body gehen erst nach einem signierten Ping über dieselbe Verbindung raus.
- Wiederholungsschutz: jede Nonce wird im Zeitfenster gemerkt, eine Wiederholung → `401 replayed request`.
- Größe: Body höchstens 8 MiB, Beitritt 1 MiB.
- Beitrittscode: 8 Zeichen, 10 min gültig, einmal verwendbar, nach 5 Fehlversuchen verworfen.
- Account: alle Mitglieder gleicher ipv64-Account oder alle ohne (0). Er steht in jeder Signatur.

## Zeiten und Grenzen

| Was | Wert |
|---|---|
| Ping an jedes Mitglied | alle 30 s |
| Mitglied gilt als offline | nach 2 min ohne Antwort |
| Abholen (Pull) | alle 15 s, bei Änderungen sofort (Anstoß gebündelt, höchstens alle 0,5 s) |
| Zeitlimit je Anfrage | 10 s (Ping, Anstoß 5 s), Protokoll-Seite 20 s, Messwerte/hub-Daten/v2 30 s |
| Seitengröße | Protokoll 200 Einträge (bis 100 Seiten je Lauf), Messwerte 1000 (bis 50 Seiten) |
| Erstes Abholen der Messwerte | die letzten 24 h |
| Healthchecks bei der anderen Node aus | 5 min Ruhe statt alle 15 s (ein Anstoß holt trotzdem sofort) |
| Konflikte | jüngere Änderung gewinnt (ms), Gleichstand: größere Node-Kennung der Urheberin |
| Löschvermerke (v2) | 30 Tage |
| Bereich neu eingeschaltet | Abholen ab Anfang (doppelt schadet nicht, die jüngere Änderung gewinnt) |

## Was abgeglichen wird

Je Node und je Modul/Bereich schaltbar (`PUT /api/group/sync`, Einstellung `peer.sync`). Ausgetauscht wird ein
Bereich nur, wenn er auf **beiden** Nodes an ist (die abholende Node nennt ihre Bereiche, die liefernde prüft ihre).

| Modul | Bereiche | Standard | Weg |
|---|---|---|---|
| `healthchecks` | `checks` (mit Messwerten), `maintenance` | an | `/peer/v1/changes`, `/measurements`, `/relay` |
| `notifications` | `settings` (Ruhezeiten, Drossel, Bündeln) | an | `/peer/v1/changes` |
| `certs` | `certificates`, `acme`, `dns_accounts`, `cas` | aus | `/peer/v2/sync` |

Benachrichtigungskanäle werden nicht abgeglichen. Neue Module hängen sich als Provider an `/peer/v2/sync`
(`internal/peer/cluster.go`); eine ältere Node bekommt nie Eintragsarten, die sie nicht kennt.

## Wenn eine Node weg ist

1. Die anderen pingen sie weiter alle 30 s; nach **2 min** gilt sie als **offline** (Liste: offline, letzter Fehler).
   Sie wird **nicht** ausgesetzt und nicht entfernt – offline ist kein Grund zum Aussetzen.
2. Die übrigen Nodes arbeiten normal weiter und gleichen untereinander ab.
3. **Benachrichtigen:** Misst sie einen Check mit anderen zusammen, übernimmt die nächste erreichbare messende Node
   die Meldungen (ohne Doppelmeldung). Misst nur sie einen Check, meldet nach 3 Intervallen (mind. 5 min) ohne
   Messung „nicht überwacht“ (`unchecked`).
4. **Weiterreichen an ipv64:** War sie die weiterreichende Node, übernimmt die nächste verknüpfte erreichbare Node.
5. **Kommt sie zurück:** Beide Seiten holen ab ihrem letzten Stand alles nach, was in der Zwischenzeit geändert
   wurde (auch Änderungen, die auf ihr selbst gemacht wurden); Messwerte ab dem letzten Stand. Dauerhaft
   entfernen nur mit „Aus dem Cluster nehmen“.

Eine eigene Meldung „Cluster-Node nicht erreichbar“ gibt es (noch) nicht; sichtbar ist es in der Oberfläche, im
Log und per Prometheus (`node64_group_member_up`).

## Ausgesetzte Nodes

Grundlegende Änderung → ausgesetzt: keine Anfragen mehr an sie, ihre Anfragen werden mit 403 abgelehnt; die anderen
arbeiten weiter. Gründe: `account_changed`, `account_mismatch`, `identity_changed`, `tls_binding`,
`version_too_old`. Zurück nur mit „Wieder aufnehmen“ (prüft erneut) – außer `version_too_old`: wird beim nächsten
Ping nach dem Update der anderen Node von selbst wieder aktiv (gestaffeltes Update).

## Beobachten

- Oberfläche `/cluster`, API `GET /api/group` (je Mitglied `online`, `state`, `reason`, `sync`, `last_seen`,
  `last_error`).
- Prometheus: `node64_group_members`, `node64_group_members_online`, `node64_group_member_up{node_id,node_name}`.
- Log (Modul `peer`): „cluster member suspended/resumed“, „peer request rejected“, „cluster entries updated“;
  Abholfehler auf Debug. Audit-Bereich `sync` (Aktionen `peer.*`).
