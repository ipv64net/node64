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
| Bereich neu eingeschaltet | Abholen ab Anfang (doppelt schadet nicht, die jüngere Änderung gewinnt); genau gleiche Einträge werden dabei zusammengeführt (siehe unten) |

## Was abgeglichen wird

Je Node und je Modul/Bereich schaltbar (`PUT /api/group/sync`, Einstellung `peer.sync`). Ausgetauscht wird ein
Bereich nur, wenn er auf **beiden** Nodes an ist (die abholende Node nennt ihre Bereiche, die liefernde prüft ihre).

| Modul | Bereiche | Standard | Weg |
|---|---|---|---|
| `healthchecks` | `checks` (mit Messwerten), `maintenance` | an | `/peer/v1/changes`, `/measurements`, `/relay` |
| `notifications` | `settings` (Ruhezeiten, Drossel, Bündeln) | an | `/peer/v1/changes` |
| `certs` | `certificates`, `acme`, `dns_accounts`, `cas` | aus | `/peer/v2/sync` |
| `dns64` | `settings`, `lists`, `allowlist`, `records` (mit Zonen), `forwards` (mit Umschreiben), `groups`, `group_members` | aus | `/peer/v2/sync` |

Benachrichtigungskanäle werden nicht abgeglichen. Neue Module hängen sich als Provider an `/peer/v2/sync`
(`internal/peer/cluster.go`); eine ältere Node bekommt nie Eintragsarten, die sie nicht kennt.
PROXY64 ist als Bereich geplant, aber zurückgestellt, bis die Nachfrage da ist:
[PLAN-NODE64-CLUSTER-MODULE.md](PLAN-NODE64-CLUSTER-MODULE.md). DNS64: [PLAN-NODE64-DNS64-LOKAL.md](PLAN-NODE64-DNS64-LOKAL.md)
(Einträge und Weiterleitungen mit „nur diese Node“ werden nie abgeglichen).

### Zertifikate: gleiche Einträge und ACME-Konto

**Zusammenführen:** Haben zwei Nodes beim Beitritt oder beim Einschalten eines Bereichs denselben Eintrag unter
verschiedener uid, bleibt er einmal – auf allen Nodes mit der kleineren uid (die Node mit der größeren übernimmt sie,
sobald sie die andere bekommt). Verweise der Zertifikate (ACME-Stelle, DNS-Zugang, CA) zeigen danach auf den
verbliebenen Eintrag; eine zusammengeführte uid merkt sich die Node (`certs.cluster_alias`), damit Verweise anderer
Nodes auf die alte uid weiter passen (Löschen geht nie über einen Alias). Zusammengeführt wird nur genau Gleiches:

| Bereich | gleich, wenn |
|---|---|
| `certificates` | dasselbe Zertifikat (SHA-256 des ersten Zertifikats) **und** derselbe private Schlüssel |
| `acme` (Stellen) | dieselbe Verzeichnis-URL **und** dasselbe EAB (KID und HMAC) oder beide ohne |
| `dns_accounts` | derselbe Anbieter **und** dieselben Zugangsdaten (der Name zählt nicht) |
| `cas` | dasselbe CA-Zertifikat **und** derselbe Schlüssel |

Alles andere bleibt getrennt, auch bei gleichem Namen. Sonderfall: dieselbe ACME-Verzeichnis-URL mit anderem EAB
kann es je Node nur einmal geben – sie wird nicht übernommen (Warnung „cluster change not applied“), Zertifikate mit
dieser Stelle erneuert dann nur ihre Node.

**ACME-Konto** (Eintrag `account` im Bereich `acme`): Hat die andere Node keins oder dasselbe (gleicher Schlüssel),
gilt es überall (Mail und Annahme der Bedingungen gehen mit). Sind es verschiedene Konten, wird **nichts
überschrieben**: Jede Node nutzt weiter ihr eigenes, die abweichenden stehen in `certs.acme_conflicts`, und die Seite
`/cluster` zeigt unter den Abgleich-Einstellungen die Karte „ACME-Konto im Cluster“ mit Node, Stelle, Mail und
Anlagedatum je Konto und „Dieses verwenden“ (API: `GET /api/group` → `acme_accounts`, Wahl mit
`POST /api/group/acme` Body `{"thumbprint":"…"}`; Audit `cert.account.choose` mit den verworfenen Konten). Die Wahl
(Zeitpunkt und die abgelösten Konten als Fingerabdruck des Schlüssels, `certs.acme_choice`) geht mit dem Konto an die
anderen Nodes; wessen Konto abgelöst ist, übernimmt das gewählte, ein später eintreffendes altes Konto ändert nichts
mehr. Bei zwei verschiedenen Wahlen gilt die jüngere. Ausgestellte Zertifikate bleiben gültig, erneuert wird mit dem
gewählten Konto. Kommt später eine Node mit einem dritten Konto dazu, erscheint die Wahl erneut.

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

**Meldung:** Ist eine Node länger als **5 min** nicht erreichbar oder ausgesetzt, kommt die Benachrichtigung
„🔴 Cluster: Node … nicht erreichbar“ (Grund: letzter Fehler bzw. `suspended: <grund>`), bei Rückkehr „🟢 … wieder
erreichbar“ (Kanäle unter Benachrichtigungen, Link auf `/cluster`). Es meldet genau eine Node: die mit der
kleinsten Kennung unter den erreichbaren; die Entwarnung schickt, wer gemeldet hat. Das Dashboard zeigt dann oben
einen Hinweis und in der Kachel **Cluster** (nur mit Mitgliedern) den Zustand jeder Node.

## Split-Brain (Verbindung zwischen Teilen des Clusters länger weg)

Es gibt **keinen Anführer und keine Mehrheitsregel**: Jeder Teil arbeitet allein weiter, nichts wird gesperrt.
Nach der Wiederverbindung holt jede Node ab ihrem letzten Stand alles nach (das Protokoll hält je Eintrag nur den
letzten Stand, es läuft also nicht über), und alle landen beim selben Ergebnis:

| Was | Während der Trennung | Nach der Wiederverbindung |
|---|---|---|
| Eintrag nur auf einer Seite geändert/neu | normal | kommt überall an |
| derselbe Eintrag auf beiden Seiten geändert | jede Seite hat ihren Stand | **jüngere Änderung gewinnt, als Ganzes** (kein Zusammenführen einzelner Felder); die ältere geht verloren |
| auf einer Seite gelöscht, auf der anderen geändert | – | jüngere gewinnt: Änderung nach dem Löschen holt den Eintrag zurück, sonst bleibt er gelöscht |
| Löschvermerke | Checks/Wartungsfenster dauerhaft; Module über v2 (Zertifikate) 30 Tage | Trennung > 30 Tage: ein gelöschtes Zertifikat kann von der anderen Seite zurückkommen |
| Messwerte | jede Node misst selbst | werden nachgeholt (Messwerte gehören je einer Node, kein Konflikt) |
| Benachrichtigungen | **jede Seite meldet für sich** – Checks, die auf beiden Seiten gemessen werden, können doppelt gemeldet werden (verknüpft mit ipv64 bewertet und meldet der hub, dann nicht) | wieder genau eine Node |
| Meldung „Node nicht erreichbar“ | jede Seite meldet die Nodes der anderen | Entwarnung von denselben Nodes |
| Zertifikate | ist die zuständige Node auf der anderen Seite, erneuert diese Seite ab einem Drittel der Frist selbst | jüngeres Zertifikat gewinnt überall (höchstens einmal doppelt bestellt) |
| Mitglieder entfernen/aufnehmen | erreicht nur die eigene Seite | nicht automatisch nachgeholt: entfernte Node auf der anderen Seite ggf. dort auch entfernen |

**Beispiel drei Nodes, A+B getrennt von C:** A und B gleichen weiter untereinander ab und melden als Paar
(A meldet „C nicht erreichbar“); C arbeitet allein und meldet „A“ und „B nicht erreichbar“. Checks, die nur C misst,
meldet C; Checks, die A/B und C messen, melden beide Seiten. Nach der Wiederverbindung bekommt C alles von A und B,
A und B alles von C; bei Änderungen am selben Eintrag gewinnt die jüngere – **auch wenn sie von C (der Minderheit)
kommt**. Die Uhrzeit entscheidet, daher NTP auf allen Hosts (bei mehr als 5 min Abweichung sprechen die Nodes ohnehin
nicht miteinander).

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
