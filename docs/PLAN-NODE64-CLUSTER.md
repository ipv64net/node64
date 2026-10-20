# Plan: Cluster (aus der „lokalen Gruppe“)

Stand 2026-10-19, Entscheidungen Dennis. Die lokale Gruppe (Package `internal/peer`) wird zum **Cluster** mit eigenem
Menüpunkt. Immer optional: ohne Mitglieder kein Verkehr. Technische Kennungen bleiben (`peer`, `peer_*`-Tabellen,
`/peer/v1/*`, `/api/group/*`, Audit-Bereich `sync`).

## Entscheidungen

- **Mitglieder:** alle mit demselben ipv64-Account **oder** alle ohne Account (Konto 0). Gemischt geht nicht.
  Ein Cluster ohne ipv64 funktioniert vollständig lokal, auch Healthchecks (Bewertung/Benachrichtigung lokal).
- **Netze:** Mitglieder können in verschiedenen Netzen stehen (Adresse je Mitglied frei änderbar).
- **Übertragung:** nur **HTTPS** (HTTPS-Port der Node). Das Zertifikat muss nicht gültig sein (selbst signiert ok),
  Schutz gegen Mitlesen/Mittelsmann trotzdem (Bindung an die Ed25519-Schlüssel der Kopplung).
- **Grundlegende Änderung an einer Node** (Account geändert 0→X, X→Y, X→0, Schlüssel/Identität, Zertifikatsbindung
  passt nicht): die Node wird **ausgesetzt**, keine Kommunikation mehr mit ihr, bis sie wieder aufgenommen wird.
  Bei drei Nodes arbeiten die anderen beiden weiter.
- **Was abgeglichen wird:** je Node je Modul und je Bereich einschaltbar. Ausgetauscht wird ein Bereich nur, wenn er
  auf beiden Seiten an ist (Ping meldet die Bereiche). Healthchecks ist ohne Einstellung an (wie bisher), alles
  andere aus.
- **Healthchecks:** weiter über die hubs wie bisher; der Cluster ist ein zusätzlicher, optionaler Weg und läuft
  auf seinem bewährten Pfad (`/peer/v1/changes`, Messwerte, hub-Daten) – jetzt mit Schaltern je Bereich.
- **Neue Module** (Zertifikate jetzt; PROXY64, DNS64 später) über den allgemeinen Weg `/peer/v2/sync`
  (Provider-Schnittstelle in `internal/peer/cluster.go`). Kein neues Protokoll für spätere Module nötig.

## Schnittstellen (verbindlich für die parallelen Sitzungen)

### Go, Package `peer`

- `Member.Sync []string` (Bereiche „modul/bereich“ laut Ping, nil = ältere Version), `Member.State`
  (`""`/`"active"`, `"suspended"`), `Member.Reason` (Kennung), `Member.Suspended() bool`.
- Gründe (`Reason`): `account_changed` (eigener Account geändert), `account_mismatch` (Account der anderen
  Node passt nicht), `identity_changed` (Schlüssel/Node-Kennung), `tls_binding` (Verbindung nicht an die Kopplung
  gebunden, z. B. TLS-terminierender Proxy dazwischen), `version_too_old`. Die Oberfläche übersetzt sie
  (`cluster.reason.<kennung>`).
- `(*Manager).Resume(ctx, nodeID) error` – wieder aufnehmen (prüft erneut; passt es nicht, bleibt sie ausgesetzt).
- `(*Manager).SyncModules(ctx) []ModuleState`, `(*Manager).SetSync(ctx, module, item string, on bool) error`
  (`item == ""` schaltet das Modul), `ErrUnknownSync`.
- `(*Manager).RegisterProvider(p Provider)`; `Provider` = `ClusterModule()`, `ClusterIDs`, `ClusterGet`,
  `ClusterApply`. Module melden lokale Änderungen mit `(*Manager).ClusterChange(ctx, module, item, id, deleted)`;
  bei Übernahmen trägt `ctx` die Herkunft (`WithClusterOrigin`/`ClusterOrigin`) – der Cluster führt Protokoll und
  Zeitstempel (jüngere Änderung gewinnt), das Modul liefert nur Daten.

### Web-API (Oberfläche, Sitzung „Cluster-Seite“)

- `GET /api/group` wie bisher, zusätzlich je Mitglied `state`, `reason`, `sync` (Liste) und oben `sync_modules`
  (= `SyncModules`), `https_port` (0 = aus → Hinweis, Cluster braucht HTTPS).
- `PUT /api/group/sync` Body `{"module":"certs","item":"certificates","enabled":true}` (`item` leer = Modul) →
  liefert `sync_modules`.
- `POST /api/group/members/{id}/resume` → `Resume`.

## Aufteilung (parallel)

| Teil | Wer | Dateien |
|---|---|---|
| K1 Menü „Cluster“, Seite `/cluster`, Schalter, Healthchecks-Sync-Seite verweist dorthin, API-Routen oben, openapi, i18n `cluster.*` | Sitzung „Cluster-Seite“ | `internal/web/**`, i18n (`cluster.*`, `nav.cluster`) |
| K2/K3 Account-Regel (0 erlaubt), HTTPS mit Bindung an die Kopplung, Aussetzen/Wiederaufnehmen | Sitzung „Cluster-Transport“ | `internal/peer/protocol.go`, `peer.go`, `suspend.go`, neue `transport*.go`, Migration `0007_*` |
| K4/K5 allgemeiner Abgleich `/peer/v2/sync`, Schalter im Healthchecks-Weg | Hauptsitzung | `internal/peer/cluster.go`, `sync2.go`, `config.go`, `measure.go`, `relay.go`, `settings.go`, Migration `0006` |
| Zertifikate als erstes Modul über den Cluster | Sitzung „Cluster-Zertifikate“ | `internal/certs/**`, Verdrahtung in `cmd/node64/main.go` (nur die Zeile) |
| Bonus: PROXY64-Tabelle zeigt Verbindungsweg zum CDN64-Server | Sitzung „PROXY64-Verbindungsweg“ | `internal/cdn64/**`, ggf. `internal/tunnel/client.go`, i18n `cdn64.online.via_*` |

Regeln für alle: nur eigene Dateien stagen (`git add -- <pfad>`), nie `-a/-A`, nicht pushen, nichts auf die Box
deployen. i18n-Dateien nur mit kleinen Einfügungen (Edit-Werkzeug, vorher frisch lesen). Keine CHANGELOG-Einträge
(sammelt die Hauptsitzung), außer PROXY64-Bonus (cdn64-CHANGELOG de+en).

## Stand 2026-10-19 (gebaut, nicht deployt)

- 8ab770d Schnittstellen · 655f056/602b1b1 v2-Abgleich + Healthchecks-Schalter · c72f709/c1936cf Transport
  (HTTPS über HTTPS-Port oder Dualport, Konto 0, Aussetzen) · b9f9116/a5e5cdb Seite `/cluster` · 11c8890 Zertifikate ·
  cbe4dc9 Healthchecks 2.16.0 · 5f792fd PROXY64 1.17.1 (Verbindungsweg, Bonus).
- Live lokal getestet (zwei Nodes ohne ipv64, nur Web-Port per Dualport): Kopplung, http→https, Klartext an
  `/peer/` = 426, Check-Abgleich, Healthchecks-Schalter aus/an (holt nach), Zertifikat übernommen und Löschen verteilt.
- Benachrichtigungen (Ruhezeiten, Drossel, Bündeln) sind ein eigenes Modul `notifications` unter „Was wird
  abgeglichen“ (Dennis 2026-10-19), technisch weiter Eintragsart `settings` im eigenen Weg `/peer/v1/changes`.
- Zertifikate: erneuert die Node, die zuletzt ausgestellt hat; eine andere übernimmt erst bei einem Drittel der
  Erneuerungsfrist (LE: 10 Tage). Löschen auf einer Node löscht überall.

## Später (nicht jetzt, aber nicht verbauen)

- PROXY64 (Hosts, Zugriffslisten, Einstellungen) und DNS64 (Zonen, Einträge, Listen) als Provider – geplant, aber
  zurückgestellt bis zur Nachfrage (Dennis 2026-10-20): [PLAN-NODE64-CLUSTER-MODULE.md](PLAN-NODE64-CLUSTER-MODULE.md).
- Nur eine Seite erreichbar (NAT): Austausch in beide Richtungen über eine Verbindung.
