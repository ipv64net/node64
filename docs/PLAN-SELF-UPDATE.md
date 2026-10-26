# Plan: Node64 aktualisiert sich selbst

Stand 2026-10-26. Ziel: Node64 kann sich ohne neues Image aktualisieren – wichtig, wo Container schwer zu
erneuern sind (Proxmox mit OCI-Image/LXC, NAS-Oberflächen, Portainer ohne Watchtower). Der Container läuft weiter,
die Daten bleiben, bei Problemen geht es automatisch zurück.

## 1. Ausgangslage

- `internal/update` prüft bereits (Opt-in `updates.check`) täglich `https://ipv64.net/node64/latest.json` und merkt
  sich das Ergebnis (`updates.latest`). Herunterladen oder Installieren gibt es nicht.
- `update.Newer` ignoriert Vorab-Kennungen: `0.12.0-alpha.15` und `0.12.0-alpha.16` gelten als gleich.
- Image: `FROM scratch`, nur `/node64`, Benutzer 65532, Wurzeldateisystem schreibgeschützt (`--read-only` üblich),
  beschreibbar nur das Volume `/data`.
- `/node64` hat Datei-Capabilities (`cap_net_bind_service,cap_net_raw,cap_net_admin=+p`), `internal/caps` schaltet
  sie beim Start scharf. **Ein nachgeladenes Programm unter `/data` hat diese Rechte nicht** (als 65532 kann man
  kein `setcap` ausführen) – ohne Vorkehrung bekäme es Port 53/443/853 und ICMP nicht.
- Datenbank-Migrationen laufen nur vorwärts; eine ältere Version startet nicht sicher auf einer neueren Datenbank.
- Images kommen über GitHub Actions (`image.yml`, amd64/arm64/arm-v7) nach GHCR; das Repo ist privat.

## 2. Lösung im Überblick

```
 Container-Start ─► /node64 (aus dem Image, mit Capabilities)
                        │  Starter: neuestes geprüftes Programm wählen
                        │    a) /node64 selbst                     (Version im Image)
                        │    b) /data/bin/node64-<version>         (Selbst-Update, Signatur geprüft)
                        │  b neuer als a ─► Capabilities als "ambient" weiterreichen, exec(b)
                        ▼
                 laufendes Node64 (PID 1 bleibt, Container läuft durch)

 Update:  Manifest holen ─► Signatur prüfen ─► Programm laden ─► SHA-256 prüfen ─► /data/bin ablegen
          ─► Datenbank sichern ─► Module sauber stoppen ─► exec(/node64)  (Starter wählt die neue Version)
          ─► neue Version läuft N Minuten gesund ─► "gut" markieren   sonst ─► Rückfall
```

- **Kein Docker-Socket nötig**, kein Neuerzeugen des Containers – funktioniert in Docker, Podman, Proxmox-LXC/OCI,
  Kubernetes gleich.
- Holt jemand später doch ein neueres Image, gewinnt automatisch die neuere Version; veraltete Dateien unter
  `/data/bin` werden aufgeräumt.

## 3. Entscheidungen (offen, für Dennis)

| # | Frage | Vorschlag |
|---|---|---|
| E1 | Woher kommen die Programme? | Solange das Repo privat ist: Dateien + Manifest auf ipv64.net (`/node64/releases/…`), von GitHub Actions gebaut, von Dennis hochgeladen. Sobald das Image öffentlich ist: direkt aus GHCR bzw. GitHub Releases, ohne Handarbeit. |
| E2 | Signaturschlüssel | Ed25519; privater Schlüssel nur als GitHub-Secret (und offline bei Dennis), öffentlicher fest im Programm. Zwei öffentliche Schlüssel erlaubt (Wechsel ohne Bruch). |
| E3 | Kanäle | `stable` (ohne Vorab-Kennung) und `preview` (alpha/beta). Standard: `stable`; während der Alpha-Phase `preview`. |
| E4 | Automatik | Standard **aus** (nur Hinweis). Optional „automatisch“ in einem Zeitfenster (z. B. 03:00–05:00), nie während einer laufenden Störung. |
| E5 | Downtime | Neustart in-place dauert wenige Sekunden; DNS64 ist so lange weg. Im Cluster mit zwei DNS64-Nodes nacheinander (später). |

## 4. Phasen

### U1 – Versionen, Manifest, Build
- `update.Newer` mit Vorab-Kennungen nach SemVer (`alpha.15 < alpha.16 < 0.12.0`), `-dev` nie neuer als ein Release.
- Manifest (`manifest.json`): Version, Kanal, Datum, Hinweise-URL, je Architektur (`amd64`, `arm64`, `armv7`) URL,
  Größe, SHA-256; dazu `manifest.sig` (Ed25519 über die Datei). Mindestversion für das Update (Starter vorhanden).
- `image.yml`: zusätzlich die Programme je Architektur bauen (gleiche Flags wie im Image), Prüfsummen, Manifest
  signieren (Secret), als Artefakt ablegen. Kein Push nach ipv64.net aus der Pipeline (E1).
- Tests: Versionsvergleich, Manifest-Prüfung (falscher Schlüssel, falsche Prüfsumme, Downgrade, falsche Arch).

### U2 – Starter im Image-Programm
- Beim Start (vor allem anderen): Kandidaten `/node64` und `/data/bin/node64-*`; nur Dateien mit gültigem Eintrag
  in `/data/bin/state.json` (Version, SHA-256, Herkunft = geprüftes Manifest). Neueste Version gewinnt.
- Capabilities weiterreichen: permitted → inheritable → `PR_CAP_AMBIENT_RAISE` für net_bind_service/net_raw/
  net_admin (nur die, die das Image-Programm hat), dann `execve`. So erbt das Programm aus `/data` die Rechte.
- Volume mit `noexec`: Rückfall über `memfd_create` + `fexecve` (Programm in den Speicher laden), sonst Hinweis in
  der Oberfläche und Weiterbetrieb mit der Image-Version.
- Startversuche zählen (`state.json`); nach 3 Starts ohne „gesund“ zurück auf die vorige bzw. die Image-Version.
- Wichtig: Der Starter kommt einmal ganz normal per Image zu den Nutzern; erst danach geht Selbst-Update.

### U3 – Herunterladen und Anwenden
- Einstellungen → Update: Kanal, Modus (aus / Hinweis / automatisch + Zeitfenster), laufende Version mit Herkunft
  („aus Image“ / „Selbst-Update“), verfügbare Version mit Hinweisen, Knopf „Jetzt aktualisieren“, Verlauf.
- Ablauf: Manifest + Signatur prüfen → Programm laden (Größenlimit, nur HTTPS, fester Host) → SHA-256 →
  `/data/bin/node64-<v>.tmp` → fsync → umbenennen → Datenbank-Sicherung (vorhandene Backup-Funktion, nur lokal) →
  Module sauber stoppen → `exec("/node64")`.
- API `GET/POST /api/update`, Audit, Meldung über die Kanäle („Node64 auf x.y.z aktualisiert“ bzw. „Rückfall“).
- Freier Platz prüfen, höchstens eine Vorversion aufheben.

### U4 – Gesundheitsprüfung und Rückfall
- Neue Version gilt nach 5 Minuten ohne Absturz und mit erfolgreichem `/api/health` als gut.
- Rückfall: vorige Version starten **und** die Datenbank-Sicherung von vor dem Update zurückspielen (Migrationen
  nur vorwärts). Die Minuten dazwischen gehen verloren; Hinweis in der Oberfläche.
- Manuell: „Zur Image-Version zurück“ (löscht `/data/bin`).

### U5 – Doku, Webseite, Cluster
- node64.de: Abschnitt „Selbst-Update“ (Proxmox/LXC als Hauptfall), Sicherheit (Signatur), Rückfall, noexec.
- Cluster-Seite zeigt die Version je Node; „alle Nodes nacheinander aktualisieren“ als spätere Ausbaustufe.
- MCP: Version und verfügbares Update lesend.

## 5. Sicherheit

- Ohne gültige Signatur und Prüfsumme wird nichts ausgeführt; kein Downgrade über das Manifest; nur fester Host.
- Das Programm unter `/data` bekommt nie mehr Rechte als das Image-Programm (nur dessen Capabilities).
- Wer `/data` beschreiben kann, kann schon heute die Datenbank ändern – trotzdem prüft der Starter bei jedem Start
  Prüfsumme und Eintrag in `state.json` (manipulierte Datei → Image-Version).

## 6. Testplan

- Einheitstests (U1, U2-Auswahl, Rückfall-Zähler).
- Auf der Box: Container mit Image n, lokales Manifest mit n+1 (Test-Schlüssel), Update auslösen; prüfen: PID 1
  bleibt, Port 53/443 gebunden, Daten da; kaputte Version → Rückfall nach 3 Starts; neueres Image → `/data/bin`
  wird ignoriert; `/data` mit noexec → memfd-Weg.
- Proxmox-LXC/OCI auf node64-test-Umgebung, arm64 auf einem Pi.
