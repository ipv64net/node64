# Monitor64-Agent: Ablage, Release und Verteilung

Wie die Dateien des Monitor64-Agents gebaut, signiert, abgelegt und von den Nodes verteilt werden. Plan:
`PLAN-NODE64-MONITOR64.md`, Abschnitte „Monitor64-Agent“ und „Sicherheit“. Code: `internal/monitor64/agentdist`
(Format, Prüfung, Zwischenspeicher), `internal/monitor64/agentdist*.go` (Node: Downloads, Updates, Seite „Agent“),
`cmd/node64-release` (Werkzeug), `.github/workflows/image.yml` (Job `release`).

## Version des Agents

Der Agent hat eine **eigene Version**, unabhängig von der Node: `cmd/monitor64-agent/VERSION` (eine Zeile,
`MAJOR.MINOR.PATCH[-vorab]`). Der Build setzt sie mit `-ldflags "-X main.Version=…"`; ohne das heißt die Version
`dev` (solche Agents aktualisiert die Node nie). **Jede Änderung am Agent-Code braucht eine höhere Version** – der
Agent nimmt nur eine höhere an (kein Downgrade), und Nodes vergleichen nur die Versionsnummer.

## Ablage

Zwei Orte mit demselben Inhalt (Inhalt des Artefakts `dist/agent/`):

- `https://ipv64.net/node64/agent/` – Standard-Quelle der Nodes (Ordner `node64` wie die Selbst-Updates)
- `https://node64.de/agent/` – Ausweichquelle der Nodes

```
agents.json                 Verzeichnis: Version und Dateien je Plattform mit Größe und SHA-256
agents.json.sig             Signatur (base64 ed25519 über die Datei – wie manifest.json.sig der Selbst-Updates)
<version>/monitor64-agent-<os>-<arch>[.exe]               Programm
<version>/monitor64-agent-<os>-<arch>[.exe].update.json   signierte Kopfzeile für die Anfrage „update“
<version>/install.sh, install.ps1, SHA256SUMS             Installationsskripte und Prüfsummen der Programme
monitor64-agent-*, install.sh, install.ps1, SHA256SUMS    aktueller Stand zusätzlich direkt im Ordner
```

Plattformen: `linux-amd64`, `linux-arm64`, `linux-armv7` (GOARCH `arm`, GOARM 6 – eine Datei für 32-Bit-ARM, läuft auch auf ARMv6 wie Raspberry Pi Zero/Pi 1; der Name bleibt wegen der Auto-Updates), `windows-amd64` (`.exe`),
`freebsd-amd64`, `freebsd-arm64`.

`agents.json` (unbekannte Felder werden ignoriert, neue Plattformen stören alte Nodes nicht):

```json
{
  "version": "0.1.0",
  "date": "2026-11-10T12:00:00Z",
  "files": {
    "linux-amd64": {"name": "monitor64-agent-linux-amd64", "os": "linux", "arch": "amd64", "size": 6414496, "sha256": "…"},
    "linux-armv7": {"name": "monitor64-agent-linux-armv7", "os": "linux", "arch": "arm", "size": 6488224, "sha256": "…"}
  },
  "scripts": {
    "install.sh": {"name": "install.sh", "size": 5120, "sha256": "…"},
    "install.ps1": {"name": "install.ps1", "size": 6144, "sha256": "…"}
  }
}
```

Die Nodes lesen nur `agents.json(.sig)` und den Ordner `<version>/`. Die Dateien direkt im Ordner sind für die
Installation aus dem Internet: Die Skripte holen Programm und `SHA256SUMS` aus dem Ordner, aus dem sie selbst kommen
(`--base` bzw. `-Base`).

## Signatur

Ein Schlüssel für alles: der Release-Schlüssel von Node64 (öffentlich in `internal/selfupdate/keys.go` und als
Standard in `cmd/monitor64-agent/main.go` `ReleaseKeys`; privat nur als GitHub-Secret `NODE64_SIGNING_KEY`).

- `agents.json.sig`: `node64-release sign agents.json` (dieselbe Funktion wie beim Manifest der Selbst-Updates).
- `<datei>.update.json`: `node64-release agent-sign` – ed25519 über Version, Plattform und SHA-256
  (`m64proto.SignedMessage`). Diese Kopfzeile prüft die Node beim Laden **und** der Agent beim Update.

## Release

Der Job `release` in `.github/workflows/image.yml` läuft bei jedem Versions-Tag der Node und legt neben den Dateien
der Selbst-Updates `dist/agent/` ins Artefakt `node64-release-<tag>`:

1. `cmd/monitor64-agent/VERSION` erhöhen (wenn sich der Agent geändert hat), committen, Tag setzen.
2. Der Job baut die sechs Dateien (`CGO_ENABLED=0`, `-trimpath -ldflags "-s -w -X main.Version=<VERSION>"`), kopiert
   `install.sh`/`install.ps1`, schreibt mit `node64-release agent-index` `agents.json` und `SHA256SUMS` und signiert
   mit `agent-sign` und `sign`. Ohne das Secret entstehen weder `agents.json.sig` noch `*.update.json` – so ein Stand
   wird von keiner Node angenommen.
3. Inhalt von `dist/agent/` nach `ipv64.net/node64/agent/` **und** `node64.de/agent/` hochladen: erst den Ordner
   `<version>/`, dann die Dateien direkt im Ordner, **zuletzt** `agents.json.sig` und `agents.json`. Alte
   Versions-Ordner können danach weg.

Von Hand (z. B. Test mit eigenem Schlüssel):

```sh
AV=$(cat cmd/monitor64-agent/VERSION); out=dist/agent/$AV; mkdir -p $out
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.Version=$AV" \
  -o $out/monitor64-agent-linux-amd64 ./cmd/monitor64-agent          # je Plattform
cp cmd/monitor64-agent/install.sh cmd/monitor64-agent/install.ps1 $out/
go run ./cmd/node64-release agent-index -version $AV -out dist/agent/agents.json $out
go run ./cmd/node64-release agent-sign -key <schlüsseldatei> -version $AV $out/monitor64-agent-*
go run ./cmd/node64-release sign -key <schlüsseldatei> dist/agent/agents.json
cp $out/monitor64-agent-* $out/install.sh $out/install.ps1 $out/SHA256SUMS dist/agent/ && rm -f dist/agent/*.update.json
```

## Was die Node damit tut

- **Abruf:** Verzeichnis und Signatur von der ersten erreichbaren Quelle (ipv64.net, sonst node64.de) – beim ersten
  Bedarf (Seite „Agent“, Download eines Hosts, Agent-Host vorhanden) und danach alle 6 h, nach einem Fehlschlag nach
  30 min. Ohne Agent-Host und ohne Aufruf geschieht nichts. Ein älteres Verzeichnis als das gespeicherte wird nicht
  übernommen.
- **Dateien:** erst beim ersten Bedarf nach `<data>/monitor64/agent/<version>/`; geprüft werden Größe, SHA-256 und
  die Signatur der Kopfzeile, Skripte gegen die SHA-256 im signierten Verzeichnis. Größengrenzen (Verzeichnis 64 KB,
  Skript 256 KB, Programm 64 MB), Zeitlimits, nur HTTPS, keine Weiterleitung auf einen anderen Host. Ordner anderer
  Versionen werden gelöscht. Was nicht geprüft ist, wird weder ausgeliefert noch verteilt.
- **Downloads für Hosts** ohne Anmeldung, nur bei laufendem Modul: `GET /monitor64/agent/install.sh`, `install.ps1`,
  `SHA256SUMS`, `monitor64-agent-<os>-<arch>[.exe]` – nur diese Namen aus dem Verzeichnis, kein Pfad. Damit
  funktionieren `install.sh --base http(s)://<node>/monitor64/agent/` und `install.ps1 -Base …`.
  **Grenze:** Über HTTP kann jemand im Netz zwischen Host und Node Skript, Datei und `SHA256SUMS` gemeinsam
  austauschen (die Prüfsumme schützt nur vor defekten Downloads). Über HTTPS muss der Host dem Zertifikat der Node
  vertrauen; mit einem selbst signierten Zertifikat bricht der Download ab. Die Seite „Agent“ sagt das beim Befehl.
- **Automatische Updates:** Die Node merkt je Agent-Zugang Version und Plattform (`info`, stündlich). Ist das
  Verzeichnis neuer und „Agent automatisch aktualisieren“ am Host an, schiebt sie Kopfzeile und Datei über die
  bestehende Verbindung (`update`, auch im Push-Betrieb): höchstens 2 Hosts gleichzeitig, nie während einer
  Abfragerunde desselben Hosts, im Cluster nur die zuständige Node. Der Agent prüft selbst (Signatur, Plattform,
  höhere Version) und fällt bei einem Fehlstart auf die alte Datei zurück. Erfolg: Ereignis „Agent 0.3.0 → 0.4.0“
  (System bzw. wer „Jetzt aktualisieren“ gedrückt hat). Fehler: Hinweis am Zugang und auf der Seite „Agent“, neuer
  Versuch frühestens nach 6 h. Stand je Zugang: `<data>/monitor64/agent/hosts.json`.

## Testen mit eigener Quelle und eigenem Schlüssel

Wie beim Selbst-Update (`NODE64_UPDATE_URL`, `UPDATE_KEYS`):

- Quelle: Umgebungsvariable `NODE64_MONITOR64_AGENT_URL=http://host:port/agent` (mehrere durch Komma; dann ist auch
  HTTP erlaubt).
- Schlüssel: Die Node prüft mit `selfupdate.PublicKeys` – für Tests beim Bauen ersetzen:
  `-ldflags "-X github.com/ipv64net/node64/internal/selfupdate.PublicKeys=<öffentlich>"` (Docker: `--build-arg
  UPDATE_KEYS=<öffentlich>`). Der Agent: `-ldflags "-X main.ReleaseKeys=<öffentlich>"`.
- Schlüsselpaar: `go run ./cmd/node64-release keygen -out test.key` (öffentlicher Teil auf stdout).
