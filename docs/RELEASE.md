# Release: Code nach GitHub, Image nach ghcr.io

Das Repo liegt öffentlich unter `github.com/ipv64net/node64` (Remote `origin`, SSH-Alias `github-ipv64net`).
Gepusht wird nur auf Ansage von Dennis.

## Image

Der Workflow `.github/workflows/image.yml` baut das Image für `linux/amd64`, `linux/arm64` und `linux/arm/v7` und schiebt es nach
`ghcr.io/ipv64net/node64`. Vorher laufen `go vet` und alle Tests; schlagen sie fehl, entsteht kein Image.
Alle Build-Stufen laufen auf der Plattform des Runners (Cross-Compile, kein QEMU); `arm/v7` setzt `GOARM=7` über
`TARGETVARIANT`. Vorab lokal prüfen: `GOOS=linux GOARCH=arm GOARM=7 go build ./cmd/node64`.

| Auslöser | Image-Tags |
|---|---|
| Tag `v1.0.0` (stabil) | `1.0.0`, `1.0`, `latest` |
| Tag `v1.0.1-rc.1` (Release-Candidate) | `1.0.1-rc.1`, `rc` |
| von Hand (Actions › image › Run workflow) | `edge`, `sha-<kurz>` |

Die Version im Programm (`/api/health`) ist der Tag ohne `v`.

## Ablauf

Ab 1.0.0 (öffentlicher Start 2026-11) gibt es kein alpha/beta mehr: Jede neue Version entsteht als Release-Candidate
(`v1.0.1-rc.1`, `-rc.2` …), wird auf der Box getestet und dann als stabile Version getaggt (`v1.0.1`).

```bash
git push origin main
git tag -a v1.0.1-rc.1 -m "1.0.1-rc.1"   # bzw. v1.0.1 fuer die stabile Version
git push origin v1.0.1-rc.1
```

Das Image ist öffentlich (ghcr.io ohne Anmeldung).

## Docker Hub

Sobald eingerichtet, schiebt derselbe Lauf dieselben Tags zusätzlich nach Docker Hub (`DOCKERHUB_IMAGE`,
z. B. `ipv64net/node64`). Ohne die Variable bleibt es bei ghcr.io. Die Beschreibung auf Docker Hub kommt aus
[DOCKERHUB.md](DOCKERHUB.md) und wird nur bei stabilen Versionen aktualisiert (höchstens 25 000 Zeichen, keine
relativen Links).

Einrichten (nur Dennis, das Token bleibt bei ihm):
1. Auf hub.docker.com das öffentliche Repository anlegen, z. B. `ipv64net/node64`.
2. *Account settings › Personal access tokens*: Token mit Zugriff **Read & Write** anlegen, das reicht für die
   Images. Die Beschreibung setzt der Workflow nur mit „Read, Write, Delete“. Gibt es die Stufe nicht bzw. ist sie
   nicht gewählt, schlägt nur dieser Schritt fehl (ohne Folgen), und die Beschreibung wird einmal von Hand aus
   [DOCKERHUB.md](DOCKERHUB.md) eingefügt (Repository › *General* › Kurzbeschreibung und *Repository overview*).
3. GitHub › ipv64net/node64 › *Settings › Secrets and variables › Actions*:
   - Secrets: `DOCKERHUB_USERNAME` (Docker-Hub-Benutzername), `DOCKERHUB_TOKEN` (das Token)
   - `DOCKERHUB_IMAGE` = Name des Images, z. B. `ipv64net/node64` (als Variable oder Secret; als Variable ist der Name in den Logs lesbar)
4. Bereits gebaute Versionen ohne Neubau kopieren: *Actions › dockerhub-copy › Run workflow*, Version `1.0.0`
   (`latest` nur für die neueste stabile Version).

## Selbst-Update (ipv64.net/node64)

Kanäle: `stable` und `preview` (in der Oberfläche „Release-Candidate“). Ohne eigene Wahl liest eine Node `preview`,
solange sie selbst eine Vorabversion fährt, sonst `stable`.

| Version | Upload-Paket `web/node64/` |
|---|---|
| Release-Candidate | `releases/<version>/…`, `releases/preview/manifest.json(.sig)` – **kein** `latest.json` |
| stabil | `releases/<version>/…`, `releases/stable/manifest.json(.sig)` **und** dieselbe Datei nach `releases/preview/` (sonst blieben RC-Nodes auf dem RC stehen), `latest.json` |

1.0.0 muss ebenfalls nach `preview`: Die Nodes bis 0.12.0-alpha.39.1 lesen ohne eigene Wahl diesen Kanal.

## Später: Docker Hub

Als Spiegel zum öffentlichen Start: Organisation auf Docker Hub anlegen, ein Access-Token als Repo-Secret
`DOCKERHUB_TOKEN` hinterlegen und im Workflow einen zweiten Login und das Image `docker.io/ipv64net/node64` ergänzen.
