# Release: Code nach GitHub, Image nach ghcr.io

Das Repo liegt privat unter `github.com/ipv64net/node64` (Remote `origin`, SSH-Alias `github-ipv64net`).
Gepusht wird nur auf Ansage von Dennis.

## Image

Der Workflow `.github/workflows/image.yml` baut das Image für `linux/amd64`, `linux/arm64` und `linux/arm/v7` und schiebt es nach
`ghcr.io/ipv64net/node64`. Vorher laufen `go vet` und alle Tests; schlagen sie fehl, entsteht kein Image.
Alle Build-Stufen laufen auf der Plattform des Runners (Cross-Compile, kein QEMU); `arm/v7` setzt `GOARM=7` über
`TARGETVARIANT`. Vorab lokal prüfen: `GOOS=linux GOARCH=arm GOARM=7 go build ./cmd/node64`.

| Auslöser | Image-Tags |
|---|---|
| Tag `v0.12.0-alpha.1` | `0.12.0-alpha.1`, `latest` |
| Tag `v0.12.0` | `0.12.0`, `0.12`, `latest` |
| von Hand (Actions › image › Run workflow) | `edge`, `sha-<kurz>` |

Die Version im Programm (`/api/health`) ist der Tag ohne `v`.

## Ablauf

```bash
git push origin main
git tag v0.12.0-alpha.1
git push origin v0.12.0-alpha.1
```

Während der Alpha bleibt das Paket privat (GitHub › Packages › node64 › Package settings). Zum Ziehen eines privaten
Images braucht der Rechner ein GitHub-Token mit `read:packages`:

```bash
echo "<token>" | docker login ghcr.io -u ipv64net --password-stdin
```

## Später: Docker Hub

Als Spiegel zum öffentlichen Start: Organisation auf Docker Hub anlegen, ein Access-Token als Repo-Secret
`DOCKERHUB_TOKEN` hinterlegen und im Workflow einen zweiten Login und das Image `docker.io/ipv64net/node64` ergänzen.
