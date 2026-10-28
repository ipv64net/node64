# Node64 – Hinweise für Claude

Node64 ist ein Go-Container fürs Heimnetz (Modul `github.com/ipv64net/node64`): Healthchecks (inkl. Proxmox VE und
Docker, Statusseiten), DNS64, PROXY64 (Reverse Proxy, intern `cdn64`) mit CDN64-Tunnel, DynDNS, Zertifikate,
Honeypot64, Cluster. Dazu die hub-Server (`internal/hub`), der Edge-Server (`internal/cdnedge`) und Portal-Dateien
für ipv64.net (`deploy/web`, PHP). Allgemeine Regeln (Sicherheit, Rollout, Upload) stehen in `../CLAUDE.md`.

## Aufbau
- `cmd/node64/main.go` verdrahtet die Module; Module unter `internal/<name>` mit eigenen Templates
  (`templates/pages/*.html`), `CHANGELOG.md`/`CHANGELOG.en.md` und Version (`Version`/`module.Info`).
- Oberfläche: Go `html/template`, Bootstrap 5, Vanilla-JS in `internal/web/static/js`, CSS in `node64.css`.
- Texte immer zweisprachig in `internal/i18n/locales/de.json` und `en.json` (verschachtelt). Platzhalter `{name}`.
- Check-Parameter werden streng dekodiert (`checks.decode` mit `DisallowUnknownFields`): neue Felder in den
  Params-Structs ergänzen und Node, hubs und Portal gemeinsam ausrollen.

## Stil
- Kleine, gezielte Änderungen; vorhandenen Stil übernehmen (deutsche Kommentare ohne Umlaute im Code, Kommentardichte
  wie die Umgebung). Keine Umbauten ohne Auftrag.
- Jede nutzersichtbare Änderung: Modul-Version erhöhen und beide Changelogs ergänzen.
- Zusätzlich öffentlicher Changelog in der Repo-Wurzel (`CHANGELOG.md`, `CHANGELOG.en.md`): je nutzersichtbarer
  Änderung ein knapper Stichpunkt unter „Unveröffentlicht“ / „Unreleased“ (Modul vorne, keine Interna, Issue-Nummer
  falls vorhanden). Beim Tag die Überschrift auf die Version und das Datum setzen und neu „Unveröffentlicht“ anlegen.
- `gofmt` muss sauber sein.

## Prüfen
- Tests unter Linux auf der Box (`ssh agentbox`), z. B. Quellbaum nach `/tmp/n64t` kopieren und
  `docker run --rm -v /tmp/n64t:/src -w /src golang:1.27 go test ./...`; JS mit `node --check` (node:22-alpine).
- PHP: `php -l` im Container `c64o-php`; Funktionstests gegen die Test-Datenbank `c64o-db`.
- Ohne Anmeldung an der Node-Oberfläche: Templates über die vorhandenen Render-Tests prüfen.

## Commits
- Nur eigene Dateien: `git commit -- <pfade>` (neue Dateien vorher `git add <pfad>`), nie `-a`/`-A`.
- Commit-Text deutsch, Modul und Version vorne („Healthchecks 2.36.1: …“).
- `deploy/upload/` und `node64-src.tar` nie committen.
