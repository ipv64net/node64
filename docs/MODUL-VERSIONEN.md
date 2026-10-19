# Modul-Versionen

Jedes Modul von Node64 hat eine eigene Version und ein eigenes Änderungsprotokoll, unabhängig von der Version
von Node64 selbst (Kern, z. B. `0.11.66-dev`). So ist sichtbar, welches Modul sich wann und wie geändert hat.

| Modul | Ordner | Startversion |
|---|---|---|
| Healthchecks | `internal/healthchecks` | 2.0.0 |
| DynDNS | `internal/dyndns` | 1.0.0 |
| DNS64 | `internal/dns64` | 1.0.0 |
| PROXY64 (ID `cdn64`) | `internal/cdn64` | 1.0.0 |

## Wo die Version steht

- `module.Info.Version` im `Info()` des Moduls, z. B. `Version: "1.2.0"`.
- `CHANGELOG.md` im Modulordner, eingebunden mit `//go:embed CHANGELOG.md` in `var changelog string` und als
  `module.Info.Changelog` übergeben.
- `CHANGELOG.en.md` daneben: die englische Fassung, eingebunden in `var changelogEN string` und als
  `module.Info.ChangelogEN` übergeben. Jeder Eintrag in `CHANGELOG.md` kommt im selben Commit auch dort hinein.
- Angezeigt in **Einstellungen → Module** (Version, Stand, Änderungen aufklappbar, in der Sprache des Benutzers), im
  Dashboard (Karte Module) und in `GET /api/modules` (`version`, `changed`; mit `?changelog=1` auch das Protokoll,
  Sprache des Benutzers oder `&lang=en`/`de`).

## Wann sich die Version ändert (SemVer)

- **Major** (`2.0.0`): inkompatibel – Daten werden umgebaut, ohne dass ein Zurück möglich ist, die lokale API
  ändert sich inkompatibel, Export/Import alter Stände geht nicht mehr.
- **Minor** (`1.3.0`): neue Funktion, neue Einstellung, neuer API-Endpunkt, neue Seite.
- **Patch** (`1.2.1`): Fehlerbehebung, Textänderung, Optik ohne neue Funktion.

Die Zertifikatsverwaltung (`internal/certs`, Seite `internal/certsui`), der gemeinsame Eingang (`internal/edge`)
und die Port-Verwaltung (`internal/ports`) gehören zum Kern und haben keine eigene Modulversion. Ihre Änderungen
stehen in [ZERTIFIKATE.md](ZERTIFIKATE.md) bzw. [CDN64.md](CDN64.md) und laufen mit der Version von Node64.

Die Version wird mit der Änderung im selben Commit erhöht. Mehrere Änderungen bis zum nächsten Ausrollen dürfen
in einer Version zusammenkommen. Änderungen nur am Kern (Menü, Einstellungen, Sync) ändern keine Modulversion.

## Format der CHANGELOG.md

```markdown
# Änderungen – <Modul>

## 1.1.0 – 2026-10-20

Optionaler Satz zur Version.

### Neu
- …

### Geändert
- …

### Behoben
- …
```

- Neueste Version oben; Überschrift `## <Version> – <JJJJ-MM-TT>` (Halbgeviertstrich, `-` geht auch).
- Abschnitte `### Neu`, `### Geändert`, `### Behoben` (nur die nötigen), Punkte als `- `-Liste; eingerückte
  Folgezeilen gehören zum Punkt darüber.
- `code` und *kursiv* werden in der Oberfläche als reiner Text gezeigt; keine Links, Tabellen oder Bilder.
- Aus Sicht der Benutzer schreiben (was ist anders), nicht Dateinamen oder Commits aufzählen.
