# Plan: Zentrale Zertifikatsverwaltung in Node64

Stand 2026-10-16, Wunsch von Dennis, noch nichts umgesetzt. Ziel: eine Zertifikatsstelle im Kern von Node64, mit
eigenem Menüpunkt links, aus der sich CDN64, DNS64 und die Oberfläche von Node64 bedienen. Alles lässt sich
herunterladen und per API abholen, damit Zertifikate auch woanders genutzt werden können (NAS, Router, andere Server).

## Was schon da ist (CDN64 C0–C5)

`internal/certs` ist bereits der zentrale Teil im Kern:
- **Wege:** ipv64 DNS-01 (bevorzugt), Alias über ipv64 (CNAME `_acme-challenge`), 12 DNS-Anbieter über lego mit
  ihren Feldern (Token, Key …) als DNS-Zugänge, HTTP-01 über den Eingang, Upload.
- **Speicherung:** Tabelle `certs`, Schlüssel mit `secret.key` verschlüsselt, im Backup.
- **Betrieb:** Erneuerung 30 Tage vor Ablauf, Meldungen bei Fehler und Ablauf, „benutzt von“, Staging.
- **API:** `/api/certs…` (Liste, Anlegen, Upload, Erneuern, Kette, DNS-Zugänge, Anbieter).
- **Nutzer:** nur CDN64. Die Seite ist ein Reiter in CDN64 (`/cdn64/certificates`).

**Lücken:**
- Die Seite ist ohne CDN64 unsichtbar.
- Erneuert wird nur, solange ein Modul die Verwaltung hält (`Acquire`).
- Kein Download mit Schlüssel.
- Keine eigene CA.
- DNS64 hat eine eigene ACME-Anbindung (`dns64/acme.go`) und eine eigene CA (`dns64/certs.go`).
- Die Oberfläche nimmt nur eine Datei (`NODE64_TLS_CERT`) oder ein selbst erzeugtes Zertifikat.

## Grundsätze

- **Ein Ort für alle Zertifikate.** Module fordern über die Zentrale an. Was ein Modul anfordert, erscheint dort
  mit „benutzt von“.
- **Kern, kein Modul.** Die Seite ist immer da, unabhängig davon, welche Module laufen.
- **Erneuerung:** Jedes Zertifikat mit „automatisch erneuern“ wird erneuert, auch wenn es nur zum Herunterladen
  existiert.
  - Die Schleife läuft nur, solange es solche Zertifikate gibt.
  - Ohne Zertifikate kostet sie nichts.
- **ipv64 zuerst.** Liegt ein Name im ipv64-Account (oder ist eine eigene Domain dort per API erreichbar), wird
  automatisch DNS-01 über ipv64 gewählt. Sonst Alias, DNS-Anbieter oder HTTP-01.
- **Schlüssel verlassen Node64 nur bewusst:**
  - Download des privaten Schlüssels nur nach erneuter Eingabe von Passwort bzw. 2FA;
  - jeder Abruf steht im Audit.
- **Bestehendes bleibt gültig.** Geräte, die heute der DNS64-CA vertrauen, müssen das weiter tun können. Die CA wird
  übernommen, nicht neu erzeugt.

## Funktionsumfang

| Bereich | Inhalt |
|---|---|
| Liste | Name(n), Weg, Aussteller, gültig bis, Tage übrig, Zustand, benutzt von, automatisch erneuern |
| Anfordern | Let's Encrypt (ipv64 / Alias / DNS-Anbieter / HTTP-01), Staging, Wildcards bei DNS-01 |
| Andere ACME-Stellen | eigene Directory-URL mit EAB (Key-ID + HMAC), z. B. ZeroSSL, Buypass, Google, step-ca im eigenen Netz |
| DNS-Zugänge | lego-Anbieter mit ihren Pflichtfeldern, verschlüsselt; Liste der Anbieter erweiterbar (siehe Entscheidungen) |
| Eigene CA | Node64-CA erzeugen oder vorhandene CA (auch Zwischen-CA) importieren; Zertifikate mit Namen **und IPs** ausstellen |
| Upload | fremdes Zertifikat mit Schlüssel (wie heute), nicht erneuerbar, Warnung vor Ablauf |
| Download | `fullchain.pem`, `cert.pem`, `chain.pem`, `privkey.pem`, PKCS#12 (`.p12` mit Passwort) für Windows/Fritzbox/NAS, alles als ZIP; CA als PEM/`.crt` und als iOS/macOS-Profil |
| API | alles aus der Oberfläche, dazu Abruf je Zertifikat mit eigenem Abruf-Schlüssel (siehe unten) |
| Einhängen | CDN64 (Proxy-Hosts, Streams), DNS64 (DoH/DoT/DoQ), Oberfläche von Node64 (HTTPS-Port und Name am Eingang) |
| Meldungen | Fehler, Ablauf (14/3 Tage), Entwarnung, erfolgreich erneuert (optional), an die Standardkanäle |

### Abruf per API

Für Skripte auf anderen Geräten:
- **Abruf-Schlüssel je Zertifikat** (`node64c_…`, nur lesend, nur dieses eine Zertifikat, widerrufbar, letzte
  Nutzung sichtbar).
  - Ein normaler API-Key hätte Vollzugriff auf Node64 und gehört nicht auf ein NAS.
- **Endpunkte:**
  - `GET /api/certs/{id}/bundle?format=pem|p12|zip` (mit Abruf-Schlüssel oder API-Key);
  - `GET /api/certs/{id}/meta` (gültig bis, Fingerabdruck).
  - `ETag`/`If-None-Match`, damit ein Cron-Skript nur bei Änderung neu lädt.
- **Doku:** Beispiel-Skripte (curl + Neustart des Dienstes) für Synology, Proxmox, OPNsense/pfSense und
  allgemeines Linux.

### Eigene CA

- **Erzeugen:** ECDSA P-256 (Standard) oder RSA 3072, CA 10 Jahre.
- **Name Constraints** (nur private Namen wie `.lan`, `.home.arpa`, `.internal` und private IPs) sind Standard und
  abschaltbar. Damit kann eine gestohlene CA keine Internet-Domains fälschen.
- **Import:** vorhandene CA mit Schlüssel (PEM), auch Zwischen-CA unter einer Offline-Root.
- **Ausstellen:** Namen und IP-Adressen, Laufzeit bis 825 Tage (Apple-Grenze) oder kürzer, automatisch erneuern
  30 Tage vor Ablauf.
- **Mehrere CAs** sind möglich, z. B. die übernommene DNS64-CA und eine eigene.

## Phasen

| Phase | Inhalt |
|---|---|
| **Z0** Eigene Seite | Menüpunkt „Zertifikate“ links (Kern). Die Seiten aus CDN64 ziehen um (`/certificates`, alte Pfade leiten weiter). Erneuerung ohne Halter für alle mit „automatisch erneuern“. CDN64 verlinkt nur noch. |
| **Z1** Download und API | Downloads (PEM, P12, ZIP) mit erneuter Anmeldung für den Schlüssel, Audit. Abruf-Schlüssel je Zertifikat, `bundle`/`meta` mit ETag, Beispiel-Skripte. |
| **Z2** Eigene CA und andere ACME-Stellen | CA erzeugen/importieren, ausstellen mit IPs, CA-Download inkl. iOS-Profil. ACME-Stellen mit EAB, Konto je Stelle. |
| **Z3** Oberfläche von Node64 | Auswahl des Zertifikats für den HTTPS-Port und den Namen am Eingang, Wechsel ohne Neustart. Reihenfolge: `NODE64_TLS_CERT` (falls gesetzt) → Auswahl → selbst erzeugt. |
| **Z4** DNS64 (mit der DNS64-Sitzung) | Modus „Zertifikat aus der Zentrale“ mit Auswahl. Übernahme des Let's-Encrypt-Zertifikats (pfsense.ipv64.de) samt Schlüssel und der DNS64-CA in die Zentrale, Geräte vertrauen weiter. Danach entfällt die eigene ACME-Anbindung von DNS64. |
| **Z5** Abschluss | Doku (`docs/ZERTIFIKATE.md`), i18n, OpenAPI, Lasttest der Erneuerung, Test auf der Box (Staging zuerst), Versionen. |

Reihenfolge Z0 → Z1 → Z3 → Z2 → Z4 → Z5 ist auch möglich, falls Download und Oberfläche wichtiger sind als die CA.

## Entscheidungen (Empfehlung in Klammern)

1. Schlüssel-Download nur nach erneuter Passwort-/2FA-Eingabe? (ja)
2. Abruf-Schlüssel je Zertifikat statt normaler API-Keys? (ja, normale API-Keys gehen zusätzlich)
3. Jedes Zertifikat mit „automatisch erneuern“ erneuern, auch unbenutzte? (ja)
4. Eigene CA standardmäßig nur für private Namen/IPs (Name Constraints)? (ja, abschaltbar)
5. Mehr lego-Anbieter? Jeder Anbieter bringt seine Bibliothek mit; große Cloud-SDKs (AWS Route 53, Azure, Google
   Cloud) machen das Image um je ~5–15 MB größer. (gezielt erweitern auf ~25 verbreitete Anbieter, Cloud-SDKs nur
   auf Nachfrage)
6. Übernahme bei DNS64 (Z4) automatisch beim Update oder per Knopf? (per Knopf mit Vorschau, Abstimmung mit der
   DNS64-Sitzung)

## Abstimmung

- **DNS64-Sitzung:** Z4 ändert `internal/dns64` (Zertifikatsmodus, Übernahme, Wegfall von `acme.go`). Der Ablauf
  wird vorher abgestimmt. Den Code von DNS64 ändert die DNS64-Sitzung oder ich nach ihrer Freigabe.
- **Gemeinsame Dateien** (i18n, `openapi.json`, `layout.html`) nur nach Ankündigung, Commits per Pfad.
- **Box:** Tests in `node64-cdn` (Ports 18xxx). Deploy auf `node64-test` (Heim-DNS) nur mit Go von Dennis.
