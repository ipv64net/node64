# Zertifikate in Node64

Stand 2026-10-16 (Z0–Z5 fertig). Die Zertifikatsverwaltung gehört zum Kern von Node64. Menüpunkt *Zertifikate*, Pfad
`/certificates`. Sie arbeitet unabhängig davon, welche Module laufen. Plan und Entscheidungen:
[PLAN-NODE64-ZERTIFIKATE.md](PLAN-NODE64-ZERTIFIKATE.md).

## Wege zum Zertifikat

| Weg | Wann |
|---|---|
| ipv64 DNS-01 | Die Namen liegen im ipv64-Account (API-Key in den Einstellungen); auch Wildcards. „Automatisch“ wählt diesen Weg, wenn alle Namen passen. |
| Alias über ipv64 | Fremde Domain; einmal CNAME `_acme-challenge.<name>` → `_acme-challenge.<präfix>.<ipv64-domain>` |
| Anderer DNS-Anbieter | DNS-Zugang mit den Feldern des Anbieters (Token, Key …), verschlüsselt gespeichert |
| HTTP-01 | Name zeigt per DNS auf den Anschluss, Port 80 des Eingangs |
| Eigenes Zertifikat | PEM hochladen (nicht erneuerbar, Warnung vor Ablauf) |
| Eigene CA | Geräte im eigenen Netz: Namen wie `nas.lan` und IP-Adressen; Geräte vertrauen der CA einmal |

**Ausstellende Stelle bei ACME:**
- Standard ist Let's Encrypt.
- Weitere Stellen lassen sich unter *ACME-Stellen* hinzufügen, siehe unten.

**DNS-Anbieter (26):**
- **Deutschsprachiger Raum:** ALL-INKL.COM, AutoDNS (InterNetX), checkdomain, Hetzner, INWX, IONOS, netcup,
  Infomaniak.
- **International:** Bunny DNS, ClouDNS, Cloudflare, deSEC, DigitalOcean, Duck DNS, Dynu, Gandi, GoDaddy,
  Hostinger, Hurricane Electric, Namecheap, OVHcloud, Porkbun.
- **Eigene Server:** PowerDNS, Technitium, RFC 2136 (BIND, Knot, pfSense/OPNsense mit TSIG), HTTP-Request
  (eigener Dienst nach dem Muster von lego `httpreq`).

**Erneuerung:**
- Jedes Zertifikat mit „automatisch“ wird 30 Tage vor Ablauf erneuert, auch wenn kein Modul es benutzt.
- Nach einem Fehler erst wieder nach 6 Stunden.
- Meldungen an die Standardkanäle: bei Fehlschlag, Entwarnung und 14 bzw. 3 Tage vor Ablauf.

## Zertifikat der Oberfläche

*Einstellungen → Ports → Zertifikat der Oberfläche* gilt für den HTTPS-Port (`NODE64_HTTPS_PORT`) und für den
Namen am Eingang. Ein Wechsel greift sofort, ohne Neustart.

| Auswahl | Verhalten |
|---|---|
| Automatisch (Standard) | Zertifikat der Zentrale, das zum aufgerufenen Namen passt, sonst selbst signiert |
| fest gewähltes Zertifikat | immer dieses (z. B. Wildcard von Let's Encrypt oder eins der eigenen CA mit IP) |
| Selbst signiert | wie früher |

- Ist `NODE64_TLS_CERT` gesetzt, nutzt der HTTPS-Port weiter diese Datei.
- Ein gewähltes Zertifikat steht bei „benutzt von“ als „Node64-Oberfläche“ und ist damit vor versehentlichem
  Löschen geschützt.

## Wer die Zentrale nutzt

| Abnehmer | Wie | „benutzt von“ |
|---|---|---|
| CDN64 | Proxy-Hosts und Streams wählen ein Zertifikat oder nehmen das passende zum Namen; im Host-Formular lässt sich gleich eins anfordern | Namen der Hosts |
| DNS64 (ab 1.10.0) | DoH, DoT, DoQ; Modus „Zertifikat aus der Zentrale“ oder Server-Zertifikat der eigenen CA (Namen und IPs der Node) | DNS64 |
| Oberfläche | HTTPS-Port und Name am Eingang | Node64-Oberfläche |
| andere Geräte | Download oder API | – |

**Umzug von DNS64 (einmal beim Update auf DNS64 1.10.0):**
- Die eigene CA von DNS64 kommt als „DNS64 Heimnetz-CA“ in die Zentrale, mit gleichem Schlüssel. Geräte, die ihr
  vertrauen, merken nichts.
- Ein vorhandenes Let's-Encrypt-Zertifikat (Modus `acme`) wird samt Schlüssel übernommen und ab dann von der
  Zentrale erneuert. Voraussetzung: Die Nutzungsbedingungen wurden in DNS64 angenommen.
- Scheitert etwas, bleibt der alte Modus, und beim nächsten Start gibt es einen neuen Versuch.
- Die alten Dateien unter `dns64/tls` und `dns64/acme` bleiben als Rückfall liegen.

## Eigene CA

Für Geräte im eigenen Netz, die kein öffentliches Zertifikat bekommen können (`nas.lan`, `192.168.1.5`,
`drucker.home.arpa`).

**Erzeugen:**
- ECDSA P-256 oder RSA 3072, 10 Jahre gültig.
- Standard ist „nur private Namen und Adressen“: `*.lan`, `*.home.arpa`, `*.internal`, `*.local`, `*.home` u. a.
  sowie private IPv4/IPv6. Auf Wunsch kommen eigene Domains dazu, z. B. `home.example.ipv64.de`.
- Wird der Schlüssel gestohlen, lassen sich damit keine Internet-Domains fälschen (Name Constraints).

**Importieren:**
- Vorhandene CA mit Schlüssel als PEM, auch eine Zwischen-CA unter einer Offline-Root (step-ca, OpenSSL, XCA).
- Die Kette der ausgestellten Zertifikate enthält die Zwischen-CA, die Root nicht.

**Ausstellen:**
- Im Formular „Zertifikat hinzufügen“ den Weg „Eigene CA“ wählen. Namen und IPs stehen je Zeile.
- Laufzeit 1–825 Tage, Standard 397. 825 ist die Grenze von Apple.
- Erneuert wird automatisch im letzten Drittel der Laufzeit, höchstens 30 Tage vor Ablauf.

**Auf Geräten installieren:** In der Karte *Eigene CAs* gibt es drei Formate.

| Datei | Gerät |
|---|---|
| PEM | Linux (`/usr/local/share/ca-certificates/` + `update-ca-certificates`), Firefox |
| `.crt` | Windows (Doppelklick → „Vertrauenswürdige Stammzertifizierungsstellen“), Android |
| iOS/macOS-Profil | iPhone/iPad: Profil laden, installieren, dann unter *Einstellungen → Allgemein → Info → Zertifikatsvertrauen* einschalten |

Eine CA lässt sich erst löschen, wenn sie kein Zertifikat mehr ausstellt.

## Weitere ACME-Stellen

Neben Let's Encrypt lassen sich andere Stellen nutzen, die ACME sprechen. Vorlagen gibt es für:

| Stelle | Verzeichnis | External Account Binding |
|---|---|---|
| ZeroSSL | `https://acme.zerossl.com/v2/DV90` | ja, im ZeroSSL-Konto unter *Developer* |
| Google Trust Services | `https://dv.acme-v02.api.pki.goog/directory` | ja, `gcloud publicca external-account-keys create` |
| SSL.com | `https://acme.ssl.com/sslcom-dv-ecc` | ja |
| step-ca im eigenen Netz | eigene URL | nein; Root-Zertifikat der step-ca angeben |

Buypass fehlt in den Vorlagen, weil es seinen kostenlosen ACME-Dienst eingestellt hat.

**Beim Hinzufügen:**
- Node64 fragt das Verzeichnis ab und meldet, wenn die Stelle EAB verlangt.
- Die Nutzungsbedingungen der Stelle werden dabei angenommen.
- Der HMAC liegt verschlüsselt in der Datenbank.
- Das Konto nutzt denselben Schlüssel wie bei Let's Encrypt.

Beim Anfordern wählt man die Stelle unter „Ausstellende Stelle“. Die Wege (ipv64, Alias, DNS-Anbieter, HTTP-01)
gelten für jede Stelle.

## Herunterladen

Das Download-Menü steht in jeder Zeile der Liste.

| Datei | Inhalt | Typisch für |
|---|---|---|
| `fullchain.pem` | Zertifikat + Zwischenzertifikate | nginx, Apache, Traefik, Proxmox |
| `cert.pem`, `chain.pem` | Zertifikat bzw. nur die Zwischenzertifikate | Synology (Import mit drei Dateien), ältere Server |
| `privkey.pem` | privater Schlüssel | zusammen mit fullchain |
| `.pem` (alles in einer Datei) | fullchain + Schlüssel | HAProxy, Fritzbox, manche Router |
| ZIP | alle vier PEM-Dateien | Skripte |
| `.p12` (PKCS#12) | alles, mit Passwort | Windows, IIS, Java, NAS; „alte Verschlüsselung“ für ältere Geräte |

Jeder Download mit Schlüssel steht im Audit (Format, Name, Seite oder API).

## Abruf per API

Mit einem normalen API-Key (*Einstellungen → API-Keys*):

| Endpunkt | Zweck |
|---|---|
| `GET /api/certs` | Liste mit Kennungen (`id`) |
| `GET /api/certs/{id}/meta` | gültig bis, Tage übrig, Fingerabdruck (= ETag) |
| `GET /api/certs/{id}/bundle?format=zip\|fullchain\|cert\|chain\|key\|pem` | Datei; mit `If-None-Match` kommt 304, solange sich nichts geändert hat |
| `POST /api/certs/{id}/p12` mit `{"password": "…", "legacy": false}` | PKCS#12 |
| `GET/POST /api/cas`, `POST /api/cas/import`, `GET /api/cas/{id}/file?format=pem\|crt\|mobileconfig` | eigene CAs |
| `GET/POST /api/acme-cas`, `GET /api/acme-cas/presets` | weitere ACME-Stellen |
| `POST /api/certs` mit `"source": "ca", "ca_id": 1, "days": 397` bzw. `"acme_ca": 2` | ausstellen mit eigener CA bzw. anderer Stelle |
| `PUT /api/edge/ui` mit `{"cert": "auto"\|"self"\|"<id>"}` | Zertifikat der Oberfläche |

**Sicherheit:**
- Der Schlüssel geht im Klartext über die Leitung, wenn die Oberfläche nur per HTTP läuft. Abruf nur im eigenen
  Netz, oder die HTTPS-Oberfläche nutzen.
- Für jedes Gerät einen eigenen API-Key anlegen, dann lässt er sich einzeln widerrufen.

### Linux (nginx o. ä.), täglich per Cron

```sh
#!/bin/sh
# /etc/cron.daily/node64-cert – holt das Zertifikat nur bei Änderung und lädt nginx neu
NODE=http://192.168.10.30:8091   # Node64 im eigenen Netz
KEY=node64_xxxxxxxx              # API-Key
ID=3                             # Kennung aus GET /api/certs
DIR=/etc/ssl/node64
mkdir -p "$DIR" && cd "$DIR" || exit 1
ETAG=$(cat etag 2>/dev/null)
CODE=$(curl -s -o new.zip -D headers -w '%{http_code}' -H "Authorization: Bearer $KEY" -H "If-None-Match: $ETAG" \
  "$NODE/api/certs/$ID/bundle?format=zip")
if [ "$CODE" = 200 ]; then
  unzip -o -q new.zip && chmod 600 privkey.pem
  grep -i '^etag:' headers | cut -d' ' -f2 | tr -d '\r' > etag
  systemctl reload nginx
fi
rm -f new.zip headers
```

### Proxmox VE

Wie oben, statt `systemctl reload nginx`:

```sh
pvenode cert set fullchain.pem privkey.pem --force --restart
```

### Windows (PowerShell, als Administrator)

```powershell
$h = @{ Authorization = "Bearer node64_xxxxxxxx" }
Invoke-RestMethod -Method Post -Uri "http://192.168.10.30:8091/api/certs/3/p12" -Headers $h `
  -ContentType "application/json" -Body '{"password":"geheim12"}' -OutFile cert.p12
Import-PfxCertificate -FilePath cert.p12 -CertStoreLocation Cert:\LocalMachine\My `
  -Password (ConvertTo-SecureString "geheim12" -AsPlainText -Force)
```

### Synology DSM

*Systemsteuerung → Sicherheit → Zertifikat → Hinzufügen → Importieren*. Dort `privkey.pem`, `cert.pem` und
`chain.pem` aus dem ZIP angeben.

## Sicherung und Umzug

- **Speicherung:** Zertifikate, Schlüssel, CAs, DNS-Zugänge und EAB-Daten liegen in `node64.db`. Die
  Schlüssel sind dort mit `/data/secret.key` verschlüsselt.
- **Backup:** Beide Dateien gehören zusammen. Ohne `secret.key` lassen sich die Schlüssel nicht mehr lesen.
- **Neuer Rechner:** Das ganze Volume `/data` umziehen. Die Zertifikate gelten dort sofort weiter.

## Leistung

Lasttest mit 500 Zertifikaten der eigenen CA auf der Testbox (4 Kerne, `go test -tags loadtest -run TestLoadCerts
-v ./internal/certs/`):

| Messung | Ergebnis |
|---|---|
| ausstellen | 3,9 s für 500 (8 ms je Zertifikat) |
| Liste mit 500 Einträgen | 2,4 ms |
| Suche beim Verbindungsaufbau (`ForName`) | 0,15 ms je Handshake |
| Erneuerung von 250 fälligen in einem Lauf | 3,5 s, Heap 2 MB, keine übrigen Goroutinen |

Ohne Zertifikate und ohne Abnehmer läuft keine Erneuerung im Hintergrund.

## Grenzen

- **Let's Encrypt:**
  - Rate-Limits wie üblich: 50 Zertifikate je registrierter Domain und Woche, 5 gleiche Zertifikate je Woche.
  - Für Tests die Testumgebung (Staging) nutzen.
- **IP-Adressen** im Zertifikat gibt es nur mit der eigenen CA, nicht über ACME.
- **Keine Sperrlisten (CRL/OCSP)** für die eigene CA. Ein kompromittiertes Zertifikat löschen und neu ausstellen.
  Bei Verdacht auf die CA selbst: neue CA anlegen und auf den Geräten tauschen.
- **Live getestet:** ipv64 DNS-01 (blog.ipv64.net, pfsense.ipv64.de). Alias, die lego-Anbieter (v4.35.2, wie
  bei Traefik und Caddy) und die weiteren ACME-Stellen sind gegen Test-Server und die echten Verzeichnisse
  geprüft, aber noch nicht mit echten Zugangsdaten.

## Fehlerbehebung

| Meldung / Zustand | Ursache und Abhilfe |
|---|---|
| „Nutzungsbedingungen … annehmen“ | Karte *Let's-Encrypt-Konto*: Haken setzen (für weitere ACME-Stellen beim Anlegen der Stelle) |
| „Für diesen Weg fehlt der ipv64-API-Key“ | *Einstellungen → ipv64*: API-Key eintragen |
| hängt bei „wartet auf die Nameserver“ | TXT-Record noch nicht sichtbar; bis 8 Minuten normal, bei netcup länger. Danach Fehler und neuer Versuch in 6 Stunden |
| Alias: „CNAME fehlt“ | Beim Anbieter der fremden Domain den angezeigten CNAME `_acme-challenge.<name>` anlegen |
| HTTP-01 scheitert | Port 80 von außen muss auf die Node zeigen (Router), und der Name muss per DNS auf den Anschluss zeigen |
| eigene CA: „… is not allowed by the CA“ | Name oder IP liegt außerhalb der Einschränkung; Domain bei einer neuen CA erlauben oder eine CA ohne Einschränkung nutzen |
| Browser warnt bei der eigenen CA | CA auf dem Gerät installieren (Karte *Eigene CAs*); bei iOS zusätzlich Zertifikatsvertrauen einschalten |
| Zertifikat lässt sich nicht löschen | Es wird benutzt (siehe „benutzt von“); erst dort umstellen oder bewusst trotzdem löschen |
