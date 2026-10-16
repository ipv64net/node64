# Zertifikate in Node64

Stand 2026-10-16 (Z1). Die Zertifikatsverwaltung gehört zum Kern von Node64. Menüpunkt *Zertifikate*, Pfad
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
