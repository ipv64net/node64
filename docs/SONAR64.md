# Sonar64 – Messknoten ohne Dashboard

Sonar64 ist das Community-Messnetz von ipv64.net: Knoten bei Teilnehmern zu Hause messen sich gegenseitig und die
Anker (Ping über ICMP oder UDP 6464), geordnet und sparsam nach einem signierten Plan von ipv64.net. Die Ergebnisse
erscheinen auf der öffentlichen Karte (ipv64.net/sonar) und unter „Mein Knoten“.

Diese Anleitung beschreibt das **eigenständige Programm `sonar64`** ohne Oberfläche: für den Raspberry Pi (auch den
ersten Pi Zero), als kleinen Docker-Container, als MikroTik-Container und als Anker. Wer Node64 betreibt, schaltet
stattdessen das Modul Sonar64 in der Oberfläche ein. Plan: [PLAN-NODE64-SONAR64.md](PLAN-NODE64-SONAR64.md),
Schnittstellen: [SONAR64-VERTRAG.md](SONAR64-VERTRAG.md).

> Stand: in Entwicklung, noch nicht veröffentlicht. Release-Dateien und Image entstehen mit dem ersten Tag
> `sonar64-v<version>`.

## Auf einen Blick

| | |
|---|---|
| Programm | eine statische Datei (< 10 MB), Standardbibliothek von Go, kein Speicher außer ein paar KB im Datenordner |
| Plattformen | `linux/arm/v6` (Pi Zero/1), `arm/v7` (Pi 2/3, MikroTik), `arm64` (Pi Zero 2, Pi 4/5, MikroTik), `amd64` |
| Image | `ghcr.io/ipv64net/sonar64` für `amd64`, `arm64`, `arm/v7` (Pi Zero/1: install.sh) |
| Anmeldung | **Sonar-Token** (`s64_…`), nur für Sonar64 – nicht der API-Key des Accounts |
| Netz | ausgehend HTTPS zu ipv64.net, ICMP und UDP 6464 zu den Zielen aus dem Plan; eingehend UDP 6464 nur, wenn man gemessen werden will |
| Rechte | nur `CAP_NET_RAW` (für ICMP), läuft als eigener Nutzer |

## 1. Sonar-Token anlegen

Jeder Knoten braucht ein eigenes Token (höchstens 10 je Account). Es wird nur einmal im Klartext angezeigt.

- Auf ipv64.net unter **Sonar64 › Mein Knoten › Neues Token**, oder
- per API mit dem API-Key des Accounts:

```sh
curl -s -H "Authorization: Bearer <API-Key>" -H 'Content-Type: application/json' \
  -d '{"name":"pi-wohnzimmer"}' https://ipv64.net/api/v2/sonar/tokens
```

Beim ersten Start legt `sonar64` damit seine **Node-ID** und einen eigenen Schlüssel (Ed25519) im Datenordner an und
bleibt danach dieser Knoten, auch nach Neustarts und Updates. Datenordner sichern = Knoten behalten; Token
zurückziehen (`DELETE /sonar/tokens/{id}` oder im Portal) = Knoten abmelden.

Name, Standort (Punkt auf der Karte), Anschlussart und Gerät setzt man danach auf ipv64.net unter „Mein Knoten“.

## 2. Raspberry Pi Zero, Pi und Linux ohne Docker (install.sh)

Für den ersten Pi Zero (W) – ARMv6, 512 MB RAM – ist Docker zu schwer. `install.sh` installiert die einzelne Datei
mit einem systemd-Dienst. Voraussetzungen: Raspberry Pi OS / Debian / Ubuntu (oder ein anderes Linux mit systemd),
`curl` oder `wget`, `sha256sum`.

```sh
curl -fsSLO https://raw.githubusercontent.com/ipv64net/node64/main/deploy/sonar64/install.sh
less install.sh          # vorher ansehen
sudo sh install.sh       # fragt nach dem Token (Eingabe unsichtbar)
```

Was das Skript tut:

1. erkennt die Architektur (`armv6l`, `armv7l`, `aarch64`, `x86_64`),
2. lädt `sonar64-linux-<arch>`, `sonar64.service` und `SHA256SUMS` aus dem neuesten fertigen
   GitHub-Release (`ipv64net/node64`, Tag `sonar64-v*`, ohne Vorabversionen) und bricht ab, wenn eine Prüfsumme nicht passt,
3. legt den Systemnutzer `sonar64` an (ohne Login, ohne Home),
4. schreibt `/etc/sonar64.env` (nur root lesbar, `0600`) mit dem Token,
5. installiert `/usr/local/bin/sonar64` und `/etc/systemd/system/sonar64.service` und startet den Dienst.

Der Dienst läuft als `sonar64` mit nur `CAP_NET_RAW`, `NoNewPrivileges`, `ProtectSystem=strict`, eigenem
`StateDirectory` (`/var/lib/sonar64`, Schlüssel und Node-ID) und `MemoryMax=64M`.

Optionen beim Aufruf (als Umgebungsvariablen, werden in `/etc/sonar64.env` übernommen):

```sh
sudo SONAR64_MEASURED=1 SONAR64_BUDGET=normal sh install.sh   # auch gemessen werden, Budget normal
sudo SONAR64_VERSION=0.1.0 sh install.sh                     # bestimmte Version
sudo sh install.sh --uninstall   # Dienst und Programm entfernen (Einstellung und Schlüssel bleiben)
sudo sh install.sh --purge       # zusätzlich Einstellung, Schlüssel und Node-ID löschen
```

Das Token per Variable (`sudo SONAR64_TOKEN=s64_… sh install.sh`) landet in der Shell-Historie – die Abfrage ist
sicherer. **Aktualisieren:** `sudo sh install.sh` erneut ausführen; Token und Einstellungen bleiben.

Betrieb:

```sh
systemctl status sonar64
journalctl -u sonar64 -f
sudo nano /etc/sonar64.env && sudo systemctl restart sonar64
```

## 3. Docker

```sh
docker run -d --name sonar64 --restart unless-stopped \
  -e SONAR64_TOKEN=s64_… \
  -v sonar64:/data \
  ghcr.io/ipv64net/sonar64
```

- Das Image ist leer bis auf das Programm (`FROM scratch`), läuft als Nutzer `65532` und braucht nur `NET_RAW`
  (in Docker Standard). Fehlt das Recht (`--cap-drop NET_RAW`, Podman rootless), startet es trotzdem und misst über
  UDP 6464 bzw. Linux-Ping-Sockets, soweit möglich.
- **Gemessen werden** (`SONAR64_MEASURED=1`): UDP 6464 muss von außen erreichbar sein, also
  `-p 6464:6464/udp` und im Router eine Portfreigabe. Für IPv6 und genaue Werte besser `--network host`.
  Der Antworter beantwortet nur öffentliche Absender: Läuft die Weiterleitung über den `docker-proxy` (häufig bei
  IPv6 ohne `ip6tables`), sieht er nur das Docker-Gateway (z. B. `172.17.0.1`) und schweigt – dann `--network host`.
- Docker Compose:

```yaml
services:
  sonar64:
    image: ghcr.io/ipv64net/sonar64
    restart: unless-stopped
    network_mode: host          # IPv6 und UDP 6464 ohne NAT
    environment:
      SONAR64_TOKEN: s64_…
      SONAR64_MEASURED: "1"
      SONAR64_QUIET: "23-6"
      TZ: Europe/Berlin
    volumes:
      - sonar64:/data
volumes:
  sonar64:
```

## 4. MikroTik (RouterOS 7, Container-Paket)

Geeignet sind Geräte mit ARM, ARM64 oder x86 und ein paar MB freiem Speicher (am besten USB-Stick oder interner
Flash mit genug Platz). Standard-Budget dort: `sparsam`.

1. **Container-Paket** installieren (System › Packages › `container`) und den Container-Modus freischalten:
   ```
   /system/device-mode/update container=yes
   ```
   Danach innerhalb von 5 Minuten den Reset-Knopf kurz drücken bzw. das Gerät aus- und einschalten.
2. **Netz für den Container** (eigene Bridge, NAT nach außen):
   ```
   /interface/veth/add name=veth-sonar64 address=172.17.64.2/24 gateway=172.17.64.1
   /interface/bridge/add name=br-containers
   /ip/address/add address=172.17.64.1/24 interface=br-containers
   /interface/bridge/port/add bridge=br-containers interface=veth-sonar64
   /ip/firewall/nat/add chain=srcnat action=masquerade src-address=172.17.64.0/24
   ```
3. **Nur wenn gemessen werden soll:** UDP 6464 zum Container weiterleiten:
   ```
   /ip/firewall/nat/add chain=dstnat action=dst-nat in-interface-list=WAN protocol=udp dst-port=6464 \
       to-addresses=172.17.64.2 to-ports=6464
   ```
4. **Registry und Ablage:**
   ```
   /container/config/set registry-url=https://ghcr.io tmpdir=usb1/pull
   ```
5. **Einstellung** (Token und Optionen; ab RouterOS 7.20 heißt das Feld `list=` statt `name=`):
   ```
   /container/envs/add name=sonar64 key=SONAR64_TOKEN value="s64_…"
   /container/envs/add name=sonar64 key=SONAR64_BUDGET value=sparsam
   /container/envs/add name=sonar64 key=TZ value=Europe/Berlin
   /container/mounts/add name=sonar64-data src=usb1/sonar64-data dst=/data
   ```
6. **Container anlegen und starten:**
   ```
   /container/add remote-image=ghcr.io/ipv64net/sonar64:latest interface=veth-sonar64 envlist=sonar64 \
       mounts=sonar64-data root-dir=usb1/sonar64 start-on-boot=yes logging=yes
   /container/start [find where tag~"sonar64"]
   /log/print where topics~"container"
   ```

Hinweise: Kann der Container den Datenordner nicht beschreiben, steht im Log `data directory not usable` – dann den
Ordner auf dem Router neu anlegen bzw. als letzte Möglichkeit `user=0:0` beim Container setzen. Ob ICMP im Container
geht, hängt von der RouterOS-Version ab; ohne ICMP misst der Knoten über UDP 6464 und meldet das ipv64.net selbst.
IPv6 im Container braucht eine IPv6-Adresse am veth und eine Route; ohne misst der Knoten nur IPv4.

## 5. Anker (neuer Standort mit einem Befehl)

Anker sind feste Messpunkte (Start: Falkenstein und Nürnberg). Ein Anker ist dasselbe Programm im Anker-Modus:
Antworter auf ICMP und UDP 6464 immer an, misst alle Knoten mit einem eigenen, größeren Budget und prüft ihre
Erreichbarkeit. Anker-Tokens (`s64a_…`) stellt nur ipv64.net aus (`php bots/sonar_anchor_token.php --name=<anker>`).

```sh
docker run -d --name sonar64-anchor --restart unless-stopped --network host \
  -e SONAR64_TOKEN=s64a_… \
  -v sonar64-anchor:/data \
  ghcr.io/ipv64net/sonar64
```

Mit einem Anker-Token schaltet `sonar64` von selbst in den Anker-Modus (`SONAR64_MODE=anchor` geht auch).
Firewall: ICMP-Echo und UDP 6464 eingehend (IPv4 und IPv6) erlauben. Ein Anker läuft völlig losgelöst von den hubs.

## 6. Einstellungen (Umgebungsvariablen)

| Variable | Standard | Bedeutung |
|---|---|---|
| `SONAR64_TOKEN` | – (Pflicht) | Sonar-Token `s64_…` bzw. Anker-Token `s64a_…` |
| `SONAR64_MODE` | `headless` (mit Anker-Token `anchor`) | `headless` oder `anchor` |
| `SONAR64_MEASURED` | `0` | `1` = auch gemessen werden (UDP 6464 beantworten); `0` = nur ausgehend messen, nie Ziel |
| `SONAR64_BUDGET` | `sparsam` | `sparsam`, `normal` oder `grosszuegig` (lokale Obergrenze, siehe Grenzen) |
| `SONAR64_QUIET` | – | Ruhezeit in lokaler Zeit, z. B. `23-6` (von 23 bis 6 Uhr keine Messungen); Zeitzone über `TZ` |
| `SONAR64_DATA` | `/data` (Dienst: `/var/lib/sonar64`) | Datenordner für Schlüssel, Node-ID, Zustand (ein paar KB) |
| `SONAR64_STATUS` | – (aus) | Mini-Status, z. B. `127.0.0.1:8064` oder `:8064` |
| `SONAR64_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `SONAR64_API` | – | nur für Tests (anderer API-Server; `http` nur zu Loopback) |
| `SONAR64_PLAN_KEY` | – | nur für Tests, solange kein Plan-Schlüssel eingebaut ist |

Falsche Werte führen zu einem klaren Fehler beim Start (Exit-Code 2, der systemd-Dienst startet dann nicht
endlos neu); das Token erscheint nie im Log.
`sonar64 version` zeigt die Version, `sonar64 healthcheck` prüft den Mini-Status (Docker `HEALTHCHECK`; ohne
`SONAR64_STATUS` immer gesund, solange der Prozess läuft).

**Mini-Status** (nur mit `SONAR64_STATUS`): `GET /` schlichte Seite (aktualisiert sich alle 5 s), `GET /status`
JSON mit Zustand und den letzten 50 Messungen raus und rein, `GET /health` (200 = läuft und angemeldet, sonst 503).
Nur lesen, ohne Anmeldung – deshalb am besten nur an `127.0.0.1` oder im Heimnetz binden, nie ins Internet
freigeben. Er enthält keine Geheimnisse und keine Adressen (auch keine Traceroute-Hops). Die volle Ansicht gibt es auf ipv64.net unter
„Mein Knoten“.

## 7. Datenschutz und Opt-in

- Teilnahme ist freiwillig; ohne `SONAR64_MEASURED=1` misst der Knoten **nur ausgehend** und erscheint nie als Ziel.
- Öffentlich sichtbar sind Anzeigename, verschleierter Standort (fester Versatz im Umkreis von 1 km), Provider/ASN,
  Anschlussart, Gerät, Vertrauensstufe, Verfügbarkeit – **nie die IP-Adresse** und nie der Account.
- Die öffentliche IP nimmt ipv64.net nur aus der Verbindung; sie bekommen ausschließlich die Knoten, die diesen
  Knoten laut Plan messen sollen.
- Der genaue Standort ist nur für den Besitzer sichtbar (und dient der Plausibilitätsprüfung).
- Gemeldet werden nur Zusammenfassungen je Ziel (Min/Mittel/Max/Jitter/Verlust), keine Rohpakete und keine Daten
  aus dem Heimnetz.

## 8. Grenzen (fest im Programm, vom Server nicht änderbar)

- Ziele je Runde (5 min): sparsam 8, normal 15, großzügig 20 (Anker 2.000).
- Höchstens 2 Pakete/s (Anker 50/s), höchstens 5 Pakete je Messung; Traceroute höchstens 2 je Stunde, TTL ≤ 30.
- Tagesgrenze: sparsam 20.000, normal 40.000, großzügig 60.000 Pakete.
- Nur Ziele aus dem von ipv64.net **signierten** Plan, nie private oder reservierte Adressen.
- Ein Plan gilt höchstens 30 min; ohne neuen Plan nur noch die Anker, nach 2 h Pause. Ergebnisse werden bis 6 h
  gepuffert und nachgereicht.
- Selbstbremse: ist die eigene Leitung gestört (≥ 80 % Verlust zu allen Ankern), pausiert der Knoten eine Runde.
- UDP 6464 antwortet nur auf das exakte Sonar-Format, nie größer als die Anfrage, höchstens 5 Pakete/s je Quelle
  und 50/s gesamt.
- Bedarf: ein paar KB auf der Platte, Ziel < 20 MB RAM, kaum CPU.

## 9. Fehlersuche

| Meldung im Log | Ursache |
|---|---|
| `SONAR64_TOKEN is required` / `invalid format` | Token fehlt oder ist unvollständig kopiert |
| `data directory not usable` | Datenordner nicht beschreibbar (Volume-Rechte, Nutzer 65532) |
| `an anchor token (s64a_) needs SONAR64_MODE=anchor` | Anker-Token mit `SONAR64_MODE=headless` |
| `no plan key …` | Entwicklungsstand ohne eingebauten Plan-Schlüssel (dann `SONAR64_PLAN_KEY`) |
| ICMP-Messungen fehlen | `CAP_NET_RAW` fehlt (Container ohne `NET_RAW`); UDP 6464 geht trotzdem |
| „gemessen“, aber nie per UDP erreichbar | Portfreigabe fehlt oder Docker leitet UDP 6464 über den `docker-proxy` (Absender = Gateway, wird nicht beantwortet): `--network host` |
