# Honeypot64 H8 – verwundbar wirken, neue Fallen, Köder-Zugangsdaten

Auftrag von Dennis vom 30.10.2026, über die Honeypot-Sitzung. Gewählt sind die Vorschläge 3, 4 und 5. Nicht gewählt:
tagesaktuelle Regeln, Erkennung neuer Wellen, Tarpit und ein Raspberry-Image.

Für alle Phasen gilt der Rahmen aus `PLAN-NODE64-HONEYPOT64.md`:
- Low Interaction: niemanden hereinlassen, nichts ausführen und nichts herunterladen (nur Adressen notieren).
- Keine Antwort größer als die Anfrage, keine Verstärker-Dienste (Memcached, NTP, SSDP, CLDAP u. ä.).
- Keine nachgebauten Hersteller-Oberflächen oder Logos.

Ausgerollt wird nur auf Dennis' Wort. Die Doku auf node64.de zieht die Webseiten-Sitzung nach, `ipv64_docs` nur
dann, wenn Portal oder Statistik betroffen sind.

Reihenfolge: 5 (nur Node64), 4 (nur Node64), 3 (Node64, Portal und SQL).

## Phase 5 – verwundbar wirken

- **Schalter:** `Config.Vulnerable` mit Einträgen `dienst:port`. Standard ist aus.
- **Oberfläche:** Häkchen „Verwundbar“ je Zeile im Dienste-Katalog, mit Warnhinweis: Das zieht mehr gezielte Scanner
  an.
- **Ohne Oberfläche:** Umgebungsvariable `NODE64_HONEYPOT_VULNERABLE=ssh:22,http:80`.
- **Möglich für:** http, https, ssh und mysql (`OldVersions`). Die Variation je Sensor bleibt, der Seed wählt
  innerhalb der alten Reihe.
- **Gezeigte Versionen:**

  | Dienst | Ältere Version |
  |---|---|
  | Apache | 2.4.49 / 2.4.50 (CVE-2021-41773/42013) |
  | nginx | 1.18.0 (Ubuntu) / 1.14.2 |
  | PHP | 7.4 als `X-Powered-By` |
  | OpenSSH | 8.2p1 Ubuntu / 7.9p1 Debian |
  | Dropbear | 2019.78 / 2020.81 |
  | Webmin | 1.890–1.920 (CVE-2019-15107) |
  | Grafana | 8.0–8.3.0 (CVE-2021-43798) |
  | MySQL / MariaDB | 5.7 bzw. MariaDB 10.3 |

- **Proxmox:** Die Anmeldeseite zeigt ohne Login keine Version, deshalb ändert sich dort nichts.
- **Erfassung:** bleibt unverändert, Ereignisse sehen gleich aus.

## Phase 4 – Fallen für aktuell angegriffene Dienste

Jede Falle ist im Katalog einzeln schaltbar und in die Profile einsortiert: „full“ bekommt alle, „standard“ nur die
häufigsten.

- **Rand des Firmennetzes (HTTP/HTTPS-Köder wie die Geräte-Endpunkte):** Login- und API-Pfade von FortiGate SSL-VPN,
  Ivanti Connect Secure, Citrix ADC/Gateway und Palo Alto GlobalProtect. Bekannte Exploit-Pfade dieser Geräte werden
  als `http:exploit` mit Gerät im Detail erfasst. Die Antworten sind schlichte Ablehnungen im Format der API, ohne
  Oberfläche.
- **IoT und Botnetze:**
  - ADB 5555/tcp: CONNECT lesen, mit einer kleinen Ablehnung antworten.
  - TR-069 7547: HTTP, CWMP-Inform bzw. Exploit-Pfade.
  - Kamera-Pfade Hikvision (`/ISAPI/...`, `/SDK/...`) und Dahua (`/RPC2_Login`, `/cgi-bin/...`) auf den Web-Fallen.
- **Industrie und Gebäudetechnik:** nur lesen und die Anfrage erfassen. Die Antwort ist nie größer als die Anfrage.
  - Modbus 502/tcp: Exception „Illegal Function“.
  - S7 102/tcp: COTP-Verbindungsbestätigung höchstens so groß wie die Anfrage, danach Ende.
  - BACnet 47808/udp: keine Antwort, nur erfassen (I-Am wäre größer als Who-Is).
- **Cloud und DevOps:**
  - Docker-API und kubelet gibt es schon.
  - Neu: CouchDB 5984, GitLab (`/users/sign_in`, `/api/v4/...`), Jenkins-Script-Pfade und Hadoop YARN 8088
    (`/ws/v1/cluster/apps/new-application`).
- **Neue Arten:** `ics:scan` (Lesen bzw. Sondierung) und `iot:exploit`. Das Portal nimmt Arten nach Muster an, das
  wird mit Phase 3 geprüft.

## Phase 3 – Köder-Zugangsdaten (Honeytokens)

- **Wo:** Die Web-Fallen liefern auf typischen Pfaden scheinbar echte Dateien aus: `/.env`, `/.git/config`,
  `/backup.sql`, `/wp-config.php.bak`, `/config.json` u. ä.
- **Inhalt:** DB-Passwort, SMTP-Zugang, API-Token und Admin-Login.
- **Werte:** je Sensor eindeutig und stabil aus dem Seed und dem Tag.
  - Keine echten Formate großer Anbieter: keine gültig aussehenden AWS- oder GitHub-Schlüssel mit Prüfsumme.
  - Eigene Muster mit einer kurzen Kennung, z. B. `hp64` im Token, damit ipv64 sie wiedererkennt.
- **Verwendung erkennen:**
  - Taucht ein ausgegebener Wert später als Login an einer Honeypot64-Falle auf, ob am gleichen Sensor, an einem
    anderen oder bei einem anderen Account, entsteht das Ereignis „Honeytoken verwendet“ (`token:used`) mit Verweis
    auf den Abruf.
  - Lokal erkennt der Sensor nur seine eigenen Werte. Über alle Sensoren verknüpft ipv64: Der Sensor meldet den Abruf
    (`token:fetched`, mit Kennung des Werts statt des Werts) und die Verwendung.
- **Portal:**
  - Neue Tabelle für die Verknüpfung von Abruf und Verwendung (Sammler gegen Verwerter).
  - Hohe Gewichtung in der Bewertung.
  - Anzeige in der Statistik und auf der Live-Karte.
  - Eine SQL-Datei im Upload-Paket.

## Stand

- Phase 5: siehe CHANGELOG Honeypot64 0.17.0.
- Phase 4: Protokoll-Fallen ADB, Modbus, S7, BACnet in Honeypot64 0.18.0. Die erweiterten HTTP-Köder (VPN-Gateways,
  Kameras, DevOps-Dienste) und TR-069 sind zurückgestellt.
- Phase 3: zurückgestellt (nicht in dieser Sitzung umgesetzt).
