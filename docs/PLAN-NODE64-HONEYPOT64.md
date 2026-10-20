# Plan: Honeypot64

Stand 2026-10-20, Entscheidungen Dennis. Noch nicht umgesetzt. Dieser Plan legt die Grundlagen so fest (Datenformat,
Arten, Speicherung, Schnittstellen), dass spätere Ausbaustufen ohne Umbau am Produkt dazukommen.

**Ziel:** Die **erste Verteidigungslinie** der Kunden stärken: Firewall (IP), Mailserver, Login-Seiten. Dazu sammeln
viele kleine Sensoren – Honeypot und Auswertung echter Logs – Angriffe und melden sie an ipv64. Dort entstehen aus den
Meldungen **mehrerer unabhängiger** Beitragender laufend aktualisierte Listen und Auskünfte, die jeder nutzen kann,
auch ohne eigenen Sensor: Homelab, Mittelstand und Hosting-Anbieter.

**Vorbilder:** DShield/SANS ISC (viele kleine Sensoren, zentrale Auswertung, Statistiken zu Ports, Quellen,
Zugangsdaten, Web-Pfaden), CrowdSec (Log-Auswertung mit Szenarien, Gemeinschaft, Bewertung über mehrere Melder, Schutz
gegen Vergiften, IP-Auskunft, „Bouncer“ an der Firewall), Spamhaus/Shadowserver (DNSBL, BGP-Feed, Berichte an
Netzbetreiber), Have I Been Pwned (Passwortprüfung ohne Preisgabe des Passworts). Bewusst **nicht** T-Pot (8–16 GB RAM,
ELK, echte Shells).

## Entscheidungen

| Thema | Entscheidung |
|---|---|
| Name | **Honeypot64** (Modul `honeypot`) |
| Meldung Sensor → ipv64 | alle **10 Minuten** |
| Auswertung bei ipv64 | alle **30 Minuten**; der Blocklisten-Cron wird so angepasst, dass das Ergebnis sofort in den Listen landet |
| Liste | Honeypot-IPs kommen in die **v64 Blocklist** (bisher „Coming soon“ auf der Listenseite), **nicht** in die Gesamtliste `all` |
| Zugangsdaten | aus dem Honeypot Benutzername und Passwort im **Klartext** übertragen und in die zentrale Statistik übernehmen, dazu ein Hash zum Abgleich |
| Schwelle | **dynamisch** nach Zahl der aktiven Beitragenden (Abschnitt 6) |
| Freigabe (Whitelist) | muss es geben; Anträge werden automatisch geprüft, geht das nicht oder ist es strittig → an Dennis |
| Eigene Sensoren | **nicht** auf srv07/srv08; Dennis betreibt selbst ein bis zwei Sensoren |
| Belohnung für Beitragende | später (Dennis überlegt) |
| Betrieb ohne Oberfläche | ja (Modus `honeypot`, Abschnitt 2) |
| Prometheus | ja |
| Daten für spätere Auswertung (auch KI) | aufheben, mit gestuften Fristen (Abschnitt 4) |

## 1. Sensoren: drei Quellen

Grundsatz für alle: Ist das Modul aus, belegt es nichts – kein Port, kein Speicher, keine Verbindung.

### 1a. Honeypot (Fallen-Dienste)

Low Interaction: Logins werden angenommen und immer abgelehnt; keine Shell, keine Befehle, keine Downloads, keine
ausgehenden Verbindungen außer der Meldung an ipv64. Limits je IP (Verbindungen, Bytes), feste Zeitlimits. **Jede**
Berührung ist verdächtig, weil dort kein echter Dienst läuft – das stärkste Signal.

| Stufe | Dienst | erfasst |
|---|---|---|
| 1 | SSH (22, 2222), Telnet (23, 2323) | Benutzername, Passwort, Client-Version (SSH-Banner), Schlüssel-Fingerabdruck bei Public-Key-Versuchen |
| 1 | HTTP/HTTPS (80, 443, 8080, 8443) | Methode, Pfad, Host, User-Agent, Login-Versuche auf gefälschten Seiten |
| 1 | beliebige weitere TCP-Ports | die ersten Bytes (Protokoll, Exploit) |
| 1 | Port-Scan-Erkennung | viele Ports in kurzer Zeit |
| 2 | FTP, SMTP-AUTH, POP3/IMAP | Zugangsdaten |
| 2 | RDP (3389) | Benutzername aus dem Verbindungsaufbau (`mstshash`), kein Login möglich |
| 2 | MySQL, MSSQL, PostgreSQL, Redis, MongoDB, Elasticsearch | Benutzername bzw. Befehl aus dem Protokoll |
| 2 | Docker-API (2375), Kubernetes (6443, 10250), MQTT (1883), VNC (5900), SIP (5060 UDP) | erste Anfrage |
| 2 | TLS-Fingerabdruck (JA4) bei HTTPS, SSH-Fingerabdruck (HASSH) | erkennt Werkzeuge unabhängig von IP und User-Agent |

Gefälschte Login-Seiten auf 80/443 (beliebte Einfallstore): WordPress, phpMyAdmin, FRITZ!Box, Exchange/OWA,
FortiGate-VPN, Citrix, Grafana, Jenkins, Synology, Proxmox.

### 1b. Log-Sensor (wie CrowdSec)

Liest Logs **echter** Dienste und erkennt Angriffe darauf – die Angriffe, die wirklich bei Kunden ankommen.

- Quellen (nur lesend, eingebunden mit `-v /var/log:/host/log:ro` bzw. Journal): `auth.log`/journald (sshd, sudo),
  nginx/Apache/Caddy (Zugriff und Fehler), Postfix/Dovecot/Exim, Proxmox, Nextcloud, Gitea/Forgejo, Vaultwarden,
  Home Assistant, Windows-Ereignisprotokoll (4625 fehlgeschlagene Anmeldung, RDP) in der Windows-Fassung.
- Auswertung über **mitgelieferte, versionierte Regeln** („Parser“ und „Szenarien“ mit fester Kennung und Version,
  z. B. `sshd/bruteforce@1`). Für die zentrale Bewertung zählen nur unveränderte mitgelieferte Regeln (wie CrowdSec:
  Kennung und Version werden mitgeschickt). Eigene Regeln wirken nur lokal.
- **Schwellen**, weil echte Logs auch Vertipper legitimer Nutzer enthalten: z. B. 5 fehlgeschlagene Logins in
  10 Minuten ohne Erfolg, Exploit-Pfad, Scanner-User-Agent.
- **Gemeldet wird nur:** IP, Szenario, Anzahl, Zeitraum, Dienst. **Keine** Benutzernamen und keine Inhalte aus echten
  Logs (das wären Mitarbeitende oder Kunden des Betreibers).

### 1c. Syslog-Empfänger

Router und Firewalls schicken ihre Logs per Syslog (UDP/TCP 514, optional TLS 6514) an den Sensor: MikroTik,
OPNsense/pfSense, FortiGate, Sophos, UniFi. Ausgewertet wie 1b (fehlgeschlagene Admin-Logins, VPN-Brute-Force,
verworfene Verbindungen in großer Zahl). Nützt vor allem Firmen, deren Firewall selbst keine Angreifer weitergibt.

### Sensor-Profile

`minimal` (SSH, HTTP, Port-Scan – für kleine Geräte), `standard` (Stufe 1 + Log-Sensor), `full` (alles).

## 2. Wo der Sensor läuft

Ein Programm (reines Go, statisch, ohne CGO), viele Wege:

| Ziel | Form | Hinweis |
|---|---|---|
| Docker (amd64, arm64, **armv7**) | `ghcr.io/ipv64net/node64`, Modus `NODE64_MODE=honeypot` | armv7 neu im Image-Build (Raspberry Pi alt, viele NAS) |
| **MikroTik RouterOS** (Container-Paket) | dasselbe Image, Profil `minimal` | sitzt direkt am Rand; RAM knapp (ab 256 MB), Speicher auf USB/Platte; Anleitung im Leitfaden |
| Raspberry Pi, VPS, Proxmox-LXC | Docker oder Binary | |
| Synology, QNAP, Unraid, TrueNAS | Docker/App | |
| Linux ohne Docker | statisches Binary + systemd-Unit, `.deb` | |
| OPNsense/pfSense | FreeBSD-Binary (Go baut es mit), später Plugin | Firewall selbst als Sensor und Syslog-Empfänger |
| Windows-Server | Dienst, liest das Ereignisprotokoll | RDP-Brute-Force im Mittelstand |
| Kubernetes | DaemonSet / Helm | Hoster |

**Modus ohne Oberfläche:** keine Web-Oberfläche, keine anderen Module; 22, 80 und 443 sind frei für den Honeypot,
keine Admin-Seite als Angriffsfläche. Einstellungen nur über Umgebungsvariablen, Zustand über Log und Prometheus,
Statistik bei ipv64.

```
docker run -d --name honeypot64 --network host --restart unless-stopped \
  -e NODE64_MODE=honeypot -e NODE64_IPV64_KEY=<api-key> -e NODE64_HONEYPOT_PROFILE=standard \
  -v /var/log:/host/log:ro ghcr.io/ipv64net/node64
```

**Info-Seite und Prometheus auch ohne Oberfläche:** ein eigener, kleiner Port (`NODE64_HONEYPOT_INFO_PORT`, Vorschlag
`9064`), getrennt von den Fallen-Ports:

- `/` – Info-Seite **nur lesend**, ohne Login-Formular: Zustand der Dienste (offen, Fehler), Treffer heute und 7 Tage,
  Top-IPs, Arten, Ports, Zugangsdaten, Pfade, User-Agents, letzte Meldung an ipv64 (Zeitpunkt, Erfolg), Version.
- `/metrics` – Prometheus.
- `/health` – für Docker und Monitoring.
- Schutz: erreichbar nur aus privaten Netzen und localhost (Standard), oder überall mit Token
  (`NODE64_HONEYPOT_INFO_TOKEN`, als `?token=` bzw. `Authorization: Bearer`). So kann die Info-Seite nie selbst
  zur Angriffsfläche werden; `NODE64_HONEYPOT_INFO_PORT=0` schaltet sie ganz ab.

**Prometheus** (Modul und Modus ohne Oberfläche gleich): `node64_honeypot_connections_total{service,port}`,
`node64_honeypot_logins_total{service}`, `node64_honeypot_events_total{kind,source}`, `node64_honeypot_unique_sources`,
`node64_honeypot_report_last_success_timestamp`, `node64_honeypot_report_errors_total`,
`node64_honeypot_listen_errors{port}`, `node64_honeypot_buffer_bytes`.

**Ressourcen:** geschätzt 30–50 MB RAM; lokal 7 Tage in SQLite (`/data/honeypot/`) mit fester Obergrenze; Ports unter
1024 über die vorhandene Fähigkeit `+p`.

**Mit Oberfläche** (als Modul neben den anderen): Zugriffe, Top-IPs, Top-Zugangsdaten, Pfade, User-Agents, Verlauf;
Benachrichtigung bei neuen Angreifern; Option „Angreifer in PROXY64 sperren“.

## 3. Arten von Angriffen (feste Einteilung)

Jede Meldung trägt eine Art aus einer festen, erweiterbaren Liste (angelehnt an MITRE ATT&CK, wie bei CrowdSec):
`ssh:bruteforce`, `telnet:bruteforce` (IoT/Mirai), `rdp:bruteforce`, `mail:auth-bruteforce`,
`http:bruteforce` (Login-Seiten), `http:exploit` (bekannte Exploit-Pfade/CVE), `http:scan` (Verzeichnis-Scan),
`http:bad-useragent`, `db:bruteforce`, `generic:portscan`, `generic:probe` (bloßer Verbindungsaufbau),
`vpn:bruteforce`, `scanner:research` (Shodan, Censys …). Zusätzlich frei: CVE-Kennung, wenn erkannt.

## 4. Datenmodell und Speicherung

**Meldung (Sensor → ipv64), versioniert** (`schema: 1`): Sensor-Kennung, Programmversion, Profil, Zeitraum (10 min),
dann je Quelle-IP: Art, Dienst/Port, Anzahl, erster/letzter Zeitpunkt, Quelle (`honeypot`/`log`/`syslog`), Regel
(`sshd/bruteforce@1`); dazu Proben: Zugangsdaten mit Anzahl (nur Honeypot), Pfade, User-Agents, JA4/HASSH,
Payload-Anfang (SHA-256 + erste 256 Bytes). Neue Felder sind optional; ältere Sensoren bleiben gültig.

**Bei ipv64 angereichert:** Land und Netzbetreiber (ASN) aus den RIR-Daten (vorhanden) und einer freien ASN-Datenbank,
Sensor-Netz (zur Gewichtung, nie veröffentlicht).

**Fristen (Vorschlag):**

| Daten | Frist |
|---|---|
| Meldungen mit voller IP | 90 Tage, danach IP auf /24 (IPv4) bzw. /48 (IPv6) gekürzt, mit ASN und Land |
| Gekürzte Meldungen (für Trends, KI) | 24 Monate |
| Zugangsdaten, Pfade, User-Agents, Fingerabdrücke, Payload-Hashes (keine personenbezogenen Daten) | unbegrenzt |
| Listen | bis 14 Tage nach dem letzten Treffer |

**Speicher:** zuerst MySQL, Meldungstabelle nur anhängend und nach Tag partitioniert (alte Tage fallen als Ganzes
weg). Wird es groß, gehen die Meldungen in eine Analyse-Datenbank (z. B. ClickHouse); das Format bleibt gleich.

## 5. Melden

- **Mit Node64:** verknüpft (API-Key), nach Opt-in, alle 10 Minuten `POST /honeypot/reports` (API v2). Fehlt die
  Verbindung, holt der Sensor aus dem lokalen Puffer nach (höchstens 7 Tage).
- **Ohne Node64** (mehr Daten mit wenig Aufwand): derselbe Endpunkt für Fail2ban (fertige Action), CrowdSec
  (Benachrichtigungs-Plugin) und eigene Skripte. Gewichtet niedriger als Honeypot-Meldungen, weil die Regeln dort
  nicht von uns sind.
- Der Sensor meldet seine eigene öffentliche IP nicht; ipv64 kennt sie aus der Verbindung und schließt sie aus.

## 6. Bewertung bei ipv64 (alle 30 Minuten)

- **Gezählt werden Accounts, nicht Sensoren.** Wer zehn Sensoren betreibt, zählt einmal. Zwei Accounts mit Sensoren im
  selben /24 zählen als einer.
- **Vertrauen je Sensor:** Werden seine Meldungen oft von anderen bestätigt, zählt er mehr; meldet er dauerhaft IPs,
  die sonst niemand sieht, weniger. Neue Accounts starten niedrig.
- **Gewichtung nach Quelle und Art:** Honeypot > Log-Sensor > Fremd-Meldung (Fail2ban); Exploit/Login > Port-Scan >
  bloßer Verbindungsaufbau. Ältere Treffer verlieren an Gewicht.
- **Dynamische Schwelle** nach Zahl der Accounts, die in den letzten 7 Tagen gemeldet haben (Startwerte):

  | aktive Accounts | aufgenommen ab |
  |---|---|
  | unter 20 | 2 Accounts mit Login/Exploit, sonst 3 |
  | 20–200 | 3 Accounts |
  | über 200 | 2 % der aktiven Accounts, mindestens 3, höchstens 10 |

- **Vertrauenswert 0–100** je IP. Rausfallen ohne neue Treffer nach 14 Tagen.
- **Nie listen:** reservierte Netze, Sensoren, Infrastruktur von ipv64, große CDNs, Freigaben.
- **IPs von ipv64-Kunden** (aktuelle DynDNS-IP): nicht automatisch listen, zur Prüfung markieren, Kunden warnen.
- **Cron:** `bots/blocklist/honeypot_score.php` alle 30 Minuten, direkt danach `create_blocklists_v2.php`; die externen
  Listen (`read_blocklists.php`) bleiben in ihrem Takt.

## 7. Was entsteht und wo es wirkt (erste Verteidigungslinie)

| Ergebnis | Form | wirkt in |
|---|---|---|
| **v64 Blocklist** | `ipv64_blocklist_v64.txt` (+ v4/v6, MikroTik), `index.json`, nicht in `all` | jede Firewall, PROXY64 |
| Teillisten je Art | `…_v64_ssh`, `…_v64_web`, `…_v64_mail`, `…_v64_rdp`, `…_v64_scanner` | gezielt je Dienst |
| Forschungs-Scanner | `…_v64_research` | wer Shodan & Co. aussperren will |
| **DNSBL** | `<ip-rückwärts>.bl.ipv64.net` → `127.0.0.x` (Code je Art) | Mailserver (Postfix, rspamd), schnelle Prüfung ohne Listen-Download; über PowerDNS |
| **Änderungs-Feed** | API `GET /threat/feed?since=` (nur Änderungen, ETag) | große Abnehmer, Hoster, eigene Werkzeuge |
| **IP-Auskunft** | Seite und API `GET /threat/ip/{ip}` | „Warum ist diese IP gelistet?“: Zeiten, Arten, Ports, Accounts, Vertrauenswert, Land/ASN |
| **Passwortprüfung** | API mit k-Anonymität (`GET /threat/passwords/range/{erste 5 Zeichen SHA-1}`), wie HIBP | Login-/Registrierungsseiten prüfen ohne das Passwort preiszugeben |
| Passwort-Sperrliste | Text, häufigste Passwörter der Angreifer | Passwort-Richtlinien (Active Directory, Nextcloud, Keycloak) |
| Benutzernamen | Text | Standard-Konten umbenennen, Registrierung sperren |
| Böse User-Agents | Text bzw. nginx-`map` | Webserver, WAF |
| Angriffs-Pfade | Text bzw. nginx-`location` | Webserver, WAF |
| **Node64 als Firewall-Helfer** | Modus `honeypot` mit `NODE64_FIREWALL=nftables` (braucht NET_ADMIN) | trägt die v64 Blocklist in nftables des Hosts ein – wie der CrowdSec-Firewall-Bouncer |
| Plugins (später) | WordPress, Nextcloud, Keycloak | Login sperrt gelistete IPs und Angreifer-Passwörter |

Alle Listen laufen über die bestehende Pipeline (Generator, `index.json`, Listenseite, Leitfaden). Das reine
Textformat nehmen auch Firmen-Firewalls direkt: Palo Alto (External Dynamic List), FortiGate (Threat Feed), Sophos.

## 8. Hosting-Anbieter und Netzbetreiber

- **Berichte für eigene Netze** (wie Shadowserver): Anbieter trägt ASN bzw. Präfixe ein (Nachweis per RIR-Eintrag oder
  Mail an die Abuse-Adresse) und bekommt laufend bzw. täglich, welche IPs aus seinem Netz angreifen – für das eigene
  Abuse-Team.
- **Zentral nutzen für Kunden:** Änderungs-Feed und DNSBL mit höheren Limits, optional **BGP-Feed** (RTBH) für den
  Rand des Netzes.
- Stabile Formate, versionierte API, Status der Feeds.

## 9. Freigabe und Löschanträge

- **Antrag** über die IP-Auskunft (Formular, mit Begründung; eingeloggt oder per Mail-Bestätigung).
- **Automatische Prüfung:** Hat die IP seit dem Antrag 24 h lang keinen Sensor mehr berührt, wird sie entfernt und
  30 Tage geschützt (wird sie danach wieder auffällig, neu bewertet).
- **Geht das nicht** (greift weiter an, mehrere Anträge, Netz eines Providers) → **an Dennis**.
- **Dauerhafte Freigaben** (eigene Infrastruktur, Partner) pflegt Dennis in einer Freigabeliste.

## 10. Statistik bei ipv64 unter „Secure“

- **Für alle:** aktive Sensoren und Länder, Angriffe 24 h und Verlauf, meistangegriffene Ports und Arten, Herkunft
  nach Land und Netzbetreiber, häufigste Benutzernamen, Passwörter, Pfade, User-Agents, neue Angreifer heute, neue
  Exploit-Pfade/CVE, Größe der Listen.
- **Für Beitragende:** eigene Sensoren (online/offline, letzte Meldung, Version), Treffer je Quelle, Port und Zeit,
  Top-Angreifer bei mir, „Deine Meldungen haben X IPs auf die v64 Blocklist gebracht“.

## 11. Für den Mittelstand

- **Frühwarnung für eigene Netze:** eigene IPs/Netze eintragen; fällt eine davon als Angreifer auf, kommt sofort eine
  Meldung (meist ein gekapertes Gerät). Für DynDNS-Kunden automatisch.
- Sensor in der DMZ oder im internen Netz: erkennt auch Angriffe von innen (die Meldung an ipv64 kann dafür
  abgeschaltet werden, die lokale Warnung bleibt).
- Log-Sensor/Syslog an der vorhandenen Firewall, Windows-Fassung für RDP.
- Stabile Adressen, Aktualisierung alle 30 Minuten, IP-Auskunft, klarer Freigabeweg.

## 12. Auswertung später (auch per KI)

Die Daten aus Abschnitt 4 reichen dafür ohne Umbau: Kampagnen erkennen (gleiche Passwortlisten, Pfade, Fingerabdrücke
über viele IPs), neue Exploit-Pfade vor der Veröffentlichung einer CVE, Botnetze nach JA4/HASSH, Häufung nach
Netzbetreibern, Zusammenfassungen in Klartext für die Statistikseite.

## 13. Sicherheit und Datenschutz

- Honeypot: Low Interaction, keine ausgehenden Verbindungen, Limits; Modus ohne Oberfläche ohne Admin-Seite.
- Log-Sensor: nur lesend, meldet keine Benutzernamen oder Inhalte aus echten Logs.
- Zu Hause braucht der Honeypot eine Portfreigabe; die Doku weist darauf hin, dass er danach von außen sichtbar ist.
- Angreifer-IPs sind personenbezogene Daten: Abwehr von Angriffen als berechtigtes Interesse, Fristen aus Abschnitt 4,
  Eintrag in der Datenschutzerklärung. Veröffentlicht werden nur bewertete Listen und Statistiken; IPs der Sensoren
  und Rohdaten bleiben intern.
- IPv6: Den Adressraum kann niemand durchscannen; Honeypots sehen überwiegend IPv4, der Log-Sensor auch IPv6.

## 14. Phasen

| Phase | Inhalt |
|---|---|
| H1 | Honeypot Stufe 1, Modul mit Oberfläche und Modus ohne Oberfläche (mit Info-Seite und Prometheus auf eigenem Port), Profile, lokale Statistik, armv7-Image |
| H2 | Meldung alle 10 Minuten (Format `schema: 1`), Tabellen bei ipv64, Statistik für Beitragende |
| H3 | Bewertung alle 30 Minuten, v64 Blocklist und Teillisten, Cron, IP-Auskunft, Freigabe-Anträge |
| H4 | Öffentliche Statistik unter „Secure“, Passwort-/Benutzer-/User-Agent-/Pfad-Listen, DNSBL, Leitfaden (Firmen-Firewalls, MikroTik-Container) |
| H5 | Log-Sensor und Syslog-Empfänger, Melden ohne Node64 (Fail2ban, CrowdSec), Frühwarnung für eigene Netze |
| H6 | Honeypot Stufe 2, JA4/HASSH, Passwortprüfung (k-Anonymität), Änderungs-Feed, Node64 als Firewall-Helfer |
| H7 | Hosting-Anbieter (Netzberichte, BGP-Feed), Plugins, weitere Plattformen (FreeBSD, Windows), KI-Auswertung, Belohnung |

## 15. Offen

1. Log-Sensor: Benutzernamen aus echten Logs nie melden (Vorschlag) – oder nur auf ausdrücklichen Wunsch?
2. Fristen aus Abschnitt 4 so übernehmen?
3. Hosting-Anbieter: kostenlos wie alle, oder eigene Stufe (Feed, BGP, höhere Limits) gegen Geld?
4. Melden ohne Node64 (Fail2ban, CrowdSec) zulassen?
5. Name der DNSBL-Zone (Vorschlag `bl.ipv64.net`).
