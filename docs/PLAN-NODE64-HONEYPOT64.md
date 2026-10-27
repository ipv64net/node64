# Plan: Honeypot64

Stand 2026-10-20, Entscheidungen Dennis. Umgesetzt: H1 (98fbfc4), H2 (948e128, live), H3 Bewertung/Listen, IP-Auskunft/Freigaben und PROXY64-Live-Listen (Einspielen: deploy/web/H3-HONEYPOT-VORHER-NACHHER.md und H3-FREIGABE-VORHER-NACHHER.md). Dieser Plan legt die Grundlagen so fest (Datenformat,
Arten, Speicherung, Schnittstellen), dass spätere Ausbaustufen ohne Umbau am Produkt dazukommen.

**Ziel:** Die **erste Verteidigungslinie** der Kunden stärken – ausschließlich über **IP- und DNS-Listen**, Honeypot64 wird nirgends als Schutzsoftware vor Anwendungen gesetzt: Firewall (IP), Mailserver, Login-Seiten. Dazu sammeln
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
| Belohnung für Beitragende | **Live-Stand** der Listen (auch mit Klasse Standard) |
| Preise | keine eigenen; alles in den bestehenden Account-Klassen |
| Betrieb ohne Oberfläche | ja (Modus `honeypot`, Abschnitt 2) |
| Prometheus | ja |
| Daten für spätere Auswertung (auch KI) | aufheben, mit gestuften Fristen (Abschnitt 4) |
| Benutzernamen/Passwörter | **nur aus dem Honeypot**, nie aus echten Logs |
| Melden | **nur über Node64** (keine Fremd-Meldungen aus Fail2ban/CrowdSec) |
| DNS-Sperrliste | entfallen (Entscheidung Dennis 2026-10-27: keine DNSBL `bl.ipv64.net`) |
| Angebot | Stufen nach dem Muster von CrowdSec (Abschnitt 8) |
| Zugang zur v64 Blocklist | **alle bekommen sie vollständig und frei**; frei = Tagesstand (einmal täglich, bis 24 h alt); **alle Klassen außer Standard** (`user_class` ≠ 1: VIP, Premium, Business, Company, Supporter) der Live-Stand nach jeder Bewertung (alle 30 min); Freigaben sind in beiden entfernt |

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

**Web-Angriffe nach OWASP eingeordnet:** Die gefälschten Webseiten prüfen jede Anfrage (Pfad, Parameter, Kopfzeilen,
Body-Anfang) gegen eine kleine, mitgelieferte Musterliste, angelehnt an die Kategorien des OWASP Core Rule Set:
`http:exploit:sqli`, `:xss`, `:traversal` (Path Traversal/LFI), `:rce` (Command Injection), `:log4shell`/`:jndi`,
`:ssrf`, `:upload` (Web-Shells). Zweck ist **nur die Bewertung der IP**: Ein eindeutiger Exploit-Versuch zählt stärker
als ein bloßer Aufruf und bringt die IP schneller und sicherer auf die Liste. Honeypot64 wird dadurch **keine WAF** und
schützt keine Webseiten selbst – geblockt wird ausschließlich über IP- und DNS-Listen.

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
- **Nur über Node64** (Entscheidung Dennis): keine Fremd-Meldungen aus Fail2ban, CrowdSec oder eigenen Skripten; so
  stammen alle Daten aus unseren eigenen, versionierten Regeln.
- Der Sensor meldet seine eigene öffentliche IP nicht; ipv64 kennt sie aus der Verbindung und schließt sie aus.

## 6. Bewertung bei ipv64 (alle 30 Minuten)

- **Gezählt werden Accounts, nicht Sensoren.** Wer zehn Sensoren betreibt, zählt einmal. Zwei Accounts mit Sensoren im
  selben /24 zählen als einer.
- **Vertrauen je Sensor:** Werden seine Meldungen oft von anderen bestätigt, zählt er mehr; meldet er dauerhaft IPs,
  die sonst niemand sieht, weniger. Neue Accounts starten niedrig.
- **Gewichtung nach Quelle und Art:** Honeypot > Log-Sensor > Syslog; Exploit/Login > Port-Scan >
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
| **v64 Blocklist** | Tagesstand frei: `ipv64_blocklist_v64.txt` (+ v4/v6, MikroTik), `index.json`, nicht in `all`; Live-Stand für alle Klassen außer Standard (Abschnitt 8) | jede Firewall, PROXY64 |
| Teillisten je Art | `…_v64_ssh`, `…_v64_web`, `…_v64_mail`, `…_v64_rdp`, `…_v64_scanner` | gezielt je Dienst |
| Forschungs-Scanner | `…_v64_research` | wer Shodan & Co. aussperren will |
| **Schadhosts aus Payloads** | Domains und IPs, die Angreifer in Payloads nachladen (`wget http://…`, `${jndi:ldap://…}`), erst ab mehreren Accounts; IPs in die v64 Blocklist, Domains als Liste für DNS-Filter | DNS64, Pi-hole, AdGuard, Firewall – blockt die Nachlade-Server, falls ein Gerät doch befallen ist |
| ~~DNSBL~~ | entfallen (2026-10-27): keine DNS-Sperrliste `bl.ipv64.net` | – |
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

## 8. Angebot und Stufen

Muster CrowdSec: Software und Grundlisten kostenlos, die Gemeinschaft liefert die Daten; bezahlt wird für Aktualität,
Menge und fertige Anbindung (Premium-Blocklisten, „Blocklist as a Service“ für Firewalls, IP-Auskunft per API,
Spiegelung der Datenbank, Support). Übertragen auf die Account-Klassen von ipv64 (Vorschlag, Preise und Zuordnung
entscheidet Dennis):

**Grundsatz (Dennis 2026-10-20):** Die v64 Blocklist bekommt **jeder vollständig** – kein Account bekommt eine
gekürzte Liste. Unterschied ist nur die **Aktualität**:

| Fassung | Inhalt | aktualisiert | für |
|---|---|---|---|
| **Tagesstand** | alle zum Stichtag gesperrten IPs, ohne Freigaben | einmal täglich (bis zu 24 h alt) | alle, frei, ohne Anmeldung |
| **Live** | alle gerade gesperrten IPs, ohne Freigaben | nach jeder Bewertung (alle 30 min) | **alle Klassen außer Standard** (`user_class` ≠ 1) |

- Gleiches Schema für die Teillisten (`…_v64_ssh`, `…_web`, …) und die Schadhosts.
- **Live-Abruf** über eine eigene Adresse mit persönlichem **Listen-Token** im Pfad, z. B.
  `https://ipv64.net/blocklists/live/<token>/ipv64_blocklist_v64.txt` – Firewalls wie pfSense, OPNsense, MikroTik,
  FortiGate können keine Kopfzeilen mitschicken, eine Adresse genügt ihnen. Das Token ist getrennt vom API-Key, im
  Account sichtbar und widerrufbar; geprüft wird die Klasse bei jedem Abruf (läuft sie ab, gibt es wieder den Tagesstand); Abrufe werden je Token begrenzt (z. B. höchstens alle 5 Minuten).
- **Freigaben** wirken in der Live-Fassung sofort, im Tagesstand mit dem nächsten Stichtag.
- ~~DNS-Sperrliste `bl.ipv64.net`~~: entfallen (Entscheidung Dennis 2026-10-27).
- In `index.json` steht die freie Fassung; Node64/PROXY64 nimmt mit hinterlegtem Listen-Token automatisch die
  Live-Fassung.

**Keine eigenen Preise** (Dennis 2026-10-20): alles läuft in den bestehenden Account-Klassen; Limits (API,
DNS-Sperrliste) über die vorhandenen Klassenwerte. Grundsätzlich bekommen **alle alles**; Unterschiede gibt es nur bei
der Aktualität der Listen und beim Umfang der Informationsseite.

| Wer | bekommt |
|---|---|
| **alle** (auch ohne Konto) | v64 Blocklist, Teillisten und Schadhosts **vollständig im Tagesstand**, DNS-Sperrliste (Tagesstand), IP-Auskunft mit Freigabe-Antrag, Listen für Passwörter, Benutzernamen, User-Agents und Pfade, **Informationsseite im Überblick** |
| **Beitragende** (mindestens ein Sensor hat in den letzten 7 Tagen gemeldet, auch Klasse Standard) | **Live-Stand** der Listen als Belohnung, Statistik „dein Beitrag“ |
| **alle Klassen außer Standard** (`user_class` ≠ 1: VIP, Premium, Business, Company, Supporter) | **Live-Stand** der Listen, **volle Informationsseite** (eingeloggt) |
| Hoster/Partner auf Anfrage | Netzberichte, BGP-Feed, Abgleich großer Datenmengen |

Änderungs-Feed, Frühwarnung für eigene Netze und Passwortprüfung stehen allen Konten offen; ihr Umfang folgt den
Klassenwerten.

Limits und Stufe hängen am API-Key; die DNS-Sperrliste zählt je abfragender IP bzw. je eingetragenem Mailserver.

## 8b. Hosting-Anbieter und Netzbetreiber

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

**Überblick für alle, volle Informationsseite eingeloggt für alle Klassen außer Standard** (Abschnitt 8).

- **Überblick (alle):** aktive Sensoren, Angriffe 24 h und Verlauf, meistangegriffene Ports und Arten, Herkunft nach
  Land, Größe der Listen, Top 10 je Bereich.
- **Volle Informationsseite (Klassen ≠ Standard):** alles aus dem Überblick ohne Top-10-Grenze, dazu Herkunft nach
  Netzbetreiber, häufigste Benutzernamen, Passwörter, Pfade und User-Agents mit Verlauf, neue Angreifer heute, neue
  Exploit-Pfade/CVE, Kampagnen, Länder der Sensoren, Suche und Export.
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
| H5 | Log-Sensor und Syslog-Empfänger, Frühwarnung für eigene Netze, Stufen und Limits |
| H6 | Honeypot Stufe 2, JA4/HASSH, Passwortprüfung (k-Anonymität), Änderungs-Feed, Node64 als Firewall-Helfer |
| H7 | Hosting-Anbieter (Netzberichte, BGP-Feed), Plugins, weitere Plattformen (FreeBSD, Windows), KI-Auswertung |

## H3 Umsetzung (Schnittstellen, verbindlich fuer die parallelen Teile)

| Teil | Dateien | Inhalt |
|---|---|---|
| Bewertung + Listen | `deploy/sql/honeypot_h3_scoring.sql`, `deploy/web/blocklists/site/bots/blocklist/honeypot_score.php`, Aenderungen an `create_blocklists_v2.php` und `v64_blocklists.php`, `deploy/web/blocklists/live.php`, Token-Verwaltung im Account (`deploy/web/honeypot/token.php`) | Abschnitt 6, 7 (v64 Blocklist + Teillisten), 8 (Tagesstand/Live, Listen-Token) |
| IP-Auskunft + Freigaben | `deploy/sql/honeypot_h3_release.sql`, `deploy/web/honeypot/ip.php`, `deploy/web/api_v2_threat.php` (`GET /threat/ip/{ip}`), `deploy/web/honeypot/admin.php`, `deploy/web/bots/honeypot_release.php` | Abschnitt 7 (IP-Auskunft), 9 (Freigabe, Loeschantraege, dauerhafte Freigaben) |
| Node64 | `internal/cdn64` (Blocklisten-Karte), ggf. `internal/honeypot` | Listen-Token hinterlegen: PROXY64 laedt v64-Listen dann live |

**Tabellen** (MariaDB, `ip_bin` = `INET6_ATON`-Form, IPv4 als 4 Byte):

- `hp_scores` (Teil Bewertung): `ip_bin` PK, `ip`, `family` (4/6), `score` 0–100, `accounts`, `sensors`, `events`,
  `kinds` (Komma), `lists` (Komma: `ssh,web,mail,rdp,scanner,research`), `first_seen`, `last_seen`, `listed` (0/1),
  `listed_since`, `reason` (`threshold`, `customer_ip`, `allowlist`, `infra`), `updated_at`.
- `hp_list_tokens` (Teil Bewertung): `userid` PK, `token` (32 Zeichen, eindeutig), `created_at`, `last_used`,
  `uses_window_start`, `uses_in_window`.
- `hp_allowlist` (Teil Freigaben, liest die Bewertung): `id`, `cidr`, `ip_start`/`ip_end` (VARBINARY(16)), `reason`,
  `source` (`manual`, `request`, `infra`, `cdn`), `until` (NULL = dauerhaft), `created_at`, `created_by`.
- `hp_release_requests` (Teil Freigaben): `id`, `ip`, `ip_bin`, `userid` (NULL = anonym), `email`, `reason`,
  `status` (`open`, `released`, `rejected`, `escalated`), `created_at`, `decided_at`, `protected_until`, `note`.

**Dateien der Listen:** Tagesstand oeffentlich unter `blocklists/ipv64_blocklist_v64.txt` (+ `_v4_`, `_v6_`,
MikroTik `v64_mikrotik_v4_v64.rsc`), Teillisten `…_v64_ssh`, `_v64_web`, `_v64_mail`, `_v64_rdp`, `_v64_scanner`,
`_v64_research`. Live-Fassung ausserhalb des Webroots bzw. in einem gesperrten Ordner, ausgeliefert ueber
`/blocklists/live/<token>/<datei>` (`live.php`). In `index.json` eigene Kategorie `honeypot`, `in_all` = false.

## H5 Umsetzung (Schnittstellen, verbindlich fuer die parallelen Teile)

Vertrag Go: `internal/honeypot/logsensor_types.go` (LogLine, LogRule, LogConfig, Status, Grenzen), `Event.Source`/`Event.Rule`
(types.go), Platzhalter `logengine.go`, `syslog.go`, `watch.go` (Signaturen bleiben).

| Teil | Dateien | Inhalt |
|---|---|---|
| Log-Sensor | `logengine.go`, `logtail.go`, `logrules_svc.go` (+ Tests) | Regeln anwenden, Schwellen je Regel und IP, Rueckstellung bei Erfolg, Dateien mitlesen (Rotation, Kuerzung, Glob, Poll), Regeln fuer sshd, nginx/Apache/Caddy, Postfix/Dovecot, Proxmox, Nextcloud, Vaultwarden, Gitea/Forgejo, Home Assistant |
| Syslog | `syslog.go`, `logrules_fw.go` (+ Tests) | UDP/TCP (RFC 3164/5424, Octet-Counting), nur erlaubte Absender (Standard private Netze), Regeln fuer MikroTik, OPNsense/pfSense, FortiGate, Sophos, UniFi |
| Einbindung | `types.go` (Config.Log), `store.go` + Migration `0002_source.sql`, `report_store.go`, `module.go`, `ui.go`, Templates, `metrics.go`, `cmd/node64/honeypot_mode.go`, `docs/HONEYPOT64.md` | Einstellungen und Port-Pruefung, Speichern mit Quelle/Regel, Meldung mit `source`/`rule`, Proben **nur** aus dem Honeypot, Oberflaeche (Quellen, Zustand der Dateien/Syslog), Umgebungsvariablen `NODE64_HONEYPOT_LOGS`, `NODE64_HONEYPOT_SYSLOG_PORT`, `NODE64_HONEYPOT_SYSLOG_ALLOW` |
| Fruehwarnung Node64 | `watch.go`, `watch_ui.go`, Template, `internal/ipv64api/threat_watch.go`, Benachrichtigung `KindHoneypotWatch` | Netze in der Oberflaeche verwalten (gespeichert bei ipv64), Treffer alle 30 min abholen und melden |
| ipv64 | `deploy/sql/honeypot_h5.sql`, `deploy/web/api_v2_threat_watch.php`, `deploy/web/honeypot/watch.php`, `deploy/web/bots/honeypot_watch.php`, `deploy/web/honeypot/hp_limits_lib.php`, kleine Aenderung `api_v2_honeypot.php` (Dienst `vpn`, Sensor-Limit) | Fruehwarnung (Netze, Pruefung nach jeder Bewertung, Mail + API), Limits je Klasse |

**Entscheidungen H5** (Vorschlag, Dennis kann aendern):

- Log-Sensor liest Textdateien; **journald direkt erst spaeter** (das Binaerformat braucht sonst CGO). Bis dahin
  `rsyslog` auf dem Host oder Weiterleitung per Syslog an den Empfaenger.
- Logs im Container: `-v /var/log:/host/log:ro`, dazu `--group-add 4` (Gruppe `adm`), weil `auth.log` nicht fuer alle
  lesbar ist. Fehlende Rechte stehen als Fehler an der Datei.
- Syslog nur von erlaubten Absendern (Standard: private Netze, localhost) – UDP-Absender lassen sich faelschen.
- Aus echten Logs gehen **keine Proben** an ipv64 (keine Pfade, User-Agents, Benutzernamen), nur IP, Art, Dienst,
  Port, Anzahl, Zeitraum, Regel. Lokal steht nur der Regelname im Detail.
- Gemeldete Regel `<id>@<version>`; ipv64 gewichtet schon nach Quelle (honeypot 1.0, log 0.8, syslog 0.7).
- Fruehwarnung: Netze ohne Nachweis bekommen nur Treffer, die **gelistet** sind (ohnehin oeffentlich); die
  aktuellen DynDNS-IPs des Accounts gelten als nachgewiesen und melden schon jede Sichtung. Limits je Klasse:
  Netze Standard 3, sonst 50; IPv4 ab /16, IPv6 ab /32.
- Sensoren je Account: Standard 5, sonst 25 (weitere Sensoren bekommen `403 sensor_limit`).

## PROXY64 und Honeypot64 (Entscheidung Dennis 2026-10-20)

Nur Opt-in: PROXY64 nutzt den Honeypot nur, wenn es in den Einstellungen von PROXY64 eingeschaltet ist (je Punkt ein
Schalter, Standard aus) und das Modul Honeypot64 laeuft. Verbindung ueber `internal/hpbridge` (keiner der beiden Teile
importiert den anderen).

| Nr. | Was | Stand |
|---|---|---|
| 1 | Anfragen ohne passenden Host (nur IP, fremde Domain, leere SNI) gehen an den Web-Koeder statt an eine Fehlerseite | jetzt |
| 2 | Zugriffe von PROXY64 (nur Metadaten) wertet der Log-Sensor mit eigenen Regeln aus (`proxy64/*@1`), gemeldet wird nur IP/Art/Anzahl | jetzt |
| 3 | Sofort-Sperre: im Honeypot auffaellige IPs sperrt PROXY64 lokal fuer eine Weile (Standard 24 h) | jetzt |
| 4 | Fallen-Pfade auf echten Hosts | spaeter |
| 5 | **Merken:** PROXY64 erkennt bekannte Angriffswerkzeuge am JA4-Fingerabdruck (Daten aus der Statistik) | spaeter |

**Dienste-Auswahl dynamischer:** Statt nur Profil oder Textliste ein Katalog aller Fallen-Dienste mit Schalter je
Dienst, Port aenderbar, Koeder-Auswahl, Anzeige „frei / belegt von …“, Profile als Vorlage („uebernehmen“ fuellt den
Katalog), „alle freien einschalten“; Dienste mehrfach auf verschiedenen Ports moeglich. Auf einer reinen Honeypot-Node
(Node64 mit Oberflaeche, sonst keine Module) sind so alle Ports nutzbar.

## Herkunft der Angreifer (Wunsch Dennis 2026-10-20)

Laenderflaggen und Herkunft im Container (wichtig) und zentral bei ipv64. Keine fremde GeoIP-Datenbank im Image.

- **Quelle:** ipv64 erzeugt taeglich aus den RIR-Daten (wie die Laenderlisten) eine Datei
  `https://ipv64.net/blocklists/country_ranges.txt.gz`: gzip-Text, Kommentarzeilen mit `#`, sonst je Zeile
  `<CC> <erste IP> <letzte IP>` (IPv4 und IPv6, zusammengefasst, aufsteigend sortiert, CC = ISO-3166 alpha-2 gross).
  In `index.json` als `"geo": {"file": "country_ranges.txt.gz", "updated": "<RFC3339>", "ranges": <Anzahl>}`.
- **Node64:** Paket `internal/geoip` laedt die Datei (nur wenn ein Nutzer sie braucht, z. B. Honeypot64 an), Cache in
  `/data/geoip/`, Aktualisierung taeglich (ETag), Suche per Binaersuche; Honeypot64 zeigt Flaggen (Emoji, keine
  Bilder), Rangliste nach Land, farbige Uebersicht „was wurde angegriffen“; Prometheus mit Label `country` begrenzt.
- **ipv64:** `hp_scores.country`, Herkunft in Statistik, `/threat/stats` und IP-Auskunft.

## 15. Offen

- Aufteilung Überblick/volle Informationsseite im Detail (bei H4).
