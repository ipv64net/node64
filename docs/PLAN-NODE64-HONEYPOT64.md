# Plan: Honeypot64

Stand 2026-10-20, Entscheidungen Dennis. Noch nicht umgesetzt.

**Ziel:** ein leichter Honeypot-Sensor in Node64, den jeder mit einem Befehl starten kann (zu Hause, auf einem VPS, im
Firmennetz). Die Sensoren melden an ipv64; dort entstehen aus den Meldungen **vieler** Beitragender eigene, laufend
aktualisierte Blocklisten und Informationen (Zugangsdaten, User-Agents, Pfade). Nutzbar für alle, auch ohne eigenen
Sensor – für Homelab und für den Mittelstand.

**Vorbilder:** DShield/SANS ISC (viele kleine Sensoren, zentrale Auswertung, Statistiken zu Ports, Quellen,
Zugangsdaten, Web-Pfaden), CrowdSec (Gemeinschaft, Bewertung über mehrere unabhängige Melder, Schutz gegen Vergiften,
IP-Auskunft mit Einordnung, Fehlalarme melden). Bewusst **nicht** T-Pot: 8–16 GB RAM, ELK, echte Shells.

## Entscheidungen

| Thema | Entscheidung |
|---|---|
| Name | **Honeypot64** (Modul `honeypot`) |
| Meldung Sensor → ipv64 | alle **10 Minuten** |
| Auswertung bei ipv64 | alle **30 Minuten**; der Blocklisten-Cron wird so angepasst, dass das Ergebnis sofort in den Listen landet |
| Liste | Honeypot-IPs kommen in die **v64 Blocklist** (bisher „Coming soon“ auf der Listenseite), **nicht** in die Gesamtliste `all` |
| Zugangsdaten | Benutzername und Passwort im **Klartext** übertragen und in die zentrale Statistik übernehmen, dazu ein Hash zum Abgleich |
| Schwelle | Vorschlag unten, **dynamisch** nach Zahl der aktiven Beitragenden |
| Freigabe (Whitelist) | muss es geben; Anträge werden automatisch geprüft, geht das nicht oder ist es strittig → an Dennis |
| Eigene Sensoren | **nicht** auf srv07/srv08; Dennis betreibt selbst ein bis zwei Sensoren |
| Belohnung für Beitragende | später (Dennis überlegt) |
| Betrieb nur als Honeypot, ohne Oberfläche | ja (eigener Modus, siehe unten) |
| Prometheus | ja |

## 1. Sensor in Node64

**Grundsatz:** Ist das Modul aus, belegt es nichts – kein Port, kein Speicher, keine Verbindung.

**Low Interaction:** Logins werden angenommen und immer abgelehnt; keine Shell, keine Befehle, keine Downloads, keine
ausgehenden Verbindungen außer der Meldung an ipv64. Limits je IP (Verbindungen, Bytes), feste Zeitlimits.

### Dienste

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
| 2 | TLS-Fingerabdruck (JA4) bei HTTPS | erkennt Werkzeuge unabhängig von IP und User-Agent |

**Gefälschte Login-Seiten auf 80/443** (beliebte Einfallstore): WordPress, phpMyAdmin, FRITZ!Box, Exchange/OWA,
FortiGate-VPN, Citrix, Grafana, Jenkins, Synology, Proxmox. Jede Seite nimmt Anmeldungen an und lehnt ab; erfasst
werden Pfad, Zugangsdaten und User-Agent.

**Ressourcen:** reines Go, ein Listener je Port, geschätzt 30–50 MB RAM, läuft auf einem Raspberry Pi. Lokal nur
7 Tage in SQLite (`/data/honeypot/`), feste Obergrenze; Ports unter 1024 über die vorhandene Fähigkeit `+p`.

### Zwei Betriebsarten

- **Als Modul** neben den anderen: Oberfläche mit Zugriffen, Top-IPs, Top-Zugangsdaten, Top-Pfaden und User-Agents,
  Verlauf; Benachrichtigung bei neuen Angreifern; Option „Angreifer auch in PROXY64 sperren“. Die Port-Verwaltung
  verhindert Überschneidungen mit echten Diensten.
- **Nur Honeypot, ohne Oberfläche:** `NODE64_MODE=honeypot`. Keine Web-Oberfläche, keine anderen Module; damit sind
  auch 22, 80 und 443 frei für den Honeypot, und es gibt keine Admin-Seite als Angriffsfläche. Einstellungen nur
  über Umgebungsvariablen, Statistik bei ipv64, Zustand über Log und Prometheus:

  ```
  docker run -d --name honeypot64 --network host --restart unless-stopped \
    -e NODE64_MODE=honeypot -e NODE64_IPV64_KEY=<api-key> \
    -e NODE64_HONEYPOT_PORTS=22,23,80,443,3389,5900 ghcr.io/ipv64net/node64
  ```

### Prometheus

`node64_honeypot_connections_total{service,port}`, `node64_honeypot_logins_total{service}`,
`node64_honeypot_unique_sources`, `node64_honeypot_report_last_success_timestamp`,
`node64_honeypot_report_errors_total`, `node64_honeypot_listen_errors{port}`. Im Modus ohne Oberfläche auf einem
eigenen Port (`NODE64_METRICS_PORT`) mit Token.

## 2. Meldung an ipv64 (alle 10 Minuten)

- Nur verknüpfte Nodes (API-Key), nach Opt-in. Endpunkt in der API v2, z. B. `POST /honeypot/reports`.
- Keine Einzelereignisse, sondern **Zusammenfassungen je 10 Minuten**: je IP Art, Port, Anzahl, erster/letzter
  Zeitpunkt; Zugangsdaten (Benutzername, Passwort im Klartext, SHA-256) mit Anzahl; die häufigsten Pfade,
  User-Agents, Payload-Anfänge und Fingerabdrücke. Hält die Datenbank bei ipv64 klein, auch bei vielen Sensoren.
- Fehlt die Verbindung, holt der Sensor nach (lokaler Puffer, höchstens 7 Tage).
- Der Sensor meldet seine eigene öffentliche IP nicht mit; ipv64 kennt sie aus der Verbindung und schließt sie aus.

## 3. Auswertung bei ipv64 (alle 30 Minuten)

- **Gezählt werden Accounts, nicht Sensoren.** Wer zehn Sensoren betreibt, zählt einmal (Schutz gegen Vergiften).
- **Gewichtung:** Exploit/Login-Versuch > Port-Scan > bloßer Verbindungsaufbau. Ältere Treffer verlieren an Gewicht.
- **Dynamische Schwelle** nach Zahl der Accounts, die in den letzten 7 Tagen gemeldet haben (Vorschlag):

  | aktive Accounts | aufgenommen ab |
  |---|---|
  | unter 20 | 2 Accounts mit Login/Exploit, sonst 3 |
  | 20–200 | 3 Accounts |
  | über 200 | 2 % der aktiven Accounts, mindestens 3, höchstens 10 |

- **Vertrauenswert 0–100** je IP (Accounts, Art, Dauer, Wiederholung). Rausfallen ohne neue Treffer nach 14 Tagen.
- **Nie listen:** reservierte Netze, die IPs der Sensoren, Infrastruktur von ipv64, große CDNs; Freigaben (unten).
- **IPs von ipv64-Kunden:** Ist eine IP gerade einer DynDNS-Domain eines Kunden zugeordnet, wird sie nicht
  automatisch gelistet, sondern zur Prüfung markiert; der Kunde bekommt eine Warnung (siehe Frühwarnung).
- **Bekannte Forschungs-Scanner** (Shodan, Censys u. a.) werden erkannt und getrennt eingeordnet, nicht in die
  v64 Blocklist (eigene Liste zum freiwilligen Sperren).
- **Cron:** neues Skript `bots/blocklist/honeypot_score.php` alle 30 Minuten, direkt danach
  `create_blocklists_v2.php`. Die externen Listen (`read_blocklists.php`) bleiben in ihrem Takt.

## 4. Was daraus entsteht

| Ergebnis | Form | Nutzen |
|---|---|---|
| **v64 Blocklist** | `ipv64_blocklist_v64.txt` (+ v4/v6, MikroTik), in `index.json`, nicht in `all` | IPs, die mehrere unabhängige Sensoren angegriffen haben |
| Teillisten je Art | `…_v64_ssh`, `…_v64_web`, `…_v64_scanner` | gezielt je Dienst |
| Forschungs-Scanner | `…_v64_research` | wer auch Shodan & Co. aussperren will |
| **Passwort-Sperrliste** | Text, häufigste Passwörter der Angreifer | in Passwort-Richtlinien (z. B. Active Directory, Nextcloud) sperren |
| **Benutzernamen** | Text, häufigste Login-Namen | Standard-Konten umbenennen, Warnung bei Treffern |
| **Böse User-Agents** | Text bzw. nginx-`map` | im Webserver/WAF sperren |
| **Angriffs-Pfade** | Text bzw. nginx-`location` | bekannte Exploit-Pfade abweisen |
| **IP-Auskunft** | Seite und API „Warum ist diese IP gelistet?“ | erster/letzter Zeitpunkt, Art, Ports, Anzahl Accounts, Vertrauenswert, Land/Netzbetreiber, Einordnung |

Alle Listen laufen über die bestehende Pipeline (Generator, `index.json`, Listenseite, Leitfaden) und damit sofort für
nftables, iptables, pfSense, OPNsense, MikroTik, nginx, CrowdSec und PROXY64. Das reine Textformat nehmen auch
Firmen-Firewalls direkt: Palo Alto (External Dynamic List), FortiGate (Threat Feed), Sophos – kommt in den Leitfaden.

## 5. Freigabe und Löschanträge

- **Antrag** über die IP-Auskunft (Formular, mit Begründung; eingeloggt oder per Mail-Bestätigung).
- **Automatische Prüfung:** Hat die IP seit dem Antrag 24 h lang keinen Sensor mehr berührt, wird sie entfernt und
  für 30 Tage geschützt (wird sie danach wieder auffällig, neu bewertet).
- **Geht das nicht** (IP greift weiter an, mehrere Anträge, Netz eines Providers) → **an Dennis** zur Entscheidung.
- **Dauerhafte Freigaben** (z. B. eigene Infrastruktur, Partner) pflegt Dennis in einer Freigabeliste.

## 6. Statistik bei ipv64 unter „Secure“

- **Für alle:** aktive Sensoren und Länder, Angriffe 24 h und Verlauf, meistangegriffene Ports, Herkunft nach Land
  und Netzbetreiber, häufigste Benutzernamen, Passwörter, Pfade und User-Agents, neue Angreifer heute, Größe der
  Listen.
- **Für Beitragende:** eigene Sensoren (online/offline, letzte Meldung), Treffer je Port und Zeit, Top-Angreifer bei
  mir, „Deine Meldungen haben X IPs auf die v64 Blocklist gebracht“.

## 7. Für den Mittelstand

- **Frühwarnung für eigene Netze:** eigene IPs/Netze eintragen; fällt eine davon in den Honeypots als Angreifer auf,
  kommt sofort eine Meldung (meist ein gekapertes Gerät im eigenen Netz). Für DynDNS-Kunden automatisch.
- Stabile Adressen der Listen, Aktualisierung alle 30 Minuten, IP-Auskunft und klarer Freigabeweg.
- Sensor im eigenen Netz (z. B. in der DMZ) im Modus ohne Oberfläche: erkennt auch Angriffe von innen.

## 8. Sicherheit und Datenschutz

- Low Interaction, keine ausgehenden Verbindungen, Limits, keine Admin-Oberfläche im Honeypot-Modus.
- Zu Hause braucht der Sensor eine Portfreigabe im Router; Hinweis in der Doku, dass der Sensor danach von außen
  sichtbar ist.
- Angreifer-IPs sind personenbezogene Daten: Abwehr von Angriffen als berechtigtes Interesse, feste Speicherfristen
  (Rohdaten 30 Tage, Listen 14 Tage nach letztem Treffer), Eintrag in der Datenschutzerklärung. Veröffentlicht werden
  nur bewertete Listen und Statistiken; die IPs der Sensoren bleiben intern.
- IPv6: Den Adressraum kann niemand durchscannen; Sensoren sehen überwiegend IPv4-Angriffe.

## 9. Phasen

| Phase | Inhalt |
|---|---|
| H1 | Sensor (Stufe 1), Modul mit Oberfläche und Modus ohne Oberfläche, lokale Statistik, Prometheus |
| H2 | Meldung alle 10 Minuten an die API v2, Tabellen bei ipv64, Statistik für Beitragende |
| H3 | Auswertung alle 30 Minuten, v64 Blocklist und Teillisten, Cron, IP-Auskunft, Freigabe-Anträge |
| H4 | Öffentliche Statistik unter „Secure“, Passwort-/Benutzer-/User-Agent-/Pfad-Listen, Leitfaden Firmen-Firewalls |
| H5 | Dienste Stufe 2, JA4-Fingerabdrücke, Frühwarnung für eigene Netze |
| H6 | Muster und Kampagnen erkennen (auch per KI), Netzbetreiber-Statistik, Belohnung für Beitragende |
