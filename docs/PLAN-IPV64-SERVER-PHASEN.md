# Serverseite ipv64.net: Phasenplan Healthchecks 2.0

Stand 2026-10-10. Gilt zusammen mit `PLAN-IPV64-SYNC.md` (Datenmodell, Protokoll, Entscheidungen). Dieser Plan beschreibt **alles, was auf ipv64-Seite zu tun ist**, in der Reihenfolge, in der es gebaut und abgenommen wird. Jede Phase hat Ziel, Schritte, Dateien, Abnahme, Rückweg und „Was ich von Dennis brauche“.

Rahmen (entschieden):
- **Zwei hub-Server** (Hetzner Cloud, Nürnberg `nbg` und Falkenstein `fsn`) für `ipv64-hub`; Redis auf nbg; der Web-Server behält Portal, PHP, MySQL.
- Beide Server sind gleichwertig (gateway + checker); Online-Checks laufen von **beiden Standorten**, Hybrid-Checks (innen + außen) mit Gesamtzustand nach Regel (Sync-Plan 3.12).
- **IPv4 und IPv6** an jeder Stelle.
- **Keine Migration**: die alte Welt bleibt unverändert und läuft parallel; wer die neue aktiviert (`users.hc2 = 1`), fängt bei null an. Abschaltung alt erst nach Frist (Sync-Plan Abschnitt 7).
- Änderungen am Webcode als Vorher/Nachher-Schnipsel, minimal, Dennis spielt ein. Go-Code im Agent-Repo (`cmd/hub`), Deploy per Binary + systemd.

---

## Überblick: fünf Phasen

Jede Phase endet mit **einer** Abnahme durch Dennis; dazwischen arbeite ich durch. Die Unterabschnitte (S0–S10) sind die Arbeitspakete innerhalb der Phasen.

| Phase | Inhalt | Arbeitspakete | Abnahme (kurz) |
| --- | --- | --- | --- |
| **1 Grundlagen** | hub-Server aufsetzen, `latest.json`, Tabellen `hc2_*`, dbconnect-Block (Hooks, Push-Eingang) | S0, S1, S2 | Server erreichbar v4/v6, Tabellen da, health.php nimmt neue Tokens an |
| **2 hub: Checks und Alarme** | Rolle checker (Online-Checks, Zustände, Push-Watchdog, Aggregation, Agent-Ausfall) und serverseitige Benachrichtigungen (alle Kanaltypen, Verifizierung) | S3, S4 | Online-Checks des Testaccounts laufen im hub, Alarme kommen über jeden Kanaltyp (Schattenmodus) |
| **3 hub: Agents anbinden** | Rolle gateway (WebSocket, Device-Code, Abgleich, Testläufe, Lasttest), Agent-Sync-Client, Betriebsgrundlagen (Metriken, Deploy, Runbook) | S5, S6, S10 (Teil) | Testkisten-Agent verknüpft, alle Offline-Szenarien 3.10 bestanden, Lasttest 10.000 Agents |
| **4 Portal** | Neue Seiten `/healthchecks2`, `/notifications`, `/agents`, `/link`, Umhängen lokal↔online, Konflikte, Statusseite, `health.php`, API v2 | S7 | Testaccount bedient alles ohne alte Seiten, Umhängen in beide Richtungen |
| **5 Beta, Freigabe, Betrieb** | Beta mit Dennis und Freiwilligen, Freigabe für alle, spätere Abschaltung alt, Monitoring/Alarmierung des hub, dritter Standort | S8, S9, S10 (Rest) | Beta ohne offene Fehler, Freigabe |

Reihenfolge 1 → 2 → 3 → 4 → 5. Innerhalb von Phase 2–4 kann Go (hub) parallel zu PHP (Portal) laufen; Phase 4 braucht die Tabellen aus 1 und für Live-Daten den hub aus 2.

---

## Phase 1 – Grundlagen

### S0 – hub-Server aufsetzen

**Ziel**: Ein Server, auf dem `ipv64-hub` sicher läuft, von Agents über `agents.ipv64.net` per v4 und v6 erreichbar, mit Zugriff auf MySQL des Web-Servers und lokalem Redis.

**Schritte**
1. Zwei Server: Hetzner Cloud `nbg1` und `fsn1`, Debian 12, je 2–4 vCPU, 4–8 GB RAM, 40 GB SSD (hub hält keine Messdaten). Öffentliche IPv4 **und** IPv6 (Hetzner gibt /64). Hetzner **Cloud Network** (privates Netz, Netzzone eu-central umfasst nbg1 und fsn1) für Redis-Verkehr fsn → nbg. Zeit per NTP, Zeitzone UTC. Alle folgenden Schritte auf beiden Servern, Unterschiede: `location` in `config.yaml`, Redis nur auf nbg.
1a. Namen: `hc-srv01.ipv64.net` (fsn) und `hc-srv02.ipv64.net` (nbg) existieren (A-Records; **AAAA fehlen noch** → Dennis). Zertifikate per HTTP-01 (certbot --nginx). Kein gemeinsamer Name, da kein DNS-01 möglich; der Agent bekommt die Endpunktliste.
2. Zugang: SSH nur mit Key, Benutzer `deploy` mit sudo, Root-Login aus. Für mich derselbe Weg wie bei der Testkiste (eigener Key, SSH-Config-Host `hub`).
3. DNS: `agents.ipv64.net` A + AAAA auf den hub-Server (über das Portal/PowerDNS wie andere Records). TTL 300.
4. Pakete: `nginx`, `certbot` (`python3-certbot-nginx`), `redis-server`, `nftables`, `mariadb-client` (nur zum Testen), kein Go (Binary kommt fertig gebaut).
5. Benutzer `ipv64-hub` (System, kein Login), Verzeichnisse `/opt/ipv64-hub/` (Binary, `hub`, `hub.prev` für Rollback), `/etc/ipv64-hub/config.yaml` (root:ipv64-hub 640), `/var/lib/ipv64-hub/` (Schlüsseldatei `secret.key`, Zustand), `/var/log/ipv64-hub/` (journald reicht, Datei optional).
6. systemd `ipv64-hub.service`: `User=ipv64-hub`, `Restart=always`, `RestartSec=2`, `LimitNOFILE=200000` (viele WebSockets), `AmbientCapabilities=CAP_NET_RAW` (ICMP) oder `sysctl net.ipv4.ping_group_range` mit der GID des Dienstes, `ProtectSystem=strict`, `ReadWritePaths=/var/lib/ipv64-hub`, `NoNewPrivileges=yes`.
7. nginx: Server-Block `agents.ipv64.net` (`listen 443 ssl http2; listen [::]:443 ssl http2;`), Let's Encrypt, `location /v1/ws { proxy_pass http://127.0.0.1:9000; proxy_http_version 1.1; proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection "upgrade"; proxy_read_timeout 120s; }`, `location /v1/ { proxy_pass http://127.0.0.1:9000; }`, `client_max_body_size 8m`, `X-Forwarded-For`/`X-Real-IP` setzen (hub wertet sie nur von 127.0.0.1/::1 aus). HTTP → HTTPS. Keine anderen Pfade.
8. Redis: `bind 127.0.0.1 ::1` plus die private/öffentliche Adresse für den Web-Server, `requirepass`, `protected-mode yes`, `maxmemory 256mb`, `maxmemory-policy allkeys-lru` (nur Signale/TTL-Keys), Persistenz aus (`save ""`, `appendonly no`) – alles, was in Redis liegt, ist rekonstruierbar. Port 6379 in nftables nur für die Web-Server-IP(s) v4/v6 offen.
9. Firewall (nftables): eingehend 22 (nur Admin-IPs oder Fail2ban), 80/443 (alle), 6379 (nur Web-Server), alles andere zu; ausgehend frei (Checks müssen überall hin). ICMP/ICMPv6 erlaubt.
10. MySQL: Hauptserver 10.100.0.110 ist aus dem privaten Netz beider hub-Server erreichbar (geprüft); eigene Datenbank für hc2 mit Benutzer `ipv64_hc` (von Dennis angelegt), Verbindung ohne TLS im privaten Netz (`--skip-ssl` / DSN `tls=false`).
11. Deploy-Skript `deploy/hub-deploy.sh` (im Agent-Repo): baut `cmd/hub` lokal (`CGO_ENABLED=0 GOOS=linux GOARCH=amd64`), kopiert nach `/opt/ipv64-hub/hub.new`, `mv hub hub.prev && mv hub.new hub`, `systemctl restart`, prüft `/v1/health`. Rollback = `hub.prev` zurückschieben.
12. Backups: nichts Fachliches auf dem hub-Server (alles in MySQL). Sichern: `/etc/ipv64-hub/`, `/var/lib/ipv64-hub/secret.key`, nginx-Config. Einmalig wegkopieren.

**Dateien**: `deploy/ipv64-hub.service`, `deploy/nginx-agents.conf`, `deploy/redis.conf.diff`, `deploy/nftables.conf`, `deploy/hub-deploy.sh`, `deploy/config.example.yaml` (alle im Agent-Repo unter `deploy/`).

**Abnahme**: `curl -4 https://agents.ipv64.net/v1/health` und `curl -6 ...` liefern `{status:"ok"}` (mit einem Platzhalter-hub aus S3), Zertifikat gültig, Redis von außer nur vom Web-Server erreichbar, `systemctl status` sauber nach Reboot.

**Rückweg**: Server abschalten; nichts hängt bis S2 davon ab.

**Von Dennis**: IP-Adressen (v4/v6) und Zugang zum neuen Server; ob Web- und hub-Server ein privates Netz teilen (dann MySQL/Redis darüber); Admin-IPs für SSH.

---

### S1 – `latest.json` und Versionsprüfung

**Ziel**: Der Agent kann prüfen, ob es eine neue Version gibt (Opt-in im Agent ist schon fertig).

**Schritte**
1. Statische Datei `agent/latest.json` im Webroot: `{"version":"0.6.0","url":"https://github.com/ipv64net/agent/releases","image":"ghcr.io/ipv64net/agent:0.6.0","published":"2026-10-20","notes":"..."}`.
2. Pflege: bei jedem Agent-Release Datei anpassen (Schritt im Release-Prozess des Agent-Repos, Makefile-Target `release-notes`). Später optional: GitHub-Action, die die Datei per API v2 setzt.
3. `Cache-Control: max-age=3600`, `Content-Type: application/json`, CORS nicht nötig.

**Abnahme**: Agent (Einstellungen → Updates) zeigt die Version. **Rückweg**: Datei löschen → Agent meldet „Prüfung fehlgeschlagen“, sonst nichts.

---

### S2 – Datenbank, MySQL-Benutzer, Migration, Portal-Hooks

**Ziel**: Alle `hc2_*`-Tabellen vorhanden, ein Testaccount migriert, das Portal schreibt bei jeder Änderung Config-Log und Redis-Signal, ohne dass die alten Seiten etwas merken.

**Schritte**
1. DDL als `deploy/sql/hc2_schema.sql` (neue, eigene Datenbank) und `deploy/sql/ipv64_main.sql` (Hauptdatenbank: Flags, `hc_locations`, Sicht, Leserechte) im Agent-Repo – idempotent, auf der Testkiste in MariaDB 10.5 geprüft; Dennis spielt ein, kein MySQL-Zugriff für mich. Portal-Benutzer braucht Rechte auf die neue Datenbank; PHP spricht die Tabellen als `<db>`.`hc2_*` an. Partitionierung `hc2_measurements` tagesweise, 8 Partitionen plus `pMAX`; Partitions-Rotation macht der hub (S3) täglich (`ALTER TABLE ... DROP PARTITION`, `ADD PARTITION`).
2. `ALTER TABLE users ADD hc2 TINYINT NOT NULL DEFAULT 0` (und `hc2_shadow TINYINT` für S8).
3. MySQL-Benutzer `hc2'@'<hub-ip>'` (v4 und v6 je ein Eintrag): `SELECT, INSERT, UPDATE, DELETE` auf `hc2_*`, `SELECT` auf `users` (nur Spalten `id, email, user_class, hc2, hc2_shadow` – per View `hc2_users_v`, damit keine Passwort-Hashes lesbar sind), `SELECT` auf `user_class`, `SELECT` auf `healthchecks` (für den Vergleichsbot in S8), `ALTER` auf `hc2_measurements` (Partitionen). `REQUIRE SSL`.
4. ~~Migrationsskript~~ entfällt (keine Migration).
5. dbconnect-Block `deploy/web/dbconnect_hc2.php`: eigene Verbindung `hc2_pdo()` mit `ipv64_hc`, `hc2_log_change()` (Revision + Config-Log + Redis-Signal), `hc2_signal()` (Redis-PUBLISH über vorhandenes `connectRedis()`, Fehler nur geloggt), `hc2_push()` (Heartbeat neuer Tokens über `health.php`), `hc2_encrypt()/hc2_decrypt()` kompatibel zum Agent.
6. Alte Bots: **unverändert** (keine `hc2 = 0`-Bedingung; alte Welt läuft für alle weiter).
7. `health.php`: eine Zeile nach der Token-Prüfung: `if (hc2_push($key, $_GET + $_POST)) { ... exit; }` – neue Tokens landen in `hc2_measurements` + Redis `hc2:push`, alte laufen wie bisher.

**Dateien**: `deploy/sql/hc2_schema.sql`, `deploy/sql/ipv64_main.sql`, `deploy/web/dbconnect_hc2.php`, `deploy/web/PHASE1-VORHER-NACHHER.md`, `health.php` (eine Zeile).

**Abnahme**: Schema angelegt; `health.php?token=<neuer Token>` schreibt nach `hc2_measurements` und publiziert `hc2:push`; alte Tokens unverändert; Redis-PUBLISH vom Web-Server aus funktioniert (`redis-cli -h 10.10.0.11 MONITOR`).

**Rückweg**: Block entfernen; alte Welt war nie betroffen.

**Von Dennis**: Bestätigung Testaccount; Ort der Redis-Zugangsdaten in der PHP-Konfiguration.

---

## Phase 2 – hub: Checks und Alarme

**Stand 2026-10-10 (spät):** umgesetzt und auf beiden Servern im Betrieb (`cmd/hub`, Version 0.6.x-dev): MySQL-Store mit Messstellen-Zuständen und Gesamtzustand (Regel all/any/majority, degraded, Diagnose), Slots je Standort über `hc2_nodes`, Config-Log-Polling (2 s), Heartbeat-Poll für Push-Checks (5 s, nur erster Standort), stündliche/tägliche Verdichtung, Partitionsrotation, Aufräumen, `/v1/health`, `/metrics`; Benachrichtigungen über den Agent-Dispatcher je Account (`hc2_channels`, `hc2_settings`, `hc2_deliveries`), direkte Sender (Telegram, Discord, ntfy, Gotify, Pushover, Webhook, SMTP) und Brücke `hc2_send.php` für ipv64_mail/ipv64_sms/App, Erinnerungen (`repeat_minutes`). Getestet mit sechs Checks des Testaccounts: beide Standorte messen v4+v6, Störung mit Incident, degraded bei Blockade eines Standorts, Live-Übernahme von Änderungen, Neustart ohne Doppel-Ereignisse. Offen aus Phase 2: Redis-Signal (nur Beschleuniger, kommt mit Phase 3), `hc2_slot_leases` (erst bei mehr als einem Node je Standort nötig), Standort-Ausfallalarm an Dennis (S10).


### S3 – hub Rolle checker

**Ziel**: Online-Checks der `hc2`-Accounts laufen im hub mit derselben Logik wie im Agent; Zustände, Ereignisse, Störungen und Aggregate stehen in `hc2_*`; Push-Checks werden überwacht; Agent-Ausfälle erkannt.

**Schritte (Go, Agent-Repo)**
1. `cmd/hub/main.go`: Konfiguration aus `/etc/ipv64-hub/config.yaml` (`mysql.dsn`, `redis.addr/password`, `listen 127.0.0.1:9000`, `roles: [checker, gateway]`, `node_name`, `location`, `limits.*`, `smtp.*`, `sms.*`, `firebase.*`, `secret_key_file`), Logging wie im Agent (`internal/logging`, JSON für journald), Signal-Handling, `/v1/health` und `/metrics` (Prometheus-Format, einfach selbst geschrieben, keine Abhängigkeit).
2. `internal/hub/mysql`: Store-Adapter für `scheduler.Store` (Interfaces aus `internal/scheduler`): Checks laden (eigene Slots), Zustand schreiben, Messpunkte/Ereignisse/Störungen schreiben, Wartungsfenster, `hc2_config_log` lesen. Verbindungspool (`SetMaxOpenConns 20`), Prepared Statements, alle Zeiten UTC `DATETIME(3)`. Batch-Writer für Messpunkte (500 ms / 500 Zeilen).
3. `internal/hub/cluster`: `hc2_nodes` Heartbeat (10 s), Slot-Zuteilung (deterministisch nach sortierter Node-Liste, 1024 Slots), `hc2_slot_leases` (60 s) als Sicherung. Mit einem Node: alle Slots. Logausgabe bei jeder Umverteilung.
4. `internal/hub/signal`: Redis `PSUBSCRIBE hc2:cfg:*`, `hc2:push`, `hc2:agent:*` mit Reconnect; **immer zusätzlich** Polling `SELECT MAX(id) FROM hc2_config_log` alle 2 s (Redis nur Beschleuniger; Ausfall von Redis = max. 2 s Verzögerung, Log-Warnung).
5. Checker-Lauf: `scheduler.Scheduler` aus dem Agent, Worker-Pool größer (Flag, Standard 200), Checks mit `execution IN ('online','both')`, `paused = 0`, `locations` enthält den eigenen Standort, eigene Slots. Zustand je Messstelle in `hc2_check_states (token, 'loc:<location>')`; nach jeder Änderung Gesamtzustand nach Regel (`internal/hub/verdict`, gleiche Funktion wie im Agent in `internal/scheduler/verdict.go`), Ereignis nur bei Wechsel des Gesamtzustands. Konfigurationsänderung → `Upsert`/`Remove` am Scheduler. IPv4/IPv6 nach `ip_mode`; `FamilyProbe` wie im Agent (der Server hat beides; falls nicht, Alarm in `/metrics`).
6. Private Ziele: Online-Checks auf RFC-1918/ULA/Loopback/Link-Local werden beim Laden übersprungen und mit `reason private_target` als down markiert (das Portal verhindert das Anlegen, S7; das ist die zweite Sicherung).
7. Push-Watchdog: Push-Checks der eigenen Slots; `hc2:push`-Signal oder `last_push_at`-Polling alle 10 s; Logik `period/grace` aus dem Agent.
8. Agent-Ausfall: Slot-0-Node prüft alle 30 s `hc2_agents.online = 1` gegen Redis `hc2:online:<id>`; Ereignis `agent_offline`/`agent_online` (Versand in S4).
9. Aggregation: `hc2_dirty_hours` abarbeiten (alle 5 min), Stunden- und Tageswerte; Partitions-Rotation täglich 00:10 UTC; `hc2_config_log` > 30 Tage, Tombstones > 90 Tage, `hc2_send_orders`/`hc2_commands` > 1 h erledigt löschen; `hc2_link_codes` abgelaufen.
10. Tests: Unit-Tests mit SQLite-Mock für Store-Logik, wo möglich; Integrationstest gegen eine lokale MariaDB in Docker auf der Testkiste (`make hub-itest`), inkl. Slot-Umverteilung mit zwei Prozessen auf einer Maschine.
11. Deploy auf den hub-Server (S0-Skript), Rolle `gateway` noch aus.

**Dateien**: `cmd/hub/`, `internal/hub/{config,mysql,cluster,signal,checker,aggregate,metrics}`, `deploy/config.example.yaml`, `Makefile` (`hub`, `hub-deploy`, `hub-itest`).

**Abnahme**: Online-Checks des Testaccounts laufen auf **beiden** Servern (je Standort eine Messreihe); Gesamtzustand nach Regel `all`/`any`/`majority` mit künstlich blockiertem Ziel an einem Standort (nftables) → `degraded` bzw. `down` wie erwartet; einen Server stoppen → anderer meldet `location_down`, Checks laufen weiter; Zustände entsprechen dem alten System (Vergleich per Hand); Push-Check kippt nach `period+grace` ohne Heartbeat; `kill -9` des hub → nach Neustart übernehmen die Checks ohne Doppel-Ereignisse; Redis stoppen → Checks laufen weiter, Konfigurationsänderung kommt nach ≤ 2 s an.

**Rückweg**: Dienst stoppen, `users.hc2 = 0`.

---

### S4 – Benachrichtigungen serverseitig

**Ziel**: Der hub verschickt Benachrichtigungen für Online-Checks, Agent-Ereignisse und (verknüpfte) Agent-Checks über Server-Kanäle; `ipv64_mail`, `ipv64_sms`, `app` existieren als Kanaltypen; Pushover ist überall gleich.

**Schritte**
1. `internal/notify` (Agent-Repo): Sender `pushover` (API `https://api.pushover.net/1/messages.json`, Felder `user_key`, `app_token` optional eigener, sonst ipv64-App-Token aus Config – im Agent standalone ist das Nutzer-Token Pflicht), Sender `app` (Firebase HTTP v1 mit Service-Account aus der Config; Gerätetoken aus Kanal-Config wie heute `mobil`), Sender `ipv64_mail` (SMTP-Daten aus Config, Absender wie heute `send_mail`, HTML-Vorlage wie heute), Sender `ipv64_sms` (Gateway wie `send_sms`, Tageslimit `user_class.sms_limit` über `hc2_sms_counter`).
2. Kanal-Geheimnisse serverseitig: `hc2_channels.config_enc` mit AES-GCM (`internal/secrets`, Schlüssel `/var/lib/ipv64-hub/secret.key`). PHP muss Kanäle anlegen können → in S7 verschlüsselt PHP mit demselben Schlüssel (`sodium_crypto_aead_aes256gcm_encrypt` oder `openssl_encrypt aes-256-gcm`, Format `enc:v1:` identisch zum Agent). Schlüssel liegt dann auf beiden Servern (Web: außerhalb des Webroots).
3. Dispatcher aus dem Agent (`internal/notify.Dispatcher`) mit Account-Einstellungen (`hc2_settings`: Ruhezeiten, Sammelmeldungen, Wiederholung, Sprache) statt Agent-Einstellungen; Deduplizierung `hc2_deliveries (event_id, channel_id)`; Ratenlimit je Kanal 60/h wie im Agent.
4. Sendeaufträge für Agent-Kanäle: `hc2_send_orders` + Redis `hc2:agent:<id>` (Zustellung über den Socket in S5).
5. Verifizierung Mail/SMS: Code-Erzeugung im Portal (S7), der Versand des Codes läuft über den hub (`hc2_send_orders` Typ `verify`), damit es nur einen Versandweg gibt.
6. Alte Integrationen: Mapping `integrations` → `hc2_channels` im Migrationsskript (S2) prüfen, Testversand je Typ mit den migrierten Kanälen eines Testaccounts.

**Abnahme**: Testnachricht je Typ aus dem hub (CLI `hub notify-test --channel <id>`), Down/Up eines Online-Checks kommt per Telegram, Mail (ipv64_mail), SMS, App, Pushover an; Ruhezeit und Sammelmeldung greifen; keine Doppelsendung nach Neustart.

**Rückweg**: Alarme für `hc2`-Accounts kommen nicht mehr vom alten `healthcheck_alarm.php` – deshalb erst nach S8 freischalten; bis dahin `hc2_shadow` (kein Versand, nur `hc2_deliveries` mit `ok = NULL`).

**Von Dennis**: Zugangsdaten für SMTP, SMS-Gateway, Firebase (nur in `config.yaml` auf dem hub-Server, nie im Chat); Pushover-App-Token von ipv64 (existiert für die alte Integration).

---

## Phase 3 – hub: Agents anbinden

### S5 – hub Rolle gateway

**Ziel**: Agents verbinden sich per WebSocket, erhalten Konfiguration in Echtzeit, liefern Messpunkte/Ereignisse, Device-Code-Verknüpfung funktioniert, Lasttest mit 10.000 simulierten Agents besteht.

**Schritte**
1. `internal/hub/gateway`: HTTP-Server auf `127.0.0.1:9000` (nginx davor), `X-Forwarded-For` nur von Loopback akzeptiert. Endpunkte aus `PLAN-IPV64-SYNC.md` Abschnitt 4 (HTTPS-Tabelle). WebSocket mit `nhooyr.io/websocket` oder `gorilla/websocket` (eine Abhängigkeit, geprüft), Nachrichten JSON, Größenlimit 1 MB, Kompression aus.
2. Auth: Token `ipv64ag_...` → `sha256` → `hc2_agent_tokens`; Cache 60 s im Speicher; Widerruf wirkt beim nächsten Verbindungsaufbau und durch `bye {reason: revoked}` (Redis-Signal `hc2:agent:<id>` Typ `revoke`).
3. Verbindungsverwaltung: Map `agent_id → conn`, `userid → []conn`; `hc2:online:<id>` in Redis bei jedem Pong; `hc2_agents.last_seen/online/version/...` gebündelt alle 60 s; `bye` an alle bei Shutdown (Drain 10 s).
4. Config-Fanout: Redis `hc2:cfg:<userid>` → Log-Zeilen `> last_sent_revision` der Verbindung laden → `config`-Nachricht; bei Verbindungsaufbau `since` prüfen → Delta oder `revision_gap`.
5. Eingang: `measurements` → Batch-Writer (`INSERT IGNORE`), `ack {ack_seq, rejected}`; `events` → `hc2_events` idempotent, `state_local` ableiten, Dispatcher (S4) anstoßen; `propose` → Revision prüfen, speichern, Log, `ack`/`conflict`; `deliveries`; `notify` (ipv64_mail/sms für Agent-Checks); `status`; `order_done`; `command_result`.
6. Device-Code: `link/start` (Code aus Alphabet ohne 0/O/1/I, 10 min, `poll_secret`), `link/poll` (20/min je Code), Einlösen durch das Portal (S7) setzt `userid`; `poll` liefert dann Token (einmal) und `ws_url`. Token-Erzeugung auch im Portal (`/agents` → „Token erzeugen“) für Setups ohne Browser am Agent.
7. Bootstrap/Config/Results über HTTPS (große Payloads, Streaming-JSON), Token-Kollisionen bei Bootstrap (`renamed`).
7a. Testläufe (Umhängen, Sync-Plan 3.11): `hc2_testruns` (id, userid, token, definition, target_execution, agent_id, status, result, created_at); online-Testlauf führt der checker sofort aus (eigener Worker, nicht der Scheduler); lokaler Testlauf geht als `command test_check` an den Agent, Ergebnis per `command_result`. Portal und Agent fragen den Status ab (Polling 2 s, max. 30 s). Erst bei Erfolg schreibt der Server `execution` um (eine Transaktion mit Log-Eintrag).
7b. Konflikte des Agents (`hc_conflicts`) meldet der Agent als `status.conflicts` (Anzahl + Tokens); das Portal zeigt sie beim Agent an und kann sie ebenfalls auflösen (Kommando `resolve_conflict {token, keep: server|local}`).
8. Push-Eingang `GET/POST /v1/push/{token}`: wie `health.php` (Messpunkt + Watchdog-Signal), Limit wie im Agent, Antwort für unbekannte Tokens identisch.
9. Ratenlimits aus Abschnitt 8 des Sync-Plans; Verbindungslimit je Instanz (Flag, Standard 20.000) → `503 Retry-After`.
10. `cmd/hubload`: simuliert N Agents (Verbindung, Pong, Messpunkte alle 30 s, Reconnect-Verhalten) gegen einen hub; Messung CPU/RAM/DB-Last; Ziel 10.000 Agents auf der Testkiste gegen den echten hub-Server (oder lokal gegen eine Test-MariaDB).
11. Deploy, Rolle `gateway` an, nginx-Pfad freischalten.

**Abnahme**: Lokaler Agent (Testkiste) verknüpft sich per Device-Code, Portal-Änderung erscheint im Agent < 1 s, Messpunkte des Agents stehen in `hc2_measurements`; **alle 18 Offline-Szenarien aus Sync-Plan 3.10** werden mit abgeschnittener Verbindung (nftables auf der Testkiste, 10 min und 2 h) durchgespielt und bestanden; Umhängen lokal→online→lokal mit Testlauf; hub-Neustart: Agent verbindet neu, nichts geht verloren; Lasttest 10.000 Agents: CPU < 50 % auf 2 Kernen, RAM < 1 GB, keine Fehler, MySQL-Schreiblast per Batch ≤ 10 Statements/s.

**Rückweg**: Rolle `gateway` aus (nginx-Pfad 503) → Agents arbeiten standalone weiter und melden sich später nach.

---

### S6 – Agent: Sync-Client

Im Agent-Repo (eigener Phasenplan dort, Phase 6): `internal/sync` echter Client (Link, WebSocket, Outbox, Konflikte, Repair, Reconnect-Backoff), UI „ipv64-Verknüpfung“, Ausführungsort-Badge, Kanaltypen `ipv64_mail`/`ipv64_sms`, Pushover als Kanal. Wird gegen S5 entwickelt und getestet. Release mit `latest.json` (S1).

---

## Phase 4 – Portal

### S7 – Portal-Seiten (PHP)

**Ziel**: Nutzer mit `hc2 = 1` sehen die neuen Seiten; alle anderen weiter die alten. Feature-Parität plus neue Typen, Agents, Kanäle.

**Schritte** (Dateien neu, alte unverändert; Menü in `header.php` prüft `hc2`)
1. `hc2_functions.php` (neu, von `header.php` eingebunden wie `bots/cdn_functions.php`): PDO-Helfer für `hc2_*`, `hc2_log_change`/`hc2_signal` (aus S2 hierher), Verschlüsselung `enc:v1:` kompatibel zum Agent, Limitprüfung: Summe der Online-Messstellen (`execution IN ('online','both')` × Anzahl `locations`) gegen `user_class.healthcheck_limit`; Standorte je Check höchstens `user_class.hc_locations` (Standard-Klasse 1, ab Supporter 2); Validierung der Check-Definition (dieselben Regeln wie `checks.Validate` im Agent: Intervalle ≥ 20 s, Zieltypen, private Ziele online verboten). Account-Karte zeigt „Online-Messstellen x von y“.
2. `/healthchecks2/index.php` (Übersicht): Kacheln, Tabelle mit Pillen (`hc2_measurements` letzte 30), Badge Ausführungsort, Filter/Sortierung/Suche, Massenaktionen (pausieren, fortsetzen, löschen, Tags), Account-Karte „Online-Checks x von y“. Pillen-Daten über API v2 (`/hc2/checks`), Seite rendert serverseitig, JS nur für Charts/Tooltips (jQuery nach `footer.php`!).
3. `/healthchecks2/edit.php` (neu/bearbeiten): Formular wie im Agent (Typen, Parameter je Typ, Intervall/Retry, Stabilisierung, IP-Modus, Tags, Beschreibung, Abhängigkeit, kritisch, Kanäle, Wiederholung) plus Karte **Messstellen und Bewertung** wie im Agent: Ausführungsort (Online/Agent/Beides mit Agent-Auswahl), Standorte (Nürnberg/Falkenstein, zweiter nur ab Supporter, sonst ausgegraut mit Hinweis), Regel „gestört, wenn alle / eine / Mehrheit“, Option „auch bei teilweise gestört benachrichtigen“.
3a. **Umhängen** (Sync-Plan 3.11): Schalter im Formular und Massenaktion in der Übersicht; Ablauf: Limit prüfen → privates Ziel abweisen → `hc2_testruns` anlegen → Ergebnis per Polling (2 s, max. 30 s) anzeigen → bei Erfolg `execution` setzen. Detailseite zeigt die Herkunft („gemessen von: Pi im Keller bis 10.10. 14:00, seitdem ipv64“) und beide Mess-Serien.
3b. **Konflikte**: Karte auf `/agents.php` (Detail) mit den Konflikten des Agents (beide Versionen nebeneinander, „Server behalten“ / „Agent-Version übernehmen“ → Kommando an den Agent). Ausstehende Vorschläge eines offline-Agents werden nicht angezeigt (kennt nur der Agent), der Agent-Status zeigt „offline seit …, Outbox: n“.
4. `/healthchecks2/check.php?token=`: Detail (Pillen groß, Verfügbarkeit 24 h/30 d/1 J aus `hc2_hourly/daily`, Latenz-Chart innen/außen, Ereignisse, Störungen, letzte Messung roh, beide Push-URLs, Diagnosehinweis bei Abweichung innen/außen).
5. `/healthchecks2/maintenance.php`, `/healthchecks2/incidents.php` (ersetzt `incidents.php` für `hc2`-Nutzer).
6. `/notifications.php` (ersetzt `integrations.php`): Kanäle anlegen je Typ (Felder wie im Agent), Test (Sendeauftrag an hub, Ergebnis per Polling), Standard, Verifizierung Mail/SMS **nach Login** per Code, Ruhezeiten/Sammelmeldung (`hc2_settings`), Zustellprotokoll.
7. `/agents.php`: Liste (Name, Standort, online/offline seit, Version, letzte Sync, Module, Outbox), Detail (Checks des Agents, Umwandeln, Remote-Checks anlegen), umbenennen, Token widerrufen/erzeugen, entfernen (`keep_checks`). `/link.php`: Code-Eingabe, Standort, Name, Remote-Verwaltung, Limit-Hinweis.
8. Statusseiten: `statuspage.php`/`status/` lesen bei `hc2 = 1` aus `hc2_checks` (Spalte `status_pages.hc2_tokens`), Design unverändert.
9. API v2 (`api_v2.php`): Pfade `/hc2/checks[...]`, `/hc2/maintenance`, `/hc2/channels`, `/hc2/agents`, `/hc2/events`, `/hc2/incidents`, `/hc2/stats` mit denselben Feldnamen wie der Agent; OpenAPI und Doku ergänzen. Alte `/healthchecks`-Pfade liefern bei `hc2 = 1` einen Hinweis (410 mit Link) oder werden gemappt – Entscheidung in S9.
10. `health.php`: Hinweis auf neue URL in `healthcheck_updater_api.php`; Verhalten aus S2.
11. Menü/Weiche: `header.php` zeigt bei `hc2 = 1` „Healthchecks“ → `/healthchecks2/`, „Benachrichtigungen“, „Agents“; sonst alte Einträge. Alte Seiten leiten bei `hc2 = 1` auf die neuen um (eine Zeile oben in `healthcheck.php`, `integrations.php`, `incidents.php`).

**Abnahme**: Testaccount bedient alles ohne alte Seiten; jede Änderung erscheint im verknüpften Agent; Limits greifen; private Ziele werden online abgewiesen; Verifizierung ohne Login unmöglich; Statusseite zeigt neue Zustände.

**Rückweg**: `hc2 = 0` → alte Seiten; neue Dateien stören nicht.

---

## Phase 5 – Schatten, Rollout, Betrieb

### S8 – Schattenbetrieb und Vergleich

**Ziel**: Zwei Wochen Betrieb mit echten Accounts, bei denen alt und neu parallel laufen, ohne doppelte Alarme; Abweichungen werden gefunden und behoben.

**Schritte**
1. Flag `users.hc2_shadow = 1`: alte Bots prüfen weiter und schreiben alte Tabellen, **senden aber keine Alarme** (eine Bedingung in `healthcheck_alarm.php`); hub prüft und sendet (S4 scharf).
2. `bots/hc2_compare.php` (Cron alle 5 min): vergleicht je Check `healthchecks.status` mit `hc2_checks.state` (Mapping), Latenz-Mittel der letzten Stunde, Alarmanzahl; schreibt `hc2_compare_log`; Zusammenfassung täglich per Mail an Dennis.
3. Accounts: Dennis, dann 10–20 Beta-Nutzer (VIP/Supporter, Einladung im Portal), Feedback-Formular.
4. Lasttest-Ergebnis (S5) und Ressourcen des hub-Servers beobachten (S10 Monitoring).
5. Fehlerliste abarbeiten; Plan-Abweichungen in `PLAN-IPV64-SYNC.md` eintragen.

**Abnahme**: 14 Tage ohne ungeklärte Abweichung; keine verpassten/doppelten Alarme bei Beta-Nutzern.

**Rückweg**: `hc2_shadow = 0`, `hc2 = 0`.

---

### S9 – Rollout und Abschaltung

**Schritte**
1. Wellen: Supporter/VIP/Premium → Business/Company (mit Ankündigung) → Standard (Free) in Blöcken à 1.000 Accounts pro Tag (`hc2_migrate.php all --limit 1000 --class 1`), jeweils 48 h beobachten. Ankündigung im Blog/Wiki, Hinweis auf neue Push-URL (alte bleibt).
2. Nach 100 %: alte Bots aus Cron nehmen (Dateien bleiben 90 Tage), alte Seiten leiten dauerhaft um, `integrations.php` entfernt, API v2 `/healthchecks` auf das neue Modell (oder `/hc2` dauerhaft – Entscheidung nach Rückmeldung der API-Nutzer), Influx-Schreiber für Healthchecks aus.
3. Aufräumen: alte Tabellen nach 90 Tagen archivieren (Dump) und droppen; `users.hc2`-Flag bleibt (immer 1), `hc2_shadow` entfernen; Dokumentation (`healthcheck_updater_api.php`, Wiki) final.
4. Pfad-Entscheidung „`/healthchecks2` → `/healthcheck`“: offen (Dennis). Technisch nur Umbenennung + Redirects.

**Abnahme**: Alte Bots aus, kein Nutzer auf alten Seiten, Vergleichsbot zeigt nichts mehr an (abgeschaltet).

---

### S10 – Betrieb des hub

**Ziel**: Beide hub-Server sind überwacht, alarmieren selbst, lassen sich sicher einzeln aktualisieren (Rolling: erst fsn, dann nbg), und der Weg zu einem dritten Standort ist beschrieben.

**Schritte**
1. `/metrics` (Prometheus): Verbindungen, Nachrichten/s, Messpunkte/s, DB-Latenz, Batch-Größen, Checks je Zustand, Slots je Node, Redis-Status, Fehlerzähler. Dazu ein kleiner Prometheus + Grafana auf dem hub-Server oder Anbindung an das, was Dennis schon hat (Influx? dann zusätzlich Influx-Line-Protocol-Export als Option).
2. Selbstüberwachung: hub meldet eigene Probleme (DB nicht erreichbar, Redis weg, Slot-Verlust, Zertifikat < 14 Tage, Disk) über `ipv64_mail`/SMS an Dennis (Kanal `hc2_channels` mit `userid = 0`), Entprellung 5 min. Zusätzlich ein **externer** Healthcheck im alten System oder bei einem Drittanbieter auf `https://agents.ipv64.net/v1/health` (v4 und v6).
3. Logs: journald mit `SystemMaxUse=1G`; Log-Level zur Laufzeit per `SIGHUP`/Admin-Endpunkt (`/v1/admin/loglevel`, nur localhost).
4. Updates: `hub-deploy.sh` mit Drain (`bye` an Agents, 10 s), Rollback mit `hub.prev`; Datenbank-Migrationen des hub versioniert (`hc2_schema_version`), vorwärts-kompatibel (Spalten hinzufügen, nie umbenennen), Migration vor dem Binary-Wechsel.
5. Backups: MySQL ist Sache des Web-Servers (bestehender Prozess; `hc2_measurements` darf aus dem Backup ausgenommen werden – 7 Tage Rohdaten sind verzichtbar, Aggregate nicht). hub-Server: `/etc/ipv64-hub`, `secret.key`, nginx.
6. Runbook (`docs/RUNBOOK-HUB.md`): Start/Stop, Logs lesen, häufige Fehler (DB-Verbindung, Zertifikat, Redis), Agent-Token widerrufen, Account auf alt zurückstellen, Slots prüfen, Lasttest wiederholen.
7. **Dritter Standort** (wenn gewünscht): Server wie S0 (ohne Redis), `config.yaml` mit `redis.addr` von nbg über das private Netz, `location` neu (z. B. `hel`), Zeile in `hc2_locations`, DNS ergänzen; Portal zeigt den Standort automatisch zur Auswahl. Redis-Ausfallsicherheit: Ausfall von nbg = Polling-Fallback auf fsn (2 s), kein Stillstand; bei Bedarf später Redis auf beiden mit Replikation/Sentinel.
7a. **Standort-Ausfall**: fällt nbg oder fsn komplett aus, verbinden sich die Agents mit dem anderen (Endpunktliste aus `hello`), Online-Checks laufen mit einem Standort weiter, Gesamtzustände rechnen ohne die fehlende Messstelle, Alarm `location_down` an Dennis. Nach Rückkehr holt der Standort seine Slots wieder, Lücke in der Messreihe bleibt sichtbar.
8. IPv6-Prüfung im Betrieb: Checker misst beide Familien, `/metrics` zählt `family_unreachable`; nginx/Redis/MySQL-Verbindungen auf v6 getestet (`curl -6`, `mysql --host=<v6>`).

---

## Sicherheit (serverseitig, zusammengefasst)

- Agent-Token nur gehasht; `agent_id` kommt aus dem Token, nie aus dem Body; Fremdzugriff → 404.
- MySQL-Benutzer `hc2` minimal, nur von hub-IPs, TLS; keine Passwort-Hashes lesbar (View).
- Geheimnisse nur in `/etc/ipv64-hub/config.yaml` und dem Schlüssel in `/var/lib/ipv64-hub` – nicht im Code, nicht im Repo (`deploy/config.example.yaml` ohne Werte).
- Redis nur mit Passwort, nur vom Web-Server erreichbar, keine persistenten Daten.
- nginx: nur `/v1/*`, Body-Limit, Ratenlimit zusätzlich (`limit_req` 60 r/min je IP für `/v1/agents/link/*`).
- Verifizierung Mail/SMS nur eingeloggt (Lücke `activate_integration` entfällt mit S7/S9).
- Private Ziele für Online-Checks doppelt verhindert (Portal und hub).

## Risiken und Gegenmittel

| Risiko | Gegenmittel |
| --- | --- |
| MySQL-Last durch Messpunkte | Batch-Inserts, Partitionen, Index nur `(token, agent_id, time, seq)` + `(time)`; Rohdaten 7 Tage; Charts aus Aggregaten |
| Netz zwischen hub und MySQL fällt aus | Checker puffert Messpunkte 10 min im Speicher, Gateway antwortet `ack` erst nach DB-Schreiben (Agent hält Outbox), Alarm an Dennis |
| Redis fällt aus | Polling-Fallback 2 s; Online-Status über `last_seen` mit 3-min-Karenz |
| Reconnect-Sturm nach hub-Neustart | Agent-Backoff mit Jitter, `bye` mit Drain, Verbindungslimit mit `Retry-After` |
| Doppelte Alarme alt/neu | Flags `hc2`/`hc2_shadow`, eine Bedingung je Bot, Vergleichsbot |
| Abweichende Check-Logik alt/neu | Gleicher Go-Code wie im Agent; Schattenbetrieb 14 Tage |
| Schlüsselverlust (`secret.key`) | Backup des Schlüssels getrennt; Kanäle sind neu anlegbar, Messdaten nicht betroffen |

## Was ich von Dennis insgesamt brauche

1. hub-Server: IPv4/IPv6, SSH-Zugang (Key), ob privates Netz zum Web-Server besteht.
2. Freigabe, auf dem Web-Server den MySQL-Benutzer `hc2` und die Firewall-Regel anzulegen (Schnipsel liefere ich).
3. Testaccount für Migration und Schattenbetrieb; später Beta-Nutzer.
4. Zugangsdaten SMTP/SMS/Firebase/Pushover nur direkt in `config.yaml` auf dem hub-Server (ich sage, welche Felder).
5. Entscheidungen, die noch offen sind: Pfad nach der Umstellung; Umgang mit den alten API-v2-Pfaden `/healthchecks` in S9; Monitoring-Stack (Prometheus/Grafana neu oder vorhandenes Influx).
