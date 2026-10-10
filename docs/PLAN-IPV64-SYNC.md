# Healthchecks 2.0 bei ipv64.net: Server, Sync, Webseite, Integrationen

Detailplan, Stand 2026-10-10. Ziel: Der Agent (standalone fertig) wird mit ipv64.net verknüpft, die Healthcheck-Seiten des Portals werden neu gebaut, die Integrationen werden auf denselben Unterbau wie im Agent gestellt. Dieser Plan ist die Vorlage für die Umsetzung; Abweichungen werden hier eingetragen.

Ergänzt das Konzept („ipv64 Agent – Konzept & Funktionsumfang“) und ersetzt die Kurzfassung in `SYNC.md`.

---

## 0. Leitentscheidungen

| Nr. | Entscheidung | Begründung |
| --- | --- | --- |
| L1 | **Ein Check-Bot in Go** für Agent und Server (`internal/checks`, `internal/scheduler`, `internal/notify` aus dem Agent-Repo). Die PHP-Bots `healthcheck_*_live.php`, `healthcheck_alarm.php` werden abgelöst. | Gleiche Logik, gleiche Fehlergründe, gleiche Zustandsmaschine überall. |
| L2 | **Neuer Dienst `ipv64-hub`** (Rolle `checker`) auf eigenen Servern neben dem Altsystem. Neue Tabellen mit Präfix `hc2_` in eigener Datenbank. **Keine Migration**: Wer die neue Welt aktiviert (`users.hc2 = 1`), fängt bei null an; die alte Welt bleibt unverändert und läuft parallel, bis sie abgeschaltet wird. | Entscheidung Dennis 2026-10-10: einfacher, kein Mapping-Risiko, kein Doppelbetrieb-Abgleich. |
| L3 | **Server ist führend** für Konfiguration (Checks, Kanäle, Wartungsfenster), sobald ein Agent verknüpft ist. **Agent ist führend** für seine Messergebnisse (append-only). | Konzept, Abschnitt Synchronisation. |
| L4 | **Eigener Go-Dienst `ipv64-hub` bei ipv64 für die gesamte Agent-Kommunikation** (Host `agents.ipv64.net`): eine WebSocket-Dauerverbindung je Agent plus HTTPS-Endpunkte für große Abgleiche. `api_v2.php` bleibt für Nutzer, Portal und Fremdsoftware; Agents reden nicht mit PHP. | Entscheidung Dennis 2026-10-10: von Anfang an für viele tausend Agents und mehrere Server-Instanzen auslegen. PHP kann weder Dauerverbindungen halten noch so skalieren; Long-Poll würde je Agent einen PHP-Prozess belegen. |
| L9 | **Zwei hub-Server von Anfang an, Nürnberg und Falkenstein** (Hetzner Cloud), getrennt vom Web-Server. Auf beiden läuft dasselbe Binary mit beiden Rollen (`gateway` + `checker`), Zustand nur in MySQL und Redis. Jeder Server ist ein **Standort** (`location`: `nbg`, `fsn`); Online-Checks werden standardmäßig **von beiden Standorten** gemessen. Fällt ein Server aus, übernimmt der andere die Agents sofort und die Online-Messung läuft mit einem Standort weiter. Ein dritter Standort ist nur ein weiterer Server mit eigenem `location`. | Entscheidung Dennis 2026-10-10: „lieber größer denken als klein“, zwei Standorte, Trennung vom Web-Server. |
| L11 | **Hybrid ist eingebaut: mehrere Messstellen je Check, ein Gesamtzustand.** Ein Check kann vom Agent (innen), von Nürnberg und von Falkenstein (außen) gemessen werden. Jede Messstelle hat ihren eigenen Zustand; der Gesamtzustand folgt einer Regel je Check, Standard **„down nur, wenn alle Messstellen down sind“**; sagt nur ein Teil down, ist der Check **„teilweise gestört“** (`degraded`, gelb) mit Diagnose, standardmäßig ohne Alarm. | Entscheidung Dennis 2026-10-10: „nur wenn beide sagen, es ist down, dann ist irgendwas down“. Vermeidet Fehlalarme durch einen einzelnen Standort oder einen Heim-Internetausfall, ohne die Information zu verlieren. |
| L10 | **IPv4 und IPv6 überall** (Namensgeber von ipv64): hub lauscht Dual-Stack, `agents.ipv64.net` hat A- und AAAA-Record, Online-Checks laufen je nach `ip_mode` über v4, v6 oder beides, MySQL/Redis-Verbindungen und nginx sind Dual-Stack; der Agent ist es bereits (Listener, Checks, ICMPv6, TLS-SANs, Ratelimits je /64). | Entscheidung Dennis 2026-10-10. |
| L5 | **Rohe Messpunkte der Online-Checks nur 7 Tage in MySQL** (partitioniert), Stunden- und Tageswerte in MySQL. Influx wird nicht mehr für Healthchecks gebraucht. | Ein Datenmodell für Agent und Server, gleiche Charts. Influx bleibt für CDN/Statistiken. |
| L6 | **Integrationen werden zu Kanälen** (`hc2_channels`), gleiche Typen wie im Agent (`smtp`, `telegram`, `discord`, `ntfy`, `gotify`, `webhook`, `pushover`) plus serverseitig `app`, `ipv64_mail`, `ipv64_sms`. Pushover auch im Agent, weil der Container ohne ipv64-Account vollwertig bleiben soll; `ipv64_mail`/`ipv64_sms` kann ein verknüpfter Agent über den hub nutzen. Alte `integrations` werden einmalig migriert, die Verifizierung per Mail/SMS bleibt. | Gleicher Versandcode (Go) auf Server und Agent; die bekannten Lücken im alten PHP (activate_integration ohne Login) verschwinden. |
| L7 | **Push-URLs**: `https://ipv64.net/health.php?token=...` funktioniert für alte und neue Tokens (health.php prüft zuerst `hc2_checks`), zusätzlich `https://hc-srv0X.ipv64.net/v1/push/{token}` direkt am hub. | Tausende Geräte rufen die alte URL. |
| L8 | Lokale Messungen im Container haben **kein Limit**. Gegen `user_class.healthcheck_limit` zählt die Zahl der **Online-Messstellen**: jeder Check mit `execution online/both` zählt einmal **je gewähltem Standort** (ein Check an nbg + fsn = 2). Kein Limit für die Anzahl Agents je Account. **Mehrere Standorte je Check** (nbg + fsn) gibt es erst ab Account-Klasse **Supporter** (neue Spalte `user_class.hc_locations`: Standard 1, alle anderen 2); darunter wählt der Server einen Standort (abwechselnd nach `crc32(token)`, damit die Last verteilt ist, im Portal änderbar). | Entscheidung Dennis, 2026-10-10. |

---

## 1. Zielarchitektur

```
Browser ──► Portal (PHP, /healthchecks2 ...) ──► MySQL hc2_*  +  Redis (Signale) ◄──┐
                                                        ▲                             │
Agent ══WSS══► agents.ipv64.net ──► ipv64-hub Instanz A ────────────────────────────┤  Rollen gateway + checker
Agent ══WSS══► (nginx/LB)      ──► ipv64-hub Instanz B ────────────────────────────┘
Geräte ──► health.php?token= (PHP)  oder  agents.ipv64.net/v1/push/{token} (hub) ──► hc2_measurements + Redis "hc2:push"
```

**ipv64-hub** (Go, aus dem Agent-Repo gebaut, `cmd/hub`; nutzt `internal/checks`, `internal/scheduler`, `internal/notify`): ein Binary, zwei Rollen, standardmäßig beide auf jeder Instanz aktiv, einzeln per Flag abschaltbar.

Rolle **gateway** (Agent-Kommunikation):
- nimmt WebSocket-Verbindungen der Agents an (`/v1/ws`), prüft den Agent-Token, hält je Verbindung zwei Goroutines (ca. 20–50 KB Speicher; 10.000 Verbindungen je Instanz sind unkritisch, Limit per Flag),
- schreibt Messpunkte und Ereignisse **gebündelt** nach MySQL (Sammler je Instanz, Batch-Insert alle 500 ms oder 500 Zeilen) und bestätigt dem Agent per `ack`,
- verteilt Konfigurationsänderungen: Portal und API schreiben `hc2_config_log` und publizieren `hc2:cfg:<userid>` in Redis; jede Instanz hat `PSUBSCRIBE hc2:cfg:*` und reicht nur an die eigenen verbundenen Agents dieses Accounts weiter (Filter im Speicher, ein Lookup `userid → Verbindungen`),
- Sendeaufträge und Kommandos an einen bestimmten Agent gehen über Redis `hc2:agent:<agent_id>`; ist der Agent nirgends verbunden, bleibt der Auftrag in `hc2_send_orders` und wird beim nächsten Verbinden zugestellt,
- pflegt den Online-Status: Redis `SET hc2:online:<agent_id> <instanz> EX 90` bei jedem Ping; `hc2_agents.last_seen/online` gebündelt alle 60 s,
- HTTPS-Endpunkte für große Abgleiche (`/v1/agents/me/bootstrap`, `/config`, `/results`), Device-Code, Push-Eingang.

Rolle **checker** (Online-Checks, ersetzt `healthcheck_*_live.php`, `healthcheck_alarm.php`):
- **Standorte**: jede Instanz hat ein `location` (`nbg`, `fsn`). Ein Online-Check läuft an jedem Standort aus `hc2_checks.locations` (Standard: alle) als eigene Messreihe mit eigenem Zustand (3.12).
- Verteilung über **Slots je Standort**: `hc2_checks.slot = crc32(token) % 1024`. Instanzen registrieren sich in `hc2_nodes` (mit `location`, Heartbeat alle 10 s). Jede Instanz berechnet aus der sortierten Liste lebender Nodes **ihres Standorts** deterministisch dieselbe Zuteilung (Node i bekommt Slots mit `slot % n == i`); mit einem Node je Standort hat er alle 1024 Slots. `hc2_slot_leases (location, slot)` (60 s) sichert gegen Doppelausführung bei Netzpartition. Fällt der einzige Node eines Standorts aus, fehlt diese Messreihe (Gesamtzustand rechnet mit den verbleibenden, 3.12) und Dennis bekommt einen Alarm `location_down`,
- lädt die Checks seiner Slots mit `execution IN ('online','both')`, `paused = 0`, plant sie wie der Agent (Worker-Pool, Jitter, Retry, Stabilisierung, Flattern, Abhängigkeiten, Wartungsfenster), schreibt Messpunkte, Zustände, Ereignisse, Störungen in `hc2_*`,
- bewertet Push-Checks seiner Slots per Watchdog; Push-Eingang kommt aus `health.php` (Redis `hc2:push`) oder aus dem hub selbst,
- verschickt Benachrichtigungen (Server-Kanäle, `ipv64_mail`, `ipv64_sms`, `app`) und erzeugt Sendeaufträge für Agent-Kanäle,
- Agent-Ausfallerkennung: die Instanz, die Slot 0 hält, prüft alle 30 s `hc2_agents.online = 1` gegen die Redis-Keys,
- verdichtet stündlich/täglich (`hc2_dirty_hours`), räumt Partitionen, Log und Tombstones auf,
- bekommt Konfigurationsänderungen über dieselbe Redis-Subscription wie das gateway (nur eigene Slots).

**Kapazität (Planungsgröße)**: 10.000 Agents × 20 Checks à 60 s ≈ 3.300 Messpunkte/s → Batch-Inserts, tagesweise Partitionen, ca. 300 MB/Tag roh (7 Tage ≈ 2 GB). WebSocket-Verkehr je Agent ≈ 1 KB/30 s. Redis trägt nur Signale, keine Daten. 100.000 Agents = zehn Instanzen gleicher Bauart, nichts umbauen.

**Deployment (Stand jetzt)**: ein **eigener hub-Server** (neu, getrennt vom Web-Server; Dennis stellt IP-Adresse und Zugang). Darauf: `ipv64-hub` als systemd-Dienst (Port 9000 intern, nur localhost), nginx davor als TLS-Terminierung und WebSocket-Proxy (`proxy_http_version 1.1`, `Upgrade`-Header durchreichen, `proxy_read_timeout 120s`, Let's Encrypt für `agents.ipv64.net`), Redis lokal (nur `127.0.0.1`/`::1`, Passwort). MySQL bleibt auf dem Web-Server; der hub verbindet sich über das Netz mit einem eigenen MySQL-Benutzer `hc2` (Rechte nur auf `hc2_*` plus `SELECT` auf `users`, `user_class`; Zugriff nur von der hub-IP, TLS oder privates Netz). Das Portal (PHP) erreicht Redis auf dem hub-Server über den schon vorhandenen Client (`connectRedis()` in `dbconnect.php`), Firewall nur für die Web-Server-IP offen. Geheimnisse des hub (MySQL, Redis, SMTP, SMS-Gateway, Firebase, Kanal-Schlüssel) liegen in `/etc/ipv64-hub/config.yaml` (root:ipv64-hub 640), nicht im Code.

**Zwei Server (Stand 2026-10-10)**: `hc-srv01.ipv64.net` = **Falkenstein** (`fsn`, 188.245.6.138 / 2a01:4f8:c014:46b::1, privat 10.10.0.10) und `hc-srv02.ipv64.net` = **Nürnberg** (`nbg`, 178.105.50.207 / 2a01:4f8:1c1f:b393::1, privat 10.10.0.11), Debian 13, gleicher Aufbau (`deploy/server/setup-hub.sh`). **Kein gemeinsamer Name** (`agents.ipv64.net` entfällt, weil kein PowerDNS-API-Key für DNS-01): Zertifikate per HTTP-01 auf die beiden Hostnamen; der Agent kennt die Endpunktliste aus `latest.json` (`endpoints`) und aus dem `hello`, wählt einen zufällig und wechselt bei Fehlschlag. **Redis** auf nbg (10.10.0.11:6379, Passwort, nur aus 10.10.0.0/24), fsn erreicht ihn über das private Netz – Redis ist nur Beschleuniger, fällt nbg aus, pollt fsn MySQL (2 s). **MySQL**: die hc2-Tabellen liegen in einer **eigenen Datenbank** auf dem Hauptserver (10.100.0.110, privates Netz, Benutzer `ipv64_hc`); die Hauptdatenbank `ipv64` wird nur minimal ergänzt (`ipv64_main.sql`: Flags, `hc_locations`, Sicht `hc2_users_v`). Ein dritter Standort = dritter Server, `location` setzen; nichts am Code ändern.

**Portal (PHP)**: neue Seiten lesen und schreiben `hc2_*` direkt über PDO (wie der Rest des Portals), jede Änderung erhöht `revision`, schreibt eine Zeile in `hc2_config_log` und publiziert `hc2:cfg:<userid>` (Redis-Client ist in `dbconnect.php` vorhanden: `connectRedis()`). Fällt Redis oder die Verbindung aus, bleibt die Änderung trotzdem nicht liegen: der hub liest `hc2_config_log` zusätzlich alle 2 s per `SELECT MAX(id)` (Fallback-Polling); Redis macht es nur schneller. Charts holen Aggregate über die API v2.

**API v2 (PHP)**: nur noch Nutzer, Portal-JS, Fremdsoftware. Keine Agent-Endpunkte; die liegen im hub.

---

## 2. Datenmodell auf dem Server (DDL)

Alle Zeiten `DATETIME(3)` in UTC (abweichend vom Rest des Portals, das Europe/Berlin speichert; die neuen Tabellen sind UTC, die API gibt ISO 8601 mit Zeitzone aus).

```sql
-- Accounts-Flag fuer die Umstellung
ALTER TABLE users ADD hc2 TINYINT NOT NULL DEFAULT 0;
-- Online-Standorte je Klasse: Standard 1, ab Supporter (und VIP/Premium/Business/Company) 2
ALTER TABLE user_class ADD hc_locations TINYINT NOT NULL DEFAULT 1;
UPDATE user_class SET hc_locations = 2 WHERE id IN (2,3,4,5,6);

CREATE TABLE hc2_agents (
  id INT AUTO_INCREMENT PRIMARY KEY,
  userid INT NOT NULL,
  agent_id VARCHAR(32) NOT NULL UNIQUE,      -- vom Agent erzeugt (settings agent.id)
  name VARCHAR(100) NOT NULL,
  location VARCHAR(100) NOT NULL DEFAULT '',
  version VARCHAR(32) NOT NULL DEFAULT '',
  timezone VARCHAR(64) NOT NULL DEFAULT 'UTC',
  modules VARCHAR(255) NOT NULL DEFAULT '',  -- aktive Module, kommagetrennt
  remote_mgmt ENUM('off','read','full') NOT NULL DEFAULT 'read',
  last_seen DATETIME(3) NULL, last_sync DATETIME(3) NULL,
  last_ack_seq BIGINT NOT NULL DEFAULT 0,    -- hoechste bestaetigte Messpunkt-Nummer
  outbox_size INT NOT NULL DEFAULT 0,        -- vom Agent gemeldet
  online TINYINT NOT NULL DEFAULT 0,         -- von hub gepflegt (Heartbeat)
  created_at DATETIME(3) NOT NULL, revoked_at DATETIME(3) NULL,
  INDEX (userid)
);
CREATE TABLE hc2_agent_tokens (
  id INT AUTO_INCREMENT PRIMARY KEY,
  agent_id VARCHAR(32) NOT NULL,
  token_hash CHAR(64) NOT NULL UNIQUE,       -- sha256(token), Token selbst nur einmal sichtbar
  created_at DATETIME(3) NOT NULL, last_used DATETIME(3) NULL, revoked_at DATETIME(3) NULL,
  INDEX (agent_id)
);
CREATE TABLE hc2_link_codes (
  code CHAR(8) PRIMARY KEY,                  -- A-Z2-9 ohne 0/O/1/I, z. B. "K7PQ-4MZB" wird ohne Bindestrich gespeichert
  agent_id VARCHAR(32) NOT NULL, agent_name VARCHAR(100) NOT NULL, agent_version VARCHAR(32) NOT NULL,
  poll_secret CHAR(32) NOT NULL,             -- nur der Agent kennt es, verhindert Fremd-Polling
  created_at DATETIME(3) NOT NULL, expires_at DATETIME(3) NOT NULL,
  userid INT NULL, location VARCHAR(100) NULL, consumed_at DATETIME(3) NULL
);

CREATE TABLE hc2_checks (
  token CHAR(32) PRIMARY KEY,                -- wie healthchecks.healthtoken
  userid INT NOT NULL,
  agent_id VARCHAR(32) NULL,                 -- Besitzer-Agent bei execution local/both
  execution ENUM('local','online','both') NOT NULL DEFAULT 'online',
  type ENUM('http','keyword','icmp','tcp','port','cert','push') NOT NULL,
  name VARCHAR(200) NOT NULL, target VARCHAR(500) NOT NULL DEFAULT '', params JSON NOT NULL,
  interval_sec INT NOT NULL DEFAULT 60, retry_interval_sec INT NOT NULL DEFAULT 20, retries TINYINT NOT NULL DEFAULT 1,
  connect_timeout_ms INT NOT NULL DEFAULT 5000, total_timeout_ms INT NOT NULL DEFAULT 10000,
  invert TINYINT NOT NULL DEFAULT 0, stabilize TINYINT NOT NULL DEFAULT 3, ip_mode ENUM('auto','ipv4','ipv6','both') NOT NULL DEFAULT 'auto',
  tags VARCHAR(255) NOT NULL DEFAULT '', description TEXT, paused TINYINT NOT NULL DEFAULT 0,
  parent_token CHAR(32) NULL, critical TINYINT NOT NULL DEFAULT 0,
  notify_down TINYINT NOT NULL DEFAULT 1, notify_up TINYINT NOT NULL DEFAULT 1, channels VARCHAR(255) NOT NULL DEFAULT '', repeat_minutes INT NOT NULL DEFAULT 0,
  revision BIGINT NOT NULL DEFAULT 1, created_at DATETIME(3) NOT NULL, updated_at DATETIME(3) NOT NULL, updated_by VARCHAR(100) NOT NULL DEFAULT '',
  deleted_at DATETIME(3) NULL,               -- Tombstone: bleibt 90 Tage, damit Agents das Loeschen sehen
  -- Messstellen und Bewertung (3.12)
  locations SET('nbg','fsn') NOT NULL DEFAULT 'nbg,fsn',   -- Standorte fuer execution online/both; Server kuerzt auf user_class.hc_locations
  policy ENUM('all','any','majority') NOT NULL DEFAULT 'all', -- down, wenn: alle / eine / Mehrheit der Messstellen down
  notify_degraded TINYINT NOT NULL DEFAULT 0,               -- Alarm auch bei "teilweise gestoert"
  -- Gesamtzustand (aus hc2_check_states berechnet, 3.12); je Messstelle siehe hc2_check_states
  state ENUM('pending','up','degraded','down','stabilizing','flapping','dependent','paused') NOT NULL DEFAULT 'pending',
  state_since DATETIME(3) NULL, last_check_at DATETIME(3) NULL, next_check_at DATETIME(3) NULL,
  last_status ENUM('up','down') NULL, last_latency_ms FLOAT NULL, last_reason VARCHAR(64) NULL, last_message VARCHAR(500) NULL,
  last_push_at DATETIME(3) NULL, down_since DATETIME(3) NULL, incident_id BIGINT NULL,
  slot SMALLINT NOT NULL DEFAULT 0,            -- crc32(token) % 1024, Verteilung auf hub-Instanzen (Rolle checker)
  INDEX (userid, deleted_at), INDEX (agent_id), INDEX idx_due (slot, execution, paused, next_check_at), INDEX (parent_token)
);

-- Zustand je Messstelle: source = 'agent:<agent_id>' oder 'loc:nbg' / 'loc:fsn'
CREATE TABLE hc2_check_states (
  token CHAR(32) NOT NULL, source VARCHAR(40) NOT NULL,
  state ENUM('pending','up','down','stabilizing','flapping','dependent','paused') NOT NULL DEFAULT 'pending',
  since DATETIME(3) NULL, last_check_at DATETIME(3) NULL, next_check_at DATETIME(3) NULL,
  last_status ENUM('up','down') NULL, last_latency_ms FLOAT NULL, last_reason VARCHAR(64) NULL, last_message VARCHAR(500) NULL,
  consecutive_fail SMALLINT NOT NULL DEFAULT 0, consecutive_ok SMALLINT NOT NULL DEFAULT 0, down_since DATETIME(3) NULL,
  PRIMARY KEY (token, source)
);

-- Messpunkte: source wie oben (Standort oder Agent), 7 Tage roh
CREATE TABLE hc2_measurements (
  token CHAR(32) NOT NULL, source VARCHAR(40) NOT NULL, agent_seq BIGINT NOT NULL DEFAULT 0,
  time DATETIME(3) NOT NULL, status TINYINT NOT NULL, latency_ms FLOAT NOT NULL DEFAULT 0,
  reason VARCHAR(64) NOT NULL DEFAULT '', message VARCHAR(500) NOT NULL DEFAULT '', family CHAR(4) NOT NULL DEFAULT '',
  details JSON NULL, flags TINYINT NOT NULL DEFAULT 0, received_at DATETIME(3) NOT NULL,
  PRIMARY KEY (token, source, time, agent_seq),    -- idempotent: Agent-Punkte sind ueber (source, agent_seq) eindeutig
  INDEX (source, agent_seq), INDEX (time)
) PARTITION BY RANGE (TO_DAYS(time)) (...tagesweise, 8 Partitionen rollierend...);

CREATE TABLE hc2_hourly (token CHAR(32), source VARCHAR(40) NOT NULL, hour DATETIME NOT NULL,
  count INT, up_count INT, min_ms FLOAT, avg_ms FLOAT, max_ms FLOAT, PRIMARY KEY (token, source, hour));
CREATE TABLE hc2_daily  (token CHAR(32), source VARCHAR(40) NOT NULL, day DATE NOT NULL,
  count INT, up_count INT, min_ms FLOAT, avg_ms FLOAT, max_ms FLOAT, PRIMARY KEY (token, source, day));

CREATE TABLE hc2_events (
  id BIGINT AUTO_INCREMENT PRIMARY KEY, event_id CHAR(32) NOT NULL UNIQUE,
  token CHAR(32) NOT NULL, userid INT NOT NULL, agent_id VARCHAR(32) NOT NULL DEFAULT '',
  kind VARCHAR(20) NOT NULL, time DATETIME(3) NOT NULL, from_state VARCHAR(12), to_state VARCHAR(12),
  reason VARCHAR(64), message VARCHAR(500), duration_sec INT NOT NULL DEFAULT 0, flaps SMALLINT NOT NULL DEFAULT 0,
  flags TINYINT NOT NULL DEFAULT 0, incident_id BIGINT NULL, notified_at DATETIME(3) NULL,
  INDEX (token, time), INDEX (userid, time)
);
CREATE TABLE hc2_incidents (id BIGINT AUTO_INCREMENT PRIMARY KEY, token CHAR(32), userid INT, agent_id VARCHAR(32) NOT NULL DEFAULT '',
  started_at DATETIME(3), ended_at DATETIME(3) NULL, reason VARCHAR(64), message VARCHAR(500), INDEX (token, started_at), INDEX (userid, started_at));

CREATE TABLE hc2_channels (
  id INT AUTO_INCREMENT PRIMARY KEY, userid INT NOT NULL,
  agent_id VARCHAR(32) NULL,                 -- NULL = Server-Kanal (gesendet von hub), sonst Agent-Kanal (gesendet vom Agent)
  type VARCHAR(20) NOT NULL,                 -- smtp, telegram, discord, ntfy, gotify, webhook, pushover, app, ipv64_mail, ipv64_sms
  name VARCHAR(100) NOT NULL, config_enc TEXT NOT NULL,   -- JSON, Geheimnisse mit Server-Schluessel (AES-GCM) verschluesselt
  secret_only_local TINYINT NOT NULL DEFAULT 0,          -- Agent-Kanal: Server kennt nur Typ und Name
  enabled TINYINT NOT NULL DEFAULT 1, is_default TINYINT NOT NULL DEFAULT 0, lang CHAR(2) NOT NULL DEFAULT 'de',
  notify_down TINYINT NOT NULL DEFAULT 1, notify_up TINYINT NOT NULL DEFAULT 1,
  verified TINYINT NOT NULL DEFAULT 1, verify_key CHAR(16) NULL, verify_expires DATETIME(3) NULL, -- email/sms wie heute
  revision BIGINT NOT NULL DEFAULT 1, created_at DATETIME(3), updated_at DATETIME(3), deleted_at DATETIME(3) NULL,
  last_used DATETIME(3) NULL, last_error VARCHAR(500) NOT NULL DEFAULT '', legacy_integration_id INT NULL,
  INDEX (userid, deleted_at), INDEX (agent_id)
);
CREATE TABLE hc2_deliveries (id BIGINT AUTO_INCREMENT PRIMARY KEY, event_id CHAR(32), channel_id INT, userid INT, agent_id VARCHAR(32) NOT NULL DEFAULT '',
  time DATETIME(3), kind VARCHAR(20), ok TINYINT, error VARCHAR(500), UNIQUE (event_id, channel_id), INDEX (userid, time));
CREATE TABLE hc2_send_orders (                -- Sendeauftraege fuer Agent-Kanaele, Zustellung ueber den Socket
  id BIGINT AUTO_INCREMENT PRIMARY KEY, agent_id VARCHAR(32), channel_id INT, event_id CHAR(32), payload JSON,
  created_at DATETIME(3), fetched_at DATETIME(3) NULL, done_at DATETIME(3) NULL, INDEX (agent_id, done_at));

CREATE TABLE hc2_maintenance (id INT AUTO_INCREMENT PRIMARY KEY, userid INT, agent_id VARCHAR(32) NULL, name VARCHAR(200),
  start_at DATETIME(3), end_at DATETIME(3), `repeat` ENUM('none','daily','weekly','monthly') DEFAULT 'none', repeat_until DATETIME(3) NULL,
  tokens TEXT, active TINYINT DEFAULT 1, revision BIGINT DEFAULT 1, created_at DATETIME(3), updated_at DATETIME(3), deleted_at DATETIME(3) NULL, INDEX (userid));

-- Aenderungsprotokoll der Konfiguration: Quelle der Deltas fuer Agents und hub
CREATE TABLE hc2_config_log (
  id BIGINT AUTO_INCREMENT PRIMARY KEY, userid INT NOT NULL, agent_id VARCHAR(32) NULL,   -- NULL = betrifft alle Agents des Accounts
  entity ENUM('check','channel','maintenance','agent') NOT NULL, entity_id VARCHAR(32) NOT NULL,
  op ENUM('upsert','delete') NOT NULL, revision BIGINT NOT NULL, origin ENUM('portal','api','agent','system') NOT NULL,
  time DATETIME(3) NOT NULL, INDEX (userid, id), INDEX (agent_id, id)
);
CREATE TABLE hc2_nodes (name VARCHAR(64) PRIMARY KEY, location VARCHAR(16) NOT NULL, roles VARCHAR(32), version VARCHAR(32),
  connections INT NOT NULL DEFAULT 0, started_at DATETIME(3), heartbeat DATETIME(3), INDEX (heartbeat));  -- lebende hub-Instanzen je Standort
CREATE TABLE hc2_locations (code VARCHAR(16) PRIMARY KEY, name VARCHAR(64), endpoint VARCHAR(100), enabled TINYINT DEFAULT 1); -- nbg "Nürnberg" hub-nbg.ipv64.net, fsn "Falkenstein" ...
CREATE TABLE hc2_slot_leases (location VARCHAR(16), slot SMALLINT, owner VARCHAR(64), until DATETIME(3), PRIMARY KEY (location, slot));  -- Sicherung gegen Doppelausfuehrung
CREATE TABLE hc2_dirty_hours (token CHAR(32), source VARCHAR(40) NOT NULL, hour DATETIME, PRIMARY KEY (token, source, hour));
```

**Alt → Neu**: keine Datenübernahme (L2). Die Spalten `legacy_id`/`legacy_integration_id` bleiben ungenutzt. Statusseiten und DNS-Failover lesen weiter die alte Welt, bis diese abgeschaltet wird; die neue Welt bekommt eigene Statusseiten (Abschnitt 6).

---

## 3. Synchronisationsprotokoll

Wer redet mit wem: **nur Agent ↔ hub**. Agents reden nie miteinander; zwei Agents desselben Accounts sehen sich nur über den Server (read-only Sicht auf die Checks des anderen). Das Portal redet nur mit MySQL (und schickt dem hub ein Signal); der hub redet mit MySQL, Redis und den Agents.

```
  Agent "Pi im Keller"                      ipv64-hub (agents.ipv64.net)                 Portal (PHP) / Nutzer
  ───────────────────                       ────────────────────────────                 ─────────────────────
  SQLite: Checks, Kanäle,                   MySQL hc2_*: Checks, Kanäle, Wartung,        liest/schreibt MySQL
  Wartung, Messpunkte (Outbox),             Messpunkte, Zustände, Config-Log             direkt, schreibt bei
  last_revision, hc_outbox, hc_conflicts                                                 Änderung Config-Log
                                                                                         + Redis-Signal
        │                                               │                                       │
        │ ══ WSS (eine Verbindung, Agent baut auf) ═══► │                                       │
        │ hello{since=last_revision}                    │ ◄── Redis hc2:cfg:<user> ◄────────────┤ Nutzer ändert Check
        │ ◄── config{changes seit since} ───────────────┤                                       │   im Portal
        │     (Server → Agent: vollständige Entität)    │                                       │
        │                                               │                                       │
        │ ── measurements{batch} ─────────────────────► │ INSERT IGNORE ──► MySQL               │ Charts/Pillen
        │ ◄── ack{ack_seq} ─────────────────────────────┤                                       │   lesen MySQL
        │ ── events{down/up} ─────────────────────────► │ state_local, Störung, Versand         │
        │                                               │                                       │
  Nutzer ändert Check │ ── propose{base_revision, data} ► │ Revision gleich? ja → speichern,     │
  in der Agent-UI     │ ◄── ack{revision, data} ──────────┤   Log, neue Revision                 │ sieht Änderung
                      │  oder                            │ nein → conflict{server}              │   sofort
                      │ ◄── conflict ─────────────────────┤                                       │
        │                                               │                                       │
        │ ◄── ping / ── pong (30 s) ────────────────────┤ Redis hc2:online:<id> EX 90           │ „online seit“
        │ ◄── send_order / command ─────────────────────┤ ◄── Redis hc2:agent:<id> ◄────────────┤ Test, Befehl
        │                                               │                                       │
   Agent 2 "Büro"     │ (eigene Verbindung, gleiche Regeln; sieht Checks von Agent 1 read-only) │
```

Faustregeln: **Konfiguration** fließt immer über den Server (er vergibt die Revisionen), lokale Änderungen sind Vorschläge, die der Server bestätigt oder als Konflikt zurückgibt. **Messdaten** fließen nur vom Agent zum Server und werden nie überschrieben. **Zustände** (`state_local`) leitet der Server aus den Ereignissen des Agents ab, `state_online` misst er selbst.

### 3.1 Identitäten und Nummern

- `agent_id`: 32 Zeichen, vom Agent beim ersten Start erzeugt, unveränderlich.
- Check-`token`: 32 Zeichen, erzeugt dort, wo der Check angelegt wird. Bei der Erstverknüpfung prüft der Server Eindeutigkeit; bei Kollision vergibt er einen neuen Token und schickt `{old_token, new_token}` zurück, der Agent benennt um (Messdaten, Ereignisse, Push-URL).
- `revision`: pro Entität (Check, Kanal, Wartungsfenster) eine ganze Zahl. **Der Server vergibt sie** aus einem Zähler je Account (`hc2_revisions.next` in einer Transaktion); damit sind Revisionen innerhalb eines Accounts streng steigend und ein Agent kann mit „alles seit Revision R“ fragen. Zwei Zwecke: `last_revision` des Agents (Account-weit, „bis hierhin habe ich alles gesehen“) und `base_revision` eines Vorschlags (die Revision **dieser Entität**, auf der die lokale Änderung aufsetzt). Konflikte werden je Entität erkannt, nie Account-weit: Änderungen an verschiedenen Checks auf beiden Seiten stören sich nicht.
- `agent_seq`: laufende Nummer je Agent für Messpunkte, nie wiederverwendet (SQLite `AUTOINCREMENT`).
- `event_id`: 32 Hex, vom Erzeuger (Agent oder hub) vergeben.

### 3.2 Erstverknüpfung (Device-Code)

```
Agent                                   ipv64-hub (HTTPS)                       Portal (Nutzer, PHP)
  │ POST /v1/agents/link/start {agent_id,name,version}
  │──────────────────────────────────────►│ legt hc2_link_codes an (8 Zeichen, 10 min gueltig)
  │◄──────────────────────────────────────│ {code:"K7PQ4MZB", poll_secret, expires_at, interval:5}
  │ zeigt "Gehe zu ipv64.net/link und gib K7PQ-4MZB ein"                                  │
  │ alle 5 s: POST /v1/agents/link/poll {code, poll_secret}                                  │
  │◄── 202 {status:"pending"} ────────────│                                               │
  │                                       │   Nutzer meldet sich an, /link: Code, Standort, Name, Remote-Verwaltung
  │                                       │◄──────────────────────────────────────────────│
  │                                       │ userid, location in hc2_link_codes, Limit Agents je Tarif pruefen
  │ POST /v1/agents/link/poll             │
  │◄── 200 {agent_token, account:{id,email,plan}, location, name, remote_mgmt} ──────────│
  │ speichert agent_token verschluesselt (secrets.Box), Status "verknuepft"
  │ POST /v1/agents/me/bootstrap, dann WebSocket /v1/ws  ► siehe 3.3 und 3.6
```

- Der Code wird dem Nutzer mit Bindestrich gezeigt, gespeichert ohne. Alphabet ohne 0/O/1/I. 10 Minuten gültig, einmal einlösbar.
- `poll_secret` schützt vor Fremden, die einen Code erraten und dann pollen.
- Alternative ohne Browser am Agent: Token aus dem Portal (Seite Agents → „Token erzeugen“) als `AGENT_IPV64_TOKEN` beim Start.
- Token-Format: `ipv64ag_` + 40 Zeichen Base64url. Server speichert `sha256`. Widerruf im Portal → nächste Anfrage 401 `token_revoked` → Agent zeigt „Verknüpfung getrennt“, arbeitet standalone weiter.

### 3.3 Dauerverbindung (WebSocket) und Konfiguration Server → Agent

- Verbindung: `wss://hc-srv0X.ipv64.net/v1/ws` (Endpunkt aus der Liste), Header `Authorization: Bearer ipv64ag_...`, Query `since=<last_revision>`. Nach dem Handshake schickt der hub `hello {server_time, revision, account:{id,plan,limits}, remote_mgmt}` und sofort alle Änderungen seit `since` (oder `revision_gap`, siehe unten).
- Nachrichten sind JSON-Textframes `{"t":"<typ>","id":"<laufende Nummer des Senders>", ...}`. Jede Nachricht, die Daten trägt, wird mit `{"t":"ack","id":<dieselbe>, ...}` beantwortet; bleibt ein `ack` 30 s aus, gilt die Verbindung als tot. Keine Nachricht größer als 1 MB.
- Server → Agent: `config {revision, changes:[{entity, id, op, revision, data}]}` (`data` ist die vollständige Entität, keine Diffs; `op: delete` ohne `data`), `send_order {id, channel_id, payload}`, `command {id, name, args}`, `ping`, `bye {reason}` (Instanz fährt herunter, Agent verbindet sofort neu).
- Agent → Server: siehe 3.4 (`propose`), 3.5 (`measurements`, `events`), 5 (`deliveries`, `order_done`, `notify`), 3.8 (`command_result`), außerdem `status {version, modules, timezone, outbox_size, local_time}` alle 5 Minuten und `pong`.
- Jede Änderung im Portal/API schreibt die Entität mit neuer Revision, eine Zeile in `hc2_config_log` und publiziert `hc2:cfg:<userid>`; das gateway, das den Agent hält, liest die neuen Log-Zeilen und schickt `config`. Latenz Portal → Agent unter einer Sekunde.
- Agent hält `last_revision` (höchste verarbeitete Revision des Accounts) und wendet an: Check upsert → Scheduler `Upsert` (Zustand behalten, wenn Typ gleich); delete → `Remove` + lokale Tombstone-Zeile.
- Keepalive: hub sendet `ping` alle 30 s, Agent antwortet `pong`; zwei ausgelassene Pongs → hub schließt. Agent-seitig: Reconnect mit Backoff 1 s → 60 s und zufälligem Jitter ±30 % (verhindert einen Reconnect-Sturm, wenn eine Instanz neu startet), nach Reconnect `since` = letzte verarbeitete Revision. Beim `bye` kein Backoff.
- Lücke (`last_revision` kleiner als die kleinste noch vorhandene Log-Revision; Log wird nach 30 Tagen gekürzt) → `revision_gap` → Agent macht Vollabgleich (3.6) über HTTPS und verbindet neu.
- Große Datenmengen (Bootstrap, Vollabgleich, Online-Ergebnisse) laufen nicht über den Socket, sondern über HTTPS am selben Host mit demselben Token.
- Betrifft ein Check-Eintrag einen anderen Agent (`agent_id` ≠ eigener, `execution local`), bekommt der Agent ihn trotzdem als **read-only Sicht** (Portal-Feature „alle Checks des Accounts sehen“), markiert `owner: other`.
- Ohne Verbindung arbeitet der Agent vollständig weiter (Checks, lokale Kanäle, Oberfläche); nur Sync und ipv64-Kanäle warten.

### 3.4 Konfiguration: Agent → Server (Vorschläge)

- Lokale Änderung bei bestehender Verbindung: Agent sendet `propose {entity:"check", op:"upsert", id, base_revision, data}` mit `base_revision` (die Revision, die er zuletzt gesehen hat) und dem vollen Objekt. Server: wenn `base_revision == aktuelle revision` → speichern, neue Revision, `ack {revision, data}` mit dem gespeicherten Objekt; der Agent übernimmt die Antwort (Write-Through). Erst dann gilt die Änderung lokal; die Oberfläche zeigt bis dahin „wird gespeichert“.
- Ohne Verbindung: Änderung in die lokale Outbox (`hc_outbox`: `kind=check_upsert|check_delete|channel_upsert|...`, `payload`, `base_revision`), Oberfläche zeigt „ausstehend“. Beim Wiederverbinden Replay in Reihenfolge.
- Konflikt (`base_revision` veraltet): `conflict {id, server: {...}, revision}`. Agent speichert beide Versionen in `hc_conflicts` und zeigt sie dem Nutzer: „Server behalten“ (lokal überschreiben) oder „Meine Version senden“ (erneut PUT mit der aktuellen Server-Revision als Basis). **Nie stilles Überschreiben.**
- Löschen: `propose {op:"delete"}` mit `base_revision`; Server setzt `deleted_at` (Tombstone), Log-Eintrag `delete`. Umgekehrt: Server-Löschung kommt als `delete` in einer `config`-Nachricht; der Agent löscht lokal **inklusive Messdaten** erst nach Bestätigung aller offenen Messpunkte (sonst Outbox leeren zuerst).
- Dieselben Regeln für Kanäle (`entity:"channel"`) und Wartungsfenster (`entity:"maintenance"`). Bei einem Repair (3.6) stehen dieselben Operationen als HTTPS `PUT/DELETE /v1/agents/me/{checks,channels,maintenance}/{id}` bereit.

### 3.5 Messergebnisse: Agent → Server

- Agent sammelt Messpunkte in der Outbox (`hc_measurements` selbst ist die Outbox: alles mit `agent_seq > last_ack_seq` ist unbestätigt).
- Alle 30 s oder ab 100 Punkten: Nachricht `measurements {batch:[{seq, token, time, status, latency_ms, reason, message, family, details, flags}]}`, höchstens 500 je Batch, nächster Batch erst nach dem `ack`.
- Server: `INSERT IGNORE` (Primärschlüssel enthält `agent_seq`), verwirft Punkte mit `time > now + 5 min` (`reason: future`), antwortet `ack {ack_seq: <höchste verarbeitete seq>, rejected:[seq...]}`. Agent speichert `ack_seq`.
- Zustand: Der Agent ist für `state_local` zuständig und meldet Statuswechsel als Ereignisse (Nachricht `events {batch}`, idempotent über `event_id`; `ack {accepted:[...], duplicates:[...]}`). Der Server leitet aus Ereignissen `state_local`, `down_since`, `incident_id` ab. hub pflegt `state_online`.
- **Gesamtzustand** `state`: aus den Zuständen aller Messstellen nach der Regel des Checks berechnet, siehe 3.12.
- Rückwirkende Punkte (Agent war offline): werden nach `time` einsortiert; Aggregate der betroffenen Stunden/Tage werden von hub nachgerechnet (Markierung in `hc2_dirty_hours`).
- Zeit: Agent sendet UTC aus NTP-Zeit; `received_at` setzt der Server. Abweichung > 5 min → Warnung im Portal und im Agent („Uhr des Agents weicht ab“).

### 3.6 Vollabgleich (Repair)

Auslöser: `revision_gap`, Erstverknüpfung, nach Wiederherstellung der Agent-Datenbank, manuell.

1. Outbox hochladen (Messpunkte und Ereignisse), bis `ack_seq` aktuell ist. Offene Konfigurations-Vorschläge als Konflikte vorlegen, nicht verwerfen.
2. `GET /v1/agents/me/config` liefert alles: Checks (eigene und Sicht auf andere), Kanäle (Server-Kanäle nur Typ/Name/Flags, eigene Agent-Kanäle mit entschlüsselter Konfiguration, außer `secret_only_local`), Wartungsfenster, Agent-Einstellungen, `revision`.
3. Agent ersetzt seine Konfiguration (lokale Zustände und Messdaten bleiben), setzt `last_revision`.
4. `GET /v1/agents/me/results?since=<time>` holt Online-Ergebnisse (Aggregate und letzte Ereignisse) für die lokale Ansicht; roh nur die letzten 24 h.

Erstverknüpfung = Repair mit vorherigem `POST /v1/agents/me/bootstrap`: der Agent lädt seine lokalen Checks, Kanäle und Wartungsfenster hoch, der Server legt sie mit `execution local`, `agent_id` an (Token-Kollisionen siehe 3.1), ohne Limitprüfung. Danach gilt der Server als führend.

### 3.7 Heartbeat und Agent-Ausfall

- Jeder `pong` erneuert den Redis-Key `hc2:online:<agent_id>` (TTL 90 s); `hc2_agents.last_seen` wird gebündelt geschrieben. Beim sauberen Schließen setzt das gateway `online = 0` erst nach 60 s Karenz (der Agent verbindet sich meist sofort mit der anderen Instanz).
- Der checker mit Slot 0 prüft alle 30 s: `online = 1` in MySQL, aber kein Redis-Key → `online = 0`, Ereignis `agent_offline` (Kanäle: Server-Kanäle des Accounts, `ipv64_mail` als Standard). Rückkehr: `agent_online` mit Dauer. Stirbt eine hub-Instanz, laufen die Keys ihrer Agents nach 90 s ab, sofern die Agents nicht längst neu verbunden sind.
- Während ein Agent offline ist, bleiben seine lokalen Checks im letzten Zustand und werden im Portal grau mit „Agent offline seit …“ gezeigt; sie lösen keine eigenen Alarme aus.

### 3.8 Kommandos Server → Agent (`command` über den Socket)

`run_check {token}`, `test_check {token, definition}` (Testlauf ohne Speichern, für 3.11), `pause {token}`, `resume {token}`, `set_log_level {level, minutes}`, `enable_module {name}`, `disable_module {name}`, `set_remote_mgmt`, `update_available {version, url}`, `repair`. Der Agent führt nur aus, was sein lokaler Schalter „Remote-Verwaltung“ erlaubt (`off`: nichts, `read`: nur `update_available`/`repair`, `full`: alles) und antwortet mit `command_result {id, ok, output}`. Kommandos für nicht verbundene Agents warten in `hc2_commands` (1 h, dann verfallen).

---

### 3.9 Wiederverbinden nach Unterbrechung (feste Reihenfolge)

Gilt nach jeder Unterbrechung, egal ob 10 Sekunden, 10 Minuten oder 10 Tage. Der Agent arbeitet währenddessen normal weiter (Checks laufen, lokale Kanäle senden, Oberfläche bedienbar, Änderungen landen in der Outbox mit Markierung „ausstehend“).

1. **Verbinden** mit `since = last_revision`. Server antwortet `hello` und `config` mit allen Log-Einträgen seit `since` (oder `revision_gap` → Schritt 1a).
   1a. `revision_gap` (Log gekürzt, Agent länger als 30 Tage weg oder DB zurückgespielt): Vollabgleich (3.6) **mit** Konflikt-Erkennung: jede Entität, für die ein Outbox-Eintrag existiert und deren Server-Revision ≠ `base_revision`, wird Konflikt; der Rest wird vom Server übernommen.
2. **Server-Änderungen anwenden, aber Outbox beachten**: Für jede Änderung aus `config`:
   - keine ausstehende lokale Änderung an dieser Entität → anwenden (upsert/delete), `last_revision` hochsetzen.
   - ausstehende lokale Änderung an dieser Entität vorhanden → **nicht** anwenden, sondern Konflikt anlegen (`hc_conflicts`: lokale Version, Server-Version, beide Revisionen) und den Outbox-Eintrag auf „Konflikt“ setzen. Sonderfall: beide Seiten haben gelöscht → kein Konflikt, lokal löschen.
3. **Outbox abspielen** in Reihenfolge (nur Einträge ohne Konflikt): `propose` mit `base_revision`. Server: Revision gleich → `ack`, Agent übernimmt Server-Antwort; Revision ungleich (zwischen Schritt 2 und 3 geändert, selten) → `conflict` wie oben.
4. **Messpunkte und Ereignisse nachliefern**: alles mit `agent_seq > ack_seq` in Batches, Ereignisse mit `event_id` (idempotent). Server sortiert nach `time` ein, Aggregate werden nachgerechnet. Server-Benachrichtigungen für nachgelieferte Ereignisse nur, wenn das Ereignis jünger als 15 min ist; ältere nur Protokoll (der Agent hat lokal längst gesendet).
5. **Sendeaufträge und Kommandos** holen, die während der Trennung liegen blieben (max. 1 h alt, sonst verfallen).
6. **Zustellprotokoll** der lokalen Kanäle nachliefern (`deliveries`), damit das Portal zeigt, dass der Agent lokal alarmiert hat.
7. Oberfläche: „ausstehend“ verschwindet, Konflikte erscheinen als Hinweis mit beiden Versionen und den zwei Knöpfen „Server behalten“ / „Meine Version senden“ (letzteres = erneutes `propose` mit der aktuellen Server-Revision als Basis). **Nie stilles Überschreiben**, nie Datenverlust: die unterlegene Version bleibt bis zur Entscheidung sichtbar. Ungelöste Konflikte älter als 30 Tage werden auf „Server behalten“ aufgelöst und protokolliert.

### 3.10 Offline-Szenarien (Prüfung gegen den Plan)

| Nr. | Während der Trennung passiert … | Nach dem Wiederverbinden |
| --- | --- | --- |
| 1 | Nur Messungen, keine Änderungen | Schritt 4: Nachlieferung, Charts im Portal füllen sich rückwirkend, keine Alarme vom Server (Agent hat lokal gesendet) |
| 2 | Lokal Check A geändert, Portal nichts | Schritt 3: `propose` → `ack`, Portal zeigt die Änderung |
| 3 | Portal Check A geändert, lokal nichts | Schritt 2: anwenden, Agent übernimmt (Zustand bleibt, wenn Typ gleich) |
| 4 | Lokal Check A geändert **und** im Portal Check B geändert | Schritt 2 wendet B an, Schritt 3 sendet A → beides durch, kein Konflikt |
| 5 | Lokal Check A geändert **und** im Portal Check A geändert | Schritt 2: Konflikt A mit beiden Versionen; Nutzer entscheidet im Agent (oder im Portal, das Konflikte des Agents ebenfalls anzeigt) |
| 6 | Lokal Check A gelöscht, Portal Check A geändert | Konflikt (Löschen vs. Ändern), Standardvorschlag „Server behalten“ |
| 7 | Portal Check A gelöscht, lokal Check A geändert | Konflikt (Ändern vs. Löschen); „Meine Version senden“ legt ihn mit neuem Token wieder an |
| 8 | Beide löschen A | Kein Konflikt, lokal weg; Messdaten erst nach Nachlieferung (Schritt 4) gelöscht |
| 9 | Lokal neuer Check C angelegt, Portal neuer Check D | Beide gehen durch; Token-Kollision (praktisch unmöglich, 32 Zeichen) wird mit `renamed` aufgelöst |
| 10 | Portal: Check A von lokal auf online umgehängt (3.11) | Server misst seit dem Umhängen online; Schritt 2: Agent stoppt A lokal, zeigt „läuft online bei ipv64“; seine letzten lokalen Messpunkte kommen noch nach und bleiben als Messreihe `agent:<id>` sichtbar |
| 11 | Agent-UI: Check A auf online umgehängt (offline) | Outbox-Vorschlag; bis zum `ack` läuft A lokal weiter (nichts geht verloren); Server macht beim `propose` den Testlauf, Erfolg → `execution = online`, Agent stoppt A |
| 12 | Portal: Kanal getestet / Befehl „jetzt prüfen“ | Sendeauftrag/Kommando wartet bis 1 h, danach verfallen mit Fehlermeldung im Portal |
| 13 | Portal: Agent-Token widerrufen | Verbindung scheitert mit `token_revoked`; Agent zeigt „Verknüpfung getrennt“, bleibt standalone, Outbox bleibt erhalten (für ein erneutes Verknüpfen desselben Accounts) |
| 14 | Agent war > 30 Tage weg | `revision_gap` → Vollabgleich mit Konflikt-Erkennung (1a); Messdaten älter als 7 Tage werden nur als Aggregat übernommen (Server rechnet `hc2_daily` aus den nachgelieferten Punkten, Rohdaten > 7 Tage verwirft er) |
| 15 | Agent-Datenbank aus Backup wiederhergestellt (älterer `last_revision`, kleinere `agent_seq`) | Server erkennt `agent_seq` ≤ `last_ack_seq` → `INSERT IGNORE` verwirft Doppelte; Konfiguration: Vollabgleich, Server gewinnt für alles ohne Outbox-Eintrag |
| 16 | Uhr des Agents falsch | Messpunkte > 5 min in der Zukunft werden abgelehnt (`rejected`), Warnung im Portal und Agent; Vergangenheit wird akzeptiert |
| 17 | hub neu gestartet / Instanz gewechselt | `bye` → sofortiger Reconnect ohne Backoff; Schritte 1–6 laufen mit leerer Differenz in < 1 s |
| 18 | Zwei Agents desselben Accounts ändern denselben Check | Nur der Besitzer-Agent (`agent_id`) darf `execution local`-Checks ändern; fremde Checks sind read-only → kein Konflikt möglich. Online-Checks (ohne Besitzer) dürfen beide ändern → normaler Revisionskonflikt wie Fall 5 |

Was dafür im Agent gebaut wird (Phase 6 des Agents): `hc_outbox` (Vorschläge mit `base_revision`, Status pending/sent/conflict), `hc_conflicts`, `last_revision`/`ack_seq` in `settings`, Markierungen „ausstehend“/„Konflikt“ in Liste und Detail, Konfliktseite mit Diff, Reconnect-Ablauf als Zustandsautomat mit Tests für jede Zeile der Tabelle.

### 3.11 Umhängen: lokal ↔ online ↔ beides

Ein Check hat einen **Ausführungsort** (`execution`): `local` (nur dieser Agent misst), `online` (nur der hub misst), `both` (Agent und Standorte messen, je Messstelle ein Zustand, ein Gesamtzustand nach 3.12). Der Ausführungsort ist ein normales Feld der Check-Konfiguration und wird wie jede andere Änderung synchronisiert, kann also im Portal **oder** in der Agent-Oberfläche geändert werden. Der Token bleibt gleich, die Messhistorie bleibt: Messpunkte tragen ihre Messstelle (`source`: `agent:<id>`, `loc:nbg`, `loc:fsn`), die Zeitleiste zeigt „ab hier online“/„ab hier lokal“, Charts zeigen beide Serien.

- **lokal → online** (z. B. „google.de erreichbar“ soll künftig von ipv64 aus geprüft werden): Server prüft das Limit (`user_class.healthcheck_limit` zählt nur online/both), weist private Ziele ab (RFC 1918, ULA, Loopback, Link-Local, `.local`, `localhost` – Hinweis auf CDN), macht einen Testlauf aus dem hub (`hc2_testruns`, Ergebnis ≤ 30 s, im Portal und im Agent sichtbar). Erfolg → `execution = online`, `agent_id` bleibt als Herkunft (für „zurück“), der Agent stoppt die lokale Messung mit der nächsten `config`-Nachricht. Misserfolg → Check bleibt lokal, Fehlermeldung mit Grund.
- **online → lokal**: Nutzer wählt den Agent (bei mehreren); der Check geht per `config` an den Agent, der ihn pausiert anlegt, einen Testlauf macht und das Ergebnis meldet (`command_result`); erst dann setzt der Server `execution = local` und stoppt die Online-Messung. Ist der Agent offline, bleibt es bei online, mit Hinweis „wartet auf Agent“.
- **beides**: wie lokal → online, nur dass der Agent weitermisst. Drei Messstellen (Agent, nbg, fsn), Gesamtzustand nach 3.12.
- **Der Agent kann auch anstoßen**: In der Agent-UI gibt es im Check-Formular denselben Schalter (nur bei Verknüpfung). Die Änderung ist ein `propose`; der Server führt dieselben Prüfungen (Limit, privates Ziel, Testlauf) aus, bevor er `ack` gibt. Bis dahin misst der Agent weiter.
- **Umhängen beim Entkoppeln** (`unlink`): `keep_checks = true` → alle lokalen Checks des Agents werden auf `online` gesetzt, sofern das Limit und die Zielregeln es erlauben (sonst bleiben sie mit `agent_id` als verwaist stehen und werden im Portal markiert); `false` → gelöscht (Tombstone).
- Massenaktion im Portal und im Agent: mehrere Checks auf einmal umhängen; Testläufe parallel, Ergebnisliste.

### 3.12 Mehrere Messstellen und Gesamtzustand (Hybrid)

**Messstellen** (`source`): `agent:<agent_id>` (innen, vom Agent gemeldet) und `loc:nbg`, `loc:fsn` (außen, vom hub gemessen). Welche aktiv sind, ergibt sich aus `execution` (`local` → nur Agent; `online` → `locations`; `both` → Agent + `locations`). Jede Messstelle hat ihre eigene Zustandsmaschine (pending/up/down/stabilizing/flapping, Retries, Stabilisierung) in `hc2_check_states`, eigene Messreihe, eigene Pillenleiste und Latenz-Kurve. Nichts wird zusammengeworfen.

**Gesamtzustand** (`hc2_checks.state`), berechnet vom hub bei jeder Zustandsänderung einer Messstelle (und vom Agent lokal für seine Anzeige, nach denselben Regeln mit den Daten, die er hat):

| Regel (`policy`) | Gesamt **down**, wenn … | sonst **degraded**, wenn … | sonst |
| --- | --- | --- | --- |
| `all` (Standard) | **alle** aktiven Messstellen down | mindestens eine down | up |
| `any` | **eine** Messstelle down | – | up |
| `majority` | mehr als die Hälfte down | mindestens eine down | up |

- **Alarm-Option je Check**: `policy` (all/any/majority) und `notify_degraded` sind vom Nutzer einstellbar – im Portal und in der Agent-Oberfläche (dort schon eingebaut, Karte „Messstellen und Bewertung“). Standard `all` + kein Alarm bei „teilweise gestört“.
- **Standorte je Klasse**: Checks von Accounts mit `hc_locations = 1` laufen an genau einem Standort; die Regel `all` ist dann „Agent + ein Standort“. Beim Wechsel der Klasse nach unten reduziert der Server die `locations` jedes Checks auf einen Standort und schreibt das ins Config-Log (Agent sieht es).
- Messstellen im Zustand `pending`, `paused`, `dependent` oder ohne aktuelle Daten (Agent offline > 3 min, Standort ausgefallen) zählen **nicht mit** (weder up noch down). Sind alle ohne Daten → `pending`. Dadurch kippt ein Check nicht auf down, nur weil der Heim-Agent gerade offline ist, und nicht auf up, nur weil ein Standort schweigt.
- `stabilizing`/`flapping` einer Messstelle gelten für die Regel als up bzw. down nach ihrem `last_status`; der Gesamtzustand zeigt `flapping`, wenn die bestimmende Messstelle flattert.
- Push-Checks haben genau eine Messstelle (die, die den Heartbeat bewertet) – Regel greift nicht.
- **Ereignisse und Alarme** entstehen nur beim Wechsel des **Gesamtzustands** (`kind: down`, `up`, `degraded`, `degraded_end`); `degraded` löst nur Benachrichtigungen aus, wenn `notify_degraded = 1` (Standard aus). Die Ereignis-Nachricht enthält die Diagnose: „außen gestört (nbg, fsn), innen OK → Router/Portfreigabe/CDN“, „innen gestört, außen OK → Heimnetz/Agent“, „nur nbg gestört → wahrscheinlich Netzpfad Nürnberg“, „alle Messstellen gestört → Ziel down“.
- Störungen (`hc2_incidents`) folgen dem Gesamtzustand; die Störungsseite zeigt, welche Messstellen beteiligt waren.
- Statusseiten zeigen den Gesamtzustand; optional je Check die Messstellen als kleine Zeile.
- Lokale Benachrichtigungen des Agents (standalone oder offline): der Agent kennt nur seine eigene Messstelle und alarmiert wie bisher über seine lokalen Kanäle; verknüpft und online überlässt er Alarme dem Server (Server-Kanäle **und** Agent-Kanäle per `send_order`), damit Hybrid-Checks nicht doppelt und nicht nach der falschen Regel alarmieren. Umschaltbar je Agent („Agent alarmiert immer lokal zusätzlich“).
- Verfügbarkeit in Prozent (24 h/30 d/1 J) wird je Messstelle und als Gesamt (nach Regel, aus `hc2_events`-Dauern) angezeigt.

**Beispiel** (Regel `all`, Check „google.de“ mit `both`): Heim-Internet fällt aus → Agent meldet down, nbg/fsn up → **degraded**, Hinweis „innen gestört, außen OK → Heimnetz“, kein Alarm (außer `notify_degraded`). Google selbst down → alle drei down → **down**, Alarm. Nürnberg hat Netzprobleme → nur `loc:nbg` down → degraded, Diagnose „Netzpfad Nürnberg“; zusätzlich sieht Dennis in den hub-Metriken, dass viele Checks an einem Standort gleichzeitig kippen (Alarm `location_degraded`, Schwelle 20 % der Checks eines Standorts in 5 min).

---

## 4. ipv64-hub: Endpunkte und Nachrichten für Agents

Hosts `hc-srv01.ipv64.net` (fsn) und `hc-srv02.ipv64.net` (nbg), Auth `Authorization: Bearer ipv64ag_...` (außer Link-Start/Poll und Push). Antworten wie in der API v2 (`{data, meta}`, Fehler RFC 9457). Ratenbegrenzung je Agent-Token und je IP, Batchgrößen begrenzt. Alles unter `/v1/`, damit spätere Protokolländerungen neben dem alten laufen können.

**HTTPS**

| Methode | Pfad | Body / Antwort |
| --- | --- | --- |
| POST | `/v1/agents/link/start` | `{agent_id, name, version}` → `{code, poll_secret, expires_at, interval}` (ohne Auth, 5/min je IP) |
| POST | `/v1/agents/link/poll` | `{code, poll_secret}` → `202 pending` oder `{agent_token, account, name, location, remote_mgmt, ws_url}` |
| GET | `/v1/agents/me` | Agent-Daten, Limits, `remote_mgmt`, `server_time` |
| PATCH | `/v1/agents/me` | `{name, location, version, timezone, modules, outbox_size}` |
| POST | `/v1/agents/me/bootstrap` | `{checks:[...], channels:[...], maintenance:[...]}` → `{renamed:[{old_token,new_token}], revision}` |
| GET | `/v1/agents/me/config` | Vollabgleich (3.6) |
| PUT/DELETE | `/v1/agents/me/checks/{token}`, `/channels/{id}`, `/maintenance/{id}` | mit `base_revision` (3.4), nur für Repair; `409 conflict` liefert Server-Version |
| POST | `/v1/agents/me/measurements`, `/events`, `/deliveries` | wie die Socket-Nachrichten, für den Nachlauf nach langer Offline-Zeit (große Outbox) |
| GET | `/v1/agents/me/results?since=` | Online-Ergebnisse für die lokale Ansicht |
| POST | `/v1/agents/me/unlink` | Entkoppeln (Token widerrufen; Checks bleiben beim Account mit `execution online` oder werden gelöscht, Parameter `keep_checks`) |
| GET | `/v1/ws` | WebSocket (3.3) |
| GET/POST | `/v1/push/{token}` | Heartbeat (gleichwertig zu `health.php?token=`, das weiter funktioniert) |
| GET | `/v1/health` | für den Load Balancer: `{status, role, connections}` |

`https://ipv64.net/agent/latest.json` (Versionsdatei) bleibt eine statische Datei im Portal.

**WebSocket-Nachrichten** (`t`)

| Richtung | `t` | Inhalt | Antwort |
| --- | --- | --- | --- |
| S→A | `hello` | `server_time, revision, account, remote_mgmt` | – |
| S→A | `config` | `revision, changes[]` | `ack` |
| S→A | `send_order` | `id, channel_id, payload` (Nachricht, die der Agent über seinen Kanal schickt) | `order_done {id, ok, error}` |
| S→A | `command` | `id, name, args` (3.8) | `command_result` |
| S→A | `revision_gap` | – | Agent macht Repair |
| S→A | `ping` / `bye` | – | `pong` / Reconnect |
| A→S | `measurements` | `batch[]` ≤ 500 | `ack {ack_seq, rejected}` |
| A→S | `events` | `batch[]` | `ack {accepted, duplicates}` |
| A→S | `propose` | `entity, op, id, base_revision, data` | `ack {revision, data}` oder `conflict` |
| A→S | `deliveries` | Zustellprotokoll der Agent-Kanäle, idempotent über `event_id+channel_id` | `ack` |
| A→S | `notify` | `channel_type (ipv64_mail/ipv64_sms), channel_id, event` → hub verschickt über ipv64 (5) | `ack {ok, error}` |
| A→S | `status` | `version, modules, timezone, outbox_size, local_time` (alle 5 min) | – |

Portal/Fremdsoftware (Session oder API-Key) bekommen dieselben Ressourcen über `api_v2.php` (Vorschlag: nach der Umstellung übernimmt der Pfad `/healthchecks` der API v2 das neue Modell; bis dahin v2-Pfad `/hc2/checks` usw.). Die Agent-eigene JSON-API bleibt identisch zur Serverseite (gleiche Feldnamen), damit Skripte lokal und online gleich aussehen.

---

## 5. Benachrichtigungen (hybrid)

| Ereignis | Standalone | Verknüpft, Agent online | Verknüpft, Agent offline |
| --- | --- | --- | --- |
| Lokaler Check down/up | Agent sendet über Agent-Kanäle (inkl. Pushover) | Agent meldet Ereignis an Server; **Server** sendet Server-Kanäle und `ipv64_mail`/`ipv64_sms`; Agent-Kanäle sendet der Agent selbst sofort (kein Umweg, kein Sendeauftrag nötig) | Agent sendet Agent-Kanäle lokal (Fallback) und meldet das Ereignis später nach; Server sendet seine Kanäle beim Nachmelden **nur, wenn das Ereignis jünger als 15 min ist** (sonst nur Protokoll) |
| Online-/Hybrid-Check: Gesamtzustand wechselt (down/up/degraded) | – | hub sendet Server-Kanäle; Agent-Kanäle als `send_order` über den Socket | Sendeauftrag bleibt liegen, verfällt nach 1 h |
| Agent offline/online | – | hub über Server-Kanäle | – |

- Deduplizierung über `event_id` in `hc2_deliveries (event_id, channel_id)` und im Agent `nf_deliveries`.
- `ipv64_mail`: Absender wie heute (`send_mail`), Empfänger Account-Adresse oder verifizierte Adresse eines Kanals vom Typ `ipv64_mail` mit `config.email`. Nach der Verknüpfung automatisch angelegt und Standard.
- `ipv64_sms`: wie `send_sms` heute, Nummer verifiziert, Tageslimit `sms_limit`.
- Ruhezeiten, Sammelmeldungen, Wiederholungen, Flattern: gleiche Regeln wie im Agent, Einstellungen je Account (`hc2_settings` oder `settings`-Tabelle, Schlüssel `notify.*`).
- **Pushover** wird ein normaler Kanaltyp im Agent-Paket `notify` (direkt an die Pushover-API mit dem Key des Nutzers, funktioniert standalone) und damit automatisch auch auf dem Server.
- **App** (Firebase, wie heute `mobil`) gibt es nur als Server-Kanal; den Firebase-Zugang hat nur ipv64.
- **`ipv64_mail` / `ipv64_sms`** im Agent: Kanaltypen, die nur mit Verknüpfung aktiv sind. Der Agent schickt `notify {channel_type, event}` über den Socket, der hub versendet über die ipv64-Infrastruktur (Absender, Empfänger = verifizierte Adresse/Nummer des Accounts, Tageslimit `sms_limit`). Ohne Verbindung landet die Nachricht in der Outbox und wird beim Verbinden nachgeholt, wenn das Ereignis jünger als 15 min ist. Standalone-Nutzer sehen diese Typen mit dem Hinweis „benötigt ipv64-Verknüpfung“.

---

## 6. Neue Healthcheck-Webseite bei ipv64.net

Pfade während der Umstellung unter `/healthchecks2/...`, nach Abschluss übernehmen sie `/healthcheck`. Technik: PHP wie das Portal (Bootstrap 4, bestehende Pillen-CSS `beat2/gros-bar`), Charts mit Chart.js über die API v2. Die Seiten werden den Agent-Seiten nachempfunden, damit Nutzer sich zurechtfinden.

| Seite | Inhalt |
| --- | --- |
| Übersicht `/healthchecks2` | Kacheln OK/gestört/pausiert/sonstige (je Ausführungsort getrennt zählbar), Tabelle mit Status, Name, Tags, **Badge Ausführungsort** (Online / Agent „Pi im Keller“ / Beides), Typ, Latenz, Pillen (letzte 30 Messungen), letzte Änderung; Filter Status/Typ/Tag/Agent/Ausführungsort, Sortierung, Suche, Massenaktionen; Account-Status-Karte mit Zähler Online-Checks vs. Limit |
| Neu/Bearbeiten `/healthchecks2/new`, `/{token}/edit` | Formular wie im Agent (Typen http, keyword, icmp, tcp, port, cert, push), **Ausführungsort** (Online, Agent X, Beides) mit Testlauf vor dem Umschalten (3.11), Kanäle, Abhängigkeit, Tags, kritisch, Wiederholung |
| Detail `/healthchecks2/{token}` | Pillenleiste groß, Verfügbarkeit 24 h/30 d/1 Jahr, Latenz-Chart (bei „beides“ innen und außen im selben Chart), Ereignisse, Störungen, letzte Messung roh, Push-URL (online **und** lokal, wenn ein Agent zuständig ist), Diagnose-Hinweis bei Abweichung innen/außen |
| Wartungsfenster `/healthchecks2/maintenance` | wie Agent |
| Störungen `/healthchecks2/incidents` | Liste aller Störungen des Accounts (ersetzt `incidents.php`) |
| Benachrichtigungen `/notifications` | Kanäle (ersetzt `integrations.php`): Liste, Anlegen je Typ, Test, Standard, Verifizierung Mail/SMS per Code **nach Login** (kein Link mehr ohne Anmeldung), Ruhezeiten, Zustellprotokoll |
| Agents `/agents` | Liste: Name, Standort, online/offline seit, Version, letzte Synchronisation, Module, Outbox; Detail mit Reitern Healthchecks (Checks dieses Agents, Umwandeln, Remote-Checks anlegen), DynDNS, Reverse-Proxy (später); Aktionen umbenennen, Standort, Token widerrufen, entfernen; Seite `/link` für den Device-Code |
| Statusseiten | bestehende `statuspage.php`/`status.php` liest Zustände aus `hc2_*` (Tokens statt IDs), Design unverändert |
| Öffentliche Seite | `healthcheck_updater_api.php` erweitern um die neue Push-URL und die Agent-Doku |

## 7. Einführung und Abschaltung alt (ohne Migration)

| Schritt | Inhalt | Rückweg |
| --- | --- | --- |
| M0 | Tabellen `hc2_*` in eigener Datenbank, `users.hc2` Flag, `latest.json` | – |
| M1 | `ipv64-hub` auf beiden Servern, zunächst ohne Nutzer; Lasttest | Dienst stoppen |
| M2 | Neue Portalseiten unter `/healthchecks2`; Schalter „Neue Healthchecks aktivieren“ setzt `hc2 = 1` (Menü zeigt dann beide Welten: „Healthchecks (neu)“ und „Healthchecks (alt)“); `health.php` nimmt neue Tokens an | Flag auf 0 blendet die neue Welt aus, Daten bleiben |
| M3 | Agent-Release mit Sync; Beta mit Dennis und Freiwilligen | Agent entkoppeln |
| M4 | Freigabe für alle (Ankündigung Blog/Wiki); alte Welt bleibt parallel, neue Checks nur noch in der neuen Welt anlegbar (alte Seite: Hinweis statt „Neu“) | Hinweis entfernen |
| M5 | Nach Frist (Vorschlag 6 Monate): alte Bots aus, alte Seiten nur noch lesend, dann abgeschaltet; alte Tabellen 90 Tage als Dump | Backup |

Limits: alte und neue Welt zählen getrennt (alt wie bisher gegen `healthcheck_limit`, neu Online-Messstellen gegen dasselbe Limit); während der Parallelzeit gilt das Limit also je Welt. Entscheidung, ob beide zusammen zählen sollen, offen (Dennis).

---

## 8. Sicherheit

- Agent-Token nur gehasht, einzeln widerrufbar, Scope auf den eigenen Agent (`agent_id` aus dem Token, nie aus dem Body).
- Alle Agent-Endpunkte prüfen Besitz: Check-Token muss zum Account gehören; fremde Tokens → 404.
- Ratenlimits: Link-Start 5/min je IP, Poll 20/min je Code, Verbindungsaufbau 10/min je Agent und 60/min je IP, Messpunkte 500 je Batch und 60 Batches/min, ungültige Tokens 20/min je IP. Je Instanz ein Verbindungslimit (Flag), darüber `503` mit `Retry-After`.
- Der hub hat keine Sitzungen und kein HTML; er prüft nur Agent-Tokens. Der Nutzer-Teil (Login, `/link`, `/agents`) bleibt im Portal.
- Remote-Verwaltung: Schalter am Agent, Standard `read`; remote angelegte Checks nur auf freigegebene Subnetze (Agent-Einstellung).
- Geheimnisse von Kanälen: Server-Schlüssel in einer Datei außerhalb des Webroots, AES-GCM wie im Agent; `secret_only_local` respektieren.
- Verifizierung Mail/SMS nur eingeloggt mit Code-Eingabe (Lücke `activate_integration` schließen).
- Datenschutz-Hinweis beim Verknüpfen (interne Ziele landen bei ipv64).

---

## 9. Arbeitspakete, Reihenfolge, Abnahme

| # | Paket | Repo | Abnahme |
| --- | --- | --- | --- |
| 1 | `latest.json` + Versionsprüfung | ipv64 | Agent zeigt Version |
| 2 | `hc2_*` DDL in eigener DB, `users.hc2`, dbconnect-Block (Hooks, Push-Eingang, Verschlüsselung) | ipv64 | Tabellen da, health.php nimmt neue Tokens an |
| 3 | `cmd/hub` Rolle **checker**: MySQL-Adapter für `scheduler.Store`, Standorte, `hc2_nodes`/Slots/Leases je Standort, Messstellen-Zustände + Gesamtzustand (3.12), Konfig-Log + Redis, Push-Watchdog, Aggregation, Agent-/Standort-Ausfall | Agent-Repo | Online-Checks eines Testaccounts laufen über zwei hub-Instanzen; eine stoppen → die andere übernimmt binnen 30 s |
| 4 | `notify`: `pushover` (Agent + Server), `app`, `ipv64_mail`, `ipv64_sms` (Server, Backend über SMTP/SMS-Gateway wie heute), Agent-Weiterleitung `notify` | Agent-Repo | Testnachrichten je Typ, lokal und über hub |
| 5 | Portal: `/notifications` (Kanäle), Verifizierung | ipv64 | Alte Integrationen migriert, Test-Button |
| 6 | Portal: `/healthchecks2` Übersicht, Detail, Formular, Wartung, Störungen, Statusseite auf `hc2` | ipv64 | Feature-Parität zur alten Seite plus neue Typen |
| 7 | `cmd/hub` Rolle **gateway**: WebSocket, Device-Code, HTTPS-Abgleich, Redis-Fanout, Batch-Writer; Portal `/link`, `/agents`; nginx-Konfiguration; Lasttest `cmd/hubload` mit 10.000 simulierten Agents | Agent-Repo + ipv64 | Lasttest ohne Fehler, Instanz-Neustart ohne Datenverlust (Messpunkte kommen per Outbox nach) |
| 8 | Agent: `internal/sync` echter Client (Link, WebSocket, Outbox, Konflikte, Repair, Reconnect-Ablauf 3.9), UI „ipv64-Verknüpfung“, Konfliktseite, Umhängen (3.11), Kanaltypen `ipv64_mail`/`ipv64_sms` | Agent-Repo | Jede Zeile der Tabelle 3.10 als Test; hub-Wechsel unbemerkt |
| 9 | Beta (Dennis + Freiwillige) mit Agent und Portal, zwei Wochen | ipv64 | keine offenen Fehler |
| 10 | Freigabe für alle, später Abschaltung alt (Abschnitt 7) | ipv64 | Alte Bots aus |

Reihenfolge: 1 → 2 → 3 → 4 → 7 → 8 → 5 → 6 → 9 → 10. Pakete 3/4/7/8 (Go) und 5/6 (PHP) können parallel laufen; 7 und 8 werden gegeneinander getestet.

---

## 10. Entscheidungen (Stand 2026-10-10, Dennis)

1. **Rohdaten der Online-Checks:** 7 Tage in MySQL.
2. **Limits:** nur für Online-Checks, wie bisher aus der User-Class; lokal im Container unbegrenzt; keine Obergrenze für Agents je Account.
3. **Pfad:** neue Seiten unter `/healthchecks2`; wie und wann umgestellt wird (Migrationsweg), bleibt offen.
4. **Pushover** auch im Agent (Standalone ohne ipv64-Account muss vollwertig sein). **App** nur serverseitig. **E-Mail und SMS über ipv64** als Agent-Kanäle, die nur verknüpft funktionieren.
5. **DNS-Failover** bleibt beim Online-System; Agent-Checks sind dafür keine Quelle.
6. ~~Kein zweiter Standort~~ → überholt durch 8/10: zwei Standorte (nbg, fsn) von Anfang an.
7. **Transport:** kein Long-Poll über PHP, sondern ein eigener Go-Dienst `ipv64-hub` mit WebSocket, von Anfang an für viele tausend Agents und mehrere gleichwertige Instanzen ausgelegt (L4, L9, Abschnitt 1).
8. **Server:** zwei hub-Server von Anfang an, **Nürnberg** und **Falkenstein** (Hetzner Cloud), getrennt vom Web-Server; Redis auf nbg über privates Netz. Zugänge (IP usw.) kommen von Dennis.
10. **Zwei Standorte für Online-Checks**: jeder Online-Check wird standardmäßig von beiden Standorten gemessen (abwählbar je Check).
11. **Hybrid**: lokal + online gleichzeitig möglich; Gesamtzustand nach Regel je Check (**einstellbar**: alle / eine / Mehrheit), Standard „down nur, wenn alle Messstellen down“, sonst „teilweise gestört“; Alarm bei „teilweise gestört“ ist eine Option je Check (3.12).
12. **Standorte und Limit**: mehrere Online-Standorte je Check erst ab Klasse Supporter (Standard-Klasse: ein Standort). Das Healthcheck-Limit der Klasse zählt Online-Messstellen (Check × Standorte); lokale Messungen zählen nie (L8).
9. **IPv6** überall, Agent und Server (L10).
13. **Keine Migration**: neue Welt startet je Nutzer bei null, alte Welt läuft unverändert parallel bis zur Abschaltung (L2, Abschnitt 7).

Der vollständige Phasenplan für die Serverseite steht in `PLAN-IPV64-SERVER-PHASEN.md`.
