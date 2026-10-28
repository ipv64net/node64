# Anbindung an ipv64.net: was auf der Serverseite gebaut werden muss

Stand: Ende Phase 5 des Nodes. Der Node läuft standalone komplett. Dieses Dokument hält fest, was ipv64.net liefern muss, damit der Node verknüpft arbeiten kann (Konzept „Node64 – Konzept & Funktionsumfang“, Abschnitt Synchronisation). Nichts davon ist im ipv64-Code schon umgesetzt.

## 1. Was der Node bereits vorbereitet hat

| Agent-Seite | Zustand |
| --- | --- |
| Check-Token (32 Zeichen, wie `healthtoken` bei ipv64) | fertig, Primärschlüssel aller Checks |
| `revision` je Check und Kanal | fertig, wird bei jeder Änderung erhöht; der Server soll sie künftig vergeben |
| `execution` je Check (`local` / `online` / `both`) | Feld vorhanden, nur `local` erlaubt |
| Messpunkte mit `node_seq` (laufende Nummer, persistiert) | fertig (`hc_measurements.node_seq`) |
| Ereignisse mit eindeutiger `event_id` | fertig (`hc_events.event_id`) |
| Outbox und Tombstones | Tabellen `hc_outbox`, `hc_tombstones` vorhanden, noch unbenutzt |
| Kanäle mit `execution` (`node` / `ipv64`) und `secret_only_local` | Felder vorhanden; Typen `ipv64_mail` und `ipv64_sms` sind als geplant markiert |
| Agent-Identität | `settings`: `node.id`, `node.name`, `node.location`, `node.timezone` |
| Sync-Client | `internal/sync`: Interface `Client`, bisher `NoOp` |
| Versionsprüfung | ruft `https://ipv64.net/node64/latest.json` ab (Opt-in), erwartet `{"version","url","notes"}` |

## 2. Datenbank bei ipv64 (neue Tabellen, Vorschlag)

```sql
-- Nodes je Account
nodes (id, userid, node_id VARCHAR(32) UNIQUE, name, location, version, token_hash, remote_mgmt ENUM('off','read','full'),
        last_seen, last_sync, outbox_size, created_at, revoked_at)

-- Device-Code-Flow
agent_link_codes (code VARCHAR(8) UNIQUE, node_id, created_at, expires_at, userid NULL, consumed_at NULL)

-- Checks: Erweiterung der bestehenden Tabelle healthchecks (kein Neubau nötig für den Start)
ALTER TABLE healthchecks ADD execution ENUM('local','online','both') DEFAULT 'online',
                         ADD node_id VARCHAR(32) NULL, ADD revision INT NOT NULL DEFAULT 1,
                         ADD params TEXT NULL;           -- JSON wie im Node (type_options bleibt für Altcode)

-- Messpunkte der Nodes (append-only, idempotent über node_id + node_seq)
agent_measurements (node_id, node_seq BIGINT, healthtoken, time, status, latency_ms, reason, message, details JSON, flags,
                    received_at, PRIMARY KEY (node_id, node_seq), INDEX (healthtoken, time))

-- Kanäle der Nodes (Konfiguration verschlüsselt, optional ohne Secret)
agent_channels (id, userid, node_id, type, name, config_enc TEXT, secret_only_local TINYINT, revision INT, ...)

-- Zustellprotokoll der Nodes
agent_deliveries (node_id, event_id, channel_id, time, ok, error)
```

Limits: lokale Checks (`execution = local`) zählen **nicht** gegen `user_class.healthcheck_limit`. Beim Umwandeln nach `online` greift das Limit.

## 3. API v2 (ipv64.net/api/v2), neue Endpunkte

Alle Aufrufe mit `Authorization: Bearer <agent_token>` (eigener Token je Node, einzeln widerrufbar, nicht der Account-API-Key).

| Methode | Pfad | Zweck |
| --- | --- | --- |
| POST | `/nodes/link/start` | Node erzeugt Device-Code (ohne Auth): liefert `code`, `expires_at`, `poll_interval` |
| POST | `/nodes/link/poll` | Node fragt mit `code`, ob der Nutzer bestätigt hat; liefert `agent_token`, `node_id`, `account` |
| Portal | `/link` | Nutzer gibt den Code ein, wählt Standort, Agent-Name; bestätigt |
| GET | `/nodes/me` | Agent-Daten, Remote-Verwaltung, Standort |
| PATCH | `/nodes/me` | Name, Standort, Version, aktive Module melden |
| GET | `/nodes/me/config?since=<revision>` | Vollabgleich oder Delta: Checks, Kanäle, Wartungsfenster mit Revisionen |
| POST | `/nodes/me/config/proposals` | Offline-Änderungen mit Basis-Revision; Server antwortet mit neuer Revision oder `409` + beide Versionen |
| POST | `/nodes/me/measurements` | Batch `[{healthtoken, node_seq, time, status, latency_ms, reason, message, details, flags}]`, Antwort `{ack_seq}` |
| POST | `/nodes/me/events` | Statuswechsel mit `event_id` (idempotent) |
| GET | `/nodes/me/results?since=<time>` | Online-Ergebnisse (Server-Checks, andere Nodes) für die lokale Ansicht |
| POST | `/nodes/me/notify` | Node bittet den Server, über ipv64-Kanäle zu senden (Mail an Account-Adresse, SMS laut Tarif) |
| GET/WS | `/nodes/me/stream` | Dauerverbindung: Konfig-Events mit Revision, Sendeaufträge für Agent-Kanäle, Update-Aufforderung |
| GET | `/node64/latest.json` (ohne Auth) | `{"version":"x.y.z","url":"...","notes":"..."}` für die Versionsprüfung |

Ratelimits serverseitig: pro Agent-Token und IP, Batch-Größe begrenzt (z. B. 500 Punkte), ungültige Tokens gedrosselt, eine Dauerverbindung je Node.

## 4. Benachrichtigungen über ipv64

Zwei Kanaltypen, die nur verknüpft verfügbar sind und vom **Server** gesendet werden:

- `ipv64_mail`: Mail von der ipv64-Infrastruktur, Standardkanal nach Verknüpfung, ohne eigene SMTP-Konfiguration. Empfänger: Account-Adresse oder bestätigte Integrations-Adresse.
- `ipv64_sms`: SMS über das ipv64-Gateway (`send_sms` in dbconnect.php), Tageslimit `user_class.sms_limit` wie heute.

Ablauf verknüpft: Node meldet Ereignis (`event_id`) → Server dedupliziert → ipv64-Kanäle sendet der Server, Agent-Kanäle bekommt der Node als Sendeauftrag über die Dauerverbindung. Ist der Node offline, sendet er seine Agent-Kanäle selbst (Fallback, bereits so gebaut) und ipv64 meldet den Node-Ausfall per Heartbeat. Checks, die nur eine Node misst, meldet sie seit Healthchecks 2.40.0 selbst (ipv64-Kanäle über die API v2, eigene Kanäle direkt); der hub sendet dann nur die übrigen Portal-Kanäle (`notify-direct`, siehe AUSFALLVERHALTEN.md).

## 5. Reihenfolge der Umsetzung (Vorschlag)

1. `latest.json` ausliefern (eine statische Datei), damit die Versionsprüfung des Nodes etwas findet.
2. Tabelle `nodes` + Device-Code-Flow + Portalseite `/link`.
3. Messpunkte-Upload mit `ack_seq`; Portal zeigt Agent-Checks read-only.
4. Konfig-Sync mit Revisionen (Server führend), Tombstones.
5. ipv64-Kanäle (`ipv64_mail`, `ipv64_sms`) und Sendeaufträge.
6. Dauerverbindung und Remote-Verwaltung.

Alles läuft ausschließlich über die API v2 (`api_v2.php`), keine Sonderwege.
