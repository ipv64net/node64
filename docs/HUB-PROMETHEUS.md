# hub-Server: Prometheus (nur für den Betreiber)

Stand 2026-11-04. Die hubs (hc-srv01/02) liefern ihre Zahlen unter `GET /metrics`. Code: `internal/hub/httpapi`
(`server.go`, `metrics.go`), Zähler in `internal/hub/store/store.go` und `metrics.go`.

## Zugang

| Was | Wert |
|---|---|
| Port | `metrics_listen` in der hub-Konfiguration, z. B. `10.10.0.10:9464` (internes Netz) |
| Erlaubte Absender | `metrics_allow` (IPs oder Netze, z. B. `10.10.0.0/24`); leer = jeder, der die Adresse erreicht |
| Falscher Absender | `403` |
| Lokal | `/metrics` auch auf dem normalen `listen`-Port |

Alle Zähler (`_total`, `_sum`, `_count`) laufen seit dem Start des hub und beginnen nach einem Neustart bei 0. In
Prometheus deshalb immer mit `rate()` bzw. `increase()` auswerten.

## Checks und Messungen

| Metrik | Art | Labels | Bedeutung |
|---|---|---|---|
| `hub_checks` | gauge | | Geladene Checks dieses hub (alle Typen) |
| `hub_checks_by_type` | gauge | `type` | Geladene Checks je Typ |
| `hub_check_runs_total` | counter | `type`, `result` (`ok`/`fail`) | Ausgeführte Läufe dieses hub je Typ und Ergebnis (nach Invertierung) |
| `hub_check_duration_seconds_sum` / `_count` | summary | `type` | Laufzeit der Läufe je Typ; Mittelwert = `_sum / _count` |
| `hub_ping_packets_sent_total` | counter | | Gesendete Ping-Pakete (IPv4 und IPv6 zusammen) |
| `hub_ping_packets_lost_total` | counter | | Davon ohne Antwort |
| `hub_checks_throttled_total` | counter | | Läufe, die die Bremse ausgelassen hat (je Zielhost bzw. Server) |
| `hub_measurements_total` | counter | | Gespeicherte Messungen (eigene und von Nodes gemeldete) |
| `hub_measurement_errors_total` | counter | | Messungen, die nicht gespeichert wurden (Puffer voll, Schreibfehler) |
| `hub_verdicts_total` | counter | | Bewertungen des Gesamtzustands |
| `hub_overall_changes_total` | counter | | Wechsel des Gesamtzustands |
| `hub_slot_index`, `hub_slot_mod` | gauge | | Anteil dieses hub an den Checks (Slot x von y) |

Werte für `type`: `http`, `keyword`, `json`, `dns`, `icmp` (Ping), `tcp`, `port`, `cert`, `whois`, `push`, `docker`.
Gezählt werden nur die Läufe, die dieser hub selbst ausführt, nicht die Messungen der Nodes (lokale Checks), keine
Testläufe und keine Push-Checks (die laufen nicht, sie warten auf Meldungen; sie stehen nur in `hub_checks_by_type`).
Von der Bremse oder dem Tageskontingent ausgelassene Läufe zählen nicht als Lauf.

## Datenbank

| Metrik | Art | Labels | Bedeutung |
|---|---|---|---|
| `hub_db_ok` | gauge | | 1 = Datenbank erreichbar |
| `hub_db_errors_total` | counter | | Datenbankfehler |
| `hub_db_write_seconds_sum` / `_count` | summary | `op` | Dauer der Schreibvorgänge je Art, auch fehlgeschlagene |
| `hub_db_pool_max` | gauge | | Höchstzahl offener Verbindungen (0 = unbegrenzt) |
| `hub_db_pool_open`, `hub_db_pool_in_use`, `hub_db_pool_idle` | gauge | | Verbindungen: offen, gerade benutzt, frei |
| `hub_db_pool_waits_total` | counter | | Wie oft auf eine freie Verbindung gewartet werden musste |
| `hub_db_pool_wait_seconds_total` | counter | | Summe dieser Wartezeit |
| `hub_measurement_buffer` | gauge | | Eigene Messungen, die auf das Schreiben warten |
| `hub_measurement_buffer_capacity` | gauge | | Größe dieses Puffers (10000); ist er voll, gehen Messungen verloren |
| `hub_cleanup_last_success_timestamp_seconds` | gauge | | Letzte fehlerfreie tägliche Aufräumrunde (Löschfristen), Unix-Zeit; 0 = seit dem Start keine |

Werte für `op`:
- `measurements`: eigene Messungen, gebündelt alle 0,5 s bzw. je 500
- `node_measurements`: Messungen der Nodes, gebündelt, mit bis zu drei Versuchen
- `states`: Zustand je Check nach jedem Lauf
- `events`: Statuswechsel

Die tägliche Aufräumrunde macht nur der Housekeeper. Auf dem anderen hub bleibt
`hub_cleanup_last_success_timestamp_seconds` deshalb 0.

## Laufzeit

| Metrik | Art | Bedeutung |
|---|---|---|
| `hub_uptime_seconds` | gauge | Sekunden seit dem Start |
| `hub_nodes` | gauge | Lebende hub-Instanzen (nur beim Housekeeper gesetzt) |
| `hub_gateway_connections` | gauge | Offene Verbindungen der Nodes |
| `hub_goroutines`, `hub_memory_heap_bytes`, `hub_memory_sys_bytes` | gauge | Go-Laufzeit |

## Beispiele (PromQL)

```promql
# Läufe je Typ pro Minute
sum by (type) (rate(hub_check_runs_total[5m])) * 60

# Fehlerquote je Typ
sum by (type) (rate(hub_check_runs_total{result="fail"}[5m])) / sum by (type) (rate(hub_check_runs_total[5m]))

# mittlere Laufzeit je Typ (Sekunden)
rate(hub_check_duration_seconds_sum[5m]) / rate(hub_check_duration_seconds_count[5m])

# Pings pro Minute und Verlustquote
rate(hub_ping_packets_sent_total[5m]) * 60
rate(hub_ping_packets_lost_total[5m]) / rate(hub_ping_packets_sent_total[5m])

# mittlere Schreibdauer je Art (Sekunden)
rate(hub_db_write_seconds_sum[5m]) / rate(hub_db_write_seconds_count[5m])

# Alarm: tägliche Aufräumrunde seit mehr als 26 Stunden nicht gelaufen (nur Housekeeper)
time() - max(hub_cleanup_last_success_timestamp_seconds) > 26 * 3600
```
