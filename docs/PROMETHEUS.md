# Prometheus-Schnittstelle

Node64 stellt seine Kennzahlen unter `GET /api/metrics` im Textformat von Prometheus bereit. Dazu gehören die Werte
des Kerns und die aller laufenden Module. Ausgeschaltete oder gestoppte Module liefern keine Werte, nur
`node64_module_running{module="…"} 0`.

## Einrichten

1. Unter **Einstellungen → API-Keys** einen eigenen Key anlegen, z. B. `prometheus`.
2. In Prometheus einen Scrape-Job anlegen:

```yaml
scrape_configs:
  - job_name: node64
    scheme: https            # oder http, je nach Weboberfläche
    metrics_path: /api/metrics
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/node64.key   # Inhalt: node64_...
    tls_config:
      insecure_skip_verify: true   # nur bei selbstsigniertem Zertifikat der Oberfläche
    static_configs:
      - targets: ["192.168.10.30:8090"]
```

Test von Hand:

```bash
curl -s -H "Authorization: Bearer $(cat node64.key)" http://192.168.10.30:8090/api/metrics | head
```

Eine Abfrage braucht nur wenige Millisekunden, ein Intervall von 15 bis 60 Sekunden ist passend. Jede Abfrage setzt
beim API-Key „zuletzt benutzt“. Falsche Keys bremst Node64 wie bei der übrigen API aus.

## Kern

| Metrik | Labels | Bedeutung |
|---|---|---|
| `node64_info` | `version`, `node_id`, `node_name`, `hostname` | immer 1 |
| `node64_start_time_seconds`, `node64_uptime_seconds` | | Start (Unix-Zeit) und Laufzeit |
| `node64_database_bytes` | | Größe der Datenbank inkl. WAL |
| `node64_module_enabled`, `node64_module_running`, `node64_module_error` | `module` | 1/0 |
| `node64_module_info` | `module`, `version` | immer 1 |
| `node64_link_linked`, `node64_link_connected` | | Verknüpfung mit ipv64.net, Verbindung zum Hub |
| `node64_link_outbox`, `node64_link_conflicts` | | noch nicht übertragene Einträge, offene Konflikte |
| `node64_link_last_sync_seconds` | | letzter Abgleich (Unix-Zeit) |
| `node64_link_online_checks_today`, `node64_link_online_checks_limit` | | Online-Messungen heute / Tageslimit (0 = keins) |
| `node64_group_members`, `node64_group_members_online` | | lokale Gruppe |
| `node64_group_member_up` | `node_id`, `node_name` | Mitglied erreichbar |
| `go_goroutines`, `go_memstats_heap_alloc_bytes`, `go_memstats_sys_bytes`, `go_gc_cycles_total` | | Laufzeit von Go |
| `node64_scrape_duration_seconds` | | Dauer der Abfrage |

## Healthchecks

Labels je Check: `token` (bleibt gleich, auch wenn der Name sich ändert), `check` (Name), `type`, `group`.

| Metrik | Bedeutung |
|---|---|
| `node64_hc_check_state{…,state}` | immer 1, Zustand im Label: `up`, `down`, `degraded`, `flapping`, `dependent`, `stabilizing`, `paused`, `pending`, `unchecked` |
| `node64_hc_check_up` | 1 erreichbar (`up`, `degraded`), 0 gestört; fehlt bei pausiert, wartend und nicht überwacht |
| `node64_hc_check_maintenance` | gerade in einer Wartung |
| `node64_hc_check_last_seconds`, `node64_hc_check_latency_seconds` | letzte Messung (Unix-Zeit) und deren Antwortzeit |
| `node64_hc_check_consecutive_failures` | Fehlschläge in Folge |
| `node64_hc_check_interval_seconds` | Prüfintervall |
| `node64_hc_check_cert_expiry_seconds` | Ablauf des TLS-Zertifikats (Unix-Zeit, nur HTTPS-Checks) |
| `node64_hc_checks{state}` | Anzahl je Zustand, `maintenance` zählt zusätzlich |
| `node64_hc_incidents_open` | offene Störungen |

## DynDNS

| Metrik | Labels | Bedeutung |
|---|---|---|
| `node64_dyndns_target_status` | `target`, `status` | immer 1, Zustand im Label: `ok`, `cdn`, `pending`, `dns`, `error`, `paused`, `off`, `new` |
| `node64_dyndns_target_ok` | `target` | 1 letzte Aktualisierung erfolgreich, 0 Fehler; fehlt bei aus, pausiert, neu |
| `node64_dyndns_target_last_ok_seconds`, `node64_dyndns_target_last_error_seconds` | `target` | Unix-Zeit |
| `node64_dyndns_targets` | `status` | Anzahl je Zustand |
| `node64_dyndns_updates_24h` | | Aufrufe bei ipv64.net in 24 Stunden |

## DNS64

Die Zähler laufen seit dem letzten Start des DNS-Servers. Eine Änderung der Einstellungen startet ihn neu; `rate()`
und `increase()` kommen damit zurecht.

| Metrik | Labels | Bedeutung |
|---|---|---|
| `node64_dns64_up` | | DNS-Server läuft |
| `node64_dns64_start_time_seconds` | | Start des DNS-Servers (Unix-Zeit) |
| `node64_dns64_blocking_paused` | | Blockieren pausiert |
| `node64_dns64_queries_total` | `status`, `proto` | Anfragen; `status`: `allowed`, `cached`, `blocked`, `local`, `error`, `custom`; `proto`: `udp`, `tcp`, `doh`, `dot`, `doq` |
| `node64_dns64_query_duration_seconds_sum`, `…_count` | | Summe und Anzahl der Antwortzeiten (Mittelwert über `rate(sum)/rate(count)`) |
| `node64_dns64_querylog_dropped_total` | | nicht ins Abfrage-Log geschriebene Einträge |
| `node64_dns64_refused_total` | | abgewiesen, weil von außerhalb der erlaubten Netze |
| `node64_dns64_blocklist_domains` | | Domains in den Blocklisten |
| `node64_dns64_cache_entries`, `node64_dns64_cache_max_entries` | | Cache |
| `node64_dns64_cache_hits_total`, `…_misses_total`, `…_stale_served_total` | | Cache-Treffer |
| `node64_dns64_upstream_up` | `upstream`, `proto` | Upstream gesund |
| `node64_dns64_upstream_requests_total`, `node64_dns64_upstream_errors_total` | `upstream`, `proto` | Anfragen und Fehler |
| `node64_dns64_upstream_latency_seconds` | `upstream`, `proto` | mittlere Antwortzeit |

Anteil blockierter Anfragen der letzten Stunde:

```promql
sum(increase(node64_dns64_queries_total{status="blocked"}[1h])) / sum(increase(node64_dns64_queries_total[1h]))
```

## Beispiele für Alarme

```yaml
groups:
  - name: node64
    rules:
      - alert: Node64CheckDown
        expr: node64_hc_check_up == 0 and on(token) node64_hc_check_maintenance == 0
        for: 2m
        annotations:
          summary: "{{ $labels.check }} ist gestört"
      - alert: Node64CertExpiresSoon
        expr: node64_hc_check_cert_expiry_seconds - time() < 14 * 86400
        annotations:
          summary: "Zertifikat von {{ $labels.check }} läuft in unter 14 Tagen ab"
      - alert: Node64DynDNSError
        expr: node64_dyndns_target_ok == 0
        for: 15m
      - alert: Node64DNSUpstreamDown
        expr: node64_dns64_upstream_up == 0
        for: 5m
      - alert: Node64HubDisconnected
        expr: node64_link_linked == 1 and node64_link_connected == 0
        for: 10m
```

## Für Module

Ein Modul liefert Werte, indem es `module.MetricsProvider` umsetzt:

```go
func (m *Module) Metrics(ctx context.Context, w *metrics.Writer) {
	w.Gauge("node64_<modul>_<name>", "Hilfetext", wert, "label", "wert")
	w.Counter("node64_<modul>_<name>_total", "Hilfetext", zaehler)
}
```

Namen beginnen mit `node64_<modul>_`. Zähler, die nur steigen, enden auf `_total`. Zeitpunkte werden als Unix-Zeit
in Sekunden (`_seconds`) angegeben, Dauern in Sekunden und Datenmengen in Bytes (`_bytes`). Der Writer fasst
gleichnamige Werte zu einer Familie zusammen und lässt ungültige Namen weg. Die Werte sollen ohne teure Abfragen
auskommen.
