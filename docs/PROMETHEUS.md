# Prometheus-Schnittstelle

Node64 stellt seine Kennzahlen unter `GET /api/metrics` im Textformat von Prometheus bereit. Dazu gehören die Werte
des Kerns und die aller laufenden Module. Ausgeschaltete oder gestoppte Module liefern keine Werte, nur
`node64_module_running{module="…"} 0`.

Die CDN64-Server srv07/srv08 haben eine eigene Schnittstelle nur für den Betreiber: [CDN64-EDGE-PROMETHEUS.md](CDN64-EDGE-PROMETHEUS.md).

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

Proxmox VE (Healthchecks → Proxmox VE): `node64_pve_up{system}`, `node64_pve_poll_failures_total`,
`node64_pve_guest_state{system,node,type,vmid,name,state}`, CPU/RAM/Disk je Node und Gast
(`node64_pve_node_*_ratio`, `node64_pve_guest_*_ratio`), Netz und Disk-I/O je Gast (`node64_pve_guest_net_*_bytes`, `node64_pve_guest_disk_*_bytes`) – Liste in [PROXMOX.md](PROXMOX.md#prometheus).

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
| `node64_dns64_group_queries_total` | `group`, `status` | Anfragen je Gerätegruppe und Ergebnis |
| `node64_dns64_group_internet_off` | `group` | Internet aus für die Gruppe (Knopf oder Zeitplan) |
| `node64_dns64_group_free` | `group` | Knopf „Frei“ aktiv (Zeitpläne und Kategorien ausgesetzt) |
| `node64_dns64_group_members` | `group` | Einträge (MAC, IP, Netz) der Gruppe |

Anteil blockierter Anfragen der letzten Stunde:

```promql
sum(increase(node64_dns64_queries_total{status="blocked"}[1h])) / sum(increase(node64_dns64_queries_total[1h]))
```

## PROXY64 und CDN64

Beide heißen technisch `cdn64`, daher beginnen die Metriken mit `node64_cdn64_` (PROXY64, der lokale
Reverse-Proxy) bzw. `node64_cdn64_online_` (CDN64 über srv07/srv08).

Labels je Host: `host_id` (bleibt gleich), `host` (erster Name), `kind` (`proxy`, `redirect`, `dead`, `passthrough`).

| Metrik | Labels | Bedeutung |
|---|---|---|
| `node64_cdn64_hosts` | | Anzahl Hosts |
| `node64_cdn64_host_enabled` | Host | 1 eingeschaltet, 0 aus |
| `node64_cdn64_host_requests_total`, `node64_cdn64_host_errors_total`, `node64_cdn64_host_blocked_total` | Host | Anfragen, Fehler (5xx, Ziel nicht erreichbar) und Abgewiesene seit dem Start der Node |
| `node64_cdn64_host_requests_24h` | Host, `status` (`2xx` … `5xx`) | Anfragen der letzten 24 Stunden je Statusklasse |
| `node64_cdn64_host_bytes_24h`, `node64_cdn64_host_blocked_24h` | Host | gesendete Bytes und Abgewiesene der letzten 24 Stunden |
| `node64_cdn64_host_target_up`, `node64_cdn64_host_target_latency_seconds` | Host | Ziel erreichbar (letzte Prüfung) und Verbindungszeit; nur Proxy und TLS durchreichen |
| `node64_cdn64_online_name` | `host_id`, `name`, `mode` | Name über srv07/srv08 eingeschaltet (immer 1) |
| `node64_cdn64_online_edge_connected` | `edge` | Tunnel zum Server verbunden |
| `node64_cdn64_online_edge_rtt_seconds` | `edge`, `transport` | Laufzeit des Tunnels |
| `node64_cdn64_online_edge_streams`, `…_streams_total`, `…_reconnects_total` | `edge` | offene Besucher-Streams, Streams und Neuverbindungen seit dem Start |
| `node64_cdn64_online_host_status` | `name`, `mode`, `status` | Zustand bei ipv64 (immer 1): `active`, `pending`, `blocked` |
| `node64_cdn64_online_host_traffic_month_bytes` | `name` | Traffic über srv07/srv08 im Monat |
| `node64_cdn64_online_domains_used`, `…_domains_limit` | | CDN-Domains des Accounts (altes CDN zählt mit) |
| `node64_cdn64_online_traffic_used_bytes`, `…_traffic_limit_bytes` | | CDN-Traffic des Accounts im Monat |
| `node64_cdn64_online_last_sync_seconds`, `node64_cdn64_online_sync_ok` | | letzter Abgleich mit ipv64 (Unix-Zeit) und ob er klappte |

Die Werte von CDN64 (`node64_cdn64_online_*`) stammen aus dem letzten Abgleich der Node (jede Minute), nicht aus einer Abfrage bei
ipv64.

## Zertifikate

| Metrik | Labels | Bedeutung |
|---|---|---|
| `node64_certs` | | Anzahl Zertifikate |
| `node64_cert_expiry_seconds` | `cert_id`, `name`, `source` | Ablauf (Unix-Zeit) |
| `node64_cert_status` | `cert_id`, `name`, `source`, `status` | immer 1, Zustand im Label |
| `node64_cert_error` | `cert_id`, `name`, `source` | 1 letzter Abruf bzw. letzte Erneuerung gescheitert |
| `node64_cert_auto_renew` | `cert_id`, `name`, `source` | 1 wird automatisch erneuert |

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
      - alert: Node64CertExpires
        expr: node64_cert_expiry_seconds - time() < 14 * 86400 and on(cert_id) node64_cert_auto_renew == 1
        annotations:
          summary: "Zertifikat {{ $labels.name }} läuft in unter 14 Tagen ab (Erneuerung klappt nicht?)"
      - alert: Node64CDN64TargetDown
        expr: node64_cdn64_host_target_up == 0 and on(host_id) node64_cdn64_host_enabled == 1
        for: 5m
      - alert: Node64CDN64TunnelDown
        expr: node64_cdn64_online_edge_connected == 0
        for: 3m
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
