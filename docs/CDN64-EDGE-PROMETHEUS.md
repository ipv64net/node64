# CDN64-Server: Prometheus (nur für den Betreiber)

Stand 2026-10-20 (cdn64-edge 0.13.1). Die CDN64-Server srv07/srv08 liefern ihre Zahlen auf einem eigenen Port – nicht
öffentlich: nur für die eingetragenen Adressen und nur mit Bearer-Token. Code: `internal/cdnedge/promexport.go`.

## Zugang

| Was | Wert |
|---|---|
| Port | `metrics_listen` in `/etc/cdn64-edge/config.yaml`, z. B. `":9464"` (TCP, Pfad `/metrics`) |
| Erlaubte Absender | `metrics_allow` (IPs oder Netze). **Leer = Port zu**, der Dienst öffnet ihn gar nicht |
| Token | Bearer-Token aus `metrics_token_file` (Standard `/var/lib/cdn64-edge/metrics-token`, 64 Hex-Zeichen). Fehlt die Datei, legt der Dienst beim Start eins an (Datei 0600, Besitzer cdn64-edge) |
| Falsche Adresse | Verbindung wird beim Annehmen geschlossen (die Firewall lässt sie ohnehin nicht durch) |
| Falsches/fehlendes Token | `403`, kein Inhalt |
| Firewall | `setup-edge.sh` mit `METRICS_ALLOW="ip …"` (optional `METRICS_PORT`) öffnet den Port nur für diese Adressen |

Einrichten (je Server, erst nach Freigabe):

```yaml
# /etc/cdn64-edge/config.yaml
metrics_listen: ":9464"
metrics_allow: ["203.0.113.7"]   # Quell-IP des Prometheus
```

```bash
METRICS_ALLOW="203.0.113.7" bash setup-edge.sh srv07 nbg srv07.cdn64.de <nachbar-ipv4> <nachbar-ipv6>
systemctl restart cdn64-edge
cat /var/lib/cdn64-edge/metrics-token   # nur fuer den Prometheus, nie in Chats/Logs
```

Beide Server haben eigene Tokens. Auf dem Prometheus je Server eine Datei mit dem Token ablegen (0600).

## prometheus.yml

```yaml
scrape_configs:
  - job_name: cdn64-srv07
    scheme: http
    metrics_path: /metrics
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/cdn64-srv07.token
    static_configs:
      - targets: ["srv07.cdn64.de:9464"]
  - job_name: cdn64-srv08
    scheme: http
    metrics_path: /metrics
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/cdn64-srv08.token
    static_configs:
      - targets: ["srv08.cdn64.de:9464"]
```

(`bearer_token_file:` statt `authorization:` geht bei älteren Prometheus-Versionen genauso.) Die Verbindung ist
Klartext-HTTP; der Schutz sind Absenderliste, Firewall und Token. Liegt der Prometheus nicht im selben vertrauten Netz,
den Weg über WireGuard o. Ä. führen.

## Werte

Alle Zeilen tragen `server` (srv07/srv08). Zähler (`_total`) zählen seit dem Start des Dienstes.

| Name | Labels | Bedeutung |
|---|---|---|
| `cdn64_edge_info` | `version`, `location`, `go` | immer 1 |
| `cdn64_edge_start_time_seconds` | | Start (Unix-Zeit), Uptime = `time() - …` |
| `cdn64_edge_goroutines`, `cdn64_edge_memory_heap_bytes`, `cdn64_edge_memory_sys_bytes` | | Go-Laufzeit |
| `cdn64_edge_tunnels` | | Tunnel mit mindestens einer Verbindung |
| `cdn64_edge_tunnel_connections` | `transport` (quic, tcp) | Tunnel-Verbindungen der Nodes (tcp = Ausweichweg, auch über 443) |
| `cdn64_edge_streams`, `cdn64_edge_streams_total` | | Besucher-Streams durch Tunnel (gerade / gesamt) |
| `cdn64_edge_hosts` | `mode` (1, 2, 3) | eingeschaltete Namen |
| `cdn64_edge_accounts` | | Accounts mit mindestens einem Namen |
| `cdn64_edge_hosts_blocked` | `reason` (z. B. traffic) | von ipv64 gesperrte Namen (Kontingent) |
| `cdn64_edge_bytes_total` | `direction` (in = Besucher → Node, out) | Verkehr gesamt |
| `cdn64_edge_connections_total`, `cdn64_edge_via_peer_total`, `cdn64_edge_no_tunnel_total` | | Verbindungen gesamt, über den Nachbarn, ohne Tunnel |
| `cdn64_edge_account_bytes_total` | `account_id`, `direction` | Verkehr je Account |
| `cdn64_edge_account_connections_total` | `account_id` | Verbindungen je Account |
| `cdn64_edge_host_bytes_total`, `cdn64_edge_host_connections_total`, `cdn64_edge_host_requests_total` | `host`, `mode`, `account_id` (`direction`) | je Name, nur die 200 Namen mit dem meisten Verkehr |
| `cdn64_edge_hosts_with_traffic` | | Namen mit Verkehr (zeigt, ob die 200 überschritten sind) |
| `cdn64_edge_requests_total` | `mode` (2, 3), `status` (1xx–5xx, aborted), `http` (1, 2, 3) | Anfragen, die der Server selbst beantwortet |
| `cdn64_edge_requests_rejected_total` | `reason` (misdirected, req_rate, acl, blocked, blocklist) | abgewiesene Anfragen (Modus 2/3) |
| `cdn64_edge_connections_open` | | offene Besucher-Verbindungen |
| `cdn64_edge_connections_tracked` | | lange Verbindungen, die nach jeder Konfiguration neu geprüft werden |
| `cdn64_edge_guard_rejected_total` | `reason` (blocklist, max_conns, conns, conn_rate) | vom Schutz abgewiesene Verbindungen |
| `cdn64_edge_blocklist_entries` | | Einträge der Blocklisten (Spamhaus DROP) |
| `cdn64_edge_quic_passthrough` | | durchgereichte HTTP/3-Besucher (Modus 1) |
| `cdn64_edge_load_mbit`, `cdn64_edge_capacity_mbit` | | Durchsatz gerade, Kapazität der fairen Drossel |
| `cdn64_edge_throttled_accounts`, `cdn64_edge_account_throttle_mbit` | `account_id` | faire Drossel gerade |
| `cdn64_edge_account_rate_mbit` | `account_id` | Durchsatz der Accounts mit Klassen-Limit |
| `cdn64_edge_certificates`, `cdn64_edge_certificate_min_days` | | Zertifikate (Modus 2/3), Tage bis zum ersten Ablauf |
| `cdn64_edge_certificate_orders_total` | `ca` (letsencrypt, zerossl), `result` (ok, error) | Bestellungen |
| `cdn64_edge_letsencrypt_week` | `domain` | neue LE-Zertifikate in 7 Tagen je registrierter Domain (Grenze 50) |
| `cdn64_edge_letsencrypt_cooldown` | | Domains, die gerade zu ZeroSSL gehen |
| `cdn64_edge_config_age_seconds`, `cdn64_edge_config_ok`, `cdn64_edge_config_errors_total` | | Abruf der Konfiguration bei ipv64 |
| `cdn64_edge_config_info` | `version`, `hosts` | Stand der Konfiguration |
| `cdn64_edge_peer_up` | | 1 = Nachbarserver hat sich in den letzten 5 s gemeldet (Raten, jede Sekunde, auch ohne Verkehr) |
| `cdn64_edge_portmap_ports` | `transport` | offene Portmapper-Ports |
| `cdn64_edge_portmap_udp_sessions` | | offene UDP-Sitzungen des Portmappers |

Verkehr des Portmappers steckt in den Werten je Name (Modus 3).

## Grafana (Beispiele)

```promql
# Durchsatz je Server (Mbit/s)
sum by (server) (rate(cdn64_edge_bytes_total[5m])) * 8 / 1e6
# Top 10 Accounts nach Verkehr in 24 h (GB)
topk(10, sum by (account_id) (increase(cdn64_edge_account_bytes_total[24h]))) / 1e9
# Tunnel je Protokoll
sum by (server, transport) (cdn64_edge_tunnel_connections)
# Anteil 5xx der Anfragen (Modus 2/3)
sum(rate(cdn64_edge_requests_total{status="5xx"}[5m])) / sum(rate(cdn64_edge_requests_total[5m]))
# Abweisungen durch den Schutz je Grund
sum by (reason) (rate(cdn64_edge_guard_rejected_total[5m]))
# Uptime (Stunden)
(time() - cdn64_edge_start_time_seconds) / 3600
```

Alarme (Vorschlag): `cdn64_edge_config_age_seconds > 300`, `cdn64_edge_peer_up == 0` für 2 min,
`cdn64_edge_certificate_min_days < 10`, `max(cdn64_edge_letsencrypt_week) > 40`, `cdn64_edge_throttled_accounts > 0`
für 15 min, `up == 0`.
