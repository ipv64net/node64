# Changes – Honeypot64

## 0.1.0 – 2026-10-20

First version (phase H1): lightweight low-interaction honeypot as a module with web interface.

### New
- Trap services SSH, Telnet, HTTP/HTTPS (neutral login decoys) and any TCP port: logins are accepted and always rejected, nothing is executed, no outgoing connections.
- Profiles `minimal`, `standard` and `full` or a custom selection (service, port, decoy); port scan detection and limits per source IP.
- Port check via the node's port management: ports that PROXY64, DNS64, streams or the web interface have open are a field error for a custom selection; a profile leaves them out and says so.
- Honeypot64 page: state of the services, numbers for 24 hours and 7 days (events, source IPs, logins), timeline, top lists (source IPs, kinds, ports, services, user names, passwords, credentials, paths, user agents) and the latest events with payload as text and hex.
- Storage in the node's database: retention (default 7 days) and limit adjustable, delete data.
- Notification about new attackers (off by default): at most one bundled message per hour with the count and the first IPs.
- API `/api/honeypot/status`, `/stats`, `/events`, `/config` (GET/PUT), `DELETE /api/honeypot/events`; changes go to the audit log.
- Prometheus: `node64_honeypot_connections_total{service,port}`, `node64_honeypot_logins_total{service}`, `node64_honeypot_events_total{kind,source}`, `node64_honeypot_unique_sources`, `node64_honeypot_listen_errors{port}`, `node64_honeypot_buffer_events`, `node64_honeypot_dropped_total`.
- Export/import of the settings; dashboard card.
- When the module is off, no port is open and nothing runs.
