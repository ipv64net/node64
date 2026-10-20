# Changes – Honeypot64

## 0.4.0 – 2026-10-20

### New
- Login traps for FTP (21), SMTP (25/587, AUTH PLAIN/LOGIN, no relay, relay attempts are reported), POP3 (110), IMAP (143) and MQTT (1883): record user name and password and reject every login. Also selectable as own services (`ftp 21`, `smtp 587`, …) and in the mode without web interface via `NODE64_HONEYPOT_SERVICES`.
- Profiles: `standard` with FTP, SMTP, IMAP, MQTT and further ports (3306, 6379, 8006, 8291), `full` with many more ports of common web interfaces and services.
- Credentials of all login traps go into the report to ipv64 (before only SSH, Telnet, HTTP/HTTPS).

## 0.3.0 – 2026-10-20

Log sensor, syslog receiver and early warning for your own networks (phase H5).

### New
- Early warning (tab "Early warning"): manage your own networks (stored at ipv64), your DynDNS IPs are watched automatically; hits are fetched every 30 minutes and sent as one bundled notification. Networks without proof only report IPs that are listed on the v64 Blocklist, DynDNS IPs report every sighting. Needs the central API key, not the report setting.
- Log sensor: reads logs of real services (sshd, nginx/Apache/Caddy, Postfix/Dovecot, Proxmox, Nextcloud, Vaultwarden, Gitea/Forgejo, Home Assistant) and detects attacks with bundled, versioned rules above a threshold. Files with format under Settings › "Log sensor and syslog", suggestions for common paths at the push of a button; paths below `/host/log`, `/var/log` and `/data/logs` are allowed (mount `-v /var/log:/host/log:ro`, for `auth.log` also `--group-add 4`).
- Syslog receiver on UDP and TCP (one port, e.g. 514) for routers and firewalls (MikroTik, OPNsense/pfSense, FortiGate, Sophos, UniFi); allowed senders only (default private networks and localhost). The port is checked against the port management like the traps (UDP and TCP).
- From real logs only IP, kind, service, port, count and rule are stored and reported – no user names, passwords, paths, user agents or content. Samples in the report to ipv64 come from the honeypot only; sources carry `source` (`honeypot`, `log`, `syslog`) and the rule.
- State per file (e.g. "no read permission – container needs --group-add 4") and of the syslog receiver in the settings, on the overview and in `GET /api/honeypot/status` (`logs`).
- Event list with sensor (honeypot, log, syslog) and rule, filter by sensor (also `GET /api/honeypot/events?source=`); statistics with a top list of sensors (`by_source`).
- Prometheus: `node64_honeypot_events_total{kind,source}` with the real source, `node64_honeypot_log_lines_total`, `node64_honeypot_log_file_ok{path}`, `node64_honeypot_syslog_messages_total`, `node64_honeypot_syslog_denied_total`.
- Mode without web interface: `NODE64_HONEYPOT_LOGS`, `NODE64_HONEYPOT_SYSLOG_PORT`, `NODE64_HONEYPOT_SYSLOG_ALLOW`; state on the info page. No profile switches the log sensor on by itself.
- Export/import of the settings including log sensor and syslog; if the syslog port is taken on the target node, syslog stays off.

## 0.2.1 – 2026-10-20

### Fixed
- When first switched on, the module briefly opened the ports of the default profile before an own selection applied.
  Now everything stays closed until the settings have been saved once.

## 0.2.0 – 2026-10-20

Reporting to ipv64 (phase H2).

### New
- Switch "Report to ipv64" (off by default, needs the central ipv64 API key): every 10 minutes, source IPs with kind, service, port and count as well as samples (credentials from the honeypot, paths, user agents, start of payloads with SHA-256) are sent to ipv64 in format `schema: 1`. The data feeds into the v64 blocklist as soon as the evaluation at ipv64 is running.
- Never reported: your own IP and sources from private or reserved networks (RFC 1918, CGNAT, loopback, link-local, ULA, documentation ranges); they stay visible locally.
- The period since the last successful report is sent (at most 7 days, in pieces of at most one hour, six hours when catching up more than a day, gzip, at most one report per 2 minutes); after an outage it catches up, on errors with backoff (Retry-After is respected). Without events a short sign of life is sent so ipv64 can count active sensors. Switching it on starts a new period.
- Fixed sensor ID per installation (UUID); version, profile and mode are sent along.
- State (last report, last error, next attempt, reported source IPs today/since start, sources last rejected by ipv64 with reason) on the overview, in the settings and in `GET /api/honeypot/status` (`report`).
- Prometheus: `node64_honeypot_report_last_success_timestamp`, `node64_honeypot_report_errors_total`, `node64_honeypot_report_sources_total`.
- Mode without web interface: reporting is on when `NODE64_IPV64_KEY` is set (switch off with `NODE64_HONEYPOT_REPORT=0`); state on the info page and in `/metrics`.

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
