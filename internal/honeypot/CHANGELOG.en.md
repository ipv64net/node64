# Changes – Honeypot64

## 0.7.0 – 2026-10-20

### New
- Attacker origin: flag (emoji), country code and name as tooltip next to every IP in the event list and top sources, in the new-attacker notification and on the info page of the headless mode. New ranking “Origin by country” with coloured bars (events and source IPs per country). Country data from ipv64.net (`country_ranges.txt.gz`, daily, only downloaded when changed, cached in `/data/geoip/`), only while Honeypot64 runs; without data everything keeps working without countries.
- “What was attacked” in colour: bars per service, port and kind, split into login/brute force, exploit, scan, probe and log/syslog; decoys and detected devices as their own small ranking.
- API: `country` on events and top sources, `by_country`, `country_unknown` and `by_decoy` in the statistics. Prometheus `node64_honeypot_events_by_country_total{country}`.

## 0.6.0 – 2026-10-20

### New
- Service selection as a catalog: all trap services with switch, editable port, decoy choice and state ("free", "used by …", "open"); presets Minimal/Standard/Full, "Enable all free", "All off", extra entries for services on several ports; the text list stays under "Advanced". API `GET /api/honeypot/catalog`. Duplicate ports are checked per protocol (161/udp and 161/tcp do not conflict).
- Working together with PROXY64 (opt-in in PROXY64): decoy for requests without a matching host, analysis of accesses with rules `proxy64/*@1`, instant blocking of conspicuous IPs in PROXY64. Line on the overview and Prometheus `node64_honeypot_proxy_*`.

## 0.5.0 – 2026-10-20

Phase H6.

### New
- Login traps for databases and remote access: PostgreSQL (5432, cleartext password), MySQL (3306, switch to cleartext password, otherwise user only), MSSQL (1433), Redis (6379, plus commands that would change the configuration reported as attacks), RDP (3389, user name from the connection request), VNC (5900, login attempt).
- MikroTik API (8728, with TLS 8729), SNMP (UDP 161, community strings, never replies) and SIP (UDP 5060, scanners and digest logins, short replies never larger than the request).
- Fingerprints of attack tools: JA4 (HTTPS and TLS on TCP ports) and HASSH (SSH) in the event list, top list and report to ipv64.
- Profiles use the new traps instead of plain TCP ports; UDP services are registered as UDP in the port management.

## 0.4.0 – 2026-10-20

### New
- Login traps for FTP (21), SMTP (25/587, AUTH PLAIN/LOGIN, no relay, relay attempts are reported), POP3 (110), IMAP (143) and MQTT (1883): record user name and password and reject every login. Also selectable as own services (`ftp 21`, `smtp 587`, …) and in the mode without web interface via `NODE64_HONEYPOT_SERVICES`.
- Profiles: `standard` with FTP, SMTP, IMAP, MQTT and further ports (3306, 6379, 8006, 8123, 8291), `full` with many more ports of common web interfaces and services.
- Web decoys recognise the login calls of common devices and interfaces (routers such as FRITZ!Box, Speedport and OpenWrt, firewalls and SSL VPN, NAS, UniFi, Home Assistant, Proxmox, Grafana, Jenkins, Webmin, Portainer) and answer with a plain rejection in the matching format; user name and password are recorded, the device is in the detail (`device=…`).
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
