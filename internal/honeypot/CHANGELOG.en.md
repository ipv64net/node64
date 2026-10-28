# Changes – Honeypot64

## 0.16.1 – 2026-10-28

### Fixed
- Sensor: fixed a crash from crafted lengths in MikroTik API and SNMP on 32-bit systems (arm/v7); parser errors no longer
  stop the service.
- Log rules: firewall rules apply only to the device's syslog lines; attacker text (user agent, user name, disconnect
  text, HELO) no longer selects the IP in sshd and Postfix rules.
- SNMP and SIP (UDP, spoofable source) no longer trigger an instant PROXY64 block; per-source limit per /64 for IPv6.
- Report to ipv64: no events are lost when the stored state was lost.
- The live map shows late events; the log sensor skips FIFOs and other special files.

## 0.16.0 – 2026-10-28

### Fixed
- Overview: the numbers (events, source IPs, login attempts for 24 hours and 7 days) and the chart dropped after cleanup
  once the limit of stored events was reached (issue #7). They now come from counters per minute and per source IP that
  are only deleted after the retention period, so they stay complete. Existing events are taken over on update.

### Changed
- Hint on the overview when the limit is reached: rankings, map and event list then only go back to the oldest stored
  event.
- The limit is enforced every 10 minutes instead of hourly, so the database does not grow beyond it.

## 0.15.2 – 2026-10-27

### Changed
- Live map in full screen: the side panel sits bottom left over the Pacific instead of top right (it covered China and
  Japan), the logo top left. Applies in the container and on ipv64.net.

## 0.15.1 – 2026-10-27

### Changed
- Live map: the "Arcs now" figure in the bar below the map is gone (container and ipv64.net).

## 0.15.0 – 2026-10-27

### New
- Local block list: new option "Block detected attackers in PROXY64", in simple and expert mode, on by default. IPs the
  honeypot detects as attackers (login attempts, exploits, port scans, scanners) are blocked by PROXY64 right away for
  all hosts and streams. This works without reporting to ipv64, so the honeypot protects your own proxy directly.
  Private addresses and exceptions are never blocked; duration (default 24 hours) and the list with "Unblock" are under
  PROXY64 → Access lists. If PROXY64 is not running, the setting says so.

## 0.14.6 – 2026-10-27

### Fixed
- Report to ipv64: with the template "PROXY64 only" (`proxy`, the default), ipv64.net rejected the report
  ("sensor.profile must be one of …", 422). The portal now accepts `proxy` (portal file `api_v2_honeypot.php`).
- Log sensor: every file or pattern now has a "Remove" button (bin) that removes the row and saves right away. Before,
  the only way was to clear the row.
- The last report error is shown on the overview and settings pages only as long as no report was accepted after it.

## 0.14.5 – 2026-10-27

### New
- Firewall helper (mode without web interface): without `NODE64_IPV64_LIST_TOKEN`, Node64 fetches the list token at
  start with `NODE64_IPV64_KEY`. Entitled accounts (contributors and all plans except Standard) automatically get the
  live version of the v64 Blocklist, others the daily list.

## 0.14.4 – 2026-10-27

### Changed
- Firewall helper (mode without web interface): the v64 Blocklist is a single list now; former sub-lists in
  `NODE64_FIREWALL_LISTS` (e.g. `v64_ssh`) count as `v64`.

## 0.14.3 – 2026-10-27

### Fixed
- Live map: the fixed arc of a selected country of origin was only a hairline; now at full width.
- Label boxes no longer catch clicks – clicking a country (event filter) works again.
- "Pause" also stops arcs that were just scheduled; after a quick resume the highlight of your own country stays
  correct. When the location changes, the old country no longer stays highlighted.
- The label of your own country stays while arcs are still arriving (it flickered before).
- Older attacks are replayed only in a tick without new attacks (as described), never twice.
- Small country as location (e.g. Singapore): the target point lights up while arcs arrive.
- Tuvalu was placed outside the right edge of the map.
- Settings: the country list is sorted by language (Austria/Österreich at O, not after Cyprus), and the page no longer
  waits up to 6 seconds while the node looks up its public IPv4.
- Mode without web interface: notice "IP country data: DB-IP.com" at the map and country list of the info page.

## 0.14.2 – 2026-10-26

### Improved
- Live map: labels smaller and in a dark grey, semi-transparent box; text always 10 px, however large the map is
  (it was very large in full screen).

## 0.14.1 – 2026-10-26

### Improved
- Live map labels: flag and country code at the source and target of each arc (hidden where they would overlap),
  faint country names of the active countries, your own country lights up while arcs arrive.
- Compact numbers below the map, also outside full screen: attacks of the last hour, countries of origin, top 3
  origins with flag, top kind and arcs now.

## 0.14.0 – 2026-10-26

### New
- Live map in full screen (button next to "Live", Esc exits): map across the whole screen, side panel with the arcs
  currently shown and the top countries of origin of the last hour. Clicking a country keeps its arc and shows the
  kinds of attacks from there. Node64 logo in the corner of the map.
- Several arcs at once (up to three new ones per tick, at most twelve on the map), only from real attacks; replays
  stay fainter and are marked as replays.
- Location of the sensor can be set ("Location of the sensor": automatic or pick a country; without web interface
  `NODE64_HONEYPOT_COUNTRY`), e.g. for a hosting provider's server abroad. Target of the arcs here and – with the
  report to ipv64 – on the live map of ipv64.net. Display only, not used for rating.
- Small countries without an area on the map (Singapore, Hong Kong, Malta, Liechtenstein, Monaco and others) get a
  fixed point: arcs from and to them are drawn now.
- Country data by location: ipv64.net now delivers countries from DB-IP (location of the address instead of the
  holder's head office, gaps from the RIR data). Notice "IP country data: DB-IP.com" at the map.

## 0.13.0 – 2026-10-26

### New
- Simple mode and expert mode (switch at the top of the settings). Simple mode is the default: pick a template
  (recommended: "Only via PROXY64"), with the list of ports to forward to the node in the router (e.g. 22/tcp,
  161/udp), the start page of the web trap, notification and reporting to ipv64. All previous settings (single
  services and ports, profiles, certificate, limits, log sensor, syslog, sign-in watch) are in expert mode.
- Phone: "Recent events" shows one card per event instead of a wide table.
- Early warning with details: every hit says why the address was noticed – per origin (honeypot, log, syslog), service,
  port, kind and rule with a count, plus sensors, accounts, events and lists (last 14 days, never sensors or content).
  In the list of recent hits and in the notification (needs the current ipv64.net; older hits have no details).
- Start page of the web trap selectable: gateway terminal in Matrix style (default) or a plain sign-in form. Also
  applies to bots PROXY64 hands to the honeypot.

- Live map: on the country map of the overview, arcs fly from the source of an attack to your sensor (colour per kind,
  pulsing target, details on hover), with the latest attacks listed below. New attacks first; when nothing new comes
  in, older ones from the last hour are replayed fainter (map only). "Live" button to pause, no animation with
  "reduce motion". The target is the country of the node's public IPv4. API `GET /api/honeypot/live`.

### Changed
- "Report to ipv64" is on by default for new setups (takes effect once the central API key is set; reporting starts
  with the first run, nothing from before). Without a key, saving leaves the switch unchanged.


## 0.12.0 – 2026-10-26

### Changed
- New start page of the web trap (`/`, also for bots PROXY64 hands to the decoy): a fictional gateway terminal
  ("NODE-07 // Gateway") instead of the plain form. The form really submits (POST username/password), credentials are
  captured as before; after an attempt it shows "ACCESS DENIED". No third-party brands, no external resources. The
  other decoys (WordPress, phpMyAdmin, admin) stay plain.

## 0.11.0 – 2026-10-25

### Added
- “Only via PROXY64” preset next to minimal, standard and full: the honeypot opens no ports of its own and only gets
  what PROXY64 passes on – requests that match no host and those recognised as malicious (blocklists, reported
  attackers, exploit patterns, AI bots). Which kinds is set in PROXY64 under Access lists → Honeypot64.

### Changed
- “Only via PROXY64” is the new default. Anyone who already saved a preset or a custom selection keeps it.

## 0.10.0 – 2026-10-22

### Added
- HTTPS traps with a web server profile and the new mail traps with TLS (SMTPS 465, IMAPS 993, POP3S 995) can
  optionally present a valid certificate from the certificate manager. It can be created directly for plausible decoy
  names (DNS-01 via ipv64, optionally with A/AAAA or CNAME records). Profiles that are self-signed in the original
  (Proxmox, Webmin, NAS …) stay self-signed. The requested name (SNI) is recorded with every event.
- Watch for the Node64 login (rule `node64/login@1`): from 5 failed logins in 10 minutes per public IP (configurable)
  one event without credentials, with a notification, an instant block via PROXY64 (with its opt-in) and reporting to
  ipv64. Counted: password, TOTP, passkey, SSO, API and MCP keys. New row in the overview.
- Headless mode: `NODE64_HONEYPOT_PERSONAS`, `NODE64_HONEYPOT_HOSTNAME`, `NODE64_NAME`.

## 0.9.0 – 2026-10-22

### Added
- Service profiles per port: SSH as OpenSSH Debian 12, Ubuntu 24.04 or Dropbear (matching banner, algorithms and
  RSA/ECDSA/Ed25519 host keys), Telnet as BusyBox or Linux login, MySQL 8.0 (caching_sha2_password) or MariaDB
  10.11/11.4, web as nginx, Apache, Proxmox VE, Webmin, Home Assistant, Grafana, NAS or Elasticsearch (headers, status
  codes, unauthenticated API responses, certificate like the original, no logos).
- Defaults per port (8006 Proxmox, 10000 Webmin, 8123 Home Assistant, 3000 Grafana, 5000/5001 NAS, 9200 Elasticsearch,
  otherwise nginx), selectable in the trap service table, configurable trap hostname.
- Hostname, versions and certificate data vary per sensor and stay stable (derived from the sensor ID), so sensors
  don't share one fingerprint. Device logins with their own profile only answer on that profile's port.

## 0.8.1 – 2026-10-21

### Fixed
- Port overview (Settings › Ports): trap services and the syslog receiver report why a port is not open; a syslog port taken by another part in the meantime is shown as configured with the error instead of not at all.

## 0.8.0 – 2026-10-20

### New
- Country map on the overview: world map with countries coloured in five levels by events in the selected period (logarithmic, light/dark), tooltip with flag, name, events and source IPs, legend. Clicking a country filters the event list by that country (no JavaScript needed). Map data Natural Earth 1:110m (public domain) embedded, nothing is loaded from the network. The same map (7 days) on the info page of the headless mode.
- Filter by country: `GET /api/honeypot/events?country=DE`, in the web interface `/honeypot?country=DE`.
- Dashboard card with more information: events 24 h with trend versus the previous 24 h, top 3 countries as flags, most attacked service, reporting to ipv64 (off/ok/error with time), failed trap services with a hint, requests via PROXY64.

## 0.7.0 – 2026-10-20

### New
- Flags on Windows too: small flag font (Twemoji, CC-BY 4.0) in the web interface that only applies to country flags.
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
