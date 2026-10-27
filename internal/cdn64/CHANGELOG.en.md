# Changes – PROXY64

## 1.34.3 – 2026-10-27

### Changed
- Proxy host list: the "Options" column now wraps and is narrower, for example with an access list. The healthcheck
  badges get the freed space and wrap less often.
- Traffic (↓/↑) without the separator dot: when the line wrapped it ended up at the start or end of a line.

## 1.34.2 – 2026-10-27

### Fixed
- Proxy host list: the neighbouring columns squeezed domains and target to one character wide, so they wrapped
  character by character. They now keep a minimum width. So that the table fits common screen widths (around
  1440 pixels) without scrolling sideways, the healthcheck badges, the CDN64 details, the traffic (↓/↑) and the buttons
  at the end of the row may wrap to a second line.

## 1.34.1 – 2026-10-27

### Changed
- Business plan with CDN64: 2 parallel tunnel connections per server instead of 4 and 10 TB CDN traffic per month
  instead of 20 TB. Company stays at 4 connections and 20 TB. The values come from ipv64.net (portal SQL
  `business_cdn_limits.sql`); the node adjusts the number of connections at the next sync by itself. The built-in
  fallback of the plan overview matches.

## 1.34.0 – 2026-10-27

### New
- New tab "CDN64 statistics" (only with CDN64 names in the account): what srv07/srv08 blocked for you – today, 7 or
  30 days.
  - Four figures: blocked, blocked IP addresses, overload stopped and connection hidden (of which via IPv4).
  - Chart "Blocked per day" by reason: blocklists, access list, overload, WAF patterns, attack tool (JA4).
  - Table per name with mode, WAF and JA4 level; a click opens the host.
  - Top attack tools from the Honeypot64 database of ipv64.net and the box "Without CDN64".
- Proxy hosts: the switch "Protection on the servers" (shield next to pause) sets the WAF patterns (mode 2/3) and the
  attack tools (JA4: off, count only, block) per host. It appears as soon as ipv64.net knows the protection.

## 1.33.1 – 2026-10-27

### Fixed
- v64 Blocklist: after restarting several nodes of the same account, the list showed "HTTP 429". The list token
  applies to the whole account, and ipv64.net allowed the same file only once every 5 minutes per token.
  - The portal dropped that limit. At most 60 fetches per 5 minutes and token still apply.
  - On a 429, PROXY64 keeps the current list and shows no error. Only without a list does it load the daily list.

## 1.33.0 – 2026-10-27

### New
- Instant block from the honeypot: blocked IPs are now also stored in the database and survive a restart (before, only
  in memory). "Unblock" removes the entry there too.
- The instant block can also be switched on in the honeypot ("Block detected attackers in PROXY64", on by default
  there). Access lists → Honeypot64 then shows "Switched on by Honeypot64"; the own switch remains for blocking
  without that option.

## 1.32.2 – 2026-10-27

### Changed
- Access lists: the card "Overload protection" is now called "DoS protection (denial of service) – overload
  protection".

## 1.32.1 – 2026-10-27

### Changed
- ipv64 blocklists: the v64 Blocklist is now listed at the top right after the combined list instead of at the end.

## 1.32.0 – 2026-10-27

### New
- v64 Blocklist live without manual steps: if no list token is entered by hand, PROXY64 fetches it itself with the
  central ipv64 API key (only when the "ipv64 Honeypot" list is enabled). Entitled accounts (contributors and all plans
  except Standard) automatically get the live version, others the daily list; when the plan changes, the version
  switches by itself with the next fetch. A token entered by hand still takes precedence.

## 1.31.1 – 2026-10-27

### Changed
- ipv64 blocklists: the v64 Blocklist is now a single list (ipv64.net no longer provides the sub-lists SSH, web,
  mail, RDP, scanner and research scanner). If a sub-list was enabled, the v64 Blocklist applies now – no gap in
  protection.

## 1.31.0 – 2026-10-26

### New
- Maintenance mode per proxy host ("Maintenance" tab, button in the list): the name stays reachable, visitors see a
  maintenance page instead of the target – terminal in Matrix style (default), plain with a gear (light/dark) or own
  HTML (up to 64 KB, preview). Response 503 with Retry-After, never cached; counts neither as rejected nor as error,
  "maintenance mode" in the access log. Also via CDN64 mode 1 and 2, not for mode 3.
- Traffic split by direction (visitor's view): download (target to visitor) and upload (visitor to target, e.g.
  uploaded files), each as it goes over the wire; WebSockets in both directions. Two tiles at the top, "↓ … · ↑ …"
  per host, two lines in the chart, also split on the access page and in the start page card. Upload is counted from
  this version on (older hours download only).

- Access lists with a login page (switch "Login page instead of browser dialog"): visitors sign in on a page in the
  style of Node64 (light/dark, German/English by browser); a signed cookie then keeps the session (12 hours, 30 days
  with "stay signed in"). A new password ends existing sessions, the cookie never reaches the target, failed attempts
  count as before (block, honeypot report). Basic Auth stays possible for programs; sign out via /.node64/logout
  (button). If the host has a certificate, signing in always moves from HTTP to HTTPS; an unknown user takes as long
  as a wrong password.

### Changed
- WebSockets count as answered (101) in the statistics instead of aborted (4xx).


## 1.30.3 – 2026-10-26

### Changed
- Phone: the host list, "Other names in CDN64" and the access log show one card per entry (label left, content right)
  instead of a wide table that needs scrolling sideways.


## 1.30.2 – 2026-10-26

### Fixed
- “Add to local DNS64”: wildcards (*.example.com) and main domains (example.com) are no longer added – DNS64 would
  have hidden mail, TXT and other records there at home. The IPv4 field only takes IPv4, the IPv6 field only IPv6;
  loopback and link-local addresses are rejected (and no longer suggested). Switched-off DNS64 records do not count as
  present, and an identical existing record is skipped instead of aborting with an error. Reverse lookups of the proxy
  address stay unchanged (record without PTR).
- The names column of the host list no longer wraps letter by letter.


## 1.30.1 – 2026-10-26

### Fixed
- The tiles “CDN domains” and “CDN traffic” only appear below the proxy hosts, no longer below redirections, 404 hosts,
  status pages and streams.

## 1.30.0 – 2026-10-26

### New
- Host list (proxies): button “Add to local DNS64” (house icon). Adds the names of the host as custom DNS records in
  DNS64 (no zone) – A and optionally AAAA pointing to the reverse proxy. Suggested is the address Node64 is opened
  with, otherwise the node's LAN address. Existing records of the same type and CNAMEs stay unchanged; a green house
  shows that all names are already local. Only while DNS64 is running.
- Dialog “Enable CDN64”: modes 1, 2 and 3 are explained briefly at the top, each with a sketch; clicking a box selects
  the mode. Mode 3 runs without Node64 and links to ipv64.net/cdn64.

## 1.29.0 – 2026-10-26

### Changed
- Statistics: “errors” are only real errors now – 5xx and “target not reachable”. 4xx answers of the target (not found,
  not logged in; e.g. missing icons with Bitwarden) are shown separately in grey, requests rejected by PROXY64 only
  count as “rejected” and no longer also as 4xx. Applies to the host table, the key figures and the chart (also on the
  dashboard). Older hours still contain rejected requests in 4xx.
- Access lists page: the Honeypot64 card sits on the right below “Overload protection” (more compact).

### Added
- “To honeypot”: requests that got the Honeypot64 decoy instead of a rejection (unknown names and those recognised as
  malicious) are counted on their own – per host in the table, as a key figure, in the chart (purple) and in the access
  log (marker and filter). Visible while the decoy is active or there were diversions in the period.

## 1.28.0 – 2026-10-25

### Added
- Honeypot: requests recognised as malicious can get the Honeypot64 decoy instead of 403 – one switch per kind under
  Access lists → Honeypot64: IPs on the ipv64 blocklists, attackers reported by the honeypot, exploit patterns, AI bots/scanners
  (all on by default) and country block (off by default). Overload (rate limits) never goes to the decoy. Only while the
  decoy is active and only for HTTP(S); TCP/UDP streams and TLS passthrough still reject.
- If Honeypot64 runs with the “Only via PROXY64” preset, the decoy is switched on automatically.

### Changed
- Blocked IPs (blocklists, honeypot block) are no longer cut off before TLS at the web entrance when their route to the
  decoy is on – the request gets the decoy instead. Passthrough hosts now check the blocks themselves after the first
  TLS packet.

## 1.27.2 – 2026-10-24

### Fixed
- Host form: after an error in the form (e.g. an invalid name or the missing terms checkbox) the chosen way to the new
  certificate stays selected instead of jumping back to “automatic”.

## 1.27.1 – 2026-10-24

### Changed
- Host form, “Request a new certificate right away”: the way to the certificate now offers all ways like under
  certificates – automatic, ipv64 DNS-01, HTTP-01, other DNS provider (per account), own CA (per CA) and self-signed.
  Unavailable ways are greyed out with the reason (no API key, no DNS account, no CA); alias via ipv64 points to
  certificates → new. Own CA and self-signed need no Let's Encrypt account – the checkbox for the terms only appears for
  the Let's Encrypt ways.

## 1.27.0 – 2026-10-24

### New
- Docker bridge network: PROXY64 checks whether the HTTP and HTTPS ports (80/443) are published on the Docker host – a
  probe request via the gateway must reach its own entry point; another program on the host does not count. If a port
  is missing, the host list shows a clear warning with a ready-to-copy `-p …`; *Settings → Ports* shows “not
  published” or “published on the host” plus an example for `docker run` and `docker compose`. Previously the check
  reported “listening” as soon as the port was open inside the container, even if nothing arrived from outside.

## 1.26.1 – 2026-10-24

### Fixed
- Proxy host with "request a new certificate" without a Let's Encrypt account: the host used to be saved and the
  certificate then failed because the terms of service were not accepted. The form now shows the terms checkbox (with
  link); without it the host is not saved and the form shows the hint.

## 1.26.0 – 2026-10-23

### New
- CDN64 for Business and Company: several parallel tunnel connections per server (4 instead of 1, over QUIC, QUIC on
  443 or TLS, whatever gets through). srv07/srv08 hand new visitors to the least loaded connection; if one fails or
  stalls, visitors carry on over the others. In the load test the single connection per server capped at about
  650–830 Mbit/s. The number comes from ipv64 per plan; when the plan changes, the node rebuilds the connections on its
  own. The host list shows "×4" on a server when several connections are up.
- Account plans: new row "Parallel tunnel connections per server".
- Requires cdn64-edge 0.18.0 on the servers (older servers keep using one connection).

## 1.25.1 – 2026-10-23

### Changed
- Proxy hosts: the per-host numbers in the table follow the period of the traffic card (24 hours, 7 days, 30 days) –
  requests, newly the traffic, errors (4xx/5xx) and rejected. Previously the column showed requests of the last 24
  hours but errors and rejected since the module started. Column header and key figures name the selected period.

## 1.25.0 – 2026-10-22

### Added
- Per host "Reject AI bots (user agent)" with "Also block fetches on behalf of users" (on by default) and "Serve
  robots.txt that blocks AI bots" (only if the target has none). Based on the ipv64.net list "v64 AI Bots (User-Agent)"
  (mirror of ai.robots.txt). Rejected AI bots get 403 and show up as "AI bot" in statistics and the access log.
- The blocklist "v64 AI Bots (IP)" (official networks of OpenAI, Perplexity, Common Crawl, Mistral, Google-Agent) can
  be selected.

## 1.24.1 – 2026-10-21

### Fixed
- Port mappings via CDN64: at most 1024 UDP sessions and 4096 TCP connections per stream from the tunnel (as on the
  stream's own port). Before, any number of UDP sessions was possible from the tunnel (the servers allow up to 4096
  per port and server).

## 1.24.0 – 2026-10-21

### New
- Port mappings for CDN64 mode 1/2: a stream can be reached from the internet via a CDN64 name of the node (option
  "Reachable from the internet via CDN64" on the stream). srv07/srv08 open a port and pass TCP or UDP through the
  encrypted tunnel to the stream. No port has to be open at home and your own address stays hidden. Block lists,
  per-IP limits and the country block apply to the real visitor address, so does the stream's TLS termination. The
  server port is shown in the stream list and in the host row; it counts towards the port mapping quota. Pause and
  the allow/block list of the name apply to these ports as well.
- Requires cdn64-edge 0.15.0 on the servers.

## 1.23.2 – 2026-10-21

### Changed
- When a mode 3 name is shown in the row of its host, the row now also lists the port mappings (server port → target
  port) and the allow/block list.

## 1.23.1 – 2026-10-21

### Changed
- Paused CDN64 names are highlighted in yellow in the host list and in "More names in CDN64".
- A name in mode 3 (on ipv64.net) or from another node that has a host here is now shown in the row of that host:
  mode, status, cache, traffic, pause and an edit link. Switching on and changing the mode are no longer offered
  there. The "More names in CDN64" card only lists names without a host here.

## 1.23.0 – 2026-10-21

### New
- Pause CDN64 (all modes): one click in the host list and srv07/srv08 stop accepting anything for the name. The
  servers close open connections within seconds. Meant as quick self-protection, for example during an attack. The
  tunnel stays connected and DNS keeps pointing to the servers, so your own address stays hidden. Settings and
  statistics are kept. Resume with the same button.
- "More names in CDN64": names of the account that this node does not manage are listed below the hosts. These are
  names in mode 3 (set up on ipv64.net, the servers go to the target directly) or names in mode 1/2 via another
  node. Shown: target, server cache, allow/block list, port mappings, status and traffic this month. You can pause
  them here; edit them on ipv64.net or in the other node.
- The node now fetches the state even without CDN64 names of its own. Without any names in the account it does so
  every 5 minutes, and right away when the list is opened.

## 1.22.0 – 2026-10-21

### Fixed
- Asset cache: aborted or failed upstream responses are never cached, including compressed ones and over HTTP/3 or the
  CDN64 tunnel.
- Cache variants follow the encodings the browser actually accepts (q=0 does not count). Responses the target
  compressed itself (e.g. deflate) are not served to browsers that can't decode them.
- 103 Early Hints from the target no longer prevent compression and caching. Accept-Ranges is removed from compressed
  responses.
- Compression uses much less memory (smaller windows, about 3–6 MB instead of up to 50 MB per response). The stronger
  level only applies to responses that are actually cached, and at most 2–4 such runs happen at once.
- X-Forwarded-For and X-Real-IP can no longer be set or removed under "Advanced" (the real client address stays
  reliable). Passthrough to the node's own web interface is refused.
- Import: status-page hosts without a page mapping in the export (older exports or Healthchecks off on the source) are
  created switched off and reported.
- Statistics: totals and timeline cover the same hours (exactly N hours including the current one).
- Quota: tiles and dashboard card share the same bar values and colours.

## 1.21.4 – 2026-10-21

### Fixed
- Export/import: hosts of the kind "status page" point to the page with the same slug on the target node after the
  import (the page ID is only valid on the source). If the page is missing there, the host is created switched off.
- Resetting the node removes the CDN64 online names and the tunnel at ipv64 even when PROXY64 is switched off, so
  nothing is left behind online.
- "24 h" (page, dashboard card, Prometheus) only counts the full hourly buckets of the last 24 hours instead of up to
  25 hours.
- Quota tiles on the PROXY64 page: the bar stays visible with small usage (at least 1 %), domains without a quota in
  the plan count as full.

## 1.21.3 – 2026-10-21

### Fixed
- Configuration export/import now also contains the honeypot switches (decoy, access to the log sensor, instant
  block with duration); they apply right after the import. The block list itself stays on the node.
- Port overview (Settings › Ports): streams report why a port is not open (e.g. "address already in use"); the CDN64 online tunnel appears as an outgoing connection (server, port, connected, last error).

## 1.21.2 – 2026-10-21

### Changed
- Start page card: when CDN64 online is used, CDN domains and CDN traffic this month as "x / y" with a bar (green,
  yellow from 80 %, red when full) and a note until when the traffic lasts at the same usage.

## 1.21.1 – 2026-10-21

### Changed
- CDN quota below the host list as two tiles with progress bars (domains with bandwidth, traffic this month) and a
  forecast: at the same usage, whether the traffic lasts until the end of the month, otherwise until when.

## 1.21.0 – 2026-10-21

### New
- Compression with zstd and Brotli in addition to gzip, chosen by the browser (dynamic zstd → Brotli → gzip, static
  files in the cache Brotli → zstd → gzip at a stronger level). On by default for new proxy hosts.

### Changed
- The cache now sits behind the compression and serves the compressed variant; the switch is called "Compress
  responses". Strong ETags become weak when compressing, `Cache-Control: no-transform` is respected.

## 1.20.1 – 2026-10-20

### Changed
- Honeypot64: the switch "Unknown requests to the honeypot" now says that the node then answers unknown requests
  visibly (login page, fallback certificate) – highlighted when the default page is set to "close connection". In the
  settings (ports) the default page points out that the decoy replaces it while it is active.

## 1.20.0 – 2026-10-20

### New
- Working together with Honeypot64 (card "Honeypot64" under access lists, three switches, all off by default, only
  with the Honeypot64 module running):
  - Unknown requests to the honeypot: requests without a matching host (IP only, foreign domain, unknown name) go to
    the web decoy instead of the default page.
  - Hand accesses to the honeypot: per request only metadata (IP, host, method, path without query, status, failed
    login) goes to the log sensor, never content.
  - Block attackers from the honeypot immediately: reported IPs are blocked for all hosts and streams (duration
    adjustable, default 24 h), never private addresses, blocklist exceptions or the hosts' proxies. List with reason
    and end, each entry can be lifted.
- API `GET/PUT /api/cdn64/honeypot`, `DELETE /api/cdn64/honeypot/blocks/{ip}`; Prometheus `node64_cdn64_honeypot_*`.

## 1.19.1 – 2026-10-20

### Fixed
- Country filter "allow only": while the list of one of the allowed countries is not loaded yet (e.g. right after
  start or when a download fails), nobody is blocked – before, visitors from that allowed country were rejected.

## 1.19.0 – 2026-10-20

### New
- ipv64 blocklists: the lists of the ipv64 honeypots (v64 blocklist and the partial lists SSH, web, mail, RDP,
  scanners, research scanners) appear marked "ipv64 Honeypot" as soon as ipv64 offers them in `index.json`.
- List token for live lists: the blocklist card lets you store, change and delete the list token from your ipv64
  account. With it, PROXY64 loads the honeypot lists in their live version (re-scored every 30 minutes), without it
  the daily version. Each list shows which version is loaded; if the token is not entitled it reads "daily version –
  token without entitlement", if it is rejected (401/403/404) PROXY64 loads the daily version and shows the error.
- The token is stored encrypted and never shown, logged or exported. API: `GET /api/cdn64/blocklists` returns
  `token_set` and, per list, `edition`, `live_denied`, `live_error`; `PUT` takes `token` (empty = delete).

## 1.18.1 – 2026-10-20

### Fixed
- Country block: a country list needed by a new host exactly while lists were loading could be missing until the next
  refresh.

## 1.18.0 – 2026-10-20

### New
- New host type "status page" (tab Status pages): your own domain shows a Healthchecks status page directly at "/",
  with central certificate, force SSL, HSTS and HTTP/3.
- As with proxy hosts, blocklists, country block, limits, exploit block and access list apply in front of the page,
  plus statistics and access log. Via CDN64 it can be switched on like a proxy host in mode 1 or 2.
- Export and import keep the assignment. If the page does not exist on the target node, the host answers 404 (503
  without Healthchecks) until a page is chosen.

## 1.17.1 – 2026-10-19

### New
- Proxy hosts with CDN64: a small icon shows how the node is connected to the servers srv07/srv08 – a lightning bolt
  for QUIC (filled: own port, outlined: via port 443), a lock for the HTTPS fallback (TLS over TCP), a plug when no
  server is connected. The tooltip names the path per server (e.g. “srv07: QUIC · srv08: HTTPS”); the self-test in
  the CDN64 dialog shows it as well. The API returns it per server as `via` (`quic`, `quic443`, `tls`).

## 1.17.0 – 2026-10-19

### Changed
- New name: the local reverse proxy is now called **PROXY64** (menu, pages, dashboard, ports, audit, backup).
  **CDN64** now only means publishing through the servers srv07/srv08 (modes 1, 2, 3); “CDN64 online” becomes
  “CDN64” (column, dialog, notifications, audit). Addresses, API, settings, export and Prometheus names stay the same.
- Logo: until the PROXY64 logo is available, the module icon takes its place.

## 1.16.0 – 2026-10-19

### New
- Proxy hosts: icons show the overload protection – a gauge when the local rate limits apply to the host (click leads
  to the settings), a green shield when the host runs through CDN64 online and is therefore also protected on the
  servers (blocklist, limits per IP, fair throttling).

## 1.15.0 – 2026-10-19

### New
- Country block for streams too (TCP and UDP): block countries or allow only certain ones, as for hosts. A change
  applies immediately without restarting the stream; for UDP the first packet of a client decides.

## 1.14.0 – 2026-10-19

### New
- Country block per host (proxy, redirect, TLS passthrough): block visitors from certain countries or allow only
  certain countries. The country lists come from ipv64.net daily and are loaded and cached only for countries in
  use. Private networks, CGNAT and the blocklist exceptions are never blocked; behind Cloudflare or similar the real
  client IP counts. Rejected visitors show up in statistics and access log as "country block".
- Blocklists: the selection now comes from `index.json` on ipv64.net. New lists appear without a Node64 update, e.g.
  all lists without Tor, abuse.ch Feodo Tracker, ET Compromised, CINS Army, IPsum, Tor (all relays) and the networks
  of AWS, Google Cloud and Cloudflare. Each list shows its license and description.

### Changed
- "IPv64 Gesamtliste" (all lists) is no longer marked as recommended because it contains Tor; the combined list
  without Tor is now recommended.

## 1.13.1 – 2026-10-19

### New
- Help links: a question mark on pages and cards opens the matching place in the documentation on node64.de (proxy
  hosts, options, access lists, blocklists, rate limits, default page, statistics, TLS passthrough, CDN64 online).

## 1.13.0 – 2026-10-19

### New
- Prometheus (`/api/metrics`): per host requests, errors and rejected requests since start and for the last 24
  hours (by status class, bytes), target reachability and response time; CDN64 online with the names switched on,
  tunnel per server (connected, round trip time, streams), state and traffic per name at ipv64, and the quota.
- Reset node: CDN64 online names and the tunnel are removed at ipv64 first.
- Complete configuration export: access lists (with users), blocklists, exceptions, limits and access log
  settings are included; after the import hosts and locations point to the lists of the new node, fixed
  certificates are found again by their names. Existing settings are kept.

## 1.12.0 – 2026-10-19

### New
- Dashboard card: requests, traffic, 5xx errors (with share) and rejected requests of the last 24 hours, plus active TCP streams.

### Fixed
- Statistics: evaluations over long periods could fail with "disk I/O error" (no directory for SQLite temporary files in the container); intermediate results now stay in memory.
- Display: CDN64 logo is light in the dark theme.
- Audit: “Load lists now” and “Check targets now” (UI and API) are logged.

## 1.11.0 – 2026-10-19

CDN64 online: HTTP/3 in mode 1 too.

### New
- Mode 1 (pass-through) supports HTTP/3: srv07/srv08 read the name from the first QUIC packet and pass QUIC raw
  through the tunnel to the node. As with TCP, TLS and HTTP/3 terminate only in the node, with the real visitor address.
  Applies to proxy hosts with “HTTP/3” (default).
- Responses via the tunnel carry the HTTP/3 hint (Alt-Svc) as soon as all connected servers support
  pass-through.

### Changed
- Mode 3 (directly to the target, without tunnel) is now only available on ipv64.net/cdn64; the enable dialog shows a
  note with a link. Mode 3 names previously enabled in the node can be switched to mode 1/2 or
  disabled.

## 1.10.0 – 2026-10-18

CDN64 online mode 3.

### New
- Mode 3 selectable: srv07/srv08 go directly to the proxy host's target without a tunnel (only if the target is publicly
  reachable; otherwise mode 1 or 2). Switching between mode 3 and 1/2 disables the name at ipv64 and enables it again.

## 1.9.0 – 2026-10-18

CDN64 online in operation.

### New
- Per enabled host, the servers' figures for the month (traffic, requests, rejections), below them the
  account's CDN quota.
- Notifications via the notification channels: tunnel connected to no server for 3 minutes, reconnected, name
  blocked at ipv64.
- The tunnel uses port 443 if 7844 is blocked.

### Changed
- Mode 2: requests no longer count as new connections (the connection limit otherwise slowed visitors down).
- The sync adopts modes changed elsewhere and resets mode 2 to 1 for “TLS passthrough”.

## 1.8.0 – 2026-10-18

CDN64 online mode 2.

### New
- Mode 2 selectable: TLS terminates on srv07/srv08 (HTTP/1.1, HTTP/2, HTTP/3), protection and request limits already apply
  there, requests arrive at the node as HTTPS with the real visitor IP. The servers obtain certificates themselves;
  until then traffic is passed through, so switching never causes an outage.
- *Switch mode* button and “Mode 1/2” badge in the list; the self-test sends a real request.

## 1.7.0 – 2026-10-18

CDN64 online with one click.

### New
- *CDN64 online* column in the host lists: *Enable* makes a host reachable from the internet via srv07/srv08.cdn64.de
  (IPv4 and IPv6, no open ports).
  - Steps in the dialog: check account, register and establish tunnel, enable name at ipv64 (DNS), self-test
    via the internet. Each step with result and error text with remedy.
  - Mode 1 (TLS is passed through, the certificate stays in the node); optionally an online health check right away.
  - Badges per server (connected, via the other server, no tunnel), “blocked”, self-test, enable more names,
    disable.
  - Disabling restores the DNS; with the last name the tunnel is deregistered. Deleted hosts and
    removed names are removed at ipv64 by the sync (every minute).
  - Notes on blocked UDP (tunnel over TCP) and a too-small UDP buffer on the Docker host.
- In the home network, DNS64 answers enabled names with the node's address (split DNS).
- API: `POST /api/cdn64/online/tunnel`, `POST|DELETE /api/cdn64/hosts/{id}/online`,
  `POST /api/cdn64/hosts/{id}/online/test`; `GET /api/cdn64/online` additionally shows names, quota and
  UDP buffer.

## 1.6.0 – 2026-10-17

Rejections in statistics and log, same chart as on the dashboard.

### New
- Every rejection is recorded: blocklists, bans, limits, access lists and exploit blocking.
  - It always appears in the access log (*Access log* tab), with reason and filter “Rejected”, even without the access log enabled; throttled to one entry per address and reason every 10 seconds.
  - Connections closed before the first request appear as “Connection rejected”.
  - Overload (total connections exhausted, target saturated) and bans appear as warnings in the node's log.
- “Rejected” tile (24 hours) on the *Access log* tab.

### Changed
- The chart in the proxy host overview and the one on the dashboard are now the same: requests and rejections stacked, traffic as a line.
- *Access lists* tab: ipv64 blocklists and overload protection side by side, your own access lists below.

## 1.5.0 – 2026-10-17

Overload protection, ipv64 blocklists, traffic in the overview.

### New
- Overload protection (*Access lists* tab), as with HAProxy, enabled with default values:
  - per IP (IPv6 per /64): 200 concurrent connections, 20 new connections per second (briefly 200),
    50 requests per second (briefly 500, above that 429);
  - 10,000 connections in total; per proxy host 200 concurrent requests to the target, further ones wait up to
    10 seconds, then 503 (WebSockets do not count);
  - anyone bouncing off 300 times within one minute is rejected at connection setup for 10 minutes; banned
    addresses appear in the card and can be released;
  - exempt: home network (can be turned off), the hosts' trusted proxies and the blocklist exceptions;
    per host under *Advanced* “No per-IP limits”;
  - also applies to TCP streams; API `/api/cdn64/limits`.
- ipv64 blocklists via toggle, rejected before TLS; API `/api/cdn64/blocklists`.
- *Traffic* card in the proxy host overview (requests by 2xx–5xx, data volume, 24 hours to 30 days).
- The table shows whether a health check monitors exactly this target (local or ipv64/other node).

## 1.4.1 – 2026-10-16

### Changed
- Certificates have their own menu item *Certificates* in the core and no longer belong to CDN64.
  - The *SSL certificates* tab leads there.
  - The old addresses under `/cdn64/certificates` and `/cdn64/dns-accounts` redirect.
- Certificates are renewed even when CDN64 is off.

## 1.4.0 – 2026-10-15

Certificates with other DNS providers too, DNS records at ipv64 on creation.

### New
- DNS accounts for Let's Encrypt via DNS-01 with other providers, including wildcards:
  - Providers: Cloudflare, Hetzner, netcup, INWX, IONOS, deSEC, Duck DNS, Porkbun, GoDaddy, DigitalOcean, Gandi, OVHcloud.
  - The credentials are stored encrypted and never shown again; when editing, empty fields remain unchanged.
  - An account used by a certificate cannot be deleted.
- New method “Other DNS provider” when requesting; likewise in the host form under “Request certificate right away”.
- DNS record at ipv64 when creating a host:
  - CNAME (e.g. to the DynDNS domain) or A/AAAA, for every domain of the host in the ipv64 account;
  - existing records remain unchanged;
  - in the API via `create_dns_record`.

## 1.3.0 – 2026-10-15

Custom locations, access lists, advanced options, statistics and access log.

### New
- Custom locations: paths of a proxy host with their own target (e.g. /api to another service).
  - Optionally with a different path at the target, their own WebSocket setting and their own access list.
  - The longest matching path wins.
- Access lists:
  - Users with password (stored only as a bcrypt hash) and IP rules (allow/deny, first match applies, otherwise blocked).
  - “Both required” or “one condition is enough”; the login can be passed on to the target.
  - After 10 failed logins within 5 minutes the IP is blocked for 15 minutes; the block appears in the audit.
  - Applies to proxy hosts, locations and redirection hosts.
- Advanced:
  - set or remove headers towards the target and towards the visitor;
  - Host header (visitor's name, target's name or a fixed value);
  - timeout to the target, upload limit (413), no buffering, gzip for text responses;
  - trusted proxies with a Cloudflare template for the real client IP.
- Statistics: requests per host and hour (2xx–5xx, data volume) over 90 days. The list shows the requests of the last 24 hours.
- Access log can be enabled per host:
  - “Access log” tab with filters by host, status and search;
  - retention 1–90 days, client IPs optionally truncated;
  - separate file cdn64.db.
- “Create health check for this target” for proxy hosts, TLS passthrough and TCP streams (requires the Healthchecks module).
- API: access lists, access log, statistics, settings, create health check.

## 1.2.0 – 2026-10-15

Redirection hosts, 404 hosts, streams, TLS passthrough and the default page.

### New
- Redirection hosts:
  - domains to another domain, optionally with port and path;
  - code 301, 302, 303, 307, 308 or 300;
  - scheme as in the request or fixed;
  - keep path and query;
  - SSL options as with proxy hosts.
- 404 hosts: domains that deliberately respond with “not found”, also via HTTPS.
- Streams:
  - a port (TCP and/or UDP) is passed raw to a target;
  - for TCP optionally with TLS termination using a certificate from certificate management;
  - ports are checked against the other parts; if one is taken, the reason is shown on the stream;
  - counters for connections and data volume, reachability of the target.
- TLS passthrough: a name on port 443 goes raw to a service with its own certificate, without decryption here. All other names on 443 stay with Node64.
- Default page for unknown names: 404, close connection, redirect or a custom HTML page.
- Export/import now also includes streams.

## 1.1.0 – 2026-10-15

SSL certificates tab.

### New
- List of all certificates:
  - names, method, issuer;
  - expiry as a pill (green, yellow from 30 days before expiry, red from 7 days) with date;
  - used by which hosts, automatic renewal on/off;
  - renew, download (without key), delete (certificates in use only after confirmation);
  - the current step during retrieval; the page reloads itself meanwhile.
- Request a certificate from Let's Encrypt:
  - automatically (ipv64 if all names are in the account, otherwise HTTP-01) or specifically via ipv64 DNS-01 (including wildcards);
  - alias via ipv64 for third-party domains, with a preview of the required CNAME records;
  - via HTTP-01;
  - staging environment selectable.
- Upload your own certificate (file or paste).
- Let's Encrypt account: email and acceptance of the terms of service.
- Host form: “Request new certificate right away”; in the API via `request_certificate` when creating or changing a host.

## 1.0.0 – 2026-10-15

First version of the reverse proxy, modeled on Nginx Proxy Manager.

### New
- Proxy hosts with multiple domains (including wildcards) and a target via http or https, name or IP, port.
- Options per host:
  - WebSockets;
  - Block Common Exploits (rules as in NPM, plus blocking of .git and .env);
  - Cache Assets: static files in memory, at most 64 MB.
- SSL per host:
  - Certificate from certificate management (matched by name or chosen explicitly) or HTTP only.
  - Force HTTPS, HSTS (including subdomains), HTTP/2, HTTP/3 (QUIC), at least TLS 1.2 or 1.3.
- Target reachability: checked every minute, shown in the list with response time or “unreachable since …”.
- An unreachable target gets a neutral “502” page. Loops (target points to the proxy itself) are detected.
- Counters per host since startup: requests, errors, blocked requests.
- Dashboard card, audit for all changes, local API under `/api/cdn64/…`.
- Export and import of hosts.
- When disabled, nothing runs: no routes, no checks, no cache, and the shared entry point (edge) closes its ports.
