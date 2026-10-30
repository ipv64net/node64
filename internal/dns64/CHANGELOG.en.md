# Changes – DNS64

## 1.31.1 – 2026-10-30

### Fixed
- Plain DNS servers with a link-local address and zone (`fe80::1%eth0`) work as upstream or forward; before, all queries
  to them failed silently.
- Encrypted page: opening it via an IPv6 address without port (`[fd00::5]`) gives valid DoH/DoQ addresses and a valid
  iOS profile again.
- Reverse lookups for the global IPv6 addresses of the own home network go to the router instead of public upstreams
  (if a router is known); `fc00::/8` and `::1` count as local too.
- DoH/DoQ via link-local addresses: group rules apply again.
- Own AAAA records with a zone or a `::ffff:` address are rejected.
- Networks in groups and additional client networks given as `::ffff:` prefix are converted to IPv4 networks (they never
  matched before).
- Settings: notice when a fixed address is set – devices of the other IP family then get no DNS.
- Router DNS shown without square brackets for IPv6.

## 1.31.0 – 2026-10-28

### Fixed
- An own CNAME and a rewrite pointing at each other no longer crash the service (SERVFAIL).
- DNSSEC queries for top-level domains (DS/DNSKEY/NS/SOA, e.g. "com") go to the upstreams; device names without a dot
  still go to the router.
- Restarting after settings changes no longer leaves DNS off when stopping hangs or the request is cancelled.
- Cache: CD bit kept separate, NXDOMAIN/NODATA behind a CNAME cached only briefly (SOA, at most 5 minutes), memory budget,
  answers over 16 KB are not cached.
- Plain upstreams (dns://) get a random query ID.
- Dynamic updates (RFC 2136) are applied all or nothing; the cluster no longer reports bogus deletions.

## 1.30.0 – 2026-10-26

### Changed
- Upstream mode "fastest": 1–6 servers can now be asked at the same time (previously 1–3, default stays 2).

## 1.29.1 – 2026-10-26

### Changed
- Phone: the query log, the upstream list in the settings, custom DNS records, forwards, rewrites, devices and group
  members show one card per entry instead of a wide table; the
  upstream cards on the overview wrap IP addresses and URL instead of running off the screen.


## 1.29.0 – 2026-10-26

### Added
- Own blocklist: block domains (including subdomains) yourself – with the “Block” button in the query log or in the new
  card below “Released domains”. It applies to all devices in addition to the blocklists; releasing the same domain
  lifts the block, a more specific release (e.g. cdn.example.com) wins. Syncable as its own cluster area, included in
  the export.
- Own upstream as a plain DNS server: just enter the IP address (e.g. 8.8.8.8, port 53, or IP:port). Marked as
  “DNS (unencrypted)” in the list.
- “Queries over time” with its own chart period: 30 min, 6 h, 24 h, 7 days.

### Changed
- Query log: when a device asks for a public domain with its local search domain appended (e.g.
  example.com.home.local), the entry says “search domain appended by the device”. The device does this itself, usually
  after the real query failed (e.g. SERVFAIL because the upstreams briefly did not answer) – DNS64 appends nothing.

## 1.28.1 – 2026-10-24

### New
- Docker bridge network: DNS64 checks through the Docker gateway whether its ports are published on the host (probe
  name via UDP, TCP, DoT, DoQ or DoH to gateway:port – a published port leads back into the container). If one is
  missing, the port overview and a warning on overview, query log, settings and encryption say so, with an example for
  `docker run` (`-p 53:53/udp -p 53:53/tcp`) and `compose` (`ports:`) or `network_mode: host`. Checked shortly after
  start and every 30 minutes; skipped in host networking.
- Query log: hints why client addresses are missing or look the same – queries with the address of the Docker gateway
  (Docker replaces the sender), refused queries from networks that are not allowed (not in the log, e.g. another VLAN
  or, in a bridge network, the home network's public IPv6) and shortened or unstored client addresses.

## 1.28.0 – 2026-10-23

### Changed
- Overview, dashboard card and device list stay fast with millions of log entries: while writing the query log DNS64
  keeps counters per minute and frequencies per domain and client per hour; KPIs, timeline and top lists read only
  these (before, every call counted all entries of the period, with “context canceled” and long loading times). On
  update DNS64 builds the counters once from the existing log.
- The log page counts matches up to 100,000 and then shows “100,000+”.

## 1.27.4 – 2026-10-23

### Fixed
- Queries of the router itself (1.27.2): a local target is no longer sent back to the router via rewrites, own CNAME
  records, SafeSearch or split DNS either (the query could loop otherwise).

## 1.27.3 – 2026-10-23

### Fixed
- Router detection (1.27.2): probe names `*.node64-probe.invalid` from other devices are still answered immediately,
  but no longer remembered – only the ones just sent by the node itself (memory grew with every such query before).

## 1.27.2 – 2026-10-23

### Fixed
- Docker bridge network with published port 53: the router search found the Docker gateway (e.g. 172.17.0.1), which
  sent the query back into the container – local names and the reverse lookup of client names (PTR) looped endlessly
  (millions of PTR queries from 172.17.0.1, full CPU, slow dashboard). The search now detects with a probe name when
  the candidate is the node itself and skips it.
- General loop protection: queries coming from the router itself (e.g. router with Node64 as upstream) are not sent
  back to the router for local names.

## 1.27.1 – 2026-10-22

### Fixed
- Import of many records (hosts file, CSV, JSON, zone file) in one transaction: 5000 records in a fraction of a second
  instead of minutes (before, everything was reloaded per record; an import of 3000 aborted with the client after 20 s).
- Cluster with thousands of records: the sending node serves the last reported state, the receiving node writes
  directly and rebuilds the DNS table in batches – 3000 records in 0.2 s instead of about 45 s.

## 1.27.0 – 2026-10-22

### New
- Own menu entry **"Local DNS"** below DNS64 (tabs zones and forwarding); DNS64 itself stays the ad blocker. The old
  addresses `/dns64/records` and `/dns64/forwards` redirect.
- Zone view (L5): zones on the left with their record count, "All records" and "Without zone"; records of the
  selected zone on the right, names relative to the zone (`@` = the zone itself). Per zone: default TTL, SOA (refresh,
  retry, expire, TTL for "does not exist", responsible mail). A network like `192.168.1.0/24` becomes the reverse zone.
- Zone file (L6): export per zone in BIND format (`$ORIGIN`, `$TTL`, SOA, NS, relative names, comments); import of
  zone files (e.g. from Bind, Technitium, Windows DNS) through the same import as hosts file/CSV/JSON – SOA values go
  to the zone, NS and unsupported types are skipped.
- Dynamic updates per RFC 2136 (L7): switchable per zone with a TSIG key (HMAC-SHA256, created by the node,
  renewable). DHCP servers like pfSense, OPNsense or Kea register names themselves (A, AAAA, CNAME, TXT, PTR, SRV, MX,
  DHCID); prerequisites and deletes per RFC, all or nothing. Without a valid key, outside the zone or for SOA/NS the
  update is refused. Records created by updates are marked; the key stays on the node (never in API, export or cluster).
- API: `GET /api/dns64/zones/{id}/zonefile`, `POST /api/dns64/records/import?zone=…` (also zone files).

## 1.26.0 – 2026-10-22

### New
- DNS64 in the cluster (phase L4): under "Cluster" DNS64 shows seven switches, all off by default – settings
  (upstreams, mode, blocking mode, cache, anonymisation, retention, Firefox, notifications), blocklists, allowlist,
  custom records with local zones, forwarding with rewrites, device groups (rules, categories, child safety, domains,
  schedules, block/free) and the members of the groups (belong to the site). An area is only synced with nodes that
  have it switched on too; the newer change wins.
- "This node only" per custom record and per forwarding: never synced, and an equal entry of another node does not
  overwrite it.
- Never synced: ports, interfaces, router, DoH/DoT/DoQ, names and certificate, client networks, pause, query log.
- Groups have a cluster id (`uid`); if the same group (same name) already exists on both nodes, it is merged on the
  first sync.
- A node takes over the entries even while DNS64 is (still) switched off there.

## 1.25.0 – 2026-10-22

### New
- Local zones (phase L2, card "Local zones" under "Custom records"): DNS64 answers names below a zone like
  `home.lan` itself – custom records, SOA/NS of the zone and, if the zone is "authoritative", NXDOMAIN with SOA for
  unknown names (otherwise on to forwarding and the router).
- Device names: devices of the device groups with a label appear as `<name>.<zone>` (e.g. "Tablet Lea" →
  `tablet-lea.home.lan`) with their current IP from the neighbour table (MAC) or the entered IP, including reverse
  lookup; can be switched off per zone. The card lists the names with their addresses.
- Configuration export/import carries the zones.
- API: `GET|POST /api/dns64/zones`, `PUT|DELETE /api/dns64/zones/{id}`, `POST /api/dns64/zones/{id}/enable|disable`, `GET /api/dns64/device-names`.

## 1.24.0 – 2026-10-22

### New
- Forwarding (phase L3, new tab "Forwarding"): domain → own DNS servers, e.g. `company.local` to the VPN DNS or
  `192.168.0.0/16` (becomes the reverse zone) to the router. Servers as IP, IP:port, `tls://`, `https://` or
  `quic://`, in order with failover to the next; the longest matching domain wins.
  Blocklists and group rules keep applying, except for local names and private reverse lookups. If no server answers,
  the result is SERVFAIL – the name never goes to the public upstreams. Test button per forwarding (SOA), statistics
  per server, reason "forwarding … via …" in the query log.
- Rewrites: a name (also `*.domain`) answers like another one; DNS64 resolves the target itself and answers under the
  queried name without CNAME. Chains are followed, loops give SERVFAIL.
- Configuration export/import carries forwarding and rewrites.
- Prometheus: `node64_dns64_forward_up`, `node64_dns64_forward_requests_total`, `node64_dns64_forward_errors_total` (`domain`, `server`).
- API: `GET|POST /api/dns64/forwards`, `PUT|DELETE /api/dns64/forwards/{id}`, `POST /api/dns64/forwards/{id}/enable|disable|test`,
  `GET|POST /api/dns64/rewrites`, `PUT|DELETE /api/dns64/rewrites/{id}`, `POST /api/dns64/rewrites/{id}/enable|disable`.

## 1.23.0 – 2026-10-22

### New
- Custom records as a local DNS server (phase L1, plan `docs/PLAN-NODE64-DNS64-LOKAL.md`):
  - More types TXT, MX, SRV, PTR (name may be the IP) and CAA; values are checked and normalised.
  - Edit in the same form, comment per record, reverse lookup (PTR) can be switched off per A/AAAA record.
  - Import from a hosts file, CSV or JSON (text or file; localhost and 0.0.0.0 lines are skipped),
    export as hosts file, CSV or JSON; search in the list.
  - API: `PUT /api/dns64/records/{id}`, `POST /api/dns64/records/import`, `GET /api/dns64/records/export?format=hosts|csv|json`.

## 1.22.3 – 2026-10-22

### Fixed
- Start hung (whole node without UI) when DNS64 registered a route at the shared entrance during start (notice page
  of a group with an "internet off" schedule, DoH via port 443) and the entrance had to open port 80/443 for it first:
  its port check asked DNS64 and waited for the running start. The port overview now reads the state without that lock.

## 1.22.2 – 2026-10-21

### Fixed
- Blocklists: files of removed lists under `/data/dns64/lists/` are deleted at start and no longer pile up
  (configured lists, also switched-off ones and those of groups, stay).
- Port overview (Settings › Ports): DNS, DoH, DoT and DoQ report their start error (e.g. "permission denied" or missing certificate).

## 1.22.1 – 2026-10-21

### Fixed
- Start page card: "blocking paused until" shows the time in the node's time zone (previously the container's,
  usually UTC), with the date if it is another day.

## 1.22.0 – 2026-10-21

### Changed
- Default upstreams for new installations: Cloudflare and Quad9 (DoH) plus dnsforge via DoQ and DoH (servers in Germany only). Existing installations keep their selection; dnsforge can be ticked there under *Upstream servers*.

## 1.21.0 – 2026-10-20

### New
- European upstream presets, each in its unfiltered variant (DNS64 filters itself):
  - DNS4EU (Whalebone, Czech Republic, co-funded by the EU): DoH and DoT, `unfiltered.joindns4.eu`;
  - dnsforge (adminForge, servers in Germany only): DoH, DoT and DoQ, variant “Blank” `blank.dnsforge.de`;
  - Freifunk München (Germany, second site in Vienna): DoH, DoT and DoQ (`doh.ffmuc.net`, `dot.ffmuc.net`, `doq.ffmuc.net`);
  - Digitalcourage (Germany): DoT only, `dns3.digitalcourage.de`.
- On existing installations the presets appear switched off; the default for new installations stays Cloudflare + Quad9. DNS0.EU is missing because the service has been discontinued.

## 1.20.0 – 2026-10-19

### New
- Device groups, phase G5:
  - Prometheus: `node64_dns64_group_queries_total{group,status}`, `node64_dns64_group_internet_off{group}`, `node64_dns64_group_free{group}`, `node64_dns64_group_members{group}`.
  - Configuration export/import carries the groups (members, rules, releases/blocks, schedules; without button state). A group of the same name on the new node stays as it is.
  - Dashboard card: number of groups and how many are blocked right now.
  - API: `GET /api/dns64/groups` returns the state of each group (`state`: internet_off, free, by_button, until_released, until, schedule), e.g. for Home Assistant.
- This completes the plan device groups and child safety (G1–G5).

## 1.19.0 – 2026-10-19

### New
- Schedules per device group (phase G4): on chosen weekdays from–to (also across midnight or all day, in the node’s time zone) either “internet off” or additional blocked categories; each can be switched on and off.
- Instant buttons per group: “Block” (30 min, 1 or 2 h, until tomorrow 7:00, until released) acts like “internet off”; “Free” (30 min, 1 or 2 h) suspends schedules and categories, blocklists keep applying; “Release” ends both. The state is shown in the group header.
- “Internet off”: only local names, custom records and the group’s releases work; all other names get the node’s address (TTL 10 s). If the device opens a page via http://, the shared entrance shows a notice on port 80 (group, reason, until when); for https:// the browser only shows a certificate error. Port 80 is only opened for this while a group can be blocked.
- Query log: reasons “internet off” and “schedule …: internet off”. API: `POST /api/dns64/groups/{id}/hold`, `POST /api/dns64/groups/{id}/schedules`, `POST /api/dns64/groups/schedules/{id}/enable|disable`, `DELETE /api/dns64/groups/schedules/{id}`.

## 1.18.0 – 2026-10-19

### New
- SafeSearch per device group (phase G3): one switch redirects Google (all country domains), Bing and DuckDuckGo to their SafeSearch addresses via CNAME and YouTube into restricted mode (strict, moderate or off). Also applies when the group released the domain; HTTPS stays untouched.
- Protection against bypassing per group: switches on the HaGeZi DoH/VPN/Proxy Bypass list for the group and answers `mask.icloud.com`/`mask-h2.icloud.com` (iCloud Private Relay) and `use-application-dns.net` (Firefox DoH) with NXDOMAIN.
- Firefox uses DNS64: `use-application-dns.net` is answered with NXDOMAIN globally so Firefox switches off its built-in DoH (like Pi-hole, on by default, can be switched off under *Settings*).
- Query log: reasons “SafeSearch → …”, “Firefox DoH switched off”, “iCloud Private Relay off”. API: `safesearch`, `youtube`, `bypass` in `PUT /api/dns64/groups/{id}/rules`, `firefox_canary` in the settings.

## 1.17.0 – 2026-10-19

### New
- Rules per device group (phase G2), under *Groups → Rules*:
  - blocklists like for all devices or an own selection from all presets and own lists;
  - block categories: social networks, games and streaming (small lists maintained by Node64, e.g. TikTok, Instagram, Roblox, Fortnite, YouTube, Netflix), gambling and adult content (switch on HaGeZi Gambling or HaGeZi NSFW for the group);
  - own releases and blocks per group (with subdomains). Order: release of the group before block of the group before categories before blocklists.
- DNS64 loads the globally enabled lists plus those a group uses in addition – each list once; which one applies to whom is a bit mask per rule (at most 64 lists).
- Query log: reason “blocked for group” or “category …”.
- API: `PUT /api/dns64/groups/{id}/rules`, `POST /api/dns64/groups/{id}/domains`, `DELETE /api/dns64/groups/domains/{id}`; `GET /api/dns64/groups` includes the rules.

### Changed
- Trackers hidden behind CNAMEs are also checked for answers from the cache (the cache is shared by all groups).
- The global pause suspends blocklists and categories, not a group's own blocks.

## 1.16.0 – 2026-10-19

### New
- Device groups (phase G1): new tab “Groups”. Create, rename and order groups (order = priority) and assign devices – by MAC address from the host’s neighbour table first (IPv4 and IPv6, via netlink), otherwise by IP address or network. A device thus stays in its group even with a new IPv6 or IPv4 address. A device belongs to at most one group.
- Devices of the last 24 hours (from the query log, with name from the router and MAC) can be assigned to a group with one click.
- Query log: group next to the client and filter by group (also “no group”); API `GET /api/dns64/log?group=`.
- API: `GET|POST /api/dns64/groups`, `PUT|DELETE /api/dns64/groups/{id}`, `POST /api/dns64/groups/{id}/move`, `POST /api/dns64/groups/{id}/members`, `DELETE /api/dns64/groups/members/{id}`, `GET /api/dns64/devices`; every change in the audit log.
- For now all groups share the same rules; lists, SafeSearch and schedules per group follow.

## 1.15.0 – 2026-10-19

### New
- 20 more blocklist presets (all off, checked for maintenance on 2026-10-19): HaGeZi Pro++, Ultimate and Pop-up Ads, Peter Lowe's Ad Servers; security: HaGeZi Fake (fake shops, subscription traps), HaGeZi Badware Hoster, Phishing Filter from malware-filter (CC0); bypass: HaGeZi DoH/VPN/Proxy Bypass (foreign DoH servers, VPNs, proxies); device tracking: HaGeZi Native Tracker for Samsung, LG webOS, Amazon, Apple, Windows/Office, Xiaomi, Huawei, TikTok and Roku; child safety: HaGeZi Gambling, HaGeZi NSFW, OISD NSFW.
- Presets carry a category badge (ads, tracking, security, device tracking, bypass, child safety).
- Lists: lines like `*.example.com` apply to the domain and its subdomains (used by Peter Lowe); `*.com` alone never blocks a whole TLD.

## 1.14.1 – 2026-10-19

### New
- Help links: on all DNS64 pages and at the main cards and fields (upstreams, mode, blocklists, allowlist, custom records, encryption, certificate, devices, client networks, router, notifications) a question mark opens the matching place of the documentation on node64.de in the language of the interface.

## 1.14.0 – 2026-10-19

### New
- Prometheus: queries per result and protocol, response times, refused queries, cache, blocklists, state and
  errors per upstream, and pause at `GET /api/metrics` (see docs/PROMETHEUS.md).
- Configuration export/import: the certificate from the certificate management is carried along and assigned on the new node (export with password, which contains the certificates).

### Fixed
- Overview: timeline, top clients and top domains stayed empty (error "disk I/O error") once the query log was large enough for SQLite to want temporary files while sorting. The container has no directory for them; intermediate results now stay in memory.
- Display: DNS64 logo is light in the dark theme.
- Port overview (Settings → Ports): DoH/DoT/DoQ only count as active when the service actually started (previously also on certificate errors).

## 1.13.0 – 2026-10-18

### New
- Internationalized domain names (IDN): entries such as `bücher.example` in blocklists (hosts, one domain per line, Adblock), in the allowlist and in custom records are converted to Punycode (`xn--bcher-kva.example`) and take effect; previously they were skipped as invalid.

### Changed
- Query log: expired entries are deleted in chunks of 5,000 rows, with writing continuing in between. A large backlog (e.g. after shortening the retention) no longer locks the database in one go, and no log entries are lost.

## 1.12.0 – 2026-10-16

### New
- Happy Eyeballs for the upstream servers (DoH, DoT, DoQ): IPv6 and IPv4 bootstrap addresses alternate, the next attempt starts after 250 ms or immediately on an error, and the most recently successful family goes first. A hanging address (IPv6 without a route, blocked IPv4) thus costs at most 250 ms instead of 2 s per connection.
- Router for local names over IPv6 as well: if there is no IPv4 gateway with DNS, DNS64 uses the IPv6 default gateway (link-local with interface, e.g. `fe80::1%eth0`). The router can now also be entered as an IPv6 address with zone or as `[IPv6]:Port`.

### Changed
- Hints under Settings mention IPv4 and IPv6 (address "all addresses (IPv4 and IPv6)", router).
- Test: DNS over UDP, TCP and DoT answers via 127.0.0.1 and ::1, including AAAA.

## 1.11.0 – 2026-10-16

### Removed
- DNS64's own Let's Encrypt integration (issuance and renewal via DNS-01, form on the encryption page, `GET|POST /api/dns64/acme`, `POST /api/dns64/acme/renew`, notification "DNS64 certificate"). Certificates are issued and renewed by the central certificate management, which also reports errors and expiry. The ipv64 API key is no longer needed in DNS64.

### Changed
- Installations that have not been migrated (e.g. terms of service not accepted) keep serving the previous Let's Encrypt certificate until the migration succeeds; the encryption page shows the reason. For this, the migration still reads `acme/` and the settings `dns64.acme_*`.

## 1.10.0 – 2026-10-16

### New
- Certificates from the central certificate management: under *Encryption → Certificate* any valid certificate from the certificate management can be selected ("From certificate management"). When the certificate management renews it, DNS64 picks it up immediately without a restart; the list there shows "used by: DNS64".
- The home network CA lives in the certificate management; it issues the server certificate for DNS64 and reissues it when names or private IPs change.

### Changed
- One-time migration on first start: DNS64's own home network CA (same key, devices keep trusting it) and an existing Let's Encrypt certificate including its key move into the certificate management, which handles renewal from then on; the acceptance of the terms of service is carried over. Afterwards the mode is set to "From certificate management". If anything fails, everything stays as before and the migration is retried on the next start. The previous files are kept as a fallback.
- New Let's Encrypt certificates are created in the certificate management; DNS64's own issuance remains only as a fallback for installations that have not been migrated and will be removed in a later version.

## 1.9.0 – 2026-10-16

### New
- Upstream mode "fastest (automatic)": each query goes only to the currently fastest servers (configurable 1–3, default 2) at the same time; the first good answer wins. The ranking is derived continuously from real response times; servers not currently being queried are re-measured every 30 s with a small query (which also keeps their connection warm). If the first ones do not answer in time (four times their usual time, 0.3–1.5 s), the next one is added; if all fail, the remaining ones are queried. Instead of 5–6 outgoing queries as with "Parallel", this usually means 2.
- Overview: the servers currently in use are marked "being queried"; API `GET /api/dns64/upstreams` returns `count` and `active` per server, settings `upstream_count`.

### Changed
- New installations start with "fastest (automatic)"; saved settings stay as they are.

## 1.8.0 – 2026-10-15

### Changed
- Client access list hardened: "Additional client networks" reject 0.0.0.0/0 and ::/0 (existing entries of this kind no longer apply). Networks on the node's own interfaces only count if they are private or an IPv6 /64 (or smaller); otherwise a public IPv4 network on a rented server would have admitted the neighbors in the data center.

### New
- DoH via the core's shared entry point: if the DoH port is the entry point's HTTPS port (default 443), DNS64 no longer opens its own listener but registers `/dns-query` on its names and for requests by IP. DoH and CDN64 thus share port 443; the entry point only lets through devices from the allowed networks (real remote address, otherwise a neutral 404), opens no port 80 for DoH and also offers DoH over HTTP/3. If a name already belongs to a proxy host, only that name is dropped for DoH. A different DoH port runs on its own listener as before.
- Warning in Settings for public networks in the access list.
- Rejected queries from unknown addresses are counted (Settings: count, most recent address) and written to the log at most once per hour, so that an accidental exposure gets noticed.

## 1.7.2 – 2026-10-15

### Fixed
- Under load, a restart or shutdown shortly after start could leave the DNS port (and DoT) occupied: the service only started after the stop and kept running, and a new start then failed with "address in use". Start now waits until the service is running.

## 1.7.1 – 2026-10-15

### Changed
- Audit log: changes via API key now carry their origin in the "Origin" field (key name); the "(api)" suffix in the details is gone.

## 1.7.0 – 2026-10-14

### New
- Everything in the UI is also available via the API: set up, issue and renew Let's Encrypt (`GET|POST /api/dns64/acme`, `POST /api/dns64/acme/renew`), enable/disable custom records (`POST /api/dns64/records/{id}/enable|disable`), import allowlist entries (`POST /api/dns64/allowlist/import`), CA and iOS/macOS profile (`GET /api/dns64/ca.crt`, `GET /api/dns64/mobileconfig`), custom upstreams and lists individually (`POST|DELETE /api/dns64/upstreams`, `POST|DELETE /api/dns64/lists`).
- Every change (settings, upstreams, lists, allowlist, custom records, encryption, Let's Encrypt including acceptance of the terms of service, pause, cache flush) is recorded in the audit log, from both UI and API (actor and IP as in the core, also behind a proxy).
- OpenAPI with request and response schemas for all DNS64 endpoints.

### Fixed
- A restart after changed settings and simultaneously disabling the module could leave the DNS port and DoH/DoT/DoQ open; start, stop and restart now run one after another.
- If stopping hangs, the upstream connections are still closed, followed by the query log.
- Errors when saving the acceptance of the terms of service were swallowed.

## 1.6.0 – 2026-10-14

### New
- Pause blocking: button at the top right of all DNS64 pages, for 10 minutes or until re-enabled. The DNS service keeps running, only the blocklists do not apply; custom records, local names and the allowlist remain in effect. The query log shows what would otherwise have been blocked; the dashboard card shows the pause.
- API: `POST /api/dns64/pause` (`{"minutes": 10}`, 0 = until re-enabled) and `POST /api/dns64/resume`; state in `GET /api/dns64/status` (`blocking`).

## 1.5.0 – 2026-10-14

### New
- Let's Encrypt: publicly trusted certificate for a name under an ipv64 domain (e.g. dns.<domain>), validated via DNS-01 through the ipv64 API with the central API key; DNS64 waits until the ipv64 name servers serve the TXT record and deletes it afterwards. This makes DoH/DoT/DoQ work on all devices without installing a CA, including Android "Private DNS".
- Automatic renewal 30 days before expiry; the new certificate takes effect immediately, without restarting the services. Until the first issuance, the services run with DNS64's own home network CA.
- Optionally, the name is added as a custom record pointing to the node's IP in the home network; the Let's Encrypt staging environment can be selected.
- Notification `dns64_cert` when issuance or renewal fails.

## 1.4.0 – 2026-10-14

### New
- Notifications via the default channels: upstream server disrupted for more than 3 minutes and reachable again, blocklist failing to load three times in a row; can be turned off under Settings. Webhook types `dns64_upstream`, `dns64_upstream_ok`, `dns64_lists`.
- Import allowlist: paste a list (one domain per line, e.g. allowlist.txt from the old DNS64 container or a Pi-hole whitelist).

## 1.3.0 – 2026-10-14

### New
- Encrypted in the home network: devices query DNS64 directly via DNS-over-HTTPS (RFC 8484, GET and POST, separate port, default 443), DNS-over-TLS (RFC 7858, 853/TCP) and DNS-over-QUIC (RFC 9250, 853/UDP); each service can be enabled individually, a port in use only stops that service.
- DNS64's own home network CA (10 years, may only certify private addresses) issues the server certificate: all private IPs of the node and the configured names, 800 days, reissued for new names/IPs or shortly before expiry. Alternatively, the web UI's certificate.
- New "Encryption" tab with status per service, connection details for devices, CA certificate and profile for iPhone/iPad/Mac (DoH or DoT) for download.
- Query log shows the protocol (TCP, DoH, DoT, DoQ).

## 1.2.0 – 2026-10-14

### New
- Upstream servers also via DNS-over-TLS (`tls://name[:853]`, RFC 7858) and DNS-over-QUIC (`quic://name[:853]`, RFC 9250); presets for Cloudflare, Quad9, Google, AdGuard and Mullvad over DoT as well as AdGuard over DoQ, custom servers with all three protocols.
- Certificate verification against the server's name for all protocols; connections are reused (DoT: up to 4 open connections, DoQ: one QUIC connection with one stream per query).
- Protocol per server visible in Overview and Settings, `proto` in `GET /api/dns64/upstreams`.

## 1.1.0 – 2026-10-14

### New
- Selectable upstream servers: Cloudflare, Quad9, Google, AdGuard, Mullvad or custom DoH servers with bootstrap IPs; mode parallel (fastest answer) or sequential (fallback on error).
- Blocklists can be turned on and off, more presets (OISD Big, HaGeZi Pro, HaGeZi Threat Intelligence) and custom list URLs; updates every 6, 12, 24 or 48 hours.
- Custom DNS records (A, AAAA, CNAME, wildcards such as *.home.lan) with automatic reverse lookup (PTR); take effect immediately, before blocklists, and are never sent to the internet. New "Custom records" tab.
- Selectable response for blocked queries: 0.0.0.0/:: or NXDOMAIN.
- Configurable cache size; client addresses in the query log stored in full, truncated (IPv4 /24, IPv6 /48) or not at all.
- Additional allowed client networks (e.g. public IPv6 prefix, VPN).
- API: `GET|PUT /api/dns64/settings`, `GET|POST /api/dns64/records`, `DELETE /api/dns64/records/{id}`; export/import includes all settings and the custom records.

### Changed
- Reasons in the query log (allowed, expired) appear in the UI language.
- Blocklists are stored in the data directory, named by URL; existing files are taken over.

## 1.0.0 – 2026-10-14

The standalone DNS64 container adopted as a Node64 module.

### New
- Local DNS resolver for the home network (UDP and TCP, default port 53), only answers private and directly connected networks (no open resolver).
- Blocking of ads, trackers and malware via 6 blocklists (StevenBlack, AdGuard DNS, OISD Small, HaGeZi Multi, EasyPrivacy, URLhaus), updated every 24 hours; trackers behind CNAMEs are detected.
- Queries to the internet encrypted via DNS-over-HTTPS (Cloudflare and Quad9 in parallel, fastest valid answer wins).
- Optimistic cache (20,000 entries): frequent domains are refreshed before expiry, expired entries up to 1 hour old are served immediately.
- Local names (e.g. fritz.box, .lan, single host names, reverse lookups of private IPs) only go to the router; client device names via PTR.
- Pages Overview (metrics, timeline, upstreams, cache, top lists), Query log (filters, search, live, allow with one click) as well as Allowlist and Blocklists.
- Settings: DNS port and address, router for local names, query log retention.
- Local API `/api/dns64/*`; export/import of settings and allowlist.
- When turned off, no processes run and no port is open.
