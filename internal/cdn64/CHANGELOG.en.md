# Changes – CDN64

## 1.12.0 – 2026-10-19

### New
- Dashboard card: requests, traffic, 5xx errors (with share) and rejected requests of the last 24 hours, plus active TCP streams.

### Fixed
- Statistics: evaluations over long periods could fail with "disk I/O error" (no directory for SQLite temporary files in the container); intermediate results now stay in memory.
- Display: CDN64 logo is light in the dark theme.

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
