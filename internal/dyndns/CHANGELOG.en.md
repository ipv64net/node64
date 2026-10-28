# Changes – DynDNS updater

## 1.4.0 – 2026-10-28

### New
- Targets from the account: if more than one name is selected, "Add selection" asks in a dialog. It lists the
  names and warns that the updater immediately sets this connection's address for all of them and overwrites existing
  A and AAAA records.

## 1.3.2 – 2026-10-23

### Fixed
- Notifications come entirely in the language of the channel: “address not determined repeatedly” and “daily limit
  reached” were always English so far.

## 1.3.1 – 2026-10-19

### Changed
- Small help icons on cards and pages link straight to the matching section of the online documentation at node64.de (in the interface language).

## 1.3.0 – 2026-10-19

### New
- Prometheus: state, last successful update and last error per target, counts per state and calls to ipv64.net in
  the last 24 hours at `GET /api/metrics` (see docs/PROMETHEUS.md).

## 1.2.1 – 2026-10-19

### Fixed
- Display: DynDNS64 logo is light in the dark theme.

## 1.2.0 – 2026-10-18

### Changed
- Names behind the ipv64 reverse proxy/CDN: if DNS returns the CDN addresses, that is intended. The updater only maintains the origin address, no longer sends an update just because of the mismatch (saves update limit, no "changed elsewhere") and shows "current · DNS via CDN/proxy". Detected from the ipv64 response (address already known or family managed by the CDN) or already when selecting from the account; once a day it checks whether this is still the case.
- A "managed by CDN" response for one family no longer pauses the target; the other family keeps being updated.
- Selection from the account: names behind the CDN can be selected (note "via ipv64 CDN"); the CDN's own records are never touched.

## 1.1.0 – 2026-10-14

Review task: code review findings implemented.

### Changed
- DNS check: the expected address only needs to be among the returned ones (multiple A/AAAA allowed), both name servers are queried, the name is absolute (with trailing dot).
- Grace period after an update is at least two check cycles; "changed elsewhere" only counts from the second consecutive round.
- Automatic pauses are resumed: nohost, conflict, ignored and flapping after 6 h; badauth with API key hourly with a freshly fetched token.
- Pauses only based on the status or info response of update.php, not on text anywhere in the response; in prefix mode a 200 only counts with valid JSON.
- Server or network errors only hold back the affected target (2, 4, 8 … at most 60 min).
- In "address of this host" mode, a temporary privacy address is replaced by the stable one from the same /64.
- Without an enabled target, the regular check is idle (no queries, no entries, no limit fetch); "Check now" still works.
- "Update now" reports "already running" instead of waiting, and "nothing to report" when no current address is known.
- Token display only shows the last 4 characters.
- Audit via the core (user and IP as there), with the target as Target; "Check now" is logged.
- Local API: settings (`GET|PUT /api/dyndns/settings`), selection from the account (`GET /api/dyndns/account/names`, `POST /api/dyndns/targets/from-account`), refetch token (`POST /api/dyndns/targets/{id}/token`).

### Fixed
- "Limit almost reached" and "Limit reached" warnings shared one daily flag; now separate, check and set under lock, without a background goroutine.
- Pause due to "changed elsewhere" was not notified.
- A manually triggered error suppressed later automatic error notifications; notifications now once per incident, all-clear as soon as the core knows about it.
- Persistently failing IP detection (3 consecutive rounds) was not notified.
- Stopping during an update produced a "context canceled" error message; the log is now written even if the caller was cancelled.
- If a token was saved during a round, the round wrote back the old pause.
- "Refetch token" picked the wrong record for A and AAAA when the AAAA came first.

## 1.0.1 – 2026-10-14

### Changed
- The connection analysis (CGNAT/DS-Lite) runs again after every start of the module, e.g. after switching to host networking.

## 1.0.0 – 2026-10-14

First complete version, accepted live on the test box and the dev node (IPv4 and IPv6).

### New
- *DynDNS* module replaces the placeholder; when disabled, no goroutines run and no tables exist.
- Public IPv4/IPv6 and /64 prefix via `ipv4.ipv64.net` / `ipv6.ipv64.net` (connection pinned to the family), fallback API v2 `/ip`, optional custom check URL; check interval 1–60 min (default 5).
- Notice on possible CGNAT (100.64.0.0/10) or DS-Lite (192.0.0.1) based on the first hops to the internet, with links to article, FAQ and port mapper.
- Select targets from the account (central ipv64 API key in the settings) or create them manually; per name selectable what is updated; targets grouped under their domain.
- Always the most secure token: record token before domain token, in the HTTP header, stored encrypted, never output.
- IPv6 modes: address of this host, prefix only (zone-wide), prefix + interface ID, interface (stable address), fixed, off.
- Updater: only updates on mismatch (last reported and direct query of the ipv64 name servers), only the changed family, at least 5 s apart, backoff on cooldown, daily limit, 3 min grace period after an update.
- Automatic pauses with explanation: token rejected, name unknown, conflict (CNAME/CDN), ignored by ipv64, changed elsewhere.
- History of all updates and IP checks with filters, configurable retention; account update limit with its own counter and warning from 80 %.
- Notifications (address change, error/pause, limit) via the standard channels; ipv64 email/SMS directly via the API, not via the hubs.
- Local API `/api/dyndns/*` with OpenAPI docs; export/import without tokens (import fetches them with the API key).

### Fixed during acceptance
- `success` with `ip.ipv4 = ignore`/`cdn` was treated as success; the target now pauses.
- Second call shortly after an update while the name servers still returned the old state.
- If checking one family failed, the last known, outdated address was reported.
- Error notification also on "Update now" (now only for automatic runs).
