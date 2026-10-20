# Changes – Healthchecks

## 2.18.2 – 2026-10-20

### Fixed
- Status pages, list and compact views: on large screens the font grew with the window width (up to 30 px) and the page
  looked heavily zoomed. It now stays at 17 px at most; only the tiles for a wall monitor still scale.

## 2.18.1 – 2026-10-20

### Fixed
- Status pages, tiles view: groups with few checks only filled part of the width on large screens; the tiles now share
  the whole row.

## 2.18.0 – 2026-10-20

### New
- Status pages: own logo per page (PNG, JPEG, WebP or SVG up to 256 KB) in the header next to the name, also as favicon;
  without an own logo the tab shows the Node64 logo. "Provided by" shows the Node64 logo.
- Status pages: option "use the Healthchecks groups" – entries appear in their Healthchecks groups as blocks (without a
  group under "Other"), in all views.
- Status pages: responsive from phone to 4K monitor (text, tiles and bars grow; more tiles per row on large screens).

### Changed
- New status pages are published directly on the node port by default; PROXY64 with an own domain is the optional way.

### Fixed
- Status pages: online checks had no availability and no daily bars. ipv64's measurements now count when there are no
  own measurements for the day (no double counting for "both").
- Status pages: without data a "–" is shown instead of a gap; tiles and rows keep the same height.

## 2.17.0 – 2026-10-20

### New
- **Status pages** (Healthchecks › Status pages): a public overview of any number of checks in groups, with an overall
  banner, daily bars (30/60/90 days) and availability; groups with problems stay open, problems first. Clicking an entry
  shows availability over 24 h/7/30 days, average latency, 24 hourly bars and the latest incidents. Incidents and
  maintenance windows appear automatically, announcements are written by hand (with updates).
- Views list, tiles (for a wall monitor) and compact (for embedding); light/dark, accent colour, language, simple
  Markdown in description and footer, optional password and "do not index".
- Visitors only see display names, state and availability, never targets, IPs, ports or error messages.
- Status pages are off until you switch them on; nothing runs before that. Reachable via PROXY64 (host type "status
  page", own domain, also via CDN64) or, deliberately switched on, directly on the node port at `/status/<name>`.
  Computed only on request (cached for 30 s, compressed).
- Plus `status.json`, badges (SVG) and an Atom feed per page; API `/api/status-pages`.

## 2.16.1 – 2026-10-20

### Changed
- Healthchecks sync page: the switch for syncing via the cluster is gone; the page only shows whether it is on and
  links to the cluster page. It is switched only there.

### Fixed
- Online checks stayed on "Pending" after a day with the quota used up, although ipv64 measured again and all
  locations reported OK (hub): when the overall state is "Pending", the hub now re-evaluates on the next measurement
  of a location.

## 2.16.0 – 2026-10-19

### New
- **Cluster** instead of “local group”: own menu entry, nodes may also be in different networks. Healthchecks keep syncing via the hubs; the cluster is an additional path that can be switched off (switch on the Healthchecks sync page and under Cluster, separately for checks and maintenance windows; notification settings are a separate entry “Notifications” under Cluster).
- Cluster without ipv64: if no node has an ipv64 account, checks, measurements, evaluation and notifications run purely locally in the cluster.
- The connection between nodes is always encrypted (HTTPS, also via the normal web port); a valid certificate is not required.

### Changed
- Members without healthchecks switched on no longer count for measurements, notifications and forwarding to ipv64; neither do suspended nodes.

## 2.15.0 – 2026-10-19

### New
- Form: **Test from ipv64** – before switching to online or hybrid, the ipv64 locations measure the input once and show the result per location (API: `POST /api/checks/online-test`).
- Form: online limit as in the portal – locations above the account class are locked, used online measuring points are shown and checked on save.
- List: filters by execution location and node, account bar with class, online measuring points (used/limit), split online/local/hybrid and nodes online.
- Detail page: events rated by ipv64 itself (e.g. not monitored, monitored again, partially down) appear with a cloud icon next to the node's own events.
- Event kinds as coloured, translated badges; duration and reason for incidents (detail page and incident list).

## 2.14.1 – 2026-10-19

### Fixed
- Daily quota used up: online checks show “Quota used up” (list, detail page with a note until midnight) instead of “Not monitored”. ipv64 rates them the same way, silently and without a separate notification per check – the single “quota reached” notification is enough; at midnight it continues just as silently.
- Reminders while down: up to 10080 minutes (one week) as in the portal; previously the node rejected values above 1440.
- Reasons “Not monitored” and “Daily quota used up” translated; sorting by state knows all states.

## 2.14.0 – 2026-10-19

### New
- Check type **JSON**: fetches a URL like HTTP and checks values in the JSON response, one condition per line, e.g. `status == ok`, `queue < 100`, `items[0].up == true`, `tags contains web`, `version exists`, `name ~ ^web-[0-9]+$`. All conditions must be met, optionally one is enough. The value of the first condition appears in the message, and as a number also in the measurement details.
- Check type **DNS**: queries a name (A, AAAA, CNAME, MX, TXT, NS, SRV, CAA, PTR, SOA) via the default resolver, a specific server or directly the authoritative name servers of the zone. Expectation: any answer, contains values, exactly these values, regex, name does not exist (NXDOMAIN) or “points to my public IP” (for DynDNS domains). Optional DNSSEC validation and minimum TTL; the response time is measured.
- Both run locally, online and hybrid. Local only: private targets, a DNS server in the home network and “points to my public IP”.

## 2.13.0 – 2026-10-19

### New
- Prometheus: state, response time, last measurement, consecutive failures, maintenance and certificate expiry per
  check, plus counts per state and open incidents at `GET /api/metrics` (see docs/PROMETHEUS.md).

### Fixed
- Configuration export: group and measuring nodes of checks were missing from the export.

## 2.12.2 – 2026-10-19

### Fixed
- Configuration import: the notification channels of checks point to the imported channels of this node. Previously the channel numbers of the old node were kept, so on another node checks notified wrong channels or none (applies to exports from this version on).

## 2.12.1 – 2026-10-16

### New
- Hints about limits (daily quota, change rejected by the hub due to the online limit, locations in the form)
  link to the new overview of account classes.

## 2.12.0 – 2026-10-16

### New
- Separate state "Not monitored": a check without a measurement for 3 intervals (at least 5 minutes) no longer shows
  as "OK" but as "Not monitored" (yellow striped) – in the list, the filter and the header of the detail page. The
  detail page also states that all values come from the last measurement (with time and the state at that time) and which
  nodes measure it. API: `state.unchecked: true` (`state.state` stays the state of the last measurement).
- Dashboard: not monitored checks no longer count as "OK" but in a separate "Not monitored" tile.

## 2.11.0 – 2026-10-16

### New
- "Not being checked": if no measuring point has measured a check for 3 intervals (at least 5 minutes), e.g. because
  the only measuring node is offline, its row in the list is marked yellow (hourglass with the last measurement).
- ipv64 (hub) detects this itself: the check goes to "pending", and the notification "no longer being checked" is sent
  with the unreachable nodes; once someone measures again, "being checked again". An open outage stays open.
  Short connection drops trigger nothing; after a restart or database error of the hub, the check waits 10 minutes.
- List: rows are lightly tinted – down red, flapping or partially down orange, not checked yellow.

## 2.10.0 – 2026-10-15

### New
- Other modules can create a check the same way as the API (validation, sync, local group, limits and audit included). CDN64 is the first to use it with "Create healthcheck for this target".

## 2.9.1 – 2026-10-15

### Fixed
- Local group: after "down" → "partially down" → "OK", the group now reports "reachable again" like the hub
  (the outage stays open until "OK", flag `group_open`, exchanged within the group). Previously only
  "partial outage ended" was sent, which was suppressed without "report partially down" – the end was missing.
- Notifications sent by the node itself (group, modules): the node sends portal channels such as webhook or Telegram
  itself; only mail, SMS and app go through the ipv64 API (previously error 422).

## 2.9.0 – 2026-10-15

### New
- Proxy nodes: checks measured by nodes of the local group without their own ipv64 link now appear in the portal via
  the forwarding node, with states and measurements. Notifications stay with the group; the group also evaluates the
  overall state of such checks on linked nodes.

## 2.8.0 – 2026-10-15

### New
- `POST /api/checks/bulk`: bulk actions via API (pause, resume, check now, delete, set or
  remove tag) with a result per check; bulk actions (also in the UI) get a single summary entry in the audit.

## 2.7.2 – 2026-10-15

### Fixed
- The check token (which also authorizes the push URL) now appears only truncated in audit and logs
  (first 6 characters), no longer in full.

## 2.7.1 – 2026-10-15

### Fixed
- `PUT /api/online-checks/{token}`: fields not provided keep their value at ipv64 (like `PUT /api/checks`)
  instead of being dropped.
- Audit: Healthchecks entries go through the core and show the origin (UI or which API key);
  creating an online check names the token so later entries can be matched.

## 2.7.0 – 2026-10-14

### New
- JSON API for online checks in API mode (ipv64 API key only, no sync): `/api/online-checks` – list,
  create, read, update, delete, pause, resume, check now; same input validation and same
  audit entries as in the UI.

## 2.6.2 – 2026-10-14

### Fixed
- The first state of a new check was lost if it reached the hub before the check had been created there;
  with long intervals (e.g. certificate) the check stayed "pending" in the portal and on other nodes for hours.
  The node now reports the state again after creation.
- Audit: the actor for checks and maintenance windows was always "api" (and spoofable via API key) instead of the
  user; the IP is now determined as in the core (also behind a proxy).
- Added audit entries for "Check now" and for online checks in API mode (create, update, pause,
  resume, check, delete); errors in doing so are logged.
- Local group: no more pings without Healthchecks running; the per-request account check no longer reads
  the entire sync status; if Healthchecks is only enabled after startup, the existing checks
  still get into the group.

## 2.6.1 – 2026-10-14

### Fixed
- Local group: a node without Healthchecks sync got stuck while taking over the forwarded hub data
  (it was waiting on itself in the database) and was no longer reachable for the group.

## 2.6.0 – 2026-10-14

### New
- Local group: a node linked to ipv64 forwards the data from the hub to nodes without Healthchecks sync –
  the overall state of checks that no node of the group measures (e.g. online checks), and the measuring points
  outside the group (ipv64 locations, other nodes) including history. A node without sync thus shows all checks
  completely.

## 2.5.0 – 2026-10-14

### New
- Local group: the account's notification settings (quiet hours, limits, summary notification) are synced
  between the nodes; changes on a node without Healthchecks sync go to ipv64 via the group.
- Detail page: "Notified by" shows who reports a status change (ipv64, this node or a node of the
  group).
- The group card explains what is synced, shows which nodes are linked to ipv64 and which node
  forwards changes to ipv64.
- The selection of measuring nodes is also available without ipv64 sync as soon as the node is in a group.

## 2.4.0 – 2026-10-14

### New
- Local group: maintenance windows are synced between the nodes (create, update, delete on any node).
  A linked node forwards windows from nodes without Healthchecks sync to ipv64; the same window from the hub
  and from the group is merged, not created twice.

### Fixed
- Changes from ipv64 were bounced back and forth once more between linked nodes of the group.
- If ipv64 rejected a single change on its content, the hub was treated as "not confirming" and the node sent
  its notifications itself; this now only applies to a real outage (database error, no response).
- Group notification: if a node took over when the reporting node failed, it could miss a transition (e.g.
  the all-clear) because it had adopted another node's state. Only the reporting node now writes the
  reported state.

## 2.3.0 – 2026-10-14

### New
- Local group: if several nodes of the group measure a check, exactly one notifies – the first reachable one
  in the list of measuring nodes (the owner node; if it fails, the next one). The reported state is the
  overall state of all measuring points as with ipv64 (incl. "partially down" if enabled). When a node
  comes back, it adopts the group's state and does not report anything twice.
- Without ipv64 sync or for checks unknown to ipv64, these notifications go through the channels of the reporting
  node (ipv64 mail/SMS via the API key); otherwise ipv64 keeps notifying.
- The nodes of the local group are available for selection as measuring nodes (also without ipv64 sync).

### Fixed
- Reminders ("still down") were also sent by a node that does not measure or own the check.

## 2.2.0 – 2026-10-14

### New
- Local group: measurements and states are exchanged between the nodes. Each node shows the checks of the
  others with current state, measuring point table and chart (a new node receives the last 24 h).
- Without Healthchecks sync (or for checks unknown to ipv64), the node determines the overall state from the
  group's measuring points using the same rule as ipv64, including outages. If the measuring node is not
  reachable, the state becomes "pending" after 2 minutes; an open outage stays open.

## 2.1.0 – 2026-10-14

### New
- Local group: nodes of the same ipv64 account in the local network sync their checks with each other (create,
  update, delete on any node, everywhere within a few seconds). The newer change wins; channels remain a
  per-node setting.
- A linked node of the group forwards changes from nodes without Healthchecks sync to ipv64. Checks that
  are only measured on nodes without sync stay within the group.

### Fixed
- Without sync (API key only), online checks coming from the group appeared twice in the overview.

## 2.0.0 – 2026-10-14

Healthchecks 2.0: first complete version in Node64, locally and together with the ipv64 hubs.

### New
- Check types HTTP(S), keyword, ping, TCP port, DNS, certificate expiry, push and Docker container (socket/TCP); port only in the port field, host:port in the target is taken over.
- Measuring points per check: local, online (ipv64 hubs), hybrid and multiple measuring nodes; display of where a check is measured (Online, Hybrid, Local, Other node).
- Healthchecks sync with ipv64: linking via code or with one click via the API key, outbox and conflicts, everything editable from any node (checks, channels, maintenance, check now via the hub).
- Online checks also without sync directly via the ipv64 API v2 (API key only).
- Daily quota of online checks as in the old system: preview in the form, projection in the dashboard, notification when reached.
- Overview with target badges, groups, filters, bulk actions and countdown to the next measurement; view for phone and tablet.
- Detail page with chart per measuring point (legend filters), events with reason and HTTP code, outages and maintenance windows.
- History of other measuring points is loaded from the hub (individual measurements 2 days, hourly values 90 days).
- Notifications via the core's channels, browser notifications; data retention and chart resolution configurable.
- Local API `/api/healthchecks/*` with OpenAPI docs; export/import.

### Fixed during acceptance testing
- Online checks and checks of other nodes ended up in the local scheduler.
- History of other measuring points was lost when changing the measuring points.
- Ownership of a check stayed with a node that no longer measures it; it now passes to the first measuring node.
