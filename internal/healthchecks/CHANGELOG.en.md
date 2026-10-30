# Changes – Healthchecks

## 2.48.0 – 2026-10-30

### New
- Proxmox VE and Docker: when editing a check, the subgroup (system) can be set by hand, e.g. when two Proxmox
  clusters have the same name. It is kept on every poll and also applies in the portal; empty = automatic again
  (cluster name or name of the system).

## 2.47.1 – 2026-10-30

### Fixed
- IPv6 targets: internal addresses are also detected in other notations (`::ffff:10.0.0.1`, `[::ffff:7f00:1]`,
  `0:0:0:0:0:0:0:1`, `::`, `fe90::1`, site-local `fec0::/10`, IPv4-compatible `::/96`, CGNAT and documentation
  ranges). Names such as `fcbayern.com` or `fdroid.org` no longer count as internal.
- HTTP target as IPv6 without scheme and brackets (`2001:db8::1`): the last block was read as the port.
- Proxmox VE/PBS: an address as IPv6 without brackets (`fd00::10`) became `[fd00:]:10`; Docker: `tcp://fd00::1`
  without brackets was accepted and is now rejected (`tcp://[fd00::1]:2375`).
- Link-local targets with a zone (`fe80::1%eth0`) are rejected with a clear message for ICMP, TCP/port, certificate
  and HTTP; the zone was lost during resolution.
- Status pages: the lock after wrong passwords applies per /64 for IPv6 (changing the address within the network no
  longer helps), v4-mapped addresses count as IPv4. A full table only drops expired or the oldest entry, active locks
  stay.
- Online (hubs): the limit per target host counts an IPv6 address in any notation as the same target.
- Portal: internal IPv6 targets detected as in the node; a DNS server given as IPv6 without brackets (`fd00::53`) is
  no longer cut off.

## 2.47.0 – 2026-10-30

### New
- Proxmox VE: storage on the system page – all storage of the cluster (local, local-lvm, ZFS, NFS, Ceph …), local
  storage per node, shared storage once, with type, content, usage and size; unavailable storage is shown with a hint.
  The rule "Storage used from" (default 90 %, system level) reports full storage like the datastores of a PBS, one per
  storage, all-clear 2 percentage points below the limit. Also in the API (`storages`).

## 2.46.0 – 2026-10-30

### New
- Proxmox Backup Server: usage alarm for datastores. Two rules on the system level of the PBS, valid for all
  datastores: "Datastore used from" (default 90 %) and "Datastore full in less than … days" (from the PBS estimate,
  default off). Notifications work like the node thresholds (delay, channels of the system), one per datastore; the
  all-clear comes only 2 percentage points or 2 days past the limit. Datastores above the limit are marked red in the
  table. Backups, tasks and services stay display only.

## 2.45.0 – 2026-10-30

### New
- Proxmox Backup Server: under Health checks → Proxmox VE there is now an "Add Proxmox Backup Server" button next to
  "Add Proxmox VE" (API token with role Audit, port 8007, fingerprint as with Proxmox VE). The host system is monitored
  like a Proxmox node: CPU, RAM, root disk, network and disk I/O with history, rules (reachable, restart, thresholds)
  and optionally as a check. For information only: datastores with usage, "estimated full", dedup factor, groups,
  snapshots and last backup across all namespaces, failed tasks of the last 7 days and the services
  proxmox-backup/proxmox-backup-proxy. For a PBS the version badge comes from its own package list (apt).

## 2.44.0 – 2026-10-30

### New
- Proxmox VE and Docker: the overview shows a small badge next to the version when a newer version exists (tooltip:
  installed and available; a new major version is named separately). Just a hint – no notification, no event, no
  state. Node64 checks at most twice a day: Docker in the stable package directory at download.docker.com, Proxmox VE
  the pve-manager version in the pve-no-subscription repository.

## 2.43.0 – 2026-10-29

### New
- Cluster: nodes without their own link forward pushes for online and hybrid checks directly to ipv64 (push address
  at ipv64); the detail page also shows the push address at ipv64. Online-only push checks give the ipv64 address as
  `push_url` in the API.

### Fixed
- Cluster: online and hybrid checks on nodes without their own link check the account limits (locations per check,
  online measuring points) via the API key (`GET /hc2/account`); if they are not readable, nothing is created or
  moved online. Before, the node accepted everything, the hub rejected it only at the forwarding node and the check
  was measured nowhere.
- Cluster: forwarding node and display follow the same rule (linked, reachable, health check sync on, smallest id).
  Before, a node without sync could count as responsible and nobody forwarded.
- API log: check tokens in the path (`/api/push/…`, `/api/checks/…`) are shortened (they are also the push
  credential).
- Linked node: after changing quiet hours/limits or name/location on the node, its configuration state stood still
  until reconnecting; the hub now sends the change back. The one-time sync after the update from 2.42.0 runs as a
  full sync that also removes checks deleted in the portal.

## 2.42.0 – 2026-10-29

### Fixed
- Linked node: a change from the portal or the API (e.g. a new online check) made at the same moment as a change on
  this node never arrived on this node, not even after reconnecting. The revision now only advances when it follows
  directly (node and hub). After the update every linked node fetches its configuration once from the start, so
  changes skipped earlier arrive.
- Cluster: changes a node without link made while separated only reached the portal after the forwarding node
  restarted; now right after rejoining.

### New
- Cluster: a node that is not linked can create, edit and move online and hybrid checks when a linked node of the
  cluster is reachable (it forwards the change to ipv64). Before, it refused ("need the ipv64 link"), even for
  renaming an online check.
- Proxmox VE and Docker: "Stopped is correct" – on a guest or container shown as a problem because it is stopped or
  exited (row on the system page and the guest page). Sets "Stopped is a problem" to no: fine immediately, a reported
  problem clears silently (no all-clear message), the last problem on the start page disappears if it was this guest.
  Undo in the guest settings. Audit `proxmox.ack`; API via the settings (`expect_running: false`). This also applies
  when the setting is set to no by hand or via the API.

### Fixed
- Proxmox VE: A backup that briefly starts a stopped guest (lock `backup`) marked it as "has run before" – afterwards
  Node64 reported "stopped" although nothing had changed. Running with a lock and the poll right after a lock no longer
  count as a run (metrics are still recorded).

## 2.41.0 – 2026-10-28

### New
- Cluster: status pages can be synced (area "Status pages", off by default) – with groups, checks in their order,
  options, visibility, password, logo and notices. PROXY64 hosts of a status page stay per node. The same slug with
  different content is not taken over (note in the log).
- Cluster: notification channels can be synced (area "Channels" under notifications, off by default) – only the
  node's own channels including credentials (stored with the other node's key), never those of the portal, not the
  browser channel and none with "secret only local". The channels of the checks are then correct on every node.
  Needed mainly for nodes without a connection to ipv64.net.

### Changed
- Proxmox VE and Docker: checks show a real latency instead of 0 ms or the Docker API time – ping to the address of
  the node, guest or container (one packet, at most 2 s), otherwise the response time of the Proxmox or Docker API.
  The source is in the raw result (`latency_source`: `ping` or `api`). The status is unchanged, a failed ping never
  turns a check red.
  - Proxmox: node addresses from `cluster/status`; addresses of running guests as check every 5 minutes via the guest
    agent (VMs, privilege `VM.Monitor`, from PVE 9 `VM.GuestAgent.Audit`) or `lxc/{vmid}/interfaces` (containers).
- Cluster: items that were already set up exactly the same on two nodes (status page, channel, Proxmox system, Docker
  host, maintenance window) are merged into one when joining or switching the area on instead of appearing twice.
  Merely similar items stay separate. Checks are never merged (the same check on two nodes = two measuring points).

## 2.40.0 – 2026-10-28

### Changed
- Notifications directly via the ipv64 API: checks measured only by this node (local, no other measuring points) are
  alerted by the node itself even when linked – ipv64 mail, SMS and app via API v2, own channels directly (previously
  as send orders via the hub). This applies to down, up, flapping and reminders.
  - Other portal channels (e.g. webhook, Telegram) are still sent by the hub, their secrets stay at ipv64. For such
    checks the hub now also sends reminders to these channels.
  - Checks with online measurement or several measuring nodes (also in the cluster), and "not checked", alert as
    before.
  - Only with an API key and an updated hub; otherwise as before.

## 2.39.0 – 2026-10-28

### Fixed
- Maintenance windows: an outage that starts during maintenance and continues afterwards is alerted; reminders and
  group alerts pause during maintenance; recurring windows keep their local time across DST.
- Dependent checks alert the outage once the parent is back; flapping that ends failed alerts as down instead of
  "stable again".
- Incidents are closed reliably (flapping, pause/resume, owner change) and not duplicated; push no longer loses data on
  cancelled requests.
- Status pages: with "show uptime"/"show history" off, that data is also left out of JSON and badges.
- History values at the retention boundary are no longer distorted; relayed measurements are no longer uploaded as own.
- ICMP: a lost ping counts as packet loss instead of a timeout; HTTP/keyword/JSON honour a custom Host header (incl. SNI).
- Notifications: temporary errors are retried for all channel types, never to deleted or changed channels; error texts
  shortened.
- Docker via unix socket: no more leaked idle connections.

## 2.38.1 – 2026-10-27

### Fixed
- Docker and Proxmox checks ran online at ipv64 (Nuremberg, Falkenstein) after their node was removed in the portal.
  On removal, the portal switched all checks without a private target to "online". A container or guest name does not
  count as a private target, though.
  - Now the hub never measures Docker and Proxmox checks online, even if the database says so.
  - The portal never switches them to online and deletes them with the node instead. Proxmox is now "node only" there,
    like Docker.
  - A portal job (every 10 minutes) moves such checks back to the node that measured them last.
- In the portal, a Docker or Proxmox check with several measuring nodes from the cluster can be edited again.

## 2.38.0 – 2026-10-27

### New
- Proxmox VE and Docker in the cluster: Cluster → Healthchecks has the new areas "Proxmox VE" and "Docker" (off by
  default).
  - With an area on at two nodes, the systems including API token or credentials go to the other node. There they are
    stored encrypted with its key and polled too. Creating, changing and deleting are synced.
  - Docker only for hosts over the network (`tcp://`, `http(s)://`, `ssh://`); a local socket stays with its node.
  - Docker and Proxmox checks can then have several measuring nodes: the form offers the nodes that sync the area (and
    the checks) too. Syncing, evaluation and notifications as for all cluster checks; the node that created the check
    stays first.
  - Notifications of the monitoring itself (guest stopped, thresholds, system unreachable) are sent only by the node
    that created the system; if it is unreachable, by the reachable node with the smallest ID. Nothing is sent twice.
  - For this every system has a cluster ID (`uid`); Proxmox checks carry it as `params.system_uid`; older checks get
    it at start.
- hub: Docker and Proxmox checks keep the measuring nodes the node sends (before, always only the owner node). They
  still cannot be moved and never run online.

## 2.37.3 – 2026-10-27

### Changed
- Dashboard: the tiles for Healthchecks, Proxmox VE and Docker are more compact. Number and label share one line, the
  icon is smaller and the spacing tighter. The card needs about half the height.

## 2.37.2 – 2026-10-26

### Changed
- Dashboard: below the Healthchecks tiles there are now separate tile rows for Proxmox VE (systems OK/with problems,
  guests running/with problems) and Docker (hosts OK/with problems, containers running/with problems), each with a
  link, a note for unreachable systems and the last incident. The former single Proxmox card is gone; Docker had none
  so far.

## 2.37.1 – 2026-10-26

### Changed
- Clear channels: for checks kept "as check" (Docker containers, Proxmox VMs) the channels are set only on the host or
  container. "Edit check" shows them there read-only, with a link and the channels in effect. Before, they could also
  be changed on the check, and the next save of the rules overwrote them again.
- Without ticks the check form now names the default channels that apply (like the detail page). For host, node and
  container, "inherited: default channels" also says which they are.


## 2.37.0 – 2026-10-26

### New
- Status pages: switch “Group by Healthchecks groups” (on by default). When off, the page shows one list without
  headings – group names and the names of Proxmox VE and Docker systems stay internal.

### Fixed
- Checks written by a newer node or ipv64.net with additional parameters (such as the system name) are taken over
  instead of rejected; unknown fields are dropped.
- Docker kept as check: the Docker host's name (grouping) is kept when editing and when the host's address changes,
  even while the host is unreachable.
- New check from a system: after an input error the chosen VM or container stays selected, even if another system has
  an entry with the same ID.


## 2.36.2 – 2026-10-26

### Changed
- Docker like Proxmox VE: switching a Docker host's monitoring off (pause) pauses its containers kept as checks, and
  the check list shows them as paused; switching it on resumes them. Before, they kept checking themselves (except
  SSH/TLS) and stayed "OK".

## 2.36.1 – 2026-10-26

### Changed
- Editing a status page: “Entries” and “Add checks” sit side by side on wide screens (stacked below that).

## 2.36.0 – 2026-10-26

### Changed
- Status pages: the page's own groups are gone. The page always groups by the healthchecks' groups, in “Proxmox VE”
  and “Docker” with the system's name (“Proxmox VE · cluster”). Existing pages show these groups right away;
  selection, order and display names of the entries stay.
- Editing: “Entries” is a simple list (name, group, display name, remove). “Add checks” is a single list for all
  checks and for nodes, VMs, LXC and containers without a check – with search (also by system), filters by group and
  tag, “Select visible” and “Add selected”. Entries without a check are created as a check when added, as before. The
  switch “Use the healthchecks' groups” is gone.

## 2.35.0 – 2026-10-26

### New
- Checks kept from Proxmox VE and Docker carry the name of their system in their parameters (`system`: cluster name
  or system name, name of the Docker host). The node keeps it current on every poll; it is synced to ipv64, where the
  portal sorts the checks into the same subgroups. Other nodes show foreign checks under the system's name as well
  (Docker with the node).

## 2.34.0 – 2026-10-26

### New
- Check list: the groups “Proxmox VE” and “Docker” get a collapsible subgroup per Proxmox system or Docker host,
  with counters. The name comes from the monitoring on every view: for Proxmox the cluster name from the last poll
  (otherwise the system's name), for Docker the host's name. Checks of another node are listed under its name. The
  open/closed state is remembered in the browser.

### Fixed (ipv64)
- Proxmox and WHOIS checks were rejected by the Healthchecks sync (“database error”): the database at ipv64 lacked
  the types. SQL `hc2_check_types_proxmox_whois.sql` – then “Send again” in Healthchecks sync.

## 2.33.0 – 2026-10-26

### New
- New check from a monitored system: the type list offers “Proxmox VE (VM, container, node)” and “Docker container”.
  Then you pick the Proxmox system or Docker host and the machine or container from the last poll. It is created like
  “also run as check” (interval, group and channels from the rules, no duplicate alert); the name is optional (empty =
  “system – name”). Entries already kept as a check are marked and locked. “Monitor a container” on a Docker host page
  preselects the host.

### Changed
- The raw type “Docker container” (container name typed by hand) is no longer offered for new checks. Existing Docker
  checks stay and remain editable; API and import are unchanged.

## 2.32.0 – 2026-10-26

### Changed
- Docker like Proxmox VE: the page always starts with the overview of the monitored Docker hosts (tiles, table with
  state, containers, CPU/RAM, edit, off, delete), even with a single host; only a click opens the host.
- The local Docker socket is no longer monitored automatically. It is only added when you add it (form “Add Docker
  host” or button “Add this machine” in the overview). Without a host the overview shows an entry like Proxmox VE and
  points to existing Docker checks in the check list. Existing hosts stay set up.
- The host page shows the host's name and has a delete button; afterwards you return to the overview.
- State of a system (Docker and Proxmox VE): “attention” is now “partly impaired” (single containers, guests or nodes
  impaired), besides “OK” and “unreachable”.

## 2.31.0 – 2026-10-26

### Added
- Check type **WHOIS / RDAP**: registration data of a domain, an IP address or network, or an AS (AS3320). First via
  RDAP (responsible server from the IANA bootstrap), otherwise via classic WHOIS on port 43 (chain whois.iana.org →
  registry, e.g. for .de). The values found are shown under “Last measurement”: for domains registrar, status, name
  servers, registration, last change and expiry; for networks and AS the name (netname), range, CIDR or route, origin
  AS, organisation, country, city/address and abuse contact.
- Down when the query fails, the domain is not (or no longer) registered, it expires in fewer than “warn before expiry”
  days (default 14) or an expected value is missing (e.g. “nameserver: ns1.ipv64.net”, “country: DE”).
- Considerate towards the servers: at most hourly, every 10 minutes while down; limited answer size. Runs locally and
  online at ipv64.

## 2.30.0 – 2026-10-26

### Fixed
- Healthchecks sync, conflicts: a conflict appears when ipv64 rejects a change of this node. So far the reason was
  missing, every card said “deleted on the server”, and “Keep server version” deleted the entry here – even a check
  ipv64 has (e.g. a Proxmox or Docker check). “Send my version” ran into the same rejection. Now:
  - The card names the reason for the rejection and shows the current state at ipv64 (the hub sends it along).
  - “Take ipv64 state” restores that state here; “Delete here” is only offered if ipv64 really does not have the entry.
  - “Send again” sends the own version once more (e.g. after the limit was raised).
  - New: “Keep here only” – the change stays on the node and is no longer sent to ipv64.
  - Older conflicts without a stored reason are never deleted; “Send again” fetches reason and state.
- “{count} conflicts” showed the placeholder instead of the number.

## 2.29.1 – 2026-10-25

### Changed
- Check form, “Sources and evaluation”: with “local on nodes” the online locations (Nuremberg, Falkenstein) and the ipv64 test are hidden; they appear only with “online” or “both”.
- Online measurement at ipv64: targets must be publicly reachable – a hostname, redirect or DNS server must not point to an internal address either. Timeouts at most 30 s (connect) / 60 s (total), retry while down at the earliest after 20 s.

## 2.29.0 – 2026-10-25

### Added
- Notifications via SecNtfy (secntfy.app): end-to-end encrypted push – title and text are encrypted with the device's public RSA key, only the device can read them. Enter the device token (NTFY-DEVICE-…), server adjustable (default api.secntfy.app), problems optionally as critical alert. In the node and in the portal (sent by the hubs).
- An encrypted block holds little: only SecNtfy shortens long messages (text at most 150 characters, title to fit the key), all other channels get them in full.

## 2.28.1 – 2026-10-25

### Fixed
- Proxmox VE, system page: the “Guests” and “Guests running” cards showed the raw guest list (`[{qemu …`) instead of the count. They show the number now.

## 2.28.0 – 2026-10-24

### Added
- E-mail and SMS via ipv64 can be managed with the API key in the normal channel table of the notifications like all
  other channels: create, edit, on/off, default, test, delete and the confirmation by code directly in the node (badge
  “ipv64”, unconfirmed ones with a badge and link to confirm). They are stored at ipv64 and apply to the whole account.
  The separate card for them is gone.

### Changed
- The “Browser notifications” card is half width below the channel table.

## 2.27.1 – 2026-10-24

### Changed
- Notifications with an API key (without linking): instead of “SMS/e-mail via ipv64 – after linking” the page shows
  the confirmed e-mail and SMS channels of the account (read only) and a link to create them on ipv64.net; the node uses
  them via the API key.
- iGotify is no longer a channel type of its own (it is a normal Gotify server); existing iGotify channels become Gotify.
  The Gotify channel mentions iGotify for the iPhone in its hint.
- Without linking to the Healthchecks sync, health check alerts (not only module messages) now also go via the API key
  to e-mail, SMS and app of the account; the ipv64 app is included as a channel.

### Fixed
- SMS quota 0 means “unlimited” at ipv64 (Business, Company) – node and portal showed “SMS not included in your class”
  and the portal refused to create an SMS channel.

## 2.27.0 – 2026-10-23

### Added
- Notifications to Slack (incoming webhook), Microsoft Teams (Workflows webhook with Adaptive Card; the old Office 365
  connectors stopped working in May 2026) and Matrix (bot account with access token, room ID or alias) – locally on the
  node and as server channel on ipv64.net. Colour like the status bar of the mails, “Details” link.

## 2.26.0 – 2026-10-23

### Added
- Status pages: when adding entries there are separate cards next to the checks for Proxmox VE (nodes, VMs, containers per
  system) and Docker (containers per host) – only if Proxmox systems or Docker hosts exist. If an entry has no check yet,
  one is created when adding, like “also run as check” (notifications of the rules, no duplicate alerts). Checks of
  nodes, guests and containers are only listed in their card.

### Fixed
- Deleting a check (also via another node, ipv64 or turning off “as check”) removes it from all status pages; entries
  of already deleted checks are removed on update.

## 2.25.0 – 2026-10-23

### Added
- Below the check table a card for the daily quota of online checks (only for classes with a quota, e.g. Free and
  Home/Supporter): usage today as a bar, projection until midnight from the active online and hybrid checks, the
  expected time the quota runs out, and a note when a full day needs more than the quota.
- Local checks may run every 5 seconds; online and hybrid stay at 20 seconds minimum (node, hub and portal). The retry
  interval is capped at the interval.

## 2.24.3 – 2026-10-23

### Added
- Proxmox VE: the page of a system has KPI tiles at the top like the overview – nodes online (with cluster name and
  quorum), guests, running, with problems (clickable as filter) and load (CPU, RAM, cores).

### Changed
- Rights hint: with a token using “Privilege Separation” only what user and token both may counts – the hint now shows
  the commands for both.

## 2.24.2 – 2026-10-23

### Fixed
- Proxmox VE: a cluster whose token may not read `cluster/status` (Sys.Audit on “/” missing) shows as “Cluster –
  quorum unknown” instead of “single node”; the hint names the missing right exactly and shows the pveum commands to
  check and set it with the token ID.
- Notifications name the reason as text in the language of the channel (“Reason: Timeout”) instead of an internal
  code (“timeout”).
- Notifications of a Docker host are now called “Docker: … down” instead of “Proxmox: …” (an unreachable
  Docker host with high priority like Proxmox).
- Docker form: setup on the host for SSH is a step-by-step guide with the “Generate key” button and ready-to-copy
  commands (create user, add the key with permissions, compare the host key).

## 2.24.1 – 2026-10-23

### Fixed
- Remote Docker hosts (review): containers kept as checks of an SSH/TLS host are paused while the host is switched off
  (no false alerts); changing the address moves its checks along, another machine starts without the history and
  “seen running” of the old one; switching the connection type or removing CA/certificate no longer keeps old
  credentials or the old fingerprint; SSH host key: Ed25519 first (as `ssh-keygen -lf …ed25519_key.pub`), host
  certificates by their key; the fallback to `docker system dial-stdio` is no longer permanent; editing keeps addresses
  unchanged (port, path, http://); “Test connection” without host no longer tests the local socket; deleting a host
  keeps Docker checks that query on their own (only SSH/TLS checks are removed); creating a remote host via API no
  longer brings back the removed local host; a changed `NODE64_DOCKER_HOST` no longer creates a second local host;
  import: entry without address no longer aborts, TLS host without credentials arrives switched off with a hint;
  host pages only show their own checks, overview counts like the host page; Docker checks on the local socket reuse
  their connection; container suggestions in the check form also for SSH/TLS hosts.

## 2.24.0 – 2026-10-22

### Added
- Remote Docker hosts without an agent: under Healthchecks → Docker further hosts can be added – via SSH
  (recommended; Node64 generates the key, the host key is confirmed in the test, works via socket forwarding or
  `docker system dial-stdio`, so also with `restrict,command="docker system dial-stdio"` in authorized_keys), via the
  Docker API with TLS (port 2376, client certificate, CA or confirmed fingerprint) or via docker-socket-proxy
  (TCP 2375). Credentials are stored encrypted. With two or more hosts there is an overview with tiles across all
  hosts; “Track as check” uses the same connection for SSH/TLS.
- Proxmox VE: the overview has tiles across all systems and clusters – systems, nodes online, guests running and with
  problems, load (CPU, RAM) with the last incident.

## 2.23.0 – 2026-10-22

### Added
- Docker monitoring like Proxmox VE: with a reachable Docker socket the host is set up automatically and all
  containers are monitored – state, health, restarts, exit code/OOM, CPU and RAM (relative to the limit, like docker
  stats), network and block I/O with history from 1 h to 30 days. Rules inherit host → container, with channels, quiet
  hours and maintenance; problem on unhealthy, restart loop, exited with error, OOM or dead. Container page with graphs
  and labels, "keep as check" (existing Docker checks are linked), label `node64.nomonitor=true`, on/off switch, API
  `/api/healthchecks/docker/systems/…`, Prometheus `node64_docker_*`, export/import.
- Notifications: new "iGotify (iPhone)" channel – sends to a Gotify server whose iGotify assistant pushes to the
  iPhone.

## 2.22.0 – 2026-10-22

### Added
- Docker containers have their own menu entry under Healthchecks (like Proxmox VE): all containers on the host with
  image, state/health, creation time and ports together with their checks, key figures, filter and search; monitor
  unwatched ones with one click, checks without a container show as "container missing". Docker checks now appear as
  normal rows in the list, which no longer queries the Docker socket (faster). New: `GET /api/healthchecks/docker/containers`.
- Notifications: new "Home Assistant" channel. It triggers an automation via its webhook (`POST /api/webhook/<ID>`,
  JSON with `state`, `kind`, `title`, `message`, `check`, `node`, `url` and `time`). The webhook ID is stored encrypted
  and never appears in error messages. Certificate verification can be turned off for self-signed certificates in your
  LAN. Only the node sends, so "Only accessible from the local network" in Home Assistant works.

### Fixed
- Channel form: ticked options stay ticked after an input error.
- The "Healthchecks sync" menu item only shows when Healthchecks is switched on.

## 2.21.1 – 2026-10-22

### Changed
- KPI tiles (uptime, Proxmox) in the unified style.

### Fixed
- The overview loads much faster: the status pills only read the latest measurements per check instead of the whole
  measurement table (which got slower as retention grew).

## 2.21.0 – 2026-10-21

### Fixed
- Proxmox VE: "Test connection" never sends the token to an unconfirmed certificate. Confirm the fingerprint first,
  then test again. The stored secret is only used for the configured addresses with the same fingerprint.
- Proxmox VE: no more duplicate notifications with "monitor as check"; an outage already reported is handed over to
  the check. An outage detected while "as check" was on or the rule was off is reported afterwards.
- Proxmox VE: "as check" checks use the channels of the Proxmox rules, also after changes; on a disabled system they
  are created paused.
- Proxmox VE: "Unreachable" waits for the configured delay in time as well. Resumed or restarted VMs no longer show a
  stale "paused/crashed" state. A stopped guest with a stale lock counts as stopped after 4 hours. Right after a
  restart the check no longer reports a short outage.
- Proxmox VE: import properly stops disabled systems; systems with the same name are matched by address, otherwise
  created anew. Concurrent saves no longer start a second poller.
- Proxmox VE: Prometheus metrics get an additional `system_id` label. The system page filter submits on change, rates
  use the language's number format, the system page loads faster.
- Notifications: alerts held during quiet hours are persisted and survive a restart. Secrets in error texts are
  redacted more thoroughly (client_secret, auth_token, JSON pairs, Authorization with any scheme); "basic constraints"
  stays readable.

## 2.20.1 – 2026-10-21

### Fixed
- Dashboard card "Proxmox VE": a system only counts as disturbed with a problem of its own (unreachable, node
  offline, quorum lost). Disturbed guests are only listed under "guests disturbed" and no longer counted twice.

## 2.20.0 – 2026-10-21

### New
- Configuration export/import contains the status pages (settings, groups, entries, logo; matched by slug). The
  password hash of a protected page only with an export password; without it the page arrives switched off.
  Announcements stay on the node.

### Changed
- Data retention: closed incidents are deleted like hourly values and events after "keep hourly values" (unlimited =
  kept); so far they were kept forever.

## 2.19.1 – 2026-10-21

### New
- Proxmox VE: channels selectable per level (system, node, guest) like for checks – default channels or specific
  channels; node and guest visibly inherit the selection (“inherited from the system”, “inherited from the node”). Deleted
  channels are skipped when sending; export/import maps the channels like for checks. API: `rules.channels`.

### Changed
- Proxmox notifications during quiet hours are no longer dropped but held back like check notifications and sent in
  the digest afterwards (with the kind of notification and a link to the Proxmox page).

## 2.19.0 – 2026-10-21

### New
- Prometheus per guest also network and disk I/O (bytes/s), RAM in bytes and CPUs; the system page shows a hint if the token lacks read permissions (most common setup error: token with privilege separation without its own role).
- Proxmox notifications respect quiet hours (crashes too) and maintenance windows (windows for all checks; for specific checks if the guest is kept as a check).
- Proxmox VE: new menu entry “Proxmox VE” under Healthchecks. Monitors Proxmox VE systems (single node or cluster)
  read-only with an API token: nodes, VMs and containers with state (incl. backup, lock, crash via qmpstatus), CPU,
  RAM, disk, network and uptime; filters by state, node, type and search.
- “Add system” wizard: address(es), token, “Test connection” with the SHA-256 fingerprint to pin (self-signed
  certificates), pveum commands for a read-only token (PVEAuditor); edit, switch off, delete.
- Detail page per guest and node with graphs (1 h, 24 h, 7 days, 30 days) and rules with visible inheritance
  (system → node → guest): crash, stopped, paused, suspended, node offline, unreachable, restart, thresholds for
  CPU/RAM/disk with duration, delay, mute.
- Notifications via the existing channels and quiet hours with new kinds (down, recovery, threshold, restart); a
  crash is sent with high priority. Open incidents survive a restart of the node.
- “Keep as check” per guest and node: new check type `proxmox` (local only), so status pages, uptime and the sync
  with ipv64 apply; state notifications then come only from the check.
- Dashboard card “Proxmox VE”, Prometheus metrics (`node64_pve_*`), API under `/api/healthchecks/proxmox`,
  export/import (token secret only with an export password).

## 2.18.3 – 2026-10-20

### Fixed
- Status pages, tiles view: the font grew too much on wide screens (up to 40 px). It now scales only gently and stays
  at 22 px at most.

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
