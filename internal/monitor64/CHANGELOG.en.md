# Monitor64 – Changes

## 0.1.9 – 2026-11-11

- New access **FRITZ!Box** (own tile in the wizard) via the TR-064 interface: internet connection (connected/disconnected, duration, external address, current throughput, access type and line state), for DSL lines sync rates, noise margin, attenuation and CRC errors, the box's uptime and FRITZ!OS version, and "update available".
- Login with a FRITZ!Box user (the password does not go over the wire). "Allow access for applications" must be enabled in the FRITZ!Box. For all values the user needs the right "FRITZ!Box Settings" – the FRITZ!Box has no read-only role; without the right you get access type, line state and the update status.

## 0.1.8 – 2026-11-11

- **Raspberry Pi, power supply corrected (agent 0.1.2 and SSH):** the values now come from `vcgencmd get_throttled` (under-voltage and throttling, now and since boot) and, where the program is missing or access is not allowed, from the kernel's under-voltage alarm ("now" only). The file `get_throttled` under `/sys` read so far is deprecated in the Pi kernel: reading it wrote a warning to the kernel log once per boot, "since boot" was not correct with it, and from kernel 6.12 (Raspberry Pi OS 13) it no longer exists.
- For "since boot" via SSH the monitoring user must be allowed to run `vcgencmd` (group `video`); the agent runs as root and needs nothing.

## 0.1.7 – 2026-11-11

- **Inodes:** every file system with an inode limit (ext4, XFS …) now has its own threshold "File system: inodes used" (warning from 80 %, critical from 90 %) – not a separate service, the value belongs to the file system and is shown in the text from 50 %. File systems without a fixed limit (Btrfs, FAT) do not have the value.
- **Btrfs:** one service "Btrfs <label>" per mounted file system with profile (single, raid1 …), number of devices and metadata usage; a missing device is reported like a degraded RAID, the devices' error counters (as in `btrfs device stats`) as a warning. Subvolumes of the same file system still appear only once. Comes with agent 0.1.1 and via SSH right away.
- **ZFS:** the pool's fragmentation is shown in the service and in the history.
- **Raspberry Pi:** own tile in the wizard; new service "Power supply": under-voltage now = critical, occurred since boot = warning, throttling = warning (firmware state as in `vcgencmd get_throttled`). Comes with agent 0.1.1 and via SSH right away.
- **Agent 0.1.1:** the 32-bit ARM file now also runs on Raspberry Pi Zero and Pi 1 (ARMv6); the install script recognises `armv6l`.

## 0.1.6 – 2026-11-11

- New access **mailcow** (own tile in the wizard) via the mailcow API with a read-only key: containers (Postfix, Dovecot, Rspamd, SOGo …; any that is not running is reported), usage of the mail storage (vmail), mail queue with the largest target domains (uses the threshold "Mail queue: deferred mails") and quarantine. In mailcow the node's address must be listed under "Allow API access from".

## 0.1.5 – 2026-11-11

- New access **Proxmox Mail Gateway** (own tile in the wizard): CPU, load, RAM, swap and root file system, services (Postfix, SMTP filter, ClamAV, database …), mail queue with the largest target domains, mail flow of the last hour (in, out, spam, viruses, rejected), quarantine, age of the ClamAV signatures, cluster (node unreachable, not in sync) and pending updates.
- Login to the Mail Gateway with user and password (role "Auditor", e.g. `monitor64@pmg`) because it has no API tokens; the ticket is renewed automatically. Users with a second factor are rejected with a hint.
- New threshold "Mail queue: deferred mails" (warning from 100, critical from 500, each for 10 minutes) in the new "E-mail" section of the thresholds; the services are listed in the new "E-mail" category.

## 0.1.4 – 2026-11-11

- If an access hangs (Docker daemon, PVE API or BMC not answering), the round is no longer discarded: the host becomes "unreachable" and is notified as expected instead of staying at its last state (often OK).
- Notifications: an explicitly chosen channel that is also a default channel now gets messages even when "default channels" is not chosen for that level (so far they were lost while the history still said "notified").
- Unreachable hosts are reminded like critical services (default: daily) as long as the problem is not acknowledged.
- After a node restart, push hosts no longer report "unknown" while their agent has not reconnected yet.
- Pausing shows the host as paused right away, also in the overview, dashboard and metrics; its old problems no longer appear there.
- A value that deliberately stops (e.g. CPU of a stopped VM) no longer stays "unknown" for 7 days when it last had a warning.
- "Check all again" after saving no longer puts hosts into lockstep for good (load peaks).
- "Discover services" no longer counts a cancelled page or a slow access as an outage.
- Prometheus: the `service` label carries the name (English) instead of an internal text key; so do the lines in the webhook without custom body.
- Cluster: an acknowledgement another node is just overwriting is no longer lost; with more than 500 entries the newest reach the other nodes; changes during a long backup are no longer missed; after a change of responsibility a node no longer takes the host back every 30 seconds (connection broken between just two nodes); a key change is no longer reverted by another node's clock running ahead; cancelled UI requests and read errors no longer disturb the cluster. Single nodes without a cluster no longer query the database every 2 s.
- History: a range far back (year) no longer shows wrong times.
- Security: changing an access's address, type or fingerprint requires entering the secret again – the stored one no longer goes silently to the new target. Push tokens are no longer in clear text in exports (encrypted with a password, left out without). A push agent can no longer lose its first host key to a foreign token holder after the host was reloaded. Agent reports are limited (at most 5000 services, 2000 local checks) so a manipulated host cannot fill the database. Failed attempts on the push port also count per IPv6 /48.
- SNMP: the time window of v3 traps applies per sender (one host no longer blocks another host's traps; starts over after an hour of silence); the trap flood protection no longer empties completely. The learned GETBULK limit (RouterOS) only lasts an hour – a single packet loss no longer throttles forever. GET responses that are too big are requested in smaller parts. Counters that were reset rather than wrapped no longer cause a spike. "Slower than usual" learns again after a link loss and does not apply to Wi-Fi. Large tables are sorted faster.
- Proxmox VE and PBS with a link-local address including zone (`fe80::1%eth0`) now really work.
- A port in the host address (SSH, e.g. `nas:2222`) no longer applies to API accesses without own URL or to SNMP – as in the UI suggestion.
- Docker/Podman: Podman CPU load on hosts with 2 cores no longer jumps between the right and a doubled value.
- Agent (with the next agent version): failed attempts before login also count per IPv6 /48.
- UI: in the wizard, input (user, password) is no longer lost when the answer for the node address or push token arrives late. Overrides for groups or tags with "|" in their name are saved correctly. On the problems page, a quickly changed problem no longer shows another problem's history (and buttons). Dialogs no longer stack old click handlers. A broken link `#svc=%` no longer stops the host page from refreshing.
- Faster: script and stylesheet are served with an ETag (unchanged = 304 instead of 230 KB each time); the dashboard card counts without database queries; new indexes for "Recent" and closed problems; the node ID is no longer read every round.

- IPv6 throughout: a host's address now also accepts IPv6 with a port (`[2001:db8::1]:2222`); this form used to be mangled on save. Invalid addresses are rejected right away.
- IPv6 without square brackets now also works in the address of a Prometheus exporter (`fd00::1`) and for Docker via `tcp://` or `ssh://`; with `ssh://user@fd00::1` the last block used to be read as the port silently.
- Link-local addresses with a zone (`fe80::1%eth0`) now also work for the HTTPS accesses (Proxmox VE, Proxmox Backup Server, TrueNAS, Unraid, server BMC) and Prometheus.
- Wizard and access dialog: the suggested URL puts an IPv6 address in brackets and drops a port from the host's address; the other nodes of a Proxmox cluster thus get the right URL even if the address carries a port.

## 0.1.3 – 2026-11-11

- Dashboard: own card with hosts, services, unreachable hosts, critical services and warnings, maintenance and the last incident. Problems appear under "Recent incidents" in the same list as the health checks (with a "Monitor64" badge).
- Tablet and smartphone: the services table on the host page fits the screen – extra texts wrap, service names no longer break letter by letter; the overview list view fits narrow screens, "4 hosts · 93 services" is no longer cut off.

## 0.1.2 – 2026-11-11

- Own logo (light and dark) in the overview and in the module list.
- New services on a host: "all" and "none" buttons above the selection.
- The Docker access also works with Podman (Docker-compatible API via `podman.socket`, locally or via `ssh://…/run/podman/podman.sock`). Container CPU load is correct there: Podman reports system time differently from Docker, so far a container using one core showed up to 100 %.
- SNMP traps switched off: the remembered trap state disappears right away, even if a round was running (so far until the next round).
- Proxmox Backup Server: the commands in the wizard now also grant `Audit` to the user – a PBS token can only do what its user may do.
- SNMP with MikroTik/RouterOS (e.g. CRS305): ports now show up. RouterOS silently drops oversized bulk requests instead of rejecting them; Monitor64 then asks in smaller pieces and remembers the limit. Missing values without saying which one (RouterOS) no longer mark the round as "partial".

## 0.1.1 – 2026-11-10

- Overview, "List" view: hosts stay together by group (group row with count, as with the tiles). Clicking a column
  sorts within each group, and the chosen order survives the automatic refresh.

## 0.1.0 – 2026-11-10

- New module: monitor systems with thresholds and history.
- Access: Monitor64 agent (Linux), agentless SSH, Proxmox VE, Proxmox Backup Server and Docker via API.
- Services are discovered but never adopted automatically; vanished services stay until "Remove".
- Thresholds on three levels (default, overrides per group/tag – top wins –, this host), duration, hysteresis,
  "GB free", trend "full in N days", fixed rules (SMART, RAID/ZFS, bonding/LACP, updates, guests/containers).
- Problems with timeline and actor (user, API key, system), acknowledge, mark as resolved, CSV.
- Notifications via the node's channels: one message per host and round, recovery to the same channels,
  reminders, flapping, quiet hours with digest, overrides per group/tag.
- Maintenance for hosts, groups and tags (now, scheduled, recurring).
- History in its own file `monitor64.db` (1 min / 5 min / 1 h), charts with zoom.
- Prometheus export at `/api/metrics`, config export/import (secrets only with export password).
- Phase 2/3: agent for Windows (service, PowerShell one-liner) and FreeBSD/OPNsense, query Prometheus exporters
  (node_exporter, windows_exporter, custom metrics), entries on status pages, rule "Windows service stopped".
- New accesses: NUT (UPS), TrueNAS, Unraid, Redfish (server BMC); wizard tiles for Windows, FreeBSD, TrueNAS,
  Unraid, server BMC, UPS and Prometheus; new rules for UPS, device alerts and Unraid parity.
- SNMP access (v1/v2c/v3, device profiles, custom OIDs) with wizard tiles "SNMP device" and "NAS"; SNMP traps
  (configurable port, immediate poll on known traps, "Traps" service until acknowledged, add unknown senders as host);
  new rules for restarts, ports, UPS alarm, printers, hardware and PoE.
- Agent push mode for hosts behind NAT or VPS (agent connects to the node, port 6466/TCP, only open when needed);
  "Connection" choice in the wizard with install command.
- Cluster UI: "monitored by", preferred and backup nodes per host with reachability check, cluster card with key
  rotation, gap note in charts.
- Code review fixes phase 2–4: more robust push mode (test no longer breaks the registration, no takeover by token
  holders, safe port change), cluster (suspended nodes, key rotation without lockout, local channels kept, age limits),
  traps (rate limit per sender, v3 time window, traps in the cluster), Windows install (existing folder, script folder,
  job object), UPS runtime only on battery, status pages (unknown, pauses, recurring maintenance), non-suggested services
  can be adopted.
- Code review fixes: intentionally missing values (stopped VM, sleeping disk) stay OK, reminders are not lost after
  quiet hours, no duplicate messages to default channels, ZFS device errors on ONLINE pools, Proxmox cluster services
  evaluated by a monitored node, hung VMs even when allowed to be off, thousands separator and hysteresis in the shown unit.
- Phase 4 (backend): Monitor64 in the cluster (areas "configuration" and "status"): one responsible node per host with
  preferred and backup nodes, takeover after 2 min and handback after 5 min stable, majority rule for separated parts,
  shared cluster key (agents are switched automatically, "change key"), overall view "monitored by", history live from
  the monitoring node, traps forwarded to the responsible node.
- Menu item "Agent": the node keeps the signed agent files ready (download also for hosts without internet), shows
  install commands and agent versions and updates agents automatically (can be switched off per host, "update now").
- Agent installable on FreeBSD, OPNsense, pfSense and TrueNAS CORE via `install.sh` (rc.d service, push mode).
- Service names, state and error texts in German and English (also in notifications, CSV and on status pages).
- Cluster: sparklines also for hosts of other nodes; card "hosts without a monitoring node" (assign/remove); open
  traps stay open on a takeover; changes are not lost after a write error in the cluster log. Status pages: times
  in which Monitor64 was not running count neither as an incident nor as observed.
- Security: with SSH password login the password is only sent to the host after the fingerprint of its host key
  was confirmed (connection test and after "discard host key"). From the security review: this now also holds in the
  "add host" wizard (a fingerprint that was only shown but not confirmed is no longer stored) and when an access gets
  a password for the first time; SNMP v3 traps must have at least the user's security level; texts from devices can
  no longer disturb the display via foreign text keys.
- From the click-through: memory of Proxmox VMs has its own rule without a default threshold (the value includes
  the guest's cache); if the Proxmox token lacks the permission for updates, the service says so instead of a
  partial error; new hosts and accesses are polled right away, newly appearing services are offered right away;
  pseudo filesystems (SNMP) and file mounts (node_exporter in a container) are left out; host tiles are real links;
  texts without plural errors.
- Windows agent: services with start type automatic that were never started since boot do not count as stopped.
  The installation no longer fails on an empty folder `%ProgramData%\monitor64-agent` owned by someone else; a
  foreground start with invalid options no longer creates this folder.
- Windows agent: icon in the notification area of the taskbar for every signed-in user – shows that the service is
  running, the version, the last poll by the node and whether an update is available (can be switched off with
  `-NoTray` or `install --no-tray`).
