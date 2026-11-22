# Monitor64 – Changes

## 0.1.26 – unreleased

Fixed:

- Proxmox VE and PBS with “Query SMART values” off: the disk list is read only at startup and on “Discover services” instead of every 30 minutes – that query also woke sleeping hard disks (#215).
- FreeBSD/OPNsense: the “Updates” service calls `pkg audit` findings “installed packages with a known vulnerability” instead of “security updates” – they can exist with “0 available” when the package repository has no fix yet.
- “OK until the value gets worse” now also ends for values close to 100 % and in “GB free” mode.
- “May be switched off”: rejected logins, a changed host key or certificate errors no longer count as switched off and are reported.
- Cluster: an acknowledgement set on another node is no longer lost.
- A confirmed SMART rule stays in place when SMART cannot be read in a round (sleeping disk, read error).
- “Service vanished” can be confirmed as OK.
- After turning off “Query SMART values”, disks with a warning no longer stay “Unknown” for days.
- TrueNAS without SMART: “Test connection” in the dialog works without saving first.
- Agent page: after refreshing, the install command shows the new checksum right away.
- UniFi: a short error of an app during the hourly detection no longer hides its services.
- Stability: a database error while closing a problem no longer aborts the polling round; “Check now” during a running poll no longer starts a second concurrent run.
- **Agent 0.1.12 (Windows):** with “Query SMART values” turned off the agent no longer reads SMART counters; Storage Spaces are still monitored.
- **Agent 0.1.12 (Linux):** at startup the agent no longer reports “no reboot required” while needs-restarting is still running.
- **install.sh:** an install command with an older checksum keeps working after a new agent release if the SHA256SUMS signature is valid.

## 0.1.25 – 2026-11-19

New:

- Prometheus: `node64_monitor_problems_open` and `node64_monitor_problems_unacked` – open problems held by this node and how many of them are not acknowledged (in a cluster each problem counts only on the responsible node).
- AI interface (MCP): `monitor64_host` shows per service the rules reporting right now and those confirmed as fine, `monitor64_problems` whether a problem still persists and whether it is in a maintenance window.
- Host page: multiple selection of services – "Select" shows checkboxes, a filter by name and "All", "Filtered" and "None"; the selected services can be set to "do not report" (display only), "report again" or ignored together. Under "Ignored" several services can be adopted again at once. API: `POST /api/monitor64/hosts/{uid}/services/report` (#182).
- Edit host: the "Tags" field suggests tags already in use (#193).
- Edit host: switch "May be switched off" for devices that only run now and then (e.g. a PC in the basement). If the host is unreachable it is shown as "switched off" – no notification, no problem, and it counts neither in the overview nor for the dot in the navigation. While it runs, its services and warnings apply as usual (#229). API: `offline_ok` on the host, `view: offline`.

Fixed:

- "Never report" and "Fine" in the service dialog: after saving, the service stayed in the list with its warning until the next poll (up to one interval), so the button was often pressed several times. Saving now waits briefly for the new poll (at most 8 s), the button shows a spinner meanwhile, and the page shows the new state right away. If a poll was running while saving, the trigger used to be lost; now another poll follows right after it (#225).

## 0.1.24 – 2026-11-18

New:

- Proxmox VE, PBS, TrueNAS and agent accesses: switch "Query SMART values" (edit access). When off, Monitor64 no longer queries SMART and sleeping hard disks stay in standby – Proxmox VE used to wake them for SMART about every 30 minutes (disk list with `skipsmart`, no `disks/smart`). The disks remain as services, without health, temperature, wear and sector errors. The SSH access keeps its "Read SMART" switch (#215).
- Host page: the accesses in the header (e.g. "Proxmox VE") open "Edit access" on click; in the "Accesses" card the button is labelled "Edit" instead of showing only a pencil.
- Navigation: next to "Monitor64" a small pulsing dot shows the overall state – green all fine, yellow-orange warning (or unknown), red critical or a host unreachable. Paused hosts, hosts in a maintenance window and display-only services do not count; when collapsed, the dot sits at the icon.
- "Value is fine": when a value reports (e.g. SSD wear 100 % on an NVMe that keeps running), it can be confirmed as fine in the service info dialog or in the settings – "until the value gets worse" (up to the current value the service counts as OK; if the value gets worse or drops back below the warning threshold, the threshold applies again) or "never report" (warning and critical off on this service). So far this only worked for state rules such as "port without link"; for values that cannot exceed 100 % no suitable threshold could be set. API: `accept` when changing a service now also takes rule kinds with numeric values.

Fixed:

- Notifications: reminders of an open problem went to the channels of the first message, not to the current setting – anyone who switched critical from SMS to the app kept getting the daily reminder by SMS. Reminders (including "unreachable") now go to the configured channels; the all-clear still goes to everyone who knows the problem.
- Problems: "Mark as resolved" seemed to do nothing for a value that is still not fine – the problem was closed, but the poll started right away opened it again (new start time, acknowledgement gone, reminders back on). The button now only appears where it has an effect: traps, paused hosts, hosts without a current state and services of an unreachable host; otherwise a hint says the problem is resolved automatically. The API rejects resolving in this case with 409 `still_failing` instead of silently "succeeding".

Changed:

- Overview: the "Problems" and "Recent" cards are gone – the hosts (tiles or list) now come right below the counters. A new counter card "Problems" (open, of which not acknowledged) leads to the Problems tab.
- Overview, tiles: below the sparkline it now says what it shows – "CPU · 24 h" with the maximum.
- Host page: clicking a service opens a centred dialog with a large history chart (range 6 h to 1 year, selectable metric when there are several), all values as a table (value, state, thresholds) and the service details (state since, access, polling, alerting, acknowledgement, key); disks with SMART show the SMART values, the "Traps" service the recent traps below. Acknowledging works right in the dialog.
- Settings and thresholds: the "Group / tags" row only appears when an override applies to the service; the dialog is wider, several thresholds sit side by side.
- Host page: settings and thresholds open from the gear at the end of each service row (or the button in the info dialog) – also as a centred dialog instead of a side panel.

## 0.1.23 – 2026-11-17

Fixes:

- SNMP profiles (e.g. QNAP): disks and volumes still went "Unknown" for a few minutes now and then, each time with an alert and an all-clear. The NAS sometimes answers its disk table without an error but empty or missing single rows – this counted as a complete answer so far, the hold of the last state from 0.1.14 only applied to tables that did not answer at all. Now every service missing in a round comes with its last state for up to 10 minutes (state kept, hint "state from … min ago"); a row without the name column no longer creates a service under the index number (#204).
- Linux agent installation: on Raspberry Pi OS 32-bit with a 64-bit kernel (e.g. Raspberry Pi 3B+) the agent did not start ("status=31/SYS"). The installer picks the arm64 file there, whose system calls the filter `SystemCallArchitectures=native` killed right away – "native" is the architecture of systemd (32-bit), not of the kernel. The unit now also allows the architecture of the agent file; existing installations get this by running the install command again (forum 5205).
- **Agent 0.1.11 (Linux):** systemd unit allows the architecture of the agent file (Raspberry Pi OS 32-bit with 64-bit kernel).

## 0.1.22 – 2026-11-16

New:

- UniFi: the "UniFi" access now also queries UniFi Drive – e.g. a UNAS Pro with the same API key. Monitor64 detects which apps run on the console (Network, Drive or both). There is one service per pool (RAID level, state, redundancy, usage with threshold, running scrub or rebuild) and one per disk (state, temperature, bad and uncorrectable sectors including "rising", power-on hours, wear on SSDs, risk notes, pool membership). In addition there are services for CPU, RAM, CPU temperature, network ports and the system with UniFi OS and Drive version, uptime and throughput. Before, the access failed on a UNAS because it only knew the Network Application.
- UniFi: the hint for a refused API key now also names the UniFi OS settings (Control Plane → Integrations).
- Windows: "Reboot required" was permanently "yes" on many PCs with the reason "PendingFileRenameOperations". It mostly lists files Windows deletes on the next start (leftovers of installers and updates) – that needs no reboot. From agent 0.1.10 only files replaced on restart count; the reason is readable ("2 file(s) to be replaced on restart, e.g. C:\…\app.dll", "Windows components (CBS)"). Reports of older agents are translated into readable text.
- **Agent 0.1.10 (Windows):** "Reboot required" only for file replacements, not deletions; readable reasons.
- Intended state: when a state rule reports (e.g. "Port without link" on a port currently not in use, "Guest not running", "Reboot required"), the service dialog lets you confirm that the state is fine – "until the state changes" (once the port gets a link again, the rule applies again and a later failure reports) or "never report". Accepted states are shown in the service list and can be undone. API: `accept` when changing a service.

## 0.1.21 – 2026-11-16

Bug fixes:

- RHEL, Oracle Linux, AlmaLinux, Rocky, Fedora (dnf): "Reboot required" was permanently "yes" and the updates reported "Read-only file system: '/var/log/dnf.log'". The agent service may not write to `/var/log`, so dnf aborted – and Monitor64 took the exit code 1 of `needs-restarting -r` as "reboot required". The agent now lets dnf log to its own folder (`/var/lib/monitor64-agent/dnf`, works without reinstalling), new installations additionally allow the existing dnf log files. If `needs-restarting` aborts with an error message, the service counts as unknown (with an error at the access) instead of "yes" – with the agent and via SSH (#169).
- **Agent 0.1.9 (Linux):** dnf logs in its own folder; `needs-restarting` with an error message is no "reboot required".

## 0.1.20 – 2026-11-15

Security:

- **Agent 0.1.8:** a node key restricted to addresses (`from=` in the `keys` file) keeps its restriction on a key change; new lines without `from=` get the restriction of the requesting key, lines with a different restriction are refused. Before, a manually set `from=` was silently lost on a key change. If you use `from=` together with cluster keys, add the addresses of the other nodes to `from=`.
- **Agent installation:** the command in the assistant names the checksum of the `SHA256SUMS` file from the node's signed index (`--sums-sha256` or `-SumsSha256`); the script only starts the program if both match. Without it, `install.sh` checks the new signature `SHA256SUMS.sig` with OpenSSL 3.0 or newer (invalid = abort). Before, program and checksums came from the same source without a signature – whoever replaced both got through (from agent release 0.1.8).
- **Agent 0.1.8:** connections without sign-in from unknown addresses only get 3 seconds for the handshake (instead of 10), addresses from `from=` patterns in the `keys` file get a pot of their own – many silent connections from foreign networks no longer block the first sign-in of a node.

## 0.1.19 – 2026-11-15

Security (code review):

- Access: switching the type to SNMP requires entering the secret again – before, the old one (e.g. a Proxmox token) stayed and was sent to the device as an SNMP community in plain text.
- Host: with a new address, Monitor64 asks before stored secrets of accesses without an address of their own and without a bound target (fingerprint, host key) would go to the new address; once confirmed, these secrets are removed and must be entered again.
- SNMP traps (v3): protection against replayed traps applies again per engine ID and user without expiry – captured traps were accepted again after an hour or via the address of another host.

Bug fixes:

- "Confirm/accept fingerprint" after the test always failed with "enter the secret again". Setting a fingerprint for the first time works without the secret; for a changed fingerprint the dialog asks for the secret right away.
- Cluster: the SMART dialog also works on a node that does not monitor the host itself (before: 404). Removing an acknowledgement here is no longer reverted by an older state from another node.
- If a value with a warning is missing for three intervals while the service runs, it becomes "unknown" instead of green (no all-clear without recovery); only a stopped guest or container leaves values out on purpose.
- UniFi: an error answer (e.g. 502 from a proxy) at the first detection no longer fixes the type (UniFi OS or Network Server) permanently wrong; a sign-in at the wrong path detects again.
- SNMP: if the probe value is missing at the first profile selection (e.g. after a restart), the next round asks again instead of 60 minutes without profile; if the scalars of a profile fail, disks and volumes come from the last state.
- mailcow: no containers (mailcow cannot reach its Docker API) counts as an error instead of "0 containers"; the domain of deferred mails is right even with a reason in the list; mail storage sizes in powers of ten like mailcow (`df -H`).
- FRITZ!Box: after a FRITZ!OS update the service shows the new version (description re-read hourly, the running version takes precedence).
- Updates after `pkg upgrade` (FreeBSD/OPNsense, agent 0.1.7) and via SSH after `apt upgrade` & co. current after about a minute instead of up to an hour later (like the Linux agent, #159).
- Host address: host names are checked according to RFC 1123 (e.g. "nas..lan", "-nas" or "host.123" are rejected).
- **Agent 0.1.7 (FreeBSD):** re-read updates after the package database changed.

## 0.1.18 – 2026-11-15

Bug fixes:

- Proxmox VE in a cluster: a VM or container that migrates to another node (manually or via HA) no longer counts as vanished. If the new node is set up as a host in Monitor64, the service moves there – with name, target state, reporting, thresholds and history, instead of waiting there as "new"; "Recent" shows "migrated from node A to node B". If the node is not set up (e.g. only one access to the cluster), the previous host keeps monitoring the guest with the values from the cluster ("runs on node B"). The same node name in another cluster does not count (#165).
- Proxmox VE: for HA resources the target state comes from the HA configuration (`started` = should be running, `stopped`/`disabled` = may be off) instead of "start at boot"; while HA moves a guest (`migrate`, `relocate`), "Guest or container not running" stays quiet (#165).

## 0.1.17 – 2026-11-14

Bug fixes:

- Linux agent: after a package update (e.g. `apt upgrade`, `dnf upgrade`, `pacman -Syu`) or refreshed package lists, the agent re-reads the updates within about a minute instead of reporting the old state for up to an hour. It detects this from the package database (dpkg, rpm, pacman, apk, opkg). Without changes it still checks once an hour (#159).
- Linux agent: "Reboot required" detects a running kernel without a module directory (Arch) or a newer installed kernel again. The service hardening `ProtectKernelModules=yes` hid `/lib/modules` from the agent. New installations only block loading kernel modules (`CapabilityBoundingSet=~CAP_SYS_MODULE`, `SystemCallFilter=~@module`); from agent 0.1.6 existing installations are read correctly without reinstalling (#158).
- Arch Linux: without `checkupdates` (package pacman-contrib), `pacman -Qu` only compares against the local package list and mostly reports "0 available". The "Updates" service now points this out (agent and SSH, #158).
- **Agent 0.1.6 (Linux):** re-read updates after package changes; "Reboot required" despite the old service hardening; hint about pacman-contrib.

## 0.1.16 – 2026-11-14

Changes:

- User management: only administrators see the push token of accesses (host page, `GET /api/monitor64/hosts/{uid}`); "Read only" sees the accesses without token.

## 0.1.15 – 2026-11-14

Bug fixes:

- Redfish: HPE iLO 4 can also be queried via a DNS name. iLO 4 always puts its IP into the redirect to the path with a trailing slash; if a redirect only adds the slash, Monitor64 now requests the path with the slash from the configured address. Still no request goes to another host (#141).
- FRITZ!Box: the access no longer checks the FRITZ!Box certificate and no longer remembers a fingerprint. The FRITZ!Box creates a new self-signed certificate with every FRITZ!OS update; the remembered fingerprint no longer matched and the access failed. Wizard and access dialog no longer ask for a fingerprint, a previously stored one is ignored. Thanks to digest authentication the password still never crosses the wire (forum 5134).
- Prometheus (macOS): macOS helper volumes (/System/Volumes/VM, Preboot, Update, xarts, iSCPreboot, Hardware, Recovery …), simulator volumes, Time Machine snapshots and backups and temporary mounts under /private/var/folders are still offered but no longer preselected – all volumes of an APFS container report the same usage and warned several times. The data volume, / and external drives under /Volumes stay preselected. Services already adopted stay until removed (#114).
- Host address: an address made only of digits and dots must be a valid IPv4 address. A typo like "10.0.0.2.16" used to count as a host name and only showed up with SSH access, because API accesses (e.g. PBS) use their own URL (forum 5175).
- Interface: long mount paths wrap in the service table and in service discovery instead of running into the neighbouring column or over the edge (#114).

## 0.1.14 – 2026-11-14

Bug fixes:

- Redfish: HPE iLO 4 (and other BMCs that only accept paths with a trailing slash) can be queried – redirects to the same BMC are followed, afterwards Monitor64 appends the slash itself. An address with a path (e.g. `https://10.1.15.17/redfish/v1/Systems/`) is accepted; redirects to another host are never followed (#141).
- File systems: several mounts with the source `none` (e.g. virtiofs without a name of its own) no longer collapse into one – before, one was missing and counted as vanished after three rounds. Via SSH right away, with the agent from 0.1.5 (#140).
- SNMP (QNAP and others): if a table of a device profile does not answer in time, Monitor64 asks again in the same round with smaller replies; if it stays away, the last state applies for up to 10 minutes (without measurements, with the note "as of … min ago") instead of setting all disks and volumes to "unknown" after three intervals. If the profile's identifier is missing once at the hourly re-selection, the profile stays selected (#136).
- FRITZ!Box, MikroTik, UniFi: an available firmware update now warns right away (new rule "Firmware update available"). Before, it went through "Security updates pending", which only warns after 24 hours – the service stayed green (forum 5134).
- Services table: while a state rule is still waiting (e.g. "Security updates pending" after 24 h), the service shows from when it will warn.

New:

- Overview and problems page: problems of hosts in a maintenance window are listed at the end in a collapsed section "In maintenance"; the counter only counts the others. Real problems no longer get lost when e.g. a backup server is switched off during the day as planned (#142).
- Linux: "Reboot required" also when a newer kernel of the same flavor than the running one is installed (Debian, Ubuntu, Proxmox, RHEL, Fedora, Raspberry Pi OS); the service names both versions. Via SSH right away, with the agent from 0.1.5 (#130).
- Prometheus access: smartctl_exporter is recognised – one service per disk with SMART status, temperature, wear and sectors like with the agent, plus all values in the SMART dialog (#135).
- Prometheus access: node_exporter on macOS delivers RAM and swap as regular services with history and thresholds (usage as in Activity Monitor) (#114).
- **Agent 0.1.5 (Linux):** mounts with source `none` separately; kernel comparison for "Reboot required".

## 0.1.13 – 2026-11-13

- New access **UniFi** (its own tile in the wizard) via the API of the UniFi Network Application – for UniFi OS consoles (UDM, UDR, UCG, Cloud Key, UniFi OS Server) and the self-hosted Network Server; SNMP delivers only little on UniFi.
- One service per device (access point, switch, gateway) with state (offline and faulty devices raise a problem), CPU, RAM, temperature, clients, uptime and firmware; per port of switches and gateways state, throughput, utilisation, error rate and PoE power; per PoE switch the used PoE budget.
- Internet connection of the gateway (status, latency, throughput, last speed test), number of clients (Wi-Fi, LAN, guests), open alarms (as far as the version still offers them), update of the Network Application and firmware updates of the devices.
- Login preferably with a local API key (UniFi Network → Integrations; UniFi OS only), otherwise with a local read-only admin ("View Only", without two-factor login). Monitor64 only reads. Fingerprint pin as with the other HTTPS accesses, the secret is stored encrypted. After a rejected login Monitor64 waits (5, 15, 60 minutes) instead of driving the console into its login lockout.
- Further sites via the field "Site" (empty = default).
- Access dialog on the host page: the field "User" now appears for all accesses with a user (it was missing for Proxmox Mail Gateway and FRITZ!Box).
- For gateways with several WAN lines the service "Internet connection" warns when one line fails, even if the connection as a whole is up.
- Tested against a UniFi OS console (UDM SE, Network 11.0.99, API key) with switch and access points and against a self-hosted Network Server 10.0.162 (read-only admin).

## 0.1.12 – 2026-11-13

- New access **MikroTik** (its own tile in the wizard) via the REST API of RouterOS version 7 and later: CPU, RAM, flash, uptime and version; temperatures, fans, power supplies, voltage and power (as far as the device has sensors); interfaces with state, throughput and error rate; number of connected Wi-Fi clients; BGP connections (a configured connection without an established session warns) and OSPF neighbors; RouterOS update available and RouterBOOT.
- Read-only: Monitor64 sends GET requests only. The user belongs in a group with `read,api,rest-api`; the wizard shows the commands for user and certificate (the `www-ssl` service accepts no connection without a certificate). Fingerprint pin as with the other HTTPS accesses, the password is stored encrypted.
- Whether an update is available is only shown after the router has checked for itself (scheduler or manually) – Monitor64 does not trigger the check.
- RouterOS 6 has no REST API; SNMP with the MikroTik profile remains the way there.
- Tested against RouterOS 7.25.1 (CHR).

## 0.1.11 – 2026-11-13

- Services table: disks have a "SMART" button. It shows all SMART values read last as a dialog – for SATA disks the whole attribute table (ID, name, value, worst, threshold, raw value; attributes below their threshold are marked), for NVMe and SAS the individual values, plus model, serial number, firmware, overall health and the time of the reading.
- Complete via the agent from 0.1.4 (Linux, FreeBSD), via SSH and via Proxmox VE or Proxmox Backup Server. Windows and older agents show the evaluated values (temperature, power-on hours, sectors …).
- The values are kept in the node's memory only (the last set per disk, no history, nothing in the database); after a restart they are back with the next SMART query. In a cluster the responsible node answers.
- API: `GET /api/monitor64/hosts/{uid}/smart?key=<service>`; services with SMART values carry `detail: "smart"`.
- **Agent 0.1.4:** delivers all SMART attributes or NVMe/SAS values per disk, the firmware and the time of the reading.

## 0.1.10 – 2026-11-13

Bug fixes from the reports on GitHub:

- Thresholds: "Save override" and the preview work again – nothing happened before ("cur is not a function" in the browser console) (#107).
- Threshold "GB free": the warning stayed although more was free again than the threshold ("only 1.2 GB free (threshold 1 GB)"). The inherited hysteresis of 2 (meant as percentage points) counted as 2 GB there; when inherited it now counts as at most a tenth of the threshold. A hysteresis set on the service together with "GB free" still applies unchanged in GB (#109).
- SNMP: devices without a sensor or LAG table (e.g. HP LaserJet) that answer the query with an empty response no longer report "partial query failed: ENTITY-SENSOR: empty response" (#98).
- Disks: two disks on identical USB adapters often report the same serial number (the adapter's) and collapsed into one service – the second was missing. In that case the serial number from SMART or the device name is used now; the disk shown so far therefore appears once as a new service (#84).
- Services table: the category is called "Guests and backups" instead of "Proxmox" – it also applies to VMs on Unraid and TrueNAS (#87).
- Changed certificate (e.g. FRITZ!Box after a new name): the access now explains what to do, and "Test connection" offers "Accept new fingerprint"; afterwards enter the secret again and save (#121).
- Status pages: the tags of Monitor64 hosts are available in the editor's tag filter (#102).
- Wizard Proxmox VE/PBS: the token hint explains privilege separation – a token with privilege separation needs the role itself, the intersection of user and token applies.
- Wizard "Linux via SSH": with the node in the Docker bridge network, the `authorized_keys` line carried the container's address (`from="172.…"`) – but the host sees the Docker host's address and refused the login. The line now shows a placeholder for the Docker host's address plus a hint; if the target is inside the bridge network itself (Docker host via the gateway), the address stays.
- "Test connection" (SSH and agent) shows the address that was actually connected to and the host key type – this reveals a name resolving differently inside the container or a connection ending up at another server via IPv6. If the server offers no public key login at all, the message says so instead of "attempted methods [none]".
- Host page: "Edit" (name, address, group, tags) is a button of its own next to "Detect" instead of an entry in the ⋯ menu (#126).
- Proxmox Backup Server: the maximum backup age can be set on the access (hours, empty = 26) – weekly backups no longer cause a permanent "backup too old" warning.
- **Agent 0.1.3 (Linux):** file systems are no longer all shown as "read-only" – the agent now reads this from the host's point of view instead of its own hardened environment (#97).
- **Agent 0.1.3:** starts on UGREEN NAS (UGOS): a `GODEBUG` set there for all services is no longer inherited. The installation checks after the start whether the service is running and shows the last log lines otherwise. UGOS locking upgrades via `apt` is a note instead of a failed partial query – also via SSH (#96).
- **Agent 0.1.3:** under SELinux (Fedora, RHEL, Rocky …) the installation labels the program folder `bin_t` so that the automatic update no longer fails with "permission denied" (#100).

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
