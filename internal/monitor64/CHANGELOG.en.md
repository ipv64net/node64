# Monitor64 – Changes

## 0.1.0 – unreleased (preview, only with switch `NODE64_MONITOR64=1`)

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
- Code review fixes: intentionally missing values (stopped VM, sleeping disk) stay OK, reminders are not lost after
  quiet hours, no duplicate messages to default channels, ZFS device errors on ONLINE pools, Proxmox cluster services
  evaluated by a monitored node, hung VMs even when allowed to be off, thousands separator and hysteresis in the shown unit.
