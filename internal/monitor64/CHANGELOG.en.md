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
- SNMP access (v1/v2c/v3, device profiles, custom OIDs) with wizard tiles "SNMP device" and "NAS"; SNMP traps
  (configurable port, immediate poll on known traps, "Traps" service until acknowledged, add unknown senders as host);
  new rules for restarts, ports, UPS alarm, printers, hardware and PoE.
- Agent push mode for hosts behind NAT or VPS (agent connects to the node, port 6466/TCP, only open when needed);
  "Connection" choice in the wizard with install command.
- Cluster UI: "monitored by", preferred and backup nodes per host with reachability check, cluster card with key
  rotation, gap note in charts.
- Code review fixes: intentionally missing values (stopped VM, sleeping disk) stay OK, reminders are not lost after
  quiet hours, no duplicate messages to default channels, ZFS device errors on ONLINE pools, Proxmox cluster services
  evaluated by a monitored node, hung VMs even when allowed to be off, thousands separator and hysteresis in the shown unit.
- Phase 4 (backend): Monitor64 in the cluster (areas "configuration" and "status"): one responsible node per host with
  preferred and backup nodes, takeover after 2 min and handback after 5 min stable, majority rule for separated parts,
  shared cluster key (agents are switched automatically, "change key"), overall view "monitored by", history live from
  the monitoring node, traps forwarded to the responsible node.
