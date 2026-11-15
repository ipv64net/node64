# IPAM64 – Changes

## 0.6.1 – unreleased

Fixed (code review):

- Child prefixes inside a DHCP network take over its range and zone: addresses in the pool get their exclusion, "next free address" no longer hands out pool addresses, and reserved ranges of the parent prefix apply in the child too. Ranges of a child prefix no longer keep the parent prefix from finding free addresses.
- DNS64 now checks an address completely before writing; if it still fails, a manual entry taken over on the way is released instead of deleted (also for import and setup assistant).
- "Hand over to DNS64" applies to the whole cluster: the other nodes release their entries as well instead of deleting them. Handed-over addresses no longer get a pool exclusion (no error every 10 minutes); turning DNS or DHCP on again lets IPAM64 manage the address again.
- Sync with DNS64: if another node syncs DNS64 but not the IPAM64 addresses, its entries are no longer deleted (no back and forth). Orphaned entries an address needs (same address assigned on two nodes) are replaced in the same run – without a gap and without errors.
- Same address assigned on two nodes at the same time: the displaced own address shows up as a conflict under "Scan & conflicts" for 24 hours and is notified. "Next free address" is atomic per node only; in a cluster assign on one node.
- IPv6 from the provider: only addresses on the interface the node had in the prefix count as the new address – a global address of WireGuard, Docker or a second uplink no longer causes wrong or missing renumbering (also for prefixes without children). Renumbering is all or nothing; if it fails, the old state stays.
- Conflict "duplicate address" only when the sightings of two MAC addresses overlap for more than 5 minutes – a device swap is no longer a conflict.
- CSV import: a broken line is an error of that line; the rest is still read.
- Targets with names (Healthchecks, PROXY64) always attach to the same address (IPv4 before IPv6).
- Overview: the "automatic scan" selection saves on change again; the automatic scan no longer shows "invalid Prefix". Dashboard card: usage only from IPv4 prefixes, never above 100 %.
- CSV export: all cells protected against formulas in spreadsheet programs.
- Faster: sightings in one transaction per round and only when changed, node addresses once per run, prefixes read once per import instead of per address, sync without quadratic effort.

## 0.6.0 – unreleased

New:

- Prefix page: grid and list on one page (tab "Addresses"), ranges as a separate tab. Clicking a used field marks the row in the list, hovering a row highlights its field; filter and search highlight the matches in the grid, the search filters while typing.
- Large networks (IPv4 larger than /22, IPv6): block overview with at most 256 fields (IPv4 per /24, otherwise 8 bits deeper), coloured by usage; a click shows only that block in the list, own prefixes inside lead to their page. For /22 and /23 the list shows the selected section of the grid.

## 0.5.1 – unreleased

Fixed (practical lab test):

- IPv6 from the provider in a cluster: a node that receives the prefix change via the cluster and still has an address in the old prefix no longer renumbers back. Renumbering only happens if the node itself was inside the previous prefix.
- Cluster nodes show up as known devices (source "Cluster") instead of unknown.
- The DHCP standby node sees the leases (from the cluster sync) even while its DHCP server is not serving.
- Large CSV imports about ten times faster (10,000 addresses with DNS record in just over 30 s instead of 6 minutes): DNS64 rebuilds DHCP and local records only once at the end for import, setup assistant, IPv6 change and reconciliation, and the browser waits for the result instead of timing out.
- IPAM64 cluster sync right from node start.

## 0.5.0 – unreleased

New:

- CSV import with preview: prefixes or addresses (including DNS/DHCP switches), comma or semicolon, existing entries are extended; the own export can be read back in.
- Prometheus at `/api/metrics`: `node64_ipam64_*` – usage, utilisation and conflicts per prefix, free addresses in the DHCP range, conflicts, hints, unknown devices, last scan.
- MCP (read only): new area IPAM64 with `ipam64_overview`, `ipam64_addresses`, `ipam64_conflicts`, `ipam64_available`.
- API: `GET /api/ipam64/conflicts` (conflicts, hints, unknown devices).
- Guide in docs/IPAM64.md, section in the README.

## 0.4.0 – unreleased

New:

- Page "Scan & conflicts": conflicts (duplicate address, foreign device on a fixed address, lease versus fixed address) and hints (statically set device in the DHCP range, fixed address with DNS record not seen for a long time, foreign DHCP server from DNS64), plus unknown devices from the neighbour table to take over or ignore.
- Fewer false alarms: two MAC addresses on one IP are only a conflict when both answer alternately (swapping a device does not count); a foreign MAC on a fixed address only after 5 minutes.
- Notifications via the default channels: new conflicts (on by default) and new devices (off by default, only one hour after start).
- Vendor of a MAC (IEEE vendor list, generated with `go run gen.go` in `internal/ipam64/oui`), random MACs are detected.

## 0.3.0 – unreleased

New:

- "Set up from existing data": suggests prefixes from the DHCP networks of DNS64 and the node's networks and takes over fixed addresses and A/AAAA records that are manual in DNS64 – with matching switches, labelled instead of duplicated. What does not fit stays manual and is listed with the reason.
- Dynamic IPv6 prefixes: a provider prefix can be marked "dynamic". When it changes, IPAM64 moves the prefixes in it (prefix ID stays), the addresses and their AAAA records in DNS64; detected via the node's addresses, checked every 2 minutes or on demand.
- Overview: last IPv6 prefix change and targets in PROXY64, Monitor64 and Healthchecks still pointing to the old prefix.
- API: field `dynamic` on prefixes.

## 0.2.0 – unreleased

New:

- DHCP and DNS from IPAM64: on every address you can switch on a local DNS record (A or AAAA, optional PTR; zone on the address or from the prefix) and a fixed assignment in the DHCP server of DNS64. IPAM64 creates them in DNS64 with a label; an identical manual reservation or record is taken over.
- Fixed addresses inside the DHCP range without a reservation are excluded from assignment by DNS64 automatically.
- If DNS64 refuses (e.g. MAC already assigned, CNAME on the name), everything stays as it was; the message says why.
- Card "Effect in DNS64" on the address: what is created or present, checked against DNS64.
- Reconciliation every 10 minutes: missing or differing entries are repaired, orphaned ones removed (carefully, so nothing flaps in the cluster).
- "Hand over to DNS64": removes the label, the entries stay editable in DNS64 (e.g. before turning IPAM64 off).
- Deleting an address also removes its entries in DNS64.
- Breadcrumbs show prefix or address; the prefix table of the overview fits narrow screens better.
- API: fields `dns`, `dns_zone`, `ptr`, `dhcp` on addresses.

## 0.1.0 – unreleased

New (based on the draft by UlrichSchwarz, community):

- IP address management for IPv4 and IPv6: prefixes with status (container, active, reserved, deprecated), VLAN, role, tags, DNS zone and "treat as full"; the hierarchy follows from the prefixes.
- Fixed addresses with status, host name, role (gateway, DNS server, VIP, anycast), MAC, description and tags; ranges for fixed addresses and to keep free.
- Merged from DHCP networks, reservations and leases of DNS64, local A/AAAA records, Monitor64, Healthchecks, PROXY64 and the neighbour table (ARP and NDP); conflict when two MAC addresses use one IP.
- Overview with prefix tree and utilisation, prefix page with grid (IPv4 up to /22), list with free blocks, and ranges; "next free address".
- Network scan only in private IPv4 networks up to /22 that the node is attached to, in the background; can be turned off per prefix.
- Cluster: prefixes, ranges and fixed addresses are synced; node export/import.
- API `/api/ipam64/…` (prefixes, ranges, addresses, free addresses including atomic assignment, scan), CSV export, dashboard card, audit area "IPAM64".
