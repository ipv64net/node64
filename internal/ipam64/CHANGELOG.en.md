# IPAM64 – Changes

## 0.1.0 – unreleased

New (based on the draft by UlrichSchwarz, community):

- IP address management for IPv4 and IPv6: prefixes with status (container, active, reserved, deprecated), VLAN, role, tags, DNS zone and "treat as full"; the hierarchy follows from the prefixes.
- Fixed addresses with status, host name, role (gateway, DNS server, VIP, anycast), MAC, description and tags; ranges for fixed addresses and to keep free.
- Merged from DHCP networks, reservations and leases of DNS64, local A/AAAA records, Monitor64, Healthchecks, PROXY64 and the neighbour table (ARP and NDP); conflict when two MAC addresses use one IP.
- Overview with prefix tree and utilisation, prefix page with grid (IPv4 up to /22), list with free blocks, and ranges; "next free address".
- Network scan only in private IPv4 networks up to /22 that the node is attached to, in the background; can be turned off per prefix.
- Cluster: prefixes, ranges and fixed addresses are synced; node export/import.
- API `/api/ipam64/…` (prefixes, ranges, addresses, free addresses including atomic assignment, scan), CSV export, dashboard card, audit area "IPAM64".
