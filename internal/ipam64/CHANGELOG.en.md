# IPAM64 – Changes

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
