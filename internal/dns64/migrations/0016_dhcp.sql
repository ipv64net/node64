-- DHCP-Server von DNS64 (opt-in, Plan docs/PLAN-NODE64-DNS64-DHCP.md): Netze je Schnittstelle, feste Adressen, Leases.
CREATE TABLE dns64_dhcp_scopes (
    id            INTEGER PRIMARY KEY,
    name          TEXT    NOT NULL DEFAULT '',
    iface         TEXT    NOT NULL,             -- Schnittstelle des Hosts (eth0, eth0.20 ...)
    subnet        TEXT    NOT NULL,             -- 192.168.1.0/24
    range_start   TEXT    NOT NULL,
    range_end     TEXT    NOT NULL,
    router        TEXT    NOT NULL DEFAULT '',  -- leer = keiner
    dns           TEXT    NOT NULL DEFAULT '',  -- Adressen durch Komma, leer = diese Node
    domain        TEXT    NOT NULL DEFAULT '',
    lease_hours   INTEGER NOT NULL DEFAULT 24,
    ntp           TEXT    NOT NULL DEFAULT '',  -- Adressen durch Komma
    authoritative INTEGER NOT NULL DEFAULT 1,
    boot_server   TEXT    NOT NULL DEFAULT '',  -- PXE: TFTP-Server
    boot_bios     TEXT    NOT NULL DEFAULT '',
    boot_uefi     TEXT    NOT NULL DEFAULT '',
    boot_ipxe     TEXT    NOT NULL DEFAULT '',
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT    NOT NULL
);
CREATE TABLE dns64_dhcp_reservations (
    id       INTEGER PRIMARY KEY,
    scope_id INTEGER NOT NULL REFERENCES dns64_dhcp_scopes(id) ON DELETE CASCADE,
    mac      TEXT    NOT NULL, -- aa:bb:cc:dd:ee:ff
    ip       TEXT    NOT NULL,
    name     TEXT    NOT NULL DEFAULT '',
    comment  TEXT    NOT NULL DEFAULT '',
    UNIQUE (scope_id, mac),
    UNIQUE (scope_id, ip)
);
CREATE TABLE dns64_dhcp_leases (
    scope_id INTEGER NOT NULL REFERENCES dns64_dhcp_scopes(id) ON DELETE CASCADE,
    mac      TEXT    NOT NULL,
    ip       TEXT    NOT NULL,
    hostname TEXT    NOT NULL DEFAULT '',
    expires  TEXT    NOT NULL,
    state    TEXT    NOT NULL, -- bound | free
    PRIMARY KEY (scope_id, mac)
);
