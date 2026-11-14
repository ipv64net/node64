-- IPAM64 (Plan docs/PLAN-NODE64-IPAM64.md, Stufe I2): Herkunft und Bezug der Eintraege, die IPAM64 besitzt
-- (origin = 'ipam64', ref = uid der Adresse in IPAM64), und Ausnahmen im DHCP-Adressbereich (Adressen, die der
-- DHCP-Server nie vergibt, z. B. fest eingestellte Geraete im Pool).
ALTER TABLE dns64_dhcp_reservations ADD COLUMN origin TEXT NOT NULL DEFAULT '';
ALTER TABLE dns64_dhcp_reservations ADD COLUMN ref TEXT NOT NULL DEFAULT '';
ALTER TABLE dns64_records ADD COLUMN ref TEXT NOT NULL DEFAULT '';

CREATE TABLE dns64_dhcp_excludes (
    id       INTEGER PRIMARY KEY,
    scope_id INTEGER NOT NULL REFERENCES dns64_dhcp_scopes(id) ON DELETE CASCADE,
    ip       TEXT    NOT NULL,
    comment  TEXT    NOT NULL DEFAULT '',
    origin   TEXT    NOT NULL DEFAULT '',
    ref      TEXT    NOT NULL DEFAULT '',
    UNIQUE (scope_id, ip)
);
