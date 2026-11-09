-- DHCP: Netz hinter einem DHCP-Relay (Anfragen nur mit giaddr, keine eigene Adresse der Node in diesem Netz noetig).
ALTER TABLE dns64_dhcp_scopes ADD COLUMN relay INTEGER NOT NULL DEFAULT 0;
