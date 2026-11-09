-- DHCP im Cluster: Zustand der anderen Nodes (Rolle, Schalter, Server-ID je Netz, DNS-Adressen) fuer die Reserve-Node
-- und die DNS-Server der Geraete; jedes Netz nur einmal (Kennung im Cluster).
CREATE TABLE dns64_dhcp_nodes (
    node_id TEXT PRIMARY KEY,
    data    TEXT NOT NULL -- JSON
);
CREATE UNIQUE INDEX dns64_dhcp_scopes_subnet ON dns64_dhcp_scopes (subnet);
