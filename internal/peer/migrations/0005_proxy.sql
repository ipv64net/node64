-- Stellvertreter-Nodes: je nicht verknuepftem Mitglied der zuletzt an den hub weitergereichte Messpunkt (node_seq dort).
ALTER TABLE peer_members ADD COLUMN pcursor INTEGER NOT NULL DEFAULT 0;
