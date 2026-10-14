-- Messwerte (Schritt 3): je Mitglied der zuletzt abgeholte Messpunkt (node_seq der anderen Node).
ALTER TABLE peer_members ADD COLUMN mcursor INTEGER NOT NULL DEFAULT 0;
