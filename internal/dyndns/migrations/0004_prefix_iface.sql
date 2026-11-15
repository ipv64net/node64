-- Praefix-Interface der Modi "prefix"/"suffix" (#154) in einer eigenen Spalte: iface gehoert dem Modus "iface" und
-- blieb frueher nach einem Moduswechsel stehen; ueber den Cluster oder alte Exporte kaeme es sonst wieder und wirkte.
ALTER TABLE dyn_targets ADD COLUMN prefix_iface TEXT NOT NULL DEFAULT '';
