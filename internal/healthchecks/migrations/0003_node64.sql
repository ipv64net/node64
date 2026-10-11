-- Umbenennung Agent -> Node64: laufende Nummer der Messpunkte heisst node_seq
ALTER TABLE hc_measurements RENAME COLUMN agent_seq TO node_seq;
