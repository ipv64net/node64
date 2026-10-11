-- Sync mit ipv64 (Phase 3): Server-ID je Kanal; Server-Kanaele (execution 'server') erscheinen
-- nur als Platzhalter ohne Konfiguration und werden vom hub gesendet.
ALTER TABLE nf_channels ADD COLUMN remote_id INTEGER NOT NULL DEFAULT 0;
