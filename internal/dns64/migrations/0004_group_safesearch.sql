-- SafeSearch und Schutz gegen Umgehen je Geraetegruppe (Phase G3).
ALTER TABLE dns64_groups ADD COLUMN safesearch INTEGER NOT NULL DEFAULT 0;
ALTER TABLE dns64_groups ADD COLUMN youtube TEXT NOT NULL DEFAULT 'strict';
ALTER TABLE dns64_groups ADD COLUMN bypass INTEGER NOT NULL DEFAULT 0;
