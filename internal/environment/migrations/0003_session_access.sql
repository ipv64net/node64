-- Environment: Zugang (env_access.id), ueber den eine Sitzung entstanden ist (0 = Cluster-Mitglied); der Widerruf des
-- Zugangs beendet diese Sitzungen.
ALTER TABLE env_sessions ADD COLUMN access_id INTEGER NOT NULL DEFAULT 0;
