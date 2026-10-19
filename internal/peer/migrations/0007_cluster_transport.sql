-- Cluster: Aussetzen von Mitgliedern (suspend.go) und der eigene Account zum Zeitpunkt der Kopplung (aendert er
-- sich, werden die Mitglieder ausgesetzt). Der Cluster spricht nur noch HTTPS: bisherige http-Adressen werden https
-- (gleicher Port, der Web-Port spricht beides).
ALTER TABLE peer_members ADD COLUMN state TEXT NOT NULL DEFAULT '';
ALTER TABLE peer_members ADD COLUMN reason TEXT NOT NULL DEFAULT '';
ALTER TABLE peer_members ADD COLUMN self_account INTEGER NOT NULL DEFAULT 0;
UPDATE peer_members SET self_account = account_id;
UPDATE peer_members SET url = 'https://' || substr(url, 8) WHERE url LIKE 'http://%';
