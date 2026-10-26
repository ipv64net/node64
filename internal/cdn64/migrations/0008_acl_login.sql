-- PROXY64: Zugriffsliste mit Login-Seite statt Browser-Dialog (access_login.go; Basic Auth bleibt fuer Programme moeglich).
ALTER TABLE cdn_access_lists ADD COLUMN login_page INTEGER NOT NULL DEFAULT 0;
