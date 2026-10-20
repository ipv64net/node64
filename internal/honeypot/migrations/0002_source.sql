-- Honeypot64 H5: Quelle und Regel je Ereignis. Bestehende Zeilen stammen alle aus dem Honeypot.
-- source: honeypot (Fallen-Dienste), log (Log-Sensor, Dateien), syslog (Syslog-Empfaenger)
-- rule:   Regel-Kennung bei log/syslog, z. B. "sshd/bruteforce@1" (leer beim Honeypot)

ALTER TABLE hp_events ADD COLUMN source TEXT NOT NULL DEFAULT 'honeypot';
ALTER TABLE hp_events ADD COLUMN rule TEXT NOT NULL DEFAULT '';

-- Filter der Ereignisliste nach Quelle (neueste zuerst): der Index enthaelt die rowid (= id), so kommt
-- "WHERE source = ? ORDER BY id DESC" ohne Durchsuchen der ganzen Tabelle aus, auch wenn eine Quelle selten ist.
CREATE INDEX IF NOT EXISTS hp_events_source ON hp_events (source);
