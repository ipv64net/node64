-- Zwei-Faktor: zuletzt verbrauchter Zeitschritt des Einmalcodes je Benutzer (RFC 6238, Zaehler = Unixzeit / 30).
-- Die Anmeldung nimmt nur groessere Schritte an, damit ein Code innerhalb seines Fensters nur einmal gilt.
ALTER TABLE users ADD COLUMN totp_last_step INTEGER NOT NULL DEFAULT 0;
