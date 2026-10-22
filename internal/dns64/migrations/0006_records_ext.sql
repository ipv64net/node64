-- Eigene Eintraege: Kommentar, PTR automatisch abschaltbar (weitere Typen TXT, MX, SRV, PTR, CAA brauchen keine Spalte).
ALTER TABLE dns64_records ADD COLUMN comment TEXT NOT NULL DEFAULT '';
ALTER TABLE dns64_records ADD COLUMN no_ptr INTEGER NOT NULL DEFAULT 0;
