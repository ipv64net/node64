-- Tags je Geraet in einer Gruppe (nur zum Ordnen und Filtern, keine Wirkung auf die Regeln); kommagetrennt.
ALTER TABLE dns64_group_members ADD COLUMN tags TEXT NOT NULL DEFAULT '';
