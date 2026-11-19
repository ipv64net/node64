-- Host darf ausgeschaltet sein (#229): nicht erreichbar = "ausgeschaltet", ohne Meldung und ohne Problem.
ALTER TABLE m64_hosts ADD COLUMN offline_ok INTEGER NOT NULL DEFAULT 0;
