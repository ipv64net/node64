-- Statusseiten: eigenes Logo je Seite (im Kopf neben dem Titel, auch als Favicon). Klein gehalten (Grenze im Code).
ALTER TABLE hc_status_pages ADD COLUMN logo BLOB;
ALTER TABLE hc_status_pages ADD COLUMN logo_type TEXT NOT NULL DEFAULT '';    -- image/png | image/jpeg | image/webp | image/svg+xml
ALTER TABLE hc_status_pages ADD COLUMN logo_updated TEXT NOT NULL DEFAULT ''; -- fuer Cache-Busting (?v=)
