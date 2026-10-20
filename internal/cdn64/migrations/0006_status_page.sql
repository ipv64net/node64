-- CDN64 (PROXY64) Hostart "status": Domain zeigt eine Statusseite der Healthchecks (hc_status_pages.id, 0 = keine).
ALTER TABLE cdn_hosts ADD COLUMN status_page_id INTEGER NOT NULL DEFAULT 0;
