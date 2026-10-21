-- Proxmox VE: Index fuer die CPU-Linien der Systemseite (alle Gaeste eines Systems, letzte Stunde) – der Primaerschluessel
-- (system_id, key, t) passt dafuer nicht (ohne diesen Index laeuft die Abfrage ueber 48 h aller Gaeste).
CREATE INDEX IF NOT EXISTS pve_hist_1m_sys_t ON pve_hist_1m(system_id, t);
