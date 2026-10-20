-- Honeypot64 H6: Fingerabdruck des Clients je Ereignis (sensor_fp.go), leer = keiner.
-- "ja4:<ja4>" (TLS-ClientHello) bzw. "hassh:<md5>" (SSH-KEXINIT des Clients). Bestehende Zeilen bleiben leer.

ALTER TABLE hp_events ADD COLUMN fingerprint TEXT NOT NULL DEFAULT '';
