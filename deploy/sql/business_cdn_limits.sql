-- 2026-10-27 (Dennis): Account-Klasse Business (user_class.id = 4) mit CDN64 einen Gang zurueck:
-- 2 parallele Tunnel-Verbindungen je Edge-Server statt 4 und 10 TB CDN-Traffic im Monat statt 20 TB (Spalte in GB).
-- Company (id 5) bleibt bei 4 Verbindungen und 20 TB. Mehrfach ausfuehrbar.
UPDATE `user_class` SET `cdn_tunnel_sessions` = 2, `cdn_traffic` = 10240 WHERE `id` = 4;
