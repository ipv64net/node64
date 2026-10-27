-- CDN64 Schutz-Statistik und leichte WAF (srv07/srv08). Hauptdatenbank ipv64, MariaDB 10.5+.
-- Planung: docs/PLAN-CDN64-SCHUTZ.md, Abschnitt 8. Mehrfach ausfuehrbar (IF NOT EXISTS). Nach cdn64_online.sql.

-- Zaehler je Host und Tag (Differenzen aus edge/report): Abgewehrt nach Grund (Blockliste, Zugriffsliste, Ueberlast,
-- WAF-Muster, JA4 gesperrt), JA4-Treffer (gesperrt oder nur gezaehlt), verschiedene gesperrte IPs (Summe der
-- Meldungen), Verbindungen von IPv4-Besuchern. rejected (Anfrage-Limit) zaehlt in der Anzeige zu "Ueberlast".
ALTER TABLE `cdn64o_traffic` ADD COLUMN IF NOT EXISTS `blocked_list` bigint(20) NOT NULL DEFAULT 0;
ALTER TABLE `cdn64o_traffic` ADD COLUMN IF NOT EXISTS `blocked_acl` bigint(20) NOT NULL DEFAULT 0;
ALTER TABLE `cdn64o_traffic` ADD COLUMN IF NOT EXISTS `blocked_flood` bigint(20) NOT NULL DEFAULT 0;
ALTER TABLE `cdn64o_traffic` ADD COLUMN IF NOT EXISTS `blocked_waf` bigint(20) NOT NULL DEFAULT 0;
ALTER TABLE `cdn64o_traffic` ADD COLUMN IF NOT EXISTS `blocked_ja4` bigint(20) NOT NULL DEFAULT 0;
ALTER TABLE `cdn64o_traffic` ADD COLUMN IF NOT EXISTS `ja4_hits` bigint(20) NOT NULL DEFAULT 0;
ALTER TABLE `cdn64o_traffic` ADD COLUMN IF NOT EXISTS `blocked_ips` bigint(20) NOT NULL DEFAULT 0;
ALTER TABLE `cdn64o_traffic` ADD COLUMN IF NOT EXISTS `conns_v4` bigint(20) NOT NULL DEFAULT 0;

-- WAF je Host: waf = Muster-WAF (Modus 2/3), ja4 = off | count | block. Der globale Start-Schalter C64O_JA4_GLOBAL
-- in api_v2_cdn64o.php ("count" in der ersten Woche) wird mit dem Host-Wert verrechnet.
ALTER TABLE `cdn64o_hosts` ADD COLUMN IF NOT EXISTS `waf` tinyint(1) NOT NULL DEFAULT 1;
ALTER TABLE `cdn64o_hosts` ADD COLUMN IF NOT EXISTS `ja4` varchar(5) NOT NULL DEFAULT 'block';

-- JA4-Treffer je Host, Tag und Fingerabdruck (hoechstens 20 je Host und Tag). Aufraeumen nach 35 Tagen in
-- bots/cdn64_orphans.php.
CREATE TABLE IF NOT EXISTS `cdn64o_ja4` (
  `host_id` int(11) NOT NULL,
  `userid` int(11) NOT NULL,
  `day` date NOT NULL,
  `ja4` varchar(64) NOT NULL,
  `hits` bigint(20) NOT NULL DEFAULT 0,
  PRIMARY KEY (`host_id`, `day`, `ja4`),
  KEY `userid_day` (`userid`, `day`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
