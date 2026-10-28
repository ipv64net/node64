-- Sonar64 bei ipv64: verteiltes Community-Messnetz (API v2 /sonar/*, Jobs in bots/sonar_*.php, Seiten unter sonar/).
-- Hauptdatenbank ipv64, MariaDB 10.5+. Mehrfach ausfuehrbar (IF NOT EXISTS). Plan: docs/PLAN-NODE64-SONAR64.md,
-- Vertrag (verbindlich): docs/SONAR64-VERTRAG.md Abschnitt 6.
--
-- Alle Zeiten UTC (von PHP mit gmdate geschrieben, nie NOW()), DATETIME(3) = Millisekunden. Texte utf8mb4; die API
-- laesst fuer Namen nur ASCII zu (Verbindung laeuft mit SET NAMES 'utf8').
-- IPs (ip4/ip6) sind intern: nie oeffentlich ausgeben, nur im Plan der Knoten, die messen sollen.
--
-- Aufbewahrung (bots/sonar_cleanup.php): sonar_results/sonar_traces 7 Tage, sonar_inbound 24 h, sonar_pair_1h 90 Tage,
-- sonar_asn_1d/sonar_outages/sonar_trust_log dauerhaft.

-- Sonar-Token (s64_ + 40 bzw. Anker s64a_ + 40). Nur SHA-256 (hex) gespeichert.
CREATE TABLE IF NOT EXISTS `sonar_tokens` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `userid` int(11) NOT NULL,                          -- 0 = ipv64 (Anker ohne Account)
  `kind` enum('node','anchor') NOT NULL DEFAULT 'node',
  `name` varchar(64) NOT NULL DEFAULT '',             -- Anker: Ankername ([a-z0-9]{2,12})
  `token_hash` char(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `node_id` varchar(16) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  `created_at` datetime(3) NOT NULL,
  `last_used_at` datetime(3) DEFAULT NULL,
  `revoked_at` datetime(3) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `token_hash` (`token_hash`),
  KEY `userid` (`userid`, `revoked_at`),
  KEY `node_id` (`node_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Knoten (eine Zeile je registriertem Token; Anker node_id a_<name>).
CREATE TABLE IF NOT EXISTS `sonar_nodes` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `node_id` varchar(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `userid` int(11) NOT NULL,
  `token_id` int(10) unsigned NOT NULL,
  `role` enum('node','anchor') NOT NULL DEFAULT 'node',
  `pubkey` varchar(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,   -- Ed25519, Base64 std
  `name` varchar(32) NOT NULL,                        -- Anzeigename, eindeutig (ohne Gross/Klein)
  `slug` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `lat` double DEFAULT NULL,                          -- genau, nur fuer Besitzer und Plausibilitaet
  `lon` double DEFAULT NULL,
  `pub_lat` double DEFAULT NULL,                      -- verschleiert (s64_pub_coords, fester Versatz <= 1 km)
  `pub_lon` double DEFAULT NULL,
  `jitter_seed` int(11) NOT NULL DEFAULT 0,
  `access` varchar(12) NOT NULL DEFAULT 'other',
  `device` varchar(16) NOT NULL DEFAULT 'other',
  `measured` tinyint(4) NOT NULL DEFAULT 0,
  `budget` varchar(12) NOT NULL DEFAULT 'sparsam',
  `mode` varchar(10) NOT NULL DEFAULT 'headless',
  `version` varchar(32) NOT NULL DEFAULT '',
  `ip4` varchar(45) DEFAULT NULL,
  `ip6` varchar(45) DEFAULT NULL,
  `asn4` int(10) unsigned DEFAULT NULL,
  `asname4` varchar(100) DEFAULT NULL,
  `asn6` int(10) unsigned DEFAULT NULL,
  `asname6` varchar(100) DEFAULT NULL,
  `asn_at` datetime(3) DEFAULT NULL,                  -- letzte ASN-Abfrage (Cache 24 h)
  `place` varchar(80) DEFAULT NULL,
  `reach4` enum('none','icmp','udp') NOT NULL DEFAULT 'none',
  `reach6` enum('none','icmp','udp') NOT NULL DEFAULT 'none',
  `trust` enum('new','stable','trusted','pillar','anchor','quarantine') NOT NULL DEFAULT 'new',
  `score` double NOT NULL DEFAULT 0,
  `uptime30` double NOT NULL DEFAULT 0,
  `plaus_ok` int(10) unsigned NOT NULL DEFAULT 0,
  `plaus_bad` int(10) unsigned NOT NULL DEFAULT 0,
  `last_seq` bigint(20) NOT NULL DEFAULT 0,
  `first_seen` datetime(3) NOT NULL,
  `last_seen` datetime(3) DEFAULT NULL,
  `last_report` datetime(3) DEFAULT NULL,
  `last_plan` datetime(3) DEFAULT NULL,
  `health` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (`health` IS NULL OR json_valid(`health`)),
  `active` tinyint(4) NOT NULL DEFAULT 1,
  PRIMARY KEY (`id`),
  UNIQUE KEY `node_id` (`node_id`),
  UNIQUE KEY `name` (`name`),
  UNIQUE KEY `slug` (`slug`),
  KEY `userid` (`userid`),
  KEY `token_id` (`token_id`),
  KEY `active_seen` (`active`, `last_seen`),
  KEY `trust` (`trust`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Aktueller Plan je Knoten (Planer schreibt node_id/issued/expires/body/etag/controls per INSERT ... ON DUPLICATE KEY
-- UPDATE, kein REPLACE). sent_* / prev_body setzt GET /sonar/plan: zuletzt und davor ausgelieferter Plan, gegen die
-- POST /sonar/results prueft (not_in_plan, too_many).
CREATE TABLE IF NOT EXISTS `sonar_plans` (
  `node_id` varchar(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `issued` datetime(3) NOT NULL,
  `expires` datetime(3) NOT NULL,
  `body` mediumtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,   -- Plan-JSON ohne Signatur (exakte Bytes)
  `etag` char(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `controls` text DEFAULT NULL,                       -- Ziel-IDs der Kontrollziele (nie als solche ausgeliefert)
  `sent_etag` char(16) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  `sent_body` mediumtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
  `prev_body` mediumtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
  `sent_at` datetime(3) DEFAULT NULL,
  PRIMARY KEY (`node_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Ergebnisse (Zusammenfassung je Ziel und Runde), 7 Tage. valid=0 mit reason: verworfen, aber zur Auswertung
-- gespeichert (bad_time, below_light, too_smooth); andere Gruende werden nur gezaehlt.
CREATE TABLE IF NOT EXISTS `sonar_results` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `round` datetime NOT NULL,
  `src` varchar(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `dst` varchar(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `fam` tinyint(4) NOT NULL,
  `method` varchar(6) CHARACTER SET ascii NOT NULL,
  `sent` tinyint(3) unsigned NOT NULL DEFAULT 0,
  `recv` tinyint(3) unsigned NOT NULL DEFAULT 0,
  `min_ms` float NOT NULL DEFAULT 0,
  `avg_ms` float NOT NULL DEFAULT 0,
  `max_ms` float NOT NULL DEFAULT 0,
  `jitter_ms` float NOT NULL DEFAULT 0,
  `at` datetime(3) NOT NULL,
  `valid` tinyint(4) NOT NULL DEFAULT 1,
  `reason` varchar(16) CHARACTER SET ascii DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `once` (`src`, `round`, `dst`, `fam`, `method`),
  KEY `dst_at` (`dst`, `at`),
  KEY `src_at` (`src`, `at`),
  KEY `at` (`at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Traceroutes, 7 Tage. hops: [{ttl, addr, rtt}], nicht oeffentliche Hop-Adressen leer.
CREATE TABLE IF NOT EXISTS `sonar_traces` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `round` datetime NOT NULL,
  `src` varchar(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `dst` varchar(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `fam` tinyint(4) NOT NULL,
  `at` datetime(3) NOT NULL,
  `hops` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL CHECK (json_valid(`hops`)),
  PRIMARY KEY (`id`),
  UNIQUE KEY `once` (`src`, `round`, `dst`, `fam`),
  KEY `dst_at` (`dst`, `at`),
  KEY `at` (`at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Auf UDP 6464 beantwortete Proben (Report.inbound), 24 h.
CREATE TABLE IF NOT EXISTS `sonar_inbound` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `node_id` varchar(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `from_short` char(8) CHARACTER SET ascii NOT NULL,
  `fam` tinyint(4) NOT NULL,
  `at` datetime(3) NOT NULL,
  `count` int(10) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `node_at` (`node_id`, `at`),
  KEY `at` (`at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Stundenwerte je Paar (bots/sonar_rollup.php), 90 Tage.
CREATE TABLE IF NOT EXISTS `sonar_pair_1h` (
  `src` varchar(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `dst` varchar(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `fam` tinyint(4) NOT NULL,
  `hour` datetime NOT NULL,
  `n` int(10) unsigned NOT NULL DEFAULT 0,
  `avg_ms` float NOT NULL DEFAULT 0,
  `p50_ms` float NOT NULL DEFAULT 0,
  `loss` float NOT NULL DEFAULT 0,
  PRIMARY KEY (`src`, `dst`, `fam`, `hour`),
  KEY `hour` (`hour`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tageswerte je Provider-Paar (bots/sonar_rollup.php), dauerhaft.
CREATE TABLE IF NOT EXISTS `sonar_asn_1d` (
  `day` date NOT NULL,
  `asn_a` int(10) unsigned NOT NULL,
  `asn_b` int(10) unsigned NOT NULL,
  `fam` tinyint(4) NOT NULL,
  `n` int(10) unsigned NOT NULL DEFAULT 0,
  `p50_ms` float NOT NULL DEFAULT 0,
  `loss` float NOT NULL DEFAULT 0,
  PRIMARY KEY (`day`, `asn_a`, `asn_b`, `fam`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Stoerungen nach Provider (ASN) oder Region (bots/sonar_outages.php), dauerhaft.
CREATE TABLE IF NOT EXISTS `sonar_outages` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `kind` enum('asn','region') NOT NULL,
  `keyval` varchar(32) NOT NULL,
  `label` varchar(120) NOT NULL DEFAULT '',
  `started` datetime(3) NOT NULL,
  `ended` datetime(3) DEFAULT NULL,
  `affected` int(10) unsigned NOT NULL DEFAULT 0,
  `total` int(10) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `open` (`ended`, `kind`, `keyval`),
  KEY `started` (`started`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Aenderungen der Vertrauensstufe (Jobs und sofortige Abstufung der API), dauerhaft.
CREATE TABLE IF NOT EXISTS `sonar_trust_log` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `node_id` varchar(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `at` datetime(3) NOT NULL,
  `old` varchar(12) NOT NULL,
  `new` varchar(12) NOT NULL,
  `reason` varchar(64) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `node_at` (`node_id`, `at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
