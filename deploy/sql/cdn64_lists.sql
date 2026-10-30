-- CDN64: Sperr- und Freigabeliste je Tunnel (PROXY64 1.45, Reiter Zugriffslisten). Die Node schickt beide Listen
-- (PUT /cdn64o/tunnels/{id}/lists); die Server weisen Adressen der Sperrliste fuer alle Namen des Tunnels schon beim
-- Verbindungsaufbau ab, die Freigabeliste geht vor. Hauptdatenbank ipv64, MariaDB 10.5+. Mehrfach ausfuehrbar.
-- Nach cdn64_online.sql.
CREATE TABLE IF NOT EXISTS `cdn64o_tunnel_lists` (
  `tunnel_id` varchar(24) NOT NULL,
  `kind` varchar(5) NOT NULL,   -- deny | allow
  `cidr` varchar(64) NOT NULL,
  PRIMARY KEY (`tunnel_id`, `kind`, `cidr`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
