<?php
/**
 * CDN64: verwaiste Tunnel aufraeumen (Node64-Container geloescht, ohne vorher abzumelden). Stuendlich ueber
 * honeypot_cron.php (Job "cdn64old"), nur Kommandozeile:
 *
 *   php cdn64_orphans.php          ausfuehren
 *   php cdn64_orphans.php --dry    nur anzeigen, nichts aendern
 *
 * Ein Tunnel, der seit 14 Tagen nicht verbunden war (last_seen; nie verbunden: seit dem Anlegen), wird mit allem
 * entfernt: DNS seiner Namen zurueck auf die urspruenglichen Eintraege, die Namen mit Zuordnung, Ziel, Liste,
 * Portmapper und Zertifikat, zuletzt der Tunnel samt Token. Die CDN64-Server holen ihre Konfiguration alle 10 s und
 * lassen die Namen danach fallen. Keine Benachrichtigung; ab 48 Stunden zeigt die Seite cdn64 einen Hinweis mit Datum.
 * Ein Name, der noch an einem anderen (verbundenen) Tunnel haengt, bleibt. Meldet sich die Node selbst noch bei
 * ipv64.net (node64_nodes.last_seen, z. B. PROXY64 nur ausgeschaltet), bleibt der Tunnel. Lehnt PowerDNS das
 * Zuruecksetzen ab, bleibt der Name (und damit der Tunnel) bis zum naechsten Lauf.
 *
 * Sicherung: nur, wenn sich gerade ein CDN64-Server meldet und in den letzten 15 Minuten irgendein Tunnel verbunden
 * war - sonst stammen alte last_seen eher von einem Ausfall bei ipv64 bzw. den Servern als von verwaisten Nodes.
 *
 * Ausserdem (immer, vor der Sicherung): JA4-Treffer (cdn64o_ja4) aelter als 35 Tage loeschen, in Stapeln.
 */
if(php_sapi_name() !== 'cli') { exit; }
include(__DIR__ . "/../dbconnect.php");

const C64X_AFTER   = 14; // Tage ohne Verbindung
const C64X_CDN_TMP = 3;  // Markierung der Server-Eintraege in subdomain_records (wie C64O_CDN_TMP in api_v2_cdn64o.php)
const C64X_TTL     = 10; // wie C64O_TTL
const C64X_JA4_KEEP = 35;  // Tage cdn64o_ja4 (Statistik zeigt hoechstens 30)
const C64X_BATCH   = 10000; // Zeilen je DELETE

$dry = in_array('--dry', $argv, true);
$l = $pdo->query("SELECT GET_LOCK('cdn64_orphans', 0) l")->fetch(PDO::FETCH_ASSOC);
if((int)($l['l'] ?? 0) !== 1) { echo "laeuft bereits\n"; exit(0); }
$q = function(string $sql, array $a = array()) use ($pdo): PDOStatement { $st = $pdo->prepare($sql); $st->execute($a); return $st; };

// JA4-Treffer der Schutz-Statistik nur so lange wie noetig
$cut = date('Y-m-d', time() - C64X_JA4_KEEP * 86400);
if($dry) {
	echo "cdn64o_ja4: " . (int)$q("SELECT COUNT(*) FROM cdn64o_ja4 WHERE day < :d", array('d' => $cut))->fetchColumn() . " Zeilen vor $cut (nur angezeigt)\n";
} else {
	$del = 0;
	do { $c = $q("DELETE FROM cdn64o_ja4 WHERE day < :d LIMIT " . C64X_BATCH, array('d' => $cut))->rowCount(); $del += $c; } while($c >= C64X_BATCH);
	if($del) { echo "cdn64o_ja4: $del Zeilen vor $cut geloescht\n"; }
}

$edge = (int)$q("SELECT COUNT(*) FROM cdn64o_edges WHERE disabled = 0 AND last_seen >= NOW() - INTERVAL 60 SECOND")->fetchColumn();
$live = (int)$q("SELECT COUNT(*) FROM cdn64o_tunnels WHERE last_seen >= NOW() - INTERVAL 15 MINUTE")->fetchColumn();
if($edge === 0 OR $live === 0) { echo "kein CDN64-Server bzw. kein verbundener Tunnel gerade - nichts geprueft\n"; exit(0); }

// wie c64o_dns_off/c64o_edges_off: Originale wieder aktivieren, Server-Eintraege entfernen, je Typ ein do_zone_update
// (ersetzt das RRset durch den Rest bzw. loescht es). false, wenn PowerDNS ablehnt (der Name bleibt, der naechste Lauf
// schickt den Stand noch einmal)
$dnsOff = function(array $h) use ($q, $pdo): bool {
	$u = (int)$h['userid']; $sid = (int)$h['subdomain_id']; $p = $h['praefix'];
	$call = function(callable $fn) { // Ausgaben von dbconnect.php unterdruecken, Fehler = nicht geklappt
		ob_start();
		try { return $fn(); }
		catch(Throwable $e) { return false; }
		finally { ob_end_clean(); }
	};
	foreach($q("SELECT r.record_id, r.role FROM cdn64o_records r WHERE r.host_id = :h", array('h' => $h['id']))->fetchAll(PDO::FETCH_ASSOC) as $r) {
		if($r['role'] === 'edge') { $q("DELETE FROM subdomain_records WHERE id = :i AND cdn_tmp = :m", array('i' => $r['record_id'], 'm' => C64X_CDN_TMP)); }
		else { $q("UPDATE subdomain_records set deactivated = 0 WHERE id = :i", array('i' => $r['record_id'])); }
		$q("DELETE FROM cdn64o_records WHERE host_id = :h AND record_id = :r", array('h' => $h['id'], 'r' => $r['record_id']));
	}
	$ok = true;
	foreach(array('A', 'AAAA') as $t) {
		if(!$call(fn() => do_zone_update($pdo, $u, $sid, $t, (string)C64X_TTL, $p))) { $ok = false; echo "  DNS " . $h['fqdn'] . " $t: abgelehnt
"; }
	}
	return $ok;
};
// wie c64o_host_purge: alles eines Namens
$purge = function(array $h) use ($q): void {
	foreach(array('cdn64o_host_tunnels', 'cdn64o_targets', 'cdn64o_acl', 'cdn64o_mappings') as $tab) { $q("DELETE FROM $tab WHERE host_id = :h", array('h' => $h['id'])); }
	$q("DELETE FROM cdn64o_certs WHERE fqdn = :f", array('f' => $h['fqdn']));
	$q("DELETE FROM cdn64o_hosts WHERE id = :h", array('h' => $h['id']));
	$q("INSERT INTO cdn64o_events (host_id, userid, kind, message) VALUES (:h, :u, 'disabled', :m)",
		array('h' => $h['id'], 'u' => $h['userid'], 'm' => 'node not connected for ' . C64X_AFTER . ' days: removed'));
};

$tunnels = $q("SELECT t.* FROM cdn64o_tunnels t WHERE COALESCE(t.last_seen, t.created_at) < NOW() - INTERVAL " . C64X_AFTER . " DAY
	AND NOT EXISTS (SELECT 1 FROM node64_nodes n WHERE n.userid = t.userid AND n.node_id = t.node_id AND n.removed_at IS NULL
		AND n.last_seen >= UTC_TIMESTAMP() - INTERVAL " . C64X_AFTER . " DAY)")->fetchAll(PDO::FETCH_ASSOC);
$names = 0; $removed = 0;
foreach($tunnels as $t) {
	$hosts = $q("SELECT h.* FROM cdn64o_hosts h JOIN cdn64o_host_tunnels ht ON ht.host_id = h.id WHERE ht.tunnel_id = :t", array('t' => $t['id']))->fetchAll(PDO::FETCH_ASSOC);
	echo "Tunnel " . $t['id'] . " (User " . $t['userid'] . ", zuletzt " . ($t['last_seen'] ?? 'nie, angelegt ' . $t['created_at']) . "): " . count($hosts) . " Name(n)\n";
	if($dry) { foreach($hosts as $h) { echo "  " . $h['fqdn'] . "\n"; } continue; }
	$gone = array(); $kept = 0;
	foreach($hosts as $h) {
		if($q("SELECT host_id FROM cdn64o_host_tunnels WHERE host_id = :h AND tunnel_id <> :t LIMIT 1", array('h' => $h['id'], 't' => $t['id']))->fetch() !== false) { // haengt noch an einem anderen Tunnel
			$q("DELETE FROM cdn64o_host_tunnels WHERE host_id = :h AND tunnel_id = :t", array('h' => $h['id'], 't' => $t['id']));
			continue;
		}
		if(!$dnsOff($h)) { $kept++; continue; } // naechster Lauf versucht es erneut
		$purge($h);
		$gone[] = $h['fqdn'];
	}
	$names += count($gone);
	if($kept) { echo "  $kept Name(n) wegen DNS-Fehler behalten, Tunnel bleibt\n"; continue; }
	$q("DELETE FROM cdn64o_tunnels WHERE id = :i", array('i' => $t['id']));
	$removed++;
	if(function_exists('add_log')) {
		add_log($pdo, $t['userid'], "0", "CDN64 online", "Tunnel " . $t['id'] . " was not connected for " . C64X_AFTER . " days and was removed" . ($gone ? " with: " . implode(', ', $gone) : "") . ".");
	}
}
echo ($dry ? count($tunnels) . " Tunnel (nur angezeigt)" : "$removed Tunnel entfernt, $names Name(n)") . "\n";
