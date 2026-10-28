<?php
/**
 * IPv64.net API v2 – CDN64 online (Pfade /cdn64o/...). Wird von api_v2.php vor dispatch() eingebunden:
 *     require __DIR__ . '/api_v2_cdn64o.php';
 * Tunnel zu den CDN64-Servern srv07/srv08.cdn64.de: Nodes melden Tunnel und Namen an (API-Key), die Server holen
 * ihre Konfiguration und melden Traffic (Server-Geheimnis). Eigene Tabellen cdn64o_* (deploy/sql/cdn64_online.sql),
 * nichts aus dem alten CDN wird geschrieben; das Kontingent (user_class.cdn_domains, cdn_traffic) teilen sich beide.
 * DNS: A/AAAA beider Server mit TTL 10 in subdomain_records (cdn_tmp = 3: von update.php und API geschuetzt),
 * vorhandene A/AAAA des Namens werden deaktiviert und beim Ausschalten wieder aktiviert.
 * Planung: docs/CDN64-ONLINE.md im Node64-Repo.
 */

const C64O_TTL          = 10;   // TTL der Server-Eintraege
const C64O_CDN_TMP      = 3;    // Markierung in subdomain_records (1/2 = altes CDN)
const C64O_MAX_TUNNELS  = 10;   // Tunnels je Account
const C64O_EDGE_STALE   = 45;   // Sekunden ohne Abruf: Server gilt als ausgefallen (G6)
const C64O_EDGE_BACK    = 30;   // Sekunden wieder da: Adressen wieder eintragen
const C64O_MODES        = array(1, 2, 3);  // 1 durchreichen, 2 terminieren (T5), 3 direkt zum Ziel (T7)
const C64O_ACL_MAX      = 200;  // Eintraege je Liste
const C64O_PORT_MIN     = 50000; // Portmapper: Ports der Server (wie beim alten CDN)
const C64O_PORT_MAX     = 62000;
const C64O_JA4_GLOBAL   = 'count'; // JA4 global: erste Woche nach dem Ausrollen nur zaehlen ('count'), danach 'block'
const C64O_JA4_DAY_MAX  = 20;   // verschiedene JA4 je Host und Tag (cdn64o_ja4)
// Schutz-Zaehler aus edge/report (Spalten in cdn64o_traffic) und Ausgabe protection (Feld => Spalte; rejected = Anfrage-Limit)
const C64O_PROT_COLS    = array('blocked_list', 'blocked_acl', 'blocked_flood', 'blocked_waf', 'blocked_ja4', 'ja4_hits', 'blocked_ips', 'conns_v4');
const C64O_PROT         = array('blocked_list' => 'blocked_list', 'blocked_acl' => 'blocked_acl', 'blocked_flood' => 'blocked_flood', 'blocked_limit' => 'rejected',
	'blocked_waf' => 'blocked_waf', 'blocked_ja4' => 'blocked_ja4', 'ja4_hits' => 'ja4_hits', 'blocked_ips' => 'blocked_ips', 'conns' => 'conns', 'conns_v4' => 'conns_v4');

// ---------------------------------------------------------------- Hilfen

function c64o_edges(bool $all = false): array {
	return qa("SELECT * FROM cdn64o_edges" . ($all ? "" : " WHERE disabled = 0") . " ORDER BY name");
}

function c64o_edge_out(array $e): array {
	$ips = array_values(array_filter(array($e['ipv6'], $e['ipv4'])));
	return array('name' => $e['name'], 'host' => $e['hostname'], 'port' => (int)$e['tunnel_port'], 'ips' => $ips);
}

/** Kontingent des Accounts: altes und neues CDN zusammen (Domains, Traffic des Monats in MB), Bandbreite. */
function c64o_quota(int $u, array $class): array {
	$old = (int)q1("SELECT count(id) c FROM cdn_domains WHERE userid = :u", array('u' => $u))['c'];
	$new = (int)q1("SELECT count(id) c FROM cdn64o_hosts WHERE userid = :u", array('u' => $u))['c'];
	$me = q1("SELECT cdn_traffic_input, cdn_traffic_output FROM users WHERE id = :u", array('u' => $u)) ?? array();
	$oldMB = (float)($me['cdn_traffic_input'] ?? 0) + (float)($me['cdn_traffic_output'] ?? 0);
	$t = q1("SELECT COALESCE(SUM(bytes_in + bytes_out), 0) b FROM cdn64o_traffic WHERE userid = :u AND day >= :d", array('u' => $u, 'd' => date('Y-m-01')));
	$newMB = (float)$t['b'] / 1048576;
	$oldMap = (int)q1("SELECT count(id) c FROM cdn_mapping WHERE userid = :u", array('u' => $u))['c'];
	$newMap = (int)q1("SELECT count(id) c FROM cdn64o_mappings WHERE userid = :u", array('u' => $u))['c'];
	return array(
		'domains' => array('used' => $old + $new, 'old_cdn' => $old, 'limit' => (int)($class['cdn_domains'] ?? 0)),
		'mappings' => array('used' => $oldMap + $newMap, 'old_cdn' => $oldMap, 'limit' => (int)($class['cdn_mappings'] ?? 0)),
		'traffic_mb' => array('used' => round($oldMB + $newMB, 1), 'old_cdn' => round($oldMB, 1), 'limit' => (int)($class['cdn_traffic'] ?? 0) * 1024),
		'bandwidth_mbit' => (int)($class['cdn_bandwidth'] ?? 0),
	);
}

function c64o_over_traffic(array $q): bool { return $q['traffic_mb']['limit'] <= 0 || $q['traffic_mb']['used'] >= $q['traffic_mb']['limit']; }

function c64o_event(int $hostId, int $u, string $kind, string $msg = ''): void {
	q("INSERT INTO cdn64o_events (host_id, userid, kind, message) VALUES (:h, :u, :k, :m)", array('h' => $hostId, 'u' => $u, 'k' => $kind, 'm' => mb_substr($msg, 0, 255)));
}

function c64o_tunnel_out(array $t): array {
	return array('id' => $t['id'], 'name' => $t['name'], 'node_id' => $t['node_id'], 'status' => $t['status'], 'created_at' => iso($t['created_at']),
		'last_seen' => iso($t['last_seen']), 'last_edge' => $t['last_edge'] ?: null, 'node_version' => $t['node_version'] ?: null,
		'sessions' => c64o_sessions($GLOBALS['CLASS'] ?? array()));
}

/** Parallele Tunnel-Verbindungen je Server fuer eine Klasse (user_class.cdn_tunnel_sessions: Business/Company mehrere). */
function c64o_sessions(array $class): int { return max(1, min(8, (int)($class['cdn_tunnel_sessions'] ?? 1))); }

function c64o_host_out(array $h): array {
	$tun = array_column(qa("SELECT tunnel_id FROM cdn64o_host_tunnels WHERE host_id = :h ORDER BY priority, tunnel_id", array('h' => $h['id'])), 'tunnel_id');
	$tr = q1("SELECT COALESCE(SUM(bytes_in), 0) i, COALESCE(SUM(bytes_out), 0) o, COALESCE(SUM(conns), 0) c, COALESCE(SUM(requests), 0) r, COALESCE(SUM(rejected), 0) x
		FROM cdn64o_traffic WHERE host_id = :h AND day >= :d", array('h' => $h['id'], 'd' => date('Y-m-01')));
	return array('id' => (int)$h['id'], 'fqdn' => $h['fqdn'], 'mode' => (int)$h['mode'], 'wildcard' => (int)$h['wildcard'] === 1, 'status' => $h['status'],
		'blocked_reason' => $h['blocked_reason'] ?: null, 'paused' => (int)($h['paused'] ?? 0) === 1, 'paused_at' => iso($h['paused_at'] ?? null), 'error' => $h['error'] ?: null, 'tunnels' => $tun, 'domain_id' => (int)$h['subdomain_id'],
		'edges' => array_map('c64o_edge_out', c64o_edges()), 'traffic_month' => array('bytes_in' => (int)$tr['i'], 'bytes_out' => (int)$tr['o'], 'conns' => (int)$tr['c'], 'requests' => (int)$tr['r'], 'rejected' => (int)$tr['x']),
		'created_via' => $h['created_via'], 'created_at' => iso($h['created_at']), 'updated_at' => iso($h['updated_at']),
		'target' => (int)$h['mode'] === 3 ? c64o_target_out((int)$h['id']) : null, 'acl' => c64o_acl_out($h),
		'mappings' => c64o_mappings_out((int)$h['id']), 'waf' => (int)($h['waf'] ?? 1) === 1, 'ja4' => $h['ja4'] ?? 'block',
		'protection' => c64o_prot_out(q1("SELECT " . c64o_prot_sum() . " FROM cdn64o_traffic WHERE host_id = :h AND day >= :d", array('h' => $h['id'], 'd' => c64o_since(30)))));
}

/** Erster Tag eines Zeitraums von $days Tagen (1 = heute). */
function c64o_since(int $days): string { return date('Y-m-d', strtotime('-' . ($days - 1) . ' days')); }

/** Summen der Schutz-Zaehler fuer SELECT (Namen wie in protection). */
function c64o_prot_sum(): string { return implode(', ', array_map(fn($k, $c) => "COALESCE(SUM($c), 0) $k", array_keys(C64O_PROT), C64O_PROT)); }

function c64o_prot_out(?array $r): array {
	$o = array();
	foreach(array_keys(C64O_PROT) as $k) { $o[$k] = (int)($r[$k] ?? 0); }
	return $o;
}

/** JA4 fuer die Server: global 'count' (Startphase) macht aus 'block' des Hosts 'count'. */
function c64o_ja4_eff(string $v): string {
	if(!in_array($v, array('off', 'count', 'block'), true)) { $v = 'block'; }
	return C64O_JA4_GLOBAL === 'count' && $v === 'block' ? 'count' : $v;
}

/** Portmapper eines Namens (Modus 3 direkt zum Ziel, Modus 1/2 durch den Tunnel zu einem Stream der Node). */
function c64o_mappings_out(int $hostId): array {
	return array_map(fn($m) => array('id' => (int)$m['id'], 'name' => $m['name'], 'listen_port' => (int)$m['listen_port'], 'transport' => $m['transport'],
		'target_port' => (int)$m['target_port']), qa("SELECT * FROM cdn64o_mappings WHERE host_id = :h ORDER BY listen_port, transport", array('h' => $hostId)));
}

/** Freier Port der Server fuer ein Mapping: der gewuenschte, sonst wie beim alten CDN (derselbe wie ein anderes Mapping
 * des Namens auf diesen Ziel-Port, derselbe wie am Ziel, sonst zufaellig). null = keiner frei. */
function c64o_mapping_port(int $hostId, string $tr, int $targetPort, ?int $wish): ?int {
	$free = fn(int $p): bool => $p >= C64O_PORT_MIN AND $p <= C64O_PORT_MAX AND q1("SELECT id FROM cdn64o_mappings WHERE transport = :t AND listen_port = :p", array('t' => $tr, 'p' => $p)) === null;
	if($wish !== null) { return $free($wish) ? $wish : null; }
	foreach(qa("SELECT listen_port FROM cdn64o_mappings WHERE host_id = :h AND target_port = :p", array('h' => $hostId, 'p' => $targetPort)) as $m) {
		if($free((int)$m['listen_port'])) { return (int)$m['listen_port']; }
	}
	if($free($targetPort)) { return $targetPort; }
	for($i = 0; $i < 50; $i++) { if($free($p = random_int(C64O_PORT_MIN, C64O_PORT_MAX))) { return $p; } }
	$used = array_flip(array_column(qa("SELECT listen_port FROM cdn64o_mappings WHERE transport = :t", array('t' => $tr)), 'listen_port'));
	for($p = C64O_PORT_MIN; $p <= C64O_PORT_MAX; $p++) { if(!isset($used[$p])) { return $p; } }
	return null;
}

// ---------------------------------------------------------------- Modus 3: Ziel, Liste

/** Oeffentliche Unicast-Adresse (kein privates, reserviertes, CGNAT-, Dokumentations- oder Server-Netz). */
function c64o_public_ip(string $ip): bool {
	if(!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) { return false; }
	$bin = inet_pton($ip);
	$in = function(string $cidr) use ($bin): bool {
		[$net, $len] = explode('/', $cidr); $n = inet_pton($net);
		if($n === false OR strlen($n) !== strlen($bin)) { return false; }
		$bytes = intdiv((int)$len, 8); $bits = (int)$len % 8;
		if(substr($bin, 0, $bytes) !== substr($n, 0, $bytes)) { return false; }
		return $bits === 0 OR ((ord($bin[$bytes]) ^ ord($n[$bytes])) & (0xff << (8 - $bits)) & 0xff) === 0;
	};
	foreach(array('100.64.0.0/10', '192.0.0.0/24', '192.0.2.0/24', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '2001:db8::/32', '64:ff9b::/96', '2002::/16', '2001::/32', 'fc00::/7', 'fe80::/10') as $c) { if($in($c)) { return false; } }
	foreach(c64o_edges(true) as $e) { if($ip === $e['ipv4'] OR $ip === $e['ipv6']) { return false; } }
	return true;
}

/** Ziel aus der Eingabe (POST /cdn64o/hosts bzw. PUT .../target); $old = bisheriges Ziel. */
function c64o_target_in(?array $old = null): array {
	global $CLASS;
	$t = $old ?? array('source' => 'records', 'target' => '', 'port' => 443, 'scheme' => 'https', 'verify_tls' => 0, 'prefer_ipv6' => 1, 'frontend' => 2, 'cache_mb' => 0, 'cache_minutes' => 10);
	if(($v = in_str('source', false, 8)) !== null) {
		if(!in_array($v, array('records', 'fixed'), true)) { fail(422, 'invalid_field', "Field 'source' must be records or fixed.", array('field' => 'source')); }
		$t['source'] = $v;
	}
	if(($v = in_str('target', false, 253)) !== null) { $t['target'] = strtolower(trim(rtrim($v, '.'), '[]')); }
	if($t['source'] === 'fixed') {
		$v = $t['target'];
		if(filter_var($v, FILTER_VALIDATE_IP)) {
			if(!c64o_public_ip($v)) { fail(422, 'target_not_public', 'The target must be a public IP address.', array('field' => 'target')); }
		} elseif(!preg_match('/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/', $v)) {
			fail(422, 'invalid_field', "Field 'target' must be a public IP address or a host name.", array('field' => 'target'));
		}
	} else { $t['target'] = ''; }
	if(($v = in_str('scheme', false, 5)) !== null) {
		if(!in_array($v, array('http', 'https'), true)) { fail(422, 'invalid_field', "Field 'scheme' must be http or https.", array('field' => 'scheme')); }
		if($old === null OR $v !== $t['scheme']) { $t['port'] = $v === 'https' ? 443 : 80; }
		$t['scheme'] = $v;
	}
	if(($v = in_int('port', false, 1, 65535)) !== null) { $t['port'] = $v; }
	if(($v = in_bool('verify_tls')) !== null) { $t['verify_tls'] = $v ? 1 : 0; }
	if(($v = in_bool('prefer_ipv6')) !== null) { $t['prefer_ipv6'] = $v ? 1 : 0; }
	if(($v = in_int('frontend', false, 0, 3)) !== null) { $t['frontend'] = $v; } // 0 = keine Webseite, nur Portmapper
	$maxCache = (int)($CLASS['cdn_cache_size'] ?? 0);
	if(($v = in_int('cache_mb', false, 0, 100000)) !== null) {
		if($v > $maxCache) { fail(422, 'cache_limit', "The cache of your plan is at most $maxCache MB.", array('field' => 'cache_mb')); }
		$t['cache_mb'] = $v;
	}
	if(($v = in_int('cache_minutes', false, 1, 1440)) !== null) { $t['cache_minutes'] = $v; }
	return $t;
}

/** Ziel speichern (Modus 3). */
function c64o_target_save(int $hostId, array $t): void {
	q("INSERT INTO cdn64o_targets (host_id, source, target, port, scheme, verify_tls, prefer_ipv6, frontend, cache_mb, cache_minutes)
		VALUES (:h, :s, :t, :p, :sc, :v, :i6, :f, :cm, :ct) ON DUPLICATE KEY UPDATE source = VALUES(source), target = VALUES(target), port = VALUES(port),
		scheme = VALUES(scheme), verify_tls = VALUES(verify_tls), prefer_ipv6 = VALUES(prefer_ipv6), frontend = VALUES(frontend),
		cache_mb = VALUES(cache_mb), cache_minutes = VALUES(cache_minutes)",
		array('h' => $hostId, 's' => $t['source'], 't' => $t['target'], 'p' => (int)$t['port'], 'sc' => $t['scheme'], 'v' => (int)$t['verify_tls'],
			'i6' => (int)$t['prefer_ipv6'], 'f' => (int)$t['frontend'], 'cm' => (int)$t['cache_mb'], 'ct' => (int)$t['cache_minutes']));
}

/** Aktuelle Zieladressen aus den deaktivierten Originalen (DynDNS aktualisiert sie weiter). */
function c64o_target_records(int $hostId): array {
	return array_values(array_filter(array_column(qa("SELECT s.content FROM cdn64o_records r JOIN subdomain_records s ON s.id = r.record_id
		WHERE r.host_id = :h AND r.role = 'original' AND s.type IN ('A','AAAA') ORDER BY s.type DESC, s.id", array('h' => $hostId)), 'content'), 'c64o_public_ip'));
}

function c64o_target_row(int $hostId): ?array { return q1("SELECT * FROM cdn64o_targets WHERE host_id = :h", array('h' => $hostId)); }

function c64o_target_out(int $hostId): ?array {
	$t = c64o_target_row($hostId);
	if($t === null) { return null; }
	return array('source' => $t['source'], 'target' => $t['target'] ?: null, 'addrs' => $t['source'] === 'records' ? c64o_target_records($hostId) : null,
		'port' => (int)$t['port'], 'scheme' => $t['scheme'], 'verify_tls' => (int)$t['verify_tls'] === 1, 'prefer_ipv6' => (int)$t['prefer_ipv6'] === 1,
		'frontend' => (int)$t['frontend'], 'websockets' => true, 'cache_mb' => (int)$t['cache_mb'], 'cache_minutes' => (int)$t['cache_minutes']);
}

/** Ziel fuer die Server (Adressen bzw. Name). */
function c64o_target_edge(int $hostId): ?array {
	$t = c64o_target_row($hostId);
	if($t === null) { return null; }
	$addrs = array(); $name = '';
	if($t['source'] === 'records') { $addrs = c64o_target_records($hostId); }
	elseif(filter_var($t['target'], FILTER_VALIDATE_IP)) { $addrs = c64o_public_ip($t['target']) ? array($t['target']) : array(); }
	else { $name = $t['target']; }
	return array('addrs' => $addrs, 'host' => $name, 'port' => (int)$t['port'], 'scheme' => $t['scheme'], 'verify_tls' => (int)$t['verify_tls'] === 1,
		'prefer_ipv6' => (int)$t['prefer_ipv6'] === 1, 'frontend' => (int)$t['frontend'], 'cache_mb' => (int)$t['cache_mb'], 'cache_minutes' => (int)$t['cache_minutes']);
}

function c64o_acl_out(array $h): array {
	return array('default' => $h['acl_default'] ?: 'off',
		'list' => array_column(qa("SELECT cidr FROM cdn64o_acl WHERE host_id = :h ORDER BY id", array('h' => $h['id'])), 'cidr'));
}

/** IP oder Netz (IPv4/IPv6) wie im alten CDN. */
function c64o_cidr(string $v): ?string {
	$v = strtolower(trim($v));
	if(filter_var($v, FILTER_VALIDATE_IP)) { return $v; }
	if(preg_match('#^([0-9a-f:.]+)/(\d{1,3})$#', $v, $m) AND filter_var($m[1], FILTER_VALIDATE_IP)) {
		$max = str_contains($m[1], ':') ? 128 : 32;
		if((int)$m[2] <= $max) { return $m[1] . '/' . (int)$m[2]; }
	}
	return null;
}

function c64o_find_host(string $ref): array {
	$h = ctype_digit($ref)
		? q1("SELECT * FROM cdn64o_hosts WHERE id = :i AND userid = :u", array('i' => (int)$ref, 'u' => uid()))
		: q1("SELECT * FROM cdn64o_hosts WHERE fqdn = :f AND userid = :u", array('f' => strtolower(rtrim($ref, '.')), 'u' => uid()));
	if($h === null) { fail(404, 'cdn64o_host_not_found', 'CDN64 online host not found.'); }
	return $h;
}

function c64o_find_tunnel(string $id): array {
	$t = q1("SELECT * FROM cdn64o_tunnels WHERE id = :i AND userid = :u", array('i' => $id, 'u' => uid()));
	if($t === null) { fail(404, 'cdn64o_tunnel_not_found', 'Tunnel not found.'); }
	return $t;
}

/** Domain des Accounts, zu der der Name gehoert (laengster passender Name), und das Praefix davor. */
function c64o_domain_for(string $fqdn): array {
	$best = null;
	foreach(qa("SELECT * FROM subdomains WHERE userid = :u AND deactivated = 0", array('u' => uid())) as $d) {
		$n = strtolower(domain_name($d));
		if($fqdn === $n OR str_ends_with($fqdn, '.' . $n)) {
			if($best === null OR strlen($n) > strlen(domain_name($best))) { $best = $d; }
		}
	}
	if($best === null) { fail(422, 'domain_not_in_account', "The name is not part of a domain in your ipv64 account.", array('field' => 'fqdn')); }
	$n = strtolower(domain_name($best));
	$p = $fqdn === $n ? '' : substr($fqdn, 0, -strlen($n) - 1);
	return array($best, $p);
}

/** DNS umstellen: Originale A/AAAA deaktivieren, Server eintragen, an PowerDNS. false = PowerDNS-Fehler. */
function c64o_dns_on(array $h, array $d): bool {
	$u = (int)$h['userid']; $sid = (int)$d['id']; $p = $h['praefix']; $dn = domain_name($d);
	foreach(qa("SELECT id FROM subdomain_records WHERE subdomain_id = :s AND praefix = :p AND type IN ('A','AAAA') AND deactivated = 0 AND cdn_tmp = 0", array('s' => $sid, 'p' => $p)) as $r) {
		q("UPDATE subdomain_records set deactivated = 1 WHERE id = :i", array('i' => $r['id']));
		q("INSERT INTO cdn64o_records (host_id, record_id, role) VALUES (:h, :r, 'original')", array('h' => $h['id'], 'r' => $r['id']));
	}
	foreach(c64o_edges() as $e) {
		if((int)($e['withdrawn'] ?? 0) === 1) { continue; } // ausgefallen (G6): kommt beim Wiedereintrag dazu
		foreach(array('A' => $e['ipv4'], 'AAAA' => $e['ipv6']) as $type => $ip) {
			if($ip === '') { continue; }
			q("INSERT INTO subdomain_records (subdomain_id, userid, domainname, praefix, content, ttl, type, record_key, cdn_tmp) VALUES (:s, :u, :dn, :p, :c, :t, :ty, :k, :m)",
				array('s' => $sid, 'u' => $u, 'dn' => $dn, 'p' => $p, 'c' => $ip, 't' => C64O_TTL, 'ty' => $type, 'k' => token32(), 'm' => C64O_CDN_TMP));
			q("INSERT INTO cdn64o_records (host_id, record_id, role) VALUES (:h, :r, 'edge')", array('h' => $h['id'], 'r' => $GLOBALS['pdo']->lastInsertId()));
		}
	}
	$ok = true;
	foreach(array('A', 'AAAA') as $t) { if(!quiet(fn() => do_zone_update($GLOBALS['pdo'], $u, $sid, $t, (string)C64O_TTL, $p))) { $ok = false; } }
	return $ok;
}

/** DNS zurueck: Server-Eintraege loeschen, Originale wieder aktivieren, an PowerDNS. */
/** Alles eines Namens bei ipv64 entfernen (nach c64o_dns_off): Zuordnung zu Tunneln, Zertifikat, Ziel, Liste, Portmapper. */
function c64o_host_purge(array $h): void {
	foreach(array('cdn64o_host_tunnels', 'cdn64o_targets', 'cdn64o_acl', 'cdn64o_mappings') as $tab) { q("DELETE FROM $tab WHERE host_id = :h", array('h' => $h['id'])); }
	q("DELETE FROM cdn64o_certs WHERE fqdn = :f", array('f' => $h['fqdn']));
	q("DELETE FROM cdn64o_hosts WHERE id = :h", array('h' => $h['id']));
}

function c64o_dns_off(array $h): bool {
	$u = (int)$h['userid']; $sid = (int)$h['subdomain_id']; $p = $h['praefix'];
	foreach(qa("SELECT record_id, role FROM cdn64o_records WHERE host_id = :h", array('h' => $h['id'])) as $r) {
		if($r['role'] === 'edge') {
			q("DELETE FROM subdomain_records WHERE id = :i AND cdn_tmp = :m", array('i' => $r['record_id'], 'm' => C64O_CDN_TMP));
		} else {
			q("UPDATE subdomain_records set deactivated = 0 WHERE id = :i", array('i' => $r['record_id']));
		}
	}
	q("DELETE FROM cdn64o_records WHERE host_id = :h", array('h' => $h['id']));
	$ok = true;
	foreach(array('A', 'AAAA') as $t) { if(!quiet(fn() => do_zone_update($GLOBALS['pdo'], $u, $sid, $t, (string)C64O_TTL, $p))) { $ok = false; } }
	return $ok;
}

/**
 * G6: Ein Server, der sich laenger als C64O_EDGE_STALE Sekunden nicht gemeldet hat (Abruf alle 10 s), verschwindet aus
 * dem DNS aller CDN64-Namen, solange ein anderer da ist; ist er wieder C64O_EDGE_BACK Sekunden da, kommt er zurueck.
 * Laeuft bei jedem Abruf eines Servers (der gesunde Server bemerkt den Ausfall des anderen), aber nur, wenn der
 * rufende Server selbst ohne Pause da war (sonst war eher ipv64 weg). Vor dem Austragen fragt ipv64 /health des
 * Servers direkt: antwortet er, fehlt ihm nur der Weg zu ipv64 und er bleibt im DNS.
 */
function c64o_edge_watch(): void {
	$edges = c64o_edges();
	$fresh = fn($e) => $e['last_seen'] !== null && strtotime($e['last_seen']) >= time() - C64O_EDGE_STALE;
	$alive = count(array_filter($edges, $fresh));
	foreach($edges as $e) {
		if(!$fresh($e)) {
			if((int)$e['withdrawn'] === 0 && $alive > 0 && !c64o_edge_answers($e)) { c64o_edge_dns($e, false); }
			elseif($e['back_since'] !== null) { q("UPDATE cdn64o_edges set back_since = NULL WHERE id = :i", array('i' => $e['id'])); }
			continue;
		}
		if((int)$e['withdrawn'] === 1) {
			if($e['back_since'] === null) { q("UPDATE cdn64o_edges set back_since = NOW() WHERE id = :i", array('i' => $e['id'])); }
			elseif(strtotime($e['back_since']) <= time() - C64O_EDGE_BACK) { c64o_edge_dns($e, true); }
		}
	}
}

/** Antwortet der Server auf /health? Hoechstens ein Versuch je Minute und Server (Ergebnis in sys_get_temp_dir()). */
function c64o_edge_answers(array $e): bool {
	$f = sys_get_temp_dir() . '/c64o_probe_' . (int)$e['id'];
	if(is_file($f) AND filemtime($f) > time() - 60) { return trim((string)@file_get_contents($f)) === '1'; }
	$ctx = stream_context_create(array('http' => array('timeout' => 3, 'ignore_errors' => true, 'header' => "Host: " . $e['hostname'] . "\r\n")));
	$ok = false;
	foreach(array_filter(array($e['ipv4'], $e['ipv6'] !== '' ? '[' . $e['ipv6'] . ']' : '')) as $a) {
		$r = @file_get_contents('http://' . $a . '/health', false, $ctx);
		if($r !== false AND ($j = json_decode($r, true)) AND ($j['status'] ?? '') === 'ok') { $ok = true; break; }
	}
	@file_put_contents($f, $ok ? '1' : '0');
	return $ok;
}

/** Adressen eines Servers aus allen CDN64-Namen nehmen (false) bzw. wieder eintragen (true), an PowerDNS. */
function c64o_edge_dns(array $e, bool $on): void {
	$ips = array_values(array_filter(array($e['ipv4'], $e['ipv6'])));
	if(empty($ips)) { return; }
	q("UPDATE cdn64o_edges set withdrawn = :w, back_since = NULL WHERE id = :i", array('w' => $on ? 0 : 1, 'i' => $e['id']));
	$in = implode(',', array_map(fn($i) => $GLOBALS['pdo']->quote($i), $ips));
	foreach(qa("SELECT * FROM cdn64o_hosts WHERE status IN ('active', 'blocked')") as $h) {
		$sid = (int)$h['subdomain_id']; $u = (int)$h['userid']; $p = $h['praefix'];
		if($on) {
			$d = q1("SELECT * FROM subdomains WHERE id = :i", array('i' => $sid));
			if($d === null) { continue; }
			foreach(array('A' => $e['ipv4'], 'AAAA' => $e['ipv6']) as $type => $ip) {
				if($ip === '' OR q1("SELECT id FROM subdomain_records WHERE subdomain_id = :s AND praefix = :p AND type = :t AND content = :c AND cdn_tmp = :m",
					array('s' => $sid, 'p' => $p, 't' => $type, 'c' => $ip, 'm' => C64O_CDN_TMP)) !== null) { continue; }
				q("INSERT INTO subdomain_records (subdomain_id, userid, domainname, praefix, content, ttl, type, record_key, cdn_tmp) VALUES (:s, :u, :dn, :p, :c, :t, :ty, :k, :m)",
					array('s' => $sid, 'u' => $u, 'dn' => domain_name($d), 'p' => $p, 'c' => $ip, 't' => C64O_TTL, 'ty' => $type, 'k' => token32(), 'm' => C64O_CDN_TMP));
				q("INSERT INTO cdn64o_records (host_id, record_id, role) VALUES (:h, :r, 'edge')", array('h' => $h['id'], 'r' => $GLOBALS['pdo']->lastInsertId()));
			}
		} else {
			foreach(qa("SELECT r.record_id FROM cdn64o_records r JOIN subdomain_records s ON s.id = r.record_id
				WHERE r.host_id = :h AND r.role = 'edge' AND s.cdn_tmp = :m AND s.content IN ($in)", array('h' => $h['id'], 'm' => C64O_CDN_TMP)) as $r) {
				q("DELETE FROM subdomain_records WHERE id = :i AND cdn_tmp = :m", array('i' => $r['record_id'], 'm' => C64O_CDN_TMP));
				q("DELETE FROM cdn64o_records WHERE host_id = :h AND record_id = :r", array('h' => $h['id'], 'r' => $r['record_id']));
			}
		}
		foreach(array('A', 'AAAA') as $t) { quiet(fn() => do_zone_update($GLOBALS['pdo'], $u, $sid, $t, (string)C64O_TTL, $p)); }
		c64o_event((int)$h['id'], $u, $on ? 'edge_back' : 'edge_down', $e['name']);
	}
	error_log("cdn64o: edge " . $e['name'] . ($on ? " back in DNS" : " withdrawn from DNS"));
}

// ---------------------------------------------------------------- Nodes (API-Key)

route('GET', '/cdn64o', function() {
	global $CLASS;
	$u = uid();
	ok(array(
		'quota' => c64o_quota($u, $CLASS),
		'edges' => array_map('c64o_edge_out', c64o_edges()),
		'tunnels' => array_map('c64o_tunnel_out', qa("SELECT * FROM cdn64o_tunnels WHERE userid = :u ORDER BY created_at", array('u' => $u))),
		'hosts' => array_map('c64o_host_out', qa("SELECT * FROM cdn64o_hosts WHERE userid = :u ORDER BY fqdn", array('u' => $u))),
	));
});

/** POST /cdn64o/tunnels {name, node_id}: Node anmelden. Antwort mit Token (nur hier sichtbar) und Server-Liste. */
route('POST', '/cdn64o/tunnels', function() {
	global $CLASS, $pdo;
	$u = uid();
	if((int)($CLASS['cdn_domains'] ?? 0) <= 0) { fail(403, 'plan_not_allowed', 'CDN64 online is not part of your plan.'); }
	if((int)q1("SELECT count(id) c FROM cdn64o_tunnels WHERE userid = :u", array('u' => $u))['c'] >= C64O_MAX_TUNNELS) { fail(403, 'limit_reached', 'Tunnel limit reached.'); }
	$name = in_str('name', false, 100, '');
	$node = in_str('node_id', false, 64, '');
	$id = 'tn_' . strtolower(substr(token32(), 0, 16));
	$tok = token32() . token32();
	q("INSERT INTO cdn64o_tunnels (id, userid, node_id, name, token_hash) VALUES (:i, :u, :n, :na, :h)", array('i' => $id, 'u' => $u, 'n' => $node, 'na' => $name, 'h' => hash('sha256', $tok)));
	add_log($pdo, $u, "0", "CDN64 online", "Tunnel $id angelegt ($name).");
	$o = c64o_tunnel_out(c64o_find_tunnel($id));
	$o['token'] = $tok;
	$o['edges'] = array_map('c64o_edge_out', c64o_edges());
	ok($o, 201);
});

/** POST /cdn64o/tunnels/{id}/token: neuen Token ausstellen (alter wird ungueltig). */
route('POST', '/cdn64o/tunnels/{id}/token', function($p) {
	$t = c64o_find_tunnel($p['id']);
	$tok = token32() . token32();
	q("UPDATE cdn64o_tunnels set token_hash = :h WHERE id = :i", array('h' => hash('sha256', $tok), 'i' => $t['id']));
	$o = c64o_tunnel_out(c64o_find_tunnel($t['id']));
	$o['token'] = $tok;
	$o['edges'] = array_map('c64o_edge_out', c64o_edges());
	ok($o);
});

route('DELETE', '/cdn64o/tunnels/{id}', function($p) {
	global $pdo;
	$t = c64o_find_tunnel($p['id']);
	foreach(qa("SELECT h.* FROM cdn64o_hosts h JOIN cdn64o_host_tunnels ht ON ht.host_id = h.id WHERE ht.tunnel_id = :t", array('t' => $t['id'])) as $h) {
		if(q1("SELECT host_id FROM cdn64o_host_tunnels WHERE host_id = :h AND tunnel_id != :t LIMIT 1", array('h' => $h['id'], 't' => $t['id'])) === null) { // letzter Tunnel: Host aus
			// wie DELETE /hosts/{id}: scheitert PowerDNS, bleiben Host und Tunnel, damit ein neuer Versuch die Server-Eintraege entfernt
			if(!c64o_dns_off($h)) { fail(502, 'dns_update_failed', 'The DNS update for ' . $h['fqdn'] . ' failed. The tunnel was not removed, try again later.'); }
			c64o_host_purge($h); // auch Portmapper und Ziel, sonst zaehlen sie weiter und belegen Ports (und die Zuordnung zum Tunnel)
		} else {
			q("DELETE FROM cdn64o_host_tunnels WHERE host_id = :h AND tunnel_id = :t", array('h' => $h['id'], 't' => $t['id']));
		}
	}
	q("DELETE FROM cdn64o_tunnels WHERE id = :i AND userid = :u", array('i' => $t['id'], 'u' => uid()));
	add_log($pdo, uid(), "0", "CDN64 online", "Tunnel " . $t['id'] . " entfernt.");
	no_content();
});

/** POST /cdn64o/hosts {fqdn, mode, tunnel_id}: Namen einschalten (Kontingent, Besitz, Konflikte, DNS). */
route('POST', '/cdn64o/hosts', function() {
	global $CLASS, $pdo;
	$u = uid();
	$fqdn = strtolower(rtrim(in_str('fqdn', true, 253), '.'));
	if(!preg_match('/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/', $fqdn)) { fail(422, 'invalid_field', "Field 'fqdn' is not a valid name.", array('field' => 'fqdn')); }
	$mode = in_int('mode', false, 1, 3, 1);
	if(!in_array($mode, C64O_MODES, true)) { fail(422, 'mode_not_available', "Mode $mode is not available yet.", array('field' => 'mode')); }
	$t = null; $target = null;
	if($mode === 3) {
		$target = c64o_target_in();
	} else {
		$t = c64o_find_tunnel(in_str('tunnel_id', true, 24));
		if($t['status'] !== 'active') { fail(409, 'tunnel_blocked', 'This tunnel is blocked.'); }
	}
	$q = c64o_quota($u, $CLASS);
	if($q['domains']['used'] >= $q['domains']['limit']) { fail(403, 'limit_reached', 'CDN domain limit of your plan is reached (old and new CDN together).'); }
	if(c64o_over_traffic($q)) { fail(403, 'traffic_limit_reached', 'Your monthly CDN traffic is used up.'); }
	[$d, $p] = c64o_domain_for($fqdn);
	if(q1("SELECT id FROM cdn64o_hosts WHERE fqdn = :f", array('f' => $fqdn)) !== null) { fail(409, 'cdn64o_exists', 'This name is already in CDN64 online.'); }
	if(q1("SELECT id FROM cdn_domains WHERE domainid = :d", array('d' => $d['id'])) !== null) { fail(409, 'old_cdn_active', 'This domain is in the old CDN. Remove it there first.'); }
	if(q1("SELECT id FROM subdomain_records WHERE subdomain_id = :s AND praefix = :p AND type = 'CNAME' AND deactivated = 0", array('s' => $d['id'], 'p' => $p)) !== null) { fail(409, 'cname_exists', 'The name has a CNAME record. Remove it first.'); }
	if(q1("SELECT id FROM subdomain_records WHERE subdomain_id = :s AND praefix = :p AND (failover = 1 OR (failover_policy != '0' AND deactivated = 1)) LIMIT 1", array('s' => $d['id'], 'p' => $p)) !== null) { fail(409, 'failover_active', 'DNS failover is active for this name.'); }
	if($mode === 3 AND $target['source'] === 'records') { // Ziel = die bisherigen Eintraege des Namens: es muss einen oeffentlichen geben
		$ok = false;
		foreach(qa("SELECT content FROM subdomain_records WHERE subdomain_id = :s AND praefix = :p AND type IN ('A','AAAA') AND deactivated = 0 AND cdn_tmp = 0", array('s' => $d['id'], 'p' => $p)) as $r) {
			if(c64o_public_ip($r['content'])) { $ok = true; }
		}
		if(!$ok) { fail(422, 'no_target_records', 'The name has no public A/AAAA record to use as target. Set a fixed target instead.', array('field' => 'source')); }
	}
	q("INSERT INTO cdn64o_hosts (userid, fqdn, subdomain_id, praefix, wildcard, mode, status, created_via) VALUES (:u, :f, :s, :p, :w, :m, 'pending', :v)",
		array('u' => $u, 'f' => $fqdn, 's' => $d['id'], 'p' => $p, 'w' => (int)$d['wildcard'], 'm' => $mode, 'v' => in_str('via', false, 8, 'node') === 'web' ? 'web' : 'node'));
	$h = q1("SELECT * FROM cdn64o_hosts WHERE fqdn = :f", array('f' => $fqdn));
	if($t !== null) { q("INSERT INTO cdn64o_host_tunnels (host_id, tunnel_id) VALUES (:h, :t)", array('h' => $h['id'], 't' => $t['id'])); }
	if($target !== null) { c64o_target_save((int)$h['id'], $target); }
	if(!c64o_dns_on($h, $d)) {
		// auch das Zuruecknehmen gescheitert: Host bleibt (pending), DELETE /hosts/{id} holt das DNS spaeter nach
		if(!c64o_dns_off($h)) { fail(502, 'dns_update_failed', 'The DNS update failed and could not be rolled back. Remove the name (DELETE /cdn64o/hosts/' . $h['id'] . ') later to clean up.'); }
		q("DELETE FROM cdn64o_host_tunnels WHERE host_id = :h", array('h' => $h['id']));
		q("DELETE FROM cdn64o_targets WHERE host_id = :h", array('h' => $h['id']));
		q("DELETE FROM cdn64o_hosts WHERE id = :h", array('h' => $h['id']));
		fail(502, 'dns_update_failed', 'The DNS update failed. Nothing was changed, try again later.');
	}
	q("UPDATE cdn64o_hosts set status = 'active' WHERE id = :h", array('h' => $h['id']));
	c64o_event((int)$h['id'], $u, 'enabled', "mode $mode" . ($t !== null ? ", tunnel " . $t['id'] : ", target " . ($target['target'] ?: 'records')));
	add_log($pdo, $u, $d['id'], "CDN64 online", "CDN64 online fuer $fqdn eingeschaltet.");
	ok(c64o_host_out(c64o_find_host((string)$h['id'])), 201);
});

route('GET', '/cdn64o/hosts/{id}', function($p) { ok(c64o_host_out(c64o_find_host($p['id']))); });

/** GET /cdn64o/stats?days=30: Zahlen der Server je Name und Tag (Traffic, Verbindungen, Anfragen, Abweisungen). */
route('GET', '/cdn64o/stats', function() {
	$days = qp_int('days', 30, 1, 400);
	ok(array_map(fn($r) => array('host_id' => (int)$r['host_id'], 'fqdn' => $r['fqdn'], 'day' => $r['day'], 'bytes_in' => (int)$r['bytes_in'],
			'bytes_out' => (int)$r['bytes_out'], 'conns' => (int)$r['conns'], 'requests' => (int)$r['requests'], 'rejected' => (int)$r['rejected']),
		qa("SELECT t.*, h.fqdn FROM cdn64o_traffic t JOIN cdn64o_hosts h ON h.id = t.host_id WHERE t.userid = :u AND t.day >= :d ORDER BY t.day, h.fqdn",
			array('u' => uid(), 'd' => date('Y-m-d', strtotime('-' . ($days - 1) . ' days'))))));
});

/** GET /cdn64o/protection?days=1|7|30 (1 = heute): Schutz-Statistik des Accounts – Summen, je Tag, je Name, top 10 JA4. */
route('GET', '/cdn64o/protection', function() {
	$v = qp('days', '30');
	if(!in_array($v, array('1', '7', '30'), true)) { fail(422, 'invalid_parameter', "Query parameter 'days' must be 1, 7 or 30."); }
	$days = (int)$v; $u = uid(); $from = c64o_since($days);
	$daily = array();
	for($i = $days - 1; $i >= 0; $i--) { $d = date('Y-m-d', strtotime("-$i days")); $daily[$d] = array_merge(array('day' => $d), c64o_prot_out(null)); }
	foreach(qa("SELECT day, " . c64o_prot_sum() . " FROM cdn64o_traffic WHERE userid = :u AND day >= :d GROUP BY day", array('u' => $u, 'd' => $from)) as $r) {
		if(isset($daily[$r['day']])) { $daily[$r['day']] = array_merge(array('day' => $r['day']), c64o_prot_out($r)); }
	}
	$sum = array();
	foreach(qa("SELECT host_id, " . c64o_prot_sum() . " FROM cdn64o_traffic WHERE userid = :u AND day >= :d GROUP BY host_id", array('u' => $u, 'd' => $from)) as $r) { $sum[(int)$r['host_id']] = $r; }
	ok(array(
		'days' => $days,
		'ja4_global' => C64O_JA4_GLOBAL,
		'totals' => c64o_prot_out(q1("SELECT " . c64o_prot_sum() . " FROM cdn64o_traffic WHERE userid = :u AND day >= :d", array('u' => $u, 'd' => $from))),
		'daily' => array_values($daily),
		'hosts' => array_map(fn($h) => array_merge(array('id' => (int)$h['id'], 'fqdn' => $h['fqdn'], 'mode' => (int)$h['mode']), c64o_prot_out($sum[(int)$h['id']] ?? null)),
			qa("SELECT id, fqdn, mode FROM cdn64o_hosts WHERE userid = :u ORDER BY fqdn", array('u' => $u))),
		'ja4_top' => array_map(fn($r) => array('ja4' => $r['ja4'], 'hits' => (int)$r['hits']),
			qa("SELECT ja4, SUM(hits) hits FROM cdn64o_ja4 WHERE userid = :u AND day >= :d GROUP BY ja4 ORDER BY hits DESC, ja4 LIMIT 10", array('u' => $u, 'd' => $from))),
	));
});

/** PUT /cdn64o/hosts/{id}/target {source, target, port, scheme, verify_tls, prefer_ipv6, frontend, cache_mb, cache_minutes}: nur Modus 3. */
route('PUT', '/cdn64o/hosts/{id}/target', function($p) {
	$h = c64o_find_host($p['id']);
	if((int)$h['mode'] !== 3) { fail(409, 'not_mode_3', 'Only names in mode 3 have a target.'); }
	$old = c64o_target_row((int)$h['id']);
	$t = c64o_target_in($old);
	if($t['source'] === 'records' AND empty(c64o_target_records((int)$h['id']))) { fail(422, 'no_target_records', 'The name has no public A/AAAA record to use as target. Set a fixed target instead.', array('field' => 'source')); }
	c64o_target_save((int)$h['id'], $t);
	c64o_event((int)$h['id'], uid(), 'target', $t['scheme'] . '://' . ($t['target'] ?: 'records') . ':' . $t['port']);
	ok(c64o_host_out(c64o_find_host((string)$h['id'])));
});

/** GET|PUT /cdn64o/hosts/{id}/acl {default: off|allow|deny, list: [IP oder Netz]} (alle Modi; Modus 1 nur nach IP). */
route('GET', '/cdn64o/hosts/{id}/acl', function($p) { ok(c64o_acl_out(c64o_find_host($p['id']))); });
route('PUT', '/cdn64o/hosts/{id}/acl', function($p) {
	$h = c64o_find_host($p['id']);
	$def = in_str('default', true, 5);
	if(!in_array($def, array('off', 'allow', 'deny'), true)) { fail(422, 'invalid_field', "Field 'default' must be off, allow or deny.", array('field' => 'default')); }
	$list = in_list('list') ?? array();
	if(count($list) > C64O_ACL_MAX) { fail(422, 'acl_too_long', 'At most ' . C64O_ACL_MAX . ' entries.', array('field' => 'list')); }
	$clean = array();
	foreach($list as $v) {
		if(($c = c64o_cidr((string)$v)) === null) { fail(422, 'invalid_field', "Entry '$v' is not an IP address or network.", array('field' => 'list')); }
		$clean[$c] = true;
	}
	q("UPDATE cdn64o_hosts set acl_default = :d WHERE id = :h", array('d' => $def === 'off' ? '' : $def, 'h' => $h['id']));
	q("DELETE FROM cdn64o_acl WHERE host_id = :h", array('h' => $h['id']));
	foreach(array_keys($clean) as $c) { q("INSERT INTO cdn64o_acl (host_id, cidr) VALUES (:h, :c)", array('h' => $h['id'], 'c' => $c)); }
	c64o_event((int)$h['id'], uid(), 'acl', $def . ', ' . count($clean) . ' entries');
	ok(c64o_acl_out(c64o_find_host((string)$h['id'])));
});

/** GET|POST /cdn64o/hosts/{id}/mappings {name, transport: tcp|udp, target_port, listen_port?}: Portmapper (alle Modi;
 * Modus 1/2: target_port = Port des Streams in der Node, die Server reichen durch den Tunnel). */
route('GET', '/cdn64o/hosts/{id}/mappings', function($p) { ok(c64o_mappings_out((int)c64o_find_host($p['id'])['id'])); });
route('POST', '/cdn64o/hosts/{id}/mappings', function($p) {
	global $CLASS;
	$h = c64o_find_host($p['id']);
	$tr = in_str('transport', false, 3, 'tcp');
	if(!in_array($tr, array('tcp', 'udp'), true)) { fail(422, 'invalid_field', "Field 'transport' must be tcp or udp.", array('field' => 'transport')); }
	$tp = in_int('target_port', true, 1, 65535);
	$wish = in_int('listen_port', false, C64O_PORT_MIN, C64O_PORT_MAX);
	$name = mb_substr(strip_tags(in_str('name', false, 64, '')), 0, 64);
	$q = c64o_quota(uid(), $CLASS);
	if($q['mappings']['used'] >= $q['mappings']['limit']) { fail(403, 'limit_reached', 'Port mapping limit of your plan is reached (old and new CDN together).'); }
	if(q1("SELECT id FROM cdn64o_mappings WHERE host_id = :h AND transport = :t AND target_port = :p", array('h' => $h['id'], 't' => $tr, 'p' => $tp)) !== null) {
		fail(409, 'mapping_exists', 'This port is already mapped for this name.', array('field' => 'target_port'));
	}
	$lp = c64o_mapping_port((int)$h['id'], $tr, $tp, $wish);
	if($lp === null) { fail(409, 'port_in_use', $wish !== null ? "Port $wish is already in use." : 'No free port left.', array('field' => 'listen_port')); }
	if(q("INSERT IGNORE INTO cdn64o_mappings (host_id, userid, name, listen_port, transport, target_port) VALUES (:h, :u, :n, :l, :t, :p)",
		array('h' => $h['id'], 'u' => uid(), 'n' => $name, 'l' => $lp, 't' => $tr, 'p' => $tp))->rowCount() !== 1) {
		fail(409, 'port_in_use', "Port $lp was just taken, try again.", array('field' => 'listen_port'));
	}
	c64o_event((int)$h['id'], uid(), 'mapping', "$tr $lp -> $tp" . ($name !== '' ? " ($name)" : ''));
	ok(c64o_mappings_out((int)$h['id']), 201);
});
route('DELETE', '/cdn64o/hosts/{id}/mappings/{mid}', function($p) {
	$h = c64o_find_host($p['id']);
	$m = q1("SELECT * FROM cdn64o_mappings WHERE id = :m AND host_id = :h", array('m' => (int)$p['mid'], 'h' => $h['id']));
	if($m === null) { fail(404, 'not_found', 'Port mapping not found.'); }
	q("DELETE FROM cdn64o_mappings WHERE id = :m", array('m' => $m['id']));
	c64o_event((int)$h['id'], uid(), 'mapping', 'removed ' . $m['transport'] . ' ' . $m['listen_port']);
	no_content();
});

route('GET', '/cdn64o/hosts/{id}/events', function($p) {
	$h = c64o_find_host($p['id']);
	ok(array_map(fn($e) => array('time' => iso($e['time']), 'kind' => $e['kind'], 'message' => $e['message']),
		qa("SELECT * FROM cdn64o_events WHERE host_id = :h ORDER BY id DESC LIMIT 100", array('h' => $h['id']))));
});

/** PATCH /cdn64o/hosts/{id} {mode, tunnels: [ids], paused, waf, ja4}. paused: die Server nehmen fuer den Namen nichts mehr an und
 * trennen offene Verbindungen; DNS bleibt auf den Servern (die eigene Adresse bleibt verborgen), Einstellungen und
 * Statistik bleiben. waf: Muster-WAF (Modus 2/3), ja4: off|count|block (alle Modi, verrechnet mit C64O_JA4_GLOBAL). */
route('PATCH', '/cdn64o/hosts/{id}', function($p) {
	global $pdo;
	$h = c64o_find_host($p['id']);
	$changed = false;
	if(($m = in_int('mode', false, 1, 3)) !== null) {
		$changed = true;
		if(!in_array($m, C64O_MODES, true)) { fail(422, 'mode_not_available', "Mode $m is not available yet.", array('field' => 'mode')); }
		if(($m === 3) !== ((int)$h['mode'] === 3)) { fail(422, 'mode_change_not_possible', 'Mode 3 (direct) and modes 1/2 (tunnel) cannot be switched; switch the name off and on again.', array('field' => 'mode')); }
		q("UPDATE cdn64o_hosts set mode = :m WHERE id = :h", array('m' => $m, 'h' => $h['id']));
	}
	if(($list = in_list('tunnels')) !== null) {
		$changed = true;
		if(empty($list)) { fail(422, 'invalid_field', "Field 'tunnels' must not be empty.", array('field' => 'tunnels')); }
		$ids = array();
		foreach($list as $tid) { $ids[] = c64o_find_tunnel((string)$tid)['id']; }
		q("DELETE FROM cdn64o_host_tunnels WHERE host_id = :h", array('h' => $h['id']));
		foreach(array_values(array_unique($ids)) as $i => $tid) { q("INSERT INTO cdn64o_host_tunnels (host_id, tunnel_id, priority) VALUES (:h, :t, :p)", array('h' => $h['id'], 't' => $tid, 'p' => $i)); }
	}
	if($changed) { c64o_event((int)$h['id'], uid(), 'changed'); }
	$waf = in_bool('waf'); $ja4 = in_str('ja4', false, 5);
	if($ja4 !== null AND !in_array($ja4, array('off', 'count', 'block'), true)) { fail(422, 'invalid_field', "Field 'ja4' must be off, count or block.", array('field' => 'ja4')); }
	if($waf !== null OR $ja4 !== null) {
		$waf = $waf ?? (int)$h['waf'] === 1; $ja4 = $ja4 ?? $h['ja4'];
		q("UPDATE cdn64o_hosts set waf = :w, ja4 = :j WHERE id = :h", array('w' => $waf ? 1 : 0, 'j' => $ja4, 'h' => $h['id']));
		c64o_event((int)$h['id'], uid(), 'waf', 'waf ' . ($waf ? 'on' : 'off') . ', ja4 ' . $ja4);
	}
	if(($v = in_bool('paused')) !== null AND $v !== ((int)$h['paused'] === 1)) {
		q("UPDATE cdn64o_hosts set paused = :p, paused_at = " . ($v ? "NOW()" : "NULL") . " WHERE id = :h", array('p' => $v ? 1 : 0, 'h' => $h['id']));
		c64o_event((int)$h['id'], uid(), $v ? 'paused' : 'resumed');
		add_log($pdo, uid(), $h['subdomain_id'], "CDN64 online", "CDN64 online fuer " . $h['fqdn'] . ($v ? " pausiert." : " fortgesetzt."));
	}
	ok(c64o_host_out(c64o_find_host((string)$h['id'])));
});

/** DELETE /cdn64o/hosts/{id}: ausschalten, DNS zurueck. */
route('DELETE', '/cdn64o/hosts/{id}', function($p) {
	global $pdo;
	$h = c64o_find_host($p['id']);
	if(!c64o_dns_off($h)) { fail(502, 'dns_update_failed', 'The DNS update failed. Try again later.'); }
	c64o_host_purge($h);
	c64o_event((int)$h['id'], uid(), 'disabled');
	add_log($pdo, uid(), $h['subdomain_id'], "CDN64 online", "CDN64 online fuer " . $h['fqdn'] . " ausgeschaltet.");
	no_content();
});

// ---------------------------------------------------------------- Server (srv07/srv08, Server-Geheimnis)

function c64o_edge_auth(): array {
	$tok = bearer();
	$fail = function() {
		rl_enforce('fail:' . client_ip(), RL_FAIL_CAPACITY, RL_FAIL_REFILL, 'failed authentication');
		fail(401, 'invalid_token', 'Unknown edge.');
	};
	if($tok === null OR strlen($tok) < 32) { $fail(); }
	$h = hash('sha256', $tok);
	foreach(c64o_edges(true) as $e) {
		if(hash_equals((string)$e['secret_hash'], $h)) {
			if((int)$e['disabled'] === 1) { fail(403, 'edge_disabled', 'This edge is disabled.'); }
			return $e;
		}
	}
	$fail();
	return array();
}

/** GET /cdn64o/edge/config: alles, was die Server brauchen (ETag; unveraendert = 304). */
route('GET', '/cdn64o/edge/config', function() {
	$self = c64o_edge_auth();
	$steady = $self['last_seen'] !== null && strtotime($self['last_seen']) >= time() - C64O_EDGE_STALE; // selbst ohne Pause da?
	q("UPDATE cdn64o_edges set last_seen = NOW() WHERE id = :i", array('i' => $self['id'])); // Lebenszeichen alle 10 s (G6)
	if($steady) { c64o_edge_watch(); }
	$tunnels = array();
	$cls = array(); // Klasse je Account (parallele Verbindungen)
	foreach(qa("SELECT id, userid, token_hash, status FROM cdn64o_tunnels ORDER BY id") as $t) {
		$u = (int)$t['userid'];
		if(!isset($cls[$u])) { $cls[$u] = q1("SELECT c.* FROM users u JOIN user_class c ON c.id = u.user_class WHERE u.id = :u", array('u' => $u)) ?? array(); }
		$tunnels[] = array('id' => $t['id'], 'token_sha256' => $t['token_hash'], 'userid' => $u, 'blocked' => $t['status'] !== 'active', 'sessions' => c64o_sessions($cls[$u]));
	}
	$ht = array();
	foreach(qa("SELECT host_id, tunnel_id FROM cdn64o_host_tunnels ORDER BY host_id, priority, tunnel_id") as $r) { $ht[(int)$r['host_id']][] = $r['tunnel_id']; }
	$hosts = array(); $users = array();
	$acl = array(); $maps = array();
	foreach(qa("SELECT host_id, cidr FROM cdn64o_acl ORDER BY id") as $r) { $acl[(int)$r['host_id']][] = $r['cidr']; }
	foreach(qa("SELECT host_id, listen_port, transport, target_port FROM cdn64o_mappings ORDER BY transport, listen_port") as $r) {
		$maps[(int)$r['host_id']][] = array('listen_port' => (int)$r['listen_port'], 'transport' => $r['transport'], 'target_port' => (int)$r['target_port']);
	}
	foreach(qa("SELECT id, userid, fqdn, wildcard, mode, status, blocked_reason, paused, acl_default, waf, ja4 FROM cdn64o_hosts WHERE status IN ('active', 'blocked') ORDER BY fqdn") as $h) {
		$x = array('id' => (int)$h['id'], 'name' => $h['fqdn'], 'wildcard' => (int)$h['wildcard'] === 1, 'mode' => (int)$h['mode'], 'userid' => (int)$h['userid'],
			'tunnels' => $ht[(int)$h['id']] ?? array(),
			'blocked' => (int)$h['paused'] === 1 ? 'paused' : ($h['status'] === 'blocked' ? ($h['blocked_reason'] ?: 'blocked') : '')); // Pause: Server sperren, DNS bleibt
		if((int)$h['mode'] === 3) { $x['target'] = c64o_target_edge((int)$h['id']); }
		if(isset($maps[(int)$h['id']])) { $x['mappings'] = $maps[(int)$h['id']]; } // Modus 1/2: durch den Tunnel
		if($h['acl_default'] !== '') { $x['acl'] = array('default' => $h['acl_default'], 'list' => $acl[(int)$h['id']] ?? array()); }
		$x['waf'] = (int)$h['waf'] === 1; // Muster-WAF (Modus 2/3)
		$x['ja4'] = c64o_ja4_eff((string)$h['ja4']); // wirksam: mit dem globalen Start-Schalter verrechnet
		$hosts[] = $x;
		$users[(int)$h['userid']] = true;
	}
	$bw = array();
	foreach(array_keys($users) as $u) {
		$c = q1("SELECT c.cdn_bandwidth FROM users u JOIN user_class c ON c.id = u.user_class WHERE u.id = :u", array('u' => $u));
		$bw[(string)$u] = (int)($c['cdn_bandwidth'] ?? 0);
	}
	$cfg = array('edges' => array_map('c64o_edge_out', c64o_edges()), 'tunnels' => $tunnels, 'hosts' => $hosts, 'bandwidth_mbit' => (object)$bw);
	$etag = '"' . sha1(json_encode($cfg)) . '"';
	header('ETag: ' . $etag);
	header('Cache-Control: no-store');
	if(trim($_SERVER['HTTP_IF_NONE_MATCH'] ?? '') === $etag) { // unveraendert: 304 ohne Inhalt
		while(ob_get_level() > 0) { ob_end_clean(); }
		http_response_code(304);
		exit;
	}
	$cfg['version'] = trim($etag, '"');
	ok($cfg);
}, true);

/**
 * POST /cdn64o/edge/report: {version, tunnels: [{id, node, node_version, transport, since}],
 * traffic: [{host_id, bytes_in, bytes_out, conns, requests, rejected, blocked_list, blocked_acl, blocked_flood, blocked_waf,
 * blocked_ja4, ja4_hits, blocked_ips, conns_v4, ja4_top: [{ja4, hits}]}]} – Zaehler seit der letzten Meldung (fehlt = 0). Danach
 * wird das Traffic-Kontingent der betroffenen Accounts geprueft (hartes Limit: Hosts auf blocked, neuer Monat: wieder frei).
 */
route('POST', '/cdn64o/edge/report', function() {
	$e = c64o_edge_auth();
	$b = body();
	q("UPDATE cdn64o_edges set last_seen = NOW(), version = :v WHERE id = :i", array('v' => mb_substr((string)($b['version'] ?? ''), 0, 32), 'i' => $e['id']));
	foreach((array)($b['tunnels'] ?? array()) as $t) {
		if(!is_array($t) OR !isset($t['id'])) { continue; }
		q("UPDATE cdn64o_tunnels set last_seen = NOW(), last_edge = :e, node_version = :v WHERE id = :i",
			array('e' => $e['name'], 'v' => mb_substr((string)($t['node_version'] ?? ''), 0, 32), 'i' => (string)$t['id']));
	}
	$users = array();
	$day = date('Y-m-d');
	foreach((array)($b['traffic'] ?? array()) as $t) {
		if(!is_array($t) OR !isset($t['host_id'])) { continue; }
		$h = q1("SELECT id, userid FROM cdn64o_hosts WHERE id = :i", array('i' => (int)$t['host_id']));
		if($h === null) { continue; }
		$in = max(0, (int)($t['bytes_in'] ?? 0)); $out = max(0, (int)($t['bytes_out'] ?? 0));
		$conns = max(0, (int)($t['conns'] ?? 0)); $rej = max(0, (int)($t['rejected'] ?? 0)); $req = max(0, (int)($t['requests'] ?? 0));
		$prot = array();
		foreach(C64O_PROT_COLS as $k) { $prot[$k] = max(0, (int)($t[$k] ?? 0)); } // Schutz-Zaehler (alte Server melden sie nicht)
		q("INSERT INTO cdn64o_traffic (host_id, userid, day, bytes_in, bytes_out, conns, requests, rejected, " . implode(', ', C64O_PROT_COLS) . ")
			VALUES (:h, :u, :d, :i, :o, :c, :q, :r, :" . implode(', :', C64O_PROT_COLS) . ")
			ON DUPLICATE KEY UPDATE bytes_in = bytes_in + VALUES(bytes_in), bytes_out = bytes_out + VALUES(bytes_out), conns = conns + VALUES(conns),
			requests = requests + VALUES(requests), rejected = rejected + VALUES(rejected), " . implode(', ', array_map(fn($k) => "$k = $k + VALUES($k)", C64O_PROT_COLS)),
			array_merge(array('h' => $h['id'], 'u' => $h['userid'], 'd' => $day, 'i' => $in, 'o' => $out, 'c' => $conns, 'q' => $req, 'r' => $rej), $prot));
		// JA4-Treffer: hoechstens C64O_JA4_DAY_MAX verschiedene je Host und Tag, weitere verworfen
		$top = is_array($t['ja4_top'] ?? null) ? array_slice($t['ja4_top'], 0, C64O_JA4_DAY_MAX) : array();
		if($top) {
			$have = array_flip(array_column(qa("SELECT ja4 FROM cdn64o_ja4 WHERE host_id = :h AND day = :d", array('h' => $h['id'], 'd' => $day)), 'ja4'));
			foreach($top as $j) {
				if(!is_array($j) OR !is_string($j['ja4'] ?? null) OR !preg_match('/^[a-z0-9_]{1,64}$/', $j['ja4'])) { continue; }
				$hits = max(0, (int)($j['hits'] ?? 0));
				if($hits === 0 OR (!isset($have[$j['ja4']]) AND count($have) >= C64O_JA4_DAY_MAX)) { continue; }
				q("INSERT INTO cdn64o_ja4 (host_id, userid, day, ja4, hits) VALUES (:h, :u, :d, :j, :n) ON DUPLICATE KEY UPDATE hits = hits + VALUES(hits)",
					array('h' => $h['id'], 'u' => $h['userid'], 'd' => $day, 'j' => $j['ja4'], 'n' => $hits));
				$have[$j['ja4']] = true;
			}
		}
		$users[(int)$h['userid']] = true;
	}
	// Namen, deren Domain es nicht mehr gibt (Domain oder Account auf ipv64.net geloescht): austragen, damit die Server sie
	// nicht weiter bedienen; Tunnel geloeschter Accounts ebenso
	foreach(qa("SELECT h.* FROM cdn64o_hosts h LEFT JOIN subdomains s ON s.id = h.subdomain_id AND s.userid = h.userid WHERE s.id IS NULL") as $h) {
		q("DELETE FROM cdn64o_records WHERE host_id = :h", array('h' => $h['id']));
		c64o_host_purge($h);
		c64o_event((int)$h['id'], (int)$h['userid'], 'disabled', 'domain deleted');
	}
	q("DELETE t FROM cdn64o_tunnels t LEFT JOIN users u ON u.id = t.userid WHERE u.id IS NULL");
	// Kontingent: auch Accounts mit wegen Traffic gesperrten Hosts pruefen (neuer Monat, hoehere Klasse)
	foreach(qa("SELECT DISTINCT userid FROM cdn64o_hosts WHERE status = 'blocked' AND blocked_reason = 'traffic'") as $r) { $users[(int)$r['userid']] = true; }
	$changed = 0;
	foreach(array_keys($users) as $u) {
		$class = q1("SELECT c.* FROM users u JOIN user_class c ON c.id = u.user_class WHERE u.id = :u", array('u' => $u)) ?? array();
		$over = c64o_over_traffic(c64o_quota($u, $class));
		if($over) {
			foreach(qa("SELECT id FROM cdn64o_hosts WHERE userid = :u AND status = 'active'", array('u' => $u)) as $h) {
				q("UPDATE cdn64o_hosts set status = 'blocked', blocked_reason = 'traffic' WHERE id = :h", array('h' => $h['id']));
				c64o_event((int)$h['id'], $u, 'blocked', 'traffic limit reached');
				$changed++;
			}
		} else {
			foreach(qa("SELECT id FROM cdn64o_hosts WHERE userid = :u AND status = 'blocked' AND blocked_reason = 'traffic'", array('u' => $u)) as $h) {
				q("UPDATE cdn64o_hosts set status = 'active', blocked_reason = '' WHERE id = :h", array('h' => $h['id']));
				c64o_event((int)$h['id'], $u, 'unblocked', 'traffic available again');
				$changed++;
			}
		}
	}
	ok(array('changed' => $changed));
}, true);

/**
 * POST /cdn64o/edge/acme-txt {fqdn, value, delete}: TXT fuer DNS-01 setzen bzw. loeschen. Nur fuer
 * _acme-challenge.<Name eines Modus-2-Hosts>; der Eintrag liegt im Account des Hosts (add_record/del_record_name wie
 * fuer ACME-Clients der API). Auf den Servern liegt dafuer kein PowerDNS- und kein API-Key eines Nutzers.
 */
route('POST', '/cdn64o/edge/acme-txt', function() {
	global $pdo;
	$e = c64o_edge_auth();
	$fqdn = strtolower(rtrim(in_str('fqdn', true, 253), '.'));
	$val = in_str('value', true, 255);
	if(!preg_match('/^[A-Za-z0-9_-]{20,128}$/', $val)) { fail(422, 'invalid_field', "Field 'value' is not a DNS-01 value.", array('field' => 'value')); }
	if(!str_starts_with($fqdn, '_acme-challenge.')) { fail(422, 'invalid_field', "Field 'fqdn' must start with _acme-challenge.", array('field' => 'fqdn')); }
	$h = q1("SELECT * FROM cdn64o_hosts WHERE fqdn = :f AND mode IN (2, 3)", array('f' => substr($fqdn, strlen('_acme-challenge.'))));
	if($h === null) { fail(404, 'cdn64o_host_not_found', 'No CDN64 online host in mode 2 or 3 with this name.'); }
	$d = q1("SELECT * FROM subdomains WHERE id = :i", array('i' => $h['subdomain_id']));
	if($d === null) { fail(404, 'domain_not_found', 'Domain not found.'); }
	$p = '_acme-challenge' . ($h['praefix'] !== '' ? '.' . $h['praefix'] : '');
	if(in_bool('delete', false)) {
		$r = quiet(fn() => del_record_name($pdo, (int)$h['userid'], domain_name($d), $p, 'TXT', $val));
		ok(array('deleted' => (string)$r === '1'));
	}
	$info = (string)quiet(fn() => add_record($pdo, (int)$h['userid'], (int)$d['id'], $p, 'TXT', "60", $val));
	if($info !== '1' AND $info !== '2') { fail(502, 'dns_update_failed', 'The TXT record could not be set (' . $info . ').'); }
	c64o_event((int)$h['id'], (int)$h['userid'], 'acme', 'TXT set by ' . $e['name']);
	ok(array('fqdn' => $fqdn), 201);
}, true);

/** GET /cdn64o/edge/certs?fqdn=...: abgelegtes Zertifikat (verschluesselt) eines Modus-2-Namens. */
route('GET', '/cdn64o/edge/certs', function() {
	c64o_edge_auth();
	$c = q1("SELECT * FROM cdn64o_certs WHERE fqdn = :f", array('f' => strtolower(rtrim(qp('fqdn') ?? '', '.'))));
	if($c === null) { fail(404, 'not_found', 'No certificate stored for this name.'); }
	ok(array('fqdn' => $c['fqdn'], 'blob' => $c['blob'], 'not_after' => iso($c['not_after']), 'edge' => $c['edge'], 'updated_at' => iso($c['updated_at'])));
}, true);

/** PUT /cdn64o/edge/certs {fqdn, blob, not_after}: Zertifikat ablegen (ein aelteres ersetzt nie ein neueres). */
route('PUT', '/cdn64o/edge/certs', function() {
	$e = c64o_edge_auth();
	$f = strtolower(rtrim(in_str('fqdn', true, 253), '.'));
	$blob = in_str('blob', true, 262144);
	$na = strtotime(in_str('not_after', true, 40) ?? '');
	if($na === false) { fail(422, 'invalid_field', "Field 'not_after' is not a date.", array('field' => 'not_after')); }
	if(q1("SELECT id FROM cdn64o_hosts WHERE fqdn = :f AND mode IN (2, 3)", array('f' => $f)) === null) { fail(404, 'cdn64o_host_not_found', 'No CDN64 online host in mode 2 or 3 with this name.'); }
	q("INSERT INTO cdn64o_certs (fqdn, `blob`, not_after, edge) VALUES (:f, :b, :n, :e)
		ON DUPLICATE KEY UPDATE `blob` = IF(VALUES(not_after) >= not_after, VALUES(`blob`), `blob`), edge = IF(VALUES(not_after) >= not_after, VALUES(edge), edge),
		not_after = GREATEST(not_after, VALUES(not_after))",
		array('f' => $f, 'b' => $blob, 'n' => date('Y-m-d H:i:s', $na), 'e' => $e['name']));
	no_content();
}, true);

// -------------------------------------------------------------------
//  Account-Klassen (oeffentlich, ohne Key): GET /plans fuer Node64 – Grenzen live aus user_class, damit jede
//  Aenderung dort auf alle Nodes kommt. Preise und Anzeige wie auf der Preisseite (pricing.php); 0 = unbegrenzt bei
//  Updates/Pings/SMS/Bandbreite, Business/Company bei Updates/Pings/SMS unbegrenzt (wie auf der Preisseite).
// -------------------------------------------------------------------
const PLANS_PUBLIC = array(
	1 => array('key' => 'free', 'name' => 'Free', 'price' => 0, 'upgrade' => 'https://ipv64.net/account'),
	6 => array('key' => 'supporter', 'name' => 'Home / Supporter', 'price' => 40, 'upgrade' => 'https://ipv64.net/account?account_class&type=supporter'),
	4 => array('key' => 'business', 'name' => 'Business', 'price' => 100, 'upgrade' => 'https://ipv64.net/account?account_class&type=business'),
	5 => array('key' => 'company', 'name' => 'Company', 'price' => 200, 'upgrade' => 'https://ipv64.net/account?account_class&type=company'),
);
route('GET', '/plans', function() {
	$out = array();
	foreach(PLANS_PUBLIC as $id => $p) {
		$c = q1("SELECT * FROM user_class WHERE id = :i", array('i' => $id));
		if($c === null) { continue; }
		$big = in_array($id, array(4, 5), true);
		$z = fn($v) => (int)$v > 0 ? (int)$v : null;
		$i = fn($k) => isset($c[$k]) ? (int)$c[$k] : null;
		$l = array(
			'dyndns_domains' => $i('dyndns_limit'), 'own_domains' => $i('owndomain_limit'),
			'dyndns_updates_24h' => $big ? null : $z($c['dyndns_update_limit'] ?? 0), 'dyndns_ttl_s' => $i('ttl'),
			'healthchecks' => $i('healthcheck_limit'), 'healthcheck_pings_24h' => $big ? null : $z($c['healthcheck_update_limit'] ?? 0),
			'sms_24h' => $big ? null : $z($c['sms_limit'] ?? 0),
			'failover_policies' => $i('failover_policies'), 'failover_monitors' => $i('failover_monitors'), 'failover_rules' => $i('failover_rules'),
			'offline_pages' => $i('offline_pages'),
			'cdn_domains' => $i('cdn_domains'), 'cdn_traffic_gb' => $i('cdn_traffic'), 'cdn_bandwidth_mbit' => $z($c['cdn_bandwidth'] ?? 0), 'cdn_mappings' => $i('cdn_mappings'),
			'cdn_tunnel_sessions' => isset($c['cdn_tunnel_sessions']) ? c64o_sessions($c) : null,
			'cloud_routers' => $i('cloud_router'), 'vpn_gateways' => $i('vpn_gateways'), 'vpn_peers' => $i('vpn_peers'), 'vpn_traffic_gb' => $i('vpn_traffic'),
			'dns64_clients' => $i('dns64_clients'),
		);
		if(isset($c['log_days'])) { $l['log_days'] = (int)$c['log_days']; } // fehlt eine Spalte, nimmt Node64 den eingebauten Wert
		$out[] = array('id' => $id, 'key' => $p['key'], 'name' => $p['name'], 'class_name' => $c['name'], 'price_year_eur' => $p['price'],
			'upgrade_url' => $p['upgrade'], 'limits' => (object)array_filter($l, fn($v, $k) => $v !== null || !in_array($k, array('dyndns_domains', 'own_domains', 'dyndns_ttl_s', 'healthchecks', 'failover_policies', 'failover_monitors', 'failover_rules', 'offline_pages', 'cdn_domains', 'cdn_traffic_gb', 'cdn_mappings', 'cdn_tunnel_sessions', 'cloud_routers', 'vpn_gateways', 'vpn_peers', 'vpn_traffic_gb', 'dns64_clients'), true), ARRAY_FILTER_USE_BOTH));
	}
	header('Cache-Control: public, max-age=600');
	ok($out);
}, true);
