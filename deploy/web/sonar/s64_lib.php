<?php
/**
 * Sonar64: gemeinsame Funktionen fuer API (api_v2_sonar.php), Jobs (bots/sonar_*.php) und Seiten (sonar/*.php).
 * Vertrag: docs/SONAR64-VERTRAG.md Abschnitt 6 im Node64-Repo. Haengt nicht von api_v2.php ab.
 *
 *   s64_pdo()                         PDO wie die anderen Bots (dbconnect.php im Webroot)
 *   s64_pub_coords($lat, $lon, $seed) verschleierter Standort, fester Versatz <= 1 km je Knoten
 *   s64_distance_km(...)              Grosskreis-Entfernung
 *   s64_light_min_ms($km)             kleinste moegliche Antwortzeit (Licht in der Faser, 2 * km / 200)
 *   s64_asn_lookup($ip)               ASN + Name ueber Team-Cymru-DNS (Fehler: asn = null)
 *   s64_is_public_ip($ip)             oeffentliche Unicast-Adresse?
 *   s64_plan_sign($planJson)          Ed25519-Signatur des Plans (kid, sig)
 *   s64_trust_label($trust, $lang)    Anzeigename der Vertrauensstufe
 *   s64_leave($pdo, $tokenId, $reason) Knoten abmelden (Token widerrufen, Knoten aus; Vertrag 10.2)
 *
 * Alle Zeiten UTC: s64_dt() schreibt DATETIME(3), s64_iso() gibt ISO 8601 aus. Nie NOW() in SQL verwenden.
 */

const S64_TRUST = array('new', 'stable', 'trusted', 'pillar', 'anchor', 'quarantine');
const S64_ACCESS = array('fiber', 'dsl', 'cable', 'mobile', 'satellite', 'datacenter', 'other');
const S64_BUDGETS = array('sparsam', 'normal', 'grosszuegig');
const S64_MODES = array('module', 'headless', 'anchor');
const S64_NODE_RE = '/^(n[a-z0-9]{11}|a_[a-z0-9]{2,12})\z/';
const S64_ONLINE = 1800; // online = Kontakt in den letzten 30 Minuten
const S64_LEAVE = array('leave', 'owner', 'admin', 'inactive'); // Gruende einer Abmeldung (sonar_trust_log.reason, new = removed)

/** PDO der Hauptdatenbank (dbconnect.php im Webroot, wie die anderen Bots). In der API ist $pdo schon da. */
function s64_pdo(): PDO {
	if(isset($GLOBALS['pdo']) AND $GLOBALS['pdo'] instanceof PDO) { return $GLOBALS['pdo']; }
	require dirname(__DIR__) . '/dbconnect.php';
	if(!isset($pdo) OR !($pdo instanceof PDO)) { throw new RuntimeException('sonar: no database connection'); }
	$GLOBALS['pdo'] = $pdo;
	return $pdo;
}

/** Unix-Zeit (mit Nachkomma) -> DATETIME(3) UTC. */
function s64_dt(?float $ts = null): string {
	$ts = $ts ?? microtime(true);
	$s = (int)floor($ts);
	return gmdate('Y-m-d H:i:s', $s) . sprintf('.%03d', min(999, (int)floor(($ts - $s) * 1000)));
}

/** DB-Zeit (UTC) -> Unix-Zeit (mit Millisekunden) oder null. */
function s64_ts($s): ?float {
	if($s === null OR $s === '' OR str_starts_with((string)$s, '0000')) { return null; }
	if(!preg_match('/^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)(\.(\d{1,6}))?$/', (string)$s, $m)) { return null; }
	$t = strtotime($m[1] . ' UTC');
	return $t === false ? null : $t + (isset($m[3]) ? (float)('0.' . $m[3]) : 0.0);
}

/** DB-Zeit (UTC) -> ISO 8601 ("...Z"), auf Wunsch mit Millisekunden. */
function s64_iso($s, bool $ms = false): ?string {
	$t = s64_ts($s);
	if($t === null) { return null; }
	$i = (int)floor($t);
	return gmdate('Y-m-d\TH:i:s', $i) . ($ms ? sprintf('.%03d', min(999, (int)round(($t - $i) * 1000))) : '') . 'Z';
}

/**
 * Verschleierter Standort: fester Versatz je Knoten (aus $seed) zwischen 300 und 950 m in fester Richtung, gerundet
 * auf 4 Nachkommastellen (~11 m), damit insgesamt <= 1 km. Rueckgabe array(lat, lon) mit Schluesseln 0/1 und lat/lon.
 */
function s64_pub_coords(float $lat, float $lon, int $seed): array {
	$h = hash('sha256', 'sonar64-pub|' . $seed, true);
	$u1 = unpack('N', substr($h, 0, 4))[1] / 4294967296;
	$u2 = unpack('N', substr($h, 4, 4))[1] / 4294967296;
	$d = 300 + 650 * $u1;          // Meter
	$b = 2 * M_PI * $u2;           // Richtung
	$plat = $lat + ($d * cos($b)) / 111320;
	$c = cos(deg2rad(max(-89.0, min(89.0, $lat))));
	$plon = $lon + ($d * sin($b)) / (111320 * max($c, 0.01));
	$plat = round(max(-90.0, min(90.0, $plat)), 4);
	if($plon > 180) { $plon -= 360; } elseif($plon < -180) { $plon += 360; }
	$plon = round($plon, 4);
	return array(0 => $plat, 1 => $plon, 'lat' => $plat, 'lon' => $plon);
}

/** Grosskreis-Entfernung in km (Haversine). */
function s64_distance_km(float $lat1, float $lon1, float $lat2, float $lon2): float {
	$p1 = deg2rad($lat1); $p2 = deg2rad($lat2);
	$dp = $p2 - $p1; $dl = deg2rad($lon2 - $lon1);
	$a = sin($dp / 2) ** 2 + cos($p1) * cos($p2) * sin($dl / 2) ** 2;
	return 2 * 6371.0088 * asin(min(1.0, sqrt($a)));
}

/** Kleinste physikalisch moegliche Antwortzeit (hin und zurueck) in ms: Licht in der Faser ~200 km je ms. */
function s64_light_min_ms(float $km): float { return 2 * $km / 200; }

/** Adresse (binaer) in einem der Netze? */
function s64_in_nets(string $bin, array $nets): bool {
	foreach($nets as $cidr) {
		[$net, $len] = explode('/', $cidr);
		$n = inet_pton($net);
		if($n === false OR strlen($n) !== strlen($bin)) { continue; }
		$bytes = intdiv((int)$len, 8); $bits = (int)$len % 8;
		if(substr($bin, 0, $bytes) !== substr($n, 0, $bytes)) { continue; }
		if($bits === 0 OR ((ord($bin[$bytes]) ^ ord($n[$bytes])) & (0xff << (8 - $bits)) & 0xff) === 0) { return true; }
	}
	return false;
}

/** Oeffentliche Unicast-Adresse (kein privates, reserviertes, CGNAT-, Dokumentations-, Multicast- oder Uebergangsnetz). */
function s64_is_public_ip(string $ip): bool {
	static $v4 = array('0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
		'192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4');
	static $v6 = array('::/8', '64:ff9b::/96', '64:ff9b:1::/48', '100::/64', '2001::/23', '2001:db8::/32', '2002::/16', '3fff::/20', '5f00::/16',
		'fc00::/7', 'fe80::/10', 'fec0::/10', 'ff00::/8');
	if(strlen($ip) > 45 OR !filter_var($ip, FILTER_VALIDATE_IP)) { return false; }
	$bin = inet_pton($ip);
	if($bin === false) { return false; }
	if(strlen($bin) === 4) { return !s64_in_nets($bin, $v4); }
	return strlen($bin) === 16 && !s64_in_nets($bin, $v6) && s64_in_nets($bin, array('2000::/3'));
}

/** Kurz-ID eines Knotens (UDP-Probe): erste 4 Byte von SHA-256(NodeID), hex klein. */
function s64_short_id(string $nodeId): string { return substr(hash('sha256', $nodeId), 0, 8); }

/**
 * ASN und Name zur oeffentlichen IP ueber Team Cymru (DNS TXT origin.asn.cymru.com / origin6.asn.cymru.com, dann
 * AS<n>.asn.cymru.com). Rueckgabe array(asn, name, prefix, cc); bei Fehler oder nicht oeffentlicher IP alles null.
 * Den Cache (24 h, Spalten asn4/asn6/asn_at) haelt der Aufrufer in der Knotenzeile.
 */
function s64_asn_lookup(string $ip): array {
	$none = array('asn' => null, 'name' => null, 'prefix' => null, 'cc' => null);
	if(!s64_is_public_ip($ip)) { return $none; }
	$bin = inet_pton($ip);
	if(strlen($bin) === 4) {
		$q = implode('.', array_reverse(explode('.', inet_ntop($bin)))) . '.origin.asn.cymru.com';
	} else {
		$q = implode('.', array_reverse(str_split(bin2hex($bin)))) . '.origin6.asn.cymru.com';
	}
	$txt = s64_dns_txt($q);
	// "3320 | 91.0.0.0/10 | DE | ripencc | 2003-01-01" (bei mehreren Ursprungs-ASN der erste)
	if($txt === null OR !preg_match('/^\s*(\d{1,10})(?:\s+\d{1,10})*\s*\|\s*([0-9a-fA-F.:\/]{3,49})\s*\|\s*([A-Z]{2})?/', $txt, $m)) { return $none; }
	$asn = (int)$m[1];
	if($asn < 1 OR $asn > 4294967295) { return $none; }
	$out = array('asn' => $asn, 'name' => null, 'prefix' => $m[2], 'cc' => ($m[3] ?? '') !== '' ? $m[3] : null);
	// "3320 | DE | ripencc | 1997-08-26 | DTAG Internet service provider operations, DE"
	$txt = s64_dns_txt('AS' . $asn . '.asn.cymru.com');
	if($txt !== null) {
		$p = explode('|', $txt);
		$name = trim((string)end($p));
		$name = (string)preg_replace('/,\s*[A-Z]{2}$/', '', $name);
		$name = trim((string)preg_replace('/[^\x20-\x7E]+/', '', $name));
		if($name !== '' AND count($p) >= 5) { $out['name'] = mb_substr($name, 0, 100); }
	}
	return $out;
}

/** Erster TXT-Eintrag eines Namens oder null. */
function s64_dns_txt(string $name): ?string {
	$r = @dns_get_record($name, DNS_TXT);
	if(!is_array($r)) { return null; }
	foreach($r as $x) {
		$t = $x['txt'] ?? (isset($x['entries']) ? implode('', $x['entries']) : null);
		if(is_string($t) AND $t !== '') { return mb_substr($t, 0, 512); }
	}
	return null;
}

/** Ablage des Plan-Schluessels: <ueber dem Webroot>/private/sonar64/plan_ed25519.key (nie im Webroot). */
function s64_plan_key_file(): string { return dirname(__DIR__, 2) . '/private/sonar64/plan_ed25519.key'; }

/** Kennung eines Public Keys: erste 8 Zeichen der Base64-URL (ohne Padding). */
function s64_kid(string $pkRaw): string { return substr(rtrim(strtr(base64_encode($pkRaw), '+/', '-_'), '='), 0, 8); }

/** Geheimen Plan-Schluessel (64 Byte) laden oder null. */
function s64_plan_secret(): ?string {
	static $sk = false;
	if($sk !== false) { return $sk; }
	$sk = null;
	$f = s64_plan_key_file();
	if(is_file($f) AND is_readable($f)) {
		$raw = base64_decode(trim((string)file_get_contents($f, false, null, 0, 1024)), true);
		if($raw !== false AND strlen($raw) === SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) { $sk = $raw; }
	}
	return $sk;
}

/** Aktuelle Public Keys der Plaene: Liste array(kid, pubkey Base64 std). Leer, solange kein Schluessel erzeugt ist. */
function s64_plan_keys(): array {
	$sk = s64_plan_secret();
	if($sk === null) { return array(); }
	$pk = sodium_crypto_sign_publickey_from_secretkey($sk);
	return array(array('kid' => s64_kid($pk), 'pubkey' => base64_encode($pk)));
}

/** Plan signieren (Ed25519 ueber die exakten Bytes). Rueckgabe array(kid, sig Base64 std); ohne Schluessel Ausnahme. */
function s64_plan_sign(string $planJson): array {
	$sk = s64_plan_secret();
	if($sk === null) { throw new RuntimeException('sonar: plan key missing (php bots/sonar_keygen.php)'); }
	$pk = sodium_crypto_sign_publickey_from_secretkey($sk);
	return array('kid' => s64_kid($pk), 'sig' => base64_encode(sodium_crypto_sign_detached($planJson, $sk)));
}

/** Prepared Statement; Fehler immer als Ausnahme (auch wenn $pdo nicht im Ausnahme-Modus laeuft). */
function s64_exec(PDO $pdo, string $sql, array $p = array()): PDOStatement {
	$st = $pdo->prepare($sql);
	if($st === false OR !$st->execute($p)) {
		$ei = ($st === false ? $pdo : $st)->errorInfo();
		throw new RuntimeException('sonar: ' . ($ei[2] ?? 'database error'));
	}
	return $st;
}

/**
 * Abmelden (Vertrag 10.2), gemeinsam fuer DELETE /sonar/me, DELETE /sonar/tokens/{id}, me.php, bots/sonar_node.php
 * und bots/sonar_cleanup.php: Token widerrufen; der Knoten dieses Tokens wird deaktiviert (disabled_at), IPs weg, Plan
 * geloescht, Eintrag in sonar_trust_log (new = removed, reason = $reason). Knoten (nicht Anker) verlieren auch den genauen
 * Standort, Name und Slug werden frei ("~" + node_id passt auf kein gueltiges Namens- oder Slug-Muster). $reason beginnt
 * mit leave | owner | admin | inactive (danach optional Text, zusammen hoechstens 64 Zeichen). add_log beim Account, wenn
 * es einen gibt und add_log geladen ist (API, Seiten, Bots ueber dbconnect.php). Mehrfacher Aufruf schadet nicht.
 * Rueckgabe: node_id des jetzt deaktivierten Knotens oder null.
 */
function s64_leave(PDO $pdo, int $tokenId, string $reason, ?float $now = null): ?string {
	$why = explode(' ', $reason, 2)[0];
	if(!in_array($why, S64_LEAVE, true)) { throw new InvalidArgumentException('sonar: unknown leave reason'); }
	$reason = mb_substr($reason, 0, 64);
	$t = s64_dt($now ?? microtime(true));
	$own = !$pdo->inTransaction();
	if($own) { $pdo->beginTransaction(); }
	try {
		$tok = s64_exec($pdo, "SELECT id, userid, revoked_at FROM sonar_tokens WHERE id = ? FOR UPDATE", array($tokenId))->fetch(PDO::FETCH_ASSOC);
		$revoked = false;
		if($tok !== false AND $tok['revoked_at'] === null) { s64_exec($pdo, "UPDATE sonar_tokens SET revoked_at = ? WHERE id = ?", array($t, $tokenId)); $revoked = true; }
		$n = s64_exec($pdo, "SELECT node_id, userid, role, trust FROM sonar_nodes WHERE token_id = ? AND active = 1 FOR UPDATE", array($tokenId))->fetch(PDO::FETCH_ASSOC);
		$nid = null;
		if($n !== false) {
			$nid = (string)$n['node_id'];
			s64_exec($pdo, "UPDATE sonar_nodes SET active = 0, disabled_at = ?, ip4 = NULL, ip6 = NULL, reach4 = 'none', reach6 = 'none'"
				. ($n['role'] === 'node' ? ", lat = NULL, lon = NULL, pub_lat = NULL, pub_lon = NULL, name = CONCAT('~', node_id), slug = CONCAT('~', node_id)" : '')
				. " WHERE node_id = ?", array($t, $nid));
			s64_exec($pdo, "DELETE FROM sonar_plans WHERE node_id = ?", array($nid));
			s64_exec($pdo, "INSERT INTO sonar_trust_log (node_id, at, `old`, `new`, reason) VALUES (?, ?, ?, 'removed', ?)", array($nid, $t, $n['trust'], $reason));
		}
		if($own) { $pdo->commit(); }
	} catch(Throwable $e) {
		if($own AND $pdo->inTransaction()) { $pdo->rollBack(); }
		throw $e;
	}
	$uid = $n !== false ? (int)$n['userid'] : ($tok !== false ? (int)$tok['userid'] : 0);
	if(($revoked OR $nid !== null) AND $uid > 0 AND function_exists('add_log')) {
		$txt = trim(substr($reason, strlen($why)));
		$msg = match($why) {
			'leave' => "Sonar64-Knoten $nid hat sich abgemeldet.",
			'owner' => "Sonar64-Token $tokenId gesperrt" . ($nid !== null ? ", Knoten $nid abgemeldet." : '.'),
			'admin' => 'Sonar64-' . ($nid !== null ? "Knoten $nid" : "Token $tokenId") . ' von ipv64.net abgemeldet' . ($txt !== '' ? ' (' . htmlspecialchars($txt) . ')' : '') . '.',
			default => 'Sonar64-' . ($nid !== null ? "Knoten $nid" : "Token $tokenId") . ' nach 30 Tagen ohne Meldung abgemeldet.',
		};
		add_log($pdo, $uid, "0", "Sonar64", $msg);
	}
	return $nid;
}

/** Anzeigename einer Vertrauensstufe (de/en). */
function s64_trust_label(string $trust, string $lang = 'de'): string {
	static $l = array(
		'de' => array('new' => 'Neu', 'stable' => 'Stabil', 'trusted' => 'Vertraut', 'pillar' => 'Säule', 'anchor' => 'Anker', 'quarantine' => 'Quarantäne'),
		'en' => array('new' => 'New', 'stable' => 'Stable', 'trusted' => 'Trusted', 'pillar' => 'Pillar', 'anchor' => 'Anchor', 'quarantine' => 'Quarantine'));
	return $l[$lang === 'en' ? 'en' : 'de'][$trust] ?? $trust;
}

/** Badge-Farbe einer Vertrauensstufe (Plan Abschnitt 6). */
function s64_trust_color(string $trust): string {
	return array('new' => '#8a8f98', 'stable' => '#2f7de1', 'trusted' => '#2e9e5b', 'pillar' => '#d4a017', 'anchor' => '#8a4fd8', 'quarantine' => '#c0392b')[$trust] ?? '#8a8f98';
}

/** Gewicht in Auswertungen (Vertrag Abschnitt 7). */
function s64_trust_weight(string $trust): float {
	return array('new' => 0.2, 'stable' => 1.0, 'trusted' => 2.0, 'pillar' => 3.0, 'anchor' => 3.0)[$trust] ?? 0.0;
}

/** Median einer Zahlenliste (leer = null). */
function s64_median(array $v): ?float {
	$n = count($v);
	if($n === 0) { return null; }
	sort($v, SORT_NUMERIC);
	$h = intdiv($n, 2);
	return $n % 2 ? (float)$v[$h] : ((float)$v[$h - 1] + (float)$v[$h]) / 2;
}

/** JSON-Objekte aus dem Datei-Cache: nicht leere als Array, leere bleiben stdClass (damit {} nicht zu [] wird). */
function s64_cache_arr($v) {
	if($v instanceof stdClass) { $v = (array)$v; if($v === array()) { return new stdClass(); } }
	return is_array($v) ? array_map('s64_cache_arr', $v) : $v;
}

/**
 * Kleiner Zwischenspeicher fuer teure oeffentliche Antworten (APCu, sonst Datei im Temp-Ordner mit Sperre, damit
 * gleichzeitige Abrufe nur einmal rechnen). $fn liefert einen JSON-faehigen Wert. APCu: waehrend einer rechnet,
 * bekommen die anderen den abgelaufenen Wert (bis 5 x ttl). Gehoert der Temp-Ordner nicht uns, wird nicht gespeichert.
 */
function s64_cache(string $key, int $ttl, callable $fn) {
	$k = 'ipv64_s64_' . sha1($key);
	if(function_exists('apcu_enabled') AND apcu_enabled()) {
		$e = apcu_fetch($k);
		if(is_array($e) AND $e['t'] >= time() - $ttl) { return $e['v']; }
		if(!apcu_add("$k.lock", 1, 30) AND is_array($e)) { return $e['v']; }
		$v = $fn();
		apcu_store($k, array('t' => time(), 'v' => $v), 5 * $ttl);
		apcu_delete("$k.lock");
		return $v;
	}
	$dir = sys_get_temp_dir() . '/ipv64_s64_cache';
	if(!is_dir($dir)) { @mkdir($dir, 0700, true); }
	clearstatcache(true, $dir);
	if(!is_dir($dir) OR (fileperms($dir) & 0022) !== 0 OR (function_exists('posix_geteuid') AND fileowner($dir) !== posix_geteuid())) { return $fn(); }
	$f = "$dir/$k.json";
	$read = function() use ($f, $ttl) {
		if(!is_file($f) OR filemtime($f) < time() - $ttl) { return array(false, null); }
		$d = json_decode((string)@file_get_contents($f), false);
		return ($d instanceof stdClass && property_exists($d, 'v')) ? array(true, s64_cache_arr($d->v)) : array(false, null);
	};
	[$hit, $v] = $read();
	if($hit) { return $v; }
	$fh = @fopen("$f.lock", 'c');
	if($fh !== false) { flock($fh, LOCK_EX); [$hit, $v] = $read(); }
	if(!$hit) {
		$v = $fn();
		$tmp = "$f." . bin2hex(random_bytes(4));
		if(@file_put_contents($tmp, json_encode(array('v' => $v), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION)) !== false) { @rename($tmp, $f); } else { @unlink($tmp); }
	}
	if($fh !== false) { flock($fh, LOCK_UN); fclose($fh); }
	return $v;
}
