<?php
/**
 * IPv64.net API v2 – Sonar64 (Pfade /sonar/...), verteiltes Community-Messnetz. Eingebunden am Ende von
 * api_v2_honeypot.php (eine Zeile), keine Aenderung an api_v2.php. Vertrag (verbindlich): docs/SONAR64-VERTRAG.md im
 * Node64-Repo (Abschnitte 2, 3, 5, 6), Go-Formate internal/sonar/wire.go. Tabellen sonar_* (deploy/sql/sonar64.sql).
 *
 *   POST/GET /sonar/tokens, DELETE /sonar/tokens/{id}       API-Key des Accounts
 *   POST /sonar/register, GET/PUT/DELETE /sonar/me, GET /sonar/plan, POST /sonar/results, GET /sonar/inbound
 *                                                           Sonar-Token (Bearer), prueft diese Datei selbst
 *   GET /sonar/public/keys|map|nodes|node/{slug}|stats|top|matrix|outages   ohne Anmeldung, Cache 60 s
 *
 * Sicherheit: Token nur als SHA-256, Vergleich mit hash_equals, Ratenbegrenzung je Token und IP, Body <= 256 KiB
 * (auch entpackt), Meldungen mit Ed25519 des Knotens signiert und streng steigender seq, Plaene mit dem Schluessel von
 * ipv64 signiert. Die IP des Knotens stammt aus der Verbindung (client_ip(): REMOTE_ADDR, hinter dem internen Reverse
 * Proxy nur dessen angehaengte Adresse), nie aus Angaben des Knotens; sie wird nie oeffentlich ausgegeben. Oeffentliche
 * Antworten enthalten keine IPs, keine genauen Koordinaten und keine Account-Daten.
 */

require_once __DIR__ . '/sonar/s64_lib.php';

const S64_MAX_BODY    = 262144;  // 256 KiB, auch entpackt
const S64_MAX_TOKENS  = 10;      // Knoten-Token je Account
const S64_NEW_TOKENS  = 20;      // neue Knoten-Token je Account in 24 h (Anlegen/Loeschen im Kreis)
const S64_MAX_RESULTS = 5000;    // Ergebnisse je Meldung (die Body-Grenze greift meist frueher)
const S64_MAX_INBOUND = 500;
const S64_MAX_HOPS    = 30;
const S64_REPORT_GAP  = 50;      // hoechstens eine Meldung je Minute (Abstand >= 50 s, damit "jede Minute" mit Schwankung passt)
const S64_BUFFER      = 21600;   // Nachreichen bis 6 h
const S64_SKEW        = 300;     // Uhrzeit des Knotens darf 5 min vorgehen
const S64_ROUND       = 300;     // Runde 5 min
const S64_LIGHT_TOL   = 0.3;     // Toleranz below_light in ms
const S64_SMOOTH_N    = 12;      // too_smooth: so viele glatte Meldungen in Folge
const S64_HIST        = 2100;    // sent_hist: ausgelieferte Fassungen der Runden der letzten 35 min (und der kommenden)
const S64_REASONS_BAD = array('not_in_plan', 'too_many', 'bad_time', 'bad_values', 'below_light', 'too_smooth'); // zaehlen in plaus_bad
const S64_SUSPECT     = array('bad_values', 'below_light', 'too_smooth'); // Manipulationsverdacht: sofortige Abstufung
const S64_STORE_BAD   = array('bad_time', 'below_light', 'too_smooth');   // werden mit valid=0 gespeichert (Teil J)
const S64_ANIMALS     = array('Falke', 'Fuchs', 'Dachs', 'Luchs', 'Otter', 'Biber', 'Eule', 'Igel', 'Wolf', 'Hase', 'Kranich', 'Adler',
	'Elch', 'Marder', 'Specht', 'Storch', 'Amsel', 'Lerche', 'Robbe', 'Delfin', 'Wiesel', 'Habicht', 'Kauz', 'Uhu');

// ---------------------------------------------------------------- Hilfen

function s64_json($v): string { return json_encode($v, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_PRESERVE_ZERO_FRACTION); }

/** Antwort mit eigenen Kopfzeilen (api_send setzt immer no-store). $json null = ohne Body. */
function s64_send(int $status, ?string $json, array $headers = array()): void {
	while(ob_get_level() > 0) { ob_end_clean(); }
	http_response_code($status);
	header('Content-Type: application/json; charset=utf-8');
	header('Cache-Control: no-store');
	header('X-Content-Type-Options: nosniff');
	header('X-API-Version: ' . API_VERSION);
	foreach($headers as $h) { header($h); }
	if($json !== null AND $status !== 204 AND $status !== 304) { echo $json; }
	exit;
}

/** Oeffentliche Antwort: Cache 60 s, von ueberall abrufbar. */
function s64_public($data): void {
	s64_send(200, s64_json(array('data' => $data)), array('Cache-Control: public, max-age=60', 'Access-Control-Allow-Origin: *'));
}

/** Ratenbegrenzung der oeffentlichen Endpunkte je IP. */
function s64_public_rl(): void { rl_enforce('s64pub:' . client_ip(), 120, 2.0, 'sonar public'); }

function s64_bad(string $field, string $detail): void { fail(422, 'invalid_report', $detail, array('field' => $field)); }

function s64_is_list(array $a): bool { return $a === array() || array_keys($a) === range(0, count($a) - 1); }

/** RFC 3339 (wie Go time.Time, bis Nanosekunden) -> Unix-Zeit mit Nachkomma. */
function s64_time($v, string $field): float {
	if(!is_string($v) OR strlen($v) > 40 OR !preg_match('/^(\d{4}-\d\d-\d\d)[Tt](\d\d:\d\d:\d\d)(\.\d{1,9})?([Zz]|[+-]\d\d:\d\d)\z/', $v, $m)) { s64_bad($field, "Field '$field' must be an RFC 3339 timestamp."); }
	$d = s64_parse_dt($m);
	if($d === null OR $d->format('Y-m-d H:i:s') !== $m[1] . ' ' . $m[2]) { s64_bad($field, "Field '$field' is not a valid time."); }
	return $d->getTimestamp() + ($m[3] !== '' ? (float)('0' . $m[3]) : 0.0);
}

/** Zeit aus einem Plan (von ipv64 erzeugt) ohne Abbruch: Unix-Sekunden oder null. */
function s64_plan_time($v): ?int {
	if(!is_string($v) OR !preg_match('/^(\d{4}-\d\d-\d\d)[Tt](\d\d:\d\d:\d\d)(\.\d{1,9})?([Zz]|[+-]\d\d:\d\d)\z/', $v, $m)) { return null; }
	$d = s64_parse_dt($m);
	return $d === null ? null : $d->getTimestamp();
}

/** Datum/Uhrzeit/Zone aus den Treffern der RFC-3339-Muster; ungueltige Zone (z. B. +99:99) = null statt Ausnahme. */
function s64_parse_dt(array $m): ?DateTime {
	if(strtoupper($m[4]) !== 'Z' AND ((int)substr($m[4], 1, 2) > 14 OR (int)substr($m[4], 4, 2) > 59)) { return null; }
	try { $d = DateTime::createFromFormat('!Y-m-d H:i:s', $m[1] . ' ' . $m[2], new DateTimeZone(strtoupper($m[4]) === 'Z' ? 'UTC' : $m[4])); }
	catch(Throwable $e) { return null; }
	return $d === false ? null : $d;
}

function s64_int($v, string $field, int $min, int $max): int {
	if(!is_int($v) OR $v < $min OR $v > $max) { s64_bad($field, "Field '$field' must be an integer between $min and $max."); }
	return $v;
}

/** Zahl (int oder float), fehlt = 0 (Go omitempty). */
function s64_num($v, string $field): float {
	if($v === null) { return 0.0; }
	if((!is_int($v) AND !is_float($v)) OR abs($v) > 1e6) { s64_bad($field, "Field '$field' must be a number."); }
	return (float)$v;
}

/** Body lesen: Content-Type JSON, optional gzip, hoechstens 256 KiB (auch entpackt). Rueckgabe [rohe Bytes, Objekt]. */
function s64_body(): array {
	if(!str_contains(strtolower((string)($_SERVER['CONTENT_TYPE'] ?? '')), 'application/json')) { fail(415, 'unsupported_media_type', 'Use Content-Type application/json.'); }
	$raw = file_get_contents('php://input', false, null, 0, S64_MAX_BODY + 1);
	if($raw === false OR $raw === '') { fail(400, 'invalid_json', 'Request body is empty.'); }
	if(strlen($raw) > S64_MAX_BODY) { fail(413, 'payload_too_large', 'Request body exceeds 256 KiB.'); }
	$enc = strtolower(trim((string)($_SERVER['HTTP_CONTENT_ENCODING'] ?? '')));
	if($enc === 'gzip') {
		$z = inflate_init(ZLIB_ENCODING_GZIP);
		$out = '';
		foreach(str_split($raw, 4096) as $part) {
			$o = @inflate_add($z, $part, ZLIB_SYNC_FLUSH);
			if($o === false) { fail(400, 'invalid_gzip', 'Request body is not valid gzip.'); }
			$out .= $o;
			if(strlen($out) > S64_MAX_BODY) { fail(413, 'payload_too_large', 'Request body exceeds 256 KiB after decompression.'); }
			if(inflate_get_status($z) === ZLIB_STREAM_END) { break; }
		}
		if(inflate_get_status($z) !== ZLIB_STREAM_END) { fail(400, 'invalid_gzip', 'Request body is not valid gzip (truncated).'); }
		$raw = $out;
	} elseif($enc !== '' AND $enc !== 'identity') {
		fail(415, 'unsupported_encoding', 'Content-Encoding must be gzip or identity.');
	}
	$b = json_decode($raw, true, 16);
	if(!is_array($b) OR ($b !== array() AND s64_is_list($b))) { fail(400, 'invalid_json', 'Request body is not a valid JSON object.'); }
	return array($raw, $b);
}

/** Ende eines JSON-Strings ab Position $i (auf dem Anfuehrungszeichen) oder null. */
function s64_skip_string(string $s, int $i): ?int {
	$n = strlen($s);
	if($i >= $n OR $s[$i] !== '"') { return null; }
	$i++;
	while(true) {
		$i += strcspn($s, "\"\\", $i);
		if($i >= $n) { return null; }
		if($s[$i] === '"') { return $i + 1; }
		$i += 2;
	}
}

/** Ende eines JSON-Werts ab Position $i oder null (der Body ist vorher als gueltiges JSON geprueft). */
function s64_skip_value(string $s, int $i): ?int {
	$n = strlen($s);
	if($i >= $n) { return null; }
	$c = $s[$i];
	if($c === '"') { return s64_skip_string($s, $i); }
	if($c === '{' OR $c === '[') {
		$depth = 0;
		while($i < $n) {
			$i += strcspn($s, "\"{}[]", $i);
			if($i >= $n) { return null; }
			$c = $s[$i];
			if($c === '"') { $i = s64_skip_string($s, $i); if($i === null) { return null; } continue; }
			if($c === '{' OR $c === '[') { if(++$depth > 32) { return null; } } else { $depth--; }
			$i++;
			if($depth === 0) { return $i; }
		}
		return null;
	}
	$len = strspn($s, '0123456789+-.eEtrufalsn', $i);
	return $len > 0 ? $i + $len : null;
}

/** Werte eines JSON-Objekts (oberste Ebene) als exakte Bytes: Schluessel => Bytes; doppelte Schluessel oder Fehler = null. */
function s64_top_raw(string $s): ?array {
	$n = strlen($s); $ws = " \t\r\n";
	$i = strspn($s, $ws);
	if($i >= $n OR $s[$i] !== '{') { return null; }
	$i++; $out = array();
	$i += strspn($s, $ws, $i);
	if($i < $n AND $s[$i] === '}') { $i++; return strspn($s, $ws, $i) === $n - $i ? $out : null; }
	while(true) {
		$i += strspn($s, $ws, $i);
		$ks = $i;
		if(($i = s64_skip_string($s, $i)) === null) { return null; }
		$key = json_decode(substr($s, $ks, $i - $ks));
		if(!is_string($key) OR array_key_exists($key, $out)) { return null; }
		$i += strspn($s, $ws, $i);
		if($i >= $n OR $s[$i] !== ':') { return null; }
		$i++;
		$i += strspn($s, $ws, $i);
		$vs = $i;
		if(($i = s64_skip_value($s, $i)) === null) { return null; }
		$out[$key] = substr($s, $vs, $i - $vs);
		$i += strspn($s, $ws, $i);
		if($i >= $n) { return null; }
		if($s[$i] === ',') { $i++; continue; }
		if($s[$i] === '}') { $i++; break; }
		return null;
	}
	return strspn($s, $ws, $i) === $n - $i ? $out : null;
}

/** IP der Verbindung (normalisiert, ::ffff:a.b.c.d als IPv4) oder ''. */
function s64_conn_ip(): string {
	$ip = client_ip();
	if(strlen($ip) > 45 OR !filter_var($ip, FILTER_VALIDATE_IP)) { return ''; }
	$bin = inet_pton($ip);
	if(strlen($bin) === 16 AND substr($bin, 0, 12) === str_repeat("\0", 10) . "\xff\xff") { $bin = substr($bin, 12); }
	return (string)inet_ntop($bin);
}

/** Sonar-Token: s64_ bzw. s64a_ + 40 Zeichen [A-Za-z0-9]. */
function s64_new_token(string $prefix): string {
	$a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'; $t = $prefix;
	for($i = 0; $i < 40; $i++) { $t .= $a[random_int(0, 61)]; }
	return $t;
}

/** Slug aus dem Namen, eindeutig (sonst mit Teil der Node-ID). */
function s64_slug(string $name, string $nodeId): string {
	$s = trim((string)preg_replace('/[^a-z0-9]+/', '-', strtolower($name)), '-');
	if($s === '') { $s = str_replace('_', '-', $nodeId); }
	$s = substr($s, 0, 40);
	if(q1("SELECT id FROM sonar_nodes WHERE slug = :s AND node_id != :n", array('s' => $s, 'n' => $nodeId)) !== null) {
		$s = substr($s, 0, 33) . '-' . substr(str_replace('_', '', $nodeId), -6);
	}
	return $s;
}

/** Zufaelliger freier Anzeigename, z. B. "Sonar-Falke-42". */
function s64_random_name(string $nodeId): string {
	for($i = 0; $i < 20; $i++) {
		$n = 'Sonar-' . S64_ANIMALS[random_int(0, count(S64_ANIMALS) - 1)] . '-' . random_int(10, 999);
		if(q1("SELECT id FROM sonar_nodes WHERE name = :n", array('n' => $n)) === null) { return $n; }
	}
	return 'Sonar-' . $nodeId;
}

/** Eigener Knoten im Format Me (wire.go). */
function s64_me_out(array $n): array {
	$f = fn($v) => $v === null ? null : (float)$v;
	$o = array('node_id' => $n['node_id'], 'name' => $n['name'], 'slug' => $n['slug'], 'lat' => $f($n['lat']), 'lon' => $f($n['lon']),
		'pub_lat' => $f($n['pub_lat']), 'pub_lon' => $f($n['pub_lon']), 'access' => $n['access'], 'device' => $n['device'],
		'measured' => (int)$n['measured'] === 1, 'budget' => $n['budget'], 'role' => $n['role'], 'trust' => $n['trust'], 'score' => (float)$n['score']);
	foreach(array('4', '6') as $x) {
		if($n["asn$x"] !== null AND (int)$n["asn$x"] > 0) { $o["asn$x"] = (int)$n["asn$x"]; $o["asname$x"] = (string)$n["asname$x"]; }
	}
	$o['reach4'] = $n['reach4']; $o['reach6'] = $n['reach6'];
	$o['since'] = s64_iso($n['first_seen']); $o['uptime30'] = (float)$n['uptime30'];
	return $o;
}

function s64_node(string $nodeId): ?array { return q1("SELECT * FROM sonar_nodes WHERE node_id = :n", array('n' => $nodeId)); }

/** Sonar-Token pruefen (Bearer). Rueckgabe [Token-Zeile, Knoten-Zeile oder null]. */
function s64_auth(): array {
	$ip = client_ip();
	rl_enforce('s64ip:' . $ip, 120, 1.0, 'sonar ip');
	$tok = bearer();
	if($tok === null OR $tok === '') {
		header('WWW-Authenticate: Bearer realm="Sonar64"');
		fail(401, 'unauthenticated', 'Send your Sonar token as "Authorization: Bearer <token>".');
	}
	$bad = function() use ($ip) {
		rl_enforce("fail:$ip", RL_FAIL_CAPACITY, RL_FAIL_REFILL, 'failed authentication');
		header('WWW-Authenticate: Bearer realm="Sonar64", error="invalid_token"');
		fail(401, 'invalid_token', 'The Sonar token is invalid or revoked.');
	};
	if(!preg_match('/^s64a?_[A-Za-z0-9]{40}\z/', $tok)) { $bad(); }
	$h = hash('sha256', $tok);
	$t = q1("SELECT * FROM sonar_tokens WHERE token_hash = :h", array('h' => $h));
	if($t === null OR !hash_equals((string)$t['token_hash'], $h) OR $t['revoked_at'] !== null) { $bad(); }
	if(($t['kind'] === 'anchor') !== str_starts_with($tok, 's64a_')) { $bad(); }
	if((int)$t['userid'] !== 0) {
		$u = q1("SELECT account_status FROM users WHERE id = :u", array('u' => (int)$t['userid']));
		if($u === null OR (string)$u['account_status'] !== '1') { $bad(); }
	}
	rl_enforce('s64tok:' . $t['id'], 120, 0.5, 'sonar token');
	$now = microtime(true);
	if($t['last_used_at'] === null OR s64_ts($t['last_used_at']) < $now - 60) {
		q("UPDATE sonar_tokens set last_used_at = :t WHERE id = :i", array('t' => s64_dt($now), 'i' => $t['id']));
	}
	return array($t, $t['node_id'] !== null ? s64_node((string)$t['node_id']) : null);
}

/** Wie s64_auth, aber mit registriertem, aktivem Knoten; vermerkt Kontakt und IP. */
function s64_node_auth(): array {
	[$t, $n] = s64_auth();
	if($n === null OR (int)$n['token_id'] !== (int)$t['id']) { fail(409, 'not_registered', 'Register this token first (POST /sonar/register).'); }
	if((int)$n['active'] !== 1) { fail(403, 'node_disabled', 'This Sonar64 node is disabled.'); }
	return array($t, s64_touch($n));
}

/**
 * Kontakt vermerken: last_seen, IP je Familie aus der Verbindung, ASN bei IP-Wechsel oder nach 24 h (Fehler: erneut
 * nach 1 h). Bei IP-Wechsel wird die Erreichbarkeit dieser Familie zurueckgesetzt: die alte Adresse gehoert vielleicht
 * schon jemand anderem und darf in keinen Plan mehr (die Anker pruefen die neue).
 */
function s64_touch(array $n): array {
	$now = microtime(true); $ip = s64_conn_ip();
	$set = array('last_seen = :ls'); $p = array('ls' => s64_dt($now), 'id' => $n['id']);
	if(s64_is_public_ip($ip)) {
		$f = str_contains($ip, ':') ? '6' : '4';
		$changed = $n["ip$f"] !== $ip;
		$at = s64_ts($n['asn_at']);
		if($changed OR $at === null OR $at < $now - 86400) {
			$a = s64_asn_lookup($ip);
			$set[] = "ip$f = :ip"; $set[] = "asn$f = :asn"; $set[] = "asname$f = :asname"; $set[] = 'asn_at = :aat';
			$p['ip'] = $ip; $p['asn'] = $a['asn']; $p['asname'] = $a['name']; $p['aat'] = s64_dt($a['asn'] === null ? $now - 82800 : $now);
			if($changed) { $set[] = "reach$f = 'none'"; }
		}
	}
	q("UPDATE sonar_nodes set " . implode(', ', $set) . " WHERE id = :id", $p);
	return s64_node((string)$n['node_id']);
}

/** Oeffentliche Sicht auf einen Knoten (ohne IP, genaue Koordinaten, Account). */
function s64_pub_node(array $n, float $now): array {
	$f = fn($v) => $v === null ? null : (float)$v;
	$asn = $n['asn4'] !== null ? (int)$n['asn4'] : ($n['asn6'] !== null ? (int)$n['asn6'] : null);
	$ls = s64_ts($n['last_seen']);
	return array('id' => $n['node_id'], 'slug' => $n['slug'], 'name' => $n['name'], 'role' => $n['role'], 'trust' => $n['trust'],
		'lat' => $f($n['pub_lat']), 'lon' => $f($n['pub_lon']), 'asn' => $asn, 'asname' => (string)($n['asn4'] !== null ? $n['asname4'] : $n['asname6']),
		'asn6' => $n['asn6'] !== null ? (int)$n['asn6'] : null, 'access' => $n['access'], 'device' => $n['device'], 'place' => (string)$n['place'],
		'measured' => (int)$n['measured'] === 1, 'reach4' => $n['reach4'], 'reach6' => $n['reach6'],
		'ipv4' => $n['ip4'] !== null, 'ipv6' => $n['ip6'] !== null,
		'since' => s64_iso($n['first_seen']), 'last_seen' => s64_iso($n['last_seen']), 'online' => $ls !== null AND $ls >= $now - S64_ONLINE,
		'uptime30' => round((float)$n['uptime30'], 4));
}

/** Oeffentlich sichtbare Knoten (aktiv, angemeldet, nicht in Quarantaene). */
function s64_public_nodes(): array {
	return qa("SELECT * FROM sonar_nodes WHERE active = 1 AND last_seen IS NOT NULL AND trust != 'quarantine' ORDER BY id");
}

/** Mediane Node->Anker der letzten 60 min: [src][anker] => ms. */
function s64_anchor_ms(array $anchors, float $now, ?string $src = null): array {
	if($anchors === array()) { return array(); }
	$in = implode(',', array_fill(0, count($anchors), '?'));
	$sql = "SELECT src, dst, avg_ms FROM sonar_results WHERE at >= ? AND valid = 1 AND recv > 0 AND dst IN ($in)" . ($src !== null ? ' AND src = ?' : '');
	$v = array();
	$st = q($sql, array_merge(array(s64_dt($now - 3600)), $anchors, $src !== null ? array($src) : array()));
	while(($r = $st->fetch(PDO::FETCH_NUM)) !== false) { $v[$r[0]][$r[1]][] = (float)$r[2]; }
	$out = array();
	foreach($v as $s => $byA) { foreach($byA as $a => $list) { $out[$s][$a] = round(s64_median($list), 1); } }
	return $out;
}

function s64_outage_out(array $o): array {
	return array('id' => (int)$o['id'], 'kind' => $o['kind'], 'key' => $o['keyval'], 'label' => $o['label'], 'started' => s64_iso($o['started']),
		'ended' => s64_iso($o['ended']), 'affected' => (int)$o['affected'], 'total' => (int)$o['total']);
}

// ---------------------------------------------------------------- Token (API-Key)

/** POST /sonar/tokens: Knoten-Token anlegen ({name}); der Klartext steht nur in dieser Antwort. */
route('POST', '/sonar/tokens', function() {
	$name = in_str('name', true, 64);
	if(!preg_match('/^[\p{L}\p{N} ._:@()\/-]{1,64}\z/u', $name)) { fail(422, 'invalid_field', "Field 'name' may contain letters, digits, space and . _ : @ ( ) / -.", array('field' => 'name')); }
	$n = (int)q1("SELECT count(*) c FROM sonar_tokens WHERE userid = :u AND kind = 'node' AND revoked_at IS NULL", array('u' => uid()))['c'];
	if($n >= S64_MAX_TOKENS) { fail(403, 'limit_reached', 'At most ' . S64_MAX_TOKENS . ' Sonar tokens per account. Delete one first.', array('limit' => S64_MAX_TOKENS)); }
	$n = (int)q1("SELECT count(*) c FROM sonar_tokens WHERE userid = :u AND kind = 'node' AND created_at >= :d", array('u' => uid(), 'd' => s64_dt(microtime(true) - 86400)))['c'];
	if($n >= S64_NEW_TOKENS) { header('Retry-After: 3600'); fail(429, 'rate_limited', 'At most ' . S64_NEW_TOKENS . ' new Sonar tokens per account in 24 hours.', array('limit' => S64_NEW_TOKENS)); }
	$tok = s64_new_token('s64_');
	q("INSERT INTO sonar_tokens (userid, kind, name, token_hash, created_at) VALUES (:u, 'node', :n, :h, :t)",
		array('u' => uid(), 'n' => $name, 'h' => hash('sha256', $tok), 't' => s64_dt()));
	$id = (int)$GLOBALS['pdo']->lastInsertId();
	add_log($GLOBALS['pdo'], uid(), "0", "Sonar64", "Sonar64 token '" . htmlspecialchars($name) . "' created via API v2.");
	ok(array('id' => $id, 'token' => $tok), 201);
});

/** GET /sonar/tokens: eigene Token (ohne Klartext). */
route('GET', '/sonar/tokens', function() {
	ok(array_map(fn($t) => array('id' => (int)$t['id'], 'name' => $t['name'], 'node_id' => $t['node_id'], 'created_at' => s64_iso($t['created_at']),
		'last_used_at' => s64_iso($t['last_used_at'])),
		qa("SELECT * FROM sonar_tokens WHERE userid = :u AND revoked_at IS NULL ORDER BY id", array('u' => uid()))));
});

/**
 * DELETE /sonar/tokens/{id}: Token widerrufen, Knoten deaktivieren (s64_leave: IP und genauer Standort werden geloescht,
 * Name und Slug frei, Plan weg, sonar_trust_log removed/owner).
 */
route('DELETE', '/sonar/tokens/{id}', function($p) {
	if(!ctype_digit($p['id']) OR strlen($p['id']) > 10) { fail(404, 'not_found', 'Token not found.'); }
	$t = q1("SELECT * FROM sonar_tokens WHERE id = :i AND userid = :u AND revoked_at IS NULL", array('i' => (int)$p['id'], 'u' => uid()));
	if($t === null) { fail(404, 'not_found', 'Token not found.'); }
	s64_leave($GLOBALS['pdo'], (int)$t['id'], 'owner'); // mit add_log
	no_content();
});

// ---------------------------------------------------------------- Knoten (Sonar-Token)

/** POST /sonar/register: Knoten anlegen (Register: pubkey, version, mode) -> Me. Wiederholung mit demselben Key = 200. */
route('POST', '/sonar/register', function() {
	[$t, $n] = s64_auth();
	[, $b] = s64_body();
	$pk = $b['pubkey'] ?? null;
	$pkRaw = (is_string($pk) AND strlen($pk) <= 64) ? base64_decode($pk, true) : false;
	if($pkRaw === false OR strlen($pkRaw) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES OR base64_encode($pkRaw) !== $pk) { fail(422, 'invalid_field', "Field 'pubkey' must be an Ed25519 public key (base64).", array('field' => 'pubkey')); }
	$ver = $b['version'] ?? null;
	if(!is_string($ver) OR !preg_match('/^[0-9A-Za-z][0-9A-Za-z.+_~-]{0,31}\z/', $ver)) { fail(422, 'invalid_field', "Field 'version' is invalid.", array('field' => 'version')); }
	$mode = $b['mode'] ?? null;
	if(!in_array($mode, S64_MODES, true)) { fail(422, 'invalid_field', "Field 'mode' must be module, headless or anchor.", array('field' => 'mode')); }
	$anchor = $t['kind'] === 'anchor';
	if($anchor !== ($mode === 'anchor')) { fail(422, 'invalid_field', $anchor ? 'An anchor token requires mode anchor.' : 'Mode anchor requires an anchor token.', array('field' => 'mode')); }

	if($n !== null AND (int)$n['token_id'] === (int)$t['id']) { // schon registriert: nur mit demselben Schluessel
		if(!hash_equals((string)$n['pubkey'], $pk)) { fail(409, 'already_registered', 'This token is already registered with another key. Create a new token to register again.'); }
		if((int)$n['active'] !== 1) { fail(403, 'node_disabled', 'This Sonar64 node is disabled.'); }
		q("UPDATE sonar_nodes set version = :v, mode = :m WHERE id = :i", array('v' => $ver, 'm' => $mode, 'i' => $n['id']));
		ok(s64_me_out(s64_touch(s64_node((string)$n['node_id']))));
	}
	if(q1("SELECT id FROM sonar_nodes WHERE pubkey = :p AND token_id != :t AND node_id != :self", array('p' => $pk, 't' => $t['id'], 'self' => $anchor ? 'a_' . $t['name'] : '')) !== null) { fail(409, 'key_in_use', 'This public key belongs to another Sonar64 node.'); }

	global $pdo;
	$now = microtime(true);
	$pdo->beginTransaction();
	try {
		$tl = q1("SELECT * FROM sonar_tokens WHERE id = :i FOR UPDATE", array('i' => $t['id']));
		if($tl === null OR $tl['revoked_at'] !== null OR $tl['node_id'] !== null) { fail(409, 'already_registered', 'This token was registered in the meantime.'); }
		if($anchor) {
			if(!preg_match('/^[a-z0-9]{2,12}\z/', (string)$t['name'])) { fail(500, 'invalid_anchor', 'The anchor token has no valid anchor name.'); }
			$id = 'a_' . $t['name'];
			$old = q1("SELECT n.*, t.revoked_at trev FROM sonar_nodes n LEFT JOIN sonar_tokens t ON t.id = n.token_id WHERE n.node_id = :n FOR UPDATE", array('n' => $id));
			if($old !== null) { // Token-Wechsel des Ankers: Knoten bleibt, neuer Schluessel und neue seq
				if($old['trev'] === null AND (int)$old['token_id'] !== (int)$t['id']) { fail(409, 'anchor_in_use', 'This anchor is bound to another active token (revoke it first).'); }
				q("UPDATE sonar_nodes set token_id = :t, userid = :u, pubkey = :p, version = :v, mode = :m, last_seq = 0, active = 1, disabled_at = NULL WHERE id = :i",
					array('t' => $t['id'], 'u' => (int)$t['userid'], 'p' => $pk, 'v' => $ver, 'm' => $mode, 'i' => $old['id']));
			} else {
				$name = 'Anker-' . strtoupper($t['name']);
				q("INSERT INTO sonar_nodes (node_id, userid, token_id, role, pubkey, name, slug, jitter_seed, access, device, measured, budget, mode, version, trust, first_seen)
					VALUES (:n, :u, :t, 'anchor', :p, :name, :slug, :js, 'datacenter', 'anchor', 1, 'grosszuegig', :m, :v, 'anchor', :fs)",
					array('n' => $id, 'u' => (int)$t['userid'], 't' => $t['id'], 'p' => $pk, 'name' => $name, 'slug' => s64_slug($name, $id),
						'js' => random_int(1, 2147483646), 'm' => $mode, 'v' => $ver, 'fs' => s64_dt($now)));
			}
		} else {
			$a = 'abcdefghijklmnopqrstuvwxyz0123456789';
			do { $id = 'n'; for($i = 0; $i < 11; $i++) { $id .= $a[random_int(0, 35)]; } } while(s64_node($id) !== null);
			$name = s64_random_name($id);
			q("INSERT INTO sonar_nodes (node_id, userid, token_id, role, pubkey, name, slug, jitter_seed, mode, version, first_seen)
				VALUES (:n, :u, :t, 'node', :p, :name, :slug, :js, :m, :v, :fs)",
				array('n' => $id, 'u' => (int)$t['userid'], 't' => $t['id'], 'p' => $pk, 'name' => $name, 'slug' => s64_slug($name, $id),
					'js' => random_int(1, 2147483646), 'm' => $mode, 'v' => $ver, 'fs' => s64_dt($now)));
		}
		q("UPDATE sonar_tokens set node_id = :n WHERE id = :i", array('n' => $id, 'i' => $t['id']));
		$pdo->commit();
	} catch(Throwable $e) {
		if($pdo->inTransaction()) { $pdo->rollBack(); }
		throw $e;
	}
	ok(s64_me_out(s64_touch(s64_node($id))), 201);
}, true); // Sonar-Token, prueft s64_auth

/** GET /sonar/me */
route('GET', '/sonar/me', function() {
	[, $n] = s64_node_auth();
	ok(s64_me_out($n));
}, true); // Sonar-Token, prueft s64_auth

/**
 * DELETE /sonar/me: abmelden (Knoten und Anker, auch vor register) wie DELETE /sonar/tokens/{id}; danach liefert jeder
 * Token-Endpunkt 401 invalid_token. -> 204
 */
route('DELETE', '/sonar/me', function() {
	[$t] = s64_auth();
	s64_leave($GLOBALS['pdo'], (int)$t['id'], 'leave');
	no_content();
}, true); // Sonar-Token, prueft s64_auth

/**
 * PUT /sonar/me: nur schreibbare Felder (name, lat/lon, access, device, measured, budget); alle anderen werden
 * ignoriert. Fehlt ein Feld oder ist ein Text leer, bleibt der Wert. lat und lon nur zusammen (beide null = entfernen).
 */
route('PUT', '/sonar/me', function() {
	[, $n] = s64_node_auth();
	[, $b] = s64_body();
	$anchor = $n['role'] === 'anchor';
	$set = array(); $p = array('id' => $n['id']);
	$name = $b['name'] ?? null;
	if($name !== null AND $name !== '') {
		if(!is_string($name) OR !preg_match('/^[A-Za-z0-9._-](?:[A-Za-z0-9._-]| (?! )){1,30}[A-Za-z0-9._-]\z/', $name)) {
			fail(422, 'invalid_field', "Field 'name' must be 3 to 32 characters of A-Z a-z 0-9 space . _ - (no leading, trailing or double spaces).", array('field' => 'name'));
		}
		if(!$anchor AND preg_match('/^(anker|anchor|ipv64|sonar64|admin)/i', $name)) { fail(422, 'reserved_name', 'This name is reserved.', array('field' => 'name')); }
		if($name !== $n['name']) {
			if(q1("SELECT id FROM sonar_nodes WHERE name = :n AND id != :i", array('n' => $name, 'i' => $n['id'])) !== null) { fail(409, 'name_taken', 'This name is already taken.', array('field' => 'name')); }
			$set[] = 'name = :name'; $set[] = 'slug = :slug'; $p['name'] = $name; $p['slug'] = s64_slug($name, (string)$n['node_id']);
		}
	}
	if(array_key_exists('lat', $b) OR array_key_exists('lon', $b)) {
		$lat = $b['lat'] ?? null; $lon = $b['lon'] ?? null;
		if($lat === null AND $lon === null) {
			$set[] = 'lat = NULL, lon = NULL, pub_lat = NULL, pub_lon = NULL';
		} else {
			if((!is_int($lat) AND !is_float($lat)) OR (!is_int($lon) AND !is_float($lon)) OR $lat < -90 OR $lat > 90 OR $lon < -180 OR $lon > 180) {
				fail(422, 'invalid_field', "Fields 'lat' (-90..90) and 'lon' (-180..180) must be set together.", array('field' => 'lat'));
			}
			$lat = round((float)$lat, 5); $lon = round((float)$lon, 5);
			$pc = s64_pub_coords($lat, $lon, (int)$n['jitter_seed']);
			$set[] = 'lat = :lat, lon = :lon, pub_lat = :plat, pub_lon = :plon';
			$p += array('lat' => $lat, 'lon' => $lon, 'plat' => $pc['lat'], 'plon' => $pc['lon']);
		}
	}
	$access = $b['access'] ?? null;
	if($access !== null AND $access !== '') {
		if(!in_array($access, S64_ACCESS, true)) { fail(422, 'invalid_field', "Field 'access' must be one of " . implode(', ', S64_ACCESS) . '.', array('field' => 'access')); }
		$set[] = 'access = :access'; $p['access'] = $access;
	}
	$device = $b['device'] ?? null;
	if($device !== null AND $device !== '') {
		if(!is_string($device) OR !preg_match('/^[a-z0-9-]{1,16}\z/', $device)) { fail(422, 'invalid_field', "Field 'device' must be 1 to 16 characters a-z 0-9 -.", array('field' => 'device')); }
		$set[] = 'device = :device'; $p['device'] = $device;
	}
	if(array_key_exists('measured', $b) AND $b['measured'] !== null AND !$anchor) {
		if(!is_bool($b['measured'])) { fail(422, 'invalid_field', "Field 'measured' must be a boolean.", array('field' => 'measured')); }
		$set[] = 'measured = :measured'; $p['measured'] = $b['measured'] ? 1 : 0;
	}
	$budget = $b['budget'] ?? null;
	if($budget !== null AND $budget !== '' AND !$anchor) {
		if(!in_array($budget, S64_BUDGETS, true)) { fail(422, 'invalid_field', "Field 'budget' must be sparsam, normal or grosszuegig.", array('field' => 'budget')); }
		$set[] = 'budget = :budget'; $p['budget'] = $budget;
	}
	if($set !== array()) { q("UPDATE sonar_nodes set " . implode(', ', $set) . " WHERE id = :id", $p); }
	ok(s64_me_out(s64_node((string)$n['node_id'])));
}, true); // Sonar-Token, prueft s64_auth

/** GET /sonar/plan: SignedPlan (Plan als exakte Bytes, Ed25519 von ipv64). ETag/If-None-Match -> 304; 204 = kein Plan. */
route('GET', '/sonar/plan', function() {
	[, $n] = s64_node_auth();
	$now = microtime(true);
	$pl = q1("SELECT * FROM sonar_plans WHERE node_id = :n", array('n' => $n['node_id']));
	$exp = $pl === null ? null : s64_ts($pl['expires']);
	$iss = $pl === null ? null : s64_ts($pl['issued']);
	if($pl === null OR $exp === null OR $iss === null OR $exp <= $now OR $iss + 1800 <= $now OR $iss > $now + S64_SKEW) { no_content(); }
	$body = trim((string)$pl['body']);
	$plan = json_decode($body, true, 16);
	if(!is_array($plan) OR ($plan['node_id'] ?? null) !== $n['node_id'] OR ($plan['v'] ?? null) !== 1) {
		error_log("api_v2 sonar: invalid plan for node " . $n['node_id']);
		no_content();
	}
	$etag = (string)$pl['etag'];
	$hdr = array('ETag: "' . $etag . '"');
	q("UPDATE sonar_nodes set last_plan = :t WHERE id = :i", array('t' => s64_dt($now), 'i' => $n['id']));
	if($pl['sent_etag'] !== $etag) { // zuletzt und davor ausgelieferter Plan, alle Fassungen der letzten Runden (Pruefung der Meldungen)
		q("UPDATE sonar_plans set prev_body = sent_body, sent_body = body, sent_etag = etag, sent_at = :t, sent_hist = :h WHERE node_id = :n AND etag = :e",
			array('t' => s64_dt($now), 'h' => s64_hist_merge($pl['sent_hist'], $plan, $now), 'n' => $n['node_id'], 'e' => $etag));
	}
	foreach(explode(',', (string)($_SERVER['HTTP_IF_NONE_MATCH'] ?? '')) as $x) {
		$x = trim($x);
		if(str_starts_with($x, 'W/')) { $x = substr($x, 2); }
		if($x !== '' AND trim($x, '"') === $etag) { s64_send(304, null, $hdr); }
	}
	try { $s = s64_plan_sign($body); }
	catch(Throwable $e) { error_log("api_v2 sonar: " . $e->getMessage()); fail(503, 'plan_key_missing', 'Plans cannot be signed at the moment.'); }
	s64_send(200, '{"data":{"plan":' . $body . ',"kid":' . s64_json($s['kid']) . ',"sig":' . s64_json($s['sig']) . '}}', $hdr);
}, true); // Sonar-Token, prueft s64_auth

/** Werte einer Messung unmoeglich? (recv > sent, Reihenfolge min <= avg <= max, Bereiche) */
function s64_bad_values(array $x): bool {
	if($x['recv'] > $x['sent']) { return true; }
	if($x['method'] !== 'trace' AND $x['sent'] > 5) { return true; }
	foreach(array('min', 'avg', 'max', 'jitter') as $k) { if($x[$k] < 0 OR $x[$k] > 60000) { return true; } }
	if($x['method'] === 'trace') { return $x['hops_bad']; }
	if($x['recv'] === 0) { return $x['min'] != 0 OR $x['avg'] != 0 OR $x['max'] != 0 OR $x['jitter'] != 0; }
	if($x['min'] <= 0 OR $x['min'] > $x['avg'] + 1e-6 OR $x['avg'] > $x['max'] + 1e-6) { return true; }
	return $x['jitter'] > ($x['max'] - $x['min']) + 0.01;
}

/** Ergebnis aus der Meldung pruefen (Form) und vereinheitlichen; Formfehler = 422 fuer die ganze Meldung. */
function s64_parse_result($x, string $f): array {
	if(!is_array($x) OR s64_is_list($x)) { s64_bad($f, "$f must be an object."); }
	$tg = $x['target'] ?? null;
	if(!is_string($tg) OR !preg_match(S64_NODE_RE, $tg)) { s64_bad("$f.target", "$f.target must be a node ID."); }
	$fam = $x['fam'] ?? null;
	if($fam !== 4 AND $fam !== 6) { s64_bad("$f.fam", "$f.fam must be 4 or 6."); }
	$m = $x['method'] ?? null;
	if(!in_array($m, array('icmp', 'udp', 'trace'), true)) { s64_bad("$f.method", "$f.method must be icmp, udp or trace."); }
	$r = array('round' => (int)floor(s64_time($x['round'] ?? null, "$f.round")), 'target' => $tg, 'fam' => $fam, 'method' => $m,
		'sent' => s64_int($x['sent'] ?? null, "$f.sent", 0, 255), 'recv' => s64_int($x['recv'] ?? null, "$f.recv", 0, 255),
		'min' => s64_num($x['min'] ?? null, "$f.min"), 'avg' => s64_num($x['avg'] ?? null, "$f.avg"), 'max' => s64_num($x['max'] ?? null, "$f.max"),
		'jitter' => s64_num($x['jitter'] ?? null, "$f.jitter"), 'at' => s64_time($x['at'] ?? null, "$f.at"), 'hops' => null, 'hops_bad' => false);
	if(array_key_exists('err', $x) AND (!is_string($x['err']) OR strlen($x['err']) > 64)) { s64_bad("$f.err", "$f.err must be a short string."); }
	$hops = $x['hops'] ?? null;
	if($hops !== null) {
		if(!is_array($hops) OR !s64_is_list($hops) OR count($hops) > S64_MAX_HOPS) { s64_bad("$f.hops", "$f.hops must be an array of at most " . S64_MAX_HOPS . " hops."); }
		$out = array(); $last = 0;
		foreach($hops as $j => $h) {
			if(!is_array($h)) { s64_bad("$f.hops[$j]", "$f.hops[$j] must be an object."); }
			$ttl = s64_int($h['ttl'] ?? null, "$f.hops[$j].ttl", 0, 255);
			$addr = $h['addr'] ?? '';
			if(!is_string($addr) OR strlen($addr) > 45) { s64_bad("$f.hops[$j].addr", "$f.hops[$j].addr must be an IP address."); }
			$rtt = s64_num($h['rtt'] ?? null, "$f.hops[$j].rtt");
			if($ttl < 1 OR $ttl > 30 OR $ttl <= $last OR $rtt < 0 OR $rtt > 60000 OR ($addr !== '' AND !filter_var($addr, FILTER_VALIDATE_IP))) { $r['hops_bad'] = true; }
			$last = $ttl;
			$o = array('ttl' => $ttl);
			if($addr !== '' AND s64_is_public_ip($addr)) { $o['addr'] = inet_ntop(inet_pton($addr)); } // nicht oeffentliche Hops (Heimnetz) nicht speichern
			if($rtt > 0) { $o['rtt'] = round($rtt, 3); }
			$out[] = $o;
		}
		$r['hops'] = $out;
	}
	if($m === 'trace' AND $r['hops'] === null) { $r['hops'] = array(); }
	return $r;
}

/** Ziele je Runde eines Plans: Runde (Unix) => "Ziel|fam|Methode" => array(Anzahl, Adresse). */
function s64_plan_rounds($plan): array {
	$out = array();
	if(!is_array($plan) OR !is_array($plan['rounds'] ?? null)) { return $out; }
	foreach($plan['rounds'] as $r) {
		$R = is_array($r) ? s64_plan_time($r['start'] ?? null) : null;
		if($R === null OR !is_array($r['targets'] ?? null)) { continue; }
		foreach($r['targets'] as $x) {
			if(!is_array($x) OR !is_string($x['id'] ?? null)) { continue; }
			$k = $x['id'] . '|' . (int)($x['fam'] ?? 0) . '|' . (string)($x['method'] ?? '');
			$out[$R][$k] = array(($out[$R][$k][0] ?? 0) + 1, is_string($x['addr'] ?? null) ? substr($x['addr'], 0, 45) : '');
		}
	}
	return $out;
}

/**
 * sent_hist: alle ausgelieferten Fassungen je Runde zusammengefasst (hoechste Anzahl, letzte Adresse), nur Runden ab
 * jetzt - 35 min. Der Planer fuellt kommende Runden auf und nimmt nicht mehr Erlaubtes heraus; wer eine aeltere Fassung
 * gemessen hat, bekommt so kein not_in_plan.
 */
function s64_hist_merge(?string $old, array $plan, float $now): string {
	$h = ($old !== null AND $old !== '') ? json_decode($old, true, 8) : array();
	$h = is_array($h) ? $h : array();
	foreach(s64_plan_rounds($plan) as $R => $keys) {
		foreach($keys as $k => $v) { $h[$R][$k] = array(max((int)($h[$R][$k][0] ?? 0), $v[0]), $v[1]); }
	}
	foreach(array_keys($h) as $R) { if(!is_int($R) OR $R < $now - S64_HIST OR !is_array($h[$R])) { unset($h[$R]); } }
	ksort($h);
	return s64_json((object)$h);
}

/**
 * Erlaubte Messungen aus den ausgelieferten Plaenen (sent_hist, zuletzt und davor ausgelieferter Plan):
 * "Runde|Ziel|fam|Methode" => array(Anzahl, Adresse laut Plan).
 */
function s64_plan_allowed(?array $pl): array {
	$allowed = array();
	$add = function(int $R, string $k, int $c, string $addr) use (&$allowed) {
		$k = $R . '|' . $k;
		$allowed[$k] = array(max($allowed[$k][0] ?? 0, $c), $addr !== '' ? $addr : ($allowed[$k][1] ?? ''));
	};
	$hist = is_string($pl['sent_hist'] ?? null) ? json_decode($pl['sent_hist'], true, 8) : null;
	foreach(is_array($hist) ? $hist : array() as $R => $keys) {
		if(!is_int($R) OR !is_array($keys)) { continue; }
		foreach($keys as $k => $v) { if(is_array($v) AND is_int($v[0] ?? null)) { $add($R, (string)$k, $v[0], is_string($v[1] ?? null) ? $v[1] : ''); } }
	}
	foreach(array($pl['sent_body'] ?? null, $pl['prev_body'] ?? null) as $body) {
		if(!is_string($body) OR $body === '') { continue; }
		foreach(s64_plan_rounds(json_decode($body, true, 16)) as $R => $keys) { foreach($keys as $k => $v) { $add($R, $k, $v[0], $v[1]); } }
	}
	return $allowed;
}

/** POST /sonar/results: SignedReport -> {accepted, rejected, reasons}. */
route('POST', '/sonar/results', function() {
	global $pdo;
	[, $n] = s64_node_auth();
	$now = microtime(true);
	$gap = function(?array $node) use ($now) {
		$lr = $node === null ? null : s64_ts($node['last_report']);
		$wait = $lr === null ? 0 : (int)ceil(S64_REPORT_GAP - ($now - $lr));
		if($wait > 0) {
			header('Retry-After: ' . $wait);
			fail(429, 'rate_limited', 'At most one report every ' . S64_REPORT_GAP . " seconds. Retry in $wait seconds.", array('retry_after' => $wait));
		}
	};
	$gap($n);
	[$raw, $b] = s64_body();
	$parts = s64_top_raw($raw);
	if($parts === null OR !isset($parts['report'], $parts['sig']) OR count($parts) !== 2) { s64_bad('report', 'Body must be {"report": {...}, "sig": "..."}.'); }
	$sig = $b['sig'];
	$sigRaw = (is_string($sig) AND strlen($sig) <= 100) ? base64_decode($sig, true) : false;
	if($sigRaw === false OR strlen($sigRaw) !== SODIUM_CRYPTO_SIGN_BYTES) { s64_bad('sig', "Field 'sig' must be an Ed25519 signature (base64)."); }
	$pk = base64_decode((string)$n['pubkey'], true);
	if($pk === false OR strlen($pk) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES OR !sodium_crypto_sign_verify_detached($sigRaw, $parts['report'], $pk)) {
		rl_enforce('fail:' . client_ip(), RL_FAIL_CAPACITY, RL_FAIL_REFILL, 'failed authentication');
		fail(403, 'invalid_signature', 'The report signature does not match the key of this node.');
	}
	$rep = $b['report'];
	if(!is_array($rep) OR s64_is_list($rep)) { s64_bad('report', "Field 'report' must be an object."); }
	if(($rep['v'] ?? null) !== 1) { fail(422, 'unsupported_version', "Field 'report.v' must be 1.", array('field' => 'report.v')); }
	if(($rep['node_id'] ?? null) !== $n['node_id']) { s64_bad('report.node_id', "Field 'report.node_id' does not belong to this token."); }
	$seq = $rep['seq'] ?? null;
	if(!is_int($seq) OR $seq < 1) { s64_bad('report.seq', "Field 'report.seq' must be a positive integer."); }
	// seq = max(letzte + 1, Unix-ms): weiter als 1 Tag voraus haette den Knoten fuer immer ausgesperrt (409 replay)
	if($seq > (int)(($now + 86400) * 1000)) { s64_bad('report.seq', "Field 'report.seq' is too far in the future (Unix milliseconds)."); }
	$sent = s64_time($rep['sent'] ?? null, 'report.sent');
	if($sent > $now + S64_SKEW OR $sent < $now - S64_BUFFER - 600) { s64_bad('report.sent', "Field 'report.sent' is too far from the current time (check the clock)."); }
	$res = $rep['results'] ?? array();
	if(!is_array($res) OR !s64_is_list($res)) { s64_bad('report.results', "Field 'report.results' must be an array."); }
	if(count($res) > S64_MAX_RESULTS) { fail(413, 'too_many_results', 'At most ' . S64_MAX_RESULTS . ' results per report.', array('field' => 'report.results')); }
	$inb = $rep['inbound'] ?? array();
	if(!is_array($inb) OR !s64_is_list($inb)) { s64_bad('report.inbound', "Field 'report.inbound' must be an array."); }
	if(count($inb) > S64_MAX_INBOUND) { fail(413, 'too_many_inbound', 'At most ' . S64_MAX_INBOUND . ' inbound entries per report.', array('field' => 'report.inbound')); }
	$items = array();
	foreach($res as $i => $x) { $items[] = s64_parse_result($x, "report.results[$i]"); }
	$inbound = array();
	foreach($inb as $i => $x) {
		$f = "report.inbound[$i]";
		if(!is_array($x)) { s64_bad($f, "$f must be an object."); }
		$from = $x['from'] ?? null;
		if(!is_string($from) OR !preg_match('/^[0-9a-f]{8}\z/', $from)) { s64_bad("$f.from", "$f.from must be 8 hex characters."); }
		$fam = $x['fam'] ?? null;
		if($fam !== 4 AND $fam !== 6) { s64_bad("$f.fam", "$f.fam must be 4 or 6."); }
		$at = s64_time($x['at'] ?? null, "$f.at");
		$cnt = s64_int($x['count'] ?? null, "$f.count", 0, 1000000);
		if($cnt > 0 AND $at <= $now + S64_SKEW AND $at >= $now - S64_BUFFER - 600) {
			$k = $from . '|' . $fam . '|' . intdiv((int)$at, S64_ROUND);
			$inbound[$k] = array($n['node_id'], $from, $fam, max($at, $inbound[$k][3] ?? 0), ($inbound[$k][4] ?? 0) + $cnt);
		}
	}
	// nur Absender, die es gibt (Kurz-ID eines aktiven Knotens); je Absender, Familie und Runde eine Zeile
	if($inbound !== array()) {
		$known = array_flip(s64_cache('short_ids', 300, fn() => array_map('s64_short_id', array_column(qa("SELECT node_id FROM sonar_nodes WHERE active = 1"), 'node_id'))));
		$inbound = array_values(array_filter($inbound, fn($r) => isset($known[$r[1]])));
		foreach($inbound as &$r) { $r[3] = s64_dt($r[3]); $r[4] = min($r[4], 1000000); }
		unset($r);
	}
	$h = is_array($rep['health'] ?? null) ? $rep['health'] : array();
	$hs = fn($k, $re) => (is_string($h[$k] ?? null) AND preg_match($re, $h[$k])) ? $h[$k] : '';
	$health = array('version' => $hs('version', '/^[0-9A-Za-z][0-9A-Za-z.+_~-]{0,31}\z/'), 'mode' => in_array($h['mode'] ?? null, S64_MODES, true) ? $h['mode'] : '',
		'uplink' => ($h['uplink'] ?? false) === true, 'paused' => $hs('paused', '/^[a-z_]{1,16}\z/'),
		'sent_today' => (is_int($h['sent_today'] ?? null) AND $h['sent_today'] >= 0) ? min($h['sent_today'], 100000000) : 0,
		'budget' => in_array($h['budget'] ?? null, S64_BUDGETS, true) ? $h['budget'] : '', 'responder' => ($h['responder'] ?? false) === true,
		'icmp_denied' => ($h['icmp_denied'] ?? false) === true);

	// Plan, Anker und Koordinaten der Ziele
	$allowed = s64_plan_allowed(q1("SELECT sent_body, prev_body, sent_hist FROM sonar_plans WHERE node_id = :n", array('n' => $n['node_id'])));
	$anchors = array();
	foreach(qa("SELECT node_id FROM sonar_nodes WHERE role = 'anchor' AND active = 1") as $a) { $anchors[$a['node_id']] = true; }
	$ids = array_values(array_unique(array_map(fn($x) => $x['target'], $items)));
	$coords = array(); $tgt = array(); // Ziele: Koordinaten; noch erlaubt (aktiv, gemessen) und aktuelle Adressen
	foreach(array_chunk($ids, 500) as $chunk) {
		foreach(qa("SELECT node_id, role, lat, lon, trust, active, measured, ip4, ip6, reach4, reach6 FROM sonar_nodes WHERE node_id IN (" . implode(',', array_fill(0, count($chunk), '?')) . ")", $chunk) as $c) {
			if($c['lat'] !== null AND $c['lon'] !== null) { $coords[$c['node_id']] = array((float)$c['lat'], (float)$c['lon'], in_array($c['trust'], array('anchor', 'pillar', 'trusted'), true)); }
			$tgt[$c['node_id']] = $c;
		}
	}
	$isAnchor = $n['role'] === 'anchor';
	$smooth = fn($x) => $x['recv'] >= 5 && $x['jitter'] == 0 && $x['min'] == $x['max'];
	$hist = array(); // too_smooth: glatt ja/nein je Ziel, neueste zuerst
	if(!$isAnchor AND array_filter($items, fn($x) => $x['method'] !== 'trace' && $smooth($x)) !== array()) {
		$st = q("SELECT dst, fam, recv, jitter_ms, min_ms, max_ms FROM sonar_results WHERE src = :s AND at >= :d ORDER BY at DESC",
			array('s' => $n['node_id'], 'd' => s64_dt($now - 43200)));
		while(($r = $st->fetch(PDO::FETCH_ASSOC)) !== false) {
			$k = $r['dst'] . '|' . $r['fam'];
			if(count($hist[$k] ?? array()) < S64_SMOOTH_N) { $hist[$k][] = (int)$r['recv'] >= 5 && (float)$r['jitter_ms'] == 0 && (float)$r['min_ms'] == (float)$r['max_ms']; }
		}
	}
	usort($items, fn($a, $b) => $a['at'] <=> $b['at']);

	$reasons = array(); $used = array(); $rows = array(); $bad = array(); $traces = array(); $checked = 0; $soft = 0; $reachUp = array();
	$why = function(string $r) use (&$reasons) { $reasons[$r] = ($reasons[$r] ?? 0) + 1; };
	foreach($items as $x) {
		if($x['sent'] === 0) { $why('not_measured'); continue; } // nicht gemessen (Budget, keine Rechte): kein Fehler
		// Runde laut Plan; steht das Ziel dort nicht, eine Runde davor oder danach (Planwechsel); Anker immer (icmp/udp)
		$R = $x['round']; $tail = '|' . $x['target'] . '|' . $x['fam'] . '|' . $x['method']; $key = null;
		if(isset($allowed[$R . $tail])) { $key = $R . $tail; }
		else {
			foreach(array($R - S64_ROUND, $R + S64_ROUND) as $RR) {
				if(isset($allowed[$RR . $tail]) AND ($key === null OR ($used[$RR . $tail] ?? 0) < $allowed[$RR . $tail][0])) { $key = $RR . $tail; }
			}
			if(isset($anchors[$x['target']]) AND $x['method'] !== 'trace' AND $R % S64_ROUND === 0 AND ($key === null OR ($used[$key] ?? 0) >= $allowed[$key][0])) { $key = 'A|' . $R . $tail; $allowed[$key] = array(1, ''); }
		}
		if($key === null OR $x['target'] === $n['node_id']) { $why('not_in_plan'); continue; }
		// stand im Plan, ist aber nicht mehr erlaubt (abgemeldet, Opt-out, andere IP): verwerfen, zaehlt nicht in plaus_bad
		$tg = $tgt[$x['target']] ?? null; $ad = $allowed[$key][1];
		if($tg === null OR (int)$tg['active'] !== 1 OR ($tg['role'] === 'node' AND (int)$tg['measured'] !== 1) OR ($ad !== '' AND $ad !== $tg['ip' . $x['fam']])) { $why('not_allowed'); continue; }
		$used[$key] = ($used[$key] ?? 0) + 1;
		if($used[$key] > $allowed[$key][0]) { $why('too_many'); continue; }
		$checked++;
		$r = null;
		if($x['at'] < $R - 60 OR $x['at'] > $R + S64_ROUND + 60 OR $x['at'] > $now + S64_SKEW OR $R < $now - S64_BUFFER - 600) { $r = 'bad_time'; }
		elseif(s64_bad_values($x)) { $r = 'bad_values'; }
		elseif($x['method'] !== 'trace' AND $x['recv'] > 0 AND $n['lat'] !== null AND $n['lon'] !== null AND isset($coords[$x['target']])
			AND $x['min'] < s64_light_min_ms(s64_distance_km((float)$n['lat'], (float)$n['lon'], $coords[$x['target']][0], $coords[$x['target']][1])) - S64_LIGHT_TOL) { $r = 'below_light'; }
		elseif(!$isAnchor AND $x['method'] !== 'trace') {
			$k = $x['target'] . '|' . $x['fam'];
			$s = $smooth($x);
			$prev = $hist[$k] ?? array();
			if($s AND count($prev) >= S64_SMOOTH_N - 1 AND !in_array(false, array_slice($prev, 0, S64_SMOOTH_N - 1), true)) { $r = 'too_smooth'; }
			array_unshift($prev, $s);
			$hist[$k] = array_slice($prev, 0, S64_SMOOTH_N);
		}
		if($r !== null) {
			$why($r);
			// below_light gegen ein Ziel mit unsicherem Standort (new/stable) kann auch am Ziel liegen (falscher Punkt auf der
			// Karte): dann zaehlt es weder in plaus_bad noch fuer die Abstufung, damit ein Ziel ehrliche Messende nicht abstufen kann
			if($r === 'below_light' AND !$coords[$x['target']][2]) { $soft++; }
			elseif(in_array($r, S64_SUSPECT, true)) { $bad[] = $r; }
			if(!in_array($r, S64_STORE_BAD, true) OR $x['method'] === 'trace') { continue; }
		}
		if($x['method'] === 'trace') {
			$traces[] = array(gmdate('Y-m-d H:i:s', $R), $n['node_id'], $x['target'], $x['fam'], s64_dt($x['at']), s64_json($x['hops']));
			continue;
		}
		// Anker erreicht einen Knoten (gueltig, Adresse laut Plan = aktuelle): Weg sofort hochstufen (udp vor icmp)
		if($isAnchor AND $r === null AND $x['recv'] > 0 AND $tg['role'] === 'node' AND $ad !== '' AND $tg['reach' . $x['fam']] !== 'udp' AND ($x['method'] === 'udp' OR $tg['reach' . $x['fam']] === 'none')) {
			$reachUp[$x['fam']][$x['method']][$x['target']] = true;
		}
		$rows[] = array(gmdate('Y-m-d H:i:s', $R), $n['node_id'], $x['target'], $x['fam'], $x['method'], $x['sent'], $x['recv'],
			round($x['min'], 3), round($x['avg'], 3), round($x['max'], 3), round($x['jitter'], 3), s64_dt($x['at']), $r === null ? 1 : 0, $r);
	}

	$accepted = 0; $dup = 0;
	$pdo->beginTransaction();
	try {
		$lock = q1("SELECT last_seq, last_report, trust FROM sonar_nodes WHERE id = :i FOR UPDATE", array('i' => $n['id']));
		$gap($lock);
		if($seq <= (int)$lock['last_seq']) { fail(409, 'replay', "Field 'report.seq' must be greater than the last accepted one.", array('last_seq' => (int)$lock['last_seq'])); }
		$ins = function(string $head, string $tuple, array $list) {
			$n = 0;
			foreach(array_chunk($list, 250) as $chunk) { $n += q($head . ' VALUES ' . implode(',', array_fill(0, count($chunk), $tuple)), array_merge(...$chunk))->rowCount(); }
			return $n;
		};
		$valid = array_values(array_filter($rows, fn($r) => $r[12] === 1));
		$invalid = array_values(array_filter($rows, fn($r) => $r[12] === 0));
		$head = 'INSERT IGNORE INTO sonar_results (`round`, src, dst, fam, method, sent, recv, min_ms, avg_ms, max_ms, jitter_ms, at, valid, reason)';
		$accepted = $ins($head, '(?,?,?,?,?,?,?,?,?,?,?,?,?,?)', $valid);
		$ins($head, '(?,?,?,?,?,?,?,?,?,?,?,?,?,?)', $invalid);
		$t = $ins('INSERT IGNORE INTO sonar_traces (`round`, src, dst, fam, at, hops)', '(?,?,?,?,?,?)', $traces);
		$dup = count($valid) - $accepted + count($traces) - $t;
		$accepted += $t;
		$ins('INSERT INTO sonar_inbound (node_id, from_short, fam, at, `count`)', '(?,?,?,?,?)', $inbound);
		$nbad = 0;
		foreach(S64_REASONS_BAD as $r) { $nbad += $reasons[$r] ?? 0; }
		$nbad -= $soft;
		$set = 'last_seq = :seq, last_report = :t, plaus_ok = plaus_ok + :ok, plaus_bad = plaus_bad + :bad, health = :h';
		$p = array('seq' => $seq, 't' => s64_dt($now), 'ok' => $accepted, 'bad' => $nbad, 'h' => s64_json($health), 'i' => $n['id']);
		if($health['version'] !== '') { $set .= ', version = :v'; $p['v'] = $health['version']; }
		if($health['mode'] !== '' AND ($health['mode'] === 'anchor') === $isAnchor) { $set .= ', mode = :m'; $p['m'] = $health['mode']; }
		q("UPDATE sonar_nodes set $set WHERE id = :i", $p);
		// Erreichbarkeit sofort (nur hochstufen; herabstufen bleibt beim Planer)
		foreach($reachUp as $fam => $byM) {
			foreach(array('udp', 'icmp') as $m) {
				foreach(array_chunk(array_keys($byM[$m] ?? array()), 500) as $chunk) {
					q("UPDATE sonar_nodes set reach$fam = '$m' WHERE role = 'node' AND active = 1 AND measured = 1 AND reach$fam " . ($m === 'udp' ? "!= 'udp'" : "= 'none'")
						. " AND node_id IN (" . implode(',', array_fill(0, count($chunk), '?')) . ")", $chunk);
				}
			}
		}
		// sofortige Abstufung bei Manipulationsverdacht (mehr als die Haelfte der geprueften Werte unmoeglich); Quarantaene macht Teil J
		$down = array('pillar' => 'trusted', 'trusted' => 'stable', 'stable' => 'new');
		if(count($bad) >= 3 AND count($bad) * 2 > $checked AND isset($down[$lock['trust']])) {
			q("UPDATE sonar_nodes set trust = :t WHERE id = :i", array('t' => $down[$lock['trust']], 'i' => $n['id']));
			q("INSERT INTO sonar_trust_log (node_id, at, `old`, `new`, reason) VALUES (:n, :t, :o, :w, :r)",
				array('n' => $n['node_id'], 't' => s64_dt($now), 'o' => $lock['trust'], 'w' => $down[$lock['trust']], 'r' => 'plaus_report ' . count($bad) . '/' . $checked));
		}
		$pdo->commit();
	} catch(Throwable $e) {
		if($pdo->inTransaction()) { $pdo->rollBack(); }
		throw $e;
	}
	if($dup > 0) { $reasons['duplicate'] = $dup; }
	ksort($reasons);
	ok(array('accepted' => $accepted, 'rejected' => array_sum($reasons), 'reasons' => (object)$reasons));
}, true); // Sonar-Token, prueft s64_auth

/** GET /sonar/inbound?since=: wer hat mich gemessen (aus den Ergebnissen bei ipv64), hoechstens 500, since <= 24 h zurueck. */
route('GET', '/sonar/inbound', function() {
	[, $n] = s64_node_auth();
	$now = microtime(true);
	$since = $now - 3600;
	if(($s = qp('since')) !== null AND $s !== '') {
		$since = s64_plan_time($s);
		if($since === null) { fail(400, 'invalid_parameter', "Query parameter 'since' must be an RFC 3339 timestamp."); }
	}
	$since = max($since, $now - 86400);
	$rows = qa("SELECT r.src, r.fam, r.method, r.sent, r.recv, r.avg_ms, r.at, s.name, s.asname4, s.asname6, s.place, s.trust
		FROM sonar_results r LEFT JOIN sonar_nodes s ON s.node_id = r.src WHERE r.dst = :d AND r.at >= :t AND r.valid = 1 ORDER BY r.at DESC LIMIT 500",
		array('d' => $n['node_id'], 't' => s64_dt($since)));
	ok(array_map(fn($r) => array('from' => $r['src'], 'name' => (string)$r['name'], 'asname' => (string)((int)$r['fam'] === 6 ? $r['asname6'] : $r['asname4']),
		'place' => (string)$r['place'], 'trust' => (string)$r['trust'], 'fam' => (int)$r['fam'], 'method' => $r['method'], 'avg' => round((float)$r['avg_ms'], 3),
		'loss' => (int)$r['sent'] > 0 ? round(1 - (int)$r['recv'] / (int)$r['sent'], 3) : 1.0, 'at' => s64_iso($r['at'], true)), $rows));
}, true); // Sonar-Token, prueft s64_auth

// ---------------------------------------------------------------- Oeffentlich (ohne Anmeldung)

route('GET', '/sonar/public/keys', function() {
	s64_public_rl();
	s64_public(array('keys' => s64_plan_keys()));
}, true);

/** GET /sonar/public/map: Knoten (online 30 min, ohne Quarantaene; Anker immer), Links (Mediane 60 min), offene Stoerungen. */
route('GET', '/sonar/public/map', function() {
	s64_public_rl();
	s64_public(s64_cache('map', 60, function() {
		$now = microtime(true);
		$nodes = array(); $anchors = array();
		foreach(s64_public_nodes() as $n) {
			$ls = s64_ts($n['last_seen']);
			if($n['role'] === 'anchor') { $anchors[] = $n['node_id']; }
			elseif($ls === null OR $ls < $now - S64_ONLINE) { continue; }
			$nodes[$n['node_id']] = $n;
		}
		$am = s64_anchor_ms($anchors, $now);
		$out = array();
		foreach($nodes as $id => $n) {
			$p = s64_pub_node($n, $now);
			$out[] = array('id' => $id, 'slug' => $p['slug'], 'name' => $p['name'], 'lat' => $p['lat'], 'lon' => $p['lon'], 'trust' => $p['trust'], 'role' => $p['role'],
				'asn' => $p['asn'], 'asname' => $p['asname'], 'access' => $p['access'], 'device' => $p['device'], 'online' => $p['online'],
				'anchor_ms' => (object)($am[$id] ?? array()));
		}
		$pairs = array();
		$st = q("SELECT src, dst, fam, avg_ms, sent, recv FROM sonar_results WHERE at >= :d AND valid = 1", array('d' => s64_dt($now - 3600)));
		while(($r = $st->fetch(PDO::FETCH_NUM)) !== false) {
			if(!isset($nodes[$r[0]], $nodes[$r[1]]) OR $nodes[$r[0]]['role'] === 'anchor' OR $nodes[$r[1]]['role'] === 'anchor') { continue; }
			$k = ($r[0] < $r[1] ? $r[0] . '|' . $r[1] : $r[1] . '|' . $r[0]) . '|' . $r[2];
			$x = &$pairs[$k];
			$x['n'] = ($x['n'] ?? 0) + 1; $x['s'] = ($x['s'] ?? 0) + (int)$r[4]; $x['r'] = ($x['r'] ?? 0) + (int)$r[5];
			if((int)$r[5] > 0) { $x['v'][] = (float)$r[3]; }
			unset($x);
		}
		uasort($pairs, fn($a, $b) => $b['n'] <=> $a['n']);
		$links = array();
		foreach(array_slice($pairs, 0, 2000, true) as $k => $x) {
			[$a, $b, $fam] = explode('|', $k);
			$med = s64_median($x['v'] ?? array());
			$links[] = array('a' => $a, 'b' => $b, 'fam' => (int)$fam, 'ms' => $med === null ? null : round($med, 1),
				'loss' => $x['s'] > 0 ? round(1 - $x['r'] / $x['s'], 3) : 1.0, 'n' => $x['n']);
		}
		return array('generated' => gmdate('Y-m-d\TH:i:s\Z', (int)$now), 'nodes' => $out, 'links' => $links,
			'outages' => array_map('s64_outage_out', qa("SELECT * FROM sonar_outages WHERE ended IS NULL ORDER BY started DESC LIMIT 200")));
	}));
}, true);

/** GET /sonar/public/nodes?trust=&asn=&q=: Teilnehmerliste (ohne Quarantaene). */
route('GET', '/sonar/public/nodes', function() {
	s64_public_rl();
	$trust = qp('trust', '');
	if($trust !== '' AND (!in_array($trust, S64_TRUST, true) OR $trust === 'quarantine')) { fail(400, 'invalid_parameter', "Query parameter 'trust' is invalid."); }
	$asn = qp('asn', '');
	if($asn !== '' AND (!ctype_digit($asn) OR strlen($asn) > 10)) { fail(400, 'invalid_parameter', "Query parameter 'asn' must be a number."); }
	$qs = mb_strtolower(mb_substr(qp('q', ''), 0, 32));
	$all = s64_cache('nodes', 60, function() {
		$now = microtime(true);
		return array_map(fn($n) => s64_pub_node($n, $now), s64_public_nodes());
	});
	$rank = array_flip(array('anchor', 'pillar', 'trusted', 'stable', 'new'));
	$list = array_values(array_filter($all, fn($p) => ($trust === '' || $p['trust'] === $trust) && ($asn === '' || $p['asn'] === (int)$asn || $p['asn6'] === (int)$asn)
		&& ($qs === '' || str_contains(mb_strtolower($p['name'] . ' ' . $p['asname'] . ' ' . $p['place']), $qs))));
	usort($list, fn($a, $b) => array($rank[$a['trust']] ?? 9, $a['name']) <=> array($rank[$b['trust']] ?? 9, $b['name']));
	s64_public(array_slice($list, 0, 2000));
}, true);

/** GET /sonar/public/node/{slug}: Knoten mit Verlauf (7 Tage Anker-Latenz je Stunde). */
route('GET', '/sonar/public/node/{slug}', function($p) {
	s64_public_rl();
	$slug = strtolower($p['slug']);
	// erst pruefen, dann zwischenspeichern: unbekannte Slugs legen keine Cache-Dateien an
	// Quarantaene wie in Karte und Liste nicht oeffentlich
	if(!preg_match('/^[a-z0-9-]{1,40}\z/', $slug) OR q1("SELECT id FROM sonar_nodes WHERE slug = :s AND active = 1 AND last_seen IS NOT NULL AND trust != 'quarantine'", array('s' => $slug)) === null) {
		fail(404, 'not_found', 'Node not found.');
	}
	$d = s64_cache('node:' . $slug, 60, function() use ($slug) {
		$now = microtime(true);
		$n = q1("SELECT * FROM sonar_nodes WHERE slug = :s AND active = 1 AND last_seen IS NOT NULL AND trust != 'quarantine'", array('s' => $slug));
		if($n === null) { return null; }
		$anchors = array_column(qa("SELECT node_id FROM sonar_nodes WHERE role = 'anchor' AND active = 1"), 'node_id');
		$hist = array();
		if($anchors !== array()) {
			$in = implode(',', array_fill(0, count($anchors), '?'));
			foreach(qa("SELECT dst, fam, hour, n, p50_ms, loss FROM sonar_pair_1h WHERE src = ? AND hour >= ? AND dst IN ($in) ORDER BY hour",
				array_merge(array($n['node_id'], gmdate('Y-m-d H:00:00', (int)$now - 7 * 86400)), $anchors)) as $h) {
				$hist[$h['dst']][] = array('hour' => s64_iso($h['hour']), 'fam' => (int)$h['fam'], 'ms' => round((float)$h['p50_ms'], 1), 'loss' => round((float)$h['loss'], 3), 'n' => (int)$h['n']);
			}
		}
		return s64_pub_node($n, $now) + array('anchor_ms' => (object)(s64_anchor_ms($anchors, $now, $n['node_id'])[$n['node_id']] ?? array()), 'history' => (object)$hist);
	});
	if($d === null) { fail(404, 'not_found', 'Node not found.'); }
	s64_public($d);
}, true);

/** GET /sonar/public/stats */
route('GET', '/sonar/public/stats', function() {
	s64_public_rl();
	s64_public(s64_cache('stats', 60, function() {
		$now = microtime(true);
		$by = array('new' => 0, 'stable' => 0, 'trusted' => 0, 'pillar' => 0, 'anchor' => 0);
		$active = 0; $total = 0; $anchors = 0; $asns = array(); $cells = array();
		foreach(s64_public_nodes() as $n) {
			$by[$n['trust']] = ($by[$n['trust']] ?? 0) + 1;
			if($n['role'] === 'anchor') { $anchors++; continue; }
			$total++;
			$ls = s64_ts($n['last_seen']);
			if($ls >= $now - S64_ONLINE) { $active++; }
			if($ls >= $now - 86400) {
				$a = $n['asn4'] ?? $n['asn6'];
				if($a !== null) { $asns[(int)$a] = true; }
				if($n['pub_lat'] !== null) { $cells[floor((float)$n['pub_lat'] * 2) . '|' . floor((float)$n['pub_lon'] * 2)] = true; }
			}
		}
		$m = (int)q1("SELECT count(*) c FROM sonar_results WHERE at >= :d AND valid = 1", array('d' => gmdate('Y-m-d 00:00:00', (int)$now)))['c'];
		return array('nodes_active' => $active, 'nodes_total' => $total, 'anchors' => $anchors, 'measurements_today' => $m,
			'providers' => count($asns), 'regions' => count($cells), 'by_trust' => $by);
	}));
}, true);

/** GET /sonar/public/top: zuverlaessigste (ab 7 Tagen dabei), laengste Teilnahme, je Provider. */
route('GET', '/sonar/public/top', function() {
	s64_public_rl();
	s64_public(s64_cache('top', 60, function() {
		$now = microtime(true);
		$list = array();
		foreach(s64_public_nodes() as $n) { if($n['role'] !== 'anchor') { $list[] = s64_pub_node($n, $now); } }
		$short = fn($p) => array('slug' => $p['slug'], 'name' => $p['name'], 'trust' => $p['trust'], 'asname' => $p['asname'], 'uptime30' => $p['uptime30'], 'since' => $p['since']);
		$rel = array_values(array_filter($list, fn($p) => strtotime($p['since']) <= $now - 7 * 86400));
		usort($rel, fn($a, $b) => array($b['uptime30'], $a['since']) <=> array($a['uptime30'], $b['since']));
		$long = $list;
		usort($long, fn($a, $b) => $a['since'] <=> $b['since']);
		$prov = array();
		foreach($list as $p) {
			if($p['asn'] === null) { continue; }
			$x = &$prov[$p['asn']];
			$x['asn'] = $p['asn']; $x['asname'] = $x['asname'] ?? $p['asname'];
			$x['nodes'] = ($x['nodes'] ?? 0) + 1; $x['online'] = ($x['online'] ?? 0) + ($p['online'] ? 1 : 0);
			if(!isset($x['best']) OR $p['uptime30'] > $x['best']['uptime30']) { $x['best'] = $short($p); }
			unset($x);
		}
		usort($prov, fn($a, $b) => array($b['nodes'], $a['asn']) <=> array($a['nodes'], $b['asn']));
		return array('reliable' => array_map($short, array_slice($rel, 0, 20)), 'longest' => array_map($short, array_slice($long, 0, 20)),
			'providers' => array_slice($prov, 0, 30));
	}));
}, true);

/** GET /sonar/public/matrix: Provider x Provider, Median der Stundenwerte (sonar_pair_1h) der letzten 24 h, hoechstens 20 Provider. */
route('GET', '/sonar/public/matrix', function() {
	s64_public_rl();
	s64_public(s64_cache('matrix', 60, function() {
		$now = microtime(true);
		$asn = array(); $cnt = array(); $names = array();
		foreach(s64_public_nodes() as $n) {
			if($n['role'] === 'anchor') { continue; }
			$asn[$n['node_id']] = array(4 => $n['asn4'] !== null ? (int)$n['asn4'] : null, 6 => $n['asn6'] !== null ? (int)$n['asn6'] : null);
			foreach(array(4, 6) as $f) {
				if($asn[$n['node_id']][$f] !== null) { $a = $asn[$n['node_id']][$f]; $cnt[$a] = ($cnt[$a] ?? 0) + 1; $names[$a] = $names[$a] ?? (string)$n["asname$f"]; }
			}
		}
		arsort($cnt);
		$top = array_slice(array_keys($cnt), 0, 20);
		$topSet = array_flip($top);
		$cells = array();
		$st = q("SELECT src, dst, fam, n, p50_ms FROM sonar_pair_1h WHERE hour >= :h", array('h' => gmdate('Y-m-d H:00:00', (int)$now - 86400)));
		while(($r = $st->fetch(PDO::FETCH_NUM)) !== false) {
			$f = (int)$r[2];
			$a = $asn[$r[0]][$f] ?? null; $b = $asn[$r[1]][$f] ?? null;
			if($a === null OR $b === null OR !isset($topSet[$a], $topSet[$b]) OR (int)$r[3] === 0) { continue; }
			$k = min($a, $b) . '|' . max($a, $b);
			$cells[$k]['v'][] = (float)$r[4];
			$cells[$k]['n'] = ($cells[$k]['n'] ?? 0) + (int)$r[3];
		}
		$out = array();
		foreach($cells as $k => $c) { [$a, $b] = explode('|', $k); $out[] = array('a' => (int)$a, 'b' => (int)$b, 'avg' => round(s64_median($c['v']), 1), 'n' => $c['n']); }
		return array('asns' => array_map(fn($a) => array('asn' => $a, 'name' => $names[$a] ?? ''), $top), 'cells' => $out);
	}));
}, true);

/** GET /sonar/public/outages?active=1: laufende (active=1) oder Stoerungen der letzten 30 Tage. */
route('GET', '/sonar/public/outages', function() {
	s64_public_rl();
	$act = qp('active', '') === '1';
	s64_public(s64_cache('outages:' . ($act ? 1 : 0), 60, fn() => array_map('s64_outage_out', $act
		? qa("SELECT * FROM sonar_outages WHERE ended IS NULL ORDER BY started DESC LIMIT 200")
		: qa("SELECT * FROM sonar_outages WHERE ended IS NULL OR started >= :d ORDER BY started DESC LIMIT 200", array('d' => s64_dt(microtime(true) - 30 * 86400))))));
}, true);
