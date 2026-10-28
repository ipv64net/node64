<?php
/**
 * IPv64.net API v2 – Honeypot64 (Pfade /honeypot/...), Phase H2. Wird von api_v2.php vor dispatch() eingebunden:
 *     require __DIR__ . '/api_v2_honeypot.php';
 * Sensoren (Node64, Modul honeypot oder Modus ohne Oberflaeche) melden alle 10 Minuten mit dem API-Key des Accounts.
 * Vertrag (Format schema 1, Antwortcodes, Grenzen): internal/honeypot/report_types.go im Node64-Repo.
 * Tabellen hp_* (deploy/sql/honeypot.sql), alle Zeiten UTC. Planung: docs/PLAN-NODE64-HONEYPOT64.md.
 *
 *   POST /honeypot/reports   Meldung annehmen (gzip erlaubt, hoechstens 2 MiB entpackt)
 *   GET  /honeypot/sensors   eigene Sensoren mit Beitrag 24 h / 7 d
 *   GET  /honeypot/stats     eigener Beitrag: Ereignisse, Quell-IPs, Top-Arten, Top-Ports, Verlauf 7 Tage
 *
 * Proben zaehlen zusaetzlich je Account (hp_sample_contrib, H4: deploy/sql/honeypot_h4_stats.sql).
 * H6: samples.fingerprints (JA4/HASSH) -> hp_samples_fps + hp_sample_contrib kind fp (deploy/sql/honeypot_h6.sql); am Ende
 * dieser Datei werden die H6-Endpunkte eingebunden (api_v2_threat_passwords.php, api_v2_threat_feed.php).
 * Die IP des Sensors (aus der Verbindung) wird nur intern gespeichert, nie ausgegeben; Meldungen ueber eigene IPs
 * (dieser Sensor und alle Sensoren des Accounts) sowie private/reservierte Adressen werden verworfen.
 */

const HP_MAX_BODY     = 2097152;  // 2 MiB entpackt (und gepackt)
const HP_MAX_SOURCES  = 5000;     // ReportMaxSources
const HP_MAX_SAMPLES  = 500;      // ReportMaxSamples je Probenart
const HP_MAX_BACK     = 612000;   // period.start hoechstens 7 Tage + 2 h zurueck (Nachholen aus dem Puffer)
const HP_MAX_PERIOD   = 604800;   // Zeitraum hoechstens 7 Tage
const HP_CLOCK_SKEW   = 300;      // Zeiten duerfen 5 min in der Zukunft liegen
const HP_MIN_GAP      = 120;      // hoechstens eine Meldung je Sensor in 2 Minuten
const HP_MAX_SENSORS  = 50;       // Sensoren je Account, nur falls honeypot/hp_limits_lib.php fehlt (H5: Limit je Klasse)
const HP_ONLINE       = 1800;     // online = Meldung in den letzten 30 Minuten
const HP_MAX_TEXT     = 256;      // MaxText (Benutzer, Passwort, User-Agent, Detail)
const HP_MAX_PATH     = 1024;     // MaxPath
const HP_MAX_PAYLOAD  = 256;      // MaxPayload (Bytes)
const HP_CHUNK        = 250;      // Zeilen je INSERT

// Feste Einteilung (types.go, Kind*/Svc*); dazu die im Plan (Abschnitt 1/3) angekuendigten Arten und Dienste fuer
// spaetere Stufen, damit neue Sensoren nicht abgewiesen werden. Unbekannte Werte: Quelle wird verworfen und gezaehlt.
const HP_KINDS = array('ssh:bruteforce', 'telnet:bruteforce', 'http:bruteforce', 'http:exploit', 'http:exploit:sqli', 'http:exploit:xss',
	'http:exploit:traversal', 'http:exploit:rce', 'http:exploit:jndi', 'http:exploit:log4shell', 'http:exploit:ssrf', 'http:exploit:upload', 'http:scan',
	'http:bad-useragent', 'generic:portscan', 'generic:probe', 'scanner:research',
	'rdp:bruteforce', 'mail:auth-bruteforce', 'db:bruteforce', 'vpn:bruteforce');
const HP_SERVICES = array('ssh', 'telnet', 'http', 'https', 'tcp', 'scan',
	'ftp', 'smtp', 'pop3', 'imap', 'rdp', 'mysql', 'mssql', 'postgres', 'redis', 'mongodb', 'elasticsearch', 'docker', 'kubernetes', 'mqtt', 'vnc', 'sip', 'udp', 'vpn');
const HP_SOURCES  = array('honeypot', 'log', 'syslog');
// Neue Arten/Dienste spaeterer Sensor-Versionen werden angenommen, wenn sie dem Muster folgen (kein Upload je neuem Dienst)
const HP_KIND_RE    = '/^[a-z][a-z0-9-]{0,15}:[a-z][a-z0-9-]{0,23}(:[a-z0-9-]{1,24})?$/';
const HP_SERVICE_RE = '/^[a-z][a-z0-9-]{0,15}$/';
const HP_FP_RE      = '/^(ja4:[a-z0-9_]{1,64}|hassh:[0-9a-f]{32})$/D'; // H6: Fingerabdruck, sonst verworfen und gezaehlt
const HP_PROFILES = array('minimal', 'standard', 'full', 'custom', 'proxy'); // proxy: nur ueber PROXY64 (Voreinstellung seit Honeypot64 0.11.0)
const HP_MODES    = array('module', 'headless');

// ---------------------------------------------------------------- Hilfen

function hp_dt(int $ts): string { return gmdate('Y-m-d H:i:s', $ts); }

/** Liste (0..n-1)? Wie array_is_list, das erst ab PHP 8.1 da ist. */
function hp_is_list(array $a): bool { return $a === array() || array_keys($a) === range(0, count($a) - 1); }

/** DB-Zeit (UTC) -> ISO 8601 */
function hp_iso($s): ?string {
	if($s === null OR $s === '' OR str_starts_with((string)$s, '0000')) { return null; }
	try { $d = new DateTime((string)$s, new DateTimeZone('UTC')); return $d->format('Y-m-d\TH:i:s\Z'); }
	catch(Throwable $e) { return null; }
}

/** Ungueltige Meldung: 422 (der Sensor verwirft sie und zaehlt). */
function hp_bad(string $field, string $detail): void { fail(422, 'invalid_report', $detail, array('field' => $field)); }

/** RFC 3339 (wie Go time.Time, bis Nanosekunden) -> Unix-Sekunden (abgerundet). */
function hp_time($v, string $field): int {
	if(!is_string($v) OR !preg_match('/^(\d{4}-\d\d-\d\d)[Tt](\d\d:\d\d:\d\d)(\.\d{1,9})?([Zz]|[+-]\d\d:\d\d)$/', $v, $m)) { hp_bad($field, "Field '$field' must be an RFC 3339 timestamp."); }
	$d = DateTime::createFromFormat('!Y-m-d H:i:s', $m[1] . ' ' . $m[2], new DateTimeZone(strtoupper($m[4]) === 'Z' ? 'UTC' : $m[4]));
	if($d === false OR $d->format('Y-m-d H:i:s') !== $m[1] . ' ' . $m[2]) { hp_bad($field, "Field '$field' is not a valid time."); }
	return $d->getTimestamp();
}

function hp_int($v, string $field, int $min, int $max): int {
	if(!is_int($v) OR $v < $min OR $v > $max) { hp_bad($field, "Field '$field' must be an integer between $min and $max."); }
	return $v;
}

function hp_str($v, string $field, int $max, bool $empty = false): string {
	if(!is_string($v) OR (!$empty AND $v === '') OR mb_strlen($v) > $max) { hp_bad($field, "Field '$field' must be a string of " . ($empty ? 0 : 1) . " to $max characters."); }
	return $v;
}

/** 4-Byte-Zeichen ersetzen: die Verbindung laeuft mit SET NAMES 'utf8' (3 Byte). Hash immer ueber das Original. */
function hp_text(string $s): string { return (string)preg_replace('/[\x{10000}-\x{10FFFF}]/u', "\u{FFFD}", $s); }

/** Adresse in einem der Netze? */
function hp_in_nets(string $bin, array $nets): bool {
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
function hp_public_ip(string $bin): bool {
	static $v4 = array('0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
		'192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4');
	static $v6 = array('::/8', '64:ff9b::/96', '64:ff9b:1::/48', '100::/64', '2001::/23', '2001:db8::/32', '2002::/16', '3fff::/20', '5f00::/16',
		'fc00::/7', 'fe80::/10', 'fec0::/10', 'ff00::/8');
	if(strlen($bin) === 4) { return !hp_in_nets($bin, $v4); }
	return strlen($bin) === 16 && !hp_in_nets($bin, $v6) && hp_in_nets($bin, array('2000::/3'));
}

/** Rohen Body lesen: Content-Type JSON, optional gzip, hoechstens HP_MAX_BODY. Rueckgabe [JSON-Objekt, Bytes]. */
function hp_body(): array {
	if(!str_contains(strtolower((string)($_SERVER['CONTENT_TYPE'] ?? '')), 'application/json')) { fail(415, 'unsupported_media_type', 'Use Content-Type application/json.'); }
	$raw = file_get_contents('php://input', false, null, 0, HP_MAX_BODY + 1);
	if($raw === false OR $raw === '') { fail(400, 'invalid_json', 'Request body is empty.'); }
	if(strlen($raw) > HP_MAX_BODY) { fail(413, 'payload_too_large', 'Request body exceeds 2 MiB.'); }
	$enc = strtolower(trim((string)($_SERVER['HTTP_CONTENT_ENCODING'] ?? '')));
	if($enc === 'gzip' OR $enc === 'x-gzip') {
		// stueckweise entpacken: Grenze greift auch bei stark gepackten Daten (gzip-Bombe)
		$z = inflate_init(ZLIB_ENCODING_GZIP);
		$out = '';
		foreach(str_split($raw, 4096) as $part) {
			$o = @inflate_add($z, $part, ZLIB_SYNC_FLUSH);
			if($o === false) { fail(400, 'invalid_gzip', 'Request body is not valid gzip.'); }
			$out .= $o;
			if(strlen($out) > HP_MAX_BODY) { fail(413, 'payload_too_large', 'Request body exceeds 2 MiB after decompression.'); }
			if(inflate_get_status($z) === ZLIB_STREAM_END) { break; }
		}
		if(inflate_get_status($z) !== ZLIB_STREAM_END) { fail(400, 'invalid_gzip', 'Request body is not valid gzip (truncated).'); }
		$raw = $out;
	} elseif($enc !== '' AND $enc !== 'identity') {
		fail(415, 'unsupported_encoding', 'Content-Encoding must be gzip or identity.');
	}
	$b = json_decode($raw, true, 16);
	if(!is_array($b) OR hp_is_list($b)) { fail(400, 'invalid_json', 'Request body is not a valid JSON object.'); }
	return array($b, strlen($raw));
}

/**
 * Meldung pruefen und vereinheitlichen. Formfehler -> 422 fuer die ganze Meldung. Einzelne Quellen mit nicht
 * oeffentlicher IP, unbekannter Art/Dienst oder Zeiten ausserhalb des Zeitraums werden verworfen und gezaehlt
 * (eigene IPs erst beim Speichern, siehe hp_store).
 */
function hp_parse(array $b, int $now): array {
	if(($b['schema'] ?? null) !== 1) { fail(422, 'unsupported_schema', "Field 'schema' must be 1.", array('field' => 'schema')); }
	$s = $b['sensor'] ?? null;
	if(!is_array($s)) { hp_bad('sensor', "Field 'sensor' must be an object."); }
	$sid = strtolower((string)(is_string($s['id'] ?? null) ? $s['id'] : ''));
	if(!preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $sid)) { hp_bad('sensor.id', "Field 'sensor.id' must be a UUID."); }
	$ver = $s['version'] ?? null;
	if(!is_string($ver) OR !preg_match('/^[0-9A-Za-z][0-9A-Za-z.+_~-]{0,31}$/', $ver)) { hp_bad('sensor.version', "Field 'sensor.version' is invalid."); }
	if(!in_array($s['profile'] ?? null, HP_PROFILES, true)) { hp_bad('sensor.profile', "Field 'sensor.profile' must be one of " . implode(', ', HP_PROFILES) . "."); }
	if(!in_array($s['mode'] ?? null, HP_MODES, true)) { hp_bad('sensor.mode', "Field 'sensor.mode' must be one of " . implode(', ', HP_MODES) . "."); }
	// Standort (nur Live-Karte): fehlt oder ungueltig = automatisch, die Meldung wird deshalb nicht abgewiesen
	$cc = (is_string($s['country'] ?? null) AND preg_match('/^[A-Z]{2}\z/', $s['country']) AND $s['country'] !== 'ZZ') ? $s['country'] : null;

	$p = $b['period'] ?? null;
	if(!is_array($p)) { hp_bad('period', "Field 'period' must be an object."); }
	$start = hp_time($p['start'] ?? null, 'period.start');
	$end = hp_time($p['end'] ?? null, 'period.end');
	if($end <= $start) { hp_bad('period', 'period.end must be after period.start.'); }
	if($end > $now + HP_CLOCK_SKEW) { hp_bad('period.end', 'period.end lies in the future (check the clock of the sensor).'); }
	if($end - $start > HP_MAX_PERIOD) { hp_bad('period', 'The period must not exceed 7 days.'); }
	if($start < $now - HP_MAX_BACK) { hp_bad('period.start', 'period.start is more than 7 days ago.'); }

	$rid = is_string($b['report_id'] ?? null) ? strtolower($b['report_id']) : '';
	if($rid !== $sid . '-' . $start) { hp_bad('report_id', "Field 'report_id' must be <sensor.id>-<period.start unix>."); }
	$dropped = array_key_exists('dropped', $b) ? hp_int($b['dropped'], 'dropped', 0, PHP_INT_MAX) : 0;

	$src = $b['sources'] ?? null;
	if(!is_array($src) OR !hp_is_list($src)) { hp_bad('sources', "Field 'sources' must be an array."); }
	if(count($src) > HP_MAX_SOURCES) { fail(413, 'too_many_sources', 'At most ' . HP_MAX_SOURCES . ' sources per report.', array('field' => 'sources')); }
	$out = array(); $rej = array();
	foreach($src as $i => $x) {
		$f = "sources[$i]";
		if(!is_array($x)) { hp_bad($f, "$f must be an object."); }
		$ip = is_string($x['ip'] ?? null) ? $x['ip'] : '';
		$bin = (strlen($ip) <= 45 AND filter_var($ip, FILTER_VALIDATE_IP)) ? inet_pton($ip) : false;
		if($bin === false) { hp_bad("$f.ip", "$f.ip is not a valid IP address."); }
		$kind = $x['kind'] ?? null;
		if(!is_string($kind) OR !preg_match('/^[a-z0-9-]{1,16}(:[a-z0-9-]{1,16}){1,2}$/', $kind)) { hp_bad("$f.kind", "$f.kind is invalid."); }
		$svc = $x['service'] ?? null;
		if(!is_string($svc) OR !preg_match('/^[a-z0-9-]{1,16}$/', $svc)) { hp_bad("$f.service", "$f.service is invalid."); }
		$port = hp_int($x['port'] ?? null, "$f.port", 0, 65535);
		$cnt = hp_int($x['count'] ?? null, "$f.count", 1, 1000000000);
		$first = hp_time($x['first'] ?? null, "$f.first");
		$last = hp_time($x['last'] ?? null, "$f.last");
		if($first > $last) { hp_bad("$f.first", "$f.first is after $f.last."); }
		$source = $x['source'] ?? null;
		if(!is_string($source) OR !preg_match('/^[a-z]{1,16}$/', $source)) { hp_bad("$f.source", "$f.source is invalid."); }
		$rule = array_key_exists('rule', $x) ? hp_str($x['rule'], "$f.rule", 64, true) : '';
		if($rule !== '' AND !preg_match('/^[a-z0-9][a-z0-9_.\/:-]*(@\d{1,6})?$/i', $rule)) { hp_bad("$f.rule", "$f.rule is invalid."); }
		$detail = $x['detail'] ?? '';
		if(!is_string($detail)) { hp_bad("$f.detail", "$f.detail must be a string."); }
		$detail = mb_substr($detail, 0, HP_MAX_TEXT); // freier Text, nur kuerzen
		// verwerfen statt abweisen
		$why = null;
		if(!hp_public_ip($bin)) { $why = 'not_public'; }
		elseif(!in_array($kind, HP_KINDS, true) AND !preg_match(HP_KIND_RE, $kind)) { $why = 'unknown_kind'; }
		elseif(!in_array($svc, HP_SERVICES, true) AND !preg_match(HP_SERVICE_RE, $svc)) { $why = 'unknown_service'; }
		elseif(!in_array($source, HP_SOURCES, true)) { $why = 'unknown_source'; }
		elseif($first < $start - HP_CLOCK_SKEW OR $last > $end + HP_CLOCK_SKEW) { $why = 'out_of_period'; }
		if($why !== null) { $rej[$why] = ($rej[$why] ?? 0) + 1; continue; }
		$out[] = array('ip' => inet_ntop($bin), 'bin' => $bin, 'kind' => $kind, 'service' => $svc, 'port' => $port, 'count' => $cnt,
			'first' => $first, 'last' => $last, 'source' => $source, 'rule' => $rule, 'detail' => hp_text($detail));
	}

	$sm = $b['samples'] ?? array();
	if(!is_array($sm) OR ($sm !== array() AND hp_is_list($sm))) { hp_bad('samples', "Field 'samples' must be an object."); }
	$samples = array('credentials' => array(), 'paths' => array(), 'user_agents' => array(), 'payloads' => array());
	foreach(array_keys($samples) as $k) {
		$list = $sm[$k] ?? array();
		if(!is_array($list) OR !hp_is_list($list)) { hp_bad("samples.$k", "Field 'samples.$k' must be an array."); }
		if(count($list) > HP_MAX_SAMPLES) { fail(413, 'too_many_samples', "At most " . HP_MAX_SAMPLES . " entries in samples.$k.", array('field' => "samples.$k")); }
		foreach($list as $i => $x) {
			$f = "samples.{$k}[$i]";
			if(!is_array($x)) { hp_bad($f, "$f must be an object."); }
			$cnt = hp_int($x['count'] ?? null, "$f.count", 1, 1000000000);
			if($k === 'credentials') {
				$svc = $x['service'] ?? null;
				if(!is_string($svc) OR !preg_match('/^[a-z0-9-]{1,16}$/', $svc)) { hp_bad("$f.service", "$f.service is invalid."); }
				$user = hp_str($x['user'] ?? null, "$f.user", HP_MAX_TEXT, true);
				$pass = hp_str($x['pass'] ?? null, "$f.pass", HP_MAX_TEXT, true);
				if(!in_array($svc, HP_SERVICES, true) AND !preg_match(HP_SERVICE_RE, $svc)) { $rej['unknown_service'] = ($rej['unknown_service'] ?? 0) + 1; continue; }
				$samples[$k][] = array('hash' => hash('sha256', $svc . "\0" . $user . "\0" . $pass, true), 'service' => $svc, 'user' => $user, 'pass' => $pass, 'count' => $cnt);
			} elseif($k === 'payloads') {
				$sha = is_string($x['sha256'] ?? null) ? strtolower($x['sha256']) : '';
				if(!preg_match('/^[0-9a-f]{64}$/', $sha)) { hp_bad("$f.sha256", "$f.sha256 must be 64 hex characters."); }
				$head = is_string($x['head'] ?? null) ? $x['head'] : null;
				$raw = $head === null ? false : base64_decode($head, true);
				if($raw === false OR strlen($raw) > HP_MAX_PAYLOAD) { hp_bad("$f.head", "$f.head must be base64 of at most " . HP_MAX_PAYLOAD . " bytes."); }
				$svc = $x['service'] ?? null;
				if(!is_string($svc) OR !preg_match('/^[a-z0-9-]{1,16}$/', $svc)) { hp_bad("$f.service", "$f.service is invalid."); }
				$port = hp_int($x['port'] ?? null, "$f.port", 0, 65535);
				if(!in_array($svc, HP_SERVICES, true) AND !preg_match(HP_SERVICE_RE, $svc)) { $rej['unknown_service'] = ($rej['unknown_service'] ?? 0) + 1; continue; }
				$samples[$k][] = array('sha256' => $sha, 'head' => base64_encode($raw), 'service' => $svc, 'port' => $port, 'count' => $cnt);
			} else {
				$key = hp_str($x['key'] ?? null, "$f.key", $k === 'paths' ? HP_MAX_PATH : HP_MAX_TEXT);
				$samples[$k][] = array('hash' => hash('sha256', $key, true), 'key' => $key, 'count' => $cnt);
			}
		}
	}
	// H6: Fingerabdruecke (optional); Key nicht nach Muster -> verworfen und gezaehlt (invalid_fingerprint)
	$list = $sm['fingerprints'] ?? array();
	if(!is_array($list) OR !hp_is_list($list)) { hp_bad('samples.fingerprints', "Field 'samples.fingerprints' must be an array."); }
	if(count($list) > HP_MAX_SAMPLES) { fail(413, 'too_many_samples', "At most " . HP_MAX_SAMPLES . " entries in samples.fingerprints.", array('field' => 'samples.fingerprints')); }
	$samples['fingerprints'] = array();
	foreach($list as $i => $x) {
		$f = "samples.fingerprints[$i]";
		if(!is_array($x)) { hp_bad($f, "$f must be an object."); }
		$cnt = hp_int($x['count'] ?? null, "$f.count", 1, 1000000000);
		$key = $x['key'] ?? null;
		if(!is_string($key) OR !preg_match(HP_FP_RE, $key)) { $rej['invalid_fingerprint'] = ($rej['invalid_fingerprint'] ?? 0) + 1; continue; }
		$samples['fingerprints'][] = array('hash' => hash('sha256', $key, true), 'key' => $key, 'count' => $cnt);
	}
	return array('report_id' => $rid, 'sensor' => array('id' => $sid, 'version' => $ver, 'profile' => $s['profile'], 'mode' => $s['mode'], 'country' => $cc),
		'start' => $start, 'end' => $end, 'dropped' => $dropped, 'sources' => $out, 'samples' => $samples, 'rejected' => $rej);
}

/** Mehrzeiliges INSERT in Bloecken; $tuple = Platzhalter einer Zeile, z. B. "(?,?,?)". */
function hp_insert(string $head, string $tuple, array $rows, string $tail = ''): void {
	foreach(array_chunk($rows, HP_CHUNK) as $chunk) {
		q($head . ' VALUES ' . implode(',', array_fill(0, count($chunk), $tuple)) . ($tail !== '' ? ' ' . $tail : ''), array_merge(...$chunk));
	}
}

/** Gleiche Schluessel einer Meldung zusammenfassen (count addieren). */
function hp_merge(array $rows, callable $key): array {
	$m = array();
	foreach($rows as $r) { $k = $key($r); if(isset($m[$k])) { $m[$k]['count'] += $r['count']; } else { $m[$k] = $r; } }
	return array_values($m);
}

/** Meldung speichern (eine Transaktion). Rueckgabe: Antwort fuer den Sensor. */
function hp_store(array $r, int $bytes, int $now): array {
	global $pdo;
	$u = uid(); $sid = $r['sensor']['id']; $ip = client_ip();
	$day = gmdate('Y-m-d', $r['start']);
	$pdo->beginTransaction();
	try {
		q("INSERT IGNORE INTO hp_sensors (sensor_id, userid, first_seen) VALUES (:s, :u, :t)", array('s' => $sid, 'u' => $u, 't' => hp_dt($now)));
		$sen = q1("SELECT * FROM hp_sensors WHERE sensor_id = :s FOR UPDATE", array('s' => $sid));
		if(($dup = q1("SELECT id, period_end FROM hp_reports WHERE report_id = :r AND day = :d", array('r' => $r['report_id'], 'd' => $day))) !== null) {
			$pdo->rollBack();
			// period_end: gespeichertes Ende; ein laengerer Zeitraum mit derselben ID schickt den Rest danach neu
			return array(200, array('duplicate' => true, 'report_id' => $r['report_id'], 'period_end' => (int)strtotime($dup['period_end'] . ' UTC')));
		}
		if((int)$sen['disabled'] === 1) { fail(403, 'sensor_disabled', 'This sensor is disabled by ipv64.'); }
		if((int)$sen['userid'] !== $u OR $sen['last_seen'] === null) { // neu oder an einen anderen Account umgezogen
			// H5: Limit je Klasse (honeypot/hp_limits_lib.php: Standard 5, sonst 25), es zaehlen nur Sensoren mit Meldung in 30 Tagen
			if(is_file(__DIR__ . '/honeypot/hp_limits_lib.php')) { require_once __DIR__ . '/honeypot/hp_limits_lib.php'; }
			[$max, $act] = function_exists('hpl_sensor_limit') ? array(hpl_sensor_limit((int)($GLOBALS['ME']['user_class'] ?? 1)), HPL_SENSOR_ACTIVE) : array(HP_MAX_SENSORS, 3650 * 86400);
			$n = (int)q1("SELECT count(*) c FROM hp_sensors WHERE userid = :u AND sensor_id != :s AND last_seen >= :d", array('u' => $u, 's' => $sid, 'd' => hp_dt($now - $act)))['c'];
			if($n >= $max) { fail(403, 'sensor_limit', "At most $max active honeypot sensors per account (account class).", array('limit' => $max)); }
			if((int)$sen['userid'] !== $u) { q("UPDATE hp_sensors set userid = :u WHERE sensor_id = :s", array('u' => $u, 's' => $sid)); }
		}
		if($sen['last_seen'] !== null AND (int)$sen['userid'] === $u) {
			$wait = HP_MIN_GAP - ($now - strtotime($sen['last_seen'] . ' UTC'));
			if($wait > 0) {
				header('Retry-After: ' . $wait);
				fail(429, 'rate_limited', "At most one report per sensor every " . HP_MIN_GAP . " seconds. Retry in $wait seconds.", array('retry_after' => $wait));
			}
		}
		// eigene IPs: Verbindung dieses Sensors und letzte IPs aller Sensoren des Accounts
		$own = array();
		if(filter_var($ip, FILTER_VALIDATE_IP)) { $own[inet_pton($ip)] = true; }
		foreach(qa("SELECT DISTINCT last_ip FROM hp_sensors WHERE userid = :u AND last_ip != ''", array('u' => $u)) as $x) {
			if(filter_var($x['last_ip'], FILTER_VALIDATE_IP)) { $own[inet_pton($x['last_ip'])] = true; }
		}
		$rej = $r['rejected']; $src = array();
		foreach($r['sources'] as $x) {
			if(isset($own[$x['bin']])) { $rej['own_ip'] = ($rej['own_ip'] ?? 0) + 1; continue; }
			$src[] = $x;
		}
		$smp = $r['samples'];
		$smp['credentials'] = hp_merge($smp['credentials'], fn($x) => $x['hash']);
		$smp['paths'] = hp_merge($smp['paths'], fn($x) => $x['hash']);
		$smp['user_agents'] = hp_merge($smp['user_agents'], fn($x) => $x['hash']);
		$smp['payloads'] = hp_merge($smp['payloads'], fn($x) => $x['sha256'] . '|' . $x['service'] . '|' . $x['port']);
		$smp['fingerprints'] = hp_merge($smp['fingerprints'], fn($x) => $x['hash']);
		$nsmp = count($smp['credentials']) + count($smp['paths']) + count($smp['user_agents']) + count($smp['payloads']) + count($smp['fingerprints']);
		$overlap = ($sen['last_period_end'] !== null AND (int)$sen['userid'] === $u AND $r['start'] < strtotime($sen['last_period_end'] . ' UTC')) ? 1 : 0;

		q("INSERT INTO hp_reports (day, report_id, sensor_id, userid, schema_version, version, period_start, period_end, received_at, sources, rejected, dropped, samples, overlap, ip, bytes)
			VALUES (:d, :r, :s, :u, 1, :v, :ps, :pe, :t, :n, :rj, :dr, :sm, :o, :ip, :b)",
			array('d' => $day, 'r' => $r['report_id'], 's' => $sid, 'u' => $u, 'v' => $r['sensor']['version'], 'ps' => hp_dt($r['start']), 'pe' => hp_dt($r['end']),
				't' => hp_dt($now), 'n' => count($src), 'rj' => array_sum($rej), 'dr' => $r['dropped'], 'sm' => $nsmp, 'o' => $overlap, 'ip' => $ip, 'b' => $bytes));
		$ref = (int)$pdo->lastInsertId();

		hp_insert("INSERT INTO hp_report_sources (day, report_ref, userid, sensor_id, ip, ip_bin, kind, service, port, `count`, first_seen, last_seen, source, rule, detail)",
			'(?,?,?,?,?,UNHEX(?),?,?,?,?,?,?,?,?,?)',
			array_map(fn($x) => array($day, $ref, $u, $sid, $x['ip'], bin2hex($x['bin']), $x['kind'], $x['service'], $x['port'], $x['count'], hp_dt($x['first']), hp_dt($x['last']), $x['source'], $x['rule'], $x['detail']), $src));

		$daily = array();
		foreach($src as $x) {
			$k = gmdate('Y-m-d', $x['last']) . '|' . $x['kind'] . '|' . $x['service'] . '|' . $x['port'];
			if(!isset($daily[$k])) { $daily[$k] = array(gmdate('Y-m-d', $x['last']), $u, $sid, $x['kind'], $x['service'], $x['port'], 0, 0); }
			$daily[$k][6] += $x['count']; $daily[$k][7]++;
		}
		hp_insert("INSERT INTO hp_daily (day, userid, sensor_id, kind, service, port, events, sources)", '(?,?,?,?,?,?,?,?)', array_values($daily),
			'ON DUPLICATE KEY UPDATE events = events + VALUES(events), sources = sources + VALUES(sources)');

		// Proben: Tag = Ende des Zeitraums (exklusiv), laufende Summen
		$sday = gmdate('Y-m-d', min($r['end'], $now) - 1); $ts = hp_dt($now);
		$upd = 'ON DUPLICATE KEY UPDATE `count` = `count` + VALUES(`count`), last_seen = VALUES(last_seen)';
		hp_insert("INSERT INTO hp_samples_creds (day, key_hash, service, username, password, pass_sha1, `count`, last_seen)", '(?,UNHEX(?),?,?,?,?,?,?)',
			array_map(fn($x) => array($sday, bin2hex($x['hash']), $x['service'], hp_text($x['user']), hp_text($x['pass']), sha1($x['pass']), $x['count'], $ts), $smp['credentials']), $upd);
		hp_insert("INSERT INTO hp_samples_paths (day, key_hash, path, `count`, last_seen)", '(?,UNHEX(?),?,?,?)',
			array_map(fn($x) => array($sday, bin2hex($x['hash']), hp_text($x['key']), $x['count'], $ts), $smp['paths']), $upd);
		hp_insert("INSERT INTO hp_samples_uas (day, key_hash, user_agent, `count`, last_seen)", '(?,UNHEX(?),?,?,?)',
			array_map(fn($x) => array($sday, bin2hex($x['hash']), hp_text($x['key']), $x['count'], $ts), $smp['user_agents']), $upd);
		hp_insert("INSERT INTO hp_samples_payloads (day, sha256, service, port, head_b64, `count`, last_seen)", '(?,?,?,?,?,?,?)',
			array_map(fn($x) => array($sday, $x['sha256'], $x['service'], $x['port'], $x['head'], $x['count'], $ts), $smp['payloads']), $upd);
		hp_insert("INSERT INTO hp_samples_fps (day, key_hash, fp, `count`, last_seen)", '(?,UNHEX(?),?,?,?)',
			array_map(fn($x) => array($sday, bin2hex($x['hash']), $x['key'], $x['count'], $ts), $smp['fingerprints']), $upd);
		// H4: Beitrag je Account (Listen/Ranglisten nur ab mehreren Accounts, deploy/sql/honeypot_h4_stats.sql)
		$con = array();
		foreach(array('cred' => 'credentials', 'path' => 'paths', 'ua' => 'user_agents', 'fp' => 'fingerprints') as $ck => $sk) {
			foreach($smp[$sk] as $x) { $con[] = array($ck, $sday, bin2hex($x['hash']), $u, $x['count']); }
		}
		$pl = array();
		foreach($smp['payloads'] as $x) { $pl[$x['sha256']] = ($pl[$x['sha256']] ?? 0) + $x['count']; }
		foreach($pl as $sha => $c) { $con[] = array('payload', $sday, $sha, $u, $c); }
		hp_insert("INSERT INTO hp_sample_contrib (kind, day, key_hash, userid, cnt)", '(?,?,UNHEX(?),?,?)', $con, 'ON DUPLICATE KEY UPDATE cnt = cnt + VALUES(cnt)');

		q("UPDATE hp_sensors set version = :v, profile = :p, mode = :m, country = :cc, last_seen = :t, last_ip = :ip, last_report_id = :r, reports = reports + 1,
			last_period_end = IF(last_period_end IS NULL OR last_period_end < :pe, :pe2, last_period_end) WHERE sensor_id = :s",
			array('v' => $r['sensor']['version'], 'p' => $r['sensor']['profile'], 'm' => $r['sensor']['mode'], 'cc' => $r['sensor']['country'], 't' => hp_dt($now), 'ip' => $ip,
				'r' => $r['report_id'], 'pe' => hp_dt($r['end']), 'pe2' => hp_dt($r['end']), 's' => $sid));
		$pdo->commit();
	} catch(Throwable $e) {
		if($pdo->inTransaction()) { $pdo->rollBack(); }
		throw $e;
	}
	ksort($rej);
	return array(202, array('accepted' => count($src), 'rejected' => array_sum($rej), 'rejected_reasons' => (object)$rej, 'report_id' => $r['report_id']));
}

// ---------------------------------------------------------------- Routen

/** POST /honeypot/reports: Meldung eines Sensors (Format schema 1). */
route('POST', '/honeypot/reports', function() {
	$now = time();
	[$b, $bytes] = hp_body();
	$r = hp_parse($b, $now);
	[$status, $out] = hp_store($r, $bytes, $now);
	ok($out, $status);
});

/** GET /honeypot/sensors: eigene Sensoren (ohne IP), Beitrag 24 h / 7 d. */
route('GET', '/honeypot/sensors', function() {
	$u = uid(); $now = time();
	$agg = array();
	foreach(qa("SELECT sensor_id, COUNT(DISTINCT CASE WHEN last_seen >= :d1 THEN ip_bin END) s24, COUNT(DISTINCT ip_bin) s7,
		SUM(CASE WHEN last_seen >= :d2 THEN `count` ELSE 0 END) e24, SUM(`count`) e7
		FROM hp_report_sources WHERE userid = :u AND last_seen >= :d7 GROUP BY sensor_id",
		array('u' => $u, 'd1' => hp_dt($now - 86400), 'd2' => hp_dt($now - 86400), 'd7' => hp_dt($now - 7 * 86400))) as $x) { $agg[$x['sensor_id']] = $x; }
	ok(array_map(function($s) use ($agg, $now) {
		$a = $agg[$s['sensor_id']] ?? array();
		return array('id' => $s['sensor_id'], 'version' => $s['version'], 'profile' => $s['profile'], 'mode' => $s['mode'],
			'first_seen' => hp_iso($s['first_seen']), 'last_seen' => hp_iso($s['last_seen']),
			'online' => $s['last_seen'] !== null && strtotime($s['last_seen'] . ' UTC') >= $now - HP_ONLINE,
			'reports' => (int)$s['reports'], 'disabled' => (int)$s['disabled'] === 1,
			'sources_24h' => (int)($a['s24'] ?? 0), 'sources_7d' => (int)($a['s7'] ?? 0), 'events_24h' => (int)($a['e24'] ?? 0), 'events_7d' => (int)($a['e7'] ?? 0));
	}, qa("SELECT * FROM hp_sensors WHERE userid = :u AND last_seen IS NOT NULL ORDER BY last_seen DESC", array('u' => $u))));
});

/** GET /honeypot/stats: eigener Beitrag. */
route('GET', '/honeypot/stats', function() {
	$u = uid(); $now = time(); $from = gmdate('Y-m-d', $now - 6 * 86400);
	$t = q1("SELECT COUNT(DISTINCT CASE WHEN last_seen >= :d1 THEN ip_bin END) s24, COUNT(DISTINCT ip_bin) s7,
		COALESCE(SUM(CASE WHEN last_seen >= :d2 THEN `count` ELSE 0 END), 0) e24, COALESCE(SUM(`count`), 0) e7
		FROM hp_report_sources WHERE userid = :u AND last_seen >= :d7", array('u' => $u, 'd1' => hp_dt($now - 86400), 'd2' => hp_dt($now - 86400), 'd7' => hp_dt($now - 7 * 86400)));
	$s = q1("SELECT COUNT(*) n, COALESCE(SUM(last_seen >= :o), 0) online, COALESCE(SUM(last_seen >= :w), 0) active, MAX(last_seen) last FROM hp_sensors WHERE userid = :u AND last_seen IS NOT NULL",
		array('u' => $u, 'o' => hp_dt($now - HP_ONLINE), 'w' => hp_dt($now - 7 * 86400)));
	$kinds = qa("SELECT kind, SUM(events) e, SUM(sources) n FROM hp_daily WHERE userid = :u AND day >= :d GROUP BY kind ORDER BY e DESC LIMIT 10", array('u' => $u, 'd' => $from));
	$ports = qa("SELECT service, port, SUM(events) e, SUM(sources) n FROM hp_daily WHERE userid = :u AND day >= :d GROUP BY service, port ORDER BY e DESC LIMIT 10", array('u' => $u, 'd' => $from));
	$days = array();
	for($i = 6; $i >= 0; $i--) { $days[gmdate('Y-m-d', $now - $i * 86400)] = 0; }
	foreach(qa("SELECT day, SUM(events) e FROM hp_daily WHERE userid = :u AND day >= :d GROUP BY day", array('u' => $u, 'd' => $from)) as $x) {
		if(isset($days[$x['day']])) { $days[$x['day']] = (int)$x['e']; }
	}
	ok(array(
		'sensors' => (int)$s['n'], 'sensors_online' => (int)$s['online'], 'contributor' => (int)$s['active'] > 0, 'last_report' => hp_iso($s['last']),
		'events_24h' => (int)$t['e24'], 'events_7d' => (int)$t['e7'], 'sources_24h' => (int)$t['s24'], 'sources_7d' => (int)$t['s7'],
		'top_kinds' => array_map(fn($x) => array('kind' => $x['kind'], 'events' => (int)$x['e'], 'sources' => (int)$x['n']), $kinds),
		'top_ports' => array_map(fn($x) => array('service' => $x['service'], 'port' => (int)$x['port'], 'events' => (int)$x['e'], 'sources' => (int)$x['n']), $ports),
		'timeline' => array_map(fn($d, $e) => array('day' => $d, 'events' => $e), array_keys($days), array_values($days)),
	));
});

/**
 * GET /honeypot/list-token: persoenliches Listen-Token fuer den Live-Stand der v64 Blocklist (wie honeypot/token.php).
 * Fehlt es, wird es angelegt; ein vorhandenes bleibt unveraendert (kein Widerruf). Node64 holt es damit selbst ueber den
 * zentralen API-Key. live = Berechtigung jetzt (Klasse ausser Standard oder Beitragende/r, Sensor in 7 Tagen);
 * blocklists/live.php prueft sie bei jedem Abruf neu und liefert ohne Berechtigung den Tagesstand.
 */
route('GET', '/honeypot/list-token', function() {
	$u = uid(); $now = time();
	$tok = (string)(q1("SELECT token FROM hp_list_tokens WHERE userid = :u", array('u' => $u))['token'] ?? '');
	if(!preg_match('/^[A-Za-z0-9]{32}\z/', $tok)) {
		$a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'; $new = '';
		for($i = 0; $i < 32; $i++) { $new .= $a[random_int(0, 61)]; }
		q("INSERT INTO hp_list_tokens (userid, token, created_at, last_used, uses_window_start, uses_in_window) VALUES (:u, :t, :c, NULL, NULL, 0)
			ON DUPLICATE KEY UPDATE token = token", array('u' => $u, 't' => $new, 'c' => hp_dt($now)));
		$tok = (string)(q1("SELECT token FROM hp_list_tokens WHERE userid = :u", array('u' => $u))['token'] ?? '');
	}
	$live = (int)($GLOBALS['ME']['user_class'] ?? 1) !== 1
		|| q1("SELECT 1 x FROM hp_sensors WHERE userid = :u AND disabled = 0 AND last_seen >= :d LIMIT 1", array('u' => $u, 'd' => hp_dt($now - 7 * 86400))) !== null;
	ok(array('token' => $tok, 'live' => $live, 'base' => 'https://ipv64.net/blocklists/live/' . $tok . '/'));
});

// H6: weitere Endpunkte, ohne Aenderung an api_v2.php (dort ist nur diese Datei und die H3-H5-Dateien eingebunden)
foreach(array('api_v2_threat_passwords.php', 'api_v2_threat_feed.php') as $hpH6File) { if(is_file(__DIR__ . "/$hpH6File")) { require_once __DIR__ . "/$hpH6File"; } }
unset($hpH6File); // eingebunden im globalen Bereich von api_v2.php
if(is_file(__DIR__ . '/api_v2_sonar.php')) { require __DIR__ . '/api_v2_sonar.php'; } // Sonar64 (Pfade /sonar/...)
