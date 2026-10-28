<?php
/**
 * Sonar64 Ende-zu-Ende (Integration aller Teile): echte sonar64-Knoten und ein Anker gegen API, Planer und Jobs in der
 * Testumgebung s64e* (run_agentbox.sh). Jede Phase gibt "ok"/"FEHLER"-Zeilen aus; run_agentbox.sh zaehlt sie.
 *
 *   S64E=1 S64E_DB=<db> php e2e.php <phase> [<arg>]
 *     setup                  Plan-Schluessel, Anker-Token (CLI), Knoten-Token (POST /sonar/tokens); Token nur in /w/sec
 *     registered             warten, bis Anker und Knoten angemeldet sind; Standorte setzen
 *     evil1 | evil2          gefaelschter Knoten (eigener Container): anmelden | Plan pruefen, Manipulation melden
 *     wait <anchors|pair>    warten auf Ergebnisse Knoten<->Anker bzw. Knoten->Knoten (udp)
 *     final                  Gesamtpruefung: Plan befolgt, Grenzen, Plausibilitaet, Jobs, oeffentliche Karte, Mini-Status
 */
if(php_sapi_name() !== 'cli' OR getenv('S64E') !== '1') { exit; }

const WEB  = '/var/www/clients/client1/web58/web';
const SEC  = '/w/sec';                                // Token und Schluessel (nur Testwerte, nie ausgegeben)
const API  = 'http://11.64.64.2:8080/api_v2.php';     // aus dem Docker-Netz (Knoten-IPs sind "oeffentlich")
const LOC  = 'http://127.0.0.1:8080/api_v2.php';      // im API-Container (fuer /sonar/tokens und public/*)
const K1   = 'TestKeyAccountOne000000000000001';      // users.apikey, Account 1 (tests/api/setup.sql)
const NET  = '11.64.64.';                             // Adressen der Knoten: duerfen nie oeffentlich erscheinen
// Alle Container laufen auf einer Box (RTT < 1 ms): die ehrlichen Knoten stehen deshalb wenige km neben dem Anker,
// sonst waeren ihre Werte physikalisch unmoeglich (below_light). Der Faelscher steht in Koeln (~390 km).
const LATLON = array('a_fsn' => array(50.47, 12.37), 'n1' => array(50.4831, 12.3517), 'n2' => array(50.4562, 12.3988), 'evil' => array(50.9400, 6.9500));

$phase = $argv[1] ?? '';
$pass = 0; $failed = 0;

function check(string $name, bool $ok, $info = ''): void {
	global $pass, $failed;
	if($ok) { $pass++; echo "  ok    $name\n"; }
	else { $failed++; echo "  FEHLER $name " . (is_string($info) ? $info : json_encode($info, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)) . "\n"; }
}
function req(string $base, string $method, string $path, ?string $body = null, ?string $tok = null): array {
	$h = array();
	if($tok !== null) { $h[] = 'Authorization: Bearer ' . $tok; }
	if($body !== null) { $h[] = 'Content-Type: application/json'; }
	$ctx = stream_context_create(array('http' => array('method' => $method, 'header' => implode("\r\n", $h), 'content' => $body ?? '',
		'ignore_errors' => true, 'timeout' => 60)));
	$raw = @file_get_contents($base . $path, false, $ctx);
	$code = 0; $hdr = array();
	foreach($http_response_header ?? array() as $l) {
		if(preg_match('#^HTTP/\S+\s+(\d{3})#', $l, $m)) { $code = (int)$m[1]; }
		elseif(str_contains($l, ':')) { [$k, $v] = explode(':', $l, 2); $hdr[strtolower(trim($k))] = trim($v); }
	}
	return array('code' => $code, 'h' => $hdr, 'j' => json_decode((string)$raw, true), 'raw' => (string)$raw);
}
function code(array $r): string { return $r['code'] . ' ' . substr($r['raw'], 0, 300); }
function iso(float $t): string { return gmdate('Y-m-d\TH:i:s', (int)$t) . 'Z'; }
function sec_put(string $name, string $v): void { file_put_contents(SEC . '/' . $name, $v); chmod(SEC . '/' . $name, 0600); }
function sec_get(string $name): string { return trim((string)@file_get_contents(SEC . '/' . $name)); }
function db(): PDO {
	static $db = null;
	if($db === null) {
		require_once WEB . '/sonar/s64_lib.php';
		$db = s64_pdo();
		$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	}
	return $db;
}
function one(string $sql, array $p = array()) { $st = db()->prepare($sql); $st->execute($p); return $st->fetch(PDO::FETCH_ASSOC); }
function all(string $sql, array $p = array()): array { $st = db()->prepare($sql); $st->execute($p); return $st->fetchAll(PDO::FETCH_ASSOC); }
function cli(string $args): array { exec(escapeshellarg(PHP_BINARY) . ' ' . WEB . '/bots/' . $args . ' 2>&1', $out, $rc); return array($rc, implode("\n", $out)); }
function ids(): array { return json_decode(sec_get('ids.json'), true) ?: array(); }
function clear_cache(): void { foreach(glob(sys_get_temp_dir() . '/ipv64_s64_cache/*') ?: array() as $f) { @unlink($f); } }
function signed(array $report, string $sk): string {
	$r = json_encode($report, JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION);
	return '{"report":' . $r . ',"sig":"' . base64_encode(sodium_crypto_sign_detached($r, $sk)) . '"}';
}
function done(): void { global $pass, $failed; echo "== $pass ok, $failed Fehler\n"; exit($failed > 0 ? 1 : 0); }

// ---------------------------------------------------------------- setup
if($phase === 'setup') {
	[$rc, $out] = cli('sonar_keygen.php');
	check('keygen', $rc === 0 AND preg_match('/pubkey ([A-Za-z0-9+\/=]{44})/', $out, $m) === 1, $out);
	sec_put('plan.pub', $m[1] ?? '');
	$keys = req(LOC, 'GET', '/sonar/public/keys')['j']['data']['keys'] ?? array();
	check('public/keys liefert den Plan-Schluessel', ($keys[0]['pubkey'] ?? '') === ($m[1] ?? 'x'), $keys);
	[$rc, $out] = cli('sonar_anchor_token.php --name=fsn');
	check('Anker-Token per CLI', $rc === 0 AND preg_match('/^(s64a_[A-Za-z0-9]{40})$/m', $out, $t) === 1, 'rc ' . $rc);
	sec_put('a_fsn.env', 'SONAR64_TOKEN=' . ($t[1] ?? '') . "\n");
	foreach(array('n1', 'n2', 'evil') as $n) {
		$r = req(LOC, 'POST', '/sonar/tokens', json_encode(array('name' => $n)), K1);
		$tok = (string)($r['j']['data']['token'] ?? '');
		check("Knoten-Token $n per POST /sonar/tokens", in_array($r['code'], array(200, 201), true) AND preg_match('/^s64_[A-Za-z0-9]{40}$/', $tok) === 1, $r['code']);
		sec_put("$n.env", "SONAR64_TOKEN=$tok\n");
		sec_put("$n.tok", $tok);
	}
	done();
}

// ---------------------------------------------------------------- registered
if($phase === 'registered') {
	$want = array('a_fsn' => 'fsn', 'n1' => 'n1', 'n2' => 'n2');
	$ids = array('a_fsn' => 'a_fsn');
	for($i = 0; $i < 90; $i++) {
		$rows = all("SELECT t.name, n.node_id, n.role, n.trust, n.ip4, n.mode FROM sonar_tokens t JOIN sonar_nodes n ON n.token_id = t.id WHERE t.revoked_at IS NULL");
		$by = array(); foreach($rows as $r) { $by[$r['name']] = $r; }
		if(count(array_intersect_key($by, array_flip($want))) === 3) { break; }
		sleep(2);
	}
	foreach($want as $k => $name) {
		$r = $by[$name] ?? null;
		check("angemeldet: $k", $r !== null, array_keys($by));
		if($r === null) { continue; }
		$ids[$k] = $r['node_id'];
		check("$k: IP aus der Verbindung (" . ($k === 'a_fsn' ? 'Anker' : 'Knoten') . ')', str_starts_with((string)$r['ip4'], NET), $r['ip4']);
		check("$k: Modus", $r['mode'] === ($k === 'a_fsn' ? 'anchor' : 'headless'), $r['mode']);
	}
	check('Anker-ID a_fsn, Stufe anchor', ($by['fsn']['node_id'] ?? '') === 'a_fsn' AND ($by['fsn']['trust'] ?? '') === 'anchor');
	check('Knoten-ID Format', preg_match('/^n[a-z0-9]{11}$/', $ids['n1'] ?? '') === 1 AND preg_match('/^n[a-z0-9]{11}$/', $ids['n2'] ?? '') === 1, $ids);
	check('n1 gemessen, n2 nur ausgehend', (int)one("SELECT measured FROM sonar_nodes WHERE node_id = ?", array($ids['n1'] ?? ''))['measured'] === 1
		AND (int)one("SELECT measured FROM sonar_nodes WHERE node_id = ?", array($ids['n2'] ?? ''))['measured'] === 0);
	[$rc, $out] = cli('sonar_anchor_token.php --name=fsn --lat=50.47 --lon=12.37 --place=Falkenstein');
	check('Anker-Standort per CLI', $rc === 0, $out);
	// Standort der Knoten wie "Mein Knoten" (me.php) bzw. PUT /sonar/me: genau + verschleiert
	foreach(array('n1', 'n2') as $k) {
		if(!isset($ids[$k])) { continue; }
		$n = one("SELECT jitter_seed FROM sonar_nodes WHERE node_id = ?", array($ids[$k]));
		[$la, $lo] = LATLON[$k]; $p = s64_pub_coords($la, $lo, (int)$n['jitter_seed']);
		db()->prepare("UPDATE sonar_nodes SET lat = ?, lon = ?, pub_lat = ?, pub_lon = ?, access = 'fiber', place = ? WHERE node_id = ?")
			->execute(array($la, $lo, $p[0], $p[1], $k === 'n1' ? 'Falkenstein' : 'Ellefeld', $ids[$k]));
	}
	sec_put('ids.json', json_encode($ids));
	done();
}

// ---------------------------------------------------------------- evil (eigener Container, nur HTTP)
if($phase === 'evil1') {
	$tok = sec_get('evil.tok');
	$kp = sodium_crypto_sign_keypair();
	sec_put('evil.key', base64_encode(sodium_crypto_sign_secretkey($kp)));
	$r = req(API, 'POST', '/sonar/register', json_encode(array('pubkey' => base64_encode(sodium_crypto_sign_publickey($kp)), 'version' => '0.1.0', 'mode' => 'headless')), $tok);
	check('Faelscher angemeldet', $r['code'] === 201, code($r));
	sec_put('evil.id', (string)($r['j']['data']['node_id'] ?? ''));
	done();
}
if($phase === 'evil-coords') {
	$id = sec_get('evil.id');
	db()->prepare("UPDATE sonar_nodes SET lat = ?, lon = ?, pub_lat = ?, pub_lon = ? WHERE node_id = ?")->execute(array(50.94, 6.95, 50.945, 6.955, $id));
	check('Faelscher Standort Koeln', one("SELECT lat FROM sonar_nodes WHERE node_id = ?", array($id))['lat'] == 50.94);
	done();
}
if($phase === 'evil2') {
	$tok = sec_get('evil.tok'); $sk = base64_decode(sec_get('evil.key')); $id = sec_get('evil.id'); $ids = ids();
	$r = req(API, 'GET', '/sonar/plan', null, $tok);
	check('Faelscher bekommt einen Plan', $r['code'] === 200, code($r));
	$sp = $r['j']['data'] ?? array();
	// Signatur ueber die exakten Bytes von "plan" (wie der Kern): aus dem rohen Body schneiden
	$rawPlan = preg_match('/"plan":(\{.*\}),"kid"/s', $r['raw'], $m) ? $m[1] : '';
	$pub = base64_decode(sec_get('plan.pub'));
	$sigOk = $rawPlan !== '' AND strlen($pub) === 32 AND sodium_crypto_sign_verify_detached(base64_decode((string)($sp['sig'] ?? '')), $rawPlan, $pub);
	check('Plan mit dem Plan-Schluessel signiert (Ed25519)', $sigOk, substr($r['raw'], 0, 200));
	check('gefaelschte Plan-Signatur faellt durch', !sodium_crypto_sign_verify_detached(base64_decode((string)($sp['sig'] ?? '')), $rawPlan . ' ', $pub));
	$plan = json_decode($rawPlan, true) ?: array();
	check('Plan fuer genau diesen Knoten', ($plan['node_id'] ?? '') === $id);
	// gemeldet wird die laufende Runde (ein neuer Plan beginnt erst mit der naechsten; Anker sind auf dem 5-min-Raster
	// immer erlaubt), nicht geplante Ziele fallen als not_in_plan heraus
	$now = time(); $R = intdiv($now, 300) * 300; $anc = null;
	foreach($plan['rounds'] ?? array() as $rd) { foreach($rd['targets'] as $t) { if($t['id'] === 'a_fsn' AND $t['method'] !== 'trace') { $anc = $t; } } }
	check('Anker a_fsn im Plan', $anc !== null, $plan['rounds'] ?? null);
	check('Plan: 6 Runden auf dem 5-min-Raster', count($plan['rounds'] ?? array()) >= 6 AND !array_filter($plan['rounds'], fn($rd) => strtotime($rd['start']) % 300 !== 0), array_column($plan['rounds'] ?? array(), 'start'));
	$tids = array(); foreach($plan['rounds'] ?? array() as $rd) { foreach($rd['targets'] as $t) { $tids[$t['id']] = true; } }
	check('Plan: nicht sich selbst, nie Knoten "nur ausgehend"', !isset($tids[$id]) AND !isset($tids[$ids['n2'] ?? 'x']), array_keys($tids));
	$m1 = $anc['method'] ?? 'icmp'; $m2 = $m1 === 'icmp' ? 'udp' : 'icmp';
	$at = iso($now);
	$res = array(
		// 0,5 ms von Koeln nach Falkenstein (~390 km, Licht >= 3,9 ms): geschoent
		array('round' => iso($R), 'target' => 'a_fsn', 'fam' => 4, 'method' => $m1, 'sent' => 5, 'recv' => 5, 'min' => 0.4, 'avg' => 0.5, 'max' => 0.6, 'jitter' => 0.1, 'at' => $at),
		// recv > sent
		array('round' => iso($R), 'target' => 'a_fsn', 'fam' => 4, 'method' => $m2, 'sent' => 5, 'recv' => 6, 'min' => 9.0, 'avg' => 10.0, 'max' => 11.0, 'jitter' => 0.5, 'at' => $at),
		// Ziel nicht im Plan (n2 wird nie gemessen)
		array('round' => iso($R), 'target' => $ids['n2'] ?? 'nxxxxxxxxxxx', 'fam' => 4, 'method' => 'icmp', 'sent' => 5, 'recv' => 5, 'min' => 9.0, 'avg' => 10.0, 'max' => 11.0, 'jitter' => 0.5, 'at' => $at),
	);
	$seq = (int)floor(microtime(true) * 1000);
	$rep = array('v' => 1, 'node_id' => $id, 'seq' => $seq, 'sent' => $at, 'results' => $res,
		'health' => array('version' => '0.1.0', 'mode' => 'headless', 'uplink' => true, 'sent_today' => 15, 'budget' => 'sparsam', 'responder' => false));
	// veraenderte Meldung (Signatur passt nicht mehr)
	$body = signed($rep, $sk);
	$bad = str_replace('"avg":0.5', '"avg":5.5', $body);
	$r = req(API, 'POST', '/sonar/results', $bad, $tok);
	check('veraenderte Meldung abgelehnt (403 invalid_signature)', $r['code'] === 403 AND str_contains($r['raw'], 'invalid_signature'), code($r));
	$r = req(API, 'POST', '/sonar/results', $body, $tok);
	$d = $r['j']['data'] ?? array();
	check('Manipulation: Meldung angenommen, aber kein Ergebnis zaehlt', $r['code'] === 200 AND (int)($d['accepted'] ?? -1) === 0 AND (int)($d['rejected'] ?? 0) === 3, code($r));
	foreach(array('below_light', 'bad_values', 'not_in_plan') as $why) { check("Grund $why", (int)($d['reasons'][$why] ?? 0) >= 1, $d['reasons'] ?? null); }
	$r = req(API, 'POST', '/sonar/results', $body, $tok);
	check('sofortige Wiederholung 429 mit Retry-After', $r['code'] === 429 AND isset($r['h']['retry-after']), code($r));
	sleep(62);
	$r = req(API, 'POST', '/sonar/results', $body, $tok);
	check('Wiederholung derselben seq 409 replay', $r['code'] === 409 AND str_contains($r['raw'], 'replay'), code($r));
	done();
}

// ---------------------------------------------------------------- wait
if($phase === 'wait') {
	db(); $ids = ids(); $what = $argv[2] ?? '';
	$need = $what === 'anchors'
		? array(array('a_fsn', $ids['n1'], null), array($ids['n1'], 'a_fsn', null), array($ids['n2'], 'a_fsn', null))
		: array(array($ids['n2'], $ids['n1'], 'udp'));
	$t0 = time(); $miss = $need;
	while(time() - $t0 < ($what === 'pair' ? 2700 : 1200)) {
		$miss = array();
		foreach($need as [$s, $d, $m]) {
			$q = "SELECT COUNT(*) c FROM sonar_results WHERE src = ? AND dst = ? AND valid = 1 AND recv > 0" . ($m ? " AND method = ?" : '');
			if((int)one($q, $m ? array($s, $d, $m) : array($s, $d))['c'] === 0) { $miss[] = "$s->$d" . ($m ? "/$m" : ''); }
		}
		// n1 meldet die beantworteten Proben von n2 mit seiner naechsten Meldung
		if($what === 'pair' AND (int)one("SELECT COUNT(*) c FROM sonar_inbound WHERE node_id = ? AND from_short = ?", array($ids['n1'], s64_short_id($ids['n2'])))['c'] === 0) { $miss[] = 'inbound n1<-n2'; }
		if(!$miss) { break; }
		sleep(15);
	}
	check("Ergebnisse $what angekommen (" . (time() - $t0) . ' s)', !$miss, $miss);
	done();
}

// ---------------------------------------------------------------- final
if($phase === 'final') {
	db(); $ids = ids(); $n1 = $ids['n1']; $n2 = $ids['n2']; $evil = sec_get('evil.id');
	$real = array('a_fsn', $n1, $n2);
	echo "Ergebnisse je Messendem/Ziel/Methode:\n";
	foreach(all("SELECT src, dst, method, COUNT(*) c, SUM(valid) v, ROUND(AVG(avg_ms), 2) ms, MAX(sent) mx FROM sonar_results GROUP BY src, dst, method ORDER BY src, dst, method") as $r) {
		$name = array_search($r['src'], $ids, true) ?: ($r['src'] === $evil ? 'evil' : $r['src']);
		$dn = array_search($r['dst'], $ids, true) ?: $r['dst'];
		echo sprintf("    %-6s -> %-6s %-5s n=%d gueltig=%d avg=%s ms max_sent=%d\n", $name, $dn, $r['method'], $r['c'], $r['v'], $r['ms'], $r['mx']);
	}
	// Ergebnisse angenommen, nichts verworfen
	foreach($real as $s) {
		$n = one("SELECT plaus_ok, plaus_bad, trust, health, last_report FROM sonar_nodes WHERE node_id = ?", array($s));
		$k = array_search($s, $ids, true);
		check("$k: Ergebnisse angenommen (plaus_ok > 0, plaus_bad = 0)", (int)$n['plaus_ok'] > 0 AND (int)$n['plaus_bad'] === 0, $n);
		$bad = one("SELECT COUNT(*) c FROM sonar_results WHERE src = ? AND valid = 0", array($s))['c'];
		check("$k: keine verworfenen Ergebnisse", (int)$bad === 0, $bad);
		$h = json_decode((string)$n['health'], true) ?: array();
		check("$k: Health gemeldet (mode, sent_today <= Tagesgrenze)", in_array($h['mode'] ?? '', array('anchor', 'headless'), true) AND ($h['sent_today'] ?? 1e9) <= ($k === 'a_fsn' ? 4000000 : 20000), $h);
	}
	check('n1 antwortet auf UDP 6464 (Health responder)', (json_decode((string)one("SELECT health FROM sonar_nodes WHERE node_id = ?", array($n1))['health'], true)['responder'] ?? false) === true);
	check('n2 ohne Antworter (nur ausgehend)', (json_decode((string)one("SELECT health FROM sonar_nodes WHERE node_id = ?", array($n2))['health'], true)['responder'] ?? true) === false);
	// Plan befolgt: jede Messung steht in einem ausgelieferten Plan (sent_body/prev_body/body) oder ist ein Anker
	foreach(array($n1, $n2, 'a_fsn') as $s) {
		$k = array_search($s, $ids, true);
		$p = one("SELECT body, sent_body, prev_body FROM sonar_plans WHERE node_id = ?", array($s));
		$planned = array(); $minR = PHP_INT_MAX;
		foreach(array('body', 'sent_body', 'prev_body') as $c) {
			foreach((json_decode((string)($p[$c] ?? ''), true)['rounds'] ?? array()) as $rd) {
				$t = strtotime($rd['start']); $minR = min($minR, $t);
				foreach($rd['targets'] as $tg) { $planned[$t . '|' . $tg['id'] . '|' . $tg['method']] = (int)$tg['count']; }
			}
		}
		$off = array(); $over = array();
		foreach(all("SELECT `round`, dst, method, sent FROM sonar_results WHERE src = ?", array($s)) as $r) {
			$t = strtotime($r['round'] . ' UTC');
			if($t < $minR) { continue; } // aeltere Plaene sind nicht mehr gespeichert
			$key = $t . '|' . $r['dst'] . '|' . $r['method'];
			if(!isset($planned[$key]) AND !str_starts_with($r['dst'], 'a_')) { $off[] = $key; }
			if(isset($planned[$key]) AND (int)$r['sent'] > $planned[$key] AND $r['method'] !== 'trace') { $over[] = $key; }
		}
		check("$k: nur Ziele aus dem Plan gemessen", !$off, array_slice($off, 0, 5));
		check("$k: nicht mehr Pakete als im Plan", !$over, array_slice($over, 0, 5));
	}
	// harte Grenzen
	foreach(array($n1, $n2) as $s) {
		$k = array_search($s, $ids, true);
		$mx = one("SELECT MAX(c) m FROM (SELECT COUNT(DISTINCT dst, fam) c FROM sonar_results WHERE src = ? AND method <> 'trace' GROUP BY `round`) x", array($s))['m'];
		check("$k: hoechstens 8 Ziele je Runde (sparsam)", (int)$mx <= 8, $mx);
		$ms = one("SELECT MAX(sent) m FROM sonar_results WHERE src = ? AND method <> 'trace'", array($s))['m'];
		check("$k: hoechstens 5 Pakete je Ziel", (int)$ms <= 5 AND (int)$ms >= 1, $ms);
		$tr = one("SELECT MAX(c) m FROM (SELECT COUNT(*) c FROM sonar_traces WHERE src = ? GROUP BY DATE_FORMAT(`round`, '%Y-%m-%d %H')) x", array($s))['m'];
		check("$k: hoechstens 2 Traceroutes je Stunde", (int)$tr <= 2, $tr);
	}
	$ip = one("SELECT COUNT(*) c FROM sonar_traces WHERE hops LIKE '%172.%' OR hops LIKE '%192.168.%' OR hops LIKE '%10.%'")['c'];
	check('keine privaten Hops gespeichert', (int)$ip === 0, $ip);
	// Pings gegen mich (UDP 6464): n1 hat Proben von n2 und vom Anker beantwortet und gemeldet
	$in = all("SELECT from_short, SUM(`count`) c FROM sonar_inbound WHERE node_id = ? GROUP BY from_short", array($n1));
	$sh = array_column($in, 'c', 'from_short');
	check('n1 meldet beantwortete Proben von n2 (inbound)', ($sh[s64_short_id($n2)] ?? 0) > 0, $in);
	check('Anker meldet beantwortete Proben (inbound)', (int)one("SELECT COUNT(*) c FROM sonar_inbound WHERE node_id = 'a_fsn'")['c'] > 0);
	// GET /sonar/inbound fuer n1 (aus den Ergebnissen bei ipv64)
	$r = req(LOC, 'GET', '/sonar/inbound', null, sec_get('n1.tok'));
	$rows = $r['j']['data'] ?? array();
	check('GET /sonar/inbound n1: Anker und n2 messen mich, ohne IPs', $r['code'] === 200 AND in_array('a_fsn', array_column($rows, 'from'), true)
		AND in_array($n2, array_column($rows, 'from'), true) AND !str_contains($r['raw'], NET), code($r));

	// Plausibilitaet: der Faelscher
	$e = one("SELECT plaus_ok, plaus_bad, trust FROM sonar_nodes WHERE node_id = ?", array($evil));
	check('Faelscher: plaus_bad >= 3, plaus_ok = 0', (int)$e['plaus_bad'] >= 3 AND (int)$e['plaus_ok'] === 0, $e);
	$ev = all("SELECT valid, reason FROM sonar_results WHERE src = ?", array($evil));
	check('Faelscher: nur below_light gespeichert, valid = 0', count($ev) === 1 AND (int)$ev[0]['valid'] === 0 AND $ev[0]['reason'] === 'below_light', $ev);

	// Jobs
	$hr = gmdate('Y-m-d\TH:05:00\Z', time() + 3600);
	[$rc, $out] = cli("sonar_rollup.php --now=$hr");
	check('Verdichtung laeuft', $rc === 0, $out);
	$pairs = all("SELECT src, dst, fam, n, p50_ms, loss FROM sonar_pair_1h");
	$pk = array(); foreach($pairs as $p) { $pk[$p['src'] . '>' . $p['dst']] = $p; }
	check('sonar_pair_1h: Anker->n1, n1->Anker, n2->n1', isset($pk["a_fsn>$n1"], $pk["$n1>a_fsn"], $pk["$n2>$n1"]), array_keys($pk));
	check('sonar_pair_1h: Werte plausibel (p50 > 0, Verlust < 1)', isset($pk["$n2>$n1"]) AND (float)$pk["$n2>$n1"]['p50_ms'] > 0 AND (float)$pk["$n2>$n1"]['loss'] < 1, $pk["$n2>$n1"] ?? null);
	check('Faelscher zaehlt nicht in der Verdichtung', !array_filter(array_keys($pk), fn($k) => str_starts_with($k, "$evil>")));
	foreach(array('sonar_trust.php', 'sonar_outages.php', 'sonar_cleanup.php --dry') as $job) {
		[$rc, $out] = cli($job);
		check("Job $job laeuft", $rc === 0 AND !preg_match('/Fatal|Warning|Exception/i', $out), $out);
	}
	check('Anker-Wahrheit: keine ehrlichen Knoten verworfen', (int)one("SELECT COUNT(*) c FROM sonar_results WHERE src IN (?, ?, 'a_fsn') AND valid = 0", array($n1, $n2))['c'] === 0);
	check('ehrliche Knoten nicht in Quarantaene', one("SELECT COUNT(*) c FROM sonar_nodes WHERE node_id IN (?, ?) AND trust = 'quarantine'", array($n1, $n2))['c'] == 0);

	// oeffentliche Karte und Seiten
	clear_cache();
	$r = req(LOC, 'GET', '/sonar/public/map');
	$map = $r['j']['data'] ?? array();
	$mids = array_column($map['nodes'] ?? array(), 'id');
	check('public/map 200 + Cache-Control public', $r['code'] === 200 AND str_contains($r['h']['cache-control'] ?? '', 'public'), code($r));
	check('public/map: Anker, n1, n2', in_array('a_fsn', $mids, true) AND in_array($n1, $mids, true) AND in_array($n2, $mids, true), $mids);
	$links = $map['links'] ?? array();
	$lk = array(); foreach($links as $l) { $lk[] = $l['a'] . '-' . $l['b']; }
	// Linien nur zwischen Knoten, die Anker stehen in anchor_ms
	check('public/map: Verbindungslinie n2<->n1', (bool)array_filter($links, fn($l) => in_array($n1, array($l['a'], $l['b']), true) AND in_array($n2, array($l['a'], $l['b']), true)), $lk);
	check('public/map: Links mit ms > 0', $links AND !array_filter($links, fn($l) => $l['loss'] < 1 AND (!is_numeric($l['ms']) OR $l['ms'] <= 0)), $links);
	$n1m = null; foreach($map['nodes'] ?? array() as $n) { if($n['id'] === $n1) { $n1m = $n; } }
	$dist = $n1m ? s64_distance_km(LATLON['n1'][0], LATLON['n1'][1], (float)$n1m['lat'], (float)$n1m['lon']) : -1;
	check('public/map: Standort verschleiert (0,2..1 km)', $dist > 0.2 AND $dist <= 1.0, $dist);
	check('public/map: Latenz zum Anker (anchor_ms)', is_numeric($n1m['anchor_ms']['a_fsn'] ?? null), $n1m);
	foreach(array('/sonar/public/map', '/sonar/public/nodes', '/sonar/public/stats', '/sonar/public/top', '/sonar/public/matrix', '/sonar/public/outages',
		'/sonar/public/node/' . rawurlencode((string)($n1m['slug'] ?? 'x'))) as $path) {
		$r = req(LOC, 'GET', $path);
		check("$path ohne IPs und genaue Koordinaten", $r['code'] === 200 AND !str_contains($r['raw'], NET) AND !preg_match('/50\.4831(?![0-9])|12\.3517(?![0-9])|50\.4562(?![0-9])|12\.3988(?![0-9])/', $r['raw']) AND !preg_match('/token|pubkey|userid|"ip4"|"ip6"/', $r['raw']), code($r));
	}
	$st = req(LOC, 'GET', '/sonar/public/stats')['j']['data'] ?? array();
	check('public/stats: Knoten und Anker gezaehlt', ($st['anchors'] ?? 0) >= 1 AND ($st['nodes_active'] ?? 0) >= 2 AND ($st['measurements_today'] ?? 0) > 0, $st);

	// Mini-Status (SONAR64_STATUS=:8064): Pings raus und rein
	foreach(array('n1' => '11', 'n2' => '12') as $k => $last) {
		$r = req('http://' . NET . $last . ':8064', 'GET', '/status');
		$j = $r['j'] ?? array();
		check("$k Mini-Status /status", $r['code'] === 200 AND ($j['status']['registered'] ?? false) === true AND ($j['status']['node_id'] ?? '') === $ids[$k], code($r));
		$targets = array_unique(array_column($j['recent'] ?? array(), 'target'));
		check("$k Mini-Status: Pings von mir", in_array('a_fsn', $targets, true) AND ($k === 'n1' OR in_array($n1, $targets, true)), $targets);
		check("$k Mini-Status ohne Adressen und Token", !str_contains($r['raw'], NET) AND !str_contains($r['raw'], 's64_'), substr($r['raw'], 0, 200));
		$h = req('http://' . NET . $last . ':8064', 'GET', '/health');
		check("$k Mini-Status /health 200", $h['code'] === 200, code($h));
	}
	$r = req('http://' . NET . '11:8064', 'GET', '/status');
	$froms = array_unique(array_column($r['j']['inbound'] ?? array(), 'from'));
	check('n1 Mini-Status: Pings gegen mich (UDP live, n2 und Anker)', in_array(s64_short_id($n2), $froms, true) AND in_array(s64_short_id('a_fsn'), $froms, true), $froms);
	done();
}
fwrite(STDERR, "Phase unbekannt\n");
exit(2);
