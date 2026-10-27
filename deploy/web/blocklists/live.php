<?php
/**
 * Honeypot64 (Phase H3): Live-Abruf der v64 Blocklist mit persoenlichem Listen-Token im Pfad.
 *   https://ipv64.net/blocklists/live/<token>/<datei>   (Rewrite auf blocklists/live.php?t=<token>&f=<datei>)
 * Firewalls (pfSense, OPNsense, MikroTik, FortiGate) und PROXY64 koennen keine Kopfzeilen mitschicken, darum steht das
 * Token (genau 32 Zeichen [A-Za-z0-9], Tabelle hp_list_tokens, verwaltet unter honeypot/token.php) in der Adresse.
 * Planung: docs/PLAN-NODE64-HONEYPOT64.md (Abschnitt 8) im Node64-Repo.
 *
 *   - Live-Stand (alle 30 min, Ordner private/blocklists_live, nicht oeffentlich) fuer alle Klassen ausser Standard
 *     (users.user_class != 1) und fuer Beitragende (ein Sensor hat in den letzten 7 Tagen gemeldet); die Berechtigung
 *     wird bei jedem Abruf geprueft. Sonst der Tagesstand aus blocklists/ (kein Fehler). Kopfzeile X-IPv64-List: live|daily.
 *   - Unbekanntes Token oder inaktiver Account: 404 (PROXY64 faellt dann auf den Tagesstand zurueck).
 *   - Nur die Dateien der v64-Listen (feste Liste), der Pfad wird nie aus der Anfrage gebaut.
 *   - Hoechstens 60 Abrufe je Token in 5 Minuten ueber alle Dateien, sonst 429 mit Retry-After; If-None-Match mit
 *     passendem ETag gibt immer 304. Keine Sperre mehr je Datei: das Token gilt fuer den Account, mehrere Nodes holen
 *     dieselbe Datei kurz nacheinander (z. B. nach einem Neustart aller Container) - die bekamen sonst 429.
 */
const HPL_GAP      = 0;            // dieselbe Datei: kein Mindestabstand (frueher 5 Minuten, traf mehrere Nodes)
const HPL_WINDOW   = 300;          // Fenster fuer die Obergrenze ueber alle Dateien
const HPL_MAX      = 60;           // Abrufe je Fenster
const HPL_CONTRIB  = 7 * 86400;    // Beitragende: Meldung in den letzten 7 Tagen
const HPL_LISTS    = array('v64'); // nur die eine v64 Blocklist (Teillisten seit 2026-10 entfernt)

function hpl_out(int $code, string $text, array $headers = array()): void {
	http_response_code($code);
	header('Content-Type: text/plain; charset=utf-8');
	header('Cache-Control: no-store');
	foreach($headers as $h) { header($h); }
	echo $text . "\n";
	exit;
}

/** erlaubte Dateinamen (wie create_blocklists_v2.php sie schreibt) */
function hpl_files(): array {
	$f = array();
	foreach(HPL_LISTS as $id) {
		array_push($f, "ipv64_blocklist_$id.txt", "ipv64_blocklist_v4_$id.txt", "ipv64_blocklist_v6_$id.txt", "v64_mikrotik_v4_$id.rsc", "v64_mikrotik_v6_$id.rsc");
	}
	return $f;
}

if(!in_array($_SERVER['REQUEST_METHOD'] ?? 'GET', array('GET', 'HEAD'), true)) { hpl_out(405, 'Method not allowed', array('Allow: GET, HEAD')); }
$token = (string)($_GET['t'] ?? '');
$file = (string)($_GET['f'] ?? '');
if(!preg_match('/^[A-Za-z0-9]{32}$/', $token)) { hpl_out(404, 'Unknown list token'); }
if(!in_array($file, hpl_files(), true)) { hpl_out(404, 'Unknown list file'); }

include(__DIR__ . '/../dbconnect.php');
$now = time();
$q = function(string $sql, array $p = array()) use ($pdo) { $st = $pdo->prepare($sql); $st->execute($p); return $st; };

try {
	$tok = $q("SELECT t.userid, t.token, u.user_class, u.account_status FROM hp_list_tokens t JOIN users u ON u.id = t.userid WHERE t.token = :t", array('t' => $token))->fetch(PDO::FETCH_ASSOC);
	if($tok === false OR !hash_equals((string)$tok['token'], $token) OR (string)$tok['account_status'] !== '1') { hpl_out(404, 'Unknown list token'); }
	$uid = (int)$tok['userid'];
	$live = (int)$tok['user_class'] !== 1;
	if(!$live) {
		$live = $q("SELECT 1 FROM hp_sensors WHERE userid = :u AND disabled = 0 AND last_seen >= :d LIMIT 1",
			array('u' => $uid, 'd' => gmdate('Y-m-d H:i:s', $now - HPL_CONTRIB)))->fetchColumn() !== false;
	}
} catch(Throwable $e) {
	error_log('blocklists/live.php: ' . $e->getMessage());
	hpl_out(503, 'Temporarily unavailable', array('Retry-After: 300'));
}

// Datei: Live-Stand (nicht oeffentlicher Ordner) oder Tagesstand; Name nur aus der festen Liste
$mode = 'daily';
$path = __DIR__ . '/' . $file;
if($live) {
	$lp = dirname(__DIR__, 2) . '/private/blocklists_live/' . $file;
	if(is_file($lp)) { $mode = 'live'; $path = $lp; }
}
if(!is_file($path)) { hpl_out(404, 'List not generated yet'); }
clearstatcache();
$mtime = (int)filemtime($path); $size = (int)filesize($path);
$etag = '"' . $mode[0] . '-' . dechex($mtime) . '-' . dechex($size) . '"';
$common = array('X-IPv64-List: ' . $mode, 'ETag: ' . $etag, 'Last-Modified: ' . gmdate('D, d M Y H:i:s', $mtime) . ' GMT');

try {
	$n = gmdate('Y-m-d H:i:s', $now);
	// unveraendert: immer 304
	$inm = (string)($_SERVER['HTTP_IF_NONE_MATCH'] ?? '');
	if($inm !== '' AND in_array($etag, array_map('trim', explode(',', $inm)), true)) {
		$q("UPDATE hp_list_tokens SET last_used = :n WHERE userid = :u", array('n' => $n, 'u' => $uid));
		http_response_code(304);
		foreach($common as $h) { header($h); }
		header('Cache-Control: private, no-cache');
		exit;
	}
	$pdo->beginTransaction();
	$t = $q("SELECT uses_window_start, uses_in_window FROM hp_list_tokens WHERE userid = :u FOR UPDATE", array('u' => $uid))->fetch(PDO::FETCH_ASSOC);
	if($t === false) { $pdo->rollBack(); hpl_out(404, 'Unknown list token'); } // gerade widerrufen
	$last = $q("SELECT last_at FROM hp_list_token_files WHERE userid = :u AND file = :f FOR UPDATE", array('u' => $uid, 'f' => $file))->fetchColumn();
	$wait = $last !== false ? HPL_GAP - ($now - strtotime($last . ' UTC')) : 0;
	$ws = $t['uses_window_start'] !== null ? strtotime($t['uses_window_start'] . ' UTC') : 0;
	$newWindow = $now - $ws >= HPL_WINDOW;
	if($wait <= 0 AND !$newWindow AND (int)$t['uses_in_window'] >= HPL_MAX) { $wait = HPL_WINDOW - ($now - $ws); }
	if($wait > 0) {
		$pdo->rollBack();
		hpl_out(429, "Too many requests: at most " . HPL_MAX . " fetches per 5 minutes for this token. Retry in $wait seconds.", array_merge($common, array('Retry-After: ' . $wait)));
	}
	$q("UPDATE hp_list_tokens SET last_used = :n, uses_window_start = :ws, uses_in_window = :c WHERE userid = :u",
		array('n' => $n, 'ws' => $newWindow ? $n : $t['uses_window_start'], 'c' => $newWindow ? 1 : (int)$t['uses_in_window'] + 1, 'u' => $uid));
	$q("INSERT INTO hp_list_token_files (userid, file, last_at) VALUES (:u, :f, :n) ON DUPLICATE KEY UPDATE last_at = VALUES(last_at)", array('u' => $uid, 'f' => $file, 'n' => $n));
	$pdo->commit();
} catch(Throwable $e) {
	if($pdo->inTransaction()) { $pdo->rollBack(); }
	error_log('blocklists/live.php: ' . $e->getMessage());
	hpl_out(503, 'Temporarily unavailable', array('Retry-After: 300'));
}

http_response_code(200);
header('Content-Type: text/plain; charset=utf-8');
header('Cache-Control: private, no-cache');
header('Content-Length: ' . $size);
foreach($common as $h) { header($h); }
if(($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'HEAD') { readfile($path); }
