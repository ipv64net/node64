<?php
/**
 * Honeypot64 (H3): gemeinsame Funktionen fuer IP-Auskunft und Freigaben. Eingebunden (require_once) von
 * honeypot/ip.php, honeypot/admin.php, api_v2_threat.php und bots/honeypot_release.php; definiert nur Konstanten und
 * Funktionen (keine Ausgabe, keine Datenbankverbindung: $pdo kommt vom Aufrufer).
 * Tabellen: hp_allowlist, hp_release_requests (deploy/sql/honeypot_h3_release.sql); liest hp_scores (Teil Bewertung)
 * und hp_report_sources (H2). Alle Zeiten UTC. Planung: docs/PLAN-NODE64-HONEYPOT64.md (Abschnitte 7, 9, 13).
 *
 * Datenschutz der Auskunft: Fuer nicht gelistete IPs gibt es keine Details (gleiche Antwort, ob Sensoren sie gesehen
 * haben oder nicht), Sichtungen nur auf den Tag genau, Ports nur, wenn mindestens HPR_PORT_MIN_ACCOUNTS Accounts sie
 * gemeldet haben. So laesst sich aus der Auskunft nicht ableiten, welche Adresse ein Sensor ist oder wer gemeldet hat.
 */

const HPR_URL            = 'https://ipv64.net/honeypot/ip.php';
const HPR_ADMIN_URL      = 'https://ipv64.net/honeypot/admin.php';
const HPR_NOTIFY         = 'info@ipv64.net'; // Mail bei Eskalation (Dennis 2026-10-20); leer = alle Accounts mit users.admin = 1
const HPR_QUIET          = 86400;     // 24 h ohne Beruehrung nach der Bestaetigung -> automatisch frei
const HPR_PROTECT_DAYS   = 30;        // Schutz nach Freigabe
const HPR_MAX_PER_DAY    = 3;         // Antraege je Absender-IP und je E-Mail/Account in 24 h
const HPR_CONFIRM_TTL    = 172800;    // unbestaetigte Antraege: 48 h
const HPR_HISTORY_DAYS   = 90;        // fruehere Antraege fuer dieselbe IP -> Eskalation
const HPR_SENDER_DAYS    = 30;        // ein Absender mit Antraegen fuer viele IPs ...
const HPR_SENDER_MAX_IPS = 5;         // ... ab so vielen verschiedenen IPs -> Eskalation
const HPR_PORT_DAYS      = 30;        // Ports aus den letzten 30 Tagen
const HPR_PORT_MIN_ACCOUNTS = 2;      // Port nur zeigen, wenn mindestens so viele Accounts ihn gemeldet haben
const HPR_RL_ANON_CAP    = 10;        // Auskunft ohne Key/Anmeldung: Burst je Client-IP ...
const HPR_RL_ANON_REFILL = 1 / 60;    // ... dann 1 je Minute (60/h)
const HPR_RL_KEY_CAP     = 120;       // mit API-Key/Anmeldung: Burst je Account ...
const HPR_RL_KEY_REFILL  = 2.0;       // ... dann 2 je Sekunde
const HPR_KINDS_TEXT = array(         // Arten fuer Laien (de, en)
	'ssh:bruteforce' => array('Passwort-Raten per SSH', 'SSH password guessing'),
	'telnet:bruteforce' => array('Passwort-Raten per Telnet (oft IoT-Botnetze)', 'Telnet password guessing (often IoT botnets)'),
	'rdp:bruteforce' => array('Passwort-Raten per Remotedesktop (RDP)', 'Remote Desktop (RDP) password guessing'),
	'mail:auth-bruteforce' => array('Passwort-Raten bei Mail-Anmeldungen', 'Mail login password guessing'),
	'http:bruteforce' => array('Passwort-Raten auf Login-Seiten', 'Password guessing on login pages'),
	'http:exploit' => array('Angriff auf bekannte Web-Sicherheitslücken', 'Attack on known web vulnerabilities'),
	'http:scan' => array('Suche nach Web-Verzeichnissen und Dateien', 'Scanning for web directories and files'),
	'http:bad-useragent' => array('Bekanntes Angriffswerkzeug im Web', 'Known attack tool on the web'),
	'db:bruteforce' => array('Passwort-Raten bei Datenbanken', 'Database password guessing'),
	'vpn:bruteforce' => array('Passwort-Raten bei VPN-Zugängen', 'VPN password guessing'),
	'generic:portscan' => array('Port-Scan (Suche nach offenen Diensten)', 'Port scan (searching for open services)'),
	'generic:probe' => array('Verbindungsversuche zu nicht angebotenen Diensten', 'Connection attempts to services that are not offered'),
	'scanner:research' => array('Internet-Scanner (z. B. Forschung, Suchmaschinen für Geräte)', 'Internet scanner (e.g. research, device search engines)'),
);

// ---------------------------------------------------------------- Datenbank, Zeit

/** Prepared Statement; Fehler als RuntimeException (unabhaengig vom PDO-Fehlermodus des Aufrufers). */
function hpr_q(PDO $pdo, string $sql, array $p = array()): PDOStatement {
	try { $st = $pdo->prepare($sql); $ok = $st !== false && $st->execute($p); }
	catch(PDOException $e) { throw new RuntimeException('hp_release SQL: ' . $e->getMessage(), 0, $e); }
	if(!$ok) { $i = $st !== false ? $st->errorInfo() : $pdo->errorInfo(); throw new RuntimeException('hp_release SQL: ' . ($i[2] ?? 'unknown')); }
	return $st;
}
function hpr_one(PDO $pdo, string $sql, array $p = array()): ?array { $r = hpr_q($pdo, $sql, $p)->fetch(PDO::FETCH_ASSOC); return $r === false ? null : $r; }
function hpr_all(PDO $pdo, string $sql, array $p = array()): array { return hpr_q($pdo, $sql, $p)->fetchAll(PDO::FETCH_ASSOC); }

function hpr_dt(int $ts): string { return gmdate('Y-m-d H:i:s', $ts); }
/** DB-Zeit (UTC) -> Unix */
function hpr_ts($s): ?int { return ($s === null OR $s === '' OR str_starts_with((string)$s, '0000')) ? null : (int)strtotime($s . ' UTC'); }
/** DB-Zeit (UTC) -> ISO 8601 */
function hpr_iso($s): ?string { $t = hpr_ts($s); return $t === null ? null : gmdate('Y-m-d\TH:i:s\Z', $t); }

/** Zufaelliges Token (32 Zeichen, a-zA-Z0-9) */
function hpr_token(): string {
	$c = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'; $t = '';
	for($i = 0; $i < 32; $i++) { $t .= $c[random_int(0, 61)]; }
	return $t;
}

// ---------------------------------------------------------------- Adressen

/** Genau eine IPv4/IPv6-Adresse (kein Netz, keine Zone), normalisiert (::ffff:a.b.c.d -> IPv4); sonst null. */
function hpr_ip(string $in): ?string {
	$in = trim($in);
	if($in === '' OR strlen($in) > 45 OR !preg_match('/^[0-9A-Fa-f:.]+$/', $in) OR !filter_var($in, FILTER_VALIDATE_IP)) { return null; }
	$b = inet_pton($in);
	return $b === false ? null : inet_ntop(hpr_unmap($b));
}

/** Binaerform: IPv4-gemappte IPv6 (::ffff:a.b.c.d) -> IPv4 (4 Byte), sonst unveraendert. */
function hpr_unmap(string $bin): string {
	return (strlen($bin) === 16 AND substr($bin, 0, 12) === str_repeat("\0", 10) . "\xff\xff") ? substr($bin, 12) : $bin;
}

/** Schluessel der Drosseln je Client: IPv4 die Adresse (auch ::ffff:-gemappt), IPv6 das /64 (sonst umgeht ein Wechsel
 * der Adresse im eigenen Netz das Limit); ungueltig -> Eingabe. */
function hpr_rl_key(string $ip): string {
	$b = @inet_pton($ip);
	if($b === false) { return $ip; }
	$b = hpr_unmap($b);
	return strlen($b) === 16 ? inet_ntop(substr($b, 0, 8) . str_repeat("\0", 8)) . '/64' : inet_ntop($b);
}

/** Adresse in einem der Netze? (gleiche Familie) */
function hpr_in_nets(string $bin, array $nets): bool {
	foreach($nets as $cidr) {
		$p = explode('/', (string)$cidr, 2);
		$n = @inet_pton(trim($p[0]));
		if($n === false OR strlen($n) !== strlen($bin)) { continue; }
		$len = isset($p[1]) ? (int)$p[1] : strlen($n) * 8;
		$bytes = intdiv($len, 8); $bits = $len % 8;
		if(substr($bin, 0, $bytes) !== substr($n, 0, $bytes)) { continue; }
		if($bits === 0 OR ((ord($bin[$bytes]) ^ ord($n[$bytes])) & (0xff << (8 - $bits)) & 0xff) === 0) { return true; }
	}
	return false;
}

/** Oeffentliche Unicast-Adresse (wie hp_public_ip in api_v2_honeypot.php). */
function hpr_public(string $bin): bool {
	static $v4 = array('0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
		'192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4');
	static $v6 = array('::/8', '64:ff9b::/96', '64:ff9b:1::/48', '100::/64', '2001::/23', '2001:db8::/32', '2002::/16', '3fff::/20', '5f00::/16',
		'fc00::/7', 'fe80::/10', 'fec0::/10', 'ff00::/8');
	if(strlen($bin) === 4) { return !hpr_in_nets($bin, $v4); }
	return strlen($bin) === 16 && !hpr_in_nets($bin, $v6) && hpr_in_nets($bin, array('2000::/3'));
}

/** CIDR (oder einzelne IP) -> array(normalisiertes CIDR, erste Adresse, letzte Adresse) als Binaerform; sonst null. */
function hpr_cidr(string $in): ?array {
	$in = trim($in);
	if(!preg_match('#^([0-9A-Fa-f:.]{2,45})(?:/(\d{1,3}))?$#', $in, $m)) { return null; }
	$ip = hpr_ip($m[1]);
	if($ip === null) { return null; }
	$b = inet_pton($ip); $max = strlen($b) * 8;
	$len = isset($m[2]) ? (int)$m[2] : $max;
	if(isset($m[2]) AND strlen($b) === 4 AND strlen((string)@inet_pton($m[1])) === 16) { $len -= 96; } // ::ffff:a.b.c.d/n -> IPv4 /n-96
	if($len < 0 OR $len > $max) { return null; }
	$start = ''; $end = '';
	for($i = 0; $i < strlen($b); $i++) {
		$keep = max(0, min(8, $len - $i * 8));
		$mask = $keep === 0 ? 0 : (0xff << (8 - $keep)) & 0xff;
		$start .= chr(ord($b[$i]) & $mask);
		$end .= chr((ord($b[$i]) & $mask) | (~$mask & 0xff));
	}
	return array(inet_ntop($start) . '/' . $len, $start, $end);
}

/** Wie client_ip() in api_v2.php: hinter dem Reverse Proxy zaehlt die letzte Adresse aus X-Forwarded-For. */
function hpr_client_ip(): string {
	$ip = (string)($_SERVER['REMOTE_ADDR'] ?? '');
	if(!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) AND !empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
		$xff = explode(',', (string)$_SERVER['HTTP_X_FORWARDED_FOR']);
		$last = trim((string)end($xff));
		if(filter_var($last, FILTER_VALIDATE_IP)) { $ip = $last; }
	}
	return $ip;
}

/**
 * Token Bucket wie rl_take() in api_v2.php (gleicher Speicher und Schluessel), damit Seite und API dieselben Toepfe
 * teilen. Rueckgabe array(erlaubt, verbleibend, Sekunden bis zum naechsten Versuch).
 */
function hpr_rl(string $bucket, float $capacity, float $refill): array {
	$now = microtime(true);
	$key = 'ipv64api2_' . sha1($bucket);
	$state = null; $fh = null;
	$apcu = function_exists('apcu_enabled') && apcu_enabled();
	if($apcu) {
		$state = apcu_fetch($key);
	} else {
		$dir = sys_get_temp_dir() . '/ipv64_api_v2_rl';
		if(!is_dir($dir)) { @mkdir($dir, 0700, true); }
		$fh = @fopen("$dir/$key", 'c+');
		if($fh !== false) { flock($fh, LOCK_EX); $raw = stream_get_contents($fh); $state = $raw ? json_decode($raw, true) : null; }
	}
	if(!is_array($state)) { $state = array('t' => $now, 'v' => $capacity); }
	$tokens = min($capacity, $state['v'] + ($now - $state['t']) * $refill);
	$allowed = $tokens >= 1.0;
	if($allowed) { $tokens -= 1.0; }
	$state = array('t' => $now, 'v' => $tokens);
	if($apcu) {
		apcu_store($key, $state, (int)ceil($capacity / max($refill, 0.001)) + 60);
	} elseif($fh !== false AND $fh !== null) {
		ftruncate($fh, 0); rewind($fh); fwrite($fh, json_encode($state)); flock($fh, LOCK_UN); fclose($fh);
	}
	return array($allowed, (int)floor($tokens), $allowed ? 0 : (int)ceil((1.0 - $tokens) / max($refill, 0.001)));
}

// ---------------------------------------------------------------- Freigaben und Auskunft

/** Gueltiger Eintrag der Freigabeliste fuer die Adresse (dauerhafte zuerst, sonst der am laengsten gueltige). */
function hpr_allowed(PDO $pdo, string $bin): ?array {
	return hpr_one($pdo, "SELECT id, cidr, source, `until` FROM hp_allowlist WHERE LENGTH(ip_start) = :l AND ip_start <= UNHEX(:b1) AND ip_end >= UNHEX(:b2)
		AND (`until` IS NULL OR `until` > :now) ORDER BY `until` IS NULL DESC, `until` DESC LIMIT 1",
		array('l' => strlen($bin), 'b1' => bin2hex($bin), 'b2' => bin2hex($bin), 'now' => hpr_dt(time())));
}

/** Komma-Liste -> Array ohne Leereintraege */
function hpr_csv($s): array { return array_values(array_filter(array_map('trim', explode(',', (string)$s)), 'strlen')); }

/**
 * IP-Auskunft (Seite und API). $ip muss mit hpr_ip() geprueft und oeffentlich sein.
 * status: listed | not_listed | released (Freigabe aus Antrag, befristet) | allowlisted (Freigabeliste)
 * release.status: none | in_review | released | allowlisted | rejected
 */
function hpr_lookup(PDO $pdo, string $ip): array {
	$bin = inet_pton($ip); $now = time();
	$out = array('ip' => $ip, 'family' => strlen($bin) === 4 ? 4 : 6, 'listed' => false, 'status' => 'not_listed', 'score' => null, 'lists' => array(),
		'kinds' => array(), 'ports' => array(), 'first_seen' => null, 'last_seen' => null, 'accounts' => null, 'country' => null, 'asn' => null,
		'release' => array('status' => 'none', 'protected_until' => null));
	$allow = hpr_allowed($pdo, $bin);
	if($allow !== null) {
		$st = $allow['source'] === 'request' ? 'released' : 'allowlisted';
		$out['status'] = $st;
		$out['release'] = array('status' => $st, 'protected_until' => hpr_iso($allow['until']));
		return $out;
	}
	$req = hpr_one($pdo, "SELECT status, decided_at FROM hp_release_requests WHERE ip_bin = UNHEX(:b) AND confirmed_at IS NOT NULL ORDER BY id DESC LIMIT 1", array('b' => bin2hex($bin)));
	if($req !== null) {
		if($req['status'] === 'open' OR $req['status'] === 'escalated') { $out['release']['status'] = 'in_review'; }
		elseif($req['status'] === 'rejected' AND hpr_ts($req['decided_at']) >= $now - HPR_PROTECT_DAYS * 86400) { $out['release']['status'] = 'rejected'; }
	}
	try {
		$s = hpr_one($pdo, "SELECT * FROM hp_scores WHERE ip_bin = UNHEX(:b)", array('b' => bin2hex($bin)));
		// IPv6: gelistet wird das ganze /64 (honeypot_score.php) - ohne eigene Zeile gilt die hoechste Zeile im /64
		if(strlen($bin) === 16 AND ($s === null OR (int)$s['listed'] !== 1)) {
			$n = hpr_one($pdo, "SELECT * FROM hp_scores WHERE ip_bin >= UNHEX(:s) AND ip_bin <= UNHEX(:e) AND LENGTH(ip_bin) = 16 AND listed = 1
				ORDER BY score DESC LIMIT 1", array('s' => bin2hex(substr($bin, 0, 8) . str_repeat("\0", 8)), 'e' => bin2hex(substr($bin, 0, 8) . str_repeat("\xff", 8))));
			if($n !== null) { $s = $n; }
		}
	} catch(RuntimeException $e) {
		error_log('hp_release: hp_scores nicht lesbar: ' . $e->getMessage()); // Bewertung noch nicht eingespielt
		$s = null;
	}
	if($s === null OR (int)$s['listed'] !== 1) { return $out; } // nicht gelistet: keine Details (siehe Kopf)
	$out['listed'] = true; $out['status'] = 'listed';
	$out['score'] = (int)$s['score'];
	$out['lists'] = hpr_csv($s['lists']);
	$out['kinds'] = hpr_csv($s['kinds']);
	$out['accounts'] = (int)$s['accounts'];
	$f = hpr_ts($s['first_seen']); $l = hpr_ts($s['last_seen']);
	$out['first_seen'] = $f === null ? null : gmdate('Y-m-d', $f);
	$out['last_seen'] = $l === null ? null : gmdate('Y-m-d', $l);
	if(isset($s['country']) AND preg_match('/^[A-Z]{2}$/', strtoupper((string)$s['country']))) { $out['country'] = strtoupper($s['country']); }
	if(isset($s['asn']) AND (int)$s['asn'] > 0) { $out['asn'] = (int)$s['asn']; }
	foreach(hpr_all($pdo, "SELECT service, port FROM hp_report_sources WHERE ip_bin = UNHEX(:b) AND last_seen >= :d AND port > 0
		GROUP BY service, port HAVING COUNT(DISTINCT userid) >= :n ORDER BY SUM(`count`) DESC LIMIT 10",
		array('b' => bin2hex((string)$s['ip_bin']), 'd' => hpr_dt($now - HPR_PORT_DAYS * 86400), 'n' => HPR_PORT_MIN_ACCOUNTS)) as $p) {
		$out['ports'][] = array('service' => $p['service'], 'port' => (int)$p['port']);
	}
	return $out;
}

/**
 * Antrag freigeben (Cron oder Admin): Status released, Eintrag in hp_allowlist. $days = null: dauerhaft
 * (source manual, until NULL), sonst source request mit until = jetzt + $days. Eine Transaktion.
 */
function hpr_release(PDO $pdo, array $r, ?int $days, ?int $by, string $note): void {
	$now = time();
	$until = $days === null ? null : hpr_dt($now + $days * 86400);
	$bin = $r['ip_bin'];
	$own = !$pdo->inTransaction();
	if($own) { $pdo->beginTransaction(); }
	try {
		hpr_q($pdo, "INSERT INTO hp_allowlist (cidr, ip_start, ip_end, reason, source, `until`, created_at, created_by) VALUES (:c, UNHEX(:s), UNHEX(:e), :r, :src, :u, :t, :by)
			ON DUPLICATE KEY UPDATE `until` = IF(`until` IS NULL OR VALUES(`until`) IS NULL, NULL, GREATEST(`until`, VALUES(`until`))), reason = VALUES(reason), created_by = VALUES(created_by)",
			array('c' => $r['ip'] . (strlen($bin) === 4 ? '/32' : '/128'), 's' => bin2hex($bin), 'e' => bin2hex($bin), 'r' => 'Antrag #' . $r['id'],
				'src' => $days === null ? 'manual' : 'request', 'u' => $until, 't' => hpr_dt($now), 'by' => $by));
		hpr_q($pdo, "UPDATE hp_release_requests SET status = 'released', decided_at = :t, decided_by = :by, protected_until = :u, note = :n WHERE id = :id",
			array('t' => hpr_dt($now), 'by' => $by, 'u' => $until, 'n' => mb_substr($note, 0, 2000), 'id' => $r['id']));
		if($own) { $pdo->commit(); }
	} catch(Throwable $e) {
		if($own AND $pdo->inTransaction()) { $pdo->rollBack(); }
		throw $e;
	}
}

/** Provider-/Cloud-Netz? Name der Liste (blocklisten.category = 'cloud', z. B. AWS, Google Cloud) oder null. */
function hpr_provider(PDO $pdo, string $bin): ?string {
	static $nets = null;
	if($nets === null) {
		$nets = array();
		try {
			foreach(hpr_all($pdo, "SELECT name, db_name FROM blocklisten WHERE category = 'cloud' AND disabled = 0") as $l) {
				if(!preg_match('/^bl_[a-z0-9_]{1,40}$/', (string)$l['db_name'])) { continue; }
				$nets[$l['name']] = array_column(hpr_all($pdo, "SELECT ip FROM `" . $l['db_name'] . "`"), 'ip');
			}
		} catch(RuntimeException $e) { error_log('hp_release: Cloud-Listen nicht lesbar: ' . $e->getMessage()); }
	}
	foreach($nets as $name => $list) { if(hpr_in_nets($bin, $list)) { return (string)$name; } }
	return null;
}

// ---------------------------------------------------------------- Mail

/** Empfaenger fuer Eskalationen */
function hpr_admin_mails(PDO $pdo): array {
	if(HPR_NOTIFY !== '') { return array(HPR_NOTIFY); }
	return array_values(array_filter(array_column(hpr_all($pdo, "SELECT email FROM users WHERE admin = 1"), 'email'), fn($m) => filter_var($m, FILTER_VALIDATE_EMAIL)));
}

/** Mail-Adresse fuer Bescheide: anonym aus dem Antrag, eingeloggt aus users. */
function hpr_requester_mail(PDO $pdo, array $r): string {
	if($r['userid'] !== null AND (int)$r['userid'] > 0) { return (string)(hpr_one($pdo, "SELECT email FROM users WHERE id = :u", array('u' => $r['userid']))['email'] ?? ''); }
	return (string)$r['email'];
}

/** Text-Mail ueber send_mail() aus dbconnect.php (wie hc2_deliver: mit 9. Parameter, falls vorhanden). */
function hpr_mail(PDO $pdo, string $to, string $subject, string $text): bool {
	if(!filter_var($to, FILTER_VALIDATE_EMAIL) OR !function_exists('send_mail')) { return false; }
	$e = fn($s) => htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
	$html = '<div style="font-family:Arial,Helvetica,sans-serif;font-size:15px;line-height:1.5;color:#1d273b"><p style="font-weight:bold;color:#17bebb">IPv64.net Honeypot64</p>'
		. preg_replace('#(https://[^\s<]+)#', '<a href="$1">$1</a>', nl2br($e($text))) . '</div>';
	$cls = 'PHPMailer\\PHPMailer\\PHPMailer';
	$mail = class_exists($cls) ? new $cls() : null;
	try {
		if((new ReflectionFunction('send_mail'))->getNumberOfParameters() >= 9) {
			$ok = send_mail($pdo, $mail, '', 'IPv64.net Honeypot64', $to, $subject, $html, '', array('text' => $text));
		} else {
			$ok = send_mail($pdo, $mail, '', 'IPv64.net Honeypot64', $to, $subject, $html, '');
		}
	} catch(Throwable $ex) {
		error_log('hp_release: Mail nicht gesendet: ' . $ex->getMessage());
		return false;
	}
	if($mail !== null AND method_exists($mail, 'smtpClose')) { $mail->smtpClose(); }
	return $ok !== false;
}

/** Bescheid an den Antragsteller (released/rejected). */
function hpr_mail_decision(PDO $pdo, array $r, string $status, ?string $until): void {
	$to = hpr_requester_mail($pdo, $r);
	if($to === '') { return; }
	$en = $r['lang'] === 'en';
	$link = HPR_URL . '?request=' . $r['token'] . ($en ? '&lang=en' : '');
	if($status === 'released') {
		$d = $until === null ? ($en ? 'permanently' : 'dauerhaft') : ($en ? 'until ' : 'bis ') . gmdate('Y-m-d H:i', (int)strtotime($until . ' UTC')) . ' UTC';
		$subj = $en ? "Honeypot64: {$r['ip']} released" : "Honeypot64: {$r['ip']} freigegeben";
		$text = $en ? "Your release request for {$r['ip']} was approved. The address is protected $d and leaves the live lists with the next evaluation (within 30 minutes), the daily lists with the next daily update.\n\nStatus: $link"
			: "Dein Freigabe-Antrag für {$r['ip']} wurde angenommen. Die Adresse ist $d geschützt und verschwindet mit der nächsten Bewertung (innerhalb von 30 Minuten) aus den Live-Listen, aus dem Tagesstand mit der nächsten Tagesaktualisierung.\n\nStatus: $link";
	} else {
		$subj = $en ? "Honeypot64: release request for {$r['ip']} declined" : "Honeypot64: Freigabe-Antrag für {$r['ip']} abgelehnt";
		$text = $en ? "Your release request for {$r['ip']} was declined because attacks from this address are still being reported. Please check the devices in your network (see the page below) and ask again later.\n\nStatus: $link"
			: "Dein Freigabe-Antrag für {$r['ip']} wurde abgelehnt, weil von dieser Adresse weiter Angriffe gemeldet werden. Bitte prüfe die Geräte in deinem Netz (Hinweise auf der Seite unten) und stelle später einen neuen Antrag.\n\nStatus: $link";
	}
	hpr_mail($pdo, $to, $subj, $text);
}
