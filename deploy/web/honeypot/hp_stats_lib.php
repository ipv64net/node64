<?php
/**
 * Honeypot64 (H4): oeffentliche Statistik, Ranglisten (Passwoerter, Benutzernamen, Pfade, User-Agents) und Cache.
 * Eingebunden (require_once) von honeypot/stats.php, api_v2_honeypot_stats.php (GET /threat/stats) und
 * bots/honeypot_lists.php (Text-Listen); definiert nur Konstanten und Funktionen ($pdo kommt vom Aufrufer).
 * Tabellen: hp_sample_contrib, hp_sample_top, hp_stats_cache (deploy/sql/honeypot_h4_stats.sql); liest die H2-Tabellen
 * und hp_scores (H3). Alle Zeiten UTC. Planung: docs/PLAN-NODE64-HONEYPOT64.md (Abschnitte 7, 8, 10, 13).
 *
 * Schutz gegen Vergiften: Ranglisten und Listen nehmen nur Proben, die mindestens N verschiedene Accounts in den letzten
 * 30 Tagen gemeldet haben (N = 2 unter 20 aktiven Accounts, sonst 3; Altbestand ohne Account-Bezug = Account 0 zaehlt
 * als einer). Je Account und Tag zaehlt eine Probe hoechstens HPS_CAP_DAY-mal (Rangfolge laesst sich nicht kaufen).
 * Bereinigt: keine Steuer-, Bidi- oder unsichtbaren Zeichen, keine E-Mail-Adressen, keine zufaelligen oder sehr langen
 * Strings, bei Benutzernamen keine Telefonnummern, bei Pfaden keine Allerweltspfade, bei User-Agents keine Browser und
 * keine bekannten Suchmaschinen/Monitoring-Dienste. Solche Eintraege fallen ganz weg (nichts wird umgeschrieben).
 *
 * H6: Rangliste der Fingerabdruecke (kind fp: JA4/HASSH aus hp_samples_fps, gleiche Schwelle, nur gueltige Keys).
 * Herkunft: Rangliste nach Land (top.countries) aus hp_scores.country, nur IPs der v64 Blocklist (also ab Schwelle).
 *
 * Cache: hps_overview() rechnet hoechstens alle HPS_TTL Sekunden neu (Sperre GET_LOCK, ein Prozess rechnet, die anderen
 * nehmen den alten Stand), sonst kommt alles aus hp_stats_cache.
 */
require_once dirname(__DIR__) . '/bots/honeypot_lists_index.php';

const HPS_DAYS        = 30;      // Fenster fuer Ranglisten, Schwelle und Listen
const HPS_TTL         = 600;     // Cache: hoechstens alle 10 Minuten neu rechnen
const HPS_CAP_DAY     = 10000;   // je Account, Tag und Probe hoechstens so viele Zaehler
const HPS_ACTIVE_LOW  = 20;      // unter so vielen aktiven Accounts (Meldung in 7 Tagen) Schwelle 2, sonst 3
const HPS_FP_MIN      = 3;       // Fingerabdruecke (JA4/HASSH) immer ab 3 Accounts: erkennen Software, keinen Angreifer
const HPS_TOP_PUBLIC  = 10;      // Ueberblick (alle)
const HPS_TOP_FULL    = 100;     // volle Seite (Klassen ausser Standard)
const HPS_KEEP        = array('pass' => 10000, 'user' => 10000, 'path' => 5000, 'ua' => 2000, 'fp' => 1000); // Eintraege je Rangliste
const HPS_MAXLEN      = array('pass' => 64, 'user' => 64, 'path' => 256, 'ua' => 256, 'fp' => 70);       // Zeichen
const HPS_TOPKEYS     = array('pass' => 'passwords', 'user' => 'usernames', 'path' => 'paths', 'ua' => 'user_agents', 'fp' => 'fingerprints');
const HPS_PATH_SKIP   = array('/', '/favicon.ico', '/robots.txt', '/sitemap.xml', '/index.html', '/index.htm', '/index.php', '/ads.txt',
	'/app-ads.txt', '/humans.txt', '/security.txt', '/manifest.json', '/site.webmanifest', '/browserconfig.xml', '/crossdomain.xml');
const HPS_PATH_SKIP_PREFIX = array('/.well-known/', '/apple-touch-icon', '/favicon');
const HPS_UA_GOOD     = '/googlebot|bingbot|applebot|duckduckbot|yandex(bot|images)|baiduspider|petalbot|facebookexternalhit|slackbot|twitterbot|linkedinbot|mediapartners-google|adsbot-google|google-inspectiontool|uptimerobot|pingdom|statuscake|site24x7|hetrixtools|betteruptime|letsencrypt|let\'s encrypt|certbot|acme\.sh/i';
const HPS_UA_TOOLS    = '/zgrab|masscan|nmap|nikto|sqlmap|nuclei|httpx|gobuster|dirbuster|feroxbuster|ffuf|wpscan|whatweb|python|aiohttp|go-http-client|libwww|lwp-|curl|wget|java\/|okhttp|scrapy|censys|shodan|expanse|internet-measurement|l9explore|l9tcpid|fasthttp|zmeu|morfeus|hello,? ?world|leakix|netcraft|nessus|openvas|acunetix|netsparker|odin|keydrop|assetnote/i';

// ---------------------------------------------------------------- Datenbank

/** Prepared Statement; Fehler als RuntimeException (unabhaengig vom PDO-Fehlermodus des Aufrufers). */
function hps_q(PDO $pdo, string $sql, array $p = array()): PDOStatement {
	try { $st = $pdo->prepare($sql); $ok = $st !== false && $st->execute($p); }
	catch(PDOException $e) { throw new RuntimeException('hp_stats SQL: ' . $e->getMessage(), 0, $e); }
	if(!$ok) { $i = $st !== false ? $st->errorInfo() : $pdo->errorInfo(); throw new RuntimeException('hp_stats SQL: ' . ($i[2] ?? 'unknown')); }
	return $st;
}
function hps_one(PDO $pdo, string $sql, array $p = array()): ?array { $r = hps_q($pdo, $sql, $p)->fetch(PDO::FETCH_ASSOC); return $r === false ? null : $r; }
function hps_all(PDO $pdo, string $sql, array $p = array()): array { return hps_q($pdo, $sql, $p)->fetchAll(PDO::FETCH_ASSOC); }
function hps_dt(int $ts): string { return gmdate('Y-m-d H:i:s', $ts); }
/** DB-Zeit (UTC) -> ISO 8601 */
function hps_iso($s): ?string { return ($s === null OR $s === '' OR str_starts_with((string)$s, '0000')) ? null : gmdate('Y-m-d\TH:i:s\Z', (int)strtotime($s . ' UTC')); }

/** Aktive Accounts (Meldung in 7 Tagen, Sensor nicht gesperrt; wie die Bewertung) und Schwelle N. */
function hps_threshold(PDO $pdo, int $now): array {
	$active = (int)hps_one($pdo, "SELECT COUNT(DISTINCT r.userid) n FROM hp_reports r JOIN hp_sensors s ON s.sensor_id = r.sensor_id
		WHERE r.received_at >= :d AND s.disabled = 0", array('d' => hps_dt($now - 7 * 86400)))['n'];
	return array($active, $active < HPS_ACTIVE_LOW ? 2 : 3);
}

// ---------------------------------------------------------------- Bereinigung

/** Shannon-Entropie in Bit je Zeichen (Bytes) */
function hps_entropy(string $s): float {
	$n = strlen($s); $e = 0.0;
	foreach(count_chars($s, 1) as $c) { $p = $c / $n; $e -= $p * log($p, 2); }
	return $e;
}

/** Sieht nach Schluessel, Hash oder Token aus? */
function hps_random(string $s): bool {
	$n = strlen($s);
	if($n >= 16 AND ctype_xdigit($s)) { return true; }
	if($n >= 20 AND preg_match('/^[A-Za-z0-9+\/=_-]+$/', $s) AND preg_match('/[0-9]/', $s) AND preg_match('/[A-Za-z]/', $s) AND hps_entropy($s) >= 3.8) { return true; }
	return $n >= 24 AND hps_entropy($s) >= 4.2;
}

/** Allerweltspfad (kein Angriff, nie sperren)? */
function hps_generic_path(string $p): bool {
	if(in_array(strtolower($p), HPS_PATH_SKIP, true)) { return true; }
	foreach(HPS_PATH_SKIP_PREFIX as $x) { if(str_starts_with(strtolower($p), $x)) { return true; } }
	return false;
}

/** Eintrag fuer Rangliste/Liste zulassen? Rueckgabe der unveraenderte Text oder null (faellt weg). */
function hps_clean(string $kind, string $s): ?string {
	if($s === '' OR !mb_check_encoding($s, 'UTF-8') OR mb_strlen($s, 'UTF-8') > HPS_MAXLEN[$kind]) { return null; }
	// Steuerzeichen (C0, DEL, C1), weiches Trennzeichen, Bidi-, unsichtbare und Format-Zeichen, Zeilentrenner, Ersatzzeichen,
	// 4-Byte-Zeichen (die Verbindung laeuft mit SET NAMES 'utf8'; die Annahme ersetzt sie ohnehin durch U+FFFD)
	if(preg_match('/[\x00-\x1F\x7F\x{80}-\x{9F}\x{AD}\x{061C}\x{180E}\x{200B}-\x{200F}\x{2028}-\x{202E}\x{2060}-\x{206F}\x{FEFF}\x{FFF9}-\x{FFFD}\x{10000}-\x{10FFFF}]/u', $s)) { return null; }
	if(preg_match('/^[\s\p{Z}]|[\s\p{Z}]$/u', $s)) { return null; }           // fuehrende/abschliessende Leerzeichen: im Textformat mehrdeutig
	if(preg_match('/[^\s@<>"]+@[^\s@<>"]+\.[A-Za-z]{2,}/u', $s)) { return null; } // E-Mail-Adresse
	switch($kind) {
		case 'user':
			if(preg_match('/^\+?[0-9][0-9 \/().-]{6,}$/', $s) AND preg_match_all('/[0-9]/', $s) >= 8) { return null; } // Telefonnummer
			return hps_random($s) ? null : $s;
		case 'pass':
			return hps_random($s) ? null : $s;
		case 'path':
			if($s[0] !== '/' OR hps_generic_path($s)) { return null; }
			foreach(preg_split('/[\/?&=;,+]/', $s) as $part) { if(hps_random($part)) { return null; } }
			return $s;
		case 'ua':
			if(preg_match(HPS_UA_GOOD, $s)) { return null; }
			if(!preg_match(HPS_UA_TOOLS, $s) AND preg_match('#^Mozilla/5\.0 \(#', $s) AND preg_match('#AppleWebKit/|Gecko/|Trident/|Chrome/|Safari/|Firefox/|Edg/#', $s)) { return null; } // Browser
			foreach(preg_split('/[\s;()\/,]+/', $s) as $part) { if(hps_random($part)) { return null; } }
			return $s;
		case 'fp': // H6: nur das Muster der Annahme (JA4/HASSH sehen zufaellig aus, darum ohne hps_random)
			return preg_match('/^(ja4:[a-z0-9_]{1,64}|hassh:[0-9a-f]{32})$/D', $s) ? $s : null;
	}
	return null;
}

// ---------------------------------------------------------------- Ranglisten

/**
 * hp_sample_top neu aufbauen (30 Tage, ab N Accounts, bereinigt). Teuer: nur ueber hps_overview() (hoechstens alle
 * 10 Minuten) bzw. den Listen-Cron aufrufen. Rueckgabe: Eintraege je Art.
 */
function hps_rebuild_top(PDO $pdo, int $n, int $now): array {
	$from = gmdate('Y-m-d', $now - (HPS_DAYS - 1) * 86400);
	$src = array('pass' => array('cred', 'hp_samples_creds', 'password'), 'user' => array('cred', 'hp_samples_creds', 'username'),
		'path' => array('path', 'hp_samples_paths', 'path'), 'ua' => array('ua', 'hp_samples_uas', 'user_agent'), 'fp' => array('fp', 'hp_samples_fps', 'fp'));
	$out = array();
	foreach($src as $kind => [$ck, $tab, $col]) {
		// CAST AS BINARY: Gross-/Kleinschreibung und Leerzeichen am Ende unterscheiden (die Spalten sind _general_ci)
		$rows = hps_all($pdo, "SELECT CAST(s.`$col` AS BINARY) t, SUM(LEAST(k.cnt, " . HPS_CAP_DAY . ")) e, COUNT(DISTINCT k.userid) a, MAX(s.last_seen) ls
			FROM hp_sample_contrib k JOIN `$tab` s ON s.day = k.day AND s.key_hash = k.key_hash
			WHERE k.kind = :k AND k.day >= :d GROUP BY t HAVING a >= " . ($kind === 'fp' ? max($n, HPS_FP_MIN) : $n) . " ORDER BY e DESC, a DESC, t LIMIT " . (HPS_KEEP[$kind] * 3),
			array('k' => $ck, 'd' => $from));
		$keep = array();
		foreach($rows as $r) {
			$t = hps_clean($kind, (string)$r['t']);
			if($t === null) { continue; }
			$keep[] = array($kind, count($keep) + 1, $t, (int)$r['e'], (int)$r['a'], (string)$r['ls']);
			if(count($keep) >= HPS_KEEP[$kind]) { break; }
		}
		$pdo->beginTransaction();
		try {
			hps_q($pdo, "DELETE FROM hp_sample_top WHERE kind = :k", array('k' => $kind));
			foreach(array_chunk($keep, 500) as $chunk) {
				hps_q($pdo, "INSERT INTO hp_sample_top (kind, pos, `text`, events, accounts, last_seen) VALUES " . implode(',', array_fill(0, count($chunk), '(?,?,?,?,?,?)')), array_merge(...$chunk));
			}
			$pdo->commit();
		} catch(Throwable $e) {
			if($pdo->inTransaction()) { $pdo->rollBack(); }
			throw $e;
		}
		$out[$kind] = count($keep);
	}
	return $out;
}

/** Rangliste einer Art (pass, user, path, ua) aus hp_sample_top. */
function hps_top(PDO $pdo, string $kind, int $limit): array {
	return array_map(fn($r) => array('value' => $r['text'], 'events' => (int)$r['events'], 'accounts' => (int)$r['accounts'], 'last_seen' => hps_iso($r['last_seen'])),
		hps_all($pdo, "SELECT `text`, events, accounts, last_seen FROM hp_sample_top WHERE kind = :k ORDER BY pos LIMIT " . max(1, $limit), array('k' => $kind)));
}

/** Suche in einer Rangliste (Teilstring, ohne Beachtung der Gross-/Kleinschreibung). */
function hps_search(PDO $pdo, string $kind, string $q, int $limit = HPS_TOP_FULL): array {
	return array_map(fn($r) => array('pos' => (int)$r['pos'], 'value' => $r['text'], 'events' => (int)$r['events'], 'accounts' => (int)$r['accounts'], 'last_seen' => hps_iso($r['last_seen'])),
		hps_all($pdo, "SELECT pos, `text`, events, accounts, last_seen FROM hp_sample_top WHERE kind = :k AND `text` LIKE :q ORDER BY pos LIMIT " . max(1, $limit),
			array('k' => $kind, 'q' => '%' . addcslashes($q, '%_\\') . '%')));
}

// ---------------------------------------------------------------- Deckung mit anderen Blocklisten

/** Netzadresse: Hostbits ab $len loeschen (Binaerstring wie inet_pton) */
function hps_mask(string $b, int $len): string {
	$m = '';
	for($i = 0; $i < strlen($b); $i++) { $k = max(0, min(8, $len - $i * 8)); $m .= chr($k === 0 ? 0 : (0xFF << (8 - $k)) & 0xFF); }
	return $b & $m;
}

/**
 * Deckung der v64 Blocklist (Live-Stand) mit den anderen Angreifer-Listen bei ipv64 (blocklisten.category attack und
 * botnet, auch die nicht in "all"; ohne Tor, Cloud, DoH, KI-Bots): wie viele IPs stehen auf mindestens einer davon
 * (als Adresse oder in einem Netz). Die uebrigen kennt nur Honeypot64. Je Praefixlaenge eine Hash-Menge der Netze.
 */
function hps_coverage(PDO $pdo): array {
	$nets = array(); $names = array();
	foreach(hps_all($pdo, "SELECT name, db_name FROM blocklisten WHERE category IN ('attack', 'botnet') AND disabled = 0 ORDER BY name") as $l) {
		if(!preg_match('/^[a-z0-9_]+$/', (string)$l['db_name'])) { continue; }
		$names[] = (string)$l['name'];
		foreach(hps_q($pdo, "SELECT ip FROM `" . $l['db_name'] . "`")->fetchAll(PDO::FETCH_COLUMN) as $s) {
			$p = explode('/', trim((string)$s, " \t\r\n[]"), 2);
			$b = @inet_pton(trim($p[0], '[]'));
			if($b === false OR (isset($p[1]) AND !ctype_digit($p[1]))) { continue; }
			$len = min(isset($p[1]) ? (int)$p[1] : 128, strlen($b) * 8);
			$nets[strlen($b)][$len][hps_mask($b, $len)] = true;
		}
	}
	$n = 0; $hit = 0;
	foreach(hps_q($pdo, "SELECT ip FROM hp_scores WHERE listed = 1 AND FIND_IN_SET('v64', lists) > 0")->fetchAll(PDO::FETCH_COLUMN) as $s) {
		$b = @inet_pton((string)$s);
		if($b === false) { continue; }
		$n++;
		foreach($nets[strlen($b)] ?? array() as $len => $set) { if(isset($set[hps_mask($b, $len)])) { $hit++; break; } }
	}
	return array('ips' => $n, 'on_other_lists' => $hit, 'only_v64' => $n - $hit, 'lists' => $names);
}

// ---------------------------------------------------------------- Ueberblick

/** Alles fuer Seite und API berechnen (ohne Cache). $rebuild = Ranglisten neu aufbauen. */
function hps_compute(PDO $pdo, string $bldir, int $now, bool $rebuild = true): array {
	[$active, $n] = hps_threshold($pdo, $now);
	if($rebuild) { hps_rebuild_top($pdo, $n, $now); }
	$today = gmdate('Y-m-d', $now); $from30 = gmdate('Y-m-d', $now - (HPS_DAYS - 1) * 86400); $from7 = gmdate('Y-m-d', $now - 6 * 86400);
	$o = array('generated_at' => gmdate('Y-m-d\TH:i:s\Z', $now), 'window_days' => HPS_DAYS, 'threshold' => array('accounts' => $n, 'active_accounts_7d' => $active));

	$s = hps_one($pdo, "SELECT COALESCE(SUM(last_seen >= :w), 0) a, COALESCE(SUM(last_seen >= :o), 0) o FROM hp_sensors WHERE disabled = 0 AND last_seen IS NOT NULL",
		array('w' => hps_dt($now - 7 * 86400), 'o' => hps_dt($now - 1800)));
	$o['sensors'] = array('active_7d' => (int)$s['a'], 'online' => (int)$s['o']);
	$a = hps_one($pdo, "SELECT COALESCE(SUM(`count`), 0) e, COUNT(DISTINCT ip_bin) s FROM hp_report_sources WHERE last_seen >= :d", array('d' => hps_dt($now - 86400)));
	$o['attacks_24h'] = array('events' => (int)$a['e'], 'sources' => (int)$a['s']);

	$days = array();
	for($i = HPS_DAYS - 1; $i >= 0; $i--) { $days[gmdate('Y-m-d', $now - $i * 86400)] = 0; }
	foreach(hps_all($pdo, "SELECT day, SUM(events) e FROM hp_daily WHERE day >= :d GROUP BY day", array('d' => $from30)) as $x) { if(isset($days[$x['day']])) { $days[$x['day']] = (int)$x['e']; } }
	$o['timeline'] = array_map(fn($d, $e) => array('day' => $d, 'events' => $e), array_keys($days), array_values($days));
	$o['top_ports'] = array_map(fn($x) => array('service' => $x['service'], 'port' => (int)$x['port'], 'events' => (int)$x['e']),
		hps_all($pdo, "SELECT service, port, SUM(events) e FROM hp_daily WHERE day >= :d GROUP BY service, port ORDER BY e DESC, port LIMIT " . HPS_TOP_FULL, array('d' => $from7)));
	$o['top_kinds'] = array_map(fn($x) => array('kind' => $x['kind'], 'events' => (int)$x['e']),
		hps_all($pdo, "SELECT kind, SUM(events) e FROM hp_daily WHERE day >= :d GROUP BY kind ORDER BY e DESC, kind LIMIT " . HPS_TOP_FULL, array('d' => $from7)));

	// Groesse der Listen: v64 Blocklist (Live-Stand aus hp_scores), Text-Listen (Dateien)
	$lists = array();
	try {
		$l = hps_one($pdo, "SELECT COALESCE(SUM(FIND_IN_SET('v64', lists) > 0), 0) v64 FROM hp_scores WHERE listed = 1");
		foreach($l as $k => $v) { $lists[$k] = (int)$v; }
	} catch(Throwable $e) { error_log('hp_stats lists: ' . $e->getMessage()); }
	foreach(hpl_index_entries($bldir) as $x) { $lists[$x['id']] = (int)$x['count']; }
	$o['lists'] = $lists;
	try { $o['coverage'] = hps_coverage($pdo); } catch(Throwable $e) { error_log('hp_stats coverage: ' . $e->getMessage()); }

	$o['top'] = array();
	foreach(HPS_TOPKEYS as $kind => $key) { $o['top'][$key] = hps_top($pdo, $kind, HPS_TOP_FULL); }
	// Herkunft nach Land: IPs der v64 Blocklist mit Sichtung in 30 Tagen, je Land IPs und Ereignisse (hp_scores.country)
	$o['top']['countries'] = array();
	try {
		$o['top']['countries'] = array_map(fn($x) => array('country' => strtoupper($x['c']), 'ips' => (int)$x['n'], 'events' => (int)$x['e']),
			hps_all($pdo, "SELECT country c, COUNT(*) n, COALESCE(SUM(events), 0) e FROM hp_scores WHERE listed = 1 AND FIND_IN_SET('v64', lists) > 0 AND last_seen >= :d
				AND country IS NOT NULL AND country != '' GROUP BY country ORDER BY n DESC, e DESC, c LIMIT 300", array('d' => hps_dt($now - HPS_DAYS * 86400))));
	} catch(Throwable $e) { error_log('hp_stats countries: ' . $e->getMessage()); } // Spalte country fehlt noch

	// neu gelistet heute (nur gelistete IPs; stehen ohnehin in der v64 Blocklist)
	$o['new_ips_today'] = array('count' => 0, 'items' => array());
	try {
		$o['new_ips_today']['count'] = (int)hps_one($pdo, "SELECT COUNT(*) n FROM hp_scores WHERE listed = 1 AND listed_since >= :t", array('t' => $today . ' 00:00:00'))['n'];
		$o['new_ips_today']['items'] = array_map(fn($x) => array('ip' => $x['ip'], 'score' => (int)$x['score'], 'accounts' => (int)$x['accounts'],
			'kinds' => $x['kinds'] === '' ? array() : explode(',', $x['kinds']), 'lists' => $x['lists'] === '' ? array() : explode(',', $x['lists']), 'listed_since' => hps_iso($x['listed_since'])),
			hps_all($pdo, "SELECT ip, score, accounts, kinds, lists, listed_since FROM hp_scores WHERE listed = 1 AND listed_since >= :t ORDER BY score DESC, accounts DESC, ip LIMIT " . HPS_TOP_FULL,
				array('t' => $today . ' 00:00:00')));
	} catch(Throwable $e) { error_log('hp_stats new ips: ' . $e->getMessage()); }

	// neue Pfade: heute erstmals gesehen, ab N Accounts (heute), bereinigt
	$np = array();
	foreach(hps_all($pdo, "SELECT p.path, p.`count` e, (SELECT COUNT(DISTINCT k.userid) FROM hp_sample_contrib k WHERE k.kind = 'path' AND k.day = p.day AND k.key_hash = p.key_hash) a
		FROM hp_samples_paths p WHERE p.day = :t AND NOT EXISTS (SELECT 1 FROM hp_samples_paths o WHERE o.key_hash = p.key_hash AND o.day < :t2)
		HAVING a >= " . (int)$n . " ORDER BY e DESC LIMIT 1000", array('t' => $today, 't2' => $today)) as $x) {
		$t = hps_clean('path', (string)$x['path']);
		if($t !== null) { $np[] = array('value' => $t, 'events' => (int)$x['e'], 'accounts' => (int)$x['a']); }
		if(count($np) >= HPS_TOP_FULL) { break; }
	}
	$o['new_paths_today'] = $np;
	return $o;
}

/**
 * Ueberblick aus dem Cache (hp_stats_cache 'overview'); aelter als HPS_TTL -> neu rechnen (ein Prozess, GET_LOCK).
 * $force: sofort neu rechnen (Cron), $rebuild: dabei auch die Ranglisten neu aufbauen.
 */
function hps_overview(PDO $pdo, string $bldir, bool $force = false, bool $rebuild = true): array {
	$now = time();
	$read = function() use ($pdo) {
		$r = hps_one($pdo, "SELECT data, updated_at FROM hp_stats_cache WHERE name = 'overview'");
		$d = $r === null ? null : json_decode((string)$r['data'], true);
		return is_array($d) ? array($d, (int)strtotime($r['updated_at'] . ' UTC')) : array(null, 0);
	};
	[$data, $at] = $read();
	if(!$force AND $data !== null AND $now - $at < HPS_TTL) { return $data; }
	// ohne Stand bis 30 s warten, sonst den alten Stand nehmen, wenn gerade ein anderer Prozess rechnet
	$got = (int)(hps_one($pdo, "SELECT GET_LOCK('hp_stats_refresh', :w) l", array('w' => ($data === null OR $force) ? 30 : 0))['l'] ?? 0);
	if($got !== 1) {
		if($data !== null) { return $data; }
		throw new RuntimeException('hp_stats: statistics are being computed');
	}
	try {
		if(!$force) { [$data, $at] = $read(); if($data !== null AND time() - $at < HPS_TTL) { return $data; } }
		$data = hps_compute($pdo, $bldir, $now, $rebuild);
		// ASCII-JSON: die Verbindung laeuft mit SET NAMES 'utf8'
		hps_q($pdo, "REPLACE INTO hp_stats_cache (name, data, updated_at) VALUES ('overview', :d, :t)", array('d' => json_encode($data, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE), 't' => hps_dt($now)));
		return $data;
	} finally {
		hps_q($pdo, "SELECT RELEASE_LOCK('hp_stats_refresh')");
	}
}

/** Ueberblick fuer alle (Seite ohne Anmeldung/Klasse Standard, GET /threat/stats): Top 10, ohne neue IPs/Pfade. */
function hps_public(array $o): array {
	$top = array();
	foreach($o['top'] as $k => $l) { $top[$k] = $k === 'countries' ? array_slice($l, 0, HPS_TOP_PUBLIC) : array_map(fn($x) => array('value' => $x['value'], 'events' => $x['events'], 'accounts' => $x['accounts']), array_slice($l, 0, HPS_TOP_PUBLIC)); }
	$top += array('countries' => array()); // Cache von vor der Herkunft
	return array('generated_at' => $o['generated_at'], 'window_days' => $o['window_days'], 'threshold' => $o['threshold'], 'sensors' => $o['sensors'],
		'attacks_24h' => $o['attacks_24h'], 'timeline' => $o['timeline'], 'top_ports' => array_slice($o['top_ports'], 0, HPS_TOP_PUBLIC),
		'top_kinds' => array_slice($o['top_kinds'], 0, HPS_TOP_PUBLIC), 'lists' => (object)$o['lists'], 'top' => $top,
		'info' => HPL_SOURCE, 'license' => HPL_LICENSE);
}

/** CSV-Zelle: Formel-Injektion in Tabellenprogrammen verhindern (= + - @ Tab CR am Anfang). */
function hps_csv_cell($v): string {
	$s = (string)$v;
	return ($s !== '' AND strpos("=+-@\t\r", $s[0]) !== false) ? "'" . $s : $s;
}
