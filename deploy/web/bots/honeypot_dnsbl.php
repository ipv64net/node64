<?php
/**
 * Honeypot64 (Phase H4): DNS-Sperrliste bl.ipv64.net (DNSBL) aus dem Tagesstand der v64 Blocklist, Abgleich mit
 * PowerDNS ueber zone_update() aus dbconnect.php. Planung: docs/PLAN-NODE64-HONEYPOT64.md (Abschnitte 7, 8, H4) im
 * Node64-Repo, Tabelle: deploy/sql/honeypot_h4_dnsbl.sql, Einspielen: deploy/web/H4-DNSBL-VORHER-NACHHER.md.
 *
 * Cron stuendlich (der Tagesstand entsteht einmal je UTC-Tag beim ersten Lauf von create_blocklists_v2.php um 00:07;
 * die uebrigen Laeufe finden keine Unterschiede oder wiederholen fehlgeschlagene Bloecke):
 *   50 * * * * php .../bots/honeypot_dnsbl.php >> .../private/honeypot_dnsbl.log 2>&1
 * Aufruf:  php honeypot_dnsbl.php                 abgleichen (nur Unterschiede seit dem letzten Lauf)
 *          php honeypot_dnsbl.php --dry           nur rechnen und Zahlen ausgeben, nichts schreiben
 *          php honeypot_dnsbl.php --full          alle Eintraege neu schreiben (z. B. nach Neuanlage der Zone)
 *          php honeypot_dnsbl.php --force         Plausibilitaetspruefung uebergehen (Quelle stark geschrumpft/leer)
 *          php honeypot_dnsbl.php --create-zone   einmalig: Zone anlegen (Master + Slave) und in ipv64.net delegieren
 *                                                 (mit --dry nur die JSON-Anfragen anzeigen)
 *
 * Abfrage wie Spamhaus/RFC 5782: IPv4 1.2.3.4 -> 4.3.2.1.bl.ipv64.net, IPv6 als 32 umgekehrte Nibbles.
 * Antwort (TTL 300): A 127.0.0.2 fuer jede gelistete IP, dazu je Teilliste 127.0.0.3 ssh/telnet, .4 web, .5 mail,
 * .6 rdp, .7 scanner (mehrere A-Records moeglich); TXT mit Arten und Link zur IP-Auskunft. Forschungs-Scanner
 * (research) stehen nicht in der DNSBL. Testeintraege nach RFC 5782: 127.0.0.2 und ::ffff:127.0.0.2 immer gelistet,
 * 127.0.0.1 nie.
 *
 * Quelle: Tagesstand ipv64_blocklist_v64.txt und Teillisten ipv64_blocklist_v64_<art>.txt im Ordner blocklists/
 * (frei fuer alle, einmal je Tag). Freigaben, die nach dem Stichtag erteilt wurden (hp_allowlist,
 * hp_release_requests.protected_until), nimmt die DNSBL sofort heraus - ein Mailserver soll nicht bis zu 24 h eine
 * freigegebene IP abweisen.
 * TODO (Plan Abschnitt 8, spaeter): Live-Antworten fuer eingetragene Mailserver-IPs der Klassen ausser Standard
 * (eigene Zone bzw. Ansicht je abfragender IP, Limits je Mailserver ueber die Klassenwerte).
 *
 * Abgleich: Zustand in hp_dnsbl (was in der Zone steht). Je Lauf nur neue, geaenderte und entfallene Namen, in
 * Bloecken von hoechstens HPD_BLOCK RRsets je PATCH; ein Name (A + TXT) wird nie auf zwei Bloecke verteilt. Zustand
 * erst nach Erfolg des Blocks; schlaegt ein Block fehl, holt ihn der naechste Lauf nach. Ist die Quelle leer,
 * unlesbar, zu fehlerhaft oder viel kleiner als der letzte Stand, bleibt die Zone unveraendert.
 */

const HPD_ZONE        = 'bl.ipv64.net';
const HPD_TTL         = 300;              // TTL der Eintraege
const HPD_BLOCK       = 1000;             // hoechstens so viele RRsets je PATCH (500 Namen, A + TXT)
const HPD_MAX_FAIL    = 3;                // Abbruch nach so vielen fehlgeschlagenen Bloecken in Folge
const HPD_MAX_BAD     = 0.01;             // Abbruch, wenn mehr als 1 % der Zeilen ungueltig sind
const HPD_SHRINK_BASE = 200;              // ab so vielen Eintraegen im Zustand gilt die Schrumpf-Grenze
const HPD_MAX_SHRINK  = 0.5;              // Abbruch, wenn die Quelle mehr als 50 % kleiner ist als der Zustand
const HPD_SETTLE      = 60;               // Datei juenger als 60 s: Generator schreibt gerade, naechster Lauf
const HPD_SKEW        = 3600;             // Teilliste weicht mehr als 1 h vom Stichtag der Hauptliste ab: Warnung
const HPD_STALE       = 3 * 86400;        // Tagesstand aelter als 3 Tage: Warnung
const HPD_INFO        = 'https://ipv64.net/honeypot/ip.php?ip=';

// Rueckgabecode der v64 Blocklist (Datei ipv64_blocklist_v64.txt); die Teillisten mit Codes 3-7 gibt es seit 2026-10
// nicht mehr
const HPD_CODES = array('v64' => 2);
// Testeintraege nach RFC 5782 (Abschnitt 5): muessen immer antworten
const HPD_TESTS = array('127.0.0.2', '::ffff:127.0.0.2');

// nur fuer --create-zone: wie beim Anlegen eigener Domains in dbconnect.php (Master, Slave mit internem Master)
const HPD_NS      = array('ns1.ipv64.net.', 'ns2.ipv64.net.');
const HPD_SOA     = 'ns1.ipv64.net. hostmaster.ipv64.net. 1 900 300 604800 300'; // refresh, retry, expire, negativ-TTL
const HPD_SERVERS = array('195.201.223.103' => 'Master', '157.90.241.20' => 'Slave');
const HPD_MASTERS = array('10.10.0.2');
const HPD_PARENT  = 'ipv64.net';

// ---------------------------------------------------------------- Namen und Eintraege

/** Name relativ zur Zone aus der Binaerform: 4.3.2.1 bzw. 32 umgekehrte Nibbles (RFC 5782) */
function hpd_name_bin(string $bin): ?string {
	if(strlen($bin) === 4) { return implode('.', array_reverse(array_values(unpack('C4', $bin)))); }
	if(strlen($bin) === 16) { return implode('.', str_split(strrev(bin2hex($bin)))); }
	return null;
}

function hpd_name(string $ip): ?string {
	$bin = filter_var($ip, FILTER_VALIDATE_IP) ? inet_pton($ip) : false;
	return $bin === false ? null : hpd_name_bin($bin);
}

/** Eintrag einer gelisteten IP: a = A-Records (Komma, aufsteigend), txt = Grund + Link */
function hpd_entry(string $ip, array $lists): array {
	$a = array(); $kinds = array();
	foreach(HPD_CODES as $l => $c) {
		if(!isset($lists[$l])) { continue; }
		$a[] = "127.0.0.$c";
		if($l !== 'v64') { $kinds[] = $l; }
	}
	if(!$a) { $a[] = '127.0.0.2'; }
	if(!in_array('127.0.0.2', $a, true)) { array_unshift($a, '127.0.0.2'); }
	$txt = 'Listed by IPv64.net Honeypot64' . ($kinds ? ' (' . implode(',', $kinds) . ')' : '') . ': ' . HPD_INFO . $ip;
	return array('ip' => $ip, 'a' => implode(',', $a), 'txt' => substr($txt, 0, 255));
}

function hpd_test_entry(string $ip): array {
	return array('ip' => $ip, 'a' => '127.0.0.2', 'txt' => 'Test entry (RFC 5782), IPv64.net Honeypot64 DNSBL');
}

/** RRsets fuer PowerDNS: $e = Eintrag (REPLACE) oder null (DELETE) */
function hpd_rrsets(string $name, ?array $e): array {
	$fq = $name . '.' . HPD_ZONE . '.';
	if($e === null) {
		return array(array('name' => $fq, 'type' => 'A', 'changetype' => 'DELETE'), array('name' => $fq, 'type' => 'TXT', 'changetype' => 'DELETE'));
	}
	$a = array();
	foreach(explode(',', $e['a']) as $x) { $a[] = array('content' => $x, 'disabled' => false); }
	return array(
		array('name' => $fq, 'type' => 'A', 'ttl' => HPD_TTL, 'changetype' => 'REPLACE', 'records' => $a),
		array('name' => $fq, 'type' => 'TXT', 'ttl' => HPD_TTL, 'changetype' => 'REPLACE',
			'records' => array(array('content' => '"' . addcslashes($e['txt'], '"\\') . '"', 'disabled' => false))),
	);
}

// ---------------------------------------------------------------- Quelle: Tagesstand

/**
 * Liest den Tagesstand aus $dir. Rueckgabe: err ('' = gut), warn, ips (Name => [ip, lists]), lines, bad, nets, stamp.
 * Nur Einzeladressen (/32, /128) kommen in die DNSBL; Teillisten liefern nur Codes fuer IPs der Hauptliste.
 */
function hpd_read_source(string $dir, int $now): array {
	$r = array('err' => '', 'warn' => array(), 'ips' => array(), 'lines' => 0, 'bad' => 0, 'nets' => 0, 'stamp' => 0);
	clearstatcache();
	$files = array();
	foreach(HPD_CODES as $l => $c) { $files[$l] = $dir . '/ipv64_blocklist_' . ($l === 'v64' ? 'v64' : "v64_$l") . '.txt'; }
	if(!is_file($files['v64']) OR !is_readable($files['v64'])) { $r['err'] = 'Tagesstand fehlt: ' . $files['v64']; return $r; }
	$r['stamp'] = (int)filemtime($files['v64']);
	foreach($files as $l => $f) {
		if(!is_file($f)) { $r['warn'][] = 'Teilliste fehlt: ' . basename($f) . ' (ohne deren Code)'; unset($files[$l]); continue; }
		$m = (int)filemtime($f);
		if($m > $now - HPD_SETTLE) { $r['err'] = 'Tagesstand wird gerade geschrieben (' . basename($f) . '), naechster Lauf'; return $r; }
		if(abs($m - $r['stamp']) > HPD_SKEW) { $r['warn'][] = 'Teilliste ' . basename($f) . ' nicht vom selben Stichtag (' . gmdate('Y-m-d H:i', $m) . ' UTC)'; }
	}
	if($r['stamp'] < $now - HPD_STALE) { $r['warn'][] = 'Tagesstand alt: ' . gmdate('Y-m-d H:i', $r['stamp']) . ' UTC (Generator pruefen)'; }
	foreach($files as $l => $f) { // v64 zuerst (Reihenfolge von HPD_CODES)
		$fh = @fopen($f, 'r');
		if($fh === false) {
			if($l === 'v64') { $r['err'] = 'Tagesstand nicht lesbar: ' . $f; return $r; }
			$r['warn'][] = 'Teilliste nicht lesbar: ' . basename($f); continue;
		}
		while(($line = fgets($fh)) !== false) {
			$line = trim($line);
			if($line === '' OR $line[0] === '#') { continue; }
			$r['lines']++;
			$ip = $line; $len = null;
			if(str_contains($line, '/')) { [$ip, $len] = explode('/', $line, 2); }
			$bin = filter_var($ip, FILTER_VALIDATE_IP) ? inet_pton($ip) : false;
			if($bin === false OR ($len !== null AND !ctype_digit($len))) { $r['bad']++; continue; }
			if($len !== null AND (int)$len !== strlen($bin) * 8) { $r['nets']++; continue; } // Netze nicht in der DNSBL
			$name = hpd_name_bin($bin);
			if($l === 'v64') { $r['ips'][$name] = array('ip' => inet_ntop($bin), 'lists' => array('v64' => true)); }
			elseif(isset($r['ips'][$name])) { $r['ips'][$name]['lists'][$l] = true; }
		}
		fclose($fh);
	}
	if($r['lines'] > 0 AND $r['bad'] / $r['lines'] > HPD_MAX_BAD) {
		$r['err'] = "Tagesstand fehlerhaft: {$r['bad']} von {$r['lines']} Zeilen ungueltig - Zone bleibt unveraendert";
	}
	return $r;
}

/** Freigaben jetzt: [Bereiche aus hp_allowlist, Set aus hp_release_requests]; fehlende Tabellen nur Warnung */
function hpd_releases(PDO $pdo, int $now, array &$warn): array {
	$n = gmdate('Y-m-d H:i:s', $now); $ranges = array(); $set = array();
	try {
		$st = $pdo->prepare("SELECT ip_start, ip_end FROM hp_allowlist WHERE `until` IS NULL OR `until` > :n"); $st->execute(array('n' => $n));
		foreach($st->fetchAll(PDO::FETCH_ASSOC) as $x) {
			if(strlen((string)$x['ip_start']) > 0 AND strlen((string)$x['ip_start']) === strlen((string)$x['ip_end'])) { $ranges[] = array((string)$x['ip_start'], (string)$x['ip_end']); }
		}
	} catch(Throwable $e) { $warn[] = 'hp_allowlist nicht lesbar'; }
	try {
		$st = $pdo->prepare("SELECT ip_bin FROM hp_release_requests WHERE protected_until > :n"); $st->execute(array('n' => $n));
		foreach($st->fetchAll(PDO::FETCH_COLUMN) as $b) { $set[(string)$b] = true; }
	} catch(Throwable $e) { $warn[] = 'hp_release_requests nicht lesbar'; }
	return array($ranges, $set);
}

function hpd_released(string $bin, array $ranges, array $set): bool {
	if(isset($set[$bin])) { return true; }
	foreach($ranges as [$s, $e]) { if(strlen($s) === strlen($bin) AND strcmp($bin, $s) >= 0 AND strcmp($bin, $e) <= 0) { return true; } }
	return false;
}

// ---------------------------------------------------------------- Abgleich

/** Unterschiede Soll ($want) zu Zustand ($state), je Name => [ip, a, txt]; $full = alle Soll-Namen neu schreiben */
function hpd_diff(array $want, array $state, bool $full): array {
	$d = array('add' => array(), 'chg' => array(), 'del' => array(), 'same' => 0);
	foreach($want as $n => $e) {
		if(!isset($state[$n])) { $d['add'][] = (string)$n; }
		elseif($full OR $state[$n]['a'] !== $e['a'] OR $state[$n]['txt'] !== $e['txt']) { $d['chg'][] = (string)$n; }
		else { $d['same']++; }
	}
	foreach($state as $n => $x) { if(!isset($want[$n])) { $d['del'][] = (string)$n; } }
	sort($d['add'], SORT_STRING); sort($d['chg'], SORT_STRING); sort($d['del'], SORT_STRING);
	return $d;
}

/** Aenderungen in Bloecke: je Name zwei RRsets (A + TXT), hoechstens $max RRsets je Block */
function hpd_blocks(array $ops, int $max): array {
	return $ops ? array_chunk($ops, max(1, intdiv($max, 2))) : array();
}

/** Zustand nach erfolgreichem Block nachziehen (REPLACE/DELETE gehen in MariaDB und SQLite) */
function hpd_state_write(PDO $pdo, array $blk, string $at): void {
	$set = array(); $del = array();
	foreach($blk as $o) {
		if($o['e'] === null) { $del[] = $o['name']; }
		else { array_push($set, $o['name'], $o['e']['ip'], $o['e']['a'], $o['e']['txt'], $at); }
	}
	$pdo->beginTransaction();
	try {
		if($set) { $pdo->prepare("REPLACE INTO hp_dnsbl (name, ip, a, txt, synced_at) VALUES " . implode(',', array_fill(0, count($set) / 5, '(?,?,?,?,?)')))->execute($set); }
		if($del) { $pdo->prepare("DELETE FROM hp_dnsbl WHERE name IN (" . implode(',', array_fill(0, count($del), '?')) . ")")->execute($del); }
		$pdo->commit();
	} catch(Throwable $e) {
		if($pdo->inTransaction()) { $pdo->rollBack(); }
		throw $e;
	}
}

/**
 * Ein Lauf. $patch(string $json, string $zone): bool ist zone_update() aus dbconnect.php (im Test ein Stub).
 * $opt: dry, full, force. Rueckgabe: Zahlen fuer Log und Test; ok = false bei Abbruch oder fehlgeschlagenen Bloecken.
 */
function hpd_run(PDO $pdo, string $dir, array $opt, callable $patch, int $now): array {
	$t0 = microtime(true);
	$res = array('ok' => false, 'err' => '', 'warn' => array(), 'source' => 0, 'nets' => 0, 'bad' => 0, 'released' => 0, 'want' => 0, 'state' => 0,
		'add' => 0, 'chg' => 0, 'del' => 0, 'same' => 0, 'blocks' => 0, 'blocks_ok' => 0, 'blocks_err' => 0, 'written' => 0, 'stamp' => 0, 'secs' => 0.0);
	$done = function() use (&$res, $t0) { $res['secs'] = round(microtime(true) - $t0, 2); return $res; };

	$src = hpd_read_source($dir, $now);
	$res['warn'] = $src['warn']; $res['nets'] = $src['nets']; $res['bad'] = $src['bad']; $res['stamp'] = $src['stamp']; $res['source'] = count($src['ips']);
	if($src['err'] !== '') { $res['err'] = $src['err']; return $done(); }

	$state = array();
	try {
		foreach($pdo->query("SELECT name, ip, a, txt FROM hp_dnsbl")->fetchAll(PDO::FETCH_ASSOC) as $x) { $state[$x['name']] = $x; }
	} catch(Throwable $e) { $res['err'] = 'hp_dnsbl nicht lesbar (honeypot_h4_dnsbl.sql eingespielt?): ' . $e->getMessage(); return $done(); }

	[$ranges, $set] = hpd_releases($pdo, $now, $res['warn']);
	$want = array();
	foreach($src['ips'] as $n => $x) {
		if(hpd_released(inet_pton($x['ip']), $ranges, $set)) { $res['released']++; continue; }
		$want[$n] = hpd_entry($x['ip'], $x['lists']);
	}
	unset($src);
	$res['want'] = count($want);
	$tests = array();
	foreach(HPD_TESTS as $ip) { $tests[hpd_name($ip)] = true; $want[hpd_name($ip)] = hpd_test_entry($ip); }
	$res['state'] = count(array_diff_key($state, $tests));

	// Plausibilitaet: nie die Zone leeren oder stark schrumpfen, nur weil die Quelle kaputt ist
	if(empty($opt['force'])) {
		if($res['state'] > 0 AND $res['want'] === 0) {
			$res['err'] = "Quelle ohne Eintraege, Zone hat {$res['state']} - nichts geaendert (absichtlich: --force)"; return $done();
		}
		if($res['state'] >= HPD_SHRINK_BASE AND $res['want'] < $res['state'] * (1 - HPD_MAX_SHRINK)) {
			$res['err'] = "Quelle mit {$res['want']} Eintraegen viel kleiner als die Zone ({$res['state']}) - nichts geaendert (absichtlich: --force)"; return $done();
		}
	}

	$d = hpd_diff($want, $state, !empty($opt['full']));
	$res['add'] = count($d['add']); $res['chg'] = count($d['chg']); $res['del'] = count($d['del']); $res['same'] = $d['same'];
	$ops = array();
	foreach(array_merge($d['add'], $d['chg']) as $n) { $ops[] = array('name' => $n, 'e' => $want[$n]); }
	foreach($d['del'] as $n) { $ops[] = array('name' => $n, 'e' => null); }
	$blocks = hpd_blocks($ops, HPD_BLOCK);
	$res['blocks'] = count($blocks);
	if(!empty($opt['dry'])) { $res['ok'] = true; return $done(); }

	$fail = 0; $at = gmdate('Y-m-d H:i:s', $now);
	foreach($blocks as $i => $blk) {
		$rr = array();
		foreach($blk as $o) { array_push($rr, ...hpd_rrsets($o['name'], $o['e'])); }
		if(!$patch(json_encode(array('rrsets' => $rr), JSON_UNESCAPED_SLASHES), HPD_ZONE)) {
			$res['blocks_err']++; $fail++;
			if($fail >= HPD_MAX_FAIL) {
				$res['warn'][] = "Abbruch nach $fail fehlgeschlagenen Bloecken in Folge, " . (count($blocks) - $i - 1) . ' Bloecke beim naechsten Lauf';
				break;
			}
			continue;
		}
		$fail = 0; $res['blocks_ok']++; $res['written'] += count($blk);
		try { hpd_state_write($pdo, $blk, $at); }
		catch(Throwable $e) { $res['warn'][] = 'Zustand nicht geschrieben (Block ' . ($i + 1) . ', wird wiederholt): ' . $e->getMessage(); }
	}
	if($res['blocks_err'] > 0) { $res['err'] = "{$res['blocks_err']} von {$res['blocks']} Bloecken fehlgeschlagen, Wiederholung beim naechsten Lauf"; }
	else { $res['ok'] = true; }
	return $done();
}

/** Logzeilen eines Laufs */
function hpd_log(array $res, array $opt): string {
	$s = sprintf("%s UTC %s%s: Tagesstand %s, Quelle %d IPs (Netze uebergangen %d, ungueltig %d, freigegeben %d), Soll %d, Zone %d\n",
		gmdate('Y-m-d H:i:s'), HPD_ZONE, !empty($opt['dry']) ? ' (nur rechnen)' : '', $res['stamp'] ? gmdate('Y-m-d H:i', $res['stamp']) . ' UTC' : '-',
		$res['source'], $res['nets'], $res['bad'], $res['released'], $res['want'], $res['state']);
	$s .= sprintf("  neu %d, geaendert %d, entfernt %d, gleich %d; Bloecke %d (ok %d, Fehler %d), Namen geschrieben %d; Laufzeit %.2f s\n",
		$res['add'], $res['chg'], $res['del'], $res['same'], $res['blocks'], $res['blocks_ok'], $res['blocks_err'], $res['written'], $res['secs']);
	foreach($res['warn'] as $w) { $s .= "  Warnung: $w\n"; }
	if($res['err'] !== '') { $s .= "  FEHLER: {$res['err']}\n"; }
	return $s;
}

// ---------------------------------------------------------------- Einmalig: Zone anlegen und delegieren

/** Anfragen fuer --create-zone: [[funktion, json, ziel], ...] */
function hpd_zone_setup(): array {
	$out = array();
	foreach(HPD_SERVERS as $server => $kind) {
		$post = array('kind' => $kind, 'id' => HPD_ZONE . '.', 'name' => HPD_ZONE . '.', 'type' => 'Zone', 'notified_serial' => '1',
			'soa_edit_api' => 'INCREASE', 'nameservers' => HPD_NS,
			'rrsets' => array(array('name' => HPD_ZONE . '.', 'type' => 'SOA', 'ttl' => HPD_TTL, 'records' => array(array('content' => HPD_SOA, 'disabled' => false)))));
		if($kind === 'Slave') { $post['masters'] = HPD_MASTERS; }
		$out[] = array('zone_create', json_encode($post, JSON_UNESCAPED_SLASHES), $server);
	}
	// Delegation in der Elternzone (nur dieses NS-RRset; sonst nichts an ipv64.net)
	$ns = array(); foreach(HPD_NS as $x) { $ns[] = array('content' => $x, 'disabled' => false); }
	$out[] = array('zone_update', json_encode(array('rrsets' => array(array('name' => HPD_ZONE . '.', 'type' => 'NS', 'ttl' => 3600, 'changetype' => 'REPLACE', 'records' => $ns))), JSON_UNESCAPED_SLASHES), HPD_PARENT);
	return $out;
}

// ---------------------------------------------------------------- Start (nicht im Test)

if(!defined('HPD_TEST')) {
	if(php_sapi_name() !== 'cli') { exit; }
	include(__DIR__ . "/../dbconnect.php");
	set_time_limit(3600);
	ini_set('memory_limit', '1024M');
	$opt = array('dry' => in_array('--dry', $argv, true), 'full' => in_array('--full', $argv, true), 'force' => in_array('--force', $argv, true));

	if(in_array('--create-zone', $argv, true)) {
		foreach(hpd_zone_setup() as [$fn, $json, $target]) {
			echo "$fn($target): $json\n";
			if($opt['dry']) { continue; }
			$r = $fn($json, $target);
			if($fn === 'zone_update') { echo $r ? "  Delegation gesetzt\n" : "  Delegation fehlgeschlagen (in PowerDNS-Admin von Hand setzen)\n"; }
		}
		echo $opt['dry'] ? "*** nur angezeigt ***\n" : "Fertig. Pruefen: dig +short SOA " . HPD_ZONE . " @ns1.ipv64.net, danach php honeypot_dnsbl.php --full\n";
		exit(0);
	}

	// nicht zweimal gleichzeitig
	$lock = fopen(sys_get_temp_dir() . '/ipv64_honeypot_dnsbl.lock', 'c');
	if($lock === false OR !flock($lock, LOCK_EX | LOCK_NB)) { echo gmdate('Y-m-d H:i:s') . " UTC laeuft schon, Ende\n"; exit(0); }

	$res = hpd_run($pdo, __DIR__ . '/../blocklists', $opt, 'zone_update', time());
	echo hpd_log($res, $opt);
	exit($res['ok'] ? 0 : 1);
}
