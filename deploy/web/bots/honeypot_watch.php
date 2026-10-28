<?php
/**
 * Honeypot64 (H5): Fruehwarnung fuer eigene Netze und DynDNS-IPs (Plan Abschnitt 11). Alle 30 Minuten, 5 Minuten nach
 * der Bewertung (bots/blocklist/honeypot_score.php laeuft um 7 und 37), nur auf der Kommandozeile:
 *
 *   12,42 * * * * php .../bots/honeypot_watch.php > /dev/null
 *   php honeypot_watch.php            ausfuehren
 *   php honeypot_watch.php --dry      nur anzeigen (nichts schreiben, keine Mail)
 *
 * Grundlage ist hp_scores (Ergebnis der Bewertung): enthaelt jede Sichtung der letzten 14 Tage ausser IPs von Sensoren
 * und nicht oeffentlichen Adressen – so verraet die Fruehwarnung keine Sensoren. Kandidaten sind IPs mit Sichtung in
 * den letzten HPW_LOOKBACK Sekunden oder frisch gelistet.
 *   - Netze (hp_watch): Bereichsvergleich LENGTH(ip_start) = LENGTH(ip_bin) AND ip_start <= ip_bin AND ip_end >= ip_bin,
 *     je Netz eine Bereichssuche im Primaerschluessel von hp_scores (STRAIGHT_JOIN, auch bei vielen Netzen schnell).
 *     Ohne Nachweis (verified = 0) nur gelistete IPs.
 *   - DynDNS-IPs: aktuelle A/AAAA-Records des Accounts (dieselbe Quelle wie reason customer_ip in der Bewertung, ohne
 *     CDN-Hilfseintraege). Ein Record ist KEIN Nachweis (jeder kann jede IP eintragen; sonst liessen sich mit einem
 *     Record auf die eigene Scanner-IP Sensoren finden): wie die IP-Auskunft nur gelistete IPs, Details grob (ohne
 *     Port und Regel, Zeiten nur auf den Tag). HPW_SHARED_MAX zaehlt nur noch fuer die Statistik.
 * Je Account und IP hoechstens ein Treffer je 24 h, ausser die IP wird neu gelistet; nach 24 h nur bei neuer Sichtung
 * (hp_scores.last_seen spaeter als beim letzten Treffer). Passt eine IP mehrfach, gewinnt DynDNS, dann das kleinste Netz.
 * Hoechstens HPW_PER_RUN Treffer je Account und Lauf (gelistete und hohe Werte zuerst, der Rest folgt im naechsten Lauf).
 * Nie gemeldet: Server von ipv64 und CDN (hp_scores.reason infra/cdn, die Bewertung kennzeichnet sie auch unter der
 * Schwelle). Je Treffer speichert der Lauf Details (hp_watch_alerts.details, JSON): wie oft, wo und wie die IP in den
 * letzten 14 Tagen aufgefallen ist – nur Anzahlen, Dienste, Ports, Arten und Regeln, nie Sensoren, Accounts oder Inhalte.
 * Mail: je Account eine Mail je Lauf an die Account-Adresse mit allen noch nicht gemeldeten Treffern der letzten 24 h.
 * Fristen: Treffer nach 90 Tagen loeschen.
 */
if(php_sapi_name() !== 'cli') { exit; }
include(__DIR__ . "/../dbconnect.php");
require_once __DIR__ . '/../honeypot/hp_limits_lib.php';
set_time_limit(900);
ini_set('memory_limit', '512M');

const HPW_LOOKBACK   = 2 * 86400;   // Sichtungen der letzten 2 Tage (Meldungen kommen bis zu einigen Stunden spaeter an)
const HPW_REPEAT     = 86400;       // eine IP je Account hoechstens einmal je 24 h (ausser neu gelistet)
const HPW_PER_RUN    = 100;         // Treffer je Account und Lauf (Rest im naechsten Lauf; begrenzt Mails und Schreiblast)
const HPW_SHARED_MAX = 3;           // DynDNS-IP in Records von mehr Accounts: kein Nachweis
const HPW_KEEP_DAYS  = 90;          // Treffer aufheben
const HPW_MAIL_MAX   = 25;          // so viele IPs stehen in der Mail, der Rest als Anzahl
const HPW_PAGE_URL   = 'https://ipv64.net/honeypot/watch.php';

$dry = in_array('--dry', $argv, true);
$now = time(); $run = hpr_dt($now);
echo ($dry ? "NUR ANZEIGEN" : "AUSFUEHREN") . ": $run UTC\n";
if((int)(hpr_one($pdo, "SELECT GET_LOCK('hp_watch', 0) l")['l'] ?? 0) !== 1) { echo "laeuft bereits\n"; exit(0); }

/** Zeilen ungepuffert lesen (grosse Abfragen); waehrenddessen keine andere Abfrage auf derselben Verbindung. */
function hpw_stream(PDO $pdo, string $sql, array $p, callable $fn): void {
	$pdo->setAttribute(PDO::MYSQL_ATTR_USE_BUFFERED_QUERY, false);
	try {
		$st = hpr_q($pdo, $sql, $p);
		while(($r = $st->fetch(PDO::FETCH_ASSOC)) !== false) { $fn($r); }
		$st->closeCursor();
	} finally {
		$pdo->setAttribute(PDO::MYSQL_ATTR_USE_BUFFERED_QUERY, true);
	}
}

$lb = hpr_dt($now - HPW_LOOKBACK);
$cols = "s.ip_bin, s.ip, s.score, s.kinds, s.first_seen, s.last_seen, s.listed, s.listed_since, s.reason, s.accounts, s.sensors, s.events, s.lists";
$when = "(s.last_seen >= :lb1 OR (s.listed = 1 AND s.listed_since >= :lb2))";
$cand = array(); // "userid|bin" -> Treffer (bester Treffer je Account und IP)
$nInfra = 0;
$add = function(int $u, array $s, string $source, ?int $net, string $cidr, string $label, int $prio) use (&$cand, &$nInfra) {
	if($s['reason'] === 'infra' OR $s['reason'] === 'cdn') { $nInfra++; return; } // eigene Server und CDN: keine Fruehwarnung
	$k = $u . '|' . $s['ip_bin'];
	if(isset($cand[$k]) AND $cand[$k]['prio'] >= $prio) { return; }
	$cand[$k] = array('u' => $u, 's' => $s, 'source' => $source, 'net' => $net, 'cidr' => $cidr, 'label' => $label, 'prio' => $prio);
};

// ---------------------------------------------------------------- 1. Netze
$nNet = 0;
foreach(hpr_all($pdo, "SELECT STRAIGHT_JOIN w.id wid, w.userid, w.cidr, w.label, w.verified, $cols
	FROM hp_watch w JOIN hp_scores s ON LENGTH(w.ip_start) = LENGTH(s.ip_bin) AND w.ip_start <= s.ip_bin AND w.ip_end >= s.ip_bin
	WHERE (w.verified = 1 OR s.listed = 1) AND $when", array('lb1' => $lb, 'lb2' => $lb)) as $r) {
	$nNet++;
	// kleineres Netz = hoeherer Vorrang (Praefixlaenge relativ zur Familie), DynDNS liegt darueber
	$prio = (int)explode('/', $r['cidr'])[1] + (strlen($r['ip_bin']) === 4 ? 96 : 0);
	$add((int)$r['userid'], $r, 'network', (int)$r['wid'], $r['cidr'], (string)$r['label'], $prio);
}

// ---------------------------------------------------------------- 2. DynDNS-IPs
$seen = array();
foreach(hpr_all($pdo, "SELECT $cols FROM hp_scores s WHERE $when", array('lb1' => $lb, 'lb2' => $lb)) as $s) { $seen[$s['ip_bin']] = $s; }
$owners = array(); // bin -> userid -> Domain
if($seen) {
	hpw_stream($pdo, "SELECT userid, praefix, domainname, content FROM subdomain_records WHERE type IN ('A', 'AAAA') AND deactivated = 0 AND cdn_tmp = 0", array(),
		function($r) use (&$owners, $seen) {
			$ip = trim((string)$r['content']);
			$bin = filter_var($ip, FILTER_VALIDATE_IP) ? inet_pton($ip) : false;
			if($bin === false OR !isset($seen[$bin])) { return; }
			$u = (int)$r['userid'];
			if(!isset($owners[$bin][$u])) { $owners[$bin][$u] = ($r['praefix'] !== '' ? $r['praefix'] . '.' : '') . $r['domainname']; }
		});
}
$nDyn = 0; $nShared = 0;
foreach($owners as $bin => $users) {
	$s = $seen[$bin];
	$shared = count($users) > HPW_SHARED_MAX;
	if($shared) { $nShared++; }
	if((int)$s['listed'] !== 1) { continue; } // DynDNS-Record ist kein Nachweis: nur gelistete IPs (wie ip.php)
	foreach($users as $u => $domain) {
		$nDyn++;
		$add($u, $s, 'dyndns', null, inet_ntop($bin) . (strlen($bin) === 4 ? '/32' : '/128'), $domain, 1000);
	}
}
unset($seen, $owners);

// ---------------------------------------------------------------- 3. Wiederholungen, aktive Accounts, Obergrenze je Lauf
$byUser = array();
foreach($cand as $c) { $byUser[$c['u']][] = $c; }
unset($cand);
$new = array(); $skipped = array('repeat' => 0, 'inactive' => 0, 'per_run' => 0);
foreach(array_chunk(array_keys($byUser), 500) as $chunk) {
	$active = array();
	foreach(hpr_all($pdo, "SELECT id FROM users WHERE account_status = '1' AND id IN (" . implode(',', array_map('intval', $chunk)) . ")") as $x) { $active[(int)$x['id']] = true; }
	foreach($chunk as $u) {
		if(!isset($active[$u])) { $skipped['inactive'] += count($byUser[$u]); continue; }
		// letzter Treffer je IP dieses Accounts
		$prev = array();
		foreach(array_chunk($byUser[$u], 500) as $part) {
			$bins = array_map(fn($c) => bin2hex($c['s']['ip_bin']), $part);
			foreach(hpr_all($pdo, "SELECT ip_bin, listed, last_seen, created_at FROM hp_watch_alerts WHERE userid = ? AND ip_bin IN (" . implode(',', array_fill(0, count($bins), 'UNHEX(?)')) . ") ORDER BY id",
				array_merge(array($u), $bins)) as $a) { $prev[$a['ip_bin']] = $a; }
		}
		$take = array();
		foreach($byUser[$u] as $c) {
			$s = $c['s']; $p = $prev[$s['ip_bin']] ?? null;
			if($p !== null) {
				$newlyListed = ((int)$s['listed'] === 1 && ((int)$p['listed'] !== 1 || ($s['listed_since'] !== null && $s['listed_since'] > $p['created_at'])));
				$recent = hpr_ts($p['created_at']) > $now - HPW_REPEAT;
				if(!$newlyListed AND ($recent OR $s['last_seen'] <= $p['last_seen'])) { $skipped['repeat']++; continue; }
			}
			$take[] = $c;
		}
		usort($take, fn($a, $b) => ((int)$b['s']['listed'] <=> (int)$a['s']['listed']) ?: ((int)$b['s']['score'] <=> (int)$a['s']['score']) ?: strcmp($a['s']['ip_bin'], $b['s']['ip_bin']));
		if(count($take) > HPW_PER_RUN) { $skipped['per_run'] += count($take) - HPW_PER_RUN; $take = array_slice($take, 0, HPW_PER_RUN); }
		foreach($take as $c) { $new[] = $c; }
	}
}
unset($byUser);

$users = array_unique(array_map(fn($c) => $c['u'], $new));
printf("Treffer in Netzen: %d, bei DynDNS-IPs: %d (geteilte IPs ohne Nachweis: %d, Infrastruktur/CDN ausgelassen: %d)\n", $nNet, $nDyn, $nShared, $nInfra);
printf("Neue Treffer: %d fuer %d Accounts; uebersprungen: schon gemeldet %d, Account nicht aktiv %d, Obergrenze je Lauf %d (folgen im naechsten Lauf)\n",
	count($new), count($users), $skipped['repeat'], $skipped['inactive'], $skipped['per_run']);
if($dry) {
	foreach(array_slice($new, 0, 50) as $c) { echo "  Account {$c['u']}: {$c['s']['ip']} ({$c['source']} {$c['cidr']}" . ($c['label'] !== '' ? " \"{$c['label']}\"" : '') . ", " . ((int)$c['s']['listed'] === 1 ? 'gelistet' : 'gesehen') . ", Wert {$c['s']['score']})\n"; }
	echo "*** DRY RUN, nichts geschrieben, keine Mail ***\n";
	exit(0);
}

// ---------------------------------------------------------------- 4. Details je IP (vor der Transaktion)
$det = array(); // bin -> JSON
foreach($new as $c) {
	$s = $c['s'];
	$dk = $s['ip_bin'] . ($c['source'] === 'dyndns' ? '|grob' : '');
	if(!isset($det[$dk])) { $det[$dk] = hpl_watch_details($pdo, $s, $now, $c['source'] === 'dyndns'); }
}

// ---------------------------------------------------------------- 5. Schreiben (ein Zeitstempel je Lauf, eine Transaktion)
// created_at = Zeit des Schreibens (nicht des Laufbeginns), damit die API ohne since kaum einen Stand nach laufenden Treffern meldet
$ins = hpr_dt(time());
$pdo->beginTransaction();
try {
	foreach(array_chunk($new, 250) as $chunk) {
		$vals = array();
		foreach($chunk as $c) {
			$s = $c['s']; // first_seen/last_seen gibt hpl_alert_out() nur auf den Tag aus
			array_push($vals, $c['u'], $s['ip'], bin2hex($s['ip_bin']), $c['net'], $c['source'], $c['cidr'], mb_substr($c['label'], 0, 255), (int)$s['listed'], (int)$s['score'],
				$s['kinds'], $s['first_seen'], $s['last_seen'], $det[$s['ip_bin'] . ($c['source'] === 'dyndns' ? '|grob' : '')], $ins);
		}
		hpr_q($pdo, "INSERT INTO hp_watch_alerts (userid, ip, ip_bin, network_id, source, cidr, label, listed, score, kinds, first_seen, last_seen, details, created_at) VALUES "
			. implode(',', array_fill(0, count($chunk), '(?,?,UNHEX(?),?,?,?,?,?,?,?,?,?,?,?)')), $vals);
	}
	$pdo->commit();
} catch(Throwable $e) {
	if($pdo->inTransaction()) { $pdo->rollBack(); }
	fwrite(STDERR, "Fehler: " . $e->getMessage() . "\n");
	exit(1);
}

// ---------------------------------------------------------------- 6. Mail je Account (alle noch nicht gemeldeten Treffer der letzten 24 h)
$mailed = 0; $mailFail = 0;
foreach(hpr_all($pdo, "SELECT DISTINCT userid FROM hp_watch_alerts WHERE mailed_at IS NULL AND created_at >= :d", array('d' => hpr_dt($now - 86400))) as $x) {
	$u = (int)$x['userid'];
	$to = (string)(hpr_one($pdo, "SELECT email FROM users WHERE id = :u AND account_status = '1'", array('u' => $u))['email'] ?? '');
	$rows = hpr_all($pdo, "SELECT * FROM hp_watch_alerts WHERE userid = :u AND mailed_at IS NULL AND created_at >= :d ORDER BY listed DESC, score DESC, id",
		array('u' => $u, 'd' => hpr_dt($now - 86400)));
	if(!$rows OR $to === '') { continue; }
	$n = count($rows); $lines = array();
	foreach(array_slice($rows, 0, HPW_MAIL_MAX) as $r) {
		$where = $r['source'] === 'dyndns' ? 'DynDNS ' . $r['label'] : $r['cidr'] . ($r['label'] !== '' ? ' (' . $r['label'] . ')' : '');
		$why = hpl_details_text(json_decode((string)($r['details'] ?? ''), true), false);
		$lines[] = '- ' . $r['ip'] . ' – ' . $where . ' – ' . ((int)$r['listed'] === 1 ? 'gelistet / listed' : 'gesehen / seen') . ', ' . $r['kinds']
			. ($why !== '' ? "\n  " . $why : '') . "\n  " . HPR_URL . '?ip=' . rawurlencode($r['ip']);
	}
	if($n > HPW_MAIL_MAX) { $lines[] = '… und ' . ($n - HPW_MAIL_MAX) . ' weitere / and ' . ($n - HPW_MAIL_MAX) . ' more'; }
	$subj = $n === 1 ? "Honeypot64 Frühwarnung: {$rows[0]['ip']} ist als Angreifer aufgefallen" : "Honeypot64 Frühwarnung: $n Adressen sind als Angreifer aufgefallen";
	$text = "Honeypot64-Sensoren haben Angriffe von Adressen aus deinen Netzen bzw. von deinen DynDNS-Adressen gesehen. Meist steckt ein befallenes Gerät dahinter (Kamera, Router, NAS, alter PC). "
		. "„gelistet“ heißt: Die Adresse steht auf der v64 Blocklist.\n\n" . implode("\n", $lines)
		. "\n\nWas tun: Geräte im Netz prüfen, Firmware aktualisieren, Standard-Passwörter ändern. Bei neu zugeteilten Adressen kann es auch der Vorbesitzer gewesen sein. "
		. "Steht eine Adresse auf der Liste und ist das Problem behoben, kannst du über die IP-Auskunft eine Freigabe beantragen.\n"
		. "Netze verwalten und alle Treffer: " . HPW_PAGE_URL . " (oder in Node64 unter Honeypot64).\n\n"
		. "English: Honeypot64 sensors have seen attacks from addresses in your networks or from your DynDNS addresses (list above). Usually an infected device is behind it. "
		. "Check your devices; manage your networks at " . HPW_PAGE_URL . "?lang=en";
	if(hpr_mail($pdo, $to, $subj, $text)) {
		$ids = array_map(fn($r) => (int)$r['id'], $rows);
		hpr_q($pdo, "UPDATE hp_watch_alerts SET mailed_at = ? WHERE id IN (" . implode(',', $ids) . ")", array($run));
		$mailed++;
	} else {
		$mailFail++;
	}
}
echo "Mails: $mailed gesendet" . ($mailFail ? ", $mailFail fehlgeschlagen (naechster Lauf versucht es erneut)" : '') . "\n";

// ---------------------------------------------------------------- 7. Fristen
$del = hpr_q($pdo, "DELETE FROM hp_watch_alerts WHERE created_at < :d", array('d' => hpr_dt($now - HPW_KEEP_DAYS * 86400)))->rowCount();
echo "Treffer aelter als " . HPW_KEEP_DAYS . " Tage geloescht: $del\n";
