<?php
/**
 * IPv64.net – Wochenbericht: einmal pro Woche eine Mail je Account mit dem Stand seiner Dienste (Domains/DynDNS,
 * Healthchecks 2.0, CDN64 samt Schutz-Zahlen, Honeypot64, Cloud Router, Konto). Abschaltbar in den Kontoeinstellungen (users.weekly_report, Standard
 * an) und per Ein-Klick-Abmeldung (List-Unsubscribe). Verteilt ueber die Woche: jeder Account hat einen festen Termin
 * (Wochentag und Stunde zwischen 6 und 21 Uhr), der Cron (weekly_report/cron.php ueber bots/honeypot_cron.php, stuendlich)
 * schickt allen, deren Termin in dieser Woche erreicht ist und die noch nichts bekommen haben.
 *
 * Alles im Ordner weekly_report/: cron.php (Versand), preview.php (Admin: Vorschau und Testmail), unsubscribe.php
 * (Abmeldung ohne Anmeldung), settings.php (Schalter in den Kontoeinstellungen, von account.php eingebunden).
 * Voraussetzung: dbconnect.php ist eingebunden ($pdo, send_mail mit 9. Parameter, hc2_pdo fuer Healthchecks 2.0).
 */

const WR_BASE = 'https://ipv64.net';
const WR_FIRST_HOUR = 6;  // Versand frühestens 6 Uhr ...
const WR_HOURS = 16;      // ... und spätestens 21 Uhr (Europe/Berlin)
const WR_LIST_MAX = 25;   // Zeilen je Abschnitt, danach "und N weitere"

function wr_h($s): string { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

function wr_tz(): DateTimeZone { static $tz = null; return $tz ?? ($tz = new DateTimeZone('Europe/Berlin')); }

/** Kalenderwoche als Schluessel, z. B. 2026-W43. */
function wr_week(int $ts): string { return (new DateTime('@' . $ts))->setTimezone(wr_tz())->format('o-\WW'); }

/** Fester Termin eines Accounts in der Woche: 0 .. 7*WR_HOURS-1 (Montag 6 Uhr = 0). */
function wr_slot(int $userid): int { return (int)(crc32('ipv64-weekly-' . $userid) % (7 * WR_HOURS)); }

/** Aktueller Termin (-1 = vor Montag 6 Uhr); null ausserhalb der Versandzeit (nachts). */
function wr_slot_now(int $ts): ?int {
	$d = (new DateTime('@' . $ts))->setTimezone(wr_tz());
	$h = (int)$d->format('G');
	if ($h < WR_FIRST_HOUR || $h >= WR_FIRST_HOUR + WR_HOURS) { return null; }
	return ((int)$d->format('N') - 1) * WR_HOURS + ($h - WR_FIRST_HOUR);
}

/** Abmelde-Token des Accounts (wird beim ersten Bedarf angelegt; nicht der DynDNS-Update-Key). */
function wr_token(PDO $pdo, int $userid): string {
	$st = $pdo->prepare("SELECT report_token FROM users WHERE id = :u"); $st->execute(array('u' => $userid));
	$t = (string)$st->fetchColumn();
	if (strlen($t) === 32) { return $t; }
	$t = bin2hex(random_bytes(16));
	$pdo->prepare("UPDATE users SET report_token = :t WHERE id = :u AND report_token = ''")->execute(array('t' => $t, 'u' => $userid));
	$st->execute(array('u' => $userid));
	return (string)$st->fetchColumn();
}

function wr_unsubscribe_url(string $token, int $userid, string $kind = 'report'): string {
	return WR_BASE . '/weekly_report/unsubscribe.php?u=' . $userid . '&k=' . $kind . '&t=' . $token;
}

/** Bytes lesbar (MB/GB/TB, Dezimalkomma bei de). */
function wr_bytes(float $b, string $lang): string {
	$u = array('B', 'KB', 'MB', 'GB', 'TB'); $i = 0;
	while ($b >= 1024 && $i < 4) { $b /= 1024; $i++; }
	return wr_num($b, $i >= 2 ? 1 : 0, $lang) . ' ' . $u[$i];
}
function wr_num(float $n, int $dec, string $lang): string { return $lang === 'en' ? number_format($n, $dec, '.', ',') : number_format($n, $dec, ',', '.'); }
function wr_dur(int $sec, string $lang): string {
	if ($sec < 3600) { return max(1, (int)round($sec / 60)) . ' min'; }
	if ($sec < 86400) { return wr_num($sec / 3600, 1, $lang) . ' h'; }
	return wr_num($sec / 86400, 1, $lang) . ($lang === 'en' ? ' days' : ' Tage');
}
function wr_date(string $dt, string $lang, bool $time = true): string {
	if ($dt === '' || strncmp($dt, '0000', 4) === 0) { return '–'; }
	$t = strtotime($dt);
	if ($t === false) { return '–'; }
	return date($lang === 'en' ? ($time ? 'Y-m-d H:i' : 'Y-m-d') : ($time ? 'd.m.Y H:i' : 'd.m.Y'), $t);
}

// ---------------------------------------------------------------- Daten

/**
 * Stand eines Accounts fuer die letzten 7 Tage. Jeder Bereich ist fuer sich abgesichert (fehlt eine Tabelle oder
 * die hc2-Datenbank, fehlt nur dieser Abschnitt). null = Account unbekannt oder gesperrt.
 */
function wr_collect(PDO $pdo, int $userid, int $now): ?array {
	$st = $pdo->prepare("SELECT * FROM users WHERE id = :u"); $st->execute(array('u' => $userid));
	$u = $st->fetch(PDO::FETCH_ASSOC);
	if (!$u || (string)($u['account_status'] ?? '1') !== '1') { return null; }
	$st = $pdo->prepare("SELECT * FROM user_class WHERE id = :c"); $st->execute(array('c' => (int)$u['user_class']));
	$cls = $st->fetch(PDO::FETCH_ASSOC) ?: array();
	$since = $now - 7 * 86400;
	$d = array('userid' => $userid, 'email' => (string)$u['email'], 'name' => trim((string)($u['username'] ?? '')),
		'lang' => (($u['weekly_report_lang'] ?? 'de') === 'en') ? 'en' : 'de', 'from' => $since, 'to' => $now, 'week' => wr_week($now),
		'class' => (string)($cls['name'] ?? ''), 'valid_until' => (string)($u['class_valid_until'] ?? ''), 'class_id' => (int)$u['user_class'],
		'domains' => null, 'hc' => null, 'cdn' => null, 'hp' => null, 'vpn' => null, 'issues' => array(), 'errors' => array());
	$lim = function(string $k) use ($cls) { return (int)($cls[$k] ?? 0); };

	// Konto: Klasse laeuft bald ab (bezahlte Klassen)
	if ($d['class_id'] > 1 && $d['valid_until'] !== '' && strncmp($d['valid_until'], '0000', 4) !== 0) {
		$left = (int)floor((strtotime($d['valid_until']) - $now) / 86400);
		if ($left >= 0 && $left <= 30) { $d['issues'][] = array('class_expiry', $left); }
	}

	// Domains und DynDNS
	try {
		$st = $pdo->prepare("SELECT id, subdomainname, maindomain, owndomain, deactivated FROM subdomains WHERE userid = :u ORDER BY owndomain, maindomain, subdomainname");
		$st->execute(array('u' => $userid));
		$list = $st->fetchAll(PDO::FETCH_ASSOC);
		if ($list) {
			$rec = array();
			$st = $pdo->prepare("SELECT subdomain_id, type, content FROM subdomain_records WHERE userid = :u AND praefix IN ('', '@') AND type IN ('A', 'AAAA') ORDER BY id");
			$st->execute(array('u' => $userid));
			foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $r) { $rec[(int)$r['subdomain_id']][$r['type']] = $rec[(int)$r['subdomain_id']][$r['type']] ?? (string)$r['content']; }
			$chg = array();
			$st = $pdo->prepare("SELECT subdomainid, COUNT(*) n, MAX(zeit) last FROM logging WHERE userid = :u AND zeit >= :s AND header LIKE 'Update A/AAAA Record%' GROUP BY subdomainid");
			$st->execute(array('u' => $userid, 's' => date('Y-m-d H:i:s', $since)));
			foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $r) { $chg[(int)$r['subdomainid']] = array((int)$r['n'], (string)$r['last']); }
			$rows = array(); $dyn = 0; $own = 0; $changes = 0;
			foreach ($list as $s) {
				$id = (int)$s['id']; $isOwn = (int)$s['owndomain'] === 1;
				$isOwn ? $own++ : $dyn++;
				$c = $chg[$id] ?? array(0, '');
				$changes += $c[0];
				$rows[] = array('name' => $isOwn ? (string)$s['maindomain'] : $s['subdomainname'] . '.' . $s['maindomain'], 'own' => $isOwn,
					'off' => (int)($s['deactivated'] ?? 0) === 1, 'v4' => $rec[$id]['A'] ?? '', 'v6' => $rec[$id]['AAAA'] ?? '', 'changes' => $c[0], 'last' => $c[1]);
			}
			usort($rows, function($a, $b) { return $b['changes'] <=> $a['changes'] ?: strcmp($a['name'], $b['name']); });
			$d['domains'] = array('rows' => $rows, 'dyn' => $dyn, 'own' => $own, 'changes' => $changes,
				'dyn_limit' => $lim('dyndns_limit'), 'own_limit' => $lim('owndomain_limit'));
			if ($lim('dyndns_limit') > 0 && $dyn >= $lim('dyndns_limit')) { $d['issues'][] = array('domains_full', $dyn); }
		}
	} catch (Throwable $e) { $d['errors'][] = 'domains: ' . $e->getMessage(); }

	// Healthchecks 2.0
	try {
		if (function_exists('hc2_pdo')) {
			$hc = hc2_pdo();
			$st = $hc->prepare("SELECT token, name, type, execution, paused, state, state_since FROM hc2_checks WHERE userid = :u AND deleted_at IS NULL ORDER BY name");
			$st->execute(array('u' => $userid));
			$checks = $st->fetchAll(PDO::FETCH_ASSOC);
			if ($checks) {
				$up = array();
				$st = $hc->prepare("SELECT h.token, SUM(h.count) c, SUM(h.up_count) u FROM hc2_hourly h JOIN hc2_checks k ON k.token = h.token
					WHERE k.userid = :u AND k.deleted_at IS NULL AND h.hour >= UTC_TIMESTAMP() - INTERVAL 7 DAY GROUP BY h.token");
				$st->execute(array('u' => $userid));
				foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $r) { $up[$r['token']] = array((int)$r['c'], (int)$r['u']); }
				$inc = array();
				$st = $hc->prepare("SELECT token, UNIX_TIMESTAMP(started_at) s, UNIX_TIMESTAMP(ended_at) e FROM hc2_incidents WHERE userid = :u
					AND (ended_at IS NULL OR ended_at >= UTC_TIMESTAMP() - INTERVAL 7 DAY)");
				$st->execute(array('u' => $userid));
				foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $r) {
					$s = max((int)$r['s'], $since); $e = $r['e'] === null ? $now : min((int)$r['e'], $now);
					if ($e <= $s && $r['e'] !== null) { continue; }
					$inc[$r['token']][0] = ($inc[$r['token']][0] ?? 0) + 1;
					$inc[$r['token']][1] = ($inc[$r['token']][1] ?? 0) + max(0, $e - $s);
				}
				$rows = array(); $sumC = 0; $sumU = 0; $down = 0; $paused = 0; $incN = 0; $incSec = 0;
				foreach ($checks as $c) {
					$state = (int)$c['paused'] === 1 ? 'paused' : (string)$c['state'];
					if ($state === 'paused') { $paused++; } elseif (in_array($state, array('down', 'dependent'), true)) { $down++; }
					$x = $up[$c['token']] ?? array(0, 0);
					$sumC += $x[0]; $sumU += $x[1];
					$i = $inc[$c['token']] ?? array(0, 0);
					$incN += $i[0]; $incSec += $i[1];
					$rows[] = array('name' => (string)$c['name'], 'type' => (string)$c['type'], 'exec' => (string)$c['execution'], 'state' => $state,
						'uptime' => $x[0] > 0 ? 100 * $x[1] / $x[0] : null, 'incidents' => $i[0], 'down_sec' => $i[1]);
				}
				$rank = function($r) { return in_array($r['state'], array('down', 'dependent'), true) ? 0 : ($r['state'] === 'degraded' || $r['state'] === 'flapping' ? 1 : ($r['incidents'] > 0 ? 2 : ($r['state'] === 'paused' ? 4 : 3))); };
				usort($rows, function($a, $b) use ($rank) { return $rank($a) <=> $rank($b) ?: strcasecmp($a['name'], $b['name']); });
				$d['hc'] = array('rows' => $rows, 'total' => count($checks), 'down' => $down, 'paused' => $paused, 'incidents' => $incN, 'down_sec' => $incSec,
					'uptime' => $sumC > 0 ? 100 * $sumU / $sumC : null);
				if ($down > 0) { $d['issues'][] = array('hc_down', $down); }
			}
		}
	} catch (Throwable $e) { $d['errors'][] = 'hc2: ' . $e->getMessage(); }

	// CDN64 2.0
	try {
		$st = $pdo->prepare("SELECT id, fqdn, mode, status, blocked_reason, paused FROM cdn64o_hosts WHERE userid = :u AND status IN ('pending', 'active', 'blocked') ORDER BY fqdn");
		$st->execute(array('u' => $userid));
		$hosts = $st->fetchAll(PDO::FETCH_ASSOC);
		if ($hosts) {
			$tw = array();
			$st = $pdo->prepare("SELECT host_id, SUM(bytes_in + bytes_out) b, SUM(requests) r FROM cdn64o_traffic WHERE userid = :u AND day >= :d GROUP BY host_id");
			$st->execute(array('u' => $userid, 'd' => date('Y-m-d', $since)));
			foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $r) { $tw[(int)$r['host_id']] = array((float)$r['b'], (int)$r['r']); }
			$st = $pdo->prepare("SELECT COALESCE(SUM(bytes_in + bytes_out), 0) FROM cdn64o_traffic WHERE userid = :u AND day >= :d");
			$st->execute(array('u' => $userid, 'd' => date('Y-m-01', $now)));
			$monthB = (float)$st->fetchColumn() + ((float)($u['cdn_traffic_input'] ?? 0) + (float)($u['cdn_traffic_output'] ?? 0)) * 1048576; // altes CDN in MB
			$limitB = (float)$lim('cdn_traffic') * 1073741824;
			$tun = array(0, 0);
			$st = $pdo->prepare("SELECT last_seen FROM cdn64o_tunnels WHERE userid = :u AND status = 'active'");
			$st->execute(array('u' => $userid));
			foreach ($st->fetchAll(PDO::FETCH_COLUMN) as $ls) { $tun[1]++; if ($ls !== null && strtotime((string)$ls) >= $now - 300) { $tun[0]++; } }
			$ev = array();
			$st = $pdo->prepare("SELECT kind, COUNT(*) n FROM cdn64o_events WHERE userid = :u AND time >= :s GROUP BY kind");
			$st->execute(array('u' => $userid, 's' => date('Y-m-d H:i:s', $since)));
			foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $r) { $ev[$r['kind']] = (int)$r['n']; }
			// Schutz-Zaehler der CDN64-Server (wie GET /cdn64o/protection und Node64 "CDN64 Statistik")
			$st = $pdo->prepare("SELECT COALESCE(SUM(blocked_list), 0) `list`, COALESCE(SUM(blocked_acl), 0) acl, COALESCE(SUM(blocked_flood + rejected), 0) overload,
				COALESCE(SUM(blocked_waf), 0) waf, COALESCE(SUM(blocked_ja4), 0) ja4, COALESCE(SUM(conns), 0) conns FROM cdn64o_traffic WHERE userid = :u AND day >= :d");
			$st->execute(array('u' => $userid, 'd' => date('Y-m-d', $since)));
			$prot = array_map('intval', $st->fetch(PDO::FETCH_ASSOC) ?: array());
			$rows = array(); $weekB = 0.0; $weekR = 0; $blocked = 0;
			foreach ($hosts as $h) {
				$t = $tw[(int)$h['id']] ?? array(0.0, 0);
				$weekB += $t[0]; $weekR += $t[1];
				$state = (int)($h['paused'] ?? 0) === 1 ? 'paused' : (string)$h['status'];
				if ($state === 'blocked') { $blocked++; }
				$rows[] = array('name' => (string)$h['fqdn'], 'mode' => (int)$h['mode'], 'state' => $state, 'reason' => (string)$h['blocked_reason'], 'bytes' => $t[0], 'requests' => $t[1]);
			}
			usort($rows, function($a, $b) { return ($a['state'] === 'blocked' ? 0 : 1) <=> ($b['state'] === 'blocked' ? 0 : 1) ?: $b['bytes'] <=> $a['bytes']; });
			$d['cdn'] = array('rows' => $rows, 'week_bytes' => $weekB, 'week_requests' => $weekR, 'month_bytes' => $monthB, 'limit_bytes' => $limitB,
				'tunnels_on' => $tun[0], 'tunnels' => $tun[1], 'events' => $ev, 'blocked' => $blocked, 'prot' => $prot);
			if ($blocked > 0) { $d['issues'][] = array('cdn_blocked', $blocked); }
			elseif ($limitB > 0 && $monthB >= 0.8 * $limitB) { $d['issues'][] = array('cdn_traffic', (int)round(100 * $monthB / $limitB)); }
		}
	} catch (Throwable $e) { $d['errors'][] = 'cdn64: ' . $e->getMessage(); }

	// Honeypot64: nur mit einem Sensor, der in den 7 Tagen gemeldet hat (Zeiten in hp_* sind UTC)
	try {
		$st = $pdo->prepare("SELECT COUNT(*) FROM hp_sensors WHERE userid = :u AND disabled = 0 AND last_seen >= :s");
		$st->execute(array('u' => $userid, 's' => gmdate('Y-m-d H:i:s', $since)));
		$sensors = (int)$st->fetchColumn();
		if ($sensors > 0) {
			$st = $pdo->prepare("SELECT COALESCE(SUM(events), 0) FROM hp_daily WHERE userid = :u AND day >= :d");
			$st->execute(array('u' => $userid, 'd' => gmdate('Y-m-d', $since)));
			$events = (int)$st->fetchColumn();
			$st = $pdo->prepare("SELECT COUNT(DISTINCT r.ip_bin) n, COUNT(DISTINCT CASE WHEN s.listed = 1 THEN r.ip_bin END) listed FROM hp_report_sources r
				LEFT JOIN hp_scores s ON s.ip_bin = r.ip_bin WHERE r.userid = :u AND r.last_seen >= :s");
			$st->execute(array('u' => $userid, 's' => gmdate('Y-m-d H:i:s', $since)));
			$src = $st->fetch(PDO::FETCH_ASSOC) ?: array();
			$st = $pdo->prepare("SELECT COUNT(DISTINCT key_hash) FROM hp_sample_contrib WHERE kind = 'fp' AND day >= :d AND userid = :u");
			$st->execute(array('u' => $userid, 'd' => gmdate('Y-m-d', $since)));
			$d['hp'] = array('sensors' => $sensors, 'events' => $events, 'sources' => (int)($src['n'] ?? 0), 'listed' => (int)($src['listed'] ?? 0),
				'fps' => (int)$st->fetchColumn());
		}
	} catch (Throwable $e) { $d['errors'][] = 'honeypot: ' . $e->getMessage(); }

	// Cloud Router
	try {
		$st = $pdo->prepare("SELECT name, status, disabled, traffic_limit FROM vpn_gateways WHERE userid = :u AND (del_gw IS NULL OR del_gw = 0) ORDER BY name");
		$st->execute(array('u' => $userid));
		$gws = $st->fetchAll(PDO::FETCH_ASSOC);
		if ($gws) {
			$rows = array();
			foreach ($gws as $g) {
				$state = (int)$g['traffic_limit'] === 1 ? 'limited' : ((int)$g['disabled'] === 1 ? 'paused' : ((int)$g['status'] === 1 ? 'active' : 'setup'));
				$rows[] = array('name' => (string)$g['name'], 'state' => $state);
			}
			$used = (float)($u['vpn_traffic_input'] ?? 0) + (float)($u['vpn_traffic_output'] ?? 0); // Bytes im Monat
			$limitB = (float)$lim('vpn_traffic') * 1073741824;
			$d['vpn'] = array('rows' => $rows, 'month_bytes' => $used, 'limit_bytes' => $limitB, 'limited' => (int)($u['vpn_limit_reached'] ?? 0) === 1);
			if ($d['vpn']['limited']) { $d['issues'][] = array('vpn_limit', 0); }
			elseif ($limitB > 0 && $used >= 0.8 * $limitB) { $d['issues'][] = array('vpn_traffic', (int)round(100 * $used / $limitB)); }
		}
	} catch (Throwable $e) { $d['errors'][] = 'vpn: ' . $e->getMessage(); }

	return $d;
}

/** Hat der Account etwas, worueber es sich zu berichten lohnt? (Sonst keine Mail.) */
function wr_has_content(array $d): bool { return $d['domains'] !== null || $d['hc'] !== null || $d['cdn'] !== null || $d['hp'] !== null || $d['vpn'] !== null; }

// ---------------------------------------------------------------- Texte

function wr_t(string $lang, string $key, ...$a): string {
	static $T = array(
		'de' => array(
			'subject' => 'Dein Wochenbericht von IPv64.net (KW %s)',
			'title' => 'Dein Wochenbericht', 'range' => '%s bis %s', 'hello' => 'Hallo %s,', 'hello0' => 'Hallo,',
			'intro' => 'hier ist der Überblick über deine Dienste bei IPv64.net in den letzten 7 Tagen.',
			'all_ok' => 'Alles in Ordnung', 'attention' => 'Bitte einmal ansehen',
			'class_expiry' => 'Deine Account-Klasse läuft in %d Tagen ab.', 'domains_full' => 'Alle DynDNS-Domains deiner Klasse sind belegt (%d).',
			'hc_down' => '%d Healthcheck(s) sind gerade gestört.', 'cdn_blocked' => '%d CDN64-Name(n) sind wegen des Traffic-Limits gesperrt.',
			'cdn_traffic' => 'Dein CDN64-Traffic in diesem Monat liegt bei %d %% des Limits.', 'vpn_limit' => 'Das Traffic-Limit deines Cloud Routers ist erreicht, die Gateways sind gedrosselt.',
			'vpn_traffic' => 'Dein Cloud-Router-Traffic in diesem Monat liegt bei %d %% des Limits.',
			'account' => 'Konto', 'class' => 'Account-Klasse', 'valid' => 'gültig bis',
			'domains' => 'Domains und DynDNS', 'dyn' => 'DynDNS-Domains', 'own' => 'Eigene Domains', 'changes' => 'IP-Wechsel in 7 Tagen',
			'col_domain' => 'Domain', 'col_v4' => 'IPv4', 'col_v6' => 'IPv6', 'col_chg' => 'Wechsel', 'col_last' => 'zuletzt', 'off' => 'deaktiviert',
			'hc' => 'Healthchecks', 'hc_total' => 'Checks', 'hc_uptime' => 'Verfügbarkeit (7 Tage)', 'hc_inc' => 'Störungen', 'hc_downtime' => 'gesamt gestört',
			'col_check' => 'Check', 'col_state' => 'Zustand', 'col_up' => 'Verfügbarkeit', 'col_inc' => 'Störungen',
			'st_up' => 'in Ordnung', 'st_down' => 'gestört', 'st_degraded' => 'teilweise gestört', 'st_paused' => 'pausiert', 'st_pending' => 'wartet',
			'st_stabilizing' => 'stabilisiert', 'st_flapping' => 'unruhig', 'st_dependent' => 'abhängig gestört',
			'cdn' => 'CDN64', 'cdn_week' => 'Traffic in 7 Tagen', 'cdn_req' => 'Anfragen in 7 Tagen', 'cdn_month' => 'Traffic im Monat', 'cdn_tun' => 'Nodes verbunden',
			'col_name' => 'Name', 'col_mode' => 'Modus', 'col_traffic' => 'Traffic', 'col_req' => 'Anfragen',
			'cs_active' => 'aktiv', 'cs_pending' => 'wird eingerichtet', 'cs_blocked' => 'gesperrt', 'cs_paused' => 'pausiert',
			'prot_blocked' => 'Von CDN64 abgewehrt (7 Tage)', 'prot_hidden' => 'Eigene IP-Adresse verborgen', 'prot_conns' => '%s Verbindungen',
			'r_list' => 'Blocklisten', 'r_acl' => 'Zugriffsliste', 'r_overload' => 'Überlast', 'r_waf' => 'WAF-Muster', 'r_ja4' => 'Angriffs-Werkzeuge',
			'hp' => 'Honeypot64', 'hp_sensors' => 'Sensoren aktiv', 'hp_events' => 'Gemeldete Zugriffe (7 Tage)', 'hp_sources' => 'Angreifer-Adressen',
			'hp_listed' => 'davon auf der v64 Blocklist', 'hp_fps' => 'Fingerabdrücke beigetragen (JA4/HASSH)',
			'thanks_head' => 'Danke, dass du IPv64.net nutzt', 'thanks' => 'Wenn dir IPv64.net gefällt, empfiehl uns gerne weiter.',
			'thanks_hp' => 'Und danke für deine Honeypot64-Meldungen – sie helfen, die Blocklisten zu führen und Angriffs-Werkzeuge zu erkennen.',
			'vpn' => 'Cloud Router', 'vpn_month' => 'Traffic im Monat', 'col_gw' => 'Gateway',
			'vs_active' => 'aktiv', 'vs_paused' => 'pausiert', 'vs_setup' => 'wird eingerichtet', 'vs_limited' => 'gedrosselt (Limit)',
			'more' => 'und %d weitere', 'open' => 'Öffnen', 'of' => 'von', 'unlimited' => 'unbegrenzt',
			'why' => 'Du bekommst diese Mail einmal pro Woche, weil der Wochenbericht in deinen Kontoeinstellungen eingeschaltet ist.',
			'settings' => 'Einstellungen', 'unsubscribe' => 'Wochenbericht abbestellen', 'privacy' => 'Datenschutz',
		),
		'en' => array(
			'subject' => 'Your weekly report from IPv64.net (week %s)',
			'title' => 'Your weekly report', 'range' => '%s to %s', 'hello' => 'Hello %s,', 'hello0' => 'Hello,',
			'intro' => 'here is the overview of your services at IPv64.net for the last 7 days.',
			'all_ok' => 'All good', 'attention' => 'Please take a look',
			'class_expiry' => 'Your account class expires in %d days.', 'domains_full' => 'All DynDNS domains of your class are in use (%d).',
			'hc_down' => '%d health check(s) are down right now.', 'cdn_blocked' => '%d CDN64 name(s) are blocked because of the traffic limit.',
			'cdn_traffic' => 'Your CDN64 traffic this month is at %d %% of the limit.', 'vpn_limit' => 'The traffic limit of your Cloud Router is reached, the gateways are throttled.',
			'vpn_traffic' => 'Your Cloud Router traffic this month is at %d %% of the limit.',
			'account' => 'Account', 'class' => 'Account class', 'valid' => 'valid until',
			'domains' => 'Domains and DynDNS', 'dyn' => 'DynDNS domains', 'own' => 'Own domains', 'changes' => 'IP changes in 7 days',
			'col_domain' => 'Domain', 'col_v4' => 'IPv4', 'col_v6' => 'IPv6', 'col_chg' => 'Changes', 'col_last' => 'last', 'off' => 'disabled',
			'hc' => 'Health checks', 'hc_total' => 'Checks', 'hc_uptime' => 'Availability (7 days)', 'hc_inc' => 'Incidents', 'hc_downtime' => 'total downtime',
			'col_check' => 'Check', 'col_state' => 'State', 'col_up' => 'Availability', 'col_inc' => 'Incidents',
			'st_up' => 'up', 'st_down' => 'down', 'st_degraded' => 'partially down', 'st_paused' => 'paused', 'st_pending' => 'pending',
			'st_stabilizing' => 'stabilizing', 'st_flapping' => 'flapping', 'st_dependent' => 'down (dependency)',
			'cdn' => 'CDN64', 'cdn_week' => 'Traffic in 7 days', 'cdn_req' => 'Requests in 7 days', 'cdn_month' => 'Traffic this month', 'cdn_tun' => 'Nodes connected',
			'col_name' => 'Name', 'col_mode' => 'Mode', 'col_traffic' => 'Traffic', 'col_req' => 'Requests',
			'cs_active' => 'active', 'cs_pending' => 'being set up', 'cs_blocked' => 'blocked', 'cs_paused' => 'paused',
			'prot_blocked' => 'Blocked by CDN64 (7 days)', 'prot_hidden' => 'Own IP address hidden', 'prot_conns' => '%s connections',
			'r_list' => 'Blocklists', 'r_acl' => 'Access list', 'r_overload' => 'Overload', 'r_waf' => 'WAF patterns', 'r_ja4' => 'Attack tools',
			'hp' => 'Honeypot64', 'hp_sensors' => 'Active sensors', 'hp_events' => 'Reported hits (7 days)', 'hp_sources' => 'Attacker addresses',
			'hp_listed' => 'of these on the v64 blocklist', 'hp_fps' => 'Fingerprints contributed (JA4/HASSH)',
			'thanks_head' => 'Thank you for using IPv64.net', 'thanks' => 'If you like IPv64.net, feel free to recommend us.',
			'thanks_hp' => 'And thank you for your Honeypot64 reports – they help keep the blocklists up to date and detect attack tools.',
			'vpn' => 'Cloud Router', 'vpn_month' => 'Traffic this month', 'col_gw' => 'Gateway',
			'vs_active' => 'active', 'vs_paused' => 'paused', 'vs_setup' => 'being set up', 'vs_limited' => 'throttled (limit)',
			'more' => 'and %d more', 'open' => 'Open', 'of' => 'of', 'unlimited' => 'unlimited',
			'why' => 'You receive this email once a week because the weekly report is switched on in your account settings.',
			'settings' => 'Settings', 'unsubscribe' => 'Unsubscribe from the weekly report', 'privacy' => 'Privacy',
		),
	);
	$s = $T[$lang][$key] ?? $T['de'][$key] ?? $key;
	return $a ? vsprintf($s, $a) : $s;
}

// ---------------------------------------------------------------- Mail

/**
 * Betreff, HTML- und Textteil. Das HTML ist schlicht (Tabellen, alle Stile inline, keine Bilder, keine externen
 * Inhalte, nur Links auf ipv64.net) und enthaelt dasselbe wie der Textteil – beides hilft gegen Spamfilter.
 */
function wr_render(array $d, string $token): array {
	$L = $d['lang'];
	$t = function(string $k, ...$a) use ($L) { return wr_t($L, $k, ...$a); };
	$week = substr($d['week'], 6);
	$subject = $t('subject', ltrim($week, '0'));
	$range = $t('range', wr_date(date('Y-m-d', $d['from']), $L, false), wr_date(date('Y-m-d', $d['to']), $L, false));
	$unsub = wr_unsubscribe_url($token, $d['userid']);
	$settingsUrl = WR_BASE . '/account.php?accountsettings#mail-prefs';

	$html = ''; $text = '';
	$teal = '#17bebb'; $ink = '#1d273b'; $muted = '#667382'; $line = '#e6e7e9';
	$p = function(string $s, string $style = '') use (&$html, $ink) { $html .= '<p style="margin:0 0 10px 0;color:' . $ink . ';' . $style . '">' . $s . '</p>'; };
	$h2 = function(string $s, string $url) use (&$html, &$text, $ink, $teal, $t) {
		$html .= '<tr><td style="padding:18px 24px 6px 24px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td style="font-size:17px;font-weight:bold;color:' . $ink . '">' . wr_h($s) . '</td>'
			. '<td align="right" style="font-size:13px"><a href="' . wr_h($url) . '" style="color:' . $teal . ';text-decoration:none">' . wr_h($t('open')) . ' &rsaquo;</a></td></tr></table></td></tr>';
		$text .= "\n" . $s . "\n" . str_repeat('-', mb_strlen($s)) . "\n";
	};
	$facts = function(array $kv) use (&$html, &$text, $muted, $ink, $line) {
		$html .= '<tr><td style="padding:0 24px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;font-size:14px">';
		foreach ($kv as $k => $v) {
			$html .= '<tr><td style="padding:5px 12px 5px 0;color:' . $muted . ';border-bottom:1px solid ' . $line . '">' . wr_h($k) . '</td><td align="right" style="padding:5px 0;color:' . $ink . ';border-bottom:1px solid ' . $line . ';font-weight:bold">' . wr_h($v) . '</td></tr>';
			$text .= $k . ': ' . $v . "\n";
		}
		$html .= '</table></td></tr>';
	};
	$table = function(array $head, array $rows, int $total) use (&$html, &$text, $muted, $ink, $line, $t) {
		$html .= '<tr><td style="padding:10px 24px 0 24px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;font-size:13px"><tr>';
		foreach ($head as $i => $h) { $html .= '<td' . ($i > 0 ? ' align="right"' : '') . ' style="padding:4px 6px 4px ' . ($i ? '6' : '0') . 'px;color:' . $muted . ';border-bottom:2px solid ' . $line . '">' . wr_h($h) . '</td>'; }
		$html .= '</tr>';
		foreach ($rows as $r) {
			$html .= '<tr>';
			foreach ($r as $i => $c) {
				[$val, $color] = is_array($c) ? $c : array($c, $ink);
				$html .= '<td' . ($i > 0 ? ' align="right"' : '') . ' style="padding:5px 6px 5px ' . ($i ? '6' : '0') . 'px;color:' . $color . ';border-bottom:1px solid ' . $line . ';word-break:break-word">' . wr_h($val) . '</td>';
			}
			$html .= '</tr>';
			$text .= '- ' . implode(' | ', array_map(function($c) { return is_array($c) ? $c[0] : $c; }, $r)) . "\n";
		}
		if ($total > count($rows)) {
			$more = $t('more', $total - count($rows));
			$html .= '<tr><td colspan="' . count($head) . '" style="padding:6px 0;color:' . $muted . '">' . wr_h($more) . '</td></tr>';
			$text .= '  ' . $more . "\n";
		}
		$html .= '</table></td></tr>';
	};
	$red = '#d63939'; $green = '#2fb344'; $orange = '#f59f00';
	// gruener Kasten mit Symbol (Emoji statt Bild: keine externen Inhalte), fuer den Dank am Ende
	$badge = function(string $icon, string $head, array $lines) use (&$html, &$text, $ink, $green) {
		$html .= '<tr><td style="padding:18px 24px 0 24px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#ebf7ee;border-left:4px solid ' . $green . '"><tr>'
			. '<td width="34" valign="top" style="padding:10px 0 10px 12px;font-size:22px;line-height:1">' . $icon . '</td>'
			. '<td style="padding:10px 12px;font-size:14px;color:' . $ink . '"><b style="color:' . $green . '">' . wr_h($head) . '</b>';
		foreach ($lines as $l) { $html .= '<br>' . wr_h($l); }
		$html .= '</td></tr></table></td></tr>';
		$text .= "\n" . $head . "\n";
		foreach ($lines as $l) { $text .= '  ' . $l . "\n"; }
	};

	// Kopf, Anrede und Hinweise
	$greeting = $d['name'] !== '' ? $t('hello', $d['name']) : $t('hello0');
	$text .= $t('title') . ' – ' . $range . "\n\n" . $greeting . "\n" . $t('intro') . "\n";
	$issues = array();
	foreach ($d['issues'] as $i) { $issues[] = $t($i[0], $i[1]); }
	$band = $issues ? array($orange, $t('attention')) : array($green, $t('all_ok'));
	$text .= "\n" . $band[1] . "\n";
	foreach ($issues as $i) { $text .= '* ' . $i . "\n"; }
	$top = '<tr><td style="padding:22px 24px 6px 24px"><div style="font-size:20px;font-weight:bold;color:' . $ink . '">' . wr_h($t('title')) . '</div><div style="font-size:13px;color:' . $muted . ';margin-top:2px">' . wr_h($range) . '</div></td></tr>'
		. '<tr><td style="padding:10px 24px 0 24px;font-size:15px;color:' . $ink . '">' . wr_h($greeting) . '<br>' . wr_h($t('intro')) . '</td></tr>'
		. '<tr><td style="padding:14px 24px 0 24px"><div style="border-left:4px solid ' . $band[0] . ';background:#f6f8fb;padding:10px 12px;font-size:14px;color:' . $ink . '"><b>' . wr_h($band[1]) . '</b>';
	foreach ($issues as $i) { $top .= '<br>&bull; ' . wr_h($i); }
	$top .= '</div></td></tr>';
	$html .= $top;

	// Konto
	$h2($t('account'), WR_BASE . '/account.php?account_class');
	$acc = array($t('class') => $d['class'] !== '' ? $d['class'] : '–');
	if ($d['class_id'] > 1 && $d['valid_until'] !== '') { $acc[$t('valid')] = wr_date($d['valid_until'], $L, false); }
	$facts($acc);

	// Domains
	if ($dm = $d['domains']) {
		$h2($t('domains'), WR_BASE . '/dyndns');
		$kv = array($t('dyn') => $dm['dyn'] . ($dm['dyn_limit'] > 0 ? ' ' . $t('of') . ' ' . $dm['dyn_limit'] : ''));
		if ($dm['own'] > 0 || $dm['own_limit'] > 0) { $kv[$t('own')] = $dm['own'] . ($dm['own_limit'] > 0 ? ' ' . $t('of') . ' ' . $dm['own_limit'] : ''); }
		$kv[$t('changes')] = (string)$dm['changes'];
		$facts($kv);
		$rows = array();
		foreach (array_slice($dm['rows'], 0, WR_LIST_MAX) as $r) {
			$rows[] = array($r['off'] ? array($r['name'] . ' (' . $t('off') . ')', $muted) : $r['name'], $r['v4'] !== '' ? $r['v4'] : '–', $r['v6'] !== '' ? $r['v6'] : '–',
				$r['changes'] > 0 ? array($r['changes'] . ' · ' . wr_date($r['last'], $L), $ink) : array('0', $muted));
		}
		$table(array($t('col_domain'), $t('col_v4'), $t('col_v6'), $t('col_chg')), $rows, count($dm['rows']));
	}

	// Healthchecks
	if ($hc = $d['hc']) {
		$h2($t('hc'), WR_BASE . '/healthchecks2/');
		$kv = array($t('hc_total') => (string)$hc['total']);
		if ($hc['uptime'] !== null) { $kv[$t('hc_uptime')] = wr_num($hc['uptime'], 2, $L) . ' %'; }
		$kv[$t('hc_inc')] = $hc['incidents'] . ($hc['incidents'] > 0 ? ' · ' . $t('hc_downtime') . ' ' . wr_dur($hc['down_sec'], $L) : '');
		$facts($kv);
		$rows = array();
		foreach (array_slice($hc['rows'], 0, WR_LIST_MAX) as $r) {
			$c = in_array($r['state'], array('down', 'dependent'), true) ? $red : (in_array($r['state'], array('degraded', 'flapping', 'stabilizing'), true) ? $orange : ($r['state'] === 'up' ? $green : $muted));
			$rows[] = array($r['name'], array($t('st_' . $r['state']), $c), $r['uptime'] === null ? '–' : wr_num($r['uptime'], 2, $L) . ' %',
				$r['incidents'] > 0 ? array($r['incidents'] . ' · ' . wr_dur($r['down_sec'], $L), $red) : array('0', $muted));
		}
		$table(array($t('col_check'), $t('col_state'), $t('col_up'), $t('col_inc')), $rows, count($hc['rows']));
	}

	// CDN64
	if ($cd = $d['cdn']) {
		$h2($t('cdn'), WR_BASE . '/cdn64');
		$kv = array($t('cdn_week') => wr_bytes($cd['week_bytes'], $L), $t('cdn_req') => wr_num($cd['week_requests'], 0, $L),
			$t('cdn_month') => wr_bytes($cd['month_bytes'], $L) . ' ' . $t('of') . ' ' . ($cd['limit_bytes'] > 0 ? wr_bytes($cd['limit_bytes'], $L) : $t('unlimited')));
		if ($cd['tunnels'] > 0) { $kv[$t('cdn_tun')] = $cd['tunnels_on'] . ' ' . $t('of') . ' ' . $cd['tunnels']; }
		// Schutz der CDN64-Server: Summe mit Schild, darunter je Grund (nur Gruende mit Treffern)
		$pr = $cd['prot']; $why = array(); $sum = 0;
		foreach (array('list', 'waf', 'ja4', 'overload', 'acl') as $k) {
			$n = (int)($pr[$k] ?? 0); $sum += $n;
			if ($n > 0) { $why['– ' . $t('r_' . $k)] = wr_num($n, 0, $L); }
		}
		if ($sum > 0) { $kv["\u{1F6E1}\u{FE0F} " . $t('prot_blocked')] = wr_num($sum, 0, $L); $kv += $why; }
		if ((int)($pr['conns'] ?? 0) > 0) { $kv[$t('prot_hidden')] = $t('prot_conns', wr_num((int)$pr['conns'], 0, $L)); }
		$facts($kv);
		$rows = array();
		foreach (array_slice($cd['rows'], 0, WR_LIST_MAX) as $r) {
			$c = $r['state'] === 'blocked' ? $red : ($r['state'] === 'active' ? $green : $muted);
			$rows[] = array($r['name'], (string)$r['mode'], array($t('cs_' . $r['state']), $c), wr_bytes($r['bytes'], $L));
		}
		$table(array($t('col_name'), $t('col_mode'), $t('col_state'), $t('col_traffic')), $rows, count($cd['rows']));
	}

	// Honeypot64
	if ($hp = $d['hp']) {
		$h2($t('hp'), WR_BASE . '/honeypot/');
		$kv = array($t('hp_sensors') => (string)$hp['sensors'], $t('hp_events') => wr_num($hp['events'], 0, $L), $t('hp_sources') => wr_num($hp['sources'], 0, $L));
		if ($hp['sources'] > 0) { $kv[$t('hp_listed')] = wr_num($hp['listed'], 0, $L); }
		if ($hp['fps'] > 0) { $kv[$t('hp_fps')] = wr_num($hp['fps'], 0, $L); }
		$facts($kv);
	}

	// Dank am Ende (mit Honeypot64 auch fuer die Meldungen)
	$badge('&#x1F49A;', $t('thanks_head'), $d['hp'] ? array($t('thanks'), $t('thanks_hp')) : array($t('thanks')));

	// Cloud Router
	if ($vp = $d['vpn']) {
		$h2($t('vpn'), WR_BASE . '/cloud-router');
		$facts(array($t('vpn_month') => wr_bytes($vp['month_bytes'], $L) . ' ' . $t('of') . ' ' . ($vp['limit_bytes'] > 0 ? wr_bytes($vp['limit_bytes'], $L) : $t('unlimited'))));
		$rows = array();
		foreach (array_slice($vp['rows'], 0, WR_LIST_MAX) as $r) {
			$c = $r['state'] === 'limited' ? $red : ($r['state'] === 'active' ? $green : $muted);
			$rows[] = array($r['name'], array($t('vs_' . $r['state']), $c));
		}
		$table(array($t('col_gw'), $t('col_state')), $rows, count($vp['rows']));
	}

	// Fuss: warum, Einstellungen, Abmelden
	$text .= "\n--\n" . $t('why') . "\n" . $t('settings') . ': ' . $settingsUrl . "\n" . $t('unsubscribe') . ': ' . $unsub . "\n" . $t('privacy') . ': ' . WR_BASE . "/datenschutz\n";
	$foot = '<tr><td style="padding:22px 24px 18px 24px;border-top:1px solid ' . $line . ';font-size:12px;line-height:1.5;color:' . $muted . '">' . wr_h($t('why')) . '<br>'
		. '<a href="' . wr_h($settingsUrl) . '" style="color:' . $muted . '">' . wr_h($t('settings')) . '</a> &middot; '
		. '<a href="' . wr_h($unsub) . '" style="color:' . $muted . '">' . wr_h($t('unsubscribe')) . '</a> &middot; '
		. '<a href="' . WR_BASE . '/datenschutz" style="color:' . $muted . '">' . wr_h($t('privacy')) . '</a></td></tr>';
	$doc = '<!DOCTYPE html><html lang="' . $L . '"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light"><title>' . wr_h($subject) . '</title></head>'
		. '<body style="margin:0;padding:0;background:#f1f1f1;font-family:Arial,Helvetica,sans-serif;font-size:15px;line-height:1.5">'
		. '<div style="display:none;max-height:0;overflow:hidden;color:#f1f1f1">' . wr_h($band[1] . ($issues ? ': ' . implode(' ', $issues) : ' – ' . $range)) . '</div>'
		. '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f1f1f1"><tr><td align="center" style="padding:24px 12px">'
		. '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:640px;background:#ffffff;border-radius:8px;overflow:hidden">'
		. '<tr><td style="padding:16px 24px;border-bottom:1px solid ' . $line . ';font-size:18px;font-weight:bold;color:' . $teal . '">IPv64.net</td></tr>'
		. $html . $foot . '</table></td></tr></table></body></html>';
	return array('subject' => $subject, 'html' => $doc, 'text' => trim($text) . "\n", 'unsubscribe' => $unsub);
}

/**
 * Verschickt den Bericht an $to (ueber send_mail mit eigenem Textteil). Ein-Klick-Abmeldung nach RFC 8058 im Kopf.
 * Liefert '' bei Erfolg, sonst eine kurze Fehlermeldung.
 */
function wr_send(PDO $pdo, array $d, string $to): string {
	if (!filter_var($to, FILTER_VALIDATE_EMAIL)) { return 'invalid address'; }
	if (!function_exists('send_mail') || (new ReflectionFunction('send_mail'))->getNumberOfParameters() < 9) { return 'send_mail without text option (9th parameter)'; }
	$m = wr_render($d, wr_token($pdo, (int)$d['userid']));
	$mail = new PHPMailer\PHPMailer\PHPMailer();
	$mail->CharSet = 'UTF-8';
	$mail->addCustomHeader('List-Unsubscribe', '<' . $m['unsubscribe'] . '>');
	$mail->addCustomHeader('List-Unsubscribe-Post', 'List-Unsubscribe=One-Click');
	$mail->addCustomHeader('List-Id', 'IPv64.net weekly report <weekly-report.ipv64.net>');
	$ok = send_mail($pdo, $mail, '', 'IPv64.net', $to, $m['subject'], $m['html'], '', array('text' => $m['text']));
	$mail->smtpClose();
	return $ok === false ? 'mail not sent' : '';
}
