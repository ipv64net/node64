<?php
/**
 * Honeypot64 (H5): Limits je Account-Klasse und gemeinsame Funktionen der Fruehwarnung fuer eigene Netze.
 * Eingebunden (require_once) von api_v2_threat_watch.php, api_v2_honeypot.php (Sensor-Limit), honeypot/watch.php und
 * bots/honeypot_watch.php; definiert nur Konstanten und Funktionen (keine Ausgabe, keine Datenbankverbindung: $pdo
 * kommt vom Aufrufer). Tabellen hp_watch, hp_watch_alerts (deploy/sql/honeypot_h5.sql). Alle Zeiten UTC.
 * Planung: docs/PLAN-NODE64-HONEYPOT64.md (Abschnitte 8, 11, "H5 Umsetzung").
 *
 * Limits als Konstanten statt Spalten in user_class: user_class hat keine passenden Werte (dyndns_limit waere fuer
 * Standard zufaellig 3, fuer VIP aber 10 und fuer Company 256 – das passt nicht zu "Standard 3, sonst 50"). Plan
 * Abschnitt 8: Unterschied nur Standard (user_class = 1) gegen alle anderen Klassen.
 */
require_once __DIR__ . '/hp_release_lib.php'; // hpr_cidr, hpr_public, hpr_q/hpr_one/hpr_all, hpr_dt, hpr_iso, hpr_csv

const HPL_NETS_STANDARD    = 3;     // eigene Netze, Klasse Standard (user_class = 1)
const HPL_NETS_OTHER       = 50;    // eigene Netze, alle anderen Klassen
const HPL_MIN_PREFIX_V4    = 16;    // IPv4 hoechstens /16
const HPL_MIN_PREFIX_V6    = 32;    // IPv6 hoechstens /32
const HPL_SENSORS_STANDARD = 5;     // Honeypot64-Sensoren je Account, Klasse Standard
const HPL_SENSORS_OTHER    = 25;    // dito, alle anderen Klassen
const HPL_SENSOR_ACTIVE    = 30 * 86400; // zum Sensor-Limit zaehlen Sensoren mit Meldung in den letzten 30 Tagen
const HPL_LABEL_MAX        = 100;   // Bezeichnung eines Netzes
const HPL_DYNDNS_MAX       = 500;   // hoechstens so viele DynDNS-IPs in Antwort/Seite

// ---------------------------------------------------------------- Limits

/** Klasse eines Accounts (users.user_class); unbekannt = Standard. */
function hpl_class(PDO $pdo, int $uid): int {
	return (int)(hpr_one($pdo, "SELECT user_class FROM users WHERE id = :u", array('u' => $uid))['user_class'] ?? 1);
}

/** Limits der Fruehwarnung je Klasse (Form wie in GET /threat/watch). */
function hpl_limits(int $class): array {
	return array('max' => $class === 1 ? HPL_NETS_STANDARD : HPL_NETS_OTHER, 'min_prefix_v4' => HPL_MIN_PREFIX_V4, 'min_prefix_v6' => HPL_MIN_PREFIX_V6);
}

/** Honeypot64-Sensoren je Account (aktive, siehe HPL_SENSOR_ACTIVE). */
function hpl_sensor_limit(int $class): int { return $class === 1 ? HPL_SENSORS_STANDARD : HPL_SENSORS_OTHER; }

// ---------------------------------------------------------------- Netze

/** Bezeichnung: ohne Steuerzeichen, getrimmt, gekuerzt. */
function hpl_label(string $s): string {
	$s = trim((string)preg_replace('/[\x00-\x1F\x7F]/u', '', $s));
	return mb_substr($s, 0, HPL_LABEL_MAX);
}

/**
 * Netz pruefen. Rueckgabe array(cidr normalisiert, erste Adresse, letzte Adresse) (binaer) oder Fehlercode:
 * invalid_cidr | prefix_too_large | not_public (ganz in privatem/reserviertem Bereich).
 */
function hpl_net_check(string $in) {
	$c = hpr_cidr($in);
	if($c === null) { return 'invalid_cidr'; }
	$len = (int)explode('/', $c[0])[1];
	if($len < (strlen($c[1]) === 4 ? HPL_MIN_PREFIX_V4 : HPL_MIN_PREFIX_V6)) { return 'prefix_too_large'; }
	if(!hpr_public($c[1]) AND !hpr_public($c[2])) { return 'not_public'; }
	return $c;
}

/**
 * Netz eintragen. Rueckgabe array(null, Netz wie hpl_net_out) oder array(Fehlercode, null):
 * invalid_cidr | prefix_too_large | not_public | duplicate | limit_reached.
 */
function hpl_net_add(PDO $pdo, int $uid, int $class, string $cidr, string $label): array {
	$c = hpl_net_check($cidr);
	if(is_string($c)) { return array($c, null); }
	if(hpr_one($pdo, "SELECT id FROM hp_watch WHERE userid = :u AND cidr = :c", array('u' => $uid, 'c' => $c[0])) !== null) { return array('duplicate', null); }
	$n = (int)hpr_one($pdo, "SELECT COUNT(*) n FROM hp_watch WHERE userid = :u", array('u' => $uid))['n'];
	if($n >= hpl_limits($class)['max']) { return array('limit_reached', null); }
	try {
		hpr_q($pdo, "INSERT INTO hp_watch (userid, cidr, ip_start, ip_end, label, verified, created_at) VALUES (:u, :c, UNHEX(:s), UNHEX(:e), :l, 0, :t)",
			array('u' => $uid, 'c' => $c[0], 's' => bin2hex($c[1]), 'e' => bin2hex($c[2]), 'l' => hpl_label($label), 't' => hpr_dt(time())));
	} catch(RuntimeException $e) {
		if(str_contains($e->getMessage(), 'Duplicate')) { return array('duplicate', null); } // gleichzeitig eingetragen
		throw $e;
	}
	return array(null, hpl_net_out(hpr_one($pdo, "SELECT * FROM hp_watch WHERE userid = :u AND cidr = :c", array('u' => $uid, 'c' => $c[0]))));
}

/** Netz loeschen; false = nicht vorhanden (oder fremd). */
function hpl_net_delete(PDO $pdo, int $uid, int $id): bool {
	return hpr_q($pdo, "DELETE FROM hp_watch WHERE id = :id AND userid = :u", array('id' => $id, 'u' => $uid))->rowCount() > 0;
}

/** Eigene Netze, aelteste zuerst. */
function hpl_nets(PDO $pdo, int $uid): array {
	return array_map('hpl_net_out', hpr_all($pdo, "SELECT * FROM hp_watch WHERE userid = :u ORDER BY id", array('u' => $uid)));
}

function hpl_net_out(array $r): array {
	return array('id' => (int)$r['id'], 'cidr' => $r['cidr'], 'label' => (string)$r['label'], 'verified' => (int)$r['verified'] === 1, 'created_at' => hpr_iso($r['created_at']));
}

// ---------------------------------------------------------------- DynDNS-IPs

/**
 * Aktuelle DynDNS-IPs eines Accounts: dieselbe Quelle wie reason customer_ip in der Bewertung
 * (bots/blocklist/honeypot_score.php: subdomain_records A/AAAA, deactivated = 0), ohne CDN-Hilfseintraege
 * (cdn_tmp != 0 zeigen auf die Edge-Server von ipv64), nur oeffentliche Adressen. Rueckgabe [{ip, domain}], je IP
 * und Domain einmal, nach Domain sortiert, hoechstens HPL_DYNDNS_MAX.
 */
function hpl_dyndns(PDO $pdo, int $uid): array {
	$out = array();
	foreach(hpr_all($pdo, "SELECT praefix, domainname, content FROM subdomain_records WHERE userid = :u AND type IN ('A', 'AAAA') AND deactivated = 0 AND cdn_tmp = 0",
		array('u' => $uid)) as $r) {
		$ip = hpr_ip(trim((string)$r['content']));
		if($ip === null OR !hpr_public(inet_pton($ip))) { continue; }
		$d = ($r['praefix'] !== '' ? $r['praefix'] . '.' : '') . $r['domainname'];
		$out[$ip . '|' . $d] = array('ip' => $ip, 'domain' => $d);
	}
	$out = array_values($out);
	usort($out, fn($a, $b) => strcmp($a['domain'], $b['domain']) ?: strcmp($a['ip'], $b['ip']));
	return array_slice($out, 0, HPL_DYNDNS_MAX);
}

// ---------------------------------------------------------------- Treffer

/** Treffer fuer API und Seite (Vertrag GET /threat/watch/alerts; label zusaetzlich: Netzname bzw. Domain). */
function hpl_alert_out(array $r): array {
	$day = fn($s) => ($t = hpr_ts($s)) === null ? null : gmdate('Y-m-d', $t);
	$det = isset($r['details']) && $r['details'] !== null ? json_decode((string)$r['details'], true) : null;
	return array('id' => (int)$r['id'], 'ip' => $r['ip'], 'cidr' => $r['cidr'], 'network_id' => $r['network_id'] === null ? null : (int)$r['network_id'],
		'source' => $r['source'], 'label' => (string)$r['label'], 'listed' => (int)$r['listed'] === 1, 'score' => (int)$r['score'], 'kinds' => hpr_csv($r['kinds']),
		'first_seen' => $day($r['first_seen']), 'last_seen' => $day($r['last_seen']), 'created_at' => hpr_iso($r['created_at']),
		'details' => is_array($det) ? $det : null);
}

/**
 * Details eines Treffers (Fruehwarnung) als JSON: warum die IP aufgefallen ist. Aus hp_scores (Anzahl Accounts,
 * Sensoren, Ereignisse, Listen, Grund) und hp_report_sources der letzten 14 Tage, gruppiert nach Herkunft (honeypot,
 * log, syslog), Dienst, Port, Art und Regel (hoechstens 8 Zeilen, die haeufigsten zuerst). Nie Sensor-Kennungen,
 * Accounts, Hostnamen oder Inhalte (Pfade, Zugangsdaten) – die Fruehwarnung darf keine Sensoren verraten.
 */
function hpl_watch_details(PDO $pdo, array $s, int $now, bool $coarse = false): string {
	$seen = array();
	try {
		// grob (DynDNS-Treffer ohne Nachweis): ohne Port und Regel, letzte Sichtung nur auf den Tag (wie ip.php)
		foreach(hpr_all($pdo, $coarse ? "SELECT source, service, 0 port, kind, '' rule, SUM(`count`) n, COUNT(DISTINCT sensor_id) sensors, DATE(MAX(last_seen)) last
			FROM hp_report_sources WHERE ip_bin = :b AND last_seen >= :d GROUP BY source, service, kind ORDER BY n DESC LIMIT 8"
			: "SELECT source, service, port, kind, rule, SUM(`count`) n, COUNT(DISTINCT sensor_id) sensors, MAX(last_seen) last
			FROM hp_report_sources WHERE ip_bin = :b AND last_seen >= :d GROUP BY source, service, port, kind, rule ORDER BY n DESC LIMIT 8",
			array('b' => $s['ip_bin'], 'd' => hpr_dt($now - 14 * 86400))) as $r) {
			$seen[] = array('origin' => (string)$r['source'], 'service' => (string)$r['service'], 'port' => (int)$r['port'], 'kind' => (string)$r['kind'],
				'rule' => (string)$r['rule'], 'count' => (int)$r['n'], 'sensors' => (int)$r['sensors'], 'last' => hpr_iso($r['last']));
		}
	} catch(Throwable $e) { /* Details sind Beiwerk: der Treffer zaehlt auch ohne */ }
	return json_encode(array('accounts' => (int)($s['accounts'] ?? 0), 'sensors' => (int)($s['sensors'] ?? 0), 'events' => (int)($s['events'] ?? 0),
		'lists' => hpr_csv($s['lists'] ?? ''), 'reason' => (string)($s['reason'] ?? ''), 'seen' => $seen), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}

/** Details als eine Zeile Text (Mail, Seite): "Honeypot ssh/22 ssh_brute ×123 · Log http/443 ×4 – 3 Sensoren, 2 Accounts". */
function hpl_details_text(?array $d, bool $en): string {
	if(!$d) { return ''; }
	$origin = array('honeypot' => 'Honeypot', 'log' => 'Log', 'syslog' => 'Syslog');
	$parts = array();
	foreach((array)($d['seen'] ?? array()) as $x) {
		$p = ($origin[$x['origin'] ?? ''] ?? (string)($x['origin'] ?? '')) . ' ' . strtolower((string)($x['service'] ?? '')) . (!empty($x['port']) ? '/' . (int)$x['port'] : '')
			. ' ' . (string)($x['kind'] ?? '') . (!empty($x['rule']) ? ' (' . $x['rule'] . ')' : '') . ' ×' . (int)($x['count'] ?? 0);
		$parts[] = trim(preg_replace('/\s+/', ' ', $p));
	}
	$sum = (int)($d['sensors'] ?? 0) . ($en ? ' sensors, ' : ' Sensoren, ') . (int)($d['accounts'] ?? 0) . ($en ? ' accounts' : ' Accounts');
	return ($parts ? implode(' · ', $parts) . ' – ' : '') . $sum;
}
