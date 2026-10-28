<?php
/**
 * IPv64.net API v2 – Fruehwarnung fuer eigene Netze, Honeypot64 Phase H5 (Pfade /threat/watch...). Wird von api_v2.php
 * vor dispatch() eingebunden:
 *     require __DIR__ . '/api_v2_threat_watch.php';
 * Gemeinsame Logik mit der Seite honeypot/watch.php und dem Cron bots/honeypot_watch.php: honeypot/hp_limits_lib.php.
 * Tabellen hp_watch, hp_watch_alerts (deploy/sql/honeypot_h5.sql). Planung: docs/PLAN-NODE64-HONEYPOT64.md (Abschnitt 11).
 *
 *   GET    /threat/watch                Limits, eigene Netze, automatisch ueberwachte DynDNS-IPs
 *   POST   /threat/watch                Netz eintragen {"cidr", "label"} -> 201; 422 invalid_cidr | prefix_too_large |
 *                                       not_public, 409 duplicate, 403 limit_reached
 *   DELETE /threat/watch/{id}           Netz loeschen -> 204; 404
 *   GET    /threat/watch/alerts?since=  Treffer nach dem Stand since, aelteste zuerst (created_at, id), hoechstens 100.
 *                                       since = Cursor aus next ("<RFC 3339>_<id>": (created_at, id) > (Zeit, id)) oder
 *                                       reines RFC 3339 (created_at > Zeit); leer = alle. next = Cursor des letzten
 *                                       Treffers; ohne neue Treffer der uebergebene Stand bzw. bei leerem since die
 *                                       aktuelle Zeit (minus HPW_SAFETY). Der Client gibt next unveraendert zurueck.
 *
 * Netze ohne Nachweis (verified = false) und DynDNS-IPs des Accounts (ein Record ist kein Nachweis) bekommen nur Treffer
 * fuer gelistete IPs (ohnehin oeffentlich), DynDNS-Details ohne Port und Regel. Treffer erzeugt der Cron alle 30 Minuten nach der Bewertung.
 * Limit je Account wie GET /threat/ip mit Key (eigener Topf).
 */
require_once __DIR__ . '/honeypot/hp_limits_lib.php';

const HPW_PAGE   = 100; // Treffer je Abruf
const HPW_SAFETY = 300; // next ohne Treffer und ohne since: jetzt minus 5 min (ein laufender Cron-Lauf schreibt noch)

function hpw_api_limit(): void { rl_enforce('threat:watch:' . uid(), HPR_RL_KEY_CAP, HPR_RL_KEY_REFILL, 'early warning'); }

/** GET /threat/watch: Limits, Netze, DynDNS-IPs. */
route('GET', '/threat/watch', function() {
	global $pdo, $ME;
	hpw_api_limit();
	ok(array('limits' => hpl_limits((int)$ME['user_class']), 'networks' => hpl_nets($pdo, uid()), 'dyndns' => hpl_dyndns($pdo, uid())));
});

/** POST /threat/watch: Netz eintragen. */
route('POST', '/threat/watch', function() {
	global $pdo, $ME;
	hpw_api_limit();
	$cidr = in_str('cidr', true, 64);
	$label = in_str('label', false, HPL_LABEL_MAX, '');
	[$err, $net] = hpl_net_add($pdo, uid(), (int)$ME['user_class'], $cidr, $label);
	if($err === null) { ok($net, 201); }
	$lim = hpl_limits((int)$ME['user_class']);
	switch($err) {
		case 'invalid_cidr': fail(422, 'invalid_cidr', 'Give a network in CIDR form (e.g. 203.0.113.0/24) or a single IP address.', array('field' => 'cidr'));
		case 'prefix_too_large': fail(422, 'prefix_too_large', "Networks may be at most /{$lim['min_prefix_v4']} (IPv4) or /{$lim['min_prefix_v6']} (IPv6).", array('field' => 'cidr'));
		case 'not_public': fail(422, 'not_public', 'Private, reserved and special networks cannot be watched.', array('field' => 'cidr'));
		case 'duplicate': fail(409, 'duplicate', 'This network is already on your watch list.', array('field' => 'cidr'));
		case 'limit_reached': fail(403, 'limit_reached', "Your plan allows at most {$lim['max']} watched networks.", array('limit' => $lim['max']));
	}
	fail(500, 'internal_error', 'An internal error occurred.');
});

/** DELETE /threat/watch/{id}: Netz loeschen (fruehere Treffer bleiben). */
route('DELETE', '/threat/watch/{id}', function($p) {
	global $pdo;
	hpw_api_limit();
	$id = (string)($p['id'] ?? '');
	if(!ctype_digit($id) OR strlen($id) > 10 OR !hpl_net_delete($pdo, uid(), (int)$id)) { fail(404, 'not_found', 'Unknown network.'); }
	no_content();
});

/** GET /threat/watch/alerts?since=<Cursor oder RFC 3339>: Treffer, aelteste zuerst. */
route('GET', '/threat/watch/alerts', function() {
	global $pdo;
	hpw_api_limit();
	$in = qp('since', '');
	$since = 0; $sid = null;
	if($in !== '') {
		if(!preg_match('/^(\d{4}-\d\d-\d\d)[Tt](\d\d:\d\d:\d\d)(\.\d{1,9})?([Zz]|[+-]\d\d:\d\d)(?:_(\d{1,19}))?$/', $in, $m)) {
			fail(400, 'invalid_parameter', "Query parameter 'since' must be the 'next' value of the previous answer or an RFC 3339 timestamp.");
		}
		$d = DateTime::createFromFormat('!Y-m-d H:i:s', $m[1] . ' ' . $m[2], new DateTimeZone(strtoupper($m[4]) === 'Z' ? 'UTC' : $m[4]));
		if($d === false OR $d->format('Y-m-d H:i:s') !== $m[1] . ' ' . $m[2]) { fail(400, 'invalid_parameter', "Query parameter 'since' is not a valid time."); }
		$since = max(0, $d->getTimestamp());
		$sid = isset($m[5]) ? $m[5] : null;
	}
	// Cursor: (created_at, id) > (Zeit, id) – auch viele Treffer mit gleichem created_at gehen nicht verloren
	$p = array('u' => uid(), 's' => hpr_dt($since));
	$cond = 'created_at > :s';
	if($sid !== null) { $cond = '(created_at > :s OR (created_at = :s2 AND id > :id))'; $p['s2'] = hpr_dt($since); $p['id'] = $sid; }
	$rows = hpr_all($pdo, "SELECT * FROM hp_watch_alerts WHERE userid = :u AND $cond ORDER BY created_at, id LIMIT " . HPW_PAGE, $p);
	if($rows) {
		$last = $rows[count($rows) - 1];
		$next = hpr_iso($last['created_at']) . '_' . $last['id'];
	} else {
		$next = $in !== '' ? $in : gmdate('Y-m-d\TH:i:s\Z', time() - HPW_SAFETY);
	}
	ok(array('alerts' => array_map('hpl_alert_out', $rows), 'next' => $next));
});
