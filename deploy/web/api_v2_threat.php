<?php
/**
 * IPv64.net API v2 – IP-Auskunft Honeypot64 (Pfade /threat/...), Phase H3. Wird von api_v2.php vor dispatch() eingebunden:
 *     require __DIR__ . '/api_v2_threat.php';
 * Gemeinsame Logik mit der Seite honeypot/ip.php: honeypot/hp_release_lib.php. Planung: docs/PLAN-NODE64-HONEYPOT64.md
 * (Abschnitte 7, 9, 13).
 *
 *   GET /threat/ip/{ip}   "Warum ist diese IP gelistet?" – ohne API-Key erlaubt (strenges Limit je Client-IP),
 *                         mit API-Key grosszuegiger (je Account). Ein ungueltiger Key ergibt 401 wie ueberall.
 *
 * Antwort: gelistet ja/nein, Status (auch Freigabe), Score, Listen, Arten, Ports, erste/letzte Sichtung (Tag, UTC),
 * Anzahl meldender Accounts, Land/ASN (falls vorhanden, sonst null). Nie: Sensor-IDs, Accounts, Zugangsdaten. Fuer
 * nicht gelistete IPs keine Details (gleiche Antwort, ob gesehen oder nicht), damit sich Sensoren nicht finden lassen.
 */
require_once __DIR__ . '/honeypot/hp_release_lib.php';

/** GET /threat/ip/{ip}: IP-Auskunft. */
route('GET', '/threat/ip/{ip}', function($p) {
	global $pdo;
	$tok = bearer();
	if($tok !== null AND $tok !== '') {
		authenticate();
		rl_enforce('threat:user:' . uid(), HPR_RL_KEY_CAP, HPR_RL_KEY_REFILL, 'IP lookups');
	} else {
		rl_enforce('threat:anon:' . hpr_rl_key(client_ip()), HPR_RL_ANON_CAP, HPR_RL_ANON_REFILL, 'IP lookups without API key');
	}
	$ip = hpr_ip((string)($p['ip'] ?? ''));
	if($ip === null) { fail(422, 'invalid_ip', 'Give exactly one IPv4 or IPv6 address (no networks, no zone).', array('field' => 'ip')); }
	if(!hpr_public(inet_pton($ip))) { fail(422, 'not_public_ip', 'Private, reserved and special addresses are never listed.', array('field' => 'ip')); }
	try {
		$r = hpr_lookup($pdo, $ip);
	} catch(Throwable $e) {
		error_log('api_v2 threat: ' . $e->getMessage());
		fail(503, 'unavailable', 'The IP lookup is temporarily unavailable.');
	}
	$r['details'] = HPR_URL . '?ip=' . rawurlencode($ip);
	ok($r);
}, true);
