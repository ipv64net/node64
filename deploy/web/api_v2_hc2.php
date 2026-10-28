<?php
/**
 * IPv64.net API v2 – Healthchecks 2.0 (Pfade /hc2/...). Wird von api_v2.php vor dispatch() eingebunden:
 *     require __DIR__ . '/api_v2_hc2.php';
 * Nutzt das Grundgeruest von api_v2.php (route, ok, fail, in_*, qp*, uid) und die Bibliothek der Portal-Seiten
 * (healthchecks2/hc2_lib.php). Feldnamen wie in der Node-API, damit Skripte gegen Node und Portal gleich aussehen.
 * Die alten /healthchecks-Pfade bleiben unveraendert.
 * Am Ende: Node-Uebersicht von Node64 (POST /node64/hello, GET /node64/nodes; Tabelle node64_nodes), weil nur diese
 * Datei sicher eingebunden ist.
 */
require_once __DIR__ . '/healthchecks2/hc2_lib.php';

// ---------------------------------------------------------------- Abbildungen

function hc2_iso(?string $utc): ?string {
	if ($utc === null || $utc === '' || str_starts_with($utc, '0000')) { return null; }
	try { $d = new DateTime($utc, new DateTimeZone('UTC')); return $d->format('Y-m-d\TH:i:s.v\Z'); } catch (Throwable $e) { return null; }
}
function hc2_dbtime(string $iso): string {
	try { $d = new DateTime($iso); } catch (Throwable $e) { fail(400, 'invalid_time', "Invalid timestamp: $iso"); }
	$d->setTimezone(new DateTimeZone('UTC'));
	return $d->format('Y-m-d H:i:s.v');
}
function hc2_find(string $token): array {
	$c = hc2_check(uid(), $token);
	if (!$c) { fail(404, 'not_found', 'Healthcheck not found.'); }
	return $c;
}
function hc2_find_node(string $id): array {
	$id = preg_replace('/[^A-Za-z0-9_-]/', '', $id);
	$n = hc2_nodes(uid(), true)[$id] ?? null;
	if (!$n) { fail(404, 'not_found', 'Node not found or unlinked.'); }
	return $n;
}
function hc2_check_out(array $c, bool $detail = false): array {
	$nodes = hc2_nodes(uid());
	$state = (int)$c['paused'] ? 'paused' : ($c['state'] ?: 'pending');
	// letzte Messung aus den Zustaenden je Messstelle (hc2_checks.last_check_at aendert sich nur beim Zustandswechsel)
	static $last = null;
	if ($last === null) {
		$last = array();
		$st = hc2_pdo()->prepare("SELECT s.token, MAX(s.last_check_at) AS m FROM hc2_check_states s JOIN hc2_checks c ON c.token = s.token WHERE c.userid = :u AND c.deleted_at IS NULL GROUP BY s.token");
		$st->execute(array('u' => uid()));
		foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $r) { $last[$r['token']] = $r['m']; }
	}
	$lastCheck = (isset($last[$c['token']]) && $last[$c['token']] > (string)$c['last_check_at']) ? $last[$c['token']] : $c['last_check_at'];
	$o = array(
		'token' => $c['token'], 'name' => $c['name'], 'type' => $c['type'], 'target' => $c['target'], 'params' => hc2_check_params($c) ?: new stdClass(),
		'interval_seconds' => (int)$c['interval_sec'], 'retry_interval_seconds' => (int)$c['retry_interval_sec'], 'retries' => (int)$c['retries'],
		'connect_timeout_seconds' => (int)$c['connect_timeout_ms'] / 1000, 'timeout_seconds' => (int)$c['total_timeout_ms'] / 1000,
		'invert' => (int)$c['invert'] === 1, 'stabilize' => (int)$c['stabilize'], 'ip_mode' => $c['ip_mode'], 'tags' => array_values(array_filter(explode(',', (string)$c['tags']))), 'group' => (string)$c['group_name'],
		'description' => (string)$c['description'], 'paused' => (int)$c['paused'] === 1, 'parent' => (string)$c['parent_token'], 'critical' => (int)$c['critical'] === 1,
		'execution' => $c['execution'], 'node_id' => $c['node_id'], 'node_name' => $c['node_id'] ? hc2_node_label($nodes, $c['node_id']) : null,
		'nodes' => array_map(function($id) use ($nodes) { return array('node_id' => $id, 'name' => hc2_node_label($nodes, $id) ?: null); }, hc2_check_nodes($c)),
		'locations' => array_values(array_filter(explode(',', (string)$c['locations']))), 'policy' => $c['policy'], 'notify_degraded' => (int)$c['notify_degraded'] === 1,
		'notify_down' => (int)$c['notify_down'] === 1, 'notify_up' => (int)$c['notify_up'] === 1, 'channels' => hc2_check_channels($c), 'repeat_minutes' => (int)$c['repeat_minutes'],
		'revision' => (int)$c['revision'], 'created_at' => hc2_iso($c['created_at']), 'updated_at' => hc2_iso($c['updated_at']),
		'state' => array('state' => $state, 'since' => hc2_iso($c['state_since']), 'last_check_at' => hc2_iso($lastCheck), 'last_status' => $c['last_status'],
			'last_latency_ms' => $c['last_latency_ms'] !== null ? (float)$c['last_latency_ms'] : null, 'last_reason' => $c['last_reason'], 'last_message' => $c['last_message'],
			'down_since' => hc2_iso($c['down_since']), 'last_push_at' => hc2_iso($c['last_push_at'])),
	);
	if ($c['type'] === 'push') {
		$o['push'] = array('url' => 'https://ipv64.net/health.php?token=' . $c['token'], 'hub_url' => 'https://hc-srv01.ipv64.net/v1/push/' . $c['token'],
			'node_path' => $c['execution'] !== 'online' ? '/api/push/' . $c['token'] : null);
	}
	if ($detail) {
		$st = hc2_pdo()->prepare("SELECT * FROM hc2_check_states WHERE token = :t ORDER BY source"); $st->execute(array('t' => $c['token']));
		$o['sources'] = array_map(function($s) use ($nodes) {
			return array('source' => $s['source'], 'label' => hc2_source_label($s['source'], $nodes), 'state' => $s['state'], 'since' => hc2_iso($s['since']), 'last_check_at' => hc2_iso($s['last_check_at']),
				'last_status' => $s['last_status'], 'last_latency_ms' => $s['last_latency_ms'] !== null ? (float)$s['last_latency_ms'] : null, 'last_reason' => $s['last_reason'], 'last_message' => $s['last_message'],
				'consecutive_fail' => (int)$s['consecutive_fail'], 'consecutive_ok' => (int)$s['consecutive_ok']);
		}, $st->fetchAll(PDO::FETCH_ASSOC));
		$o['availability_percent'] = hc2_availability($c['token']);
	}
	return $o;
}
function hc2_event_out(array $e, array $nodes): array {
	return array('id' => (int)$e['id'], 'event_id' => $e['event_id'], 'token' => $e['token'], 'source' => $e['source'], 'source_label' => hc2_source_label($e['source'], $nodes), 'kind' => $e['kind'],
		'time' => hc2_iso($e['time']), 'from_state' => $e['from_state'], 'to_state' => $e['to_state'], 'reason' => $e['reason'], 'message' => $e['message'],
		'duration_seconds' => (int)$e['duration_sec'], 'flaps' => (int)$e['flaps'], 'silent' => ((int)$e['flags'] & 2) === 2, 'incident_id' => $e['incident_id'] !== null ? (int)$e['incident_id'] : null);
}
function hc2_incident_out(array $i, array $nodes, array $names): array {
	$end = $i['ended_at'] ? strtotime($i['ended_at'] . ' UTC') : time();
	return array('id' => (int)$i['id'], 'token' => $i['token'], 'name' => $names[$i['token']] ?? null, 'status' => $i['ended_at'] ? 'closed' : 'open', 'started_at' => hc2_iso($i['started_at']),
		'ended_at' => hc2_iso($i['ended_at']), 'duration_seconds' => max(0, $end - strtotime($i['started_at'] . ' UTC')), 'reason' => $i['reason'], 'message' => $i['message'],
		'sources' => array_values(array_filter(explode(',', (string)$i['sources']))));
}
function hc2_channel_out(array $ch): array {
	$types = hc2_channel_types(); $cfg = array();
	foreach ($ch['config'] as $k => $v) { if (!in_array($k, $ch['has_secret'], true)) { $cfg[$k] = $v === 'true' ? true : $v; } }
	return array('id' => (int)$ch['id'], 'type' => $ch['type'], 'type_label' => $types[$ch['type']]['label'] ?? $ch['type'], 'name' => $ch['name'], 'config' => $cfg ?: new stdClass(),
		'secrets_set' => array_values($ch['has_secret']), 'enabled' => (int)$ch['enabled'] === 1, 'default' => (int)$ch['is_default'] === 1, 'verified' => (int)$ch['verified'] === 1, 'lang' => $ch['lang'],
		'notify_down' => (int)$ch['notify_down'] === 1, 'notify_up' => (int)$ch['notify_up'] === 1, 'execution' => $ch['execution'], 'node_id' => $ch['node_id'],
		'last_used' => hc2_iso($ch['last_used']), 'last_error' => (string)$ch['last_error'], 'revision' => (int)$ch['revision'], 'created_at' => hc2_iso($ch['created_at']),
		'sendable_via_api' => !$ch['node_id'] && array_key_exists($ch['type'], HC2_API_SEND_TYPES) && (int)$ch['verified'] === 1 && (int)$ch['enabled'] === 1);
}
function hc2_maint_out(array $m): array {
	return array('id' => (int)$m['id'], 'name' => $m['name'], 'start_at' => hc2_iso($m['start_at']), 'end_at' => hc2_iso($m['end_at']), 'repeat' => $m['repeat'], 'repeat_until' => hc2_iso($m['repeat_until']),
		'tokens' => array_values(array_filter(explode(',', (string)$m['tokens']))), 'active' => (int)$m['active'] === 1, 'node_id' => $m['node_id'], 'revision' => (int)$m['revision']);
}
function hc2_node_out(array $n, bool $detail = false): array {
	$o = array('node_id' => $n['node_id'], 'name' => $n['name'], 'location' => $n['location'], 'version' => $n['version'], 'timezone' => $n['timezone'], 'modules' => array_values(array_filter(explode(',', hc2_node_modules($n['modules'])))),
		'remote_mgmt' => $n['remote_mgmt'], 'online' => (int)$n['online'] === 1, 'last_seen' => hc2_iso($n['last_seen']), 'last_sync' => hc2_iso($n['last_sync']), 'outbox_size' => (int)$n['outbox_size'],
		'conflicts' => (int)$n['conflicts'], 'hub' => $n['node'] ?? '', 'linked_at' => hc2_iso($n['created_at']));
	if ($detail) {
		$st = hc2_pdo()->prepare("SELECT * FROM hc2_checks WHERE (node_id = :n OR FIND_IN_SET(:n2, nodes) > 0) AND userid = :u AND deleted_at IS NULL AND execution IN ('local','both') ORDER BY name"); $st->execute(array('n' => $n['node_id'], 'n2' => $n['node_id'], 'u' => uid()));
		$o['checks'] = array_map(fn($c) => hc2_check_out($c), $st->fetchAll(PDO::FETCH_ASSOC));
	}
	return $o;
}
function hc2_testrun_out(array $t): array { unset($t['token']); return $t; }

/** JSON-Body in Formularfelder der Bibliothek umsetzen (Teiländerung: fehlende Felder aus $old). */
function hc2_check_input(?array $old): array {
	$b = body(); $f = array();
	$p = $old ? hc2_check_params($old) : array();
	$f['type'] = (string)($b['type'] ?? ($old['type'] ?? 'http'));
	if (!isset(hc2_types()[$f['type']])) { fail(422, 'invalid_type', 'type must be one of ' . implode(', ', array_keys(hc2_types())) . '.', array('field' => 'type')); }
	$f['name'] = (string)($b['name'] ?? ($old['name'] ?? ''));
	$f['target'] = (string)($b['target'] ?? ($old['target'] ?? ''));
	$pin = isset($b['params']) && is_array($b['params']) ? $b['params'] : array();
	if ($old && $f['type'] === $old['type']) { $pin = array_merge($p, $pin); }
	foreach (array('method','accept_status','max_redirects','keyword','basic_user','basic_password','body','count','max_loss_percent','max_latency_ms','port','send','expect','min_days','cert_min_days','server_name','period_seconds','grace_seconds') as $k) {
		if (isset($pin[$k])) { $f[$k] = is_bool($pin[$k]) ? ($pin[$k] ? '1' : '0') : (string)$pin[$k]; }
	}
	foreach (array('keyword_absent','insecure_tls','tls','skip_chain','skip_hostname','json_any') as $k) { if (!empty($pin[$k])) { $f[$k] = '1'; } }
	if (isset($pin['json_rules'])) { $f['json_rules'] = $pin['json_rules']; } // Liste aus {path, op, value} oder Textform
	foreach (array('record_type','resolver','server','expect','values','min_ttl') as $k) { if ($f['type'] === 'dns' && isset($pin[$k])) { $f['dns_' . $k] = $pin[$k]; } }
	if ($f['type'] === 'dns' && !empty($pin['dnssec'])) { $f['dns_dnssec'] = '1'; }
	if ($f['type'] === 'whois') { // Parameter des WHOIS-Checks (source, min_days, contains)
		if (isset($pin['source'])) { $f['whois_source'] = (string)$pin['source']; }
		if (isset($pin['min_days'])) { $f['whois_min_days'] = (string)(int)$pin['min_days']; }
		if (isset($pin['contains']) && is_array($pin['contains'])) { $f['whois_contains'] = implode("\n", array_map('strval', $pin['contains'])); }
	}
	if (array_key_exists('follow_redirects', $pin)) { $f['follow_redirects_present'] = 1; if ($pin['follow_redirects']) { $f['follow_redirects'] = '1'; } } elseif (!$old) { $f['follow_redirects'] = '1'; }
	if (isset($pin['headers']) && is_array($pin['headers'])) { $lines = array(); foreach ($pin['headers'] as $k => $v) { $lines[] = $k . ': ' . $v; } $f['headers'] = implode("\n", $lines); }
	$map = array('interval_seconds' => array('interval_sec', 60), 'retry_interval_seconds' => array('retry_interval_sec', 20), 'retries' => array('retries', 1), 'stabilize' => array('stabilize', 3), 'repeat_minutes' => array('repeat_minutes', 0));
	foreach ($map as $in => [$col, $def]) { $f[$col] = isset($b[$in]) ? (string)(int)$b[$in] : (string)($old[$col] ?? $def); }
	$f['connect_timeout'] = isset($b['connect_timeout_seconds']) ? (string)(float)$b['connect_timeout_seconds'] : (string)(($old['connect_timeout_ms'] ?? 5000) / 1000);
	$f['total_timeout'] = isset($b['timeout_seconds']) ? (string)(float)$b['timeout_seconds'] : (string)(($old['total_timeout_ms'] ?? 10000) / 1000);
	$f['ip_mode'] = (string)($b['ip_mode'] ?? ($old['ip_mode'] ?? 'auto'));
	$f['group_name'] = isset($b['group']) ? (string)$b['group'] : (string)($old['group_name'] ?? '');
	$f['tags'] = isset($b['tags']) ? (is_array($b['tags']) ? implode(',', $b['tags']) : (string)$b['tags']) : (string)($old['tags'] ?? '');
	$f['description'] = (string)($b['description'] ?? ($old['description'] ?? ''));
	$f['parent_token'] = (string)($b['parent'] ?? ($old['parent_token'] ?? ''));
	$f['channels'] = isset($b['channels']) && is_array($b['channels']) ? $b['channels'] : ($old ? hc2_check_channels($old) : array());
	foreach (array('invert' => 'invert', 'paused' => 'paused', 'critical' => 'critical', 'notify_down' => 'notify_down', 'notify_up' => 'notify_up', 'notify_degraded' => 'notify_degraded') as $in => $col) {
		$def = $old ? (int)$old[$col] === 1 : in_array($col, array('notify_down', 'notify_up'), true);
		$f[$col] = (isset($b[$in]) ? (bool)$b[$in] : $def) ? '1' : '0';
	}
	$f['execution'] = (string)($b['execution'] ?? ($old['execution'] ?? 'online'));
	$f['node_id'] = (string)($b['node_id'] ?? ($old['node_id'] ?? ''));
	// messende Nodes: Liste "nodes" (IDs); nur node_id = eine Node; sonst bisherige Liste
	if (isset($b['nodes']) && is_array($b['nodes'])) { $f['nodes'] = array_values(array_map('strval', $b['nodes'])); }
	elseif (isset($b['node_id'])) { $f['nodes'] = array((string)$b['node_id']); }
	elseif ($old) { $f['nodes'] = hc2_check_nodes($old); }
	$f['locations'] = isset($b['locations']) && is_array($b['locations']) ? $b['locations'] : ($old ? array_filter(explode(',', $old['locations'])) : array_keys(hc2_locations()));
	$f['policy'] = (string)($b['policy'] ?? ($old['policy'] ?? 'all'));
	return $f;
}
function hc2_validate_or_fail(array $f, ?array $old): array {
	$v = hc2_validate_check($f, uid(), $old);
	if ($v['errors']) {
		$code = 'invalid_healthcheck';
		foreach ($v['errors'] as $e) { if (str_contains($e, 'Limit')) { $code = 'limit_reached'; } elseif (str_contains($e, 'privat')) { $code = 'private_target'; } }
		fail($code === 'limit_reached' ? 403 : 422, $code, implode(' ', $v['errors']), array('errors' => $v['errors']));
	}
	return $v['row'];
}
function hc2_paged(string $sql, array $pa, string $idcol = 'id'): array {
	$limit = qp_int('limit', 100, 1, 1000);
	if (($b = qp('before')) !== null && ctype_digit($b)) { $sql .= " AND $idcol < :b"; $pa['b'] = (int)$b; }
	if (($a = qp('after')) !== null && ctype_digit($a)) { $sql .= " AND $idcol > :a"; $pa['a'] = (int)$a; }
	if (($s = qp('since')) !== null && $s !== '') { $sql .= " AND time >= :s"; $pa['s'] = hc2_dbtime($s); }
	$asc = qp('after') !== null;
	$st = hc2_pdo()->prepare("$sql ORDER BY $idcol " . ($asc ? 'ASC' : 'DESC') . " LIMIT " . ($limit + 1)); $st->execute($pa);
	$rows = $st->fetchAll(PDO::FETCH_ASSOC);
	$more = count($rows) > $limit; $rows = array_slice($rows, 0, $limit); $last = end($rows);
	return array($rows, array('limit' => $limit, 'has_more' => $more, ($asc ? 'next_after' : 'next_before') => ($more && $last) ? (int)$last[$idcol] : null));
}

// ---------------------------------------------------------------- Account

route('GET', '/hc2/account', function() {
	$acc = hc2_account(uid()); $nodes = hc2_nodes(uid()); $on = 0; foreach ($nodes as $n) { if ((int)$n['online']) { $on++; } }
	$locs = array(); foreach (hc2_locations() as $code => $name) { $locs[] = array('code' => $code, 'name' => $name); }
	ok(array('plan' => $acc['class_name'], 'online_measuring_points' => array('used' => hc2_online_used(uid()), 'limit' => $acc['healthcheck_limit'] ?: null), 'locations_per_check' => $acc['hc_locations'],
		'checks_per_day' => array('used' => hc2_checks_today(uid()), 'limit' => $acc['checks_per_day'] ?: null),
		'sms_per_day' => $acc['sms_limit'], 'locations' => $locs, 'nodes' => array('total' => count($nodes), 'online' => $on), 'checks' => count(hc2_checks(uid()))));
});

route('GET', '/hc2/settings', function() { ok(hc2_settings(uid()) ?: new stdClass()); });
route('PATCH', '/hc2/settings', function() {
	$allowed = array('notify.quiet_enabled', 'notify.quiet_from', 'notify.quiet_to', 'notify.quiet_days', 'notify.quiet_tz', 'notify.rate_per_hour', 'notify.batch_threshold', 'notify.batch_window_seconds');
	$n = 0;
	foreach (body() as $k => $v) {
		if (!in_array($k, $allowed, true)) { fail(422, 'invalid_setting', "Unknown setting '$k'. Allowed: " . implode(', ', $allowed) . '.', array('field' => $k)); }
		if (is_bool($v)) { $v = $v ? '1' : '0'; } elseif (is_array($v)) { $v = implode(',', array_map('intval', $v)); }
		$v = trim((string)$v); $bad = false;
		// Werte pruefen wie Node und hub (sonst wuerde eine ungueltige Uhrzeit die Ruhezeit still abschalten)
		switch ($k) {
			case 'notify.quiet_enabled': $v = in_array(strtolower($v), array('1', 'true', 'on'), true) ? '1' : '0'; break;
			case 'notify.quiet_from': case 'notify.quiet_to': $bad = !preg_match('/^([01]\d|2[0-3]):[0-5]\d$/', $v); break;
			case 'notify.quiet_days': $d = array_unique(array_map('intval', array_filter(explode(',', $v), 'strlen'))); sort($d); $bad = (bool)array_filter($d, function($x) { return $x < 1 || $x > 7; }); $v = implode(',', $d); break;
			case 'notify.quiet_tz': $bad = $v !== '' && !in_array($v, timezone_identifiers_list(), true); break;
			default: $lim = array('notify.rate_per_hour' => 1000, 'notify.batch_threshold' => 100, 'notify.batch_window_seconds' => 600)[$k]; $bad = !preg_match('/^\d+$/', $v) || (int)$v > $lim; break;
		}
		if ($bad) { fail(422, 'invalid_value', "Invalid value for '$k'.", array('field' => $k)); }
		hc2_set_setting(uid(), $k, $v); $n++;
	}
	if ($n) { hc2_log_change(uid(), 'settings', 'notify', 'upsert', 'api'); }
	ok(hc2_settings(uid()) ?: new stdClass());
});

// ---------------------------------------------------------------- Checks

route('GET', '/hc2/checks', function() {
	$list = hc2_checks(uid());
	$stateOf = fn($c) => (int)$c['paused'] ? 'paused' : ($c['state'] ?: 'pending');
	if (($t = qp('type')) !== null) { $list = array_filter($list, fn($c) => $c['type'] === $t); }
	if (($s = qp('state')) !== null) { $list = array_filter($list, fn($c) => $stateOf($c) === $s); }
	if (($e = qp('execution')) !== null) { $list = array_filter($list, fn($c) => $c['execution'] === $e); }
	if (($n = qp('node_id')) !== null) { $list = array_filter($list, fn($c) => in_array($n, hc2_check_nodes($c), true)); }
	if (($g = qp('tag')) !== null) { $list = array_filter($list, fn($c) => in_array($g, explode(',', $c['tags']), true)); }
	if (($gr = qp('group')) !== null) { $list = array_filter($list, fn($c) => $c['group_name'] === $gr); }
	if (($q = qp('q')) !== null && $q !== '') { $list = array_filter($list, fn($c) => stripos($c['name'] . ' ' . $c['target'], $q) !== false); }
	ok(array_values(array_map(fn($c) => hc2_check_out($c), $list)));
});

route('POST', '/hc2/checks', function() {
	$row = hc2_validate_or_fail(hc2_check_input(null), null);
	$t = hc2_insert_check(uid(), $row);
	ok(hc2_check_out(hc2_find($t), true), 201);
});

route('GET', '/hc2/checks/{token}', function($p) { ok(hc2_check_out(hc2_find($p['token']), true)); });

route('PATCH', '/hc2/checks/{token}', function($p) {
	$old = hc2_find($p['token']);
	$row = hc2_validate_or_fail(hc2_check_input($old), $old);
	$moved = $row['execution'] !== $old['execution'] || ($row['execution'] !== 'online' && !hc2_same_list(array_filter(explode(',', (string)$row['nodes'])), hc2_check_nodes($old))) || ($row['execution'] !== 'local' && $row['locations'] !== $old['locations']);
	if ($moved && !in_bool('force_move', false)) {
		// Ausfuehrungsort nur ueber den Testlauf (POST .../move); alle anderen Felder werden gespeichert
		$row['execution'] = $old['execution']; $row['node_id'] = $old['node_id']; $row['nodes'] = (string)$old['nodes']; $row['locations'] = $old['locations'];
		hc2_update_check(uid(), $old['token'], $row);
		fail(409, 'move_requires_test', 'execution/nodes/locations changed: start a test run with POST /hc2/checks/{token}/move (other fields were saved), or send force_move=true to switch without a test.');
	}
	hc2_update_check(uid(), $old['token'], $row);
	ok(hc2_check_out(hc2_find($old['token']), true));
});

route('DELETE', '/hc2/checks/{token}', function($p) {
	$c = hc2_find($p['token']);
	$uses = hc2_failover_uses(uid(), array($c['token']))[$c['token']] ?? array(); // Monitor in DNS Failover: nur warnen, nicht sperren
	hc2_delete_check(uid(), $c['token']);
	if ($uses) { header('Warning: 299 ipv64.net "check was a monitor in DNS failover: ' . str_replace('"', "'", implode(', ', $uses)) . '"'); }
	no_content();
});
route('POST', '/hc2/checks/{token}/pause', function($p) { $c = hc2_find($p['token']); if (!(int)$c['paused']) { hc2_set_check(uid(), $c['token'], array('paused' => 1)); } ok(hc2_check_out(hc2_find($c['token']))); });
route('POST', '/hc2/checks/{token}/resume', function($p) { $c = hc2_find($p['token']); if ((int)$c['paused']) { hc2_set_check(uid(), $c['token'], array('paused' => 0)); } ok(hc2_check_out(hc2_find($c['token']))); });
route('POST', '/hc2/checks/{token}/run', function($p) {
	$c = hc2_find($p['token']);
	if ($c['type'] === 'push') { fail(422, 'not_applicable', 'Push checks are not measured actively.'); }
	if ($c['execution'] === 'online' || !hc2_check_nodes($c)) { ok(array('queued' => false, 'detail' => 'Online checks run on their interval; the next measurement follows shortly.')); }
	$ids = array(); foreach (hc2_check_nodes($c) as $rn) { $ids[$rn] = hc2_command($rn, 'run_check', array('token' => $c['token'])); }
	ok(array('queued' => true, 'command_id' => reset($ids), 'node_id' => array_key_first($ids), 'commands' => $ids), 202);
});

/** Umhaengen: Testlauf starten; Ergebnis per GET /hc2/testruns/{id} (bei ok wird der Wechsel angewendet) */
route('POST', '/hc2/checks/{token}/move', function($p) {
	$c = hc2_find($p['token']);
	$to = in_str('execution', true, 10);
	if (!in_array($to, array('local', 'online', 'both'), true)) { fail(422, 'invalid_execution', 'execution must be local, online or both.', array('field' => 'execution')); }
	$one = in_str('node_id', false, 32);
	$nl = in_list('nodes') ?? ($one !== null && $one !== '' ? array($one) : (hc2_check_nodes($c) ?: array()));
	$locs = in_list('locations') ?? array_filter(explode(',', $c['locations']));
	if ($c['execution'] === $to && ($to === 'online' || hc2_same_list($nl, hc2_check_nodes($c))) && ($to === 'local' || implode(',', $locs) === $c['locations'])) { fail(409, 'unchanged', 'The check already runs this way.'); }
	$r = hc2_testrun_create(uid(), $c, $to, $nl, array_values($locs));
	if ($r['error'] !== '') { fail(422, 'move_rejected', $r['error']); }
	ok(hc2_testrun_out(hc2_testrun_status(uid(), $r['id'])), 202);
});
route('GET', '/hc2/testruns/{id}', function($p) {
	$t = hc2_testrun_status(uid(), (int)$p['id']);
	if ($t['status'] === 'missing') { fail(404, 'not_found', 'Test run not found.'); }
	ok(hc2_testrun_out($t));
});

route('GET', '/hc2/checks/{token}/measurements', function($p) {
	$c = hc2_find($p['token']); $nodes = hc2_nodes(uid());
	$limit = qp_int('limit', 200, 1, 5000);
	$sql = "SELECT source, node_seq, time, status, latency_ms, reason, message, family, details FROM hc2_measurements WHERE token = :t"; $pa = array('t' => $c['token']);
	if (($s = qp('since')) !== null && $s !== '') { $sql .= " AND time >= :s"; $pa['s'] = hc2_dbtime($s); }
	if (($u = qp('until')) !== null && $u !== '') { $sql .= " AND time < :u"; $pa['u'] = hc2_dbtime($u); }
	if (($src = qp('source')) !== null) { $sql .= " AND source = :src"; $pa['src'] = $src; }
	$st = hc2_pdo()->prepare("$sql ORDER BY time DESC LIMIT $limit"); $st->execute($pa);
	ok(array_map(fn($m) => array('time' => hc2_iso($m['time']), 'source' => $m['source'], 'source_label' => hc2_source_label($m['source'], $nodes), 'status' => (int)$m['status'] === 1 ? 'up' : 'down',
		'latency_ms' => (float)$m['latency_ms'], 'reason' => $m['reason'], 'message' => $m['message'], 'family' => $m['family'], 'details' => $m['details'] !== null ? json_decode($m['details']) : null), $st->fetchAll(PDO::FETCH_ASSOC)),
		200, array('limit' => $limit));
});

route('GET', '/hc2/checks/{token}/events', function($p) {
	$c = hc2_find($p['token']); $nodes = hc2_nodes(uid());
	[$rows, $meta] = hc2_paged("SELECT * FROM hc2_events WHERE token = :t AND userid = :u", array('t' => $c['token'], 'u' => uid()));
	ok(array_map(fn($e) => hc2_event_out($e, $nodes), $rows), 200, $meta);
});
route('GET', '/hc2/events', function() {
	$nodes = hc2_nodes(uid());
	[$rows, $meta] = hc2_paged("SELECT * FROM hc2_events WHERE userid = :u", array('u' => uid()));
	ok(array_map(fn($e) => hc2_event_out($e, $nodes), $rows), 200, $meta);
});
route('GET', '/hc2/checks/{token}/incidents', function($p) {
	$c = hc2_find($p['token']); $nodes = hc2_nodes(uid()); $names = array($c['token'] => $c['name']);
	$limit = qp_int('limit', 50, 1, 500);
	$st = hc2_pdo()->prepare("SELECT * FROM hc2_incidents WHERE token = :t AND userid = :u ORDER BY id DESC LIMIT $limit"); $st->execute(array('t' => $c['token'], 'u' => uid()));
	ok(array_map(fn($i) => hc2_incident_out($i, $nodes, $names), $st->fetchAll(PDO::FETCH_ASSOC)));
});
route('GET', '/hc2/incidents', function() {
	$nodes = hc2_nodes(uid()); $names = array(); foreach (hc2_checks(uid()) as $c) { $names[$c['token']] = $c['name']; }
	$limit = qp_int('limit', 100, 1, 1000); $sql = "SELECT * FROM hc2_incidents WHERE userid = :u"; $pa = array('u' => uid());
	if (qp('open') === 'true' || qp('open') === '1') { $sql .= " AND ended_at IS NULL"; }
	if (($s = qp('since')) !== null && $s !== '') { $sql .= " AND started_at >= :s"; $pa['s'] = hc2_dbtime($s); }
	$st = hc2_pdo()->prepare("$sql ORDER BY id DESC LIMIT $limit"); $st->execute($pa);
	ok(array_map(fn($i) => hc2_incident_out($i, $nodes, $names), $st->fetchAll(PDO::FETCH_ASSOC)));
});

route('GET', '/hc2/checks/{token}/stats', function($p) {
	$c = hc2_find($p['token']); $nodes = hc2_nodes(uid());
	$ranges = array('24h' => array('hc2_hourly', 'hour', 24, 'HOUR'), '7d' => array('hc2_hourly', 'hour', 168, 'HOUR'), '30d' => array('hc2_daily', 'day', 30, 'DAY'), '1y' => array('hc2_daily', 'day', 365, 'DAY'));
	$range = qp('range', '24h');
	if (!isset($ranges[$range])) { fail(400, 'invalid_parameter', 'range must be one of ' . implode(', ', array_keys($ranges)) . '.'); }
	[$tbl, $col, $span, $unit] = $ranges[$range];
	$pdo = hc2_pdo();
	$st = $pdo->prepare("SELECT source, SUM(count) n, SUM(up_count) up, MIN(min_ms) mn, SUM(avg_ms * count) / NULLIF(SUM(count), 0) av, MAX(max_ms) mx FROM $tbl WHERE token = :t AND $col >= UTC_TIMESTAMP() - INTERVAL $span $unit GROUP BY source"); $st->execute(array('t' => $c['token']));
	$bySource = array(); $tn = 0; $tu = 0;
	foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $r) { $tn += (int)$r['n']; $tu += (int)$r['up']; $bySource[] = array('source' => $r['source'], 'label' => hc2_source_label($r['source'], $nodes), 'measurements' => (int)$r['n'],
		'availability_percent' => (int)$r['n'] > 0 ? round(100 * (int)$r['up'] / (int)$r['n'], 3) : null, 'latency_ms' => array('min' => $r['mn'] !== null ? (float)$r['mn'] : null, 'avg' => $r['av'] !== null ? round((float)$r['av'], 2) : null, 'max' => $r['mx'] !== null ? (float)$r['mx'] : null)); }
	$st = $pdo->prepare("SELECT source, $col ts, count, up_count, avg_ms, max_ms FROM $tbl WHERE token = :t AND $col >= UTC_TIMESTAMP() - INTERVAL $span $unit ORDER BY $col"); $st->execute(array('t' => $c['token']));
	$series = array_map(fn($s) => array('time' => hc2_iso($s['ts']), 'source' => $s['source'], 'measurements' => (int)$s['count'], 'availability_percent' => (int)$s['count'] > 0 ? round(100 * (int)$s['up_count'] / (int)$s['count'], 2) : null,
		'latency_avg_ms' => $s['avg_ms'] !== null ? round((float)$s['avg_ms'], 2) : null, 'latency_max_ms' => $s['max_ms'] !== null ? (float)$s['max_ms'] : null), $st->fetchAll(PDO::FETCH_ASSOC));
	ok(array('range' => $range, 'bucket' => $unit === 'HOUR' ? 'hour' : 'day', 'measurements' => $tn, 'availability_percent' => $tn > 0 ? round(100 * $tu / $tn, 3) : null, 'sources' => $bySource, 'series' => $series));
});

// ---------------------------------------------------------------- Kanaele

route('GET', '/hc2/channel-types', function() {
	$out = array();
	foreach (hc2_channel_types() as $k => $t) { $out[] = array('type' => $k, 'label' => $t['label'], 'needs_verification' => !empty($t['verify']), 'fields' => array_map(fn($f) => array('key' => $f['key'], 'label' => $f['label'], 'kind' => $f['kind'] ?? 'text', 'required' => !empty($f['required']), 'secret' => !empty($f['secret']), 'options' => $f['options'] ?? null, 'default' => $f['default'] ?? null), $t['fields'])); }
	ok($out);
});
route('GET', '/hc2/channels', function() { ok(array_map('hc2_channel_out', hc2_channels(uid()))); });
route('GET', '/hc2/channels/{id}', function($p) { $ch = hc2_channel(uid(), (int)$p['id']); if (!$ch) { fail(404, 'not_found', 'Channel not found.'); } ok(hc2_channel_out($ch)); });

function hc2_channel_save(?array $old): array {
	$b = body(); $types = hc2_channel_types(); $acc = hc2_account(uid());
	$type = $old ? $old['type'] : (string)($b['type'] ?? '');
	if (!isset($types[$type])) { fail(422, 'invalid_type', 'type must be one of ' . implode(', ', array_keys($types)) . '.', array('field' => 'type')); }
	$name = in_str('name', !$old, 100) ?? $old['name'];
	$in = array(); foreach ((array)($b['config'] ?? array()) as $k => $v) { $in['f_' . $k] = is_bool($v) ? ($v ? '1' : '') : (string)$v; }
	if ($old) { foreach ($old['config'] as $k => $v) { if (!array_key_exists('f_' . $k, $in) && !in_array($k, $old['has_secret'], true)) { $in['f_' . $k] = $v === 'true' ? '1' : $v; } } }
	$cfg = hc2_channel_config($type, $in, $old);
	if ($cfg['errors']) { fail(422, 'invalid_channel', implode(' ', $cfg['errors']), array('errors' => $cfg['errors'])); }
	$lang = in_str('lang', false, 2) ?? ($old['lang'] ?? 'de'); if ($lang !== 'en') { $lang = 'de'; }
	$p = array('u' => uid(), 'n' => $name, 'c' => $cfg['config_enc'], 'e' => in_bool('enabled', $old ? (int)$old['enabled'] === 1 : true) ? 1 : 0, 'd' => in_bool('default', $old ? (int)$old['is_default'] === 1 : false) ? 1 : 0, 'l' => $lang,
		'nd' => in_bool('notify_down', $old ? (int)$old['notify_down'] === 1 : true) ? 1 : 0, 'nu' => in_bool('notify_up', $old ? (int)$old['notify_up'] === 1 : true) ? 1 : 0);
	$needsVerify = !empty($types[$type]['verify']); $pdo = hc2_pdo();
	if ($old) {
		$p['i'] = (int)$old['id']; $changed = $needsVerify && $cfg['config_enc'] !== $old['config_enc'];
		$pdo->prepare("UPDATE hc2_channels SET name = :n, config_enc = :c, enabled = :e, is_default = :d, lang = :l, notify_down = :nd, notify_up = :nu" . ($changed ? ", verified = 0" : "") . " WHERE id = :i AND userid = :u AND deleted_at IS NULL")->execute($p);
		$id = (int)$old['id'];
	} else {
		$p['t'] = $type; $p['v'] = $needsVerify ? 0 : 1;
		$pdo->prepare("INSERT INTO hc2_channels (userid, type, name, config_enc, enabled, is_default, lang, notify_down, notify_up, verified, created_at, updated_at) VALUES (:u, :t, :n, :c, :e, :d, :l, :nd, :nu, :v, UTC_TIMESTAMP(3), UTC_TIMESTAMP(3))")->execute($p);
		$id = (int)$pdo->lastInsertId();
	}
	hc2_log_change(uid(), 'channel', (string)$id, 'upsert', 'api');
	return hc2_channel(uid(), $id);
}
route('POST', '/hc2/channels', function() { $ch = hc2_channel_save(null); ok(hc2_channel_out($ch) + array('verification_required' => (int)$ch['verified'] !== 1, 'detail' => (int)$ch['verified'] !== 1 ? 'Confirm the channel with the code in the portal (notifications page) before it is used.' : null), 201); });
route('PATCH', '/hc2/channels/{id}', function($p) {
	$old = hc2_channel(uid(), (int)$p['id'], true); if (!$old) { fail(404, 'not_found', 'Channel not found.'); }
	if ($old['node_id']) {
		// Kanal einer Node: Name und Schalter auch hier, die Zugangsdaten nur in der Node
		if (array_key_exists('config', body())) { fail(409, 'node_channel', 'The configuration of a node channel is edited in the node.'); }
		$lang = in_str('lang', false, 2) ?? $old['lang']; if ($lang !== 'en') { $lang = 'de'; }
		hc2_pdo()->prepare("UPDATE hc2_channels SET name = :n, enabled = :e, is_default = :d, lang = :l, notify_down = :nd, notify_up = :nu WHERE id = :i AND userid = :u AND deleted_at IS NULL")->execute(array('u' => uid(), 'i' => (int)$old['id'],
			'n' => in_str('name', false, 100) ?? $old['name'], 'e' => in_bool('enabled', (int)$old['enabled'] === 1) ? 1 : 0, 'd' => in_bool('default', (int)$old['is_default'] === 1) ? 1 : 0, 'l' => $lang,
			'nd' => in_bool('notify_down', (int)$old['notify_down'] === 1) ? 1 : 0, 'nu' => in_bool('notify_up', (int)$old['notify_up'] === 1) ? 1 : 0));
		hc2_log_change(uid(), 'channel', (string)$old['id'], 'upsert', 'api');
		ok(hc2_channel_out(hc2_channel(uid(), (int)$old['id'])));
	}
	ok(hc2_channel_out(hc2_channel_save($old)));
});
route('DELETE', '/hc2/channels/{id}', function($p) {
	$ch = hc2_channel(uid(), (int)$p['id']); if (!$ch) { fail(404, 'not_found', 'Channel not found.'); }
	hc2_log_change(uid(), 'channel', (string)$ch['id'], 'delete', 'api');
	foreach (hc2_checks(uid()) as $c) { $ids = hc2_check_channels($c); if (in_array((int)$ch['id'], $ids, true)) { hc2_set_check(uid(), $c['token'], array('channels' => implode(',', array_diff($ids, array((int)$ch['id']))))); } }
	no_content();
});
// Direkter Versand ueber einen ipv64-Kanal (Mail, SMS, App) ohne hub, z. B. fuer DynDNS-Meldungen einer Node.
// Empfaenger nur aus dem verifizierten Kanal; Tageslimit SMS wie beim hub (hc2_sms_counter), Rate-Limit je Account,
// doppelte event_id innerhalb von 24 h wird nicht erneut verschickt.
const HC2_API_SEND_TYPES = array('ipv64_mail' => 'mail', 'ipv64_sms' => 'sms', 'app' => 'app');
const HC2_API_SEND_PER_DAY = 200;
/** SMS heute noch uebrig; null = unbegrenzt (user_class.sms_limit 0 wie in api_v2.php, z. B. Business/Company). */
function hc2_sms_left(int $userid): ?int {
	$limit = hc2_account($userid)['sms_limit'];
	if ($limit <= 0) { return null; }
	$st = hc2_pdo()->prepare("SELECT count FROM hc2_sms_counter WHERE userid = :u AND day = UTC_DATE()"); $st->execute(array('u' => $userid));
	return max(0, $limit - (int)$st->fetchColumn());
}
route('POST', '/hc2/channels/{id}/send', function($p) {
	global $pdo;
	require_once __DIR__ . '/hc2_send_lib.php';
	$ch = hc2_channel(uid(), (int)$p['id'], true); if (!$ch) { fail(404, 'not_found', 'Channel not found.'); }
	if ($ch['node_id'] || !array_key_exists($ch['type'], HC2_API_SEND_TYPES)) { fail(422, 'not_server_channel', 'Only ipv64 channels (ipv64_mail, ipv64_sms, app) can send via the API.'); }
	if (!(int)$ch['verified']) { fail(409, 'not_verified', 'Confirm the channel in the portal first.'); }
	if (!(int)$ch['enabled']) { fail(409, 'disabled', 'The channel is disabled.'); }
	$subject = trim(in_str('subject', true, 200)); $text = trim(in_str('text', true, 4000));
	$kind = (string)(in_str('kind', false, 40) ?? ''); $event = trim((string)(in_str('event_id', false, 100) ?? '')); $source = (string)(in_str('source', false, 60) ?? 'api');
	$type = HC2_API_SEND_TYPES[$ch['type']]; $db = hc2_pdo(); $cid = (int)$ch['id'];
	if ($event !== '') {
		$st = $db->prepare("SELECT 1 FROM hc2_api_sends WHERE userid = :u AND channel_id = :c AND event_id = :e AND ok = 1 AND sent_at > UTC_TIMESTAMP(3) - INTERVAL 1 DAY");
		$st->execute(array('u' => uid(), 'c' => $cid, 'e' => $event));
		if ($st->fetchColumn()) { ok(array('sent' => false, 'duplicate' => true, 'sms_left' => $type === 'sms' ? hc2_sms_left(uid()) : null)); }
	}
	rl_enforce('hc2send:' . uid(), 30, 30 / 3600, 'notifications'); // 30 auf einmal, danach 30 je Stunde
	$st = $db->prepare("SELECT COUNT(*) FROM hc2_api_sends WHERE userid = :u AND sent_at >= UTC_DATE()"); $st->execute(array('u' => uid()));
	if ((int)$st->fetchColumn() >= HC2_API_SEND_PER_DAY) { fail(429, 'rate_limited', 'Daily limit of ' . HC2_API_SEND_PER_DAY . ' notifications via the API reached.'); }
	$updown = preg_match('/fail|down|error|limit/', strtolower($kind)) ? '0' : (preg_match('/(^|_)(up|ok|recovered)$/', strtolower($kind)) ? '1' : '');
	$html = ''; $msg = $text;
	switch ($type) {
		case 'mail':
			$to = trim((string)($ch['config']['email'] ?? ''));
			$brand = stripos($source, 'node64') === 0 ? 'IPv64.net Node64' : 'IPv64.net';
			$html = hc2_mail_html($subject, $text, $kind, (string)$ch['lang'], $brand);
			break;
		case 'sms':
			$to = hc2_sms_number((string)($ch['config']['number'] ?? ''));
			if ($to === '') { fail(422, 'invalid_number', 'The SMS channel has no valid number.'); }
			$limit = hc2_account(uid())['sms_limit'];
			$db->prepare("INSERT INTO hc2_sms_counter (userid, day, count) VALUES (:u, UTC_DATE(), 0) ON DUPLICATE KEY UPDATE count = count")->execute(array('u' => uid()));
			$st = $db->prepare("UPDATE hc2_sms_counter SET count = count + 1 WHERE userid = :u AND day = UTC_DATE()" . ($limit > 0 ? " AND count < :l" : ""));
			$st->execute($limit > 0 ? array('u' => uid(), 'l' => $limit) : array('u' => uid()));
			if ($st->rowCount() !== 1) { fail(429, 'sms_limit', 'Daily SMS limit reached.'); }
			$lines = preg_split('/\r?\n/', $text);
			$msg = preg_replace('/\s+/u', ' ', preg_replace('/[\x{1F000}-\x{1FFFF}\x{2600}-\x{27BF}\x{FE0F}\x{200D}]/u', '', $subject . (isset($lines[0]) && $lines[0] !== '' ? ' - ' . $lines[0] : '')));
			$msg = mb_substr(trim($msg), 0, 300);
			break;
		default:
			$to = trim((string)($ch['config']['device_token'] ?? ''));
			$msg = $subject;
	}
	if ($to === '') { fail(422, 'invalid_channel', 'The channel has no recipient.'); }
	try { $err = hc2_deliver($pdo, $type, $to, $subject, $msg, $html, $updown, uid()); }
	catch (Throwable $e) { error_log('api hc2 send: ' . $e->getMessage()); $err = 'send failed'; }
	$db->prepare("INSERT INTO hc2_api_sends (userid, channel_id, event_id, kind, source, sent_at, ok, error) VALUES (:u, :c, :e, :k, :s, UTC_TIMESTAMP(3), :o, :x)")
		->execute(array('u' => uid(), 'c' => $cid, 'e' => $event !== '' ? $event : null, 'k' => $kind, 's' => $source, 'o' => $err === '' ? 1 : 0, 'x' => $err));
	$db->prepare("UPDATE hc2_channels SET last_used = UTC_TIMESTAMP(3), last_error = :x WHERE id = :c AND userid = :u")->execute(array('x' => $err, 'c' => $cid, 'u' => uid()));
	if (mt_rand(1, 100) === 1) { $db->exec("DELETE FROM hc2_api_sends WHERE sent_at < UTC_TIMESTAMP() - INTERVAL 35 DAY"); }
	if ($err !== '') { fail(502, 'delivery_failed', $err); }
	ok(array('sent' => true, 'duplicate' => false, 'sms_left' => $type === 'sms' ? hc2_sms_left(uid()) : null));
});

// Bestaetigung von E-Mail-/SMS-Kanaelen per Code (wie die Benachrichtigungsseite des Portals), z. B. aus Node64.
route('POST', '/hc2/channels/{id}/verify/send', function($p) {
	$ch = hc2_channel(uid(), (int)$p['id']); if (!$ch) { fail(404, 'not_found', 'Channel not found.'); }
	if ((int)$ch['verified'] === 1) { ok(array('sent' => false, 'verified' => true)); }
	rl_enforce('hc2verify:' . uid(), 5, 5 / 3600, 'verification codes');
	$code = (string)random_int(100000, 999999);
	hc2_pdo()->prepare("UPDATE hc2_channels SET verify_key = :k, verify_expires = UTC_TIMESTAMP(3) + INTERVAL 15 MINUTE WHERE id = :i AND userid = :u")->execute(array('k' => $code, 'i' => (int)$ch['id'], 'u' => uid()));
	$r = hc2_hub_call('/v1/portal/channel-test', array('userid' => uid(), 'channel_id' => (int)$ch['id'], 'kind' => 'verify', 'code' => $code, 'lang' => $ch['lang']));
	if (empty($r['ok'])) { fail(502, 'delivery_failed', (string)($r['error'] ?? 'unknown error')); }
	ok(array('sent' => true, 'verified' => false, 'expires_in_seconds' => 900));
});
route('POST', '/hc2/channels/{id}/verify', function($p) {
	$ch = hc2_channel(uid(), (int)$p['id']); if (!$ch) { fail(404, 'not_found', 'Channel not found.'); }
	if ((int)$ch['verified'] === 1) { ok(hc2_channel_out($ch)); }
	rl_enforce('hc2verifycheck:' . uid(), 10, 10 / 3600, 'verification attempts');
	$code = preg_replace('/[^0-9]/', '', (string)(in_str('code', true, 12) ?? ''));
	$st = hc2_pdo()->prepare("SELECT verify_key, verify_expires FROM hc2_channels WHERE id = :i AND userid = :u AND deleted_at IS NULL"); $st->execute(array('i' => (int)$ch['id'], 'u' => uid())); $row = $st->fetch(PDO::FETCH_ASSOC);
	if (!$row || !$row['verify_key'] || $code === '' || !hash_equals((string)$row['verify_key'], $code) || $row['verify_expires'] <= gmdate('Y-m-d H:i:s')) { fail(422, 'invalid_code', 'Code wrong or expired.'); }
	hc2_pdo()->prepare("UPDATE hc2_channels SET verified = 1, verify_key = NULL, verify_expires = NULL WHERE id = :i")->execute(array('i' => (int)$ch['id']));
	hc2_log_change(uid(), 'channel', (string)$ch['id'], 'upsert', 'api');
	ok(hc2_channel_out(hc2_channel(uid(), (int)$ch['id'])));
});
route('POST', '/hc2/channels/{id}/test', function($p) {
	$ch = hc2_channel(uid(), (int)$p['id']); if (!$ch) { fail(404, 'not_found', 'Channel not found.'); }
	if (!(int)$ch['verified']) { fail(409, 'not_verified', 'Confirm the channel in the portal first.'); }
	rl_enforce('hc2test:' . uid() . ':' . $ch['id'], RL_TEST_CAPACITY, RL_TEST_REFILL, 'test notifications');
	$r = hc2_hub_call('/v1/portal/channel-test', array('userid' => uid(), 'channel_id' => (int)$ch['id'], 'kind' => 'test', 'lang' => $ch['lang']));
	if (empty($r['ok'])) { fail(502, 'delivery_failed', (string)($r['error'] ?? 'unknown error')); }
	ok(array('sent' => true, 'queued_at_node' => !empty($r['queued'])));
});

// ---------------------------------------------------------------- Wartungsfenster

function hc2_find_maint(int $id): array {
	$st = hc2_pdo()->prepare("SELECT * FROM hc2_maintenance WHERE id = :i AND userid = :u AND deleted_at IS NULL"); $st->execute(array('i' => $id, 'u' => uid()));
	$m = $st->fetch(PDO::FETCH_ASSOC); if (!$m) { fail(404, 'not_found', 'Maintenance window not found.'); }
	return $m;
}
function hc2_maint_save(?array $old): array {
	$name = in_str('name', !$old, 200) ?? $old['name'];
	$start = has('start_at') ? hc2_dbtime(in_str('start_at', true, 40)) : ($old['start_at'] ?? null);
	$end = has('end_at') ? hc2_dbtime(in_str('end_at', true, 40)) : ($old['end_at'] ?? null);
	if (!$start || !$end) { fail(422, 'invalid_window', 'start_at and end_at are required.'); }
	if ($end <= $start) { fail(422, 'invalid_window', 'end_at must be after start_at.'); }
	$repeat = in_str('repeat', false, 10) ?? ($old['repeat'] ?? 'none');
	if (!in_array($repeat, array('none', 'daily', 'weekly', 'monthly'), true)) { fail(422, 'invalid_repeat', 'repeat must be none, daily, weekly or monthly.', array('field' => 'repeat')); }
	$until = has('repeat_until') ? (in_str('repeat_until', false, 40) ? hc2_dbtime(in_str('repeat_until', false, 40)) : null) : ($old['repeat_until'] ?? null);
	$tokens = has('tokens') ? (in_list('tokens') ?? array()) : array_filter(explode(',', (string)($old['tokens'] ?? '')));
	foreach ($tokens as $t) { hc2_find((string)$t); }
	$active = in_bool('active', $old ? (int)$old['active'] === 1 : true) ? 1 : 0;
	$p = array('u' => uid(), 'n' => $name, 's' => $start, 'e' => $end, 'r' => $repeat, 'ru' => $until, 't' => $tokens ? implode(',', $tokens) : null, 'a' => $active); $pdo = hc2_pdo();
	if ($old) { $p['i'] = (int)$old['id']; $pdo->prepare("UPDATE hc2_maintenance SET name = :n, start_at = :s, end_at = :e, `repeat` = :r, repeat_until = :ru, tokens = :t, active = :a WHERE id = :i AND userid = :u AND deleted_at IS NULL")->execute($p); $id = (int)$old['id']; }
	else { $pdo->prepare("INSERT INTO hc2_maintenance (userid, name, start_at, end_at, `repeat`, repeat_until, tokens, active, created_at, updated_at) VALUES (:u, :n, :s, :e, :r, :ru, :t, :a, UTC_TIMESTAMP(3), UTC_TIMESTAMP(3))")->execute($p); $id = (int)$pdo->lastInsertId(); }
	hc2_log_change(uid(), 'maintenance', (string)$id, 'upsert', 'api');
	return hc2_find_maint($id);
}
route('GET', '/hc2/maintenance', function() { $st = hc2_pdo()->prepare("SELECT * FROM hc2_maintenance WHERE userid = :u AND deleted_at IS NULL ORDER BY start_at DESC"); $st->execute(array('u' => uid())); ok(array_map('hc2_maint_out', $st->fetchAll(PDO::FETCH_ASSOC))); });
route('POST', '/hc2/maintenance', function() { ok(hc2_maint_out(hc2_maint_save(null)), 201); });
route('GET', '/hc2/maintenance/{id}', function($p) { ok(hc2_maint_out(hc2_find_maint((int)$p['id']))); });
route('PATCH', '/hc2/maintenance/{id}', function($p) { ok(hc2_maint_out(hc2_maint_save(hc2_find_maint((int)$p['id'])))); });
route('DELETE', '/hc2/maintenance/{id}', function($p) { $m = hc2_find_maint((int)$p['id']); hc2_log_change(uid(), 'maintenance', (string)$m['id'], 'delete', 'api'); no_content(); });

// ---------------------------------------------------------------- Nodes

route('GET', '/hc2/nodes', function() { ok(array_values(array_map(fn($n) => hc2_node_out($n), hc2_nodes(uid())))); });
route('GET', '/hc2/nodes/{node_id}', function($p) { ok(hc2_node_out(hc2_find_node($p['node_id']), true)); });
route('PATCH', '/hc2/nodes/{node_id}', function($p) {
	$n = hc2_find_node($p['node_id']);
	$name = in_str('name', false, 100) ?? $n['name']; $loc = in_str('location', false, 100) ?? $n['location']; $rm = in_str('remote_mgmt', false, 10) ?? $n['remote_mgmt'];
	if (!in_array($rm, array('off', 'read', 'full'), true)) { fail(422, 'invalid_remote_mgmt', 'remote_mgmt must be off, read or full.', array('field' => 'remote_mgmt')); }
	if ($name === '') { fail(422, 'invalid_name', 'name must not be empty.', array('field' => 'name')); }
	hc2_pdo()->prepare("UPDATE hc2_nodes SET name = :na, location = :l, remote_mgmt = :r WHERE node_id = :n AND userid = :u")->execute(array('na' => $name, 'l' => $loc, 'r' => $rm, 'n' => $n['node_id'], 'u' => uid()));
	hc2_log_change(uid(), 'node', $n['node_id'], 'upsert', 'api');
	ok(hc2_node_out(hc2_find_node($n['node_id'])));
});
route('POST', '/hc2/nodes/{node_id}/commands', function($p) {
	$n = hc2_find_node($p['node_id']);
	$name = in_str('name', true, 32);
	if (!in_array($name, array('run_check', 'repair', 'pause', 'resume', 'resolve_conflict'), true)) { fail(422, 'invalid_command', 'name must be run_check, repair, pause, resume or resolve_conflict.', array('field' => 'name')); }
	$args = (array)(body()['args'] ?? array());
	if (in_array($name, array('run_check', 'pause', 'resume'), true)) { $c = hc2_find((string)($args['token'] ?? '')); $args = array('token' => $c['token']); }
	if ($name === 'resolve_conflict') { $args = array('id' => (int)($args['id'] ?? 0), 'keep' => ($args['keep'] ?? 'server') === 'local' ? 'local' : 'server'); }
	if ($name === 'repair') { $args = array(); }
	$id = hc2_command($n['node_id'], $name, $args);
	ok(array('command_id' => $id, 'node_id' => $n['node_id'], 'name' => $name, 'args' => $args ?: new stdClass()), 202);
});
route('GET', '/hc2/nodes/{node_id}/commands', function($p) {
	$n = hc2_find_node($p['node_id']); $limit = qp_int('limit', 20, 1, 200);
	$st = hc2_pdo()->prepare("SELECT * FROM hc2_commands WHERE node_id = :n ORDER BY id DESC LIMIT $limit"); $st->execute(array('n' => $n['node_id']));
	ok(array_map(fn($c) => array('command_id' => (int)$c['id'], 'name' => $c['name'], 'args' => json_decode((string)$c['args']), 'created_at' => hc2_iso($c['created_at']), 'done_at' => hc2_iso($c['done_at']),
		'ok' => $c['ok'] === null ? null : (int)$c['ok'] === 1, 'output' => ($c['output'] !== null && ($j = json_decode((string)$c['output'])) !== null) ? $j : $c['output']), $st->fetchAll(PDO::FETCH_ASSOC)));
});
/** Verknuepfung per Code (wie link.php) */
route('POST', '/hc2/nodes/link', function() {
	$code = strtoupper(preg_replace('/[^A-Za-z0-9]/', '', in_str('code', true, 9)));
	if (strlen($code) !== 8) { fail(422, 'invalid_code', 'The code has 8 characters.', array('field' => 'code')); }
	$loc = in_str('location', false, 100) ?? ''; $rm = in_str('remote_mgmt', false, 10) ?? 'full';
	if (!in_array($rm, array('off', 'read', 'full'), true)) { fail(422, 'invalid_remote_mgmt', 'remote_mgmt must be off, read or full.', array('field' => 'remote_mgmt')); }
	$st = hc2_pdo()->prepare("UPDATE hc2_link_codes SET userid = :u, location = :l, remote_mgmt = :r WHERE code = :c AND userid IS NULL AND consumed_at IS NULL AND expires_at > UTC_TIMESTAMP(3)");
	$st->execute(array('u' => uid(), 'l' => $loc, 'r' => $rm, 'c' => $code));
	if ($st->rowCount() !== 1) { fail(404, 'code_unknown', 'Code unknown, expired or already used. Request a new one in the node.'); }
	ok(array('accepted' => true, 'detail' => 'The node fetches its token itself within about 10 seconds.'), 202);
});
route('DELETE', '/hc2/nodes/{node_id}', function($p) {
	$n = hc2_find_node($p['node_id']); $keep = in_bool('keep_checks', true); $pdo = hc2_pdo();
	$pdo->prepare("UPDATE hc2_node_tokens SET revoked_at = UTC_TIMESTAMP(3) WHERE node_id = :n AND revoked_at IS NULL")->execute(array('n' => $n['node_id']));
	$pdo->prepare("UPDATE hc2_nodes SET revoked_at = UTC_TIMESTAMP(3), online = 0 WHERE node_id = :n")->execute(array('n' => $n['node_id']));
	hc2_log_change(uid(), 'node', $n['node_id'], 'delete', 'api'); hc2_signal('hc2:node:' . $n['node_id'], 'revoke');
	$st = $pdo->prepare("SELECT * FROM hc2_checks WHERE (node_id = :n OR FIND_IN_SET(:n2, nodes) > 0) AND userid = :u AND deleted_at IS NULL AND execution IN ('local','both')"); $st->execute(array('n' => $n['node_id'], 'n2' => $n['node_id'], 'u' => uid()));
	$kept = 0; $dropped = 0; $acc = hc2_account(uid());
	foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $c) {
		$rest = array_values(array_diff(hc2_check_nodes($c), array($n['node_id'])));
		if ($rest) { hc2_set_check(uid(), $c['token'], array('nodes' => implode(',', $rest), 'node_id' => (string)$c['node_id'] === $n['node_id'] ? $rest[0] : $c['node_id'])); continue; }
		$locs = array_filter(explode(',', $c['locations'])) ?: array_keys(hc2_locations());
		$fits = $keep && !hc2_private_target($c['type'], $c['target']) && ($acc['healthcheck_limit'] <= 0 || hc2_online_used(uid(), $c['token']) + count($locs) <= $acc['healthcheck_limit']);
		if ($fits) { hc2_set_check(uid(), $c['token'], array('execution' => 'online', 'node_id' => null, 'nodes' => '')); $kept++; } else { hc2_delete_check(uid(), $c['token']); $dropped++; }
	}
	ok(array('unlinked' => true, 'checks_kept_online' => $kept, 'checks_deleted' => $dropped));
});

// ---------------------------------------------------------------- Node64: eine Liste aller Nodes (nodes.php)
// Tabelle node64_nodes in der Hauptdatenbank (deploy/sql/node64_nodes.sql), Zeiten UTC. Die Node meldet sich beim Start,
// alle 15 Minuten und nach Aenderungen (POST /node64/hello); jede Anfrage mit X-Node64-Node frischt last_seen auf.

/** Kennung einer Node (node.id: 32 Zeichen base64url; Modus ohne Oberflaeche: Sensor-UUID), sonst ''. */
function n64_id($v, int $max = 64): string { $v = is_string($v) ? $v : ''; return preg_match('/^[A-Za-z0-9_-]{8,' . $max . '}$/', $v) ? $v : ''; }
/** Freitext kuerzen; 4-Byte-Zeichen ersetzen (Verbindung laeuft mit SET NAMES 'utf8'). */
function n64_text($v, int $max): string { return mb_substr(trim((string)preg_replace('/[\x{10000}-\x{10FFFF}]/u', "\u{FFFD}", is_scalar($v) ? (string)$v : '')), 0, $max); }
function n64_out(array $n, array $hubs): array {
	$h = $hubs[$n['hub_node_id'] !== '' ? $n['hub_node_id'] : $n['node_id']] ?? null;
	return array('node_id' => $n['node_id'], 'name' => $n['name'], 'location' => $n['location'], 'version' => $n['version'], 'os_arch' => $n['os_arch'], 'mode' => $n['mode'] !== '' ? $n['mode'] : 'full',
		'modules' => array_values(array_filter(explode(',', (string)$n['modules']))),
		'features' => array('hc_sync_linked' => (int)$n['hc_linked'] === 1, 'hub_node_id' => $n['hub_node_id'] !== '' ? $n['hub_node_id'] : null, 'honeypot_sensor_id' => $n['sensor_id'] !== '' ? $n['sensor_id'] : null,
			'cdn64_tunnel' => $n['tunnel_id'] !== '' ? $n['tunnel_id'] : null, 'dyndns' => (int)$n['dyndns'] === 1),
		'healthchecks' => $h ? array('online' => (int)$h['online'] === 1, 'last_sync' => hc2_iso($h['last_sync'])) : null,
		'first_seen' => hc2_iso($n['first_seen']), 'last_seen' => hc2_iso($n['last_seen']), 'removed' => $n['removed_at'] !== null, 'removed_at' => hc2_iso($n['removed_at']));
}

route('POST', '/node64/hello', function() {
	global $AUTH;
	$b = body(); $u = uid();
	$nid = n64_id($b['node_id'] ?? '');
	if ($nid === '') { fail(422, 'invalid_node_id', 'node_id must have 8 to 64 characters A-Z, a-z, 0-9, _ or -.', array('field' => 'node_id')); }
	$hdr = (string)($_SERVER['HTTP_X_NODE64_NODE'] ?? '');
	if ($hdr !== '' && $hdr !== $nid) { fail(422, 'node_id_mismatch', 'node_id differs from the X-Node64-Node header.', array('field' => 'node_id')); }
	rl_enforce('node64hello:' . $u . ':' . $nid, 10, 1 / 60, 'node hello');
	$f = is_array($b['features'] ?? null) ? $b['features'] : array();
	$mods = array(); foreach ((is_array($b['modules'] ?? null) ? $b['modules'] : array()) as $m) { if (is_string($m) && preg_match('/^[a-z0-9_-]{1,32}$/', $m)) { $mods[$m] = true; } }
	$sensor = strtolower((string)(is_string($f['honeypot_sensor_id'] ?? null) ? $f['honeypot_sensor_id'] : ''));
	// entfernt: diese Node oder ihr Sensor (vor dem ersten hello nur als Sensor bekannt, node_id = Sensor-Kennung)
	if (q1("SELECT node_id FROM node64_nodes WHERE userid = :u AND node_id IN (:n, :s) AND removed_at IS NOT NULL LIMIT 1", array('u' => $u, 'n' => $nid, 's' => $sensor !== '' ? $sensor : $nid)) !== null) {
		fail(403, 'node_removed', 'This node was removed on ipv64.net. Allow it again in the node overview (ipv64.net/nodes.php) and enter the API key in the node again.');
	}
	$tunnel = is_string($f['cdn64_tunnel'] ?? null) && preg_match('/^[A-Za-z0-9_-]{1,24}$/', $f['cdn64_tunnel']) ? $f['cdn64_tunnel'] : '';
	$p = array('u' => $u, 'n' => $nid, 'na' => n64_text($b['name'] ?? '', 100), 'l' => n64_text($b['location'] ?? '', 100), 'v' => n64_text($b['version'] ?? '', 32),
		'o' => n64_text($b['os_arch'] ?? '', 32), 'mo' => ($b['mode'] ?? '') === 'headless' ? 'headless' : '', 'm' => mb_substr(implode(',', array_keys($mods)), 0, 255),
		'hl' => !empty($f['hc_sync_linked']) ? 1 : 0, 'h' => n64_id($f['hub_node_id'] ?? '', 32), 's' => preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $sensor) ? $sensor : '',
		't' => $tunnel, 'd' => !empty($f['dyndns']) ? 1 : 0, 'k' => $AUTH['key_id'] ?? null, 'ip' => client_ip());
	q("INSERT INTO node64_nodes (userid, node_id, name, location, version, os_arch, mode, modules, hc_linked, hub_node_id, sensor_id, tunnel_id, dyndns, api_key_id, first_seen, last_seen, last_hello, last_ip)
		VALUES (:u, :n, :na, :l, :v, :o, :mo, :m, :hl, :h, :s, :t, :d, :k, UTC_TIMESTAMP(), UTC_TIMESTAMP(), UTC_TIMESTAMP(), :ip)
		ON DUPLICATE KEY UPDATE name = VALUES(name), location = VALUES(location), version = VALUES(version), os_arch = VALUES(os_arch), mode = VALUES(mode), modules = VALUES(modules),
		hc_linked = VALUES(hc_linked), hub_node_id = VALUES(hub_node_id), sensor_id = VALUES(sensor_id), tunnel_id = VALUES(tunnel_id), dyndns = VALUES(dyndns), api_key_id = VALUES(api_key_id),
		last_seen = VALUES(last_seen), last_hello = VALUES(last_hello), last_ip = VALUES(last_ip)", $p);
	ok(array('ok' => true, 'removed' => false, 'node_id' => $nid));
});
route('GET', '/node64/nodes', function() {
	$hubs = array();
	try { $hubs = hc2_nodes(uid(), true); } catch (Throwable $e) { error_log('node64/nodes: ' . $e->getMessage()); } // Healthchecks-Datenbank nicht erreichbar: ohne
	ok(array_map(fn($n) => n64_out($n, $hubs), qa("SELECT * FROM node64_nodes WHERE userid = :u ORDER BY removed_at IS NOT NULL, name, node_id", array('u' => uid()))));
});

// Jede Anfrage einer Node (X-Node64-Node) frischt ihr last_seen auf, hoechstens einmal je Minute; nach der Antwort
// und ohne Fehler, falls die Tabelle noch fehlt.
if (!empty($_SERVER['HTTP_X_NODE64_NODE'])) {
	register_shutdown_function(function() {
		global $ME, $pdo;
		$nid = n64_id($_SERVER['HTTP_X_NODE64_NODE'] ?? '');
		if (empty($ME['id']) || $nid === '' || !($pdo instanceof PDO)) { return; }
		try {
			$st = $pdo->prepare("UPDATE node64_nodes SET last_seen = UTC_TIMESTAMP() WHERE userid = :u AND node_id = :n AND removed_at IS NULL AND (last_seen IS NULL OR last_seen < UTC_TIMESTAMP() - INTERVAL 60 SECOND)");
			if ($st) { $st->execute(array('u' => (int)$ME['id'], 'n' => $nid)); }
		} catch (Throwable $e) { error_log('node64 last_seen: ' . $e->getMessage()); }
	});
}
