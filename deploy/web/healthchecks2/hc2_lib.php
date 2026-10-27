<?php
/**
 * Healthchecks 2.0 – gemeinsame Hilfsfunktionen der neuen Portal-Seiten (healthchecks2/*, notifications.php, nodes.php).
 * Voraussetzung: header.php ist eingebunden (Session, $userid, $pdo) und dbconnect.php enthaelt die hc2_*-Grundfunktionen
 * (hc2_pdo, hc2_log_change, hc2_signal, hc2_encrypt, hc2_decrypt). Alle Zeiten in der DB sind UTC.
 * Bewusst ohne Menuelinks: nur wer die URL kennt, findet die Seiten.
 */

defined('HC2_BRIDGE_SECRET_FILE') || define('HC2_BRIDGE_SECRET_FILE', '/var/www/clients/client1/web58/private/hc2_bridge.secret');
defined('HC2_HUBS') || define('HC2_HUBS', 'https://hc-srv01.ipv64.net,https://hc-srv02.ipv64.net');
defined('HC2_BASE') || define('HC2_BASE', '/healthchecks2');

// ---------------------------------------------------------------- Grundlagen

function hc2_h($s): string { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

/** Login erzwingen (wie die alten Seiten: Hinweis statt Umleitung) und CSRF-Token bereitstellen. */
function hc2_require_login(): void {
	global $userid;
	if ($userid == '') {
		echo '<div class="container"><div class="alert alert-warning mt-3">Bitte zuerst anmelden.</div></div>';
		include(__DIR__ . '/../footer.php');
		exit;
	}
	if (empty($_SESSION['hc2_csrf'])) { $_SESSION['hc2_csrf'] = bin2hex(random_bytes(16)); }
}
function hc2_csrf_field(): string { return '<input type="hidden" name="_csrf" value="' . hc2_h($_SESSION['hc2_csrf'] ?? '') . '">'; }
function hc2_csrf_ok(): bool {
	$t = (string)($_POST['_csrf'] ?? $_GET['_csrf'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');
	return !empty($_SESSION['hc2_csrf']) && hash_equals($_SESSION['hc2_csrf'], $t);
}
function hc2_is_post(): bool { return $_SERVER['REQUEST_METHOD'] === 'POST'; }
function hc2_redirect(string $url): void { while (ob_get_level() > 0) { ob_end_clean(); } header('Location: ' . $url); exit; } // Ausgabe aus header.php verwerfen, sonst scheitert die Weiterleitung
function hc2_flash(string $kind, string $msg): void { $_SESSION['hc2_flash'] = array($kind, $msg); }
function hc2_flash_out(): string {
	if (empty($_SESSION['hc2_flash'])) { return ''; }
	[$k, $m] = $_SESSION['hc2_flash']; unset($_SESSION['hc2_flash']);
	return '<div class="alert alert-' . hc2_h($k) . '" role="alert">' . hc2_h($m) . '</div>';
}
function hc2_json(array $out, int $code = 200): void {
	while (ob_get_level() > 0) { ob_end_clean(); } // HTML aus header.php verwerfen
	http_response_code($code);
	header('Content-Type: application/json; charset=utf-8'); header('Cache-Control: no-store');
	echo json_encode($out, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
	exit;
}

/** Zeitzone des Accounts (Einstellungen > Benachrichtigungen), Standard Europe/Berlin. */
function hc2_timezones(): array {
	return array('UTC', 'Europe/Berlin', 'Europe/Vienna', 'Europe/Zurich', 'Europe/Amsterdam', 'Europe/Brussels', 'Europe/Paris', 'Europe/London', 'Europe/Dublin', 'Europe/Madrid',
		'Europe/Rome', 'Europe/Warsaw', 'Europe/Prague', 'Europe/Stockholm', 'Europe/Oslo', 'Europe/Copenhagen', 'Europe/Helsinki', 'Europe/Athens', 'Europe/Istanbul', 'Europe/Moscow',
		'America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles', 'America/Toronto', 'America/Sao_Paulo', 'Asia/Tokyo', 'Asia/Shanghai', 'Asia/Singapore',
		'Asia/Dubai', 'Asia/Kolkata', 'Australia/Sydney', 'Pacific/Auckland');
}
function hc2_tz(): string {
	static $tz = null;
	if ($tz !== null) { return $tz; }
	global $userid;
	$tz = 'Europe/Berlin';
	try {
		if ((int)$userid > 0) { $v = hc2_settings((int)$userid)['notify.quiet_tz'] ?? ''; if (in_array($v, timezone_identifiers_list(), true)) { $tz = $v; } }
	} catch (Throwable $e) { error_log('hc2_tz: ' . $e->getMessage()); }
	return $tz;
}
/** UTC-Zeit aus der DB -> Zeitzone des Accounts, formatiert. */
function hc2_dt($utc, string $fmt = 'd.m.Y H:i:s'): string {
	if (!$utc) { return '–'; }
	try { $t = new DateTime($utc, new DateTimeZone('UTC')); $t->setTimezone(new DateTimeZone(hc2_tz())); return $t->format($fmt); }
	catch (Throwable $e) { return (string)$utc; }
}
function hc2_ago($utc): string {
	if (!$utc) { return '–'; }
	$s = time() - strtotime($utc . ' UTC');
	if ($s < 0) { $s = 0; }
	if ($s < 60) { return $s . ' s'; }
	if ($s < 3600) { return floor($s / 60) . ' min'; }
	if ($s < 86400) { return floor($s / 3600) . ' h ' . floor(($s % 3600) / 60) . ' min'; }
	return floor($s / 86400) . ' d ' . floor(($s % 86400) / 3600) . ' h';
}
function hc2_dur(int $sec): string {
	if ($sec < 60) { return $sec . ' s'; }
	if ($sec < 3600) { return floor($sec / 60) . ' min ' . ($sec % 60) . ' s'; }
	if ($sec < 86400) { return floor($sec / 3600) . ' h ' . floor(($sec % 3600) / 60) . ' min'; }
	return floor($sec / 86400) . ' d ' . floor(($sec % 86400) / 3600) . ' h';
}
function hc2_token(int $len = 32): string {
	$a = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'; $o = '';
	for ($i = 0; $i < $len; $i++) { $o .= $a[random_int(0, strlen($a) - 1)]; }
	return $o;
}
function hc2_slot(string $token): int { return (int)(sprintf('%u', crc32($token)) % 1024); }

// ---------------------------------------------------------------- Account, Nodes, Standorte

/** Account-Klasse und Limits (Sicht ipv64.hc2_users_v, lesbar fuer ipv64_hc). */
function hc2_account(int $userid): array {
	static $cache = array();
	if (isset($cache[$userid])) { return $cache[$userid]; }
	$st = hc2_pdo()->prepare("SELECT v.id, v.email, v.user_class, v.hc2, v.healthcheck_limit, v.hc_locations, v.sms_limit, c.healthcheck_update_limit FROM ipv64.hc2_users_v v LEFT JOIN ipv64.user_class c ON c.id = v.user_class WHERE v.id = :u");
	$st->execute(array('u' => $userid));
	$a = $st->fetch(PDO::FETCH_ASSOC) ?: array('id' => $userid, 'email' => '', 'user_class' => 1, 'hc2' => 0, 'healthcheck_limit' => 0, 'hc_locations' => 1, 'sms_limit' => 0);
	$names = array(1 => 'Standard', 2 => 'VIP', 3 => 'Premium', 4 => 'Business', 5 => 'Company', 6 => 'Supporter');
	$a['class_name'] = $names[(int)$a['user_class']] ?? ('Klasse ' . $a['user_class']);
	$a['healthcheck_limit'] = (int)$a['healthcheck_limit']; $a['hc_locations'] = max(1, (int)$a['hc_locations']); $a['sms_limit'] = (int)$a['sms_limit']; // 0 = unbegrenzt (Business/Company)
	$a['checks_per_day'] = (int)($a['healthcheck_update_limit'] ?? 0); // Tageskontingent Online-Messungen + Pushes, 0 = unbegrenzt
	return $cache[$userid] = $a;
}

/** Online-Messungen und Pushes heute (Tageskontingent, vom hub alle 30 s geschrieben; Tag Europe/Berlin). */
function hc2_checks_today(int $userid): int {
	try {
		$st = hc2_pdo()->prepare("SELECT checks FROM hc2_usage_daily WHERE userid = :u AND day = :d");
		$st->execute(array('u' => $userid, 'd' => (new DateTime('now', new DateTimeZone('Europe/Berlin')))->format('Y-m-d')));
		return (int)$st->fetchColumn();
	} catch (Throwable $e) { return 0; } // Tabelle noch nicht angelegt
}

/** Belegte Online-Messstellen (Check x Standorte), optional ohne einen Token. */
function hc2_online_used(int $userid, string $except = ''): int {
	$st = hc2_pdo()->prepare("SELECT COALESCE(SUM(LENGTH(locations) - LENGTH(REPLACE(locations, ',', '')) + 1), 0) FROM hc2_checks WHERE userid = :u AND deleted_at IS NULL AND execution IN ('online','both') AND token <> :t");
	$st->execute(array('u' => $userid, 't' => $except));
	return (int)$st->fetchColumn();
}

/** Hochrechnung des Tagesverbrauchs (Online-Messungen je Standort) aller aktiven Online-/Hybrid-Checks
 *  ohne $except, wie der hub zaehlt (leere Standorte = beide, bei nur einem Standort je Check hoechstens 1). */
function hc2_daily_projection(int $userid, string $except = ''): int {
	$acc = hc2_account($userid);
	$st = hc2_pdo()->prepare("SELECT interval_sec, locations FROM hc2_checks WHERE userid = :u AND deleted_at IS NULL AND execution IN ('online','both') AND paused = 0 AND type <> 'push' AND token <> :t");
	$st->execute(array('u' => $userid, 't' => $except));
	$sum = 0;
	foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $c) {
		$n = $c['locations'] === '' ? 2 : count(explode(',', $c['locations']));
		if ($acc['hc_locations'] === 1) { $n = min($n, 1); }
		if ((int)$c['interval_sec'] > 0) { $sum += intdiv(86400, (int)$c['interval_sec']) * $n; }
	}
	return $sum;
}

/** Aktive Nodes des Accounts, Schluessel node_id. */
function hc2_nodes(int $userid, bool $fresh = false): array {
	static $cache = array();
	if (isset($cache[$userid]) && !$fresh) { return $cache[$userid]; }
	$st = hc2_pdo()->prepare("SELECT node_id, name, location, version, remote_mgmt, online, last_seen, last_sync, outbox_size, conflicts, modules, timezone, created_at FROM hc2_nodes WHERE userid = :u AND revoked_at IS NULL ORDER BY name");
	$st->execute(array('u' => $userid));
	$out = array();
	foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $n) { $out[$n['node_id']] = $n; }
	return $cache[$userid] = $out;
}
/** Messende Nodes eines Checks (Spalte nodes; alte Checks: nur die Besitzer-Node). */
function hc2_check_nodes(array $c): array {
	if (($c['execution'] ?? 'online') === 'online') { return array(); }
	$l = array_values(array_unique(array_filter(explode(',', (string)($c['nodes'] ?? '')))));
	if (!$l && !empty($c['node_id'])) { $l = array((string)$c['node_id']); }
	return $l;
}
/** Docker-Checks gehoeren zur Node mit dem Container; Push-Checks sind frei zuordenbar. */
function hc2_single_node_type(string $type): bool { return $type === 'docker' || $type === 'proxmox'; } // nur auf Nodes, nie online
function hc2_same_list(array $a, array $b): bool { sort($a); sort($b); return array_values($a) === array_values($b); }
function hc2_nodes_label(array $nodes, array $ids): string {
	$o = array(); foreach ($ids as $id) { $o[] = hc2_node_label($nodes, $id) ?: 'Node'; }
	return implode(', ', $o);
}
function hc2_node_label(array $nodes, ?string $nodeId): string {
	if (!$nodeId) { return ''; }
	if (!isset($nodes[$nodeId])) { return 'Node (getrennt)'; }
	$n = $nodes[$nodeId];
	return $n['name'] . ($n['location'] !== '' ? ' (' . $n['location'] . ')' : '');
}

/** Standorte der hubs (Code => Name). */
function hc2_locations(): array {
	static $l = null;
	if ($l !== null) { return $l; }
	$l = array();
	try {
		foreach (hc2_pdo()->query("SELECT code, name FROM hc2_locations WHERE enabled = 1 ORDER BY code") as $r) { $l[$r['code']] = $r['name']; }
	} catch (Throwable $e) { error_log('hc2_locations: ' . $e->getMessage()); }
	if (!$l) { $l = array('nbg' => 'Nürnberg', 'fsn' => 'Falkenstein'); }
	return $l;
}

// ---------------------------------------------------------------- Checks: Definitionen

function hc2_types(): array {
	return array('http' => 'HTTP(S)', 'keyword' => 'Schlüsselwort', 'json' => 'JSON (API)', 'dns' => 'DNS', 'icmp' => 'Ping (ICMP)', 'tcp' => 'TCP', 'port' => 'Port', 'cert' => 'Zertifikat', 'push' => 'Push / Heartbeat', 'docker' => 'Docker-Container', 'whois' => 'WHOIS / RDAP');
}
function hc2_states(): array {
	return array('up' => array('OK', 'success'), 'down' => array('Gestört', 'danger'), 'degraded' => array('Teilweise gestört', 'warning'), 'flapping' => array('Instabil', 'warning'),
		'paused' => array('Pausiert', 'secondary'), 'pending' => array('Ausstehend', 'info'), 'maintenance' => array('Wartung', 'secondary'), 'unknown' => array('Unbekannt', 'secondary'),
		'stabilizing' => array('Stabilisiert sich', 'info'), 'dependent' => array('Abhängigkeit gestört', 'secondary'), 'unchecked' => array('Nicht überwacht', 'warning'), 'quota' => array('Kontingent aufgebraucht', 'secondary'));
}
/** Zustand fuer die Anzeige: wie gespeichert, aber "ausstehend" mit Grund unchecked bzw. quota_exhausted als
 *  "nicht ueberwacht" bzw. "Kontingent aufgebraucht" (der hub misst bzw. bekommt keine Messung mehr). */
function hc2_check_state(array $c): string {
	if ((int)$c['paused']) { return 'paused'; }
	$s = $c['state'] ?: 'pending';
	if ($s === 'pending' && ($c['last_reason'] ?? '') === 'unchecked') { return 'unchecked'; }
	if ($s === 'pending' && ($c['last_reason'] ?? '') === 'quota_exhausted') { return 'quota'; }
	return $s;
}
function hc2_state_badge(?string $state): string {
	$s = hc2_states(); $x = $s[$state ?? 'pending'] ?? array($state, 'secondary');
	return '<span class="badge badge-' . $x[1] . '">' . hc2_h($x[0]) . '</span>';
}
function hc2_reason_text(?string $r): string {
	$m = array('ok' => 'OK', 'timeout' => 'Zeitüberschreitung', 'dns' => 'DNS-Fehler', 'connection_refused' => 'Verbindung abgelehnt', 'connect_error' => 'Verbindungsfehler', 'tls' => 'TLS-Fehler',
		'http_status' => 'HTTP-Status', 'keyword_missing' => 'Schlüsselwort fehlt', 'keyword_present' => 'Schlüsselwort vorhanden', 'port_closed' => 'Port geschlossen', 'port_open' => 'Port offen',
		'packet_loss' => 'Paketverlust', 'latency' => 'Latenz zu hoch', 'cert_expiring' => 'Zertifikat läuft ab', 'cert_expired' => 'Zertifikat abgelaufen', 'cert_invalid' => 'Zertifikat ungültig',
		'push_missing' => 'Push ausgeblieben', 'push_down' => 'Push meldet Störung', 'invalid_definition' => 'Definition ungültig', 'unreachable' => 'Nicht erreichbar', 'inverted' => 'Invertiert',
		'icmp_not_permitted' => 'ICMP nicht erlaubt', 'family_unreachable' => 'IP-Familie nicht erreichbar',
		// Codes der Nodes und des hubs (wie im Container)
		'dns_failed' => 'DNS-Fehler', 'connect_failed' => 'Verbindung fehlgeschlagen', 'tls_failed' => 'TLS-Fehler', 'status_mismatch' => 'Falscher HTTP-Status',
		'too_many_redirects' => 'Zu viele Weiterleitungen', 'banner_mismatch' => 'Banner passt nicht', 'latency_high' => 'Latenz zu hoch', 'no_address_for_family' => 'Keine Adresse für IP-Version',
		'cert_hostname_mismatch' => 'Zertifikat passt nicht zum Namen', 'push_reported_down' => 'Push meldet Störung', 'container_missing' => 'Container fehlt',
		'container_stopped' => 'Container gestoppt', 'container_paused' => 'Container pausiert', 'container_restarting' => 'Container startet neu',
		'whois_failed' => 'WHOIS-Abfrage fehlgeschlagen', 'whois_not_found' => 'Domain nicht registriert', 'whois_expiring' => 'Domain läuft bald ab',
		'whois_expired' => 'Domain abgelaufen', 'whois_mismatch' => 'WHOIS-Angabe fehlt',
		'container_unhealthy' => 'Container ungesund', 'docker_unavailable' => 'Docker nicht erreichbar', 'dependency_down' => 'Abhängigkeit gestört', 'internal_error' => 'Interner Fehler',
		'json_invalid' => 'Keine gültige JSON-Antwort', 'json_mismatch' => 'JSON-Bedingung nicht erfüllt', 'dns_mismatch' => 'DNS-Antwort passt nicht', 'dns_nxdomain' => 'Name existiert nicht', 'dnssec_failed' => 'DNSSEC nicht validiert',
		'unchecked' => 'Nicht überwacht', 'quota_exhausted' => 'Tageskontingent aufgebraucht');
	return $m[$r ?? ''] ?? (string)$r;
}

/** Ziel fuer Listen: bei TCP/Port mit Port, beim Zertifikat mit abweichendem Port (wie im Container). */
function hc2_target_display(array $c): string {
	$t = trim((string)$c['target']);
	if ($t === '' || preg_match('/^\[.*\]:\d+$|^[^:\[\]]+:\d+$/', $t) || preg_match('#^[a-z]+://#i', $t)) { return $t; }
	$p = json_decode((string)($c['params'] ?? ''), true); $port = (int)($p['port'] ?? 0);
	if ($c['type'] === 'cert' && $port === 443) { $port = 0; }
	if (!in_array($c['type'], array('tcp', 'port', 'cert'), true) || $port <= 0) { return $t; }
	$h = trim($t, '[]');
	return (strpos($h, ':') !== false ? '[' . $h . ']' : $h) . ':' . $port;
}

/** Ziel als dezentes Badge mit Symbol je Art (wie im Container); URL ohne https:// und "/" am Ende. */
function hc2_target_badge(array $c): string {
	$t = hc2_target_display($c);
	$style = 'display:inline-flex;align-items:center;max-width:100%;padding:.2rem .55rem;border:1px solid #dee2e6;border-radius:50rem;background:#f8f9fa;font-weight:normal;font-size:.8rem';
	if ($t === '') { return '<span class="badge hc2-tbadge" style="' . $style . '"><i class="fa-solid fa-circle-down text-muted mr-1"></i> Push / Heartbeat</span>'; }
	$icon = array('tcp' => 'fa-plug', 'port' => 'fa-plug', 'icmp' => 'fa-tower-broadcast', 'cert' => 'fa-shield-halved', 'docker' => 'fa-box', 'dns' => 'fa-signs-post', 'whois' => 'fa-address-card')[$c['type']] ?? 'fa-bullseye';
	$cls = 'text-muted'; $short = $t;
	if ($c['type'] === 'dns') { $short = strtoupper((string)(hc2_check_params($c)['record_type'] ?? 'A')) . ' ' . rtrim($t, '.'); }
	if (in_array($c['type'], array('http', 'keyword', 'json'), true)) {
		$secure = stripos($t, 'http://') !== 0;
		$icon = $secure ? 'fa-lock' : 'fa-lock-open'; $cls = $secure ? 'text-success' : 'text-warning';
		$short = rtrim(preg_replace('#^[a-z]+://#i', '', $t), '/');
	}
	return '<span class="badge hc2-tbadge" style="' . $style . '" title="' . hc2_h($t) . '"><i class="fa-solid ' . $icon . ' ' . $cls . ' mr-1"></i><span class="text-truncate text-monospace">' . hc2_h($short) . '</span></span>';
}

/** Badge fuer einen Grund (OK gruen, Warnungen gelb, Fehler rot). */
function hc2_reason_badge(?string $r): string {
	if ($r === null || $r === '') { return ''; }
	$cls = $r === 'ok' ? 'success' : (in_array($r, array('cert_expiring', 'latency', 'latency_high', 'packet_loss', 'dependency_down', 'container_restarting', 'container_paused'), true) ? 'warning' : 'danger');
	return '<span class="badge badge-' . $cls . '" title="' . hc2_h($r) . '">' . hc2_h(hc2_reason_text($r)) . '</span>';
}

/** Badges fuer die HTTP-Codes einer Meldung (ipv4/ipv6 je einmal). */
function hc2_http_badges(string $msg): string {
	if (!preg_match_all('/\bHTTP (\d{3})\b/', $msg, $m)) { return ''; }
	$out = '';
	foreach (array_unique($m[1]) as $code) {
		$cls = array('2' => 'success', '3' => 'info', '4' => 'warning', '5' => 'danger')[$code[0]] ?? 'secondary';
		$out .= '<span class="badge badge-' . $cls . ' mr-1">' . hc2_h($code) . '</span>';
	}
	return $out;
}
/** Kurzform fuer Listen (wie im Container); Einzelheiten im Tooltip. */
function hc2_exec_short(array $c, array $nodes): string {
	$ids = hc2_check_nodes($c);
	$locs = array(); foreach (explode(',', (string)($c['locations'] ?? '')) as $l) { if ($l !== '') { $locs[] = hc2_locations()[$l] ?? $l; } }
	$tip = array();
	if ($ids) { $tip[] = 'Nodes: ' . hc2_nodes_label($nodes, $ids); }
	if (($c['execution'] ?? 'online') !== 'local') { $tip[] = 'ipv64: ' . implode(', ', $locs); }
	$t = hc2_h(implode(' · ', $tip));
	switch ($c['execution'] ?? 'online') {
		case 'local': return '<span class="badge badge-light" title="' . $t . '"><i class="fa-solid fa-house"></i> Lokal auf Nodes</span>';
		case 'both': return '<span class="badge badge-light" title="' . $t . '"><i class="fa-solid fa-house"></i>+<i class="fa-solid fa-cloud"></i> Lokal und online (Hybrid)</span>';
		default: return '<span class="badge badge-light" title="' . $t . '"><i class="fa-solid fa-cloud"></i> Nur online bei ipv64</span>';
	}
}
function hc2_exec_badge(array $c, array $nodes): string {
	$node = hc2_nodes_label($nodes, hc2_check_nodes($c));
	$locs = array(); foreach (explode(',', (string)($c['locations'] ?? '')) as $l) { if ($l !== '') { $locs[] = hc2_locations()[$l] ?? $l; } }
	$online = 'ipv64 (' . implode(', ', $locs) . ')';
	switch ($c['execution'] ?? 'online') {
		case 'local': return '<span class="badge badge-light" title="Wird nur von der Node gemessen"><i class="fa-solid fa-house"></i> ' . hc2_h($node ?: 'Node') . '</span>';
		case 'both': return '<span class="badge badge-light" title="Hybrid: Node und ipv64 messen"><i class="fa-solid fa-house"></i> ' . hc2_h($node ?: 'Node') . ' + <i class="fa-solid fa-cloud"></i> ' . hc2_h($online) . '</span>';
		default: return '<span class="badge badge-light" title="Wird von ipv64.net gemessen"><i class="fa-solid fa-cloud"></i> ' . hc2_h($online) . '</span>';
	}
}
function hc2_source_label(string $src, array $nodes): string {
	if (strncmp($src, 'loc:', 4) === 0) { $c = substr($src, 4); return 'ipv64 ' . (hc2_locations()[$c] ?? $c); }
	if (strncmp($src, 'node:', 5) === 0) { return hc2_node_label($nodes, substr($src, 5)) ?: 'Node'; }
	if ($src === 'push') { return 'Push'; }
	return $src === '' ? 'Gesamt' : $src;
}

/** Ein Check des Accounts oder null. */
function hc2_check(int $userid, string $token): ?array {
	if (!preg_match('/^[A-Za-z0-9]{20,50}$/', $token)) { return null; }
	$st = hc2_pdo()->prepare("SELECT * FROM hc2_checks WHERE token = :t AND userid = :u AND deleted_at IS NULL");
	$st->execute(array('t' => $token, 'u' => $userid));
	$c = $st->fetch(PDO::FETCH_ASSOC);
	return $c ?: null;
}
function hc2_checks(int $userid): array {
	$st = hc2_pdo()->prepare("SELECT * FROM hc2_checks WHERE userid = :u AND deleted_at IS NULL ORDER BY name, token");
	$st->execute(array('u' => $userid));
	return $st->fetchAll(PDO::FETCH_ASSOC);
}
function hc2_check_params(array $c): array { $p = json_decode((string)($c['params'] ?? '{}'), true); return is_array($p) ? $p : array(); }
function hc2_check_channels(array $c): array { $o = array(); foreach (explode(',', (string)($c['channels'] ?? '')) as $x) { if ($x !== '' && is_numeric($x)) { $o[] = (int)$x; } } return $o; }

/** Privates Ziel? (RFC 1918, ULA, Loopback, Link-Local, .local, localhost) – online verboten. */
function hc2_private_target(string $type, string $target): bool {
	$t = trim($target);
	if ($t === '' || $type === 'push') { return false; }
	$host = $t;
	if (in_array($type, array('http', 'keyword', 'json'), true)) { $host = (string)parse_url($t, PHP_URL_HOST); }
	elseif ($type === 'dns') { $host = rtrim($t, '.'); }
	elseif (preg_match('/^\[([^\]]+)\](?::\d+)?$/', $t, $m)) { $host = $m[1]; }
	elseif (substr_count($t, ':') === 1) { $host = explode(':', $t)[0]; }
	$host = strtolower(trim($host, '[]'));
	if ($host === '' ) { return false; }
	if ($host === 'localhost' || substr($host, -6) === '.local' || substr($host, -10) === '.localhost' || substr($host, -9) === '.internal') { return true; }
	if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
		return !filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) || strncmp($host, '169.254.', 8) === 0 || strncmp($host, '100.64.', 7) === 0;
	}
	if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
		return $host === '::1' || preg_match('/^f[cd][0-9a-f]{2}:/', $host) || preg_match('/^fe[89ab][0-9a-f]:/', $host);
	}
	return false;
}

/** JSON-Check: Vergleiche (wie checks.JSONOps in der Node) und Textform "Pfad Vergleich Wert" je Zeile. */
function hc2_json_ops(): array {
	return array('==' => 'eq', '=' => 'eq', '!=' => 'ne', '<' => 'lt', '<=' => 'le', '>' => 'gt', '>=' => 'ge', 'contains' => 'contains', '!contains' => 'not_contains', '~' => 'regex', 'exists' => 'exists', '!exists' => 'not_exists');
}
/** Bedingungen aus Text (Formular) oder Liste (API) lesen und pruefen; liefert array(rules, errors). */
function hc2_json_rules($in): array {
	$rules = array(); $err = array(); $ops = hc2_json_ops(); $valid = array_unique(array_values($ops));
	if (is_array($in)) {
		foreach ($in as $r) { if (is_array($r)) { $rules[] = array('path' => trim((string)($r['path'] ?? '')), 'op' => (string)($r['op'] ?? ''), 'value' => (string)($r['value'] ?? '')); } }
	} else {
		foreach (preg_split('/\r?\n/', (string)$in) as $n => $line) {
			$line = trim($line);
			if ($line === '' || $line[0] === '#') { continue; }
			$w = preg_split('/\s+/', $line);
			if (count($w) < 2 || !isset($ops[$w[1]])) { $err[] = 'JSON-Bedingung Zeile ' . ($n + 1) . ': erwartet „Pfad Vergleich Wert“, z. B. status == ok.'; continue; }
			$op = $ops[$w[1]]; $val = '';
			if ($op !== 'exists' && $op !== 'not_exists') {
				$val = trim(substr($line, strpos($line, $w[1], strlen($w[0])) + strlen($w[1])));
				if (strlen($val) >= 2 && $val[0] === '"' && substr($val, -1) === '"') { $val = substr($val, 1, -1); }
			} elseif (count($w) > 2) { $err[] = 'JSON-Bedingung Zeile ' . ($n + 1) . ': ' . $w[1] . ' hat keinen Wert.'; continue; }
			$rules[] = array('path' => $w[0], 'op' => $op, 'value' => $val);
		}
	}
	if (!$rules && !$err) { $err[] = 'Mindestens eine JSON-Bedingung angeben, z. B. status == ok.'; }
	if (count($rules) > 10) { $err[] = 'Höchstens 10 JSON-Bedingungen.'; }
	foreach ($rules as $i => $r) {
		$p = preg_replace('/^\$\.?/', '', $r['path']);
		if ($p !== '' && !preg_match('/^[^.\[\]\s]+(\[\d+\])*(\.[^.\[\]\s]+(\[\d+\])*)*$/', $p)) { $err[] = 'JSON-Bedingung ' . ($i + 1) . ': Pfad ungültig (z. B. data.items[0].status).'; }
		if (!in_array($r['op'], $valid, true)) { $err[] = 'JSON-Bedingung ' . ($i + 1) . ': unbekannter Vergleich.'; }
		if (in_array($r['op'], array('lt', 'le', 'gt', 'ge'), true) && !is_numeric(trim($r['value']))) { $err[] = 'JSON-Bedingung ' . ($i + 1) . ': < und > brauchen eine Zahl.'; }
		if ($r['op'] === 'regex' && @preg_match('~' . str_replace('~', '\~', $r['value']) . '~', '') === false) { $err[] = 'JSON-Bedingung ' . ($i + 1) . ': regulärer Ausdruck ungültig.'; }
		if ($r['op'] === 'exists' || $r['op'] === 'not_exists') { unset($rules[$i]['value']); }
	}
	return array(array_values($rules), $err);
}
/** Textform der Bedingungen fuer das Formular. */
function hc2_json_rules_text(array $rules): string {
	$sym = array('eq' => '==', 'ne' => '!=', 'lt' => '<', 'le' => '<=', 'gt' => '>', 'ge' => '>=', 'contains' => 'contains', 'not_contains' => '!contains', 'regex' => '~', 'exists' => 'exists', 'not_exists' => '!exists');
	$l = array();
	foreach ($rules as $r) { if (!is_array($r)) { continue; } $op = (string)($r['op'] ?? ''); $l[] = trim(($r['path'] ?? '') . ' ' . ($sym[$op] ?? $op) . (in_array($op, array('exists', 'not_exists'), true) ? '' : ' ' . ($r['value'] ?? ''))); }
	return implode("\n", $l);
}
/** DNS-Check: Eintragstypen, Resolver-Arten und Erwartungen (wie in der Node). */
function hc2_dns_types(): array { return array('A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV', 'CAA', 'PTR', 'SOA'); }
function hc2_dns_resolvers(): array { return array('system' => 'Standard-Resolver', 'server' => 'Bestimmter Server', 'authoritative' => 'Zuständige Nameserver der Zone'); }
function hc2_dns_expects(): array {
	return array('any' => 'Irgendeine Antwort', 'contains' => 'Antwort enthält die Werte', 'equals' => 'Antwort ist genau die Werte', 'regex' => 'Ein Eintrag passt zum Muster (Regex)',
		'nxdomain' => 'Name existiert nicht (NXDOMAIN)', 'public_ip' => 'Zeigt auf die öffentliche IP der Node (nur lokal)');
}
/** DNS-Server als host:port; '' bei ungueltiger Angabe. */
function hc2_dns_server(string $s): string {
	$s = trim($s);
	if (preg_match('/^\[([0-9a-fA-F:.]+)\]:(\d+)$/', $s, $m) && filter_var($m[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) && (int)$m[2] >= 1 && (int)$m[2] <= 65535) { return '[' . $m[1] . ']:' . $m[2]; }
	if (preg_match('/^([0-9.]+):(\d+)$/', $s, $m) && filter_var($m[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && (int)$m[2] >= 1 && (int)$m[2] <= 65535) { return $m[1] . ':' . $m[2]; }
	if (filter_var(trim($s, '[]'), FILTER_VALIDATE_IP)) { return trim($s, '[]'); }
	return '';
}
/** DNS-Check, der nur auf der Node laufen kann (DNS-Server im Heimnetz, oeffentliche IP der Node). */
function hc2_dns_needs_node(array $p): bool {
	if (($p['expect'] ?? '') === 'public_ip') { return true; }
	if (($p['resolver'] ?? '') === 'server') {
		$ip = trim(preg_replace('/:\d+$/', '', preg_replace('/^\[(.*)\](:\d+)?$/', '$1', (string)($p['server'] ?? ''))), '[]');
		return $ip !== '' && hc2_private_target('icmp', $ip);
	}
	return false;
}

/**
 * Formulareingabe pruefen und in eine hc2_checks-Zeile umsetzen. Regeln wie checks.Validate in der Node.
 * Liefert array('row' => ..., 'errors' => array()).
 */
function hc2_validate_check(array $in, int $userid, ?array $old): array {
	$acc = hc2_account($userid); $nodes = hc2_nodes($userid); $locs = hc2_locations(); $err = array();
	$type = (string)($in['type'] ?? 'http');
	if (!isset(hc2_types()[$type])) { $err[] = 'Unbekannter Check-Typ.'; $type = 'http'; }
	$name = mb_substr(trim((string)($in['name'] ?? '')), 0, 200);
	if ($name === '') { $err[] = 'Name fehlt.'; }
	$target = mb_substr(trim((string)($in['target'] ?? '')), 0, 500);
	$p = array();
	$num = function($k, $def, $min, $max) use ($in) { $v = $in[$k] ?? ''; if ($v === '' || $v === null) { return $def; } $v = (int)$v; return max($min, min($max, $v)); };
	$flag = function($k) use ($in) { return !empty($in[$k]) && $in[$k] !== '0'; };
	switch ($type) {
		case 'http': case 'keyword': case 'json':
			if (!preg_match('#^https?://[^\s/]+#i', $target) || parse_url($target, PHP_URL_HOST) === null) { $err[] = 'Ziel muss eine http(s)-URL sein.'; }
			$m = strtoupper((string)($in['method'] ?? 'GET')); if (!in_array($m, array('GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'), true)) { $m = 'GET'; }
			if ($m !== 'GET') { $p['method'] = $m; }
			$as = trim((string)($in['accept_status'] ?? ''));
			if ($as !== '' && !preg_match('/^\d{3}(-\d{3})?(\s*,\s*\d{3}(-\d{3})?)*$/', $as)) { $err[] = 'Erlaubte Statuscodes: z. B. 200-299,301'; }
			if ($as !== '' && $as !== '200-299') { $p['accept_status'] = $as; }
			if (!$flag('follow_redirects') && isset($in['follow_redirects_present'])) { $p['follow_redirects'] = false; }
			if (($mr = $num('max_redirects', 5, 0, 20)) !== 5) { $p['max_redirects'] = $mr; }
			if ($type === 'keyword') { $kw = trim((string)($in['keyword'] ?? '')); if ($kw === '') { $err[] = 'Schlüsselwort fehlt.'; } $p['keyword'] = $kw; if ($flag('keyword_absent')) { $p['keyword_absent'] = true; } }
			if (($bu = trim((string)($in['basic_user'] ?? ''))) !== '') { $p['basic_user'] = $bu; $p['basic_password'] = (string)($in['basic_password'] ?? ''); }
			$hd = array(); foreach (preg_split('/\r?\n/', (string)($in['headers'] ?? '')) as $line) { if (strpos($line, ':') !== false) { [$k, $v] = explode(':', $line, 2); $k = trim($k); if ($k !== '') { $hd[$k] = trim($v); } } }
			if ($hd) { $p['headers'] = $hd; }
			if (($b = (string)($in['body'] ?? '')) !== '') { $p['body'] = $b; }
			if ($flag('insecure_tls')) { $p['insecure_tls'] = true; }
			if (($cd = $num('cert_min_days', 0, 0, 3650)) > 0) { $p['cert_min_days'] = $cd; }
			if ($type === 'json') {
				[$rules, $jerr] = hc2_json_rules($in['json_rules'] ?? '');
				$err = array_merge($err, $jerr); $p['json_rules'] = $rules;
				if ($flag('json_any')) { $p['json_any'] = true; }
			}
			break;
		case 'dns':
			$target = rtrim(strtolower($target), '.');
			$rt = strtoupper(trim((string)($in['dns_record_type'] ?? 'A'))); if (!in_array($rt, hc2_dns_types(), true)) { $err[] = 'Eintragstyp ungültig.'; $rt = 'A'; }
			$nameOk = preg_match('/^(\*\.)?([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$/', $target) || ($rt === 'PTR' && filter_var($target, FILTER_VALIDATE_IP));
			if ($target === '' || !$nameOk) { $err[] = 'Ziel muss ein Domainname sein (bei PTR auch eine IP-Adresse).'; }
			$p['record_type'] = $rt;
			$res = (string)($in['dns_resolver'] ?? 'system'); if (!isset(hc2_dns_resolvers()[$res])) { $res = 'system'; }
			$p['resolver'] = $res;
			if ($res === 'server') { $sv = hc2_dns_server((string)($in['dns_server'] ?? '')); if ($sv === '') { $err[] = 'DNS-Server muss eine IP-Adresse sein (optional mit Port).'; } $p['server'] = $sv; }
			$ex = (string)($in['dns_expect'] ?? 'any'); if (!isset(hc2_dns_expects()[$ex])) { $ex = 'any'; }
			$p['expect'] = $ex;
			$vals = $in['dns_values'] ?? array(); if (!is_array($vals)) { $vals = preg_split('/\r?\n/', (string)$vals); }
			$vals = array_values(array_filter(array_map(function($v) { return trim((string)$v); }, $vals), 'strlen'));
			if (in_array($ex, array('contains', 'equals', 'regex'), true)) {
				if (!$vals) { $err[] = 'Für diese Erwartung mindestens einen Wert angeben.'; }
				if ($ex === 'regex' && $vals && @preg_match('~' . str_replace('~', '\~', $vals[0]) . '~', '') === false) { $err[] = 'Regulärer Ausdruck ungültig.'; }
				$p['values'] = $ex === 'regex' ? array_slice($vals, 0, 1) : array_slice($vals, 0, 50);
			}
			if ($ex === 'public_ip' && $rt !== 'A' && $rt !== 'AAAA') { $err[] = '„Öffentliche IP“ geht nur mit A oder AAAA.'; }
			if ($flag('dns_dnssec')) { $p['dnssec'] = true; }
			if (($mt = $num('dns_min_ttl', 0, 0, 604800)) > 0) { $p['min_ttl'] = $mt; }
			break;
		case 'icmp':
			if ($target === '') { $err[] = 'Ziel (Host oder IP) fehlt.'; }
			if (($c = $num('count', 3, 1, 20)) !== 3) { $p['count'] = $c; }
			if (($l = $num('max_loss_percent', 0, 0, 100)) !== 0) { $p['max_loss_percent'] = $l; }
			if (($ml = $num('max_latency_ms', 0, 0, 60000)) !== 0) { $p['max_latency_ms'] = $ml; }
			break;
		case 'tcp': case 'port': case 'cert':
			if ($target === '') { $err[] = 'Ziel (Host oder IP) fehlt.'; }
			$port = $num('port', 0, 0, 65535);
			// Port nur im Feld Port: host:port im Ziel wird uebernommen, zwei verschiedene Ports sind ein Fehler
			if (preg_match('/^(\[[^\]]+\]|[^:]+):(\d+)$/', $target, $tm)) {
				$tp = (int)$tm[2];
				if ($tp < 1 || $tp > 65535) { $err[] = 'Port im Ziel muss zwischen 1 und 65535 liegen.'; }
				elseif ($port > 0 && $port !== $tp) { $err[] = 'Im Ziel steht Port ' . $tp . ', im Feld Port ' . $port . '. Den Port bitte nur im Feld Port eintragen.'; }
				else { $port = $tp; $target = trim($tm[1], '[]'); }
			}
			if ($type === 'cert' && $port === 0) { $port = 443; }
			if ($port > 0) { $p['port'] = $port; } else { $err[] = 'Port fehlt.'; }
			if ($type === 'tcp') { if (($s = (string)($in['send'] ?? '')) !== '') { $p['send'] = $s; } if (($e = (string)($in['expect'] ?? '')) !== '') { $p['expect'] = $e; } if ($flag('tls')) { $p['tls'] = true; } }
			if ($type === 'port') { $e = (string)($in['expect'] ?? 'open'); if ($e === 'closed') { $p['expect'] = 'closed'; } }
			if ($type === 'cert') { if (($d = $num('min_days', 14, 0, 3650)) !== 14) { $p['min_days'] = $d; } if (($sn = trim((string)($in['server_name'] ?? ''))) !== '') { $p['server_name'] = $sn; } if ($flag('skip_chain')) { $p['skip_chain'] = true; } if ($flag('skip_hostname')) { $p['skip_hostname'] = true; } }
			break;
		case 'docker':
			if (!preg_match('/^\/?[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/', $target)) { $err[] = 'Containername oder -ID fehlt (Buchstaben, Ziffern, _ . -).'; }
			if (($h = trim((string)($in['docker_host'] ?? ''))) !== '') { if (!preg_match('#^(unix|tcp|https?)://#', $h)) { $err[] = 'Docker-Host muss mit unix://, tcp:// oder http(s):// beginnen.'; } else { $p['host'] = $h; } }
			if (($sy = trim((string)($in['docker_system'] ?? ''))) !== '') { $p['system'] = mb_substr($sy, 0, 200); } // Anzeige-Name des Docker-Hosts (setzt die Node)
			break;
		case 'whois':
			// Domain, IP/Netz oder AS-Nummer; Auskunft per RDAP, sonst WHOIS (Port 43) – wie im Container (internal/checks/whois.go)
			$target = trim($target);
			$wIp = explode('/', $target, 2);
			$wOk = (bool)preg_match('/^(AS)?\d{1,10}$/i', $target)
				|| (filter_var($wIp[0], FILTER_VALIDATE_IP) !== false && (!isset($wIp[1]) || ctype_digit($wIp[1])))
				|| (bool)preg_match('/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}\.?$/i', $target);
			if (!$wOk) { $err[] = 'Ziel: Domain, IP-Adresse/Netz oder AS-Nummer (z. B. example.de, 203.0.113.0/24, AS3320).'; }
			$srcw = (string)($in['whois_source'] ?? 'auto'); if (in_array($srcw, array('rdap', 'whois'), true)) { $p['source'] = $srcw; }
			if (($wd = $num('whois_min_days', 14, 0, 3650)) !== 14) { $p['min_days'] = $wd; }
			$rules = array(); foreach (preg_split('/\r?\n/', (string)($in['whois_contains'] ?? '')) as $rl) { $rl = trim($rl); if ($rl !== '') { $rules[] = mb_substr($rl, 0, 200); } }
			if (count($rules) > 20) { $err[] = 'Höchstens 20 erwartete Angaben.'; }
			if ($rules) { $p['contains'] = array_slice($rules, 0, 20); }
			break;
		case 'push':
			$target = '';
			if (($ps = $num('period_seconds', 3600, 20, 31536000)) !== 3600) { $p['period_seconds'] = $ps; }
			if (isset($in['grace_seconds']) && $in['grace_seconds'] !== '') { $g = $num('grace_seconds', 600, 0, 31536000); if ($g !== 600) { $p['grace_seconds'] = $g; } }
			break;
	}
	$interval = $num('interval_sec', 60, 5, 86400); // lokal ab 5 s; online/hybrid ab 20 s (unten nach dem Ausfuehrungsort)
	$retryInt = $num('retry_interval_sec', 20, 5, 86400);
	$retries = $num('retries', 1, 0, 10);
	$cto = (float)($in['connect_timeout'] ?? 5); $cto = max(0.5, min(60, $cto));
	$tto = (float)($in['total_timeout'] ?? 10); $tto = max(1, min(120, $tto));
	$stab = $num('stabilize', 3, 1, 20);
	$ipMode = (string)($in['ip_mode'] ?? 'auto'); if (!in_array($ipMode, array('auto','ipv4','ipv6','both'), true)) { $ipMode = 'auto'; }
	$tags = array(); foreach (preg_split('/[,\s]+/', (string)($in['tags'] ?? '')) as $t) { $t = trim($t); if ($t !== '' && !in_array($t, $tags, true)) { $tags[] = mb_substr($t, 0, 40); } }
	$tags = implode(',', array_slice($tags, 0, 20)); if (strlen($tags) > 255) { $tags = substr($tags, 0, 255); }
	$group = mb_substr(trim((string)($in['group_name'] ?? '')), 0, 100);
	$desc = mb_substr(trim((string)($in['description'] ?? '')), 0, 5000);
	$parent = trim((string)($in['parent_token'] ?? ''));
	if ($parent !== '') {
		if (($old && $parent === $old['token']) || !hc2_check($userid, $parent)) { $err[] = 'Abhängigkeit ungültig.'; $parent = ''; }
	}
	$channels = array();
	$own = array(); foreach (hc2_channels($userid) as $ch) { $own[(int)$ch['id']] = true; }
	foreach ((array)($in['channels'] ?? array()) as $cid) { $cid = (int)$cid; if (isset($own[$cid]) && !in_array($cid, $channels, true)) { $channels[] = $cid; } }
	$repeat = $num('repeat_minutes', 0, 0, 10080);

	// Messstellen und Bewertung
	$execution = (string)($in['execution'] ?? 'online'); if (!in_array($execution, array('local','online','both'), true)) { $execution = 'online'; }
	if ($execution !== 'local' && $type !== 'push' && $interval < 20) { $interval = 20; }
	if ($type === 'whois') { $interval = max(3600, $interval); $retryInt = max(600, $retryInt); } // WHOIS/RDAP-Server begrenzen Abfragen (wie Node und hub)
	if ($retryInt > $interval) { $retryInt = $interval; }
	// Messende Nodes (mehrere moeglich); node_id = Besitzer: bleibt, solange er gewaehlt ist
	$oldNodes = $old ? hc2_check_nodes($old) : array();
	if (isset($in['nodes']) && is_array($in['nodes'])) { $req = $in['nodes']; }
	elseif (isset($in['node_id']) && (string)$in['node_id'] !== '') { $req = array((string)$in['node_id']); }
	else { $req = $oldNodes ?: (($old && !empty($old['node_id'])) ? array($old['node_id']) : array()); }
	$nodeSel = array(); foreach ($req as $nid) { $nid = (string)$nid; if ($nid !== '' && !in_array($nid, $nodeSel, true)) { $nodeSel[] = $nid; } }
	$nodeId = '';
	if ($execution !== 'online') {
		foreach ($nodeSel as $nid) { if (!isset($nodes[$nid])) { $err[] = 'Eine gewählte Node ist nicht (mehr) verknüpft.'; break; } }
		if (!$nodeSel) { $err[] = 'Für lokale oder hybride Messung mindestens eine verbundene Node wählen.'; }
		if (hc2_single_node_type($type) && count($nodeSel) > 1 && !($old && hc2_same_list(hc2_check_nodes($old), $nodeSel))) { $err[] = 'Docker- und Proxmox-Checks gehören zu ihrer Node (weitere Nodes nur über den Cluster in Node64).'; }
		$nodeId = ($old && in_array((string)$old['node_id'], $nodeSel, true)) ? (string)$old['node_id'] : (string)($nodeSel[0] ?? '');
		if (hc2_single_node_type($type) && $old && !empty($old['node_id']) && $nodeId !== (string)$old['node_id']) { $err[] = 'Docker- und Proxmox-Checks gehören zu ihrer Node und sind nicht umhängbar.'; }
	}
	$sel = array(); foreach ((array)($in['locations'] ?? array_keys($locs)) as $l) { if (isset($locs[$l]) && !in_array($l, $sel, true)) { $sel[] = $l; } }
	if (!$sel) { $sel = array_keys($locs); }
	if (count($sel) > $acc['hc_locations']) { $sel = array_slice($sel, 0, $acc['hc_locations']); }
	$policy = (string)($in['policy'] ?? 'all'); if (!in_array($policy, array('all','any','majority'), true)) { $policy = 'all'; }
	if (hc2_single_node_type($type) && $execution !== 'local') { $err[] = 'Docker- und Proxmox-Checks laufen nur lokal auf ihrer Node, nie online.'; }
	if ($execution !== 'local' && !hc2_single_node_type($type)) {
		if (hc2_private_target($type, $target)) { $err[] = 'Online-Checks können keine privaten Ziele prüfen (Heimnetz, localhost, .local). Dafür eine Node nutzen.'; }
		if ($type === 'dns' && hc2_dns_needs_node($p)) { $err[] = 'Ein DNS-Server im Heimnetz und „zeigt auf die öffentliche IP“ gehen nur lokal auf einer Node.'; }
		$used = hc2_online_used($userid, $old['token'] ?? '');
		if ($acc['healthcheck_limit'] > 0 && $used + count($sel) > $acc['healthcheck_limit']) {
			$err[] = 'Online-Limit erreicht: ' . $used . ' von ' . $acc['healthcheck_limit'] . ' Messstellen belegt, benötigt werden ' . count($sel) . ' weitere. Standorte reduzieren oder lokal auf einer Node messen.';
		}
	}
	$row = array(
		'type' => $type, 'name' => $name, 'target' => $target, 'params' => json_encode($p ?: new stdClass(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
		'interval_sec' => $interval, 'retry_interval_sec' => $retryInt, 'retries' => $retries, 'connect_timeout_ms' => (int)round($cto * 1000), 'total_timeout_ms' => (int)round($tto * 1000),
		'invert' => $flag('invert') ? 1 : 0, 'stabilize' => $stab, 'ip_mode' => $ipMode, 'tags' => $tags, 'group_name' => $group, 'description' => $desc, 'paused' => $flag('paused') ? 1 : 0,
		'parent_token' => $parent !== '' ? $parent : null, 'critical' => $flag('critical') ? 1 : 0, 'notify_down' => $flag('notify_down') ? 1 : 0, 'notify_up' => $flag('notify_up') ? 1 : 0,
		'channels' => implode(',', $channels), 'repeat_minutes' => $repeat,
		'execution' => $execution, 'node_id' => $execution === 'online' ? ($old['node_id'] ?? null) : $nodeId, 'nodes' => $execution === 'online' ? '' : implode(',', $nodeSel), 'locations' => implode(',', $sel), 'policy' => $policy, 'notify_degraded' => $flag('notify_degraded') ? 1 : 0,
	);
	if ($execution === 'online' && $row['node_id'] === '') { $row['node_id'] = null; }
	return array('row' => $row, 'errors' => $err);
}

/** Neuen Check anlegen; liefert den Token. */
function hc2_insert_check(int $userid, array $row): string {
	$pdo = hc2_pdo(); $token = hc2_token();
	$cols = array_keys($row);
	$sql = "INSERT INTO hc2_checks (token, userid, slot, revision, created_at, updated_at, updated_by, " . implode(',', $cols) . ") VALUES (:token, :userid, :slot, 1, UTC_TIMESTAMP(3), UTC_TIMESTAMP(3), 'portal', :" . implode(', :', $cols) . ")";
	$row['token'] = $token; $row['userid'] = $userid; $row['slot'] = hc2_slot($token);
	$pdo->prepare($sql)->execute($row);
	hc2_log_change($userid, 'check', $token, 'upsert', 'portal');
	return $token;
}
/** Bestehenden Check speichern. */
function hc2_update_check(int $userid, string $token, array $row): void {
	$pdo = hc2_pdo();
	$set = array(); foreach (array_keys($row) as $k) { $set[] = "$k = :$k"; }
	$row['token'] = $token; $row['userid'] = $userid;
	$pdo->prepare("UPDATE hc2_checks SET " . implode(', ', $set) . ", updated_by = 'portal' WHERE token = :token AND userid = :userid AND deleted_at IS NULL")->execute($row);
	hc2_log_change($userid, 'check', $token, 'upsert', 'portal');
}
function hc2_set_check(int $userid, string $token, array $fields): void {
	$set = array(); foreach (array_keys($fields) as $k) { $set[] = "$k = :$k"; }
	$fields['token'] = $token; $fields['userid'] = $userid;
	hc2_pdo()->prepare("UPDATE hc2_checks SET " . implode(', ', $set) . ", updated_by = 'portal' WHERE token = :token AND userid = :userid AND deleted_at IS NULL")->execute($fields);
	hc2_log_change($userid, 'check', $token, 'upsert', 'portal');
}
/** DNS-Failover-Policies, die Checks als Monitor nutzen: token => Namen der Policies. Nur fuer die Warnung beim
 *  Loeschen – geloescht wird trotzdem, die Policy zaehlt den Monitor danach weder online noch offline. Leer, solange
 *  DNS Failover die neuen Healthchecks nicht nutzt (FAILOVER_HC2 in failover_hc2_lib.php). */
function hc2_failover_uses(int $userid, array $tokens): array {
	if (!defined('FAILOVER_HC2')) { @include_once(__DIR__ . '/../failover_hc2_lib.php'); }
	$pdo = $GLOBALS['pdo'] ?? null;
	if (!defined('FAILOVER_HC2') || !FAILOVER_HC2 || !$pdo instanceof PDO || !$tokens) { return array(); }
	try {
		$in = implode(',', array_fill(0, count($tokens), '?'));
		$st = $pdo->prepare("SELECT m.healthtoken, p.name FROM dns_failover_monitors m JOIN dns_failover_policies p ON p.failover_hash = m.failover_hash
			WHERE m.userid = ? AND m.healthtoken IN ($in) ORDER BY p.name");
		$st->execute(array_merge(array($userid), array_values($tokens)));
		$out = array();
		foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $r) { $out[$r['healthtoken']][] = (string)$r['name']; }
		return $out;
	} catch (Throwable $e) {
		return array();
	}
}
/** Text der Warnung: welche Policies einen geloeschten Check als Monitor hatten ('' = keine). */
function hc2_failover_warning(array $uses): string {
	$names = array(); foreach ($uses as $list) { foreach ($list as $n) { $names[$n] = 1; } }
	if (!$names) { return ''; }
	return 'Achtung: Monitor in DNS Failover (' . implode(', ', array_keys($names)) . '). Die Policy zählt ihn jetzt weder als online noch als gestört – bitte dort einen anderen Healthcheck als Monitor eintragen.';
}
function hc2_delete_check(int $userid, string $token): void {
	hc2_log_change($userid, 'check', $token, 'delete', 'portal'); // setzt deleted_at
	hc2_pdo()->prepare("UPDATE hc2_incidents SET ended_at = UTC_TIMESTAMP(3) WHERE userid = :u AND token = :t AND ended_at IS NULL")->execute(array('u' => $userid, 't' => $token));
	hc2_pdo()->prepare("UPDATE hc2_checks SET parent_token = NULL WHERE userid = :u AND parent_token = :t")->execute(array('u' => $userid, 't' => $token));
}

/** Pillen (letzte n Messpunkte, alle Messstellen) im Stil der alten Seite. */
function hc2_pills(string $token, int $n, array $nodes): string {
	$st = hc2_pdo()->prepare("SELECT source, time, status, latency_ms, reason, message FROM hc2_measurements WHERE token = :t ORDER BY time DESC LIMIT " . (int)$n);
	$st->execute(array('t' => $token));
	$out = '';
	foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $m) {
		$cls = (int)$m['status'] === 1 ? 'little-bar-green' : 'little-bar-danger';
		$tip = hc2_dt($m['time'], 'd.m. H:i:s') . ' · ' . hc2_source_label($m['source'], $nodes) . ' · ' . ((int)$m['status'] === 1 ? 'OK' : hc2_reason_text($m['reason'])) . ((float)$m['latency_ms'] > 0 ? ' · ' . round((float)$m['latency_ms'], 1) . ' ms' : '') . ($m['message'] !== '' ? ' · ' . mb_substr($m['message'], 0, 80) : '');
		$out = '<div class="beat2 gros-bar ' . $cls . '" data-toggle="tooltip" data-placement="top" title="' . hc2_h($tip) . '"></div>' . $out;
	}
	return $out === '' ? '<span class="text-muted small">noch keine Messungen</span>' : $out;
}

/** Verfuegbarkeit in Prozent aus hc2_hourly (24 h), hc2_daily (30 d, 365 d). */
function hc2_availability(string $token): array {
	$pdo = hc2_pdo(); $out = array();
	foreach (array('24h' => array('hc2_hourly', 'hour', 24), '30d' => array('hc2_daily', 'day', 30), '1y' => array('hc2_daily', 'day', 365)) as $k => [$tbl, $col, $span]) {
		try {
			$unit = $tbl === 'hc2_hourly' ? 'HOUR' : 'DAY';
			$st = $pdo->prepare("SELECT SUM(count) c, SUM(up_count) u FROM $tbl WHERE token = :t AND $col >= UTC_TIMESTAMP() - INTERVAL $span $unit");
			$st->execute(array('t' => $token)); $r = $st->fetch(PDO::FETCH_ASSOC);
			$out[$k] = ($r && (int)$r['c'] > 0) ? round(100 * (int)$r['u'] / (int)$r['c'], 3) : null;
		} catch (Throwable $e) { $out[$k] = null; }
	}
	return $out;
}

// ---------------------------------------------------------------- Umhaengen (Testlauf)

/** Wire-Definition eines Checks (wie die Node sie dem hub schickt), optional mit abweichenden Feldern. */
function hc2_wire_def(array $c): array {
	return array('token' => $c['token'] ?? '', 'name' => $c['name'] ?? '', 'type' => $c['type'], 'target' => $c['target'] ?? '', 'params' => json_decode((string)($c['params'] ?? '{}')) ?: new stdClass(),
		'ip_mode' => $c['ip_mode'] ?? 'auto', 'connect_timeout_seconds' => ((int)($c['connect_timeout_ms'] ?? 5000)) / 1000, 'timeout_seconds' => ((int)($c['total_timeout_ms'] ?? 10000)) / 1000,
		'interval_seconds' => (int)($c['interval_sec'] ?? 60));
}

/**
 * Testlauf fuer ein Umhaengen anlegen: online/both -> die hubs messen je Standort; local/both -> Kommando test_check an die Node.
 * Liefert array('id' => ..., 'error' => '') .
 */
function hc2_testrun_create(int $userid, array $c, string $target, $nodeIds, array $locations): array {
	$acc = hc2_account($userid); $nodes = hc2_nodes($userid);
	$ids = array(); foreach ((array)$nodeIds as $x) { $x = (string)$x; if ($x !== '' && !in_array($x, $ids, true)) { $ids[] = $x; } }
	if (!in_array($target, array('local','online','both'), true)) { return array('id' => 0, 'error' => 'Ungültiger Ausführungsort.'); }
	if (hc2_single_node_type($c['type'])) { return array('id' => 0, 'error' => 'Docker- und Proxmox-Checks laufen nur lokal auf ihrer Node und sind nicht umhängbar.'); }
	$nodeId = null;
	if ($target !== 'online') {
		if (!$ids) { return array('id' => 0, 'error' => 'Keine Node gewählt.'); }
		foreach ($ids as $nid) {
			if (!isset($nodes[$nid])) { return array('id' => 0, 'error' => 'Node nicht gefunden oder getrennt.'); }
			$nl = hc2_node_label($nodes, $nid);
			if ((int)$nodes[$nid]['online'] !== 1) { return array('id' => 0, 'error' => 'Die Node ' . $nl . ' ist offline; der Testlauf braucht verbundene Nodes.'); }
			if ($nodes[$nid]['remote_mgmt'] === 'off') { return array('id' => 0, 'error' => 'Die Node ' . $nl . ' nimmt keine Befehle an (Fernverwaltung aus).'); }
		}
		$nodeId = in_array((string)$c['node_id'], $ids, true) ? (string)$c['node_id'] : $ids[0]; // Besitzer bleibt, solange gewaehlt
	}
	if ($target !== 'local') {
		if (hc2_private_target($c['type'], $c['target'])) { return array('id' => 0, 'error' => 'Online-Checks können keine privaten Ziele prüfen.'); }
		$locations = array_values(array_intersect($locations ?: array_keys(hc2_locations()), array_keys(hc2_locations())));
		if (!$locations) { $locations = array_keys(hc2_locations()); }
		$locations = array_slice($locations, 0, $acc['hc_locations']);
		$used = hc2_online_used($userid, $c['token']);
		if ($acc['healthcheck_limit'] > 0 && $used + count($locations) > $acc['healthcheck_limit']) { return array('id' => 0, 'error' => 'Online-Limit erreicht (' . $used . ' von ' . $acc['healthcheck_limit'] . ' Messstellen).'); }
	} else { $locations = array_keys(hc2_locations()); }
	$def = json_encode(hc2_wire_def($c), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
	$pdo = hc2_pdo();
	$pdo->prepare("INSERT INTO hc2_testruns (userid, token, definition, target_execution, node_id, nodes, locations, status, created_at) VALUES (:u, :t, :d, :e, :n, :ns, :l, 'pending', UTC_TIMESTAMP(3))")
		->execute(array('u' => $userid, 't' => $c['token'], 'd' => $def, 'e' => $target, 'n' => $nodeId, 'ns' => $target === 'online' ? '' : implode(',', $ids), 'l' => implode(',', $locations)));
	$id = (int)$pdo->lastInsertId();
	if ($target !== 'online') {
		foreach ($ids as $nid) { hc2_command($nid, 'test_check', array('definition' => json_decode($def), 'testrun_id' => $id, 'token' => $c['token'])); }
	}
	return array('id' => $id, 'error' => '');
}

/** Status eines Testlaufs; bei ok wird das Umhaengen genau einmal angewendet (result.applied). */
function hc2_testrun_status(int $userid, int $id): array {
	$pdo = hc2_pdo();
	$st = $pdo->prepare("SELECT * FROM hc2_testruns WHERE id = :i AND userid = :u"); $st->execute(array('i' => $id, 'u' => $userid));
	$t = $st->fetch(PDO::FETCH_ASSOC);
	if (!$t) { return array('status' => 'missing'); }
	$res = json_decode((string)$t['result'], true) ?: array();
	$out = array('id' => $id, 'status' => $t['status'], 'token' => $t['token'], 'target' => $t['target_execution'], 'results' => array(), 'applied' => !empty($res['applied']));
	$nodes = hc2_nodes($userid);
	foreach ($res as $k => $r) {
		if ($k === 'applied' || !is_array($r)) { continue; }
		$label = $k === 'node' ? (hc2_node_label($nodes, $t['node_id']) ?: 'Node') : (strncmp($k, 'node:', 5) === 0 ? (hc2_node_label($nodes, substr($k, 5)) ?: 'Node') : 'ipv64 ' . (hc2_locations()[$k] ?? $k));
		$msg = $r['error'] ?? '';
		if ($msg === '' && !empty($r['results']) && is_array($r['results'])) { $parts = array(); foreach ($r['results'] as $x) { $parts[] = ($x['family'] ?? '') . ' ' . ($x['status'] ?? '') . (isset($x['latency_ms']) ? ' ' . round((float)$x['latency_ms'], 1) . ' ms' : '') . (!empty($x['message']) ? ' (' . $x['message'] . ')' : ''); } $msg = implode(' | ', $parts); }
		$out['results'][] = array('source' => $label, 'ok' => !empty($r['ok']), 'message' => trim($msg));
	}
	if ($t['status'] === 'ok' && empty($res['applied'])) {
		$c = hc2_check($userid, $t['token']);
		if ($c) {
			$fields = array('execution' => $t['target_execution'], 'locations' => $t['locations']);
			if ($t['target_execution'] !== 'local' && $c['type'] !== 'push' && (int)$c['interval_sec'] < 20) { $fields['interval_sec'] = 20; } // ipv64 misst hoechstens alle 20 s
			if ($t['target_execution'] !== 'online') { $fields['node_id'] = $t['node_id']; $fields['nodes'] = (string)($t['nodes'] ?? '') !== '' ? $t['nodes'] : $t['node_id']; } else { $fields['nodes'] = ''; }
			hc2_set_check($userid, $t['token'], $fields);
		}
		$pdo->prepare("UPDATE hc2_testruns SET result = JSON_SET(COALESCE(result,'{}'), '$.applied', true) WHERE id = :i")->execute(array('i' => $id));
		$out['applied'] = true;
	}
	if ($t['status'] === 'expired') { $out['error'] = 'Keine Antwort innerhalb von 60 s (Node offline oder Standort nicht erreichbar).'; }
	return $out;
}

/** Kommando an eine Node (hc2_commands). */
function hc2_command(string $nodeId, string $name, array $args = array()): int {
	$pdo = hc2_pdo();
	$pdo->prepare("INSERT INTO hc2_commands (node_id, name, args, created_at) VALUES (:n, :c, :a, UTC_TIMESTAMP(3))")
		->execute(array('n' => $nodeId, 'c' => $name, 'a' => json_encode($args ?: new stdClass(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)));
	$id = (int)$pdo->lastInsertId();
	hc2_signal('hc2:node:' . $nodeId, 'command');
	return $id;
}

// ---------------------------------------------------------------- Kanaele (Benachrichtigungen)

/** Kanaltypen mit Feldern (wie Fields in der Node). secret => verschluesselt gespeichert. */
function hc2_channel_types(): array {
	return array(
		'ipv64_mail' => array('label' => 'E-Mail (ipv64)', 'icon' => 'fa-envelope', 'verify' => true, 'fields' => array(
			array('key' => 'email', 'label' => 'E-Mail-Adresse', 'required' => true, 'kind' => 'email'))),
		'ipv64_sms' => array('label' => 'SMS (ipv64)', 'icon' => 'fa-mobile-screen', 'verify' => true, 'fields' => array(
			array('key' => 'number', 'label' => 'Mobilnummer mit Ländervorwahl, z. B. +49 177 1234567 oder 0049 177 1234567', 'required' => true, 'kind' => 'text'))),
		'app' => array('label' => 'IPv64 App (Push)', 'icon' => 'fa-bell', 'fields' => array(
			array('key' => 'device_token', 'label' => 'Geräte-Token aus der App', 'required' => true, 'secret' => true, 'kind' => 'password'))),
		'telegram' => array('label' => 'Telegram', 'icon' => 'fa-paper-plane', 'fields' => array(
			array('key' => 'bot_token', 'label' => 'Bot-Token', 'required' => true, 'secret' => true, 'kind' => 'password'), array('key' => 'chat_id', 'label' => 'Chat-ID', 'required' => true, 'kind' => 'text'),
			array('key' => 'silent', 'label' => 'Lautlos senden', 'kind' => 'bool'))),
		'discord' => array('label' => 'Discord', 'icon' => 'fa-comments', 'fields' => array(
			array('key' => 'webhook_url', 'label' => 'Webhook-URL', 'required' => true, 'secret' => true, 'kind' => 'password'), array('key' => 'username', 'label' => 'Anzeigename (optional)', 'kind' => 'text'))),
		'slack' => array('label' => 'Slack', 'icon' => 'fa-hashtag', 'hint' => 'In Slack eine App mit „Incoming Webhooks“ anlegen, für den Kanal einen Webhook hinzufügen und die URL (https://hooks.slack.com/services/…) eintragen.', 'fields' => array(
			array('key' => 'webhook_url', 'label' => 'Webhook-URL', 'required' => true, 'secret' => true, 'kind' => 'password'))),
		'teams' => array('label' => 'Microsoft Teams', 'icon' => 'fa-people-group', 'hint' => 'Im Teams-Kanal „Workflows“ öffnen, Vorlage „Bei Empfang einer Webhookanforderung in einem Kanal posten“ wählen und die angezeigte URL eintragen (die alten Office-365-Connectoren gibt es seit Mai 2026 nicht mehr).', 'fields' => array(
			array('key' => 'webhook_url', 'label' => 'Workflow-URL', 'required' => true, 'secret' => true, 'kind' => 'password'))),
		'matrix' => array('label' => 'Matrix', 'icon' => 'fa-comment-dots', 'hint' => 'Eigenes Bot-Konto anlegen, in den Raum einladen und dessen Zugriffstoken (Element: Einstellungen → Hilfe & Info) sowie Raum-ID (!abc:matrix.org) oder Alias (#raum:matrix.org) eintragen.', 'fields' => array(
			array('key' => 'server', 'label' => 'Homeserver', 'required' => true, 'kind' => 'url', 'default' => 'https://matrix.org'), array('key' => 'token', 'label' => 'Zugriffstoken des Bot-Kontos', 'required' => true, 'secret' => true, 'kind' => 'password'),
			array('key' => 'room', 'label' => 'Raum-ID oder Alias, z. B. !abc123:matrix.org oder #alarme:matrix.org', 'required' => true, 'kind' => 'text'))),
		'ntfy' => array('label' => 'ntfy', 'icon' => 'fa-bullhorn', 'fields' => array(
			array('key' => 'server', 'label' => 'Server', 'required' => true, 'kind' => 'url', 'default' => 'https://ntfy.sh'), array('key' => 'topic', 'label' => 'Topic', 'required' => true, 'kind' => 'text'),
			array('key' => 'token', 'label' => 'Zugriffs-Token (optional)', 'secret' => true, 'kind' => 'password'), array('key' => 'user', 'label' => 'Benutzer (optional)', 'kind' => 'text'), array('key' => 'password', 'label' => 'Passwort (optional)', 'secret' => true, 'kind' => 'password'),
			array('key' => 'priority_down', 'label' => 'Priorität bei Störung', 'kind' => 'select', 'options' => array('1','2','3','4','5'), 'default' => '4'), array('key' => 'priority_up', 'label' => 'Priorität bei Entwarnung', 'kind' => 'select', 'options' => array('1','2','3','4','5'), 'default' => '3'))),
		'gotify' => array('label' => 'Gotify', 'icon' => 'fa-bullhorn', 'fields' => array(
			array('key' => 'server', 'label' => 'Server-URL', 'required' => true, 'kind' => 'url'), array('key' => 'app_token', 'label' => 'App-Token', 'required' => true, 'secret' => true, 'kind' => 'password'), array('key' => 'priority', 'label' => 'Priorität', 'kind' => 'number', 'default' => '5'))),
		'pushover' => array('label' => 'Pushover', 'icon' => 'fa-bell', 'fields' => array(
			array('key' => 'user_key', 'label' => 'User-Key', 'required' => true, 'secret' => true, 'kind' => 'password'), array('key' => 'app_token', 'label' => 'App-Token', 'required' => true, 'secret' => true, 'kind' => 'password'), array('key' => 'device', 'label' => 'Gerät (optional)', 'kind' => 'text'),
			array('key' => 'priority_down', 'label' => 'Priorität bei Störung', 'kind' => 'select', 'options' => array('-2','-1','0','1','2'), 'default' => '1'), array('key' => 'priority_up', 'label' => 'Priorität bei Entwarnung', 'kind' => 'select', 'options' => array('-2','-1','0','1','2'), 'default' => '0'))),
		'secntfy' => array('label' => 'SecNtfy (verschlüsselt)', 'icon' => 'fa-user-shield', 'hint' => 'Ende-zu-Ende verschlüsselte Push-Nachrichten: Titel und Text werden mit dem Schlüssel deines Geräts verschlüsselt. Geräte-Token (NTFY-DEVICE-…) aus der SecNtfy-App eintragen. Lange Meldungen kommen bei SecNtfy gekürzt an (Text höchstens 150 Zeichen).', 'fields' => array(
			array('key' => 'device_key', 'label' => 'Geräte-Token (NTFY-DEVICE-…)', 'required' => true, 'secret' => true, 'kind' => 'password'),
			array('key' => 'server', 'label' => 'Server', 'required' => true, 'kind' => 'url', 'default' => 'https://api.secntfy.app'),
			array('key' => 'critical', 'label' => 'Störungen als kritischen Alarm senden (kommt auch im Lautlos-Modus durch)', 'kind' => 'bool'))),
		'webhook' => array('label' => 'Webhook', 'icon' => 'fa-link', 'fields' => array(
			array('key' => 'url', 'label' => 'URL', 'required' => true, 'kind' => 'url'), array('key' => 'method', 'label' => 'Methode', 'kind' => 'select', 'options' => array('POST','PUT','GET'), 'default' => 'POST'),
			array('key' => 'headers', 'label' => 'Zusätzliche Header (eine je Zeile: Name: Wert)', 'kind' => 'textarea', 'secret' => true), array('key' => 'body', 'label' => 'Eigener Body (leer = JSON-Standard)', 'kind' => 'textarea'),
			array('key' => 'insecure_tls', 'label' => 'TLS-Fehler ignorieren', 'kind' => 'bool'))),
		'smtp' => array('label' => 'Eigener SMTP-Server', 'icon' => 'fa-envelope-open', 'fields' => array(
			array('key' => 'host', 'label' => 'Host', 'required' => true, 'kind' => 'text'), array('key' => 'port', 'label' => 'Port', 'kind' => 'number', 'default' => '587'),
			array('key' => 'security', 'label' => 'Verschlüsselung', 'kind' => 'select', 'options' => array('starttls','tls','none'), 'default' => 'starttls'),
			array('key' => 'user', 'label' => 'Benutzer', 'kind' => 'text'), array('key' => 'password', 'label' => 'Passwort', 'secret' => true, 'kind' => 'password'),
			array('key' => 'from', 'label' => 'Absender', 'required' => true, 'kind' => 'email'), array('key' => 'to', 'label' => 'Empfänger', 'required' => true, 'kind' => 'email'))),
	);
}

/** Kanaele des Accounts (Konfiguration entschluesselt, Geheimnisse als '' + has_secret-Liste). */
function hc2_channels(int $userid, bool $withSecrets = false): array {
	$st = hc2_pdo()->prepare("SELECT * FROM hc2_channels WHERE userid = :u AND deleted_at IS NULL ORDER BY name, id");
	$st->execute(array('u' => $userid));
	$out = array();
	foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $ch) {
		$cfg = json_decode((string)$ch['config_enc'], true) ?: array();
		$ch['config'] = array(); $ch['has_secret'] = array();
		foreach ($cfg as $k => $v) {
			if (is_string($v) && strncmp($v, 'enc:v1:', 7) === 0) { $ch['has_secret'][] = $k; $ch['config'][$k] = $withSecrets ? hc2_decrypt($v) : ''; }
			else { $ch['config'][$k] = $v; }
		}
		$ch['execution'] = $ch['node_id'] ? 'node' : 'server';
		$out[] = $ch;
	}
	return $out;
}
function hc2_channel(int $userid, int $id, bool $withSecrets = false): ?array {
	foreach (hc2_channels($userid, $withSecrets) as $ch) { if ((int)$ch['id'] === $id) { return $ch; } }
	return null;
}

/** Formular -> Konfiguration (Geheimnisse verschluesselt); liefert array('config_enc'=>json,'errors'=>[]). */
function hc2_channel_config(string $type, array $in, ?array $old): array {
	$types = hc2_channel_types(); $err = array(); $cfg = array();
	if (!isset($types[$type])) { return array('config_enc' => '{}', 'errors' => array('Unbekannter Kanaltyp.')); }
	foreach ($types[$type]['fields'] as $f) {
		$k = $f['key']; $v = $in['f_' . $k] ?? null;
		if (($f['kind'] ?? '') === 'bool') { if (!empty($v) && $v !== '0') { $cfg[$k] = 'true'; } continue; }
		$v = $v === null ? '' : trim((string)$v);
		if (($f['kind'] ?? '') === 'select' && !in_array($v, $f['options'], true)) { $v = $f['default'] ?? $f['options'][0]; }
		if ($v === '' && !empty($f['secret']) && $old && in_array($k, $old['has_secret'], true)) { $v = (string)($old['config'][$k] ?? ''); } // leer = unveraendert lassen
		if ($v === '' && isset($f['default'])) { $v = $f['default']; }
		if ($v === '' && !empty($f['required'])) { $err[] = $f['label'] . ' fehlt.'; }
		if ($v !== '' && ($f['kind'] ?? '') === 'email' && !filter_var($v, FILTER_VALIDATE_EMAIL)) { $err[] = $f['label'] . ' ist keine gültige E-Mail-Adresse.'; }
		if ($v !== '' && ($f['kind'] ?? '') === 'url' && !preg_match('#^https?://#i', $v)) { $err[] = $f['label'] . ' muss mit http:// oder https:// beginnen.'; }
		if ($v !== '' && $k === 'webhook_url' && in_array($type, array('slack', 'teams', 'discord'), true) && !preg_match('#^https://[^/\s]+/#i', $v)) { $err[] = $f['label'] . ' muss eine https-Adresse sein.'; }
		if ($type === 'matrix' && $k === 'room' && $v !== '' && !preg_match('/^[!#][^:\s]+:\S+$/', $v)) { $err[] = 'Raum bitte als Raum-ID (!abc:matrix.org) oder Alias (#raum:matrix.org) angeben.'; }
		if ($type === 'matrix' && $k === 'server') { $v = rtrim($v, '/'); }
		if ($type === 'secntfy' && $k === 'server') { $v = rtrim($v, '/'); }
		if ($type === 'secntfy' && $k === 'device_key' && $v !== '' && !preg_match('/^NTFY-DEVICE-[^\x00-\x20\x7f]+$/', $v)) { $err[] = 'Geräte-Token muss mit NTFY-DEVICE- beginnen.'; }
		if ($type === 'ipv64_sms' && $k === 'number') {
			$plus = strpos($v, '+') === 0; $v = preg_replace('/[^0-9]/', '', $v);
			if (!$plus && strpos($v, '0') === 0 && strpos($v, '00') !== 0) { $err[] = 'Mobilnummer bitte mit Ländervorwahl angeben, z. B. +49 177 1234567.'; }
			elseif (strlen($v) < 7 || strlen($v) > 20) { $err[] = 'Mobilnummer ungültig.'; }
		}
		if ($v !== '') { $cfg[$k] = !empty($f['secret']) ? hc2_encrypt($v) : $v; }
	}
	return array('config_enc' => json_encode($cfg ?: new stdClass(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), 'errors' => $err);
}

/** Signierter Aufruf an den hub (Portal-Endpunkte). Liefert array('ok'=>bool,'error'=>'',...). */
function hc2_hub_call(string $path, array $body): array {
	$secret = is_file(HC2_BRIDGE_SECRET_FILE) ? trim((string)file_get_contents(HC2_BRIDGE_SECRET_FILE)) : '';
	if ($secret === '') { return array('ok' => false, 'error' => 'Portal-Schlüssel fehlt (hc2_bridge.secret).'); }
	$body['ts'] = time();
	$raw = json_encode($body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
	$sig = hash_hmac('sha256', $raw, $secret);
	$last = 'kein hub erreichbar';
	foreach (explode(',', HC2_HUBS) as $hub) {
		$ch = curl_init(trim($hub) . $path);
		curl_setopt_array($ch, array(CURLOPT_POST => true, CURLOPT_POSTFIELDS => $raw, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 30, CURLOPT_CONNECTTIMEOUT => 5,
			CURLOPT_HTTPHEADER => array('Content-Type: application/json', 'X-HC2-Signature: ' . $sig, 'User-Agent: ipv64-portal')));
		$res = curl_exec($ch); $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE); $cerr = curl_error($ch); curl_close($ch);
		if ($res === false || $code === 502 || $code === 503 || $code === 504) { $last = $cerr !== '' ? $cerr : ('HTTP ' . $code); continue; }
		$j = json_decode((string)$res, true);
		if (!is_array($j)) { return array('ok' => false, 'error' => 'Unerwartete Antwort (HTTP ' . $code . ')'); }
		if ($code >= 400 && !isset($j['ok'])) { return array('ok' => false, 'error' => (string)($j['error'] ?? ('HTTP ' . $code))); }
		return $j;
	}
	return array('ok' => false, 'error' => $last);
}

/** Einstellungen des Accounts (hc2_settings) lesen/schreiben. */
function hc2_settings(int $userid): array {
	$st = hc2_pdo()->prepare("SELECT `key`, `value` FROM hc2_settings WHERE userid = :u"); $st->execute(array('u' => $userid));
	$o = array(); foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $r) { $o[$r['key']] = $r['value']; }
	return $o;
}
function hc2_set_setting(int $userid, string $key, string $value): void {
	hc2_pdo()->prepare("INSERT INTO hc2_settings (userid, `key`, `value`) VALUES (:u, :k, :v) ON DUPLICATE KEY UPDATE `value` = VALUES(`value`)")->execute(array('u' => $userid, 'k' => $key, 'v' => mb_substr($value, 0, 500)));
}

/** Kleine Seitenkopf-Navigation der neuen Seiten (kein Eintrag im Hauptmenue). */
function hc2_subnav(string $active): string {
	$items = array('index' => array(HC2_BASE . '/', 'fa-heart-pulse', 'Healthchecks'), 'incidents' => array(HC2_BASE . '/incidents.php', 'fa-triangle-exclamation', 'Störungen'),
		'maintenance' => array(HC2_BASE . '/maintenance.php', 'fa-wrench', 'Wartungsfenster'), 'notifications' => array('/notifications.php', 'fa-bell', 'Benachrichtigungen'), 'nodes' => array('/nodes.php', 'fa-server', 'Nodes'));
	$o = hc2_ui_assets() . '<ul class="nav nav-pills mb-3 hc2-subnav">';
	foreach ($items as $k => [$href, $ico, $label]) { $o .= '<li class="nav-item"><a class="nav-link' . ($k === $active ? ' active' : '') . '" href="' . $href . '"><i class="fa-solid ' . $ico . '"></i> ' . $label . '</a></li>'; }
	return $o . '</ul>';
}

/**
 * Optik wie im Node64-Container: Symbole vor den Eingabefeldern, farbige Knoepfe und Kartenkoepfe,
 * Tabellen mit Schatten. Einmal je Seite (ueber hc2_subnav), wirkt nur im Container der Unternavigation.
 */
function hc2_ui_assets(): string {
	static $done = false;
	if ($done) { return ''; }
	$done = true;
	return <<<'HTML'
<style>
.hc2-page .card { border-radius: .6rem; }
.hc2-page .card.shadow-sm, .hc2-page .table-responsive { box-shadow: 0 .125rem .35rem rgba(0,0,0,.08) !important; }
.hc2-page .card-header { background: rgba(0,0,0,.025); font-weight: 600; }
.hc2-page .card-header > i, .hc2-page .card-header > span > i { color: #007bff; margin-right: .2rem; }
.hc2-page .card-header .fa-bell { color: #e0a800 !important; }
.hc2-page .card-header .fa-clock, .hc2-page .card-header .fa-stopwatch { color: #17a2b8 !important; }
.hc2-page .card-header .fa-triangle-exclamation { color: #dc3545 !important; }
.hc2-page .card-header .fa-location-dot { color: #28a745 !important; }
.hc2-page .table-responsive { border: 1px solid rgba(0,0,0,.08); border-radius: .5rem; background: #fff; }
.hc2-page .table-responsive > .table { margin-bottom: 0; }
.hc2-page .table thead th { border-top: 0; font-size: .85rem; color: #6c757d; font-weight: 600; white-space: nowrap; }
.hc2-page .input-group-text { background: #f8f9fa; min-width: 2.4rem; justify-content: center; }
.hc2-page .input-group > .input-group-prepend > .input-group-text { border-right: 0; }
.hc2-page .input-group > .input-group-prepend + .form-control, .hc2-page .input-group > .input-group-prepend + .custom-select { border-left-color: #ced4da; }
.hc2-page label { font-weight: 500; font-size: .9rem; margin-bottom: .3rem; }
.hc2-page .form-control:focus, .hc2-page .custom-select:focus { box-shadow: 0 0 0 .15rem rgba(0,123,255,.18); }
.hc2-page .nav-pills .nav-link { border-radius: .5rem; }
.hc2-page .btn { border-radius: .4rem; }
/* Darkmode (css/darkmode.css setzt die Variablen): Tabellenflaeche, Kopfzeilen und Eingabe-Symbole nicht weiss */
html[data-theme="dark"] .hc2-page .table-responsive { background: var(--dm-bg2); border-color: var(--dm-border); box-shadow: 0 .125rem .35rem rgba(0,0,0,.5) !important; }
html[data-theme="dark"] .hc2-page .card-header { background: var(--dm-bg3); }
html[data-theme="dark"] .hc2-page .table thead th { color: var(--dm-muted); }
html[data-theme="dark"] .hc2-page .input-group-text { background: #2c333a; }
html[data-theme="dark"] .hc2-tbadge { background: var(--dm-bg3) !important; border-color: var(--dm-border) !important; color: var(--dm-text); }
html[data-theme="dark"] .hc2-page .input-group > .input-group-prepend + .form-control, html[data-theme="dark"] .hc2-page .input-group > .input-group-prepend + .custom-select { border-left-color: var(--dm-border); }
</style>
<script>
document.addEventListener('DOMContentLoaded', function () {
	var nav = document.querySelector('.hc2-subnav'); if (!nav) { return; }
	var page = nav.closest('.container, .container-fluid') || document.body; page.classList.add('hc2-page');
	// Symbol je Feld (wie im Container)
	var icons = { name: 'fa-tag text-primary', target: 'fa-bullseye text-danger', type: 'fa-shapes text-secondary', method: 'fa-right-left text-secondary',
		accept_status: 'fa-check-double text-success', keyword: 'fa-magnifying-glass text-primary', basic_user: 'fa-user text-secondary', basic_password: 'fa-key text-warning',
		count: 'fa-hashtag text-secondary', max_loss_percent: 'fa-percent text-warning', max_latency_ms: 'fa-gauge-high text-warning', port: 'fa-plug text-primary',
		send: 'fa-paper-plane text-secondary', expect: 'fa-reply text-secondary', expect_port: 'fa-door-open text-success', min_days: 'fa-calendar-days text-success',
		server_name: 'fa-server text-secondary', docker_host: 'fa-brands fa-docker text-primary', period_seconds: 'fa-clock text-info', grace_seconds: 'fa-hourglass-half text-warning',
		tags: 'fa-tags text-secondary', parent_token: 'fa-sitemap text-secondary', interval_sec: 'fa-stopwatch text-info', retry_interval_sec: 'fa-rotate text-warning',
		connect_timeout: 'fa-plug-circle-bolt text-secondary', total_timeout: 'fa-hourglass-end text-secondary', ip_mode: 'fa-network-wired text-primary',
		execution: 'fa-location-dot text-success', node_id: 'fa-server text-primary', policy: 'fa-scale-balanced text-secondary', retries: 'fa-repeat text-warning',
		stabilize: 'fa-wave-square text-info', repeat_minutes: 'fa-bell text-warning', start_at: 'fa-calendar-plus text-success', end_at: 'fa-calendar-xmark text-danger',
		repeat: 'fa-repeat text-secondary', repeat_until: 'fa-calendar-check text-secondary', email: 'fa-envelope text-primary', url: 'fa-link text-primary',
		server: 'fa-server text-primary', topic: 'fa-hashtag text-primary', token: 'fa-key text-warning', app_token: 'fa-key text-warning', user_key: 'fa-key text-warning',
		chat_id: 'fa-comments text-primary', bot_token: 'fa-robot text-warning', webhook_url: 'fa-link text-primary', priority: 'fa-flag text-warning', host: 'fa-server text-primary',
		username: 'fa-user text-secondary', password: 'fa-key text-warning', from: 'fa-at text-secondary', to: 'fa-at text-secondary', phone: 'fa-mobile-screen text-primary',
		location: 'fa-location-dot text-success', code: 'fa-qrcode text-primary', q: 'fa-magnifying-glass text-secondary', tag: 'fa-tag text-secondary' };
	page.querySelectorAll('input.form-control[name], select.custom-select[name], select.form-control[name]').forEach(function (el) {
		if (el.type === 'hidden' || el.closest('.input-group')) { return; }
		var key = el.name.replace(/\[\]$/, '').replace(/^cfg_|^config\[|\]$/g, ''), ic = icons[key];
		if (!ic) { return; }
		var g = document.createElement('div'); g.className = 'input-group' + (el.classList.contains('form-control-sm') || el.classList.contains('custom-select-sm') ? ' input-group-sm' : '');
		var pre = document.createElement('div'); pre.className = 'input-group-prepend';
		pre.innerHTML = '<span class="input-group-text"><i class="' + (ic.indexOf('fa-brands') === 0 ? '' : 'fa-solid ') + ic + '"></i></span>';
		if (el.style.width) { g.style.width = el.style.width; el.style.width = ''; }
		el.parentNode.insertBefore(g, el); g.appendChild(pre); g.appendChild(el);
	});
	// Knoepfe farbig wie im Container (Pause gelb, Fortsetzen gruen, Pruefen hellblau, Bearbeiten/Umhaengen blau)
	var colors = { 'fa-pause': 'warning', 'fa-play': 'success', 'fa-rotate': 'info', 'fa-arrows-rotate': 'info', 'fa-pen': 'primary', 'fa-right-left': 'primary', 'fa-paper-plane': 'info', 'fa-star': 'warning' };
	page.querySelectorAll('.btn-outline-secondary').forEach(function (b) {
		var i = b.querySelector('i'); if (!i) { return; }
		for (var k in colors) { if (i.classList.contains(k)) { b.classList.remove('btn-outline-secondary'); b.classList.add('btn-outline-' + colors[k]); break; } }
	});
});
</script>
HTML;
}

/** Pillen fuer viele Checks auf einmal. Liefert token => HTML.
 *  Je Check und Messstelle die letzten n ueber den Primaerschluessel (token, source, time) statt alle Messpunkte
 *  von 7 Tagen zu lesen und zu sortieren: im Lasttest (8 Tage Rohdaten) 2 ms statt 361 ms fuer 10 Checks. */
function hc2_pills_many(array $tokens, int $n, array $nodes): array {
	$out = array();
	if (!$tokens) { return $out; }
	$pdo = hc2_pdo(); $n = (int)$n; $tokens = array_values($tokens);
	$ph = implode(',', array_fill(0, count($tokens), '?'));
	$st = $pdo->prepare("SELECT token, source FROM hc2_check_states WHERE token IN ($ph)");
	$st->execute($tokens);
	$srcs = array(); foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $r) { $srcs[$r['token']][$r['source']] = true; }
	$parts = array();
	foreach ($tokens as $t) {
		foreach (array_keys(($srcs[$t] ?? array()) + array('push' => true)) as $src) { $parts[] = array($t, (string)$src); }
	}
	$rows = array();
	foreach (array_chunk($parts, 200) as $chunk) {
		$sql = implode(' UNION ALL ', array_fill(0, count($chunk), "(SELECT token, source, time, status, latency_ms, reason, message FROM hc2_measurements WHERE token = ? AND source = ? AND time > UTC_TIMESTAMP() - INTERVAL 7 DAY ORDER BY time DESC LIMIT $n)"));
		$st = $pdo->prepare($sql);
		$st->execute(array_merge(...$chunk));
		foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $m) { $rows[$m['token']][] = $m; }
	}
	$list = array();
	foreach ($rows as $t => $ms) {
		usort($ms, function($a, $b) { return strcmp($b['time'], $a['time']); });
		foreach (array_slice($ms, 0, $n) as $m) { $list[] = $m; }
	}
	foreach ($list as $m) {
		$cls = (int)$m['status'] === 1 ? 'little-bar-green' : 'little-bar-danger';
		$tip = hc2_dt($m['time'], 'd.m. H:i:s') . ' · ' . hc2_source_label($m['source'], $nodes) . ' · ' . ((int)$m['status'] === 1 ? 'OK' : hc2_reason_text($m['reason'])) . ((float)$m['latency_ms'] > 0 ? ' · ' . round((float)$m['latency_ms'], 1) . ' ms' : '');
		$out[$m['token']] = '<div class="beat2 gros-bar ' . $cls . '" data-toggle="tooltip" data-placement="top" title="' . hc2_h($tip) . '"></div>' . ($out[$m['token']] ?? '');
	}
	return $out;
}

// Ablaufdatum des HTTPS-Zertifikats aus Meldungen ("cert valid until JJJJ-MM-TT"), frühestes gewinnt
function hc2_cert_until($messages) {
	$best = null;
	foreach ((array)$messages as $m) {
		if (preg_match_all('/cert valid until (\d{4}-\d{2}-\d{2})/', (string)$m, $mm)) {
			foreach ($mm[1] as $d) { if ($best === null || $d < $best) { $best = $d; } }
		}
	}
	return $best;
}
function hc2_cert_badge($until) {
	if ($until === null) { return ''; }
	$days = (int)floor((strtotime($until . ' 00:00:00 UTC') - time()) / 86400);
	$cls = $days <= 7 ? 'danger' : ($days <= 21 ? 'warning' : 'success');
	return '<span class="badge badge-' . $cls . '" title="Zertifikat gültig bis ' . hc2_h(date('d.m.Y', strtotime($until))) . '"><i class="fa-solid fa-lock"></i> noch ' . $days . ' Tage</span>';
}
