<?php
/**
 * Honeypot64 – Statistik (Phase H4, Plan Abschnitt 10). Oeffentlich, ohne Menuelink; verlinkt aus "Secure".
 *
 *   stats.php                     Ueberblick fuer alle: Sensoren, Angriffe 24 h und Verlauf, Top 10 Ports/Arten,
 *                                 Groesse der Listen, Top 10 Benutzernamen/Passwoerter/Pfade/User-Agents/Fingerabdruecke (H6)
 *                                 Volle Seite (eingeloggt, Klasse ausser Standard, users.user_class != 1): Top 100,
 *                                 neu gelistete IPs heute, neue Pfade heute, Suche, CSV-Export
 *   stats.php?q=<text>&k=<art>    Suche in einer Rangliste (volle Seite; art: pass, user, path, ua, fp)
 *   stats.php?export=<art>        CSV (volle Seite; art: pass, user, path, ua, fp, ports, kinds, timeline, new_ips, new_paths, countries)
 *   &lang=en                      Englisch
 *
 * Daten aus dem Cache (honeypot/hp_stats_lib.php, hoechstens alle 10 Minuten neu); Ranglisten nur mit Eintraegen, die
 * mindestens N Accounts gemeldet haben. Keine Sensor-IPs, keine Accounts. Herkunft nach Land (IPs der v64 Blocklist, 30 Tage):
 * Flaggen als Emoji aus dem Code, volle Seite alle Laender, sonst Top 10.
 */
ob_start(); // CSV-Export: Ausgabe von header.php wieder verwerfen
include("../header.php");
echo '<link rel="stylesheet" href="flags.css?v=1">'; // Flaggen auch unter Windows
require_once __DIR__ . '/hp_stats_lib.php';

$hssEn = (($_GET['lang'] ?? '') === 'en');
function hss_t(string $de, string $en): string { global $hssEn; return $hssEn ? $en : $de; }
function hss_h($s): string { return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function hss_num($n): string { global $hssEn; return number_format((int)$n, 0, $hssEn ? '.' : ',', $hssEn ? ',' : '.'); }
function hss_url(array $q): string { global $hssEn; if($hssEn) { $q['lang'] = 'en'; } return 'stats.php' . ($q ? '?' . http_build_query($q) : ''); }
function hss_day(string $d): string { global $hssEn; return gmdate($hssEn ? 'm-d' : 'd.m.', (int)strtotime($d . ' UTC')); }
/** ISO (UTC) -> Ortszeit der Seite */
function hss_time($iso): string { global $hssEn; return $iso === null ? '–' : date($hssEn ? 'Y-m-d H:i' : 'd.m.Y H:i', (int)strtotime($iso)); }
/** Flagge als Emoji aus dem Laendercode (zwei Regional-Indicator-Zeichen) */
function hss_flag(string $cc): string { return preg_match('/^[A-Z]{2}$/', $cc) ? mb_chr(0x1F1E6 + ord($cc[0]) - 65, 'UTF-8') . mb_chr(0x1F1E6 + ord($cc[1]) - 65, 'UTF-8') : ''; }
/** Name des Landes (intl, falls vorhanden), sonst der Code */
function hss_country(string $cc): string { global $hssEn; $n = class_exists('Locale') ? (string)Locale::getDisplayRegion('und_' . $cc, $hssEn ? 'en' : 'de') : ''; return $n === '' ? $cc : $n; }
/** Tabelle einer Rangliste (Wert, Ereignisse, Accounts) */
function hss_table(array $rows, string $empty, bool $mono = true, int $start = 1): string {
	if(!$rows) { return '<p class="text-muted small p-3 mb-0">' . hss_h($empty) . '</p>'; }
	$s = '<div class="table-responsive"><table class="table table-sm table-striped mb-0 small"><thead><tr><th>#</th><th>' . hss_t('Wert', 'Value') . '</th><th class="text-right">'
		. hss_t('Ereignisse', 'Events') . '</th><th class="text-right" title="' . hss_t('verschiedene meldende Accounts', 'different reporting accounts') . '">Accounts</th></tr></thead><tbody>';
	foreach($rows as $i => $r) {
		$v = $mono ? '<code style="word-break:break-all">' . hss_h($r['value']) . '</code>' : hss_h($r['value']);
		$s .= '<tr><td class="text-muted">' . ($r['pos'] ?? $start + $i) . '</td><td>' . $v . '</td><td class="text-right">' . hss_num($r['events']) . '</td><td class="text-right">' . hss_num($r['accounts']) . '</td></tr>';
	}
	return $s . '</tbody></table></div>';
}

$hssUid = (isset($userid) AND (string)$userid !== '' AND (string)$userid !== '0') ? (int)$userid : 0;
$full = false; $contributor = false; $o = null;
try {
	if($hssUid > 0) {
		$c = hps_one($pdo, "SELECT user_class FROM users WHERE id = :u", array('u' => $hssUid));
		$full = ($c !== null && (int)$c['user_class'] !== 1);
		$contributor = hps_one($pdo, "SELECT 1 x FROM hp_sensors WHERE userid = :u AND last_seen >= :d LIMIT 1", array('u' => $hssUid, 'd' => hps_dt(time() - 7 * 86400))) !== null;
	}
	$o = hps_overview($pdo, dirname(__DIR__) . '/blocklists');
} catch(Throwable $e) {
	error_log('honeypot/stats.php: ' . $e->getMessage());
}

// ---------------------------------------------------------------- CSV-Export (volle Seite)
$exp = (string)($_GET['export'] ?? '');
$msg = '';
if($exp !== '' AND $o !== null) {
	$csv = null;
	if(!$full) {
		$msg = hss_t('Der Export gehört zur vollen Statistik (eingeloggt, alle Klassen außer Standard).', 'The export is part of the full statistics (logged in, all plans except Standard).');
	} elseif(isset(HPS_KEEP[$exp])) {
		try {
			$csv = array(array('rank', 'value', 'events', 'accounts', 'last_seen_utc'));
			foreach(hps_top($pdo, $exp, HPS_KEEP[$exp]) as $i => $r) { $csv[] = array($i + 1, $r['value'], $r['events'], $r['accounts'], $r['last_seen']); }
		} catch(Throwable $e) { error_log('honeypot/stats.php export: ' . $e->getMessage()); $csv = null; $msg = hss_t('Der Export ist gerade nicht verfügbar.', 'The export is currently not available.'); }
	} elseif($exp === 'ports') {
		$csv = array(array('service', 'port', 'events_7d'));
		foreach($o['top_ports'] as $r) { $csv[] = array($r['service'], $r['port'], $r['events']); }
	} elseif($exp === 'kinds') {
		$csv = array(array('kind', 'events_7d'));
		foreach($o['top_kinds'] as $r) { $csv[] = array($r['kind'], $r['events']); }
	} elseif($exp === 'timeline') {
		$csv = array(array('day_utc', 'events'));
		foreach($o['timeline'] as $r) { $csv[] = array($r['day'], $r['events']); }
	} elseif($exp === 'new_ips') {
		$csv = array(array('ip', 'score', 'accounts', 'kinds', 'lists', 'listed_since_utc', 'country'));
		foreach($o['new_ips_today']['items'] as $r) { $csv[] = array($r['ip'], $r['score'], $r['accounts'], implode(' ', $r['kinds']), implode(' ', $r['lists']), $r['listed_since'], $r['country'] ?? ''); }
	} elseif($exp === 'new_paths') {
		$csv = array(array('path', 'events', 'accounts'));
		foreach($o['new_paths_today'] as $r) { $csv[] = array($r['value'], $r['events'], $r['accounts']); }
	} elseif($exp === 'countries') {
		$csv = array(array('country', 'ips', 'events'));
		foreach($o['top']['countries'] ?? array() as $r) { $csv[] = array($r['country'], $r['ips'], $r['events']); }
	}
	if($csv !== null) {
		while(ob_get_level() > 0) { ob_end_clean(); }
		header('Content-Type: text/csv; charset=utf-8');
		header('Content-Disposition: attachment; filename="ipv64_honeypot_' . $exp . '_' . gmdate('Ymd') . '.csv"');
		header('Cache-Control: private, no-store');
		header('X-Content-Type-Options: nosniff');
		$f = fopen('php://output', 'w');
		foreach($csv as $i => $row) { fputcsv($f, $i === 0 ? $row : array_map('hps_csv_cell', $row), ',', '"', ''); }
		fclose($f);
		exit;
	}
}
ob_end_flush();

// ---------------------------------------------------------------- Suche (volle Seite)
$kinds = array('pass' => hss_t('Passwörter', 'Passwords'), 'user' => hss_t('Benutzernamen', 'Usernames'), 'path' => hss_t('Pfade', 'Paths'), 'ua' => 'User-Agents',
	'fp' => hss_t('Fingerabdrücke (JA4/HASSH)', 'Fingerprints (JA4/HASSH)'));
$q = mb_substr(trim((string)($_GET['q'] ?? '')), 0, 100);
$k = isset($kinds[$_GET['k'] ?? '']) ? (string)$_GET['k'] : 'pass';
$found = null;
if($full AND $q !== '') {
	try { $found = hps_search($pdo, $k, $q); }
	catch(Throwable $e) { error_log('honeypot/stats.php search: ' . $e->getMessage()); $msg = hss_t('Die Suche ist gerade nicht verfügbar.', 'The search is currently not available.'); }
}
$lim = $full ? HPS_TOP_FULL : HPS_TOP_PUBLIC;
?>
<p></p>
<div class="container">
	<div class="card mb-3"><div class="card-body">
		<a class="float-right small" href="<?php echo hss_h($hssEn ? 'stats.php' : 'stats.php?lang=en'); ?>"><?php echo $hssEn ? 'Deutsch' : 'English'; ?></a>
		<h4 class="mb-2"><i class="fa-solid fa-chart-line text-primary"></i> Honeypot64 – <?php echo hss_t('Statistik', 'Statistics'); ?>
			<span class="badge badge-<?php echo $full ? 'success' : 'secondary'; ?> align-middle small"><?php echo $full ? hss_t('volle Ansicht', 'full view') : hss_t('Überblick', 'overview'); ?></span></h4>
		<p class="mb-1"><?php echo hss_t('Viele kleine Node64-Sensoren melden Angriffe an IPv64.net. Daraus entstehen die <b>v64 Blocklist</b> und Listen mit Passwörtern, Benutzernamen, User-Agents und Pfaden der Angreifer – frei für alle als erste Verteidigungslinie.',
			'Many small Node64 sensors report attacks to IPv64.net. From these reports we build the <b>v64 Blocklist</b> and lists of attacker passwords, usernames, user agents and paths – free for everyone as a first line of defense.'); ?></p>
		<p class="mb-0 small text-muted"><?php echo hss_t('Ranglisten und Listen enthalten nur Einträge, die mindestens', 'Rankings and lists only contain entries reported by at least'); ?>
			<b><?php echo (int)($o['threshold']['accounts'] ?? 2); ?></b> <?php echo hss_t('unabhängige Accounts in den letzten 30 Tagen gemeldet haben; E-Mail-Adressen, zufällige Zeichenketten und Steuerzeichen sind entfernt.',
			'independent accounts in the last 30 days; e-mail addresses, random strings and control characters are removed.'); ?>
			<?php if(!$full) { echo hss_t('Volle Statistik (Top 100, neu gelistete IPs, neue Pfade, Suche, Export): eingeloggt mit allen Klassen außer Standard.', 'Full statistics (top 100, newly listed IPs, new paths, search, export): logged in with all plans except Standard.'); } ?></p>
	</div></div>

	<div class="card mb-3"><div class="card-body p-2 small"><i class="fa-solid fa-satellite-dish text-primary"></i>
		<?php if($contributor) { echo hss_t('Danke für deinen Beitrag! Deine Sensoren und dein Beitrag:', 'Thanks for contributing! Your sensors and your contribution:') . ' <a href="/honeypot/">/honeypot/</a>'; }
		else { echo hss_t('Selbst beitragen: Honeypot64 in Node64 einschalten (Anleitung unter', 'Contribute yourself: enable Honeypot64 in Node64 (guide at') . ' <a href="https://node64.de/docs/honeypot/" target="_blank" rel="noopener">node64.de/docs/honeypot/</a>)'
			. hss_t(', eigene Sensoren unter', ', your sensors at') . ' <a href="/honeypot/">/honeypot/</a>. ' . hss_t('Beitragende bekommen den Live-Stand der Listen.', 'Contributors get the live lists.'); } ?>
		· <?php echo hss_t('IP prüfen:', 'Check an IP:'); ?> <a href="/honeypot/ip.php<?php echo $hssEn ? '?lang=en' : ''; ?>">/honeypot/ip.php</a>
		· <i class="fa-solid fa-earth-europe text-danger"></i> <a href="/honeypot/live.php<?php echo $hssEn ? '?lang=en' : ''; ?>"><?php echo hss_t('Live-Karte', 'Live map'); ?></a></div></div>

<?php
if($msg !== '') { echo '<div class="alert alert-warning" role="alert">' . hss_h($msg) . '</div>'; }
if($o === null) {
	echo '<div class="alert alert-danger" role="alert">' . hss_t('Die Statistik ist gerade nicht verfügbar.', 'The statistics are currently not available.') . '</div></div>';
	include("../footer.php");
	exit;
}
$l = $o['lists'];
// Deckung: Anteil der v64-IPs, die auf keiner anderen Angreifer-Liste bei ipv64 stehen (hps_coverage)
$cv = $o['coverage'] ?? null; $cvSub = '';
if(is_array($cv) AND (int)$cv['ips'] > 0) {
	$cvTip = hss_num($cv['only_v64']) . ' ' . hss_t('von', 'of') . ' ' . hss_num($cv['ips']) . ' ' . hss_t('IPs stehen auf keiner anderen Angreifer-Liste bei IPv64.net', 'IPs are on no other attacker list at IPv64.net')
		. ' (' . implode(', ', $cv['lists']) . '), ' . hss_num($cv['on_other_lists']) . ' ' . hss_t('auch dort', 'also there');
	$cvSub = '<span title="' . hss_h($cvTip) . '"><b>' . (int)round(100 * $cv['only_v64'] / $cv['ips']) . ' %</b> ' . hss_t('nur bei uns, auf keiner anderen Blocklist', 'only here, on no other blocklist') . '</span>';
}
?>
	<div class="row">
		<?php foreach(array(array(hss_t('Sensoren aktiv (7 Tage)', 'Active sensors (7 days)'), hss_num($o['sensors']['active_7d']) . ' <small class="text-muted">/ ' . hss_num($o['sensors']['online']) . ' online</small>', 'fa-satellite-dish', 'success', ''),
			array(hss_t('Beitragende Accounts (7 Tage)', 'Contributing accounts (7 days)'), hss_num($o['threshold']['active_accounts_7d']), 'fa-users', 'secondary', ''),
			array(hss_t('Angriffe 24 h', 'Attacks 24 h'), hss_num($o['attacks_24h']['events']), 'fa-bug', 'primary', ''),
			array(hss_t('Angreifer-IPs 24 h', 'Attacker IPs 24 h'), hss_num($o['attacks_24h']['sources']), 'fa-earth-europe', 'info', ''),
			array(hss_t('v64 Blocklist (live)', 'v64 Blocklist (live)'), hss_num($l['v64'] ?? 0), 'fa-ban', 'danger', $cvSub)) as [$label, $val, $icon, $color, $sub]) { ?>
		<div class="col-6 col-md pb-3"><div class="card bg-light h-100" style="border-left:4px solid var(--<?php echo $color; ?>)"><div class="card-body p-2"><i class="fa-solid <?php echo $icon; ?> fa-2xl float-right pt-4 text-<?php echo $color; ?>"></i>
			<p class="lead m-0"><?php echo hss_h($label); ?></p><p class="card-text h3<?php echo $sub !== '' ? ' mb-0' : ''; ?>"><?php echo $val; ?></p>
			<?php if($sub !== '') { echo '<p class="small text-muted m-0">' . $sub . '</p>'; } ?>
		</div></div></div>
		<?php } ?>
	</div>

	<div class="card mb-3"><div class="card-header p-2"><i class="fa-solid fa-chart-column text-primary"></i> <?php echo hss_t('Angriffe je Tag (30 Tage, UTC)', 'Attacks per day (30 days, UTC)'); ?>
		<?php if($full) { ?><a class="float-right small" href="<?php echo hss_h(hss_url(array('export' => 'timeline'))); ?>">CSV</a><?php } ?></div>
		<div class="card-body p-2"><canvas id="hssTimeline" height="70"></canvas></div></div>

	<div class="row">
		<div class="col-12 col-lg-6 pb-3"><div class="card h-100"><div class="card-header p-2"><?php echo hss_t('Meistangegriffene Ports (7 Tage)', 'Most attacked ports (7 days)'); ?>
			<?php if($full) { ?><a class="float-right small" href="<?php echo hss_h(hss_url(array('export' => 'ports'))); ?>">CSV</a><?php } ?></div><div class="card-body p-2">
			<canvas id="hssPorts" height="160"></canvas>
			<?php if($full) { ?>
			<details class="small mt-2"><summary><?php echo hss_t('Tabelle', 'Table'); ?> (<?php echo count($o['top_ports']); ?>)</summary><table class="table table-sm mb-0"><tbody>
			<?php foreach($o['top_ports'] as $p) { echo '<tr><td>' . (int)$p['port'] . ' <small class="text-muted">' . hss_h($p['service']) . '</small></td><td class="text-right">' . hss_num($p['events']) . '</td></tr>'; } ?>
			</tbody></table></details>
			<?php } ?>
		</div></div></div>
		<div class="col-12 col-lg-6 pb-3"><div class="card h-100"><div class="card-header p-2"><?php echo hss_t('Arten (7 Tage)', 'Kinds (7 days)'); ?>
			<?php if($full) { ?><a class="float-right small" href="<?php echo hss_h(hss_url(array('export' => 'kinds'))); ?>">CSV</a><?php } ?></div><div class="card-body p-0">
			<table class="table table-sm table-striped mb-0 small"><tbody>
			<?php if(!$o['top_kinds']) { echo '<tr><td class="text-muted p-3">' . hss_t('Noch keine Daten.', 'No data yet.') . '</td></tr>'; }
			foreach(array_slice($o['top_kinds'], 0, $lim) as $x) { echo '<tr><td><code>' . hss_h($x['kind']) . '</code></td><td class="text-right">' . hss_num($x['events']) . '</td></tr>'; } ?>
			</tbody></table>
		</div></div></div>
	</div>

<?php $hssC = $o['top']['countries'] ?? array(); $hssCmax = $hssC ? max(1, $hssC[0]['ips']) : 1; $hssCsum = max(1, array_sum(array_column($hssC, 'ips'))); ?>
	<div class="card mb-3"><div class="card-header p-2"><i class="fa-solid fa-earth-europe text-primary"></i> <?php echo hss_t('Herkunft nach Land', 'Origin by country'); ?>
		<small class="text-muted">(<?php echo hss_t('IPs der v64 Blocklist mit Sichtung in 30 Tagen', 'IPs on the v64 Blocklist seen in the last 30 days'); ?><?php if(!$full AND count($hssC) > HPS_TOP_PUBLIC) { echo ', Top ' . HPS_TOP_PUBLIC; } ?>)</small>
		<?php if($full) { ?><a class="float-right small" href="<?php echo hss_h(hss_url(array('export' => 'countries'))); ?>">CSV</a><?php } ?></div>
		<div class="card-body p-0"><?php if(!$hssC) { echo '<p class="text-muted small p-3 mb-0">' . hss_t('Noch keine Daten.', 'No data yet.') . '</p>'; } else { ?>
		<div class="table-responsive"><table class="table table-sm mb-0 small"><thead><tr><th>#</th><th><?php echo hss_t('Land', 'Country'); ?></th><th style="width:40%"></th>
			<th class="text-right">IPs</th><th class="text-right"><?php echo hss_t('Ereignisse', 'Events'); ?></th></tr></thead><tbody>
		<?php foreach(($full ? $hssC : array_slice($hssC, 0, HPS_TOP_PUBLIC)) as $i => $x) {
			$w = max(1, (int)round(100 * $x['ips'] / $hssCmax)); $hue = (int)round(45 - 45 * $x['ips'] / $hssCmax); // groesste rot, kleine gelb
			echo '<tr><td class="text-muted">' . ($i + 1) . '</td><td style="white-space:nowrap"><span style="font-size:1.25em">' . hss_flag($x['country']) . '</span> ' . hss_h(hss_country($x['country']))
				. (hss_country($x['country']) !== $x['country'] ? ' <small class="text-muted">' . hss_h($x['country']) . '</small>' : '') . '</td><td class="align-middle"><div title="' . hss_h(round(100 * $x['ips'] / $hssCsum, 1) . ' %')
				. '" style="height:.7rem;border-radius:3px;width:' . $w . '%;background:hsl(' . $hue . ',80%,50%)"></div></td><td class="text-right">' . hss_num($x['ips'])
				. '</td><td class="text-right">' . hss_num($x['events']) . '</td></tr>';
		} ?>
		</tbody></table></div><?php } ?>
		<p class="small text-muted px-2 py-1 mb-0"><?php echo hss_t('IP-Länderdaten:', 'IP country data:'); ?> <a href="https://db-ip.com" target="_blank" rel="noopener">DB-IP.com</a></p></div></div>

	<div class="card mb-3"><div class="card-header p-2"><i class="fa-solid fa-list text-primary"></i> <?php echo hss_t('Listen', 'Lists'); ?>
		<small class="text-muted">– <?php echo hss_t('frei, Lizenz CC BY 4.0, ohne Gewähr', 'free, license CC BY 4.0, provided as is'); ?></small></div>
		<div class="card-body p-0"><div class="table-responsive"><table class="table table-sm mb-0 small"><tbody>
		<tr><td><a href="/v64_blocklists">v64 Blocklist</a> <small class="text-muted">(<?php echo hss_t('IPs, Tagesstand frei, Live-Stand für Beitragende und Klassen ab VIP', 'IPs, daily list free, live list for contributors and plans from VIP'); ?>)</small></td>
			<td class="text-right"><?php echo hss_num($l['v64'] ?? 0); ?></td></tr>
		<?php foreach(HPL_DATA_LISTS as $id => [$name, $desc, $main, $more]) { ?>
		<tr><td><a href="/blocklists/<?php echo hss_h($main); ?>" target="_blank" rel="noopener"><?php echo hss_h($main); ?></a>
			<?php foreach($more as $f) { echo ' · <a href="/blocklists/' . hss_h($f) . '" target="_blank" rel="noopener">' . hss_h($f) . '</a>'; } ?></td>
			<td class="text-right"><?php echo isset($l[$id]) ? hss_num($l[$id]) : '–'; ?></td></tr>
		<?php } ?>
		</tbody></table></div>
		<p class="small text-muted p-2 mb-0"><?php echo hss_t('Passwort-/Benutzerlisten alle 6 Stunden, je Zeile ein Eintrag (häufigste zuerst). Alle Listen mit Anzahl und Stand:', 'Password/username lists every 6 hours, one entry per line (most used first). All lists with count and update:'); ?>
			<a href="/blocklists/index.json" target="_blank" rel="noopener">index.json</a></p></div>

<?php if($full) { ?>
	<div class="card mb-3"><div class="card-body p-2">
		<form class="form-inline" method="get" action="stats.php">
			<?php if($hssEn) { ?><input type="hidden" name="lang" value="en"><?php } ?>
			<label class="mr-2 small" for="hssQ"><i class="fa-solid fa-magnifying-glass"></i> <?php echo hss_t('Suche', 'Search'); ?></label>
			<select name="k" class="form-control form-control-sm mr-2"><?php foreach($kinds as $kk => $kn) { echo '<option value="' . $kk . '"' . ($kk === $k ? ' selected' : '') . '>' . hss_h($kn) . '</option>'; } ?></select>
			<input id="hssQ" type="text" name="q" maxlength="100" class="form-control form-control-sm mr-2" value="<?php echo hss_h($q); ?>" placeholder="<?php echo hss_t('z. B. admin', 'e.g. admin'); ?>">
			<button class="btn btn-sm btn-primary" type="submit"><?php echo hss_t('Suchen', 'Search'); ?></button>
		</form>
		<?php if($found !== null) { echo '<div class="mt-2">' . hss_table($found, hss_t('Nichts gefunden (nur Einträge ab der Schwelle).', 'Nothing found (only entries above the threshold).')) . '</div>'; } ?>
	</div></div>
<?php } ?>

	<div class="row">
		<?php foreach(array('user' => 'usernames', 'pass' => 'passwords', 'path' => 'paths', 'ua' => 'user_agents', 'fp' => 'fingerprints') as $kk => $key) { ?>
		<div class="col-12 col-lg-6 pb-3"><div class="card h-100"><div class="card-header p-2"><?php echo hss_t('Top', 'Top') . ' ' . $lim . ' ' . hss_h($kinds[$kk]); ?> <small class="text-muted">(30 <?php echo hss_t('Tage', 'days'); ?>)</small>
			<?php if($full) { ?><a class="float-right small" href="<?php echo hss_h(hss_url(array('export' => $kk))); ?>">CSV</a><?php } ?></div>
			<div class="card-body p-0"><?php echo hss_table(array_slice($o['top'][$key] ?? array(), 0, $lim), hss_t('Noch keine Einträge über der Schwelle.', 'No entries above the threshold yet.')); ?></div></div></div>
		<?php } ?>
	</div>

<?php if($full) { $ni = $o['new_ips_today']; ?>
	<div class="card mb-3"><div class="card-header p-2"><i class="fa-solid fa-user-secret text-danger"></i> <?php echo hss_t('Neu gelistet heute (UTC)', 'Newly listed today (UTC)'); ?>
		<span class="badge badge-secondary"><?php echo hss_num($ni['count']); ?></span>
		<a class="float-right small" href="<?php echo hss_h(hss_url(array('export' => 'new_ips'))); ?>">CSV</a></div>
		<div class="card-body p-0"><?php if(!$ni['items']) { echo '<p class="text-muted small p-3 mb-0">' . hss_t('Heute noch keine neuen IPs.', 'No new IPs today yet.') . '</p>'; } else { ?>
		<div class="table-responsive"><table class="table table-sm table-striped mb-0 small"><thead><tr><th>IP</th><th><?php echo hss_t('Land', 'Country'); ?></th><th class="text-right">Score</th><th class="text-right">Accounts</th><th><?php echo hss_t('Arten', 'Kinds'); ?></th><th><?php echo hss_t('Listen', 'Lists'); ?></th><th><?php echo hss_t('seit', 'since'); ?></th></tr></thead><tbody>
		<?php foreach($ni['items'] as $x) {
			echo '<tr><td><a href="/honeypot/ip.php?' . hss_h(http_build_query(array('ip' => $x['ip']) + ($hssEn ? array('lang' => 'en') : array()))) . '"><code>' . hss_h($x['ip']) . '</code></a></td><td style="white-space:nowrap">' . (($cc = (string)($x['country'] ?? '')) !== ''
				? '<span style="font-size:1.25em" title="' . hss_h(hss_country($cc)) . '">' . hss_flag($cc) . '</span> <small class="text-muted">' . hss_h($cc) . '</small>' : '<span class="text-muted">–</span>')
				. '</td><td class="text-right">' . (int)$x['score']
				. '</td><td class="text-right">' . (int)$x['accounts'] . '</td><td>' . hss_h(implode(', ', $x['kinds'])) . '</td><td>' . hss_h(implode(', ', $x['lists'])) . '</td><td>' . hss_h(hss_time($x['listed_since'])) . '</td></tr>';
		} ?>
		</tbody></table></div><?php } ?></div></div>

	<div class="card mb-3"><div class="card-header p-2"><i class="fa-solid fa-route text-warning"></i> <?php echo hss_t('Neue Pfade heute (erstmals gesehen, UTC)', 'New paths today (first seen, UTC)'); ?>
		<a class="float-right small" href="<?php echo hss_h(hss_url(array('export' => 'new_paths'))); ?>">CSV</a></div>
		<div class="card-body p-0"><?php echo hss_table($o['new_paths_today'], hss_t('Heute noch keine neuen Pfade über der Schwelle.', 'No new paths above the threshold today yet.')); ?></div></div>
<?php } ?>

	<?php if(!$contributor) { $node64_hint = hss_t('Selbst mitmachen: Honeypot64 ist ein Modul von Node64, dem Homelab-Container von ipv64.net.', 'Join in: Honeypot64 is a module of Node64, the homelab container by ipv64.net.');
		$node64_hint_btn = hss_t('Mehr zu Node64', 'More about Node64'); $node64_hint_href = $hssEn ? '/node64.php?lang=en' : '/node64.php'; include("../node64_hint.php"); } ?>
	<p class="small text-muted"><?php echo hss_t('Stand', 'As of'); ?> <?php echo hss_h(hss_time($o['generated_at'])); ?> (<?php echo hss_t('höchstens alle 10 Minuten neu', 'refreshed at most every 10 minutes'); ?>).
		<?php echo hss_t('Veröffentlicht werden nur Statistiken und bewertete Listen; IPs der Sensoren und meldende Accounts bleiben intern.', 'Only statistics and rated lists are published; sensor IPs and reporting accounts stay internal.'); ?>
		API: <code>GET https://ipv64.net/api/v2/threat/stats</code></p>
</div>
<script src="/js/chartjs/dist/chart.min.js"></script>
<script>
(function() {
	if(typeof Chart === 'undefined') { return; }
	var tl = <?php echo json_encode($o['timeline'], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); ?>;
	var ports = <?php echo json_encode(array_slice($o['top_ports'], 0, HPS_TOP_PUBLIC), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); ?>;
	var lbl = <?php echo json_encode(hss_t('Angriffe', 'Attacks'), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); ?>;
	new Chart(document.getElementById('hssTimeline'), {type: 'bar', data: {labels: tl.map(function(x) { return x.day.substr(5); }),
		datasets: [{label: lbl, data: tl.map(function(x) { return x.events; }), backgroundColor: 'rgba(0, 123, 255, 0.6)'}]},
		options: {responsive: true, plugins: {legend: {display: false}}, scales: {y: {beginAtZero: true}}}});
	new Chart(document.getElementById('hssPorts'), {type: 'bar', data: {labels: ports.map(function(x) { return x.port + ' (' + x.service + ')'; }),
		datasets: [{label: lbl, data: ports.map(function(x) { return x.events; }), backgroundColor: 'rgba(220, 53, 69, 0.6)'}]},
		options: {indexAxis: 'y', responsive: true, plugins: {legend: {display: false}}, scales: {x: {beginAtZero: true}}}});
})();
</script>
<?php include("../footer.php"); ?>
