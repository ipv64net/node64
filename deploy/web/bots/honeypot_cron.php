<?php
/**
 * Honeypot64: ein Cron fuer alle Honeypot-Jobs. Ersetzt die einzelnen Zeilen; neue Jobs kommen nur noch hier dazu.
 *
 *   * * * * * php8.4 /var/www/ipv64.net/web/bots/honeypot_cron.php > /dev/null 2>&1
 *
 * Laeuft jede Minute, startet die faelligen Jobs im Hintergrund (jeder Job hat seine eigene Sperre und laeuft nicht
 * doppelt). Zeiten wie bisher: Minute/Stunde, "*" = jede, Liste mit Komma, "*\/n" = alle n.
 *   php honeypot_cron.php --list           Jobs und naechste Faelligkeit anzeigen
 *   php honeypot_cron.php --run=<name>     einen Job sofort starten (im Vordergrund, mit Ausgabe)
 */
if(php_sapi_name() !== 'cli') { exit; }
chdir(__DIR__); // wie bisher "cd .../bots"

// name => array(Minute, Stunde, Datei relativ zu bots/, Argumente, danach (optional, nur wenn erfolgreich))
const HPC_JOBS = array(
	'score'   => array('7,37', '*',   'blocklist/honeypot_score.php',      '', array('blocklist/create_blocklists_v2.php', '--only=v64')),
	'watch'   => array('12,42', '*',  'honeypot_watch.php',                '', null),
	'release' => array('15', '*',     'honeypot_release.php',              '', null),
	'lists'   => array('17', '*/6',   'honeypot_lists.php',                '', null),
	'pwrange' => array('27', '*/6',   'honeypot_passwords.php',            '', null), // H6: Passwortpruefung (hp_pw_range)
	'cleanup' => array('40', '3',     'honeypot_cleanup.php',              '', null),
	'unlock'  => array('*/5', '*',    'limits_unlock.php',                 '', null), // Limits nach Klassenaenderung freigeben
	'weekly'  => array('5', '*',      '../weekly_report/cron.php',         '', null), // Wochenbericht, verteilt ueber die Woche (6–21 Uhr)
	'cdn64old' => array('23', '*',    'cdn64_orphans.php',                 '', null), // CDN64: Tunnel 14 Tage ohne Verbindung entfernen
	'live'    => array('*/2', '*',    'honeypot_live.php',                 '', null), // Live-Karte: honeypot/live.json (letzte Stunde)
	'hc2fix'  => array('*/10', '*',   'hc2_single_repair.php',             '', null), // Docker/Proxmox nie online: zurueck auf ihre Node
	's64plan'  => array('*/5', '*',   'sonar_plan.php',                    '', null), // Sonar64: Messplaene, Erreichbarkeit
	's64out'   => array('2,7,12,17,22,27,32,37,42,47,52,57', '*', 'sonar_outages.php', '', null), // Sonar64: Stoerungen nach ASN/Region
	's64roll'  => array('4', '*',     'sonar_rollup.php',                  '', null), // Sonar64: Stunden je Paar, Tage je ASN
	's64trust' => array('21', '*',    'sonar_trust.php',                   '', null), // Sonar64: Pruefungen stuendlich, Stufen taeglich (02 Uhr UTC)
	's64clean' => array('45', '3',    'sonar_cleanup.php',                 '', null), // Sonar64: Aufbewahrung
);

function hpc_match(string $spec, int $v): bool {
	if($spec === '*') { return true; }
	if(str_starts_with($spec, '*/')) { $n = (int)substr($spec, 2); return $n > 0 AND $v % $n === 0; }
	return in_array($v, array_map('intval', explode(',', $spec)), true);
}

function hpc_cmd(string $file, string $args): string {
	return escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/' . $file) . ($args !== '' ? ' ' . $args : '');
}

function hpc_line(array $j): string {
	$c = hpc_cmd($j[2], $j[3]);
	if($j[4]) { $c .= ' && ' . hpc_cmd($j[4][0], $j[4][1]); }
	return $c;
}

$opt = getopt('', array('list', 'run:'));
if(isset($opt['list'])) {
	foreach(HPC_JOBS as $n => $j) { printf("%-8s Minute %-6s Stunde %-4s %s\n", $n, $j[0], $j[1], hpc_line($j)); }
	exit(0);
}
if(isset($opt['run'])) {
	$j = HPC_JOBS[$opt['run']] ?? null;
	if(!$j) { fwrite(STDERR, "unbekannter Job\n"); exit(1); }
	passthru(hpc_line($j), $rc);
	exit($rc);
}

$t = getdate();
foreach(HPC_JOBS as $n => $j) {
	if(!hpc_match($j[0], $t['minutes']) OR !hpc_match($j[1], $t['hours'])) { continue; }
	if(!is_file(__DIR__ . '/' . $j[2])) { continue; } // Job noch nicht hochgeladen
	exec('(' . hpc_line($j) . ') > /dev/null 2>&1 &');
}
