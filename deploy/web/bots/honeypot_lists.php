<?php
/**
 * Honeypot64 (H4): Text-Listen aus den Proben der Sensoren (Plan Abschnitt 7), oeffentlich unter blocklists/.
 * Cron alle 6 Stunden, nur auf der Kommandozeile:
 *
 *   17 *\/6 * * *  php .../bots/honeypot_lists.php > /dev/null
 *
 *   php honeypot_lists.php               Ranglisten neu, Listen schreiben, index.json ("data"), Statistik-Cache, Aufraeumen
 *   php honeypot_lists.php --dry         nur rechnen und Zahlen ausgeben (schreibt keine Dateien)
 *   php honeypot_lists.php --out=/tmp/x  Listen zum Vergleichen nach /tmp/x (kein index.json, kein Cache, kein Aufraeumen)
 *
 * Dateien (je Zeile ein Eintrag, ohne Zaehlung, haeufigste zuerst; atomar geschrieben):
 *   ipv64_passwords.txt               Passwoerter (bis 10 000)      ipv64_passwords_sha1.txt  SHA-1, gross, sortiert
 *   ipv64_usernames.txt               Benutzernamen (bis 10 000)
 *   ipv64_bad_useragents.txt          User-Agents (bis 2 000)       ipv64_bad_useragents.nginx.map  map $http_user_agent $ipv64_bad_ua
 *   ipv64_attack_paths.txt            Pfade (bis 5 000)             ipv64_attack_paths.nginx.conf   location ~ "^(?:...)$" { return 403; }
 *   ipv64_ja4.txt                     JA4 fuer die CDN64-Server (bis 1 000, ohne Praefix, abzueglich CDN64_JA4_EXCLUDE, # = Kommentar)
 * Inhalt: hp_sample_top (honeypot/hp_stats_lib.php): 30 Tage, nur ab N Accounts, bereinigt (keine Steuer-/Bidi-Zeichen,
 * keine E-Mail-Adressen, keine zufaelligen/sehr langen Strings, keine Browser-User-Agents, keine Allerweltspfade).
 * Danach: Eintraege in index.json unter "data" (honeypot_lists_index.php) und hp_sample_contrib aelter als 35 Tage loeschen.
 */
if(php_sapi_name() !== 'cli') { exit; }
include(__DIR__ . "/../dbconnect.php");
require_once __DIR__ . '/../honeypot/hp_stats_lib.php';
require_once __DIR__ . '/honeypot_lists_index.php';
set_time_limit(900);
ini_set('memory_limit', '512M');

const HPL_CONTRIB_KEEP = 35;     // Tage hp_sample_contrib (Schwelle braucht 30)
const HPL_BATCH        = 10000;  // Zeilen je DELETE
const HPL_NGINX_TOKEN  = 3000;   // Bytes je regex-location (nginx: hoechstens 4096 je Parameter)
const CDN64_JA4_EXCLUDE = array(); // JA4 von Browsern und verbreiteten Bibliotheken, die nie auf ipv64_ja4.txt kommen (pflegt Dennis)

$OUT = realpath(__DIR__ . '/../blocklists');
$dry = false; $extern = false;
foreach($argv as $a) {
	if($a === '--dry') { $dry = true; }
	if(str_starts_with($a, '--out=')) { $OUT = rtrim(substr($a, 6), '/'); $extern = true; @mkdir($OUT, 0755, true); }
}
if($OUT === false OR !is_dir($OUT)) { fwrite(STDERR, "Ausgabeverzeichnis nicht gefunden\n"); exit(1); }
echo ($dry ? "*** DRY RUN ***\n" : "Ausgabe: $OUT\n");

/** Atomar schreiben (Temp-Datei im selben Ordner, dann umbenennen). */
function hpl_write(string $path, string $content): void {
	global $dry;
	if($dry) { return; }
	$tmp = $path . '.tmp.' . getmypid();
	if(file_put_contents($tmp, $content) !== strlen($content)) { @unlink($tmp); throw new RuntimeException("$path: schreiben fehlgeschlagen"); }
	chmod($tmp, 0644);
	if(!rename($tmp, $path)) { @unlink($tmp); throw new RuntimeException("$path: umbenennen fehlgeschlagen"); }
}

/** Zeichenkette fuer nginx in doppelten Anfuehrungszeichen (\ und " maskiert). */
function hpl_ngx(string $s): string { return '"' . str_replace(array('\\', '"'), array('\\\\', '\\"'), $s) . '"'; }

/** Schluessel einer nginx-map (exakter Vergleich): ~ (Regex), \ und die Sonderwoerter brauchen ein fuehrendes \. */
function hpl_ngx_key(string $s): string {
	$k = hpl_ngx($s);
	if($s[0] === '~' OR $s[0] === '\\' OR in_array(strtolower($s), array('default', 'hostnames', 'include', 'volatile'), true)) { $k = '"\\\\' . substr($k, 1); }
	return $k;
}

/** Pfad fuer die nginx-location: nur der Pfadteil, nur unkritische Zeichen, kein Allerweltspfad; sonst null. */
function hpl_ngx_path(string $p): ?string {
	$p = explode('#', explode('?', $p, 2)[0], 2)[0];
	if(!preg_match('#^/[A-Za-z0-9._~!&\'()*+,;=:@/-]*$#', $p) OR preg_match('#//|/\.\.?(/|$)#', $p) OR hps_generic_path($p)) { return null; }
	return $p;
}

$now = time();
$head = "# IPv64.net Honeypot64 - %s - generated " . gmdate('Y-m-d H:i') . " UTC - " . HPL_SOURCE . "\n# License: " . HPL_LICENSE . "\n";
try {
	[$active, $n] = hps_threshold($pdo, $now);
	$cnt = hps_rebuild_top($pdo, $n, $now);
	printf("Aktive Accounts (7 Tage): %d, Schwelle: %d Accounts in %d Tagen\n", $active, $n, HPS_DAYS);
	$top = array();
	foreach(array_keys(HPS_TOPKEYS) as $k) { $top[$k] = array_column(hps_all($pdo, "SELECT `text` FROM hp_sample_top WHERE kind = :k ORDER BY pos", array('k' => $k)), 'text'); }

	// Passwoerter, SHA-1 (wie HIBP: gross, sortiert), Benutzernamen
	hpl_write("$OUT/ipv64_passwords.txt", $top['pass'] ? implode("\n", $top['pass']) . "\n" : '');
	$sha = array_unique(array_map(fn($p) => strtoupper(sha1($p)), $top['pass']));
	sort($sha, SORT_STRING);
	hpl_write("$OUT/ipv64_passwords_sha1.txt", $sha ? implode("\n", $sha) . "\n" : '');
	hpl_write("$OUT/ipv64_usernames.txt", $top['user'] ? implode("\n", $top['user']) . "\n" : '');

	// User-Agents: Text und nginx-map (exakter Vergleich; nginx vergleicht ohne Gross-/Kleinschreibung -> doppelte weg)
	hpl_write("$OUT/ipv64_bad_useragents.txt", $top['ua'] ? implode("\n", $top['ua']) . "\n" : '');
	$map = sprintf($head, 'bad user agents (exact match)')
		. "# http {} block:   map_hash_max_size 4096; map_hash_bucket_size 512;   (long keys need a larger bucket size)\n"
		. "#                  include /etc/nginx/ipv64_bad_useragents.nginx.map;\n"
		. "# server {} block: if (\$ipv64_bad_ua) { return 403; }\n"
		. "map \$http_user_agent \$ipv64_bad_ua {\n\tdefault 0;\n";
	$seen = array(); $nua = 0;
	foreach($top['ua'] as $ua) {
		$l = strtolower($ua);
		if(isset($seen[$l])) { continue; }
		$seen[$l] = true; $nua++;
		$map .= "\t" . hpl_ngx_key($ua) . " 1;\n";
	}
	hpl_write("$OUT/ipv64_bad_useragents.nginx.map", $map . "}\n");

	// Pfade: Text und nginx-Snippet (regex-locations mit exaktem Vergleich, in Bloecken unter 4096 Bytes je Parameter)
	hpl_write("$OUT/ipv64_attack_paths.txt", $top['path'] ? implode("\n", $top['path']) . "\n" : '');
	$conf = sprintf($head, 'attack paths')
		. "# server {} block (before your own regex locations):  include /etc/nginx/ipv64_attack_paths.nginx.conf;\n"
		. "# Only for sites that do not serve these paths (e.g. not on WordPress: wp-login.php is listed). Review before use.\n";
	$paths = array();
	foreach($top['path'] as $p) { $x = hpl_ngx_path($p); if($x !== null) { $paths[$x] = true; } }
	$chunk = array(); $len = 0; $nloc = 0;
	$flush = function() use (&$chunk, &$len, &$conf, &$nloc) {
		if(!$chunk) { return; }
		$conf .= 'location ~ ' . hpl_ngx('^(?:' . implode('|', $chunk) . ')$') . " { return 403; }\n";
		$chunk = array(); $len = 0; $nloc++;
	};
	foreach(array_keys($paths) as $p) {
		$re = preg_quote((string)$p);
		if($len + strlen($re) * 2 + 1 > HPL_NGINX_TOKEN) { $flush(); }
		$chunk[] = $re; $len += strlen($re) * 2 + 1;
	}
	$flush();
	hpl_write("$OUT/ipv64_attack_paths.nginx.conf", $conf);

	// JA4 fuer die CDN64-Server (docs/PLAN-CDN64-SCHUTZ.md): nur ja4:-Eintraege der Rangliste, ohne Praefix
	$ja4 = array();
	foreach(hps_top($pdo, 'fp', 1000) as $x) { if(str_starts_with($x['value'], 'ja4:')) { $ja4[substr($x['value'], 4)] = true; } }
	$ja4 = array_values(array_diff(array_map('strval', array_keys($ja4)), CDN64_JA4_EXCLUDE));
	hpl_write("$OUT/ipv64_ja4.txt", sprintf($head, 'JA4 TLS fingerprints of attack tools (CDN64)') . "# One JA4 per line, most seen first, from several independent accounts in 30 days\n"
		. ($ja4 ? implode("\n", $ja4) . "\n" : ''));

	printf("Passwoerter %d, Benutzernamen %d, User-Agents %d (map %d), Pfade %d (nginx %d in %d locations), JA4 %d\n",
		count($top['pass']), count($top['user']), count($top['ua']), $nua, count($top['path']), count($paths), $nloc, count($ja4));

	if(!$dry AND !$extern) {
		// index.json: Eintraege unter "data" ersetzen (fehlt sie, kommen sie mit dem naechsten vollen Lauf des Generators hinein)
		$idx = is_file("$OUT/index.json") ? json_decode((string)file_get_contents("$OUT/index.json"), true) : null;
		if(is_array($idx) AND isset($idx['lists'])) {
			$idx['data'] = hpl_index_entries($OUT);
			hpl_write("$OUT/index.json", json_encode($idx, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n");
			echo "index.json: " . count($idx['data']) . " Text-Listen unter \"data\"\n";
		} else {
			echo "index.json fehlt oder ist ungueltig: Text-Listen kommen mit dem naechsten vollen Lauf von create_blocklists_v2.php hinein\n";
		}
		// Statistik-Cache neu (Ranglisten sind schon frisch)
		hps_overview($pdo, $OUT, true, false);
		// Beitraege je Account nur so lange wie noetig
		$cut = gmdate('Y-m-d', $now - HPL_CONTRIB_KEEP * 86400); $del = 0;
		foreach(array('cred', 'path', 'ua', 'payload', 'fp') as $k) {
			do { $c = hps_q($pdo, "DELETE FROM hp_sample_contrib WHERE kind = :k AND day < :d LIMIT " . HPL_BATCH, array('k' => $k, 'd' => $cut))->rowCount(); $del += $c; } while($c >= HPL_BATCH);
		}
		echo "hp_sample_contrib: $del Zeilen vor $cut geloescht\n";
	}
} catch(Throwable $e) {
	fwrite(STDERR, "honeypot_lists: " . $e->getMessage() . "\n");
	exit(1);
}
echo "Fertig" . ($dry ? " (nichts geschrieben)" : "") . "\n";
