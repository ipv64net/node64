<?php
/**
 * Herkunft nach Standort: country_ranges.txt.gz aus DB-IP "IP to Country Lite" (monatlich, CC BY 4.0, Namensnennung
 * "IP-Länderdaten: DB-IP.com" mit Link auf https://db-ip.com), eingebunden von create_blocklists_v2.php (voller Lauf,
 * kein eigener Cron). Die RIR-Daten nennen das Land des Inhabers einer Zuteilung (Hoster mit Rechenzentren im Ausland
 * stehen dort mit ihrem Firmensitz), DB-IP den Standort - wichtig fuer Statistik, Weltkarte und Live-Karte.
 * Luecken (Adressen ohne Land bei DB-IP) fuellen die RIR-Daten.
 *
 * Die Datei des laufenden Monats wird einmal geladen (Versuch hoechstens alle GDB_RETRY Sekunden) und im
 * Zwischenspeicher behalten; fehlt sie oder ist sie unbrauchbar, gilt die naechstaeltere (eine unbrauchbare wird
 * geloescht und spaeter neu geladen). Ohne gueltige Datei: null (der Generator nimmt
 * dann wie bisher nur die RIR-Daten). Die Laender-Blocklisten selbst bleiben bei den RIR-Daten.
 * Bereiche intern gepackt wie geo_key (erste IP . letzte IP . Land, IPv4 10 Byte, IPv6 34 Byte) - wenig Speicher.
 * Nur Konstanten und Funktionen; braucht geo_next aus dem Generator.
 */

const GDB_URL         = 'https://download.db-ip.com/free/dbip-country-lite-%s.csv.gz'; // %s = JJJJ-MM
const GDB_RETRY       = 6 * 3600;        // fehlgeschlagenen Abruf fruehestens danach wiederholen
const GDB_TIMEOUT     = 300;
const GDB_MAX_BYTES   = 64 << 20;        // gepackte Datei
const GDB_MIN_V4      = 50000;           // so viele IPv4-Bereiche muss die Datei mindestens liefern
const GDB_MAX_LINES   = 1900000;         // Node64 liest hoechstens 2 Mio. Zeilen
const GDB_SOURCE      = 'DB-IP IP to Country Lite (https://db-ip.com), gaps from RIR delegated-extended statistics';
const GDB_LICENSE     = 'CC BY 4.0';
const GDB_ATTRIBUTION = 'IP-Länderdaten: DB-IP.com (https://db-ip.com)';

/** Datei des Monats laden (gzip pruefen), atomar ablegen; true bei Erfolg */
function gdb_download(string $month, string $path): bool
{
	$tmp = $path.'.tmp';
	$fh = fopen($tmp, 'wb');
	if($fh === false) { return false; }
	$c = curl_init();
	curl_setopt_array($c, array(
		CURLOPT_URL => sprintf(GDB_URL, $month),
		CURLOPT_FILE => $fh,
		CURLOPT_FOLLOWLOCATION => true,
		CURLOPT_MAXREDIRS => 5,
		CURLOPT_CONNECTTIMEOUT => 15,
		CURLOPT_TIMEOUT => GDB_TIMEOUT,
		CURLOPT_FAILONERROR => true,
		CURLOPT_USERAGENT => 'IPv64.net-Blocklists/1.0 (+https://ipv64.net/v64_blocklists)',
		CURLOPT_NOPROGRESS => false,
		CURLOPT_XFERINFOFUNCTION => function($ch, $dt, $dn) { return $dn > GDB_MAX_BYTES ? 1 : 0; }, // abbrechen, wenn zu gross
	));
	$ok = curl_exec($c) === true;
	curl_close($c);
	fclose($fh);
	if($ok) {
		$g = gzopen($tmp, 'rb');
		$first = $g !== false ? gzgets($g) : false;
		if($g !== false) { gzclose($g); }
		$ok = (is_string($first) && str_contains($first, ',')); // Inhalt prueft gdb_ranges
	}
	if(!$ok) { @unlink($tmp); return false; }
	chmod($tmp, 0644);
	return rename($tmp, $path);
}

/** Dateien im Zwischenspeicher, neueste zuerst (laufenden Monat bei Bedarf laden), aeltere als die zwei neuesten loeschen */
function gdb_files(string $dir, bool $fetch): array
{
	if(!is_dir($dir)) { @mkdir($dir, 0750, true); }
	$month = gmdate('Y-m');
	$want = "$dir/dbip-country-lite-$month.csv.gz";
	$mark = "$dir/last_try";
	if($fetch AND !is_file($want) AND (!is_file($mark) OR time() - filemtime($mark) > GDB_RETRY)) {
		@touch($mark);
		echo gdb_download($month, $want) ? "Herkunft: DB-IP $month geladen\n" : "Herkunft: DB-IP $month nicht geladen (alte Datei gilt weiter)\n";
	}
	$files = glob("$dir/dbip-country-lite-*.csv.gz") ?: array();
	rsort($files, SORT_STRING);
	foreach(array_slice($files, 2) as $f) { @unlink($f); }
	return array_slice($files, 0, 2);
}

/** Vorige Adresse (Binaerstring - 1), null bei Unterlauf */
function gdb_prev(string $b): ?string
{
	for($i = strlen($b) - 1; $i >= 0; $i--) {
		if($b[$i] !== "\x00") { $b[$i] = chr(ord($b[$i]) - 1); return $b; }
		$b[$i] = "\xFF";
	}
	return null;
}

/** DB-IP-CSV ("erste IP,letzte IP,CC", aufsteigend) -> [4 => gepackt, 16 => gepackt], benachbarte Bereiche desselben
 *  Landes zusammengefasst, ZZ (unbekannt) weggelassen. null bei unbrauchbarer Datei. */
function gdb_ranges(string $file): ?array
{
	$g = gzopen($file, 'rb');
	if($g === false) { return null; }
	$out = array(4 => '', 16 => ''); $cnt = array(4 => 0, 16 => 0);
	$cur = array(4 => null, 16 => null);  // [erste, letzte, CC]
	$last = array(4 => null, 16 => null); // Ende des vorigen Bereichs (Reihenfolge pruefen)
	$bad = 0;
	$flush = function(int $w) use (&$out, &$cnt, &$cur) {
		if($cur[$w] === null) { return; }
		$out[$w] .= $cur[$w][0].$cur[$w][1].$cur[$w][2];
		$cnt[$w]++;
		$cur[$w] = null;
	};
	while(($l = gzgets($g, 256)) !== false) {
		$f = explode(',', str_replace('"', '', trim($l)));
		if(count($f) !== 3 OR $f[0] === 'ip_start') { $bad++; continue; } // ip_start: Kopfzeile, falls vorhanden
		$a = @inet_pton($f[0]); $b = @inet_pton($f[1]); $cc = $f[2];
		if($a === false OR $b === false OR strlen($a) !== strlen($b) OR strcmp($a, $b) > 0) { $bad++; continue; }
		$w = strlen($a);
		if($last[$w] !== null AND strcmp($a, $last[$w]) <= 0) { $bad++; continue; } // nicht aufsteigend oder ueberlappend
		$last[$w] = $b;
		if(!preg_match('/^[A-Z]{2}$/', $cc) OR $cc === 'ZZ') { $flush($w); continue; }
		if($cur[$w] !== null AND $cur[$w][2] === $cc AND geo_next($cur[$w][1]) === $a) { $cur[$w][1] = $b; continue; }
		$flush($w);
		$cur[$w] = array($a, $b, $cc);
	}
	gzclose($g);
	$flush(4); $flush(16);
	if($bad > 1000 OR $cnt[4] < GDB_MIN_V4) {
		echo "Herkunft: DB-IP-Datei unbrauchbar ({$cnt[4]} + {$cnt[16]} Bereiche, $bad fehlerhafte Zeilen)\n";
		return null;
	}
	return $out;
}

/** Luecken von DB-IP ($d gepackt, sortiert, ohne Ueberlappung) aus den RIR-Schluesseln ($rir, geo_key) fuellen ->
 *  Zeilen "<CC> <erste IP> <letzte IP>", aufsteigend, benachbarte Bereiche desselben Landes zusammengefasst.
 *  $filled = Anzahl der Stuecke aus den RIR-Daten. */
function gdb_fill(string $d, array $rir, int $w, int &$n, int &$filled): string
{
	$rs = 2 * $w + 2;
	$nd = intdiv(strlen($d), $rs);
	$da = function(int $i) use ($d, $rs, $w) { return substr($d, $i * $rs, $w); };
	$db = function(int $i) use ($d, $rs, $w) { return substr($d, $i * $rs + $w, $w); };
	// RIR-Luecken als gepackte Stuecke (aufsteigend, weil RIR sortiert und ohne Ueberlappung verarbeitet)
	sort($rir, SORT_STRING);
	$gaps = ''; $i = 0; $rEnd = null;
	foreach($rir as $k) {
		$a = substr($k, 0, $w); $b = substr($k, $w, $w); $cc = substr($k, 2 * $w, 2);
		if($rEnd !== null) {
			if(strcmp($b, $rEnd) <= 0) { continue; }
			if(strcmp($a, $rEnd) <= 0) { $a = geo_next($rEnd); }
		}
		$rEnd = $b;
		while($i < $nd AND strcmp($db($i), $a) < 0) { $i++; }
		$cur = $a; $j = $i;
		while($cur !== null AND strcmp($cur, $b) <= 0) {
			if($j < $nd AND strcmp($da($j), $cur) <= 0) { $cur = geo_next($db($j)); $j++; continue; }
			$end = ($j < $nd AND strcmp($da($j), $b) <= 0) ? gdb_prev($da($j)) : $b;
			$gaps .= $cur.$end.$cc; $filled++;
			$cur = geo_next($end);
		}
	}
	// beide Listen zusammenfuehren, benachbarte Bereiche desselben Landes zusammenfassen
	$ng = intdiv(strlen($gaps), $rs);
	$s = ''; $ca = null; $cb = null; $c0 = null; $i = 0; $j = 0;
	while($i < $nd OR $j < $ng) {
		if($j >= $ng OR ($i < $nd AND strcmp($da($i), substr($gaps, $j * $rs, $w)) < 0)) { $rec = substr($d, $i * $rs, $rs); $i++; }
		else { $rec = substr($gaps, $j * $rs, $rs); $j++; }
		$a = substr($rec, 0, $w); $b = substr($rec, $w, $w); $cc = substr($rec, 2 * $w, 2);
		if($ca !== null AND $cc === $c0 AND geo_next($cb) === $a) { $cb = $b; continue; }
		if($ca !== null) { $s .= "$c0 ".inet_ntop($ca)." ".inet_ntop($cb)."\n"; $n++; }
		$ca = $a; $cb = $b; $c0 = $cc;
	}
	if($ca !== null) { $s .= "$c0 ".inet_ntop($ca)." ".inet_ntop($cb)."\n"; $n++; }
	return $s;
}

/** -> ['txt' => Zeilen, 'n4' => .., 'n6' => .., 'filled' => .., 'file' => Dateiname] oder null (dann nur RIR-Daten).
 *  $rir = [4 => geo_key-Liste, 6 => geo_key-Liste] aus den RIR-Laendernetzen. */
function gdb_build(string $dir, bool $fetch, array $rir): ?array
{
	$d = null;
	foreach(gdb_files($dir, $fetch) as $file) {
		if(($d = gdb_ranges($file)) !== null) { break; }
		@unlink($file); // unbrauchbar: weg, damit sie neu geladen wird (nach GDB_RETRY); naechstaeltere versuchen
	}
	if($d === null) { return null; }
	$n4 = 0; $n6 = 0; $filled = 0;
	$txt = gdb_fill($d[4], $rir[4] ?? array(), 4, $n4, $filled).gdb_fill($d[16], $rir[6] ?? array(), 16, $n6, $filled);
	if($n4 + $n6 > GDB_MAX_LINES) { echo "Herkunft: zu viele Bereiche ($n4 + $n6), nur RIR-Daten\n"; return null; }
	return array('txt' => $txt, 'n4' => $n4, 'n6' => $n6, 'filled' => $filled, 'file' => basename($file));
}
