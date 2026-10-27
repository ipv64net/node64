<?php
/**
 * Honeypot64 H4 (DNSBL bl.ipv64.net): Pruefung der Logik von bots/honeypot_dnsbl.php ohne PowerDNS und ohne MariaDB.
 * Zustand in SQLite (im Speicher), zone_update() als Stub, der die RRset-Aenderungen aufzeichnet und die Zone im
 * Speicher nachbildet. Aufruf: php run_tests.php <pfad/zu/honeypot_dnsbl.php>
 */
define('HPD_TEST', true);
require $argv[1] ?? __DIR__ . '/../../../bots/honeypot_dnsbl.php';

$pass = 0; $fail = 0;
function ok(bool $c, string $what): void { global $pass, $fail; if($c) { $pass++; echo "  ok   $what\n"; } else { $fail++; echo "  FAIL $what\n"; } }

// ---------------------------------------------------------------- Umgebung

function newdb(): PDO {
	$pdo = new PDO('sqlite::memory:', null, null, array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION));
	$pdo->exec("CREATE TABLE hp_dnsbl (name TEXT PRIMARY KEY, ip TEXT NOT NULL, a TEXT NOT NULL, txt TEXT NOT NULL, synced_at TEXT NOT NULL)");
	$pdo->exec("CREATE TABLE hp_allowlist (id INTEGER PRIMARY KEY, ip_start BLOB, ip_end BLOB, `until` TEXT NULL)");
	$pdo->exec("CREATE TABLE hp_release_requests (id INTEGER PRIMARY KEY, ip_bin BLOB, protected_until TEXT NULL)");
	return $pdo;
}

/** Stub fuer zone_update: zeichnet auf, bildet die Zone nach; $failOn = Nummern der Aufrufe (1-basiert), die scheitern */
class Pdns {
	public array $calls = array(); public array $zone = array(); public array $failOn = array(); public bool $alwaysFail = false; public int $n = 0;
	public function __invoke(string $json, string $zone): bool {
		$this->n++;
		$p = json_decode($json, true);
		$this->calls[] = array('zone' => $zone, 'rrsets' => $p['rrsets']);
		if($this->alwaysFail OR in_array($this->n, $this->failOn, true)) { return false; }
		foreach($p['rrsets'] as $r) {
			$k = $r['name'] . ' ' . $r['type'];
			if($r['changetype'] === 'DELETE') { unset($this->zone[$k]); }
			else { $this->zone[$k] = array_column($r['records'], 'content'); }
		}
		return true;
	}
	public function a(string $name): ?array { return $this->zone["$name.bl.ipv64.net. A"] ?? null; }
	public function txt(string $name): ?string { return $this->zone["$name.bl.ipv64.net. TXT"][0] ?? null; }
}

$base = sys_get_temp_dir() . '/hp4b-' . getmypid();
@mkdir($base, 0755, true);
$now = time();
/** Tagesstand schreiben: $lists = [liste => [zeilen]], Zeitstempel 2 h alt (Stichtag) */
function source(string $dir, array $lists, int $mtime): void {
	@mkdir($dir, 0755, true);
	foreach(glob("$dir/*") as $f) { unlink($f); }
	foreach($lists as $l => $lines) {
		$f = $dir . '/ipv64_blocklist_' . ($l === 'v64' ? 'v64' : "v64_$l") . '.txt';
		file_put_contents($f, $lines ? implode("\n", $lines) . "\n" : '');
		touch($f, $mtime);
	}
}
function stamp(): int { return time() - 7200; }
function count_rrsets(Pdns $p): int { $n = 0; foreach($p->calls as $c) { $n += count($c['rrsets']); } return $n; }

// ---------------------------------------------------------------- 1. Namen (RFC 5782)

echo "Namen\n";
ok(hpd_name('1.2.3.4') === '4.3.2.1', 'IPv4 1.2.3.4 -> 4.3.2.1');
ok(hpd_name('192.0.2.99') === '99.2.0.192', 'IPv4 RFC 5782 Beispiel 192.0.2.99 -> 99.2.0.192');
ok(hpd_name('2001:db8:1:2:3:4:567:89ab') === 'b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.8.b.d.0.1.0.0.2', 'IPv6 RFC 5782 Beispiel 2001:db8:1:2:3:4:567:89ab');
ok(hpd_name('2A01:4F8::1') === '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.f.4.0.1.0.a.2', 'IPv6 Grossbuchstaben und :: -> 32 Nibbles, klein');
ok(count(explode('.', (string)hpd_name('::1'))) === 32, 'IPv6 immer 32 Nibbles');
ok(hpd_name('127.0.0.2') === '2.0.0.127', 'Testeintrag 127.0.0.2 -> 2.0.0.127');
ok(hpd_name('::ffff:127.0.0.2') === '2.0.0.0.0.0.f.7.f.f.f.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0', 'Testeintrag ::FFFF:7F00:2 (RFC 5782 IPv6)');
ok(hpd_name('1.2.3') === null AND hpd_name('x') === null AND hpd_name('1.2.3.4/32') === null, 'ungueltige Eingaben -> null');

// ---------------------------------------------------------------- 2. Code (nur die v64 Blocklist, seit 2026-10 ohne Teillisten)

echo "Codes\n";
$e = hpd_entry('1.2.3.4', array('v64' => true));
ok($e['a'] === '127.0.0.2', 'v64 Blocklist -> 127.0.0.2');
ok(str_ends_with($e['txt'], 'https://ipv64.net/honeypot/ip.php?ip=1.2.3.4') AND !str_contains($e['txt'], '('), 'TXT mit Link, ohne Arten');
$e = hpd_entry('1.2.3.4', array('v64' => true, 'ssh' => true, 'research' => true));
ok($e['a'] === '127.0.0.2', 'fruehere Teillisten geben keinen eigenen Code mehr');
ok(HPD_CODES === array('v64' => 2), 'nur Code 2');
ok(strlen(hpd_entry('2a01:4f8:ffff:ffff:ffff:ffff:ffff:ffff', array_fill_keys(array_keys(HPD_CODES), true))['txt']) <= 255, 'TXT hoechstens 255 Zeichen');
ok(!in_array(1, HPD_CODES, true), 'Code 127.0.0.1 nie vergeben');

$rr = hpd_rrsets('4.3.2.1', hpd_entry('1.2.3.4', array('v64' => true)));
ok(count($rr) === 2 AND $rr[0]['type'] === 'A' AND $rr[1]['type'] === 'TXT', 'REPLACE: A + TXT');
ok($rr[0]['name'] === '4.3.2.1.bl.ipv64.net.' AND $rr[0]['ttl'] === 300 AND $rr[0]['changetype'] === 'REPLACE', 'Name absolut, TTL 300');
ok(array_column($rr[0]['records'], 'content') === array('127.0.0.2'), 'A-Record 127.0.0.2');
ok($rr[1]['records'][0]['content'][0] === '"' AND str_ends_with($rr[1]['records'][0]['content'], '"'), 'TXT in Anfuehrungszeichen');
$rr = hpd_rrsets('4.3.2.1', null);
ok($rr[0]['changetype'] === 'DELETE' AND $rr[1]['changetype'] === 'DELETE' AND !isset($rr[0]['records']), 'DELETE: A + TXT ohne Records');

// ---------------------------------------------------------------- 3. Quelle lesen

echo "Quelle\n";
$dir = "$base/src";
source($dir, array(
	'v64'      => array('# Kommentar', '1.2.3.4/32', '5.6.7.8/32', '2a01:4f8::1/128', '198.51.200.0/24', '', '7.7.7.7'),
	'ssh'      => array('1.2.3.4/32', '6.6.6.6/32'),
	'web'      => array('2a01:4f8::1/128'),
	'mail'     => array('1.2.3.4/32'),
	'rdp'      => array(),
	'scanner'  => array('5.6.7.8/32'),
	'research' => array('9.9.9.9/32'),
), stamp());
$s = hpd_read_source($dir, $now);
ok($s['err'] === '', 'Tagesstand lesbar');
ok(count($s['ips']) === 4, '4 Einzel-IPs aus der Hauptliste (Netz uebergangen)');
ok($s['nets'] === 1 AND $s['bad'] === 0, 'Netz /24 gezaehlt, nichts ungueltig');
ok(!isset($s['ips']['4.3.2.1']['lists']['ssh']) AND !$s['warn'], 'fruehere Teillisten-Dateien werden nicht gelesen, keine Warnung');
ok(!isset($s['ips'][hpd_name('6.6.6.6')]), 'nur in alter Teilliste -> nicht gelistet');
ok(!isset($s['ips'][hpd_name('9.9.9.9')]), 'research nie in der DNSBL');
ok(isset($s['ips'][hpd_name('7.7.7.7')]), 'Zeile ohne Praefix angenommen');

// ---------------------------------------------------------------- 4. Erster Lauf, Testeintraege

echo "Erster Lauf\n";
$pdo = newdb(); $p = new Pdns();
$r = hpd_run($pdo, $dir, array(), $p, $now);
ok($r['ok'] AND $r['err'] === '', 'Lauf ok');
ok($r['add'] === 6 AND $r['chg'] === 0 AND $r['del'] === 0, 'neu: 4 IPs + 2 Testeintraege');
ok(count($p->calls) === 1 AND $p->calls[0]['zone'] === 'bl.ipv64.net', 'ein PATCH an Zone bl.ipv64.net');
ok($p->a('2.0.0.127') === array('127.0.0.2'), 'Testeintrag 2.0.0.127 -> 127.0.0.2');
ok($p->a('2.0.0.0.0.0.f.7.f.f.f.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0') === array('127.0.0.2'), 'IPv6-Testeintrag ::ffff:7f00:2');
ok($p->a('1.0.0.127') === null, '1.0.0.127 nie gelistet');
ok($p->a('4.3.2.1') === array('127.0.0.2'), '1.2.3.4 -> .2');
ok($p->a('8.7.6.5') === array('127.0.0.2'), '5.6.7.8 -> .2');
ok($p->a(hpd_name('2a01:4f8::1')) === array('127.0.0.2'), 'IPv6 2a01:4f8::1 -> .2');
ok(str_contains((string)$p->txt('4.3.2.1'), 'ip.php?ip=1.2.3.4'), 'TXT mit Link');
ok((int)$pdo->query("SELECT COUNT(*) FROM hp_dnsbl")->fetchColumn() === 6, 'Zustand: 6 Namen');
ok($r['state'] === 0 AND $r['want'] === 4, 'Zahlen ohne Testeintraege');
echo hpd_log($r, array());

// ---------------------------------------------------------------- 5. Zweiter Lauf ohne Aenderung

echo "Zweiter Lauf, gleich\n";
$p2 = new Pdns();
$r = hpd_run($pdo, $dir, array(), $p2, $now);
ok($r['ok'] AND $r['same'] === 6 AND $r['add'] + $r['chg'] + $r['del'] === 0, 'keine Unterschiede');
ok(count($p2->calls) === 0, 'kein PATCH');

// ---------------------------------------------------------------- 6. Differenz neu/entfernt/geaendert

echo "Differenz\n";
source($dir, array(
	'v64' => array('1.2.3.4/32', '2a01:4f8::1/128', '7.7.7.7/32', '4.4.4.4/32'),
	'ssh' => array('1.2.3.4/32'), 'web' => array('1.2.3.4/32', '2a01:4f8::1/128'), 'mail' => array('1.2.3.4/32'), 'rdp' => array(), 'scanner' => array(),
), stamp());
$p->calls = array();
$r = hpd_run($pdo, $dir, array(), $p, $now);
ok($r['ok'] AND $r['add'] === 1 AND $r['chg'] === 0 AND $r['del'] === 1 AND $r['same'] === 5, 'neu 1 (4.4.4.4), entfernt 1 (5.6.7.8), Rest gleich');
$ch = array(); foreach($p->calls[0]['rrsets'] as $x) { $ch[$x['name'] . ' ' . $x['type']] = $x['changetype']; }
ok(count($ch) === 4, 'nur 2 Namen (4 RRsets) geschrieben');
ok(($ch['8.7.6.5.bl.ipv64.net. A'] ?? '') === 'DELETE' AND ($ch['8.7.6.5.bl.ipv64.net. TXT'] ?? '') === 'DELETE', 'entfernt per DELETE (A + TXT)');
ok($p->a('4.3.2.1') === array('127.0.0.2'), '1.2.3.4 weiter .2');
ok($p->a('8.7.6.5') === null AND $p->txt('8.7.6.5') === null, '5.6.7.8 aus der Zone');
ok($p->a('4.4.4.4') === array('127.0.0.2'), '4.4.4.4 neu');
ok((int)$pdo->query("SELECT COUNT(*) FROM hp_dnsbl WHERE name = '8.7.6.5'")->fetchColumn() === 0, 'Zustand ohne 5.6.7.8');
ok($p->a('2.0.0.127') === array('127.0.0.2'), 'Testeintrag bleibt');

// ---------------------------------------------------------------- 7. Bloecke

echo "Bloecke\n";
$big = array(); for($i = 0; $i < 1200; $i++) { $big[] = '11.0.' . intdiv($i, 250) . '.' . ($i % 250 + 1) . '/32'; }
source($dir, array('v64' => $big, 'ssh' => array(), 'web' => array(), 'mail' => array(), 'rdp' => array(), 'scanner' => array()), stamp());
$pdo = newdb(); $p = new Pdns();
$r = hpd_run($pdo, $dir, array(), $p, $now);
ok($r['ok'] AND $r['add'] === 1202, '1200 IPs + 2 Testeintraege neu');
ok(count($p->calls) === 3 AND $r['blocks'] === 3, '3 Bloecke (500 Namen je Block)');
$max = 0; $split = false;
foreach($p->calls as $c) {
	$max = max($max, count($c['rrsets']));
	$names = array(); foreach($c['rrsets'] as $x) { $names[$x['name']][] = $x['type']; }
	foreach($names as $t) { if(count($t) !== 2) { $split = true; } }
}
ok($max <= HPD_BLOCK, 'hoechstens ' . HPD_BLOCK . " RRsets je PATCH (max $max)");
ok(!$split, 'A und TXT eines Namens immer im selben Block');
ok(count($p->zone) === 2404, 'Zone: 1202 Namen x 2 RRsets');

// ---------------------------------------------------------------- 8. Fehler: Wiederholung beim naechsten Lauf

echo "Fehler und Wiederholung\n";
$pdo = newdb(); $p = new Pdns(); $p->failOn = array(2);
$r = hpd_run($pdo, $dir, array(), $p, $now);
ok(!$r['ok'] AND $r['blocks_ok'] === 2 AND $r['blocks_err'] === 1, 'Block 2 scheitert, 1 und 3 geschrieben');
ok((int)$pdo->query("SELECT COUNT(*) FROM hp_dnsbl")->fetchColumn() === 1202 - 500, 'Zustand ohne den fehlgeschlagenen Block');
$p->failOn = array(); $p->calls = array();
$r = hpd_run($pdo, $dir, array(), $p, $now);
ok($r['ok'] AND $r['add'] === 500 AND count($p->calls) === 1, 'naechster Lauf holt genau die 500 Namen nach');
ok(count($p->zone) === 2404, 'Zone danach vollstaendig');

$pdo = newdb(); $p = new Pdns(); $p->alwaysFail = true;
$big2 = array(); for($i = 0; $i < 3000; $i++) { $big2[] = '12.' . intdiv($i, 250) . '.0.' . ($i % 250 + 1); }
source($dir, array('v64' => $big2), stamp());
$r = hpd_run($pdo, $dir, array(), $p, $now);
ok(!$r['ok'] AND count($p->calls) === HPD_MAX_FAIL, 'Abbruch nach ' . HPD_MAX_FAIL . ' Fehlern in Folge (von ' . $r['blocks'] . ' Bloecken)');
ok((int)$pdo->query("SELECT COUNT(*) FROM hp_dnsbl")->fetchColumn() === 0, 'Zustand unveraendert');
ok(count($r['warn']) >= 1 AND str_contains(implode(' ', $r['warn']), 'Abbruch'), 'Warnung im Log');

// ---------------------------------------------------------------- 9. Schutz bei leerer/kaputter Quelle

echo "Schutz der Zone\n";
source($dir, array('v64' => $big, 'ssh' => array(), 'web' => array(), 'mail' => array(), 'rdp' => array(), 'scanner' => array()), stamp());
$pdo = newdb(); $p = new Pdns();
hpd_run($pdo, $dir, array(), $p, $now);
$n0 = count($p->zone);

source($dir, array('v64' => array(), 'ssh' => array(), 'web' => array(), 'mail' => array(), 'rdp' => array(), 'scanner' => array()), stamp());
$p->calls = array();
$r = hpd_run($pdo, $dir, array(), $p, $now);
ok(!$r['ok'] AND str_contains($r['err'], 'ohne Eintraege') AND count($p->calls) === 0, 'leere Quelle: nichts geloescht');

unlink("$dir/ipv64_blocklist_v64.txt");
$r = hpd_run($pdo, $dir, array(), $p, $now);
ok(!$r['ok'] AND str_contains($r['err'], 'fehlt') AND count($p->calls) === 0, 'fehlende Hauptliste: nichts geaendert');

source($dir, array('v64' => array_slice($big, 0, 500), 'ssh' => array()), stamp());
$r = hpd_run($pdo, $dir, array(), $p, $now);
ok(!$r['ok'] AND str_contains($r['err'], 'viel kleiner') AND count($p->calls) === 0, 'Quelle 500 statt 1200: nichts geaendert');

$bad = array_slice($big, 0, 1100); for($i = 0; $i < 20; $i++) { $bad[] = 'kaputt' . $i; }
source($dir, array('v64' => $bad), stamp());
$r = hpd_run($pdo, $dir, array(), $p, $now);
ok(!$r['ok'] AND str_contains($r['err'], 'fehlerhaft') AND count($p->calls) === 0, 'mehr als 1 % ungueltige Zeilen: nichts geaendert');

source($dir, array('v64' => $big), $now - 10);
$r = hpd_run($pdo, $dir, array(), $p, $now);
ok(!$r['ok'] AND str_contains($r['err'], 'gerade geschrieben') AND count($p->calls) === 0, 'Datei juenger als 60 s: naechster Lauf');

source($dir, array('v64' => array_slice($big, 0, 500)), stamp());
$r = hpd_run($pdo, $dir, array('force' => true), $p, $now);
ok($r['ok'] AND $r['del'] === 700, '--force: Schrumpfen erlaubt (700 entfernt)');
source($dir, array('v64' => array()), stamp());
$r = hpd_run($pdo, $dir, array('force' => true), $p, $now);
ok($r['ok'] AND $r['del'] === 500 AND count($p->zone) === 4, '--force mit leerer Quelle: nur Testeintraege bleiben');
ok($p->a('2.0.0.127') === array('127.0.0.2'), 'Testeintrag 127.0.0.2 auch bei leerer Liste');
ok($n0 === 2404, 'Ausgangszone war vollstaendig');

// ---------------------------------------------------------------- 10. Freigaben nach dem Stichtag

echo "Freigaben\n";
source($dir, array('v64' => array('1.2.3.4/32', '5.6.7.8/32', '2a01:4f8::1/128', '8.8.4.4/32')), stamp());
$pdo = newdb(); $p = new Pdns();
hpd_run($pdo, $dir, array(), $p, $now);
$st = $pdo->prepare("INSERT INTO hp_allowlist (ip_start, ip_end, `until`) VALUES (?, ?, ?)");
$st->bindValue(1, inet_pton('5.6.7.0'), PDO::PARAM_LOB); $st->bindValue(2, inet_pton('5.6.7.255'), PDO::PARAM_LOB); $st->bindValue(3, null, PDO::PARAM_NULL); $st->execute();
$st->bindValue(1, inet_pton('8.8.4.4'), PDO::PARAM_LOB); $st->bindValue(2, inet_pton('8.8.4.4'), PDO::PARAM_LOB); $st->bindValue(3, gmdate('Y-m-d H:i:s', $now - 60)); $st->execute(); // abgelaufen
$st = $pdo->prepare("INSERT INTO hp_release_requests (ip_bin, protected_until) VALUES (?, ?)");
$st->bindValue(1, inet_pton('2a01:4f8::1'), PDO::PARAM_LOB); $st->bindValue(2, gmdate('Y-m-d H:i:s', $now + 86400)); $st->execute();
$r = hpd_run($pdo, $dir, array(), $p, $now);
ok($r['ok'] AND $r['released'] === 2 AND $r['del'] === 2, 'Freigabe (Bereich) und geschuetzter Antrag sofort entfernt');
ok($p->a('8.7.6.5') === null AND $p->a(hpd_name('2a01:4f8::1')) === null, '5.6.7.8 und 2a01:4f8::1 nicht mehr in der Zone');
ok($p->a('4.4.8.8') === array('127.0.0.2'), 'abgelaufene Freigabe wirkt nicht');

// ---------------------------------------------------------------- 11. --dry und --full

echo "dry und full\n";
source($dir, array('v64' => array('1.2.3.4/32', '9.8.7.6/32')), stamp());
$p->calls = array(); $before = $pdo->query("SELECT name, a, txt FROM hp_dnsbl ORDER BY name")->fetchAll();
$r = hpd_run($pdo, $dir, array('dry' => true), $p, $now);
ok($r['ok'] AND $r['add'] === 1 AND $r['del'] === 1 AND count($p->calls) === 0, '--dry: Zahlen, kein PATCH');
ok($pdo->query("SELECT name, a, txt FROM hp_dnsbl ORDER BY name")->fetchAll() === $before, '--dry: Zustand unveraendert');
$r = hpd_run($pdo, $dir, array('full' => true), $p, $now);
ok($r['ok'] AND $r['add'] === 1 AND $r['chg'] === 3 AND $r['same'] === 0, '--full: alle Soll-Namen neu geschrieben');

// ---------------------------------------------------------------- 12. Zustand nicht schreibbar

echo "Zustand\n";
$pdo2 = new PDO('sqlite::memory:', null, null, array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION));
$r = hpd_run($pdo2, $dir, array(), new Pdns(), $now);
ok(!$r['ok'] AND str_contains($r['err'], 'hp_dnsbl nicht lesbar'), 'ohne Tabelle hp_dnsbl: Abbruch vor PowerDNS');
ok(in_array('hp_allowlist nicht lesbar', $r['warn'], true) === false, 'Abbruch vor dem Lesen der Freigaben');

// ---------------------------------------------------------------- 13. Einrichtung

echo "Einrichtung\n";
$z = hpd_zone_setup();
ok(count($z) === 3 AND $z[0][0] === 'zone_create' AND $z[1][0] === 'zone_create' AND $z[2][0] === 'zone_update', 'zone_create Master + Slave, zone_update Delegation');
$m = json_decode($z[0][1], true); $s2 = json_decode($z[1][1], true); $d = json_decode($z[2][1], true);
ok($m['name'] === 'bl.ipv64.net.' AND $m['kind'] === 'Master' AND $m['soa_edit_api'] === 'INCREASE', 'Master-Zone bl.ipv64.net.');
ok($m['rrsets'][0]['records'][0]['content'] === 'ns1.ipv64.net. hostmaster.ipv64.net. 1 900 300 604800 300', 'SOA mit kurzen Zeiten');
ok($s2['kind'] === 'Slave' AND isset($s2['masters']), 'Slave mit Master');
ok($z[2][2] === 'ipv64.net' AND $d['rrsets'][0]['type'] === 'NS' AND $d['rrsets'][0]['name'] === 'bl.ipv64.net.' AND count($d['rrsets']) === 1, 'Delegation: nur NS bl.ipv64.net. in ipv64.net');

// ---------------------------------------------------------------- Ende
array_map('unlink', glob("$dir/*")); @rmdir($dir); @rmdir($base);
echo "\nErgebnis: $pass ok, $fail Fehler\n";
exit($fail ? 1 : 0);
