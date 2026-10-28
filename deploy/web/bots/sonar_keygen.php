<?php
/**
 * Sonar64: Plan-Schluessel (Ed25519) erzeugen. Nur von Hand auf dem Webserver, einmalig:
 *
 *   php bots/sonar_keygen.php            Schluessel anlegen (bricht ab, wenn schon einer da ist)
 *   php bots/sonar_keygen.php --show     Public Key des vorhandenen Schluessels anzeigen
 *   php bots/sonar_keygen.php --force    vorhandenen Schluessel ersetzen (alle Knoten brauchen dann den neuen Public Key!)
 *
 * Ablage ausserhalb des Webroots: <ueber dem Webroot>/private/sonar64/plan_ed25519.key (Ordner 0700, Datei 0600,
 * Besitzer wie der Webroot, damit PHP ihn lesen kann). Ausgegeben wird nur der Public Key (Base64) und seine Kennung;
 * den Public Key in internal/sonar/keys.go (PlanKeys) eintragen. Der geheime Schluessel verlaesst den Server nie.
 */
if(php_sapi_name() !== 'cli') { exit; }
require __DIR__ . '/../sonar/s64_lib.php';

$opt = getopt('', array('force', 'show'));
if(!function_exists('sodium_crypto_sign_keypair')) { fwrite(STDERR, "PHP ohne sodium\n"); exit(1); }
$file = s64_plan_key_file();
$dir = dirname($file);

if(isset($opt['show'])) {
	$k = s64_plan_keys();
	if($k === array()) { fwrite(STDERR, "Kein Schluessel unter $file\n"); exit(1); }
	echo "kid    " . $k[0]['kid'] . "\npubkey " . $k[0]['pubkey'] . "\n";
	exit(0);
}
if(file_exists($file) AND !isset($opt['force'])) { fwrite(STDERR, "Schluessel existiert schon ($file). Anzeigen: --show, ersetzen: --force\n"); exit(1); }

umask(0077);
if(!is_dir($dir) AND !mkdir($dir, 0700, true)) { fwrite(STDERR, "Ordner $dir nicht anlegbar\n"); exit(1); }
@chmod($dir, 0700);
$kp = sodium_crypto_sign_keypair();
$sk = sodium_crypto_sign_secretkey($kp);
$pk = sodium_crypto_sign_publickey($kp);
$tmp = $file . '.tmp' . bin2hex(random_bytes(4));
if(file_put_contents($tmp, base64_encode($sk) . "\n") === false OR !chmod($tmp, 0600)) { @unlink($tmp); fwrite(STDERR, "Schreiben fehlgeschlagen\n"); exit(1); }
// als root: Besitzer wie der Webroot (PHP-FPM laeuft als dessen Benutzer)
$web = dirname(__DIR__);
if(function_exists('posix_geteuid') AND posix_geteuid() === 0) {
	foreach(array(dirname($dir), $dir, $tmp) as $p) { @chown($p, fileowner($web)); @chgrp($p, filegroup($web)); }
}
if(!rename($tmp, $file)) { @unlink($tmp); fwrite(STDERR, "Schreiben fehlgeschlagen\n"); exit(1); }
sodium_memzero($sk); sodium_memzero($kp);
echo "Plan-Schluessel angelegt: $file\n";
echo "kid    " . s64_kid($pk) . "\npubkey " . base64_encode($pk) . "\n";
echo "Public Key in internal/sonar/keys.go (PlanKeys) eintragen.\n";
