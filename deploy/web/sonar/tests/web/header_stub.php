<?php
// Test-Stub fuer header.php (Sonar64 Teil W): Sitzung wie im Portal, angemeldet als Account aus dem Cookie s64w_as
// (fehlt oder 0 = abgemeldet). Nur fuer die Pruefung in s64w*-Containern. Nicht hochladen.
if(getenv('S64WTEST') !== '1') { exit; }
include(__DIR__ . '/dbconnect.php');
session_start();
$userid = isset($_COOKIE['s64w_as']) ? (string)(int)$_COOKIE['s64w_as'] : '';
if($userid === '0') { $userid = ''; }
echo "<html><head><title>test</title></head><body>\n";
