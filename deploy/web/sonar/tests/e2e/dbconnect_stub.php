<?php
// Test-Stub fuer dbconnect.php (nur Ende-zu-Ende-Pruefung in s64e*-Containern, eigene Test-DB, Test-Passwort). Nicht hochladen.
if(getenv('S64E') !== '1') { exit; }
$pdo = new PDO('mysql:host=' . getenv('S64E_DB') . ';dbname=ipv64', 'root', 's64etest', array(PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES 'utf8mb4'"));
date_default_timezone_set('Europe/Berlin');
function add_log($pdo, $userid, $subdomainid, $header, $content) {}
