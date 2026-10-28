<?php
// Test-Stub fuer dbconnect.php (nur Pruefung in s64w*-Containern, eigene Test-DB, Test-Passwort). Nicht hochladen.
if(getenv('S64WTEST') !== '1') { exit; }
$pdo = new PDO('mysql:host=' . getenv('S64WDB') . ';dbname=ipv64', 'root', 's64wtest', array(PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES 'utf8'"));
date_default_timezone_set('Europe/Berlin');
function add_log($pdo, $userid, $subdomainid, $header, $content) {}
