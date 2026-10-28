<?php
// Test-Stub fuer dbconnect.php (nur Pruefung der Sonar64-Jobs, eigene Datenbank s64jobs_test in c64o-db). Nicht hochladen.
// Zugang nur aus der Umgebung (run_agentbox.sh reicht ihn weiter, er steht in keiner Datei und keiner Ausgabe).
if(getenv('S64J') !== '1') { exit; }
$pdo = new PDO('mysql:host=' . getenv('S64J_DBHOST') . ';dbname=s64jobs_test', 'root', (string)getenv('S64J_DBPW'),
	array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES 'utf8'"));
date_default_timezone_set('Europe/Berlin');
