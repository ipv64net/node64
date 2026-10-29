<?php 
include("dbconnect.php");
include("/var/www/clients/client1/web58/web/bots/cdn_functions.php");

ini_set('max_execution_time', 60);
header('Content-type: application/json');

//Update A & AAAA Record 
//Key wird direkt eine Domain updated

if(isset($_GET["domain"])) { $domain = $_GET["domain"];}
if(isset($_POST["domain"]) AND empty($domain)){$domain = $_POST["domain"];}
if(isset($_POST["domains"]) AND empty($domain)){$domain = $_POST["domains"];}
if(isset($_GET["domains"]) AND empty($domain)){$domain = $_GET["domains"];}
if(isset($_POST["host"]) AND empty($domain)){$domain = $_POST["host"];}
if(isset($_GET["host"]) AND empty($domain)){$domain = $_GET["host"];}
if(isset($_POST["hostname"]) AND empty($domain)){$domain = $_POST["hostname"];}
if(isset($_GET["hostname"]) AND empty($domain)){$domain = $_GET["hostname"];}
if(isset($_GET["host_id"]) AND empty($domain)){$domain = $_GET["host_id"];}
if(isset($_GET["zone"]) AND empty($domain)){$domain = $_GET["zone"];}
if(isset($_POST["zone"]) AND empty($domain)){$domain = $_POST["zone"];}
//OPNsense


if(isset($_GET["key"])) { $key = $_GET["key"];}
if(isset($_POST["key"]) AND empty($key)){$key = $_POST["key"];}
if(isset($_GET["token"]) AND empty($key)){$key = $_GET["token"];}
if(isset($_POST["token"]) AND empty($key)){$key = $_POST["token"];}
if(isset($_POST["user"]) AND empty($key)){$key = $_POST["user"];}
if(isset($_GET["user"]) AND empty($key)){$key = $_GET["user"];}
if(isset($_POST["username"]) AND empty($key)){$key = $_POST["username"];}
if(isset($_GET["username"]) AND empty($key)){$key = $_GET["username"];}
if(isset($_POST["pwd"]) AND empty($key)){$key = $_POST["pwd"];}
if(isset($_GET["pwd"]) AND empty($key)){$key = $_GET["pwd"];}
if(isset($_POST["pass"]) AND empty($key)){$key = $_POST["pass"];}
if(isset($_GET["pass"]) AND empty($key)){$key = $_GET["pass"];}
if(isset($_POST["password"]) AND empty($key)){$key = $_POST["password"];}
if(isset($_GET["password"]) AND empty($key)){$key = $_GET["password"];}

if(isset($_GET["dkey"])) { $dkey = $_GET["dkey"]; }
if(isset($_POST["dkey"]) AND empty($dkey)){$dkey = $_POST["dkey"];}
$key = trim($key ?? "");

if(isset($_SERVER["HTTP_AUTHORIZATION"]) AND empty($key)) {
	$requestHeaders = apache_request_headers();
	$headers = trim($requestHeaders['Authorization']);
	
	if (preg_match('/Bearer\s(\S+)/', $headers, $matches) OR preg_match('/Token\s(\S+)/', $headers, $matches)) {
		$key = $matches[1];
	}else{
		$auth = $_SERVER["HTTP_AUTHORIZATION"];
		$auth_array = explode(" ", $auth);
		$un_pw = explode(":", base64_decode($auth_array[1]));
		if(!empty($un_pw["0"]) AND (strlen($un_pw["0"]) == 32 OR strlen($un_pw["0"]) == 24)){$key = $un_pw["0"];}
		elseif(!empty($un_pw["1"]) AND (strlen($un_pw["1"]) == 32 OR strlen($un_pw["1"]) == 24)){$key = $un_pw["1"];}
		else{$key = "";}
	}
}
if(isset($_SERVER['PHP_AUTH_USER']) OR isset($_SERVER['PHP_AUTH_PW'])) {
	if(strlen($_SERVER['PHP_AUTH_PW']) == 32 OR strlen($_SERVER['PHP_AUTH_PW']) == 24) {
		$key = $_SERVER['PHP_AUTH_PW'];
	}elseif(strlen($_SERVER['PHP_AUTH_USER']) == 32 OR strlen($_SERVER['PHP_AUTH_USER']) == 24) {
		$key = $_SERVER['PHP_AUTH_USER'];
	}
}

$ipv4 = "";
if(isset($_POST["ip"]) AND empty($ipv4)){$ipv4 = $_POST["ip"];}
if(isset($_GET["ip"]) AND empty($ipv4)){$ipv4 = $_GET["ip"];}
if(isset($_POST["ip4"]) AND empty($ipv4)){$ipv4 = $_POST["ip4"];}
if(isset($_GET["ip4"]) AND empty($ipv4)){$ipv4 = $_GET["ip4"];}
if(isset($_POST["ipv4"]) AND empty($ipv4)){$ipv4 = $_POST["ipv4"];}
if(isset($_GET["ipv4"]) AND empty($ipv4)){$ipv4 = $_GET["ipv4"];}
if(isset($_POST["myip"]) AND empty($ipv4)){$ipv4 = $_POST["myip"];}
if(isset($_GET["myip"]) AND empty($ipv4)){$ipv4 = $_GET["myip"];}
if(isset($_POST["myip4"]) AND empty($ipv4)){$ipv4 = $_POST["myip4"];}
if(isset($_GET["myip4"]) AND empty($ipv4)){$ipv4 = $_GET["myip4"];}
if(isset($_POST["myipv4"]) AND empty($ipv4)){$ipv4 = $_POST["myipv4"];}
if(isset($_GET["myipv4"]) AND empty($ipv4)){$ipv4 = $_GET["myipv4"];}


$ipv6 = "";
if(isset($_POST["ip6"]) AND empty($ipv6)){$ipv6 = $_POST["ip6"];}
if(isset($_GET["ip6"]) AND empty($ipv6)){$ipv6 = $_GET["ip6"];}
if(isset($_POST["ipv6"]) AND empty($ipv6)){$ipv6 = $_POST["ipv6"];}
if(isset($_GET["ipv6"]) AND empty($ipv6)){$ipv6 = $_GET["ipv6"];}
if(isset($_POST["myip6"]) AND empty($ipv6)){$ipv6 = $_POST["myip6"];}
if(isset($_GET["myip6"]) AND empty($ipv6)){$ipv6 = $_GET["myip6"];}
if(isset($_POST["myipv6"]) AND empty($ipv6)){$ipv6 = $_POST["myipv6"];}
if(isset($_GET["myipv6"]) AND empty($ipv6)){$ipv6 = $_GET["myipv6"];}

if($ipv4 == "auto"){$ipv4 = "";}
if($ipv6 == "auto"){$ipv6 = "";}

$praefix = "";
if(isset($_POST["praefix"]) AND empty($praefix)){$praefix = $_POST["praefix"];}
if(isset($_GET["praefix"]) AND empty($praefix)){$praefix = $_GET["praefix"];}
$praefix = htmlspecialchars($praefix, ENT_QUOTES);

$dualstack = "";
if(isset($_POST["dualstack"]) AND empty($dualstack)){$dualstack = $_POST["dualstack"];}
if(isset($_GET["dualstack"]) AND empty($dualstack)){$dualstack = $_GET["dualstack"];}
$dualstack = htmlspecialchars($dualstack, ENT_QUOTES);

//IPv6 Prefix 
$ipv6prefix = "";
if(isset($_POST["ipv6prefix"]) AND empty($ipv6prefix)){$ipv6prefix = $_POST["ipv6prefix"];}
if(isset($_GET["ipv6prefix"]) AND empty($ipv6prefix)){$ipv6prefix = $_GET["ipv6prefix"];}
if(isset($_POST["ip6lanprefix"]) AND empty($ipv6prefix)){$ipv6prefix = $_POST["ip6lanprefix"];}
if(isset($_GET["ip6lanprefix"]) AND empty($ipv6prefix)){$ipv6prefix = $_GET["ip6lanprefix"];}
if(isset($_POST["ip6prefix"]) AND empty($ipv6prefix)){$ipv6prefix = $_POST["ip6prefix"];}
if(isset($_GET["ip6prefix"]) AND empty($ipv6prefix)){$ipv6prefix = $_GET["ip6prefix"];}
if(isset($_POST["ipv6lanprefix"]) AND empty($ipv6prefix)){$ipv6prefix = $_POST["ipv6lanprefix"];}
if(isset($_GET["ipv6lanprefix"]) AND empty($ipv6prefix)){$ipv6prefix = $_GET["ipv6lanprefix"];}
if(isset($_POST["prefix"]) AND empty($ipv6prefix)){$ipv6prefix = $_POST["prefix"];}
if(isset($_GET["prefix"]) AND empty($ipv6prefix)){$ipv6prefix = $_GET["prefix"];}
if($ipv6prefix != "auto") {
	$ipv6prefix = htmlspecialchars($ipv6prefix, ENT_QUOTES);
	$ipv6prefix = str_replace("::::","::",$ipv6prefix);
	$ipv6prefix = str_replace(":::","::",$ipv6prefix);
}

//NUR Präfix aktualisieren Flag
$onlyprefix = 0;
if(isset($_GET["onlyprefix"]) AND empty($onlyprefix)){$onlyprefix = 1;}
if(isset($_POST["onlyprefix"]) AND empty($onlyprefix)){$onlyprefix = 1;}

$healthtoken = "";
if(isset($_POST["healthtoken"]) AND empty($healthtoken)){$healthtoken = $_POST["healthtoken"];}
if(isset($_GET["healthtoken"]) AND empty($healthtoken)){$healthtoken = $_GET["healthtoken"];}
if(isset($_POST["healthcheck"]) AND empty($healthtoken)){$healthtoken = $_POST["healthcheck"];}
if(isset($_GET["healthcheck"]) AND empty($healthtoken)){$healthtoken = $_GET["healthcheck"];}
$healthtoken = htmlspecialchars($healthtoken, ENT_QUOTES);

//Output 
if(isset($_GET["output"])) { $output = $_GET["output"];}else{$output = "full";}

$ausgabe["info"] = "";
	

if(strpos($_SERVER['REQUEST_URI'],"/nic/update") !== false AND $output != "full" AND $output != "none") {$output = "min";}

//Bruteforce Fehlschläge auf Domain.. x anzahl dann 10 min. bann
if((isset($dkey) AND $dkey != "") OR (isset($key) AND $key != "" AND (strlen($key) == "24" OR strlen($key) == "32")))
{
	//User Key gefunden?
	$statement = $pdo->prepare("SELECT id,dyndns_updates,user_class,account_status,verbose FROM users WHERE BINARY updatehash = :ukey");
	$result = $statement->execute(array('ukey' => $key));
	$user2 = $statement->fetch();
	
	if (($user2["id"] ?? "") == "")
	{	//Guck mal ob du den User über DOMAIN KEY findest.
		$statement = $pdo->prepare("SELECT id,userid,subdomainname,maindomain,owndomain FROM subdomains WHERE BINARY update_hash = :ukey");
		$result = $statement->execute(array('ukey' => $key));
		$sub = $statement->fetch();
		
		//Record Key evtl der richtige?
		if (($sub["userid"] ?? "") == "")	
		{
			$statement = $pdo->prepare("SELECT userid,subdomain_id,praefix FROM subdomain_records WHERE BINARY record_key = :ukey");
			$result = $statement->execute(array('ukey' => $key));
			$record = $statement->fetch();
			if(isset($record["praefix"])) { $recordkey_praefix = $record["praefix"]; }
			if (($record["subdomain_id"] ?? "") != "") {
				$statement = $pdo->prepare("SELECT id,userid,subdomainname,maindomain,owndomain FROM subdomains WHERE id = :sid");
				$result = $statement->execute(array('sid' => $record["subdomain_id"]));
				$sub = $statement->fetch();
			}
		}
		
		if (($sub["userid"] ?? "") != "")
		{
			$keysub_id = $sub["id"];
			//Ohne domain-Parameter: die Zone des Keys nehmen
			if(!isset($domain) OR $domain == "") {
				if($sub["owndomain"] == 1){ $domain = $sub["maindomain"]; }else{ $domain = $sub["subdomainname"].".".$sub["maindomain"]; }
			}
			
			$statement = $pdo->prepare("SELECT id,dyndns_updates,user_class,account_status,verbose FROM users WHERE id = :uid");
			$result = $statement->execute(array('uid' => $sub["userid"]));
			$user2 = $statement->fetch();
		}
	}
	
	if (($user2["account_status"] ?? "") == "1")
	{
	
	$jetzt = date("Y-m-d H:i:s",time()-10);
	//print_r($jetzt);
	$statement = $pdo->prepare("SELECT count(id) as anz FROM logging WHERE userid = :userid AND zeit >= :jetz");
	$result = $statement->execute(array('userid' => $user2["id"],'jetz' => $jetzt));
	$log = $statement->fetch();

	if($log["anz"] <= 2)
	{
	$domain = preg_replace('/\s+/', '', $domain);
	$domains = explode(",",$domain);
	$praefix_param = $praefix;
	foreach($domains as $domain)
	{
		unset($subdomain); unset($ips);
		if(isset($dkey) AND $dkey !== "")
		{
		$statement = $pdo->prepare("SELECT * FROM subdomains WHERE BINARY update_hash = :update_hash");
		$result = $statement->execute(array('update_hash' => $dkey));
		$subdomain = $statement->fetch();
		}
		else
		{
			$zone = find_user_zone($pdo, $user2["id"], $domain, $praefix_param);
			if($zone !== false){ $subdomain = $zone["subdomain"]; $praefix = $zone["praefix"]; }
		}
		if(isset($recordkey_praefix)) { $praefix = $recordkey_praefix; }
		if(isset($keysub_id) AND (($subdomain["id"] ?? "") != $keysub_id)) { unset($subdomain); }
		
		if (($subdomain["id"] ?? "") != "")
		{
		if($subdomain["deactivated"] == "0")
		{
		//Wie häufig darf er aktualisieren ????
		//ABFRAGE
		$statement = $pdo->prepare("SELECT dyndns_updates,user_class FROM users WHERE id = :userid");
		$result = $statement->execute(array('userid' => $subdomain["userid"]));
		$user = $statement->fetch();
		
		$statement = $pdo->prepare("SELECT * FROM user_class WHERE id = :uid");
		$result = $statement->execute(array('uid' => $user["user_class"]));
		$accountclass = $statement->fetch();
		
		$limit = $accountclass["dyndns_update_limit"];
		$ttl = $accountclass["ttl"];
		
		if($limit == "0"){$limit = 1000000;}
		if($user["dyndns_updates"] < $limit)
		{
			//Nur IPv6 Prefix updaten und Records Updaten 
			if($ipv6prefix != "")
			{
				if($ipv6prefix == "auto")
				{
					if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
						$ip = $_SERVER['HTTP_CLIENT_IP'];
					} elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
						$ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
					} else {
						$ip = $_SERVER['REMOTE_ADDR'];
					}
					if(filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) { 
						$v6hex = str_split(bin2hex(substr(inet_pton($ip), 0, 8)), 4);
						foreach($v6hex as $k => $v){ $v6hex[$k] = ltrim($v, "0") ?: "0"; }
						$ipv6prefix = implode(":", $v6hex)."::/64";
					}
				}
				
				$pp = explode("/", $ipv6prefix);
				if(isset($pp[1]) AND filter_var($pp[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
					$v6hex = str_split(bin2hex(substr(inet_pton($pp[0]), 0, 8)), 4);
					foreach($v6hex as $k => $v){ $v6hex[$k] = ltrim($v, "0") ?: "0"; }
					$ipv6prefix = implode(":", $v6hex)."::/".$pp[1];
				}
				
				if($ipv6prefix != "auto"){
					$v6explode = explode(":",$ipv6prefix); 
					$v6explode2 = explode("/",$v6explode["5"]);
					if($v6explode["5"] != "" AND !isset($v6explode["6"]) AND $v6explode2["0"] == "" AND $v6explode2["1"] != "")
					{
						if($subdomain["ipv6prefix"] != $ipv6prefix)
						{
						$statement = $pdo->prepare("UPDATE subdomains set ipv6prefix = :ipv6prefix WHERE id = :sid");
						$result = $statement->execute(array('sid'=> $subdomain["id"],'ipv6prefix'=> $ipv6prefix));
						//Updates senden
						//do_zone_update($pdo,$subdomain["userid"],$subdomain["id"],"AAAA","$ttl","");
						
						$count = 0;
						$statement = $pdo->prepare("SELECT * FROM subdomain_records WHERE userid = :userid AND subdomain_id = :subdomain AND type = 'AAAA' AND content LIKE :content");
						$result = $statement->execute(array('userid' => $subdomain["userid"],'subdomain' => $subdomain["id"],'content' => "::%"));
						$recs = $statement->fetchAll();
						foreach($recs as $rec) {
							$date = date("Y-m-d H:i:s");
							$statement = $pdo->prepare("UPDATE subdomain_records set last_update = :dupdate,update_dns = :dup WHERE id = :sid");
							$result = $statement->execute(array('dupdate' => $date,'dup' => 1,'sid'=> $rec["id"]));
							//do_zone_update($pdo,$subdomain["userid"],$subdomain["id"],"AAAA","$ttl","$rec[praefix]");
							$count++;
						}
						$ausgabe["updated_ipv6prefix_ips"] = "$count";
						$ausgabe["ipv6prefix"] = "$ipv6prefix";
						if($onlyprefix == 1){ $ausgabe["status"] = "success"; $ausgabe["info"] = "good"; } // nur Praefix: Status fuer output=min
						}else{
							$ausgabe["ipv6prefix"] = "$ipv6prefix";
							if($onlyprefix == 1){ $ausgabe["status"] = "success"; $ausgabe["info"] = "nochg"; }else{ $ausgabe["status"] = "nochg"; }
						}
					}else{
						$ausgabe["ipv6prefix"] = "format error";
					}
				}
			}
			if($onlyprefix == 0)
			{
			//Sendet er eine IP mit? 
			// das habe ich entfernt, kp die auswirkungen -> AND $ipv6prefix == ""
			if(empty($ipv4) AND empty($ipv6))
			{ 
				//IPv X auslesen
				if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
						$ips[] = $_SERVER['HTTP_CLIENT_IP'];
					} elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
						$ips[] = $_SERVER['HTTP_X_FORWARDED_FOR'];
					} else {
						$ips[] = $_SERVER['REMOTE_ADDR'];
					}
			}elseif($onlyprefix != 1){ 
				//Speedport (komma in myip "2a01...,91...")
				if (str_contains($ipv4, ',')) {
					$ipps = explode(",",$ipv4);
					foreach($ipps as $ibb) {
						if(filter_var($ibb, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
							$ips[] = $ibb;
						}
						if(filter_var($ibb, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
							$ips[] = $ibb;
						}
					}
				}else{
					if(!empty($ipv4)) {$ips[] = $ipv4;} 
					if(!empty($ipv6)) {$ips[] = $ipv6;}
				}
			}
			$ausgabe["status"] = "success";
			
			if($user2["verbose"] == "1") {
			add_log($pdo,$subdomain["userid"],$subdomain["id"],"Verbose","Update URL: $_SERVER[REQUEST_URI]");
			}

			foreach($ips as $ip)
			{
				$ip = preg_replace('/%.*$/', '', trim($ip, " []"));
				$type = "";
				if(filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
					if($subdomain["ignore46"] == "4"){$ausgabe["ip"]["ipv4"] = "ignore";continue;}
					$type = "A";
					$ausgabe["ip"]["ipv4"] = "$ip";
				}
				if(filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) AND stripos($ip, "::ffff:") !== 0) { 
					if($subdomain["ignore46"] == "6"){$ausgabe["ip"]["ipv6"] = "ignore";continue;}
					$type = "AAAA";
					$ausgabe["ip"]["ipv6"] = "$ip";
				}
				if($type != "")
				{
					if($subdomain["owndomain"] == 1){ $domainname = $subdomain["maindomain"]; }else{
						$domainname = $subdomain["subdomainname"].".".$subdomain["maindomain"];
					}
				
				//CNAME gesetzt? Dann nix tun!
				$statement = $pdo->prepare("SELECT id FROM subdomain_records WHERE userid = :userid AND domainname = :domainname AND type = :cname AND praefix = :praefix");
				$result = $statement->execute(array('userid' => $subdomain["userid"],'domainname' => $domainname,'cname' => "CNAME",'praefix' => $praefix));
				$cnamecheck = $statement->fetch();
				if(($cnamecheck["id"] ?? "") == "")
				{
				
					//Gibt es diesen Eintrag bereits? Es gibt keinen A oder AAAA Eintrag.
					//$statement = $pdo->prepare("SELECT * FROM subdomain_records WHERE type = :type AND domainname = :domainname AND praefix = :praefix");
					//$result = $statement->execute(array('type' => $type,'domainname' => $domainname,'praefix' => $praefix));
					//$check = $statement->fetch();
					$statement = $pdo->prepare("SELECT * FROM subdomain_records WHERE type = :type AND domainname = :domainname AND praefix = :praefix ORDER BY cdn_tmp ASC, id ASC LIMIT 1");
					$result = $statement->execute(array('type' => $type,'domainname' => $domainname,'praefix' => $praefix));
					$check = $statement->fetch();
					//CDN Record? Nicht anfassen.
					if(($check["cdn_tmp"] ?? 0) != 0){ $ausgabe["ip"][($type == "A" ? "ipv4" : "ipv6")] = "cdn"; if($ausgabe["info"] == ""){ $ausgabe["info"] = "nochg"; } continue; }
					
					if($check["id"] == "")
					{	$date = date("Y-m-d H:i:s");
						$chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
						$record_key = strval(substr(str_shuffle($chars),0,32));
						//Erst alles in die DB und dann ALLES wieder rein in den DNS Server 				
						$statement = $pdo->prepare("INSERT INTO subdomain_records (subdomain_id,userid,domainname,praefix,content,ttl,type,record_key,update_dns) 
						VALUES (:subdomain_id,:userid,:domainname,:praefix,:content,:ttl,:type,:record_key,:update_dns)");
						$result = $statement->execute(array(
						'subdomain_id' => $subdomain["id"],
						'userid'=> $subdomain["userid"],
						'domainname'=> $domainname,
						'praefix'=> $praefix,
						'content'=> $ip,
						'ttl'=> "$ttl",
						'type'=> $type,
						'record_key'=> $record_key,
						'update_dns'=> 1));
						
						usleep(100000);
						
						//Sende an DNS Server
						//do_zone_update($pdo,$subdomain["userid"],$subdomain["id"],$type,$ttl,$praefix);
						add_log($pdo,$subdomain["userid"],$subdomain["id"],"Update A/AAAA Record - GOOD","Updates the A/AAAA Record to the IP: $ip. ($domainname)");
						http_response_code(200);
						$ausgabe["info"] = "good";
					}else{
						$date = date("Y-m-d H:i:s");
						if($check["deactivated"] == "0" OR ($check["deactivated"] == "1" AND ($check["cdn_token"] != "0" OR $check["cdn_token"] != "1")))
						{
							//ES GIBT BEREITS DEN A oder AAAA Eintrag . Mach bitte ein Update 
							if($ip != $check["content"])
							{
								
								$dup = 1;
								//Domain teil von einem CDN 
								if($check["cdn_token"] != 0) {
									//$command = cdn_update_dns($pdo, $check["id"], $subdomain["userid"]);
									//$dup = 0;
								}
								
								//DNS Update wird im Hintergrund ausgeführt durch den BOT - update_dns erledigt das.
								//do_zone_update($pdo,$subdomain["userid"],$subdomain["id"],$type,$ttl,$praefix);
								//IP passt nicht, mach ein Update.
								//IP UPDATE 
								$statement = $pdo->prepare("UPDATE subdomain_records set content = :ip,last_update = :dupdate,update_dns = :dup WHERE id = :sid");
								$result = $statement->execute(array('ip' => $ip,'dupdate' => $date,'dup' => $dup,'sid'=> $check["id"]));
								
								//Falls ein Failover irgendwo sein sollte, update auch den.
								$statement = $pdo->prepare("SELECT * FROM dns_failover_rules WHERE content = :content");
								$result = $statement->execute(array('content' => $check["record_key"]));
								$rule = $statement->fetch();
								if((($rule["status"] ?? "") == "2") AND strlen($rule["content"]) == 32) {
									//Dann Update auch diesen Eintrag.
									$statement = $pdo->prepare("UPDATE subdomain_records set content = :ip,last_update = :dupdate 
									WHERE record_key = :record_key");
									$result = $statement->execute(array('ip' => $ip,'dupdate' => $date,'record_key'=> $rule["temp_record_key"]));
									//Daten abrufen 
									$statement = $pdo->prepare("SELECT * FROM subdomain_records WHERE record_key = :rk");
									$result = $statement->execute(array('rk' => $rule["temp_record_key"]));
									$fail_check = $statement->fetch();
									//Sende an DNS Server 
									do_zone_update($pdo,$fail_check["userid"],$fail_check["subdomain_id"],$type,$fail_check["ttl"],$fail_check["praefix"]);
								}
								
								//Logging
								add_log($pdo,$subdomain["userid"],$subdomain["id"],"Update A/AAAA Record - GOOD","Updates the A/AAAA records to the IP: $ip. ($domainname)");
								http_response_code(200);
								$ausgabe["info"] = "good";
							}else{
								//IP ist die Same, brauchst nix machen.
								$statement = $pdo->prepare("UPDATE subdomain_records set last_update = :dupdate WHERE id = :sid");
								$result = $statement->execute(array('dupdate' => $date,'sid'=> $check["id"]));
								//add_log($pdo,$subdomain["userid"],$subdomain["id"],"Update A/AAAA Record - NOCHG","Updates des A/AAAA Records, aber keine Veränderung. ($domainname)");
								http_response_code(200);
								$ausgabe["info"] = "nochg";
							}
						}else{
						http_response_code(401);
						$ausgabe["status"] = "401 Unauthorized";
						$ausgabe["info"] = "badauth";
						}
					}
					$statement = $pdo->prepare("UPDATE subdomains set update_count = update_count + 1,last_update = :lupdate WHERE id = :sid");
					$result = $statement->execute(array('lupdate' => $date,'sid'=> $subdomain["id"]));
					$statement = $pdo->prepare("UPDATE users set dyndns_updates = dyndns_updates + 1 WHERE id = :sid");
					$result = $statement->execute(array('sid'=> $subdomain["userid"]));
					
					http_response_code(200);
					//Health aktualisieren
					if($healthtoken != ""){
						$ch = curl_init();
						curl_setopt($ch, CURLOPT_URL, "https://ipv64.net/health.php?token=$healthtoken");
						curl_setopt($ch, CURLOPT_HEADER, 0);
						curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
						curl_setopt($ch, CURLOPT_TIMEOUT, 5);
						$info = curl_exec($ch);
						curl_close($ch);
						$ausgabe["healthcheck"] = "$info";
					}
					
				}else{
					//CNAME ist gesetzt. Da geht nix.
					$ausgabe["status"] = "409 Conflict";
					$ausgabe["info"] = "CNAME is set.";
					//add_log($pdo,$subdomain["userid"],$subdomain["id"],"Updatelimit Überschritten","Dein Updatelimit ist überschritten. Update wurde nicht ausgeführt.");
					http_response_code(409);
				}
				}else{
					$ausgabe["status"] = "400 Bad Request";
					$ausgabe["info"] = "No correct IP transmitted";
					http_response_code(400);
				}
			}
			}
		}else{
			//Update Limit erreicht heute
			$ausgabe["status"] = "429 Too Many Requests";
			$ausgabe["info"] = "Updateintervall overcommited";
			//add_log($pdo,$subdomain["userid"],$subdomain["id"],"Updatelimit Überschritten","Dein Updatelimit ist überschritten. Update wurde nicht ausgeführt.");
			http_response_code(429);
		}
		}else{
			http_response_code(401);
			$ausgabe["status"] = "401 Unauthorized";
			$ausgabe["info"] = "badauth";
		}
		}else{
			http_response_code(404);
			$ausgabe["status"] = "404 Not Found";
			$ausgabe["info"] = "nohost";
		}
		}
	}else{
		$ausgabe["status"] = "429 Too Many Requests";
		$ausgabe["info"] = "Update Cooldown - 10sec";
		//add_log($pdo,$user2["id"],"0","Updatelimit Überschritten","Max. 3 Anfragen in 10 Sekunden.");
		http_response_code(429);
	}
	}else{
		$ausgabe["status"] = "401 Unauthorized";
		$ausgabe["info"] = "badauth";
		//add_log($pdo,$user2["id"],"0","Updatelimit Überschritten","Max. 3 Anfragen in 10 Sekunden.");
		http_response_code(401);
	}
	
}elseif(isset($_GET["howismyip"]))
{	
	//how is my ip 
	 if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
		$ip = $_SERVER['HTTP_CLIENT_IP'];
	} elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
		$ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
	} else {
		$ip = $_SERVER['REMOTE_ADDR'];
	}
	
	$ausgabe["ip"] = $ip;
	$ausgabe["status"] = "success";
	$ausgabe["info"] = "good";
	$output = "full";
	http_response_code(200);
}else{
		http_response_code(401);
		header('WWW-Authenticate: Basic realm="IPv64"');
		header('HTTP/1.0 401 Unauthorized');
		$ausgabe["status"] = "401 Unauthorized";
		$ausgabe["info"] = "badauth";
}


if($output == "min" OR $output == "none") { header('Content-type: text/plain'); }
//Output Filter 
if($ausgabe["status"] == "success" AND $ausgabe["info"] == "good" AND $output == "min")
{
	echo "good";
}elseif($ausgabe["status"] == "success" AND $ausgabe["info"] == "nochg" AND $output == "min")
{
	echo "nochg";
}elseif($ausgabe["info"] == "badauth" AND $output == "min")
{
	echo "badauth";
}elseif($ausgabe["info"] == "nohost" AND $output == "min")
{
	echo "nohost";
}elseif(str_starts_with($ausgabe["status"], "429") AND $output == "min")
{
	echo "abuse";
}elseif($ausgabe["status"] != "success" AND $output == "min")
{
	echo "911";
}elseif($output == "none")
{
	//Keine Ausgabe
}else{
	echo json_encode($ausgabe);
}



//User Agent Tracking
if(http_response_code() == "200")
{
if(isset($_SERVER['HTTP_USER_AGENT'])) {
	$agent = $_SERVER['HTTP_USER_AGENT'];
	$statement = $pdo->prepare("SELECT * FROM updater_agents WHERE agent = :agent");
	$result = $statement->execute(array('agent' => $agent));
	$agents = $statement->fetch();
	if($agents["id"] != "")
	{
		$statement = $pdo->prepare("UPDATE updater_agents set counter = counter + 1 WHERE id = :sid");
		$result = $statement->execute(array('sid'=> $agents["id"]));
	}else{
		$statement = $pdo->prepare("INSERT INTO updater_agents (agent) VALUES (:agent)");
		$result = $statement->execute(array('agent' => $agent));
	}
}
}
?>
