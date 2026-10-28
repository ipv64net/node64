<?php 
$lock = fopen('/var/lock/failover_checker.lock', 'c');
if (!flock($lock, LOCK_EX | LOCK_NB)) { exit("laeuft bereits\n"); }

include("/var/www/clients/client1/web58/web/dbconnect.php");
include("/var/www/clients/client1/web58/web/bots/cdn_functions.php");
include("/var/www/clients/client1/web58/web/failover_hc2_lib.php"); //Monitore: alte oder neue Healthchecks (Schalter FAILOVER_HC2)

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
use PHPMailer\PHPMailer\SMTP;

$mail = new PHPMailer();

//Name in CDN64 online (Host vorhanden)? Dann sind die Originale absichtlich deaktiviert (Server-Eintraege stattdessen):
//nie wieder aktivieren und keinen Ersatz-Record veroeffentlichen, sonst steht die Ursprungs-IP neben den Servern im DNS
function failover_cdn64o_active($pdo, $record) {
	try {
		$st = $pdo->prepare("SELECT id FROM cdn64o_hosts WHERE subdomain_id = :s AND praefix = :p LIMIT 1");
		$st->execute(array('s' => $record["subdomain_id"], 'p' => $record["praefix"]));
		if($st->fetch() !== false) { return true; }
		$st = $pdo->prepare("SELECT host_id FROM cdn64o_records WHERE record_id = :i AND role = 'original' LIMIT 1");
		$st->execute(array('i' => $record["id"]));
		return $st->fetch() !== false;
	} catch (Throwable $e) { return false; }
}

//Alle 15 Sekunden Check ?
for($bb=0;$bb<=2;$bb++)
{

$statement = $pdo->prepare("SELECT * FROM dns_failover_policies WHERE status != 3");
$result = $statement->execute();
$policies = $statement->fetchAll();
foreach($policies as $policy)
{
	
	$statement = $pdo->prepare("SELECT user_class FROM users WHERE id = :uid");
	$result = $statement->execute(array('uid' => $policy["userid"]));
	$account = $statement->fetch();
	
	$statement = $pdo->prepare("SELECT ttl FROM user_class WHERE id = :uid");
	$result = $statement->execute(array('uid' => $account["user_class"]));
	$accountclass = $statement->fetch();
	//Prüfen ob Policies von Status 0 zu 1 kommen
	//Dafür muss gültiges Monitoring und Rule set da sein. 
	if($policy["status"] == "0")
	{
		$statement = $pdo->prepare("SELECT id FROM dns_failover_monitors WHERE failover_hash = :fh");
		$result = $statement->execute(array("fh"=>$policy["failover_hash"]));
		$monitors = $statement->fetch();
		$statement = $pdo->prepare("SELECT id FROM dns_failover_rules WHERE failover_hash = :fh");
		$result = $statement->execute(array("fh"=>$policy["failover_hash"]));
		$rules = $statement->fetch();
		if(!empty($monitors["id"]) 
		AND !empty($rules["id"]))
		{
			$statement = $pdo->prepare("UPDATE dns_failover_policies set status = :status WHERE failover_hash = :policyhash");
			$result = $statement->execute(array('status' => "1",'policyhash' => $policy["failover_hash"]));
			add_log($pdo,$policy["userid"],"0","DNS Failover activated","DNS Failover Policy automated activated: $policy[name]");
		}
		continue;
	}
	
	//DNS Failover TRIGGER 
	//Nur wenn in Status 1
	if($policy["status"] == "1" OR $policy["status"] == "4")
	{
		//Nur wenn alle Healthchecks Offline sind Triggern
		$i=0;$all=0;
		$statement = $pdo->prepare("SELECT healthtoken,id,negate FROM dns_failover_monitors WHERE failover_hash = :policyhash");
		$result = $statement->execute(array('policyhash' => $policy["failover_hash"]));
		$monitors = $statement->fetchAll();
		foreach($monitors as $monitor)
		{	$i++;
			$hc = failover_check($pdo, (int)$policy["userid"], (string)$monitor["healthtoken"]) ?: array('status' => ''); //Healthcheck geloescht: zaehlt weder online noch offline
			if($hc["status"] == "1" AND $monitor["negate"] == 1){$all++;}
			if($hc["status"] == "4" AND $monitor["negate"] == 0){$all++;}
		}
		//echo $policy["name"]." ".$i." ".$all."\n";
		//Wenn ALLE angegeben Healthchecks Offline sind.. dann Failover OR Manual
		//Erste ist AND Verknüpfung
		//Zweite OR 
		//Dritte Manuell
		if(($all == $i AND $i != 0 AND $all != 0 AND $policy["failover_type"] != 2 AND $policy["linking"] == "and") OR 
			($i != 0 AND $all > 0 AND $policy["failover_type"] != 2 AND $policy["linking"] == "or")
			OR $policy["status"] == "4"){
			
			//Records nach Regeln Offline/Deaktivieren 
			//Records nach Regeln erstellen mit Flag auf die Policie.
			echo "Failover $policy[id]";
			$statement = $pdo->prepare("SELECT * FROM dns_failover_rules WHERE failover_hash = :fh");
			$result = $statement->execute(array("fh"=>$policy["failover_hash"]));
			$rules = $statement->fetchAll();
			foreach($rules as $rule)
			{	//Lese Original Record aus 
				
				$statement = $pdo->prepare("SELECT * FROM subdomain_records WHERE BINARY record_key = :record_key");
				$result = $statement->execute(array('record_key' => $rule["subdomain_record_key"]));
				$record = $statement->fetch();
				if($record === false) { echo " Regel $rule[id]: Record fehlt"; continue; } //Original-Record geloescht
				if(failover_cdn64o_active($pdo, $record)) { echo " Regel $rule[id]: CDN64 online aktiv, kein Ersatz-Record"; continue; }
				
				$chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
				$record_key = strval(substr(str_shuffle($chars),0,32));
				$trk = "0"; //nur gesetzt, wenn unten wirklich ein Ersatz-Record angelegt wird
				
				//Ist es eine IP oder ein Key?
				if(!filter_var($rule["content"], FILTER_VALIDATE_IP) AND strlen($rule["content"]) == 32)
				{	
					$statement = $pdo->prepare("SELECT content,id,record_key,type,subdomain_id FROM subdomain_records WHERE record_key = :rk");
					$result = $statement->execute(array('rk' => $rule["content"]));
					$sdst_record = $statement->fetch();
					$statement = $pdo->prepare("SELECT * FROM subdomains WHERE id = :id");
					$result = $statement->execute(array('id' => $sdst_record["subdomain_id"]));
					$subdomain = $statement->fetch();
					
					//Ist der Content so eine Prefix v6 Zeugs?
					$host = explode("::",$sdst_record["content"]);
					if($sdst_record["type"] == "AAAA" AND $subdomain["ipv6prefix"] != "" AND filter_var($sdst_record["content"], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) AND $host["0"] == "") {
						$check1 = explode("::",$sdst_record["content"]);
						if($check1["1"] != "" AND $check1["0"] == "")
						{
							$prefix = explode("::",$subdomain["ipv6prefix"]);
							$host = explode("::",$sdst_record["content"]);
							$countpref = substr_count($prefix["0"], ':');
							$countsum = $countpref + substr_count($host["1"], ':') + 1;
							if($countsum <= 6){$points = "::";}else{$points = ":";}
							$sdst_record["content"] = $prefix["0"].$points.$host["1"];
							if(!filter_var($sdst_record["content"], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)){continue;}
						}else{continue;}
					}
					if($sdst_record["id"] != ""){$rule["content"] = $sdst_record["content"];}
				}
				
				
				
				//Checken ob es sich hier um ein CDN handelt
				if($record["cdn_token"] != 0) {
					$deactivated = 1;
				}else{ $deactivated = 0;}
					
				//Failover Record hinzufügen - nur wenn ein gueltiges Ziel da ist
				if(filter_var($rule["content"], FILTER_VALIDATE_IP) AND $record !== false)
				{	
				//Offline nehmen und FP setzen
				$statement = $pdo->prepare("UPDATE subdomain_records set deactivated = :deactivated,failover_policy = :fp WHERE BINARY record_key = :record_key");
				$result = $statement->execute(array('deactivated' => "1",'fp' => $policy["failover_hash"],'record_key' => $rule["subdomain_record_key"]));
					
					//Gleicher Inhalt schon aktiv im selben RRset (anderer Record oder andere Regel dieser Policy)? Dann nicht
					//doppelt anlegen - PowerDNS lehnt sonst das ganze RRset ab (422 Duplicate record) und die Zone bleibt alt
					$statement = $pdo->prepare("SELECT content FROM subdomain_records WHERE subdomain_id = :sid AND BINARY praefix = :praefix AND type = :type AND deactivated = '0'");
					$result = $statement->execute(array('sid' => $record["subdomain_id"],'praefix' => $record["praefix"],'type' => $record["type"]));
					$dup = false; $want = @inet_pton($rule["content"]);
					foreach($statement->fetchAll() as $other) { if($want !== false AND @inet_pton($other["content"]) === $want) { $dup = true; break; } }
					if($dup AND $deactivated == 0) {
						do_zone_update($pdo,$record["userid"],$record["subdomain_id"],$record["type"],10,$record["praefix"]);
					}else{
					$statement = $pdo->prepare("INSERT INTO subdomain_records (subdomain_id,userid,domainname,praefix,content,ttl,deactivated,type,record_key,failover,failover_policy) 
						VALUES (:subdomain_id,:userid,:domainname,:praefix,:content,:ttl,:deactivated,:type,:record_key,:failover,:failover_policy)");
						$result = $statement->execute(array(
						'subdomain_id' => $record["subdomain_id"],
						'userid'=> $record["userid"],
						'domainname'=> $record["domainname"],
						'praefix'=> $record["praefix"],
						'content'=> $rule["content"],
						'ttl'=> 10,
						'deactivated'=> $deactivated,
						'type'=> $record["type"],
						'record_key'=> $record_key,
						'failover'=> 1,
						'failover_policy'=> $policy["failover_hash"]));
						$newrecordid = $pdo->lastInsertId();
						$trk = $record_key;
					//DNS Update ausführen
					do_zone_update($pdo,$record["userid"],$record["subdomain_id"],$record["type"],10,$record["praefix"]);
					
					//Checken ob es sich hier um ein CDN handelt und im CDN aendern
					if($record["cdn_token"] != 0) {
						$command = cdn_update_dns($pdo, $newrecordid, $record["userid"]);
						echo $command;
					}
					}
				}
				//Rules Status ändern in 
				$statement = $pdo->prepare("UPDATE dns_failover_rules set status = :status,temp_record_key = :trk WHERE id = :id");
				$result = $statement->execute(array('status' => "2",'trk' => $trk,'id' => $rule["id"]));
			}
			
			//Ganze Policy Status auf 2 setzen
			$statement = $pdo->prepare("UPDATE dns_failover_policies set status = :status WHERE failover_hash = :policyhash");
			$result = $statement->execute(array('status' => "2",'policyhash' => $policy["failover_hash"]));
			//Log setzen 
			add_log($pdo,$policy["userid"],"1","DNS Failover Policy","DNS Failover Policy TRIGGERED");
			
			//Integration triggern
			if($policy["disable_notifications"] == 0) {
				send_integrations($pdo,$policy["userid"],$policy["integration"],"IPv64.net - DNS Failover Policy $policy[name] TRIGGERED",$mail,"");
			}
		}
		$jetzt = date("Y-m-d H:i:s",time());
		$statement = $pdo->prepare("UPDATE dns_failover_policies set last_check = :last_check WHERE failover_hash = :policyhash");
		$result = $statement->execute(array('last_check' => $jetzt,'policyhash' => $policy["failover_hash"]));
		continue;
	}
	
	//DNS FALLBACK
	//Nur wenn in Status 2
	if($policy["status"] == "2" OR $policy["status"] == "5")
	{
		//Nur wenn alle Healthchecks ONLINE oder nur einer. 
		$i=0;$all=0;
		$statement = $pdo->prepare("SELECT healthtoken,id,negate FROM dns_failover_monitors WHERE failover_hash = :policyhash");
		$result = $statement->execute(array('policyhash' => $policy["failover_hash"]));
		$monitors = $statement->fetchAll();
		foreach($monitors as $monitor)
		{	$i++;
			$hc = failover_check($pdo, (int)$policy["userid"], (string)$monitor["healthtoken"]) ?: array('status' => ''); //Healthcheck geloescht: zaehlt weder online noch offline
			if($hc["status"] == "1" AND $monitor["negate"] == 0){$all++;}
			if($hc["status"] == "4" AND $monitor["negate"] == 1){$all++;}
		}

		//ALLE MÜSSEN ONLINE SEIN ----- ODER ----- NUR EINER REICHT SCHON
		if(($all == $i AND $i != 0 AND $all != 0 AND $policy["fallback_rule"] == 1 AND $policy["failover_type"] == 1 AND $policy["manual"] == 0 AND $policy["linking"] == "and") 
			OR ($all <= $i AND $i != 0 AND $all != 0 AND $policy["fallback_rule"] == 0 AND $policy["failover_type"] == 1 AND $policy["manual"] == 0 AND $policy["linking"] == "and")
		
		OR ($all == $i AND $i != 0 AND $all != 0 AND $policy["fallback_rule"] == 1 AND $policy["failover_type"] == 1 AND $policy["manual"] == 0 AND $policy["linking"] == "or")
					OR ($i != 0 AND $all > 0 AND $policy["fallback_rule"] == 0 AND $policy["failover_type"] == 1 AND $policy["manual"] == 0 AND $policy["linking"] == "or")
					
		OR ($policy["status"] == "5" AND $policy["manual"] == 1)){
			//echo $policy["name"]." ".$i." ".$all."\n";
			
			echo "Failback $policy[id]";
			//Records nach Regeln AKTIVIEREN		
			//Temporäre Records löschen
			//TEMPO LÖSCHEN
			//War da drin: thema CDN -  AND deactivated = '0'
			$statement = $pdo->prepare("SELECT DISTINCT userid,subdomain_id,type,praefix FROM subdomain_records WHERE failover_policy = :failover_policy AND failover = '1'");
			$result = $statement->execute(array('failover_policy' => $policy["failover_hash"]));
			$tempSets = $statement->fetchAll();
			$statement = $pdo->prepare("DELETE FROM subdomain_records WHERE failover_policy = :failover_policy AND failover = '1'");
			$result = $statement->execute(array('failover_policy' => $policy["failover_hash"]));
			$done = array();
				
			$statement = $pdo->prepare("SELECT * FROM dns_failover_rules WHERE failover_hash = :fh");
			$result = $statement->execute(array("fh"=>$policy["failover_hash"]));
			$rules = $statement->fetchAll();
			foreach($rules as $rule)
			{	
				//Lese Original Record aus 
				$statement = $pdo->prepare("SELECT * FROM subdomain_records WHERE BINARY record_key = :record_key");
				$result = $statement->execute(array('record_key' => $rule["subdomain_record_key"]));
				$record = $statement->fetch();
				if($record === false) { //Original-Record geloescht: nur die Regel zuruecksetzen
					$statement = $pdo->prepare("UPDATE dns_failover_rules set status = :status,temp_record_key = :trk WHERE id = :id");
					$result = $statement->execute(array('status' => "0",'id' => $rule["id"],'trk' => "0"));
					continue;
				}
				
				//Ist es CDN ? (altes CDN oder CDN64 online: Original bleibt deaktiviert)
				if($record["cdn_token"] != 0 OR failover_cdn64o_active($pdo, $record)) {
					$deactivated = 1;
				}else{ $deactivated = 0;}
				
				//ONLINE nehmen 
				$statement = $pdo->prepare("UPDATE subdomain_records set deactivated = :deactivated,failover_policy = :fp WHERE BINARY record_key = :record_key");
				$result = $statement->execute(array('deactivated' => $deactivated,'fp' => "0",'record_key' => $rule["subdomain_record_key"]));
				
				//Rules Status ändern in 
				$statement = $pdo->prepare("UPDATE dns_failover_rules set status = :status,temp_record_key = :trk WHERE id = :id");
				$result = $statement->execute(array('status' => "0",'id' => $rule["id"],'trk' => "0"));
				
				//DNS Update ausführen
				do_zone_update($pdo,$record["userid"],$record["subdomain_id"],$record["type"],$accountclass["ttl"],$record["praefix"]);
				$done[$record["subdomain_id"]."|".$record["type"]."|".$record["praefix"]] = 1;
				
				//Checken ob es sich hier um ein CDN handelt
				if($record["cdn_token"] != 0) {
					$command = cdn_update_dns($pdo, $record["id"], $record["userid"]);
				}
			}
			//Zonen, deren Original-Record fehlt: Ersatz-IP trotzdem aus PowerDNS nehmen
			foreach($tempSets as $ts) {
				if(isset($done[$ts["subdomain_id"]."|".$ts["type"]."|".$ts["praefix"]])) { continue; }
				do_zone_update($pdo,$ts["userid"],$ts["subdomain_id"],$ts["type"],$accountclass["ttl"],$ts["praefix"]);
			}
			//Ganze Policy Status auf 0 pending setzen
			$statement = $pdo->prepare("UPDATE dns_failover_policies set status = :status,manual = :manual WHERE failover_hash = :policyhash");
			$result = $statement->execute(array('status' => "0",'manual' => "0",'policyhash' => $policy["failover_hash"]));
			//Log setzen 
			add_log($pdo,$policy["userid"],"1","DNS Failover Policy","DNS Failover Policy FALLBACK");
			
			//Integration triggern 
			if($policy["disable_notifications"] == 0) {
				send_integrations($pdo,$policy["userid"],$policy["integration"],"IPv64.net - DNS Failover Policy $policy[name] FALLBACK",$mail,"");
			}
		}
		$jetzt = date("Y-m-d H:i:s",time());
		$statement = $pdo->prepare("UPDATE dns_failover_policies set last_check = :last_check WHERE failover_hash = :policyhash");
		$result = $statement->execute(array('last_check' => $jetzt,'policyhash' => $policy["failover_hash"]));
		continue;
	}
}
echo "warte..";
sleep(18);
}
$mail->smtpClose();
		
?>