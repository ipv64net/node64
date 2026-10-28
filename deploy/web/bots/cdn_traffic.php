<?php 
include("/var/www/clients/client1/web58/web/dbconnect.php");

include("/var/www/clients/client1/web58/web/bots/cdn_functions.php");

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
use PHPMailer\PHPMailer\SMTP;

$mail = new PHPMailer();


echo "Server check START und Abfrage";

$statement = $pdo->prepare("SELECT * FROM cdn_server");
$result = $statement->execute();
$servers = $statement->fetchAll();
foreach($servers as $server)
{
	//Check ob Server erreichbar 
	if (isportopen("$server[hostname].cdn64.de", 80, 1)) {
		$statement = $pdo->prepare("UPDATE cdn_server set online = :online WHERE id = :id");
		$result = $statement->execute(array('online' => 1,'id' => $server["id"]));
	}else{
		$statement = $pdo->prepare("UPDATE cdn_server set online = :online WHERE id = :id");
		$result = $statement->execute(array('online' => 0,'id' => $server["id"]));
	}
}
echo "\nServer check ENDE\n";


$daten = array();

$statement = $pdo->prepare("SELECT * FROM cdn_server");
$result = $statement->execute();
$servers = $statement->fetchAll();
foreach($servers as $server)
{
	echo "Server $server[id]\n";
	//$table_chain_name = "traffic_cdn_$cdn_domain[domainid]";
	
	//$command = "nft --json list table inet $table_chain_name";
	$command = "nft --json list ruleset";
	$data = send_command($server["ipv4"],$command);
	$data = json_decode($data,true);
	if(!empty($data))
	{
		foreach($data["nftables"] as $dataa)
		{
			if(!empty($dataa["rule"]))
			{
				if(!empty($dataa["rule"]["expr"]["0"]["counter"]))
				{
					$cdn_domain = explode("traffic_cdn_",$dataa["rule"]["table"]);
					$cdn_domainid = $cdn_domain["1"];
					$chain = explode("_count_",$dataa["rule"]["chain"]);
					$chain = $chain["1"];
					$bytes = $dataa["rule"]["expr"]["0"]["counter"]["bytes"];
					$daten[$cdn_domainid][$chain]["bytes"] = $bytes;
				}
			}
		}
	}
}
$srvtraff = array();
//Daten zur DB bringen 
foreach($daten as $key => $data)
{
	$statement = $pdo->prepare("SELECT userid,domainid,input_traffic,output_traffic,cdn_server FROM cdn_domains WHERE domainid = :domainid");
	$result = $statement->execute(array("domainid"=>$key));
	$cdn_domain = $statement->fetch();
	
	if($cdn_domain["userid"] != "")
	{
		$statement = $pdo->prepare("SELECT userid,input,output FROM cdn_traffic WHERE domainid = :domainid ORDER BY id DESC LIMIT 1");
		$result = $statement->execute(array("domainid"=>$key));
		$last_traffic = $statement->fetch();
		
		$statement = $pdo->prepare("SELECT id,cdn_traffic_input,cdn_traffic_output FROM users WHERE id = :userid");
		$result = $statement->execute(array("userid"=>$cdn_domain["userid"]));
		$user = $statement->fetch();
		
		//Megabyte machen wa draus.
		$bytes_input = round(($data["input"]["bytes"] / 1024 / 1024),3);
		$bytes_output = round(($data["output"]["bytes"] / 1024 / 1024),3);
		
		$statement = $pdo->prepare("INSERT INTO cdn_traffic (userid,domainid,input,output) VALUES (:userid,:domainid,:input,:output)");
		$result = $statement->execute(array('userid' => $cdn_domain["userid"],'domainid'=> $cdn_domain["domainid"],'input'=> $bytes_input,'output'=> $bytes_output));
		
		//Differenz zur letzten abfrage und dann zur Domain hinzufügen
		if($last_traffic["input"] <= $bytes_input){	$input = $cdn_domain["input_traffic"] + ($bytes_input - $last_traffic["input"]); $srv_in = $bytes_input - $last_traffic["input"]; }else{$input = $cdn_domain["input_traffic"] + $bytes_input;$srv_in = $bytes_input;}
		if($last_traffic["output"] <= $bytes_output){	$output = $cdn_domain["output_traffic"] + ($bytes_output - $last_traffic["output"]); $srv_out = $bytes_output - $last_traffic["output"]; }else{$output = $cdn_domain["output_traffic"] + $bytes_output;$srv_out = $bytes_output;}
		
		if($last_traffic["input"] <= $bytes_input){	$input_user = $user["cdn_traffic_input"] + ($bytes_input - $last_traffic["input"]); }else{$input_user = $user["cdn_traffic_input"] + $bytes_input;}
		if($last_traffic["output"] <= $bytes_output){	$output_user = $user["cdn_traffic_output"] + ($bytes_output - $last_traffic["output"]); }else{$output_user = $user["cdn_traffic_output"] + $bytes_output;}
		
		//echo "$key $last_traffic[input]  $bytes_input = $input_user\n";
		$statement = $pdo->prepare("UPDATE cdn_domains set input_traffic = :input_traffic, output_traffic = :output_traffic WHERE domainid = :domainid");
		$result = $statement->execute(array('input_traffic' => $input,'output_traffic' => $output,'domainid' => $cdn_domain["domainid"]));
		
		$statement = $pdo->prepare("UPDATE users set cdn_traffic_input = :input_traffic, cdn_traffic_output = :output_traffic WHERE id = :id");
		$result = $statement->execute(array('input_traffic' => $input_user,'output_traffic' => $output_user,'id' => $user["id"]));
		
		//Summe für Server 
		$srvtraff[$cdn_domain["cdn_server"]]["input"] += $srv_in;
		$srvtraff[$cdn_domain["cdn_server"]]["output"] += $srv_out;
	}
}
//CDN Server Traffic updaten.
foreach($srvtraff as $key => $data)
{	
	$input = ""; $output = "";
	$statement = $pdo->prepare("SELECT * FROM cdn_server WHERE id = :id");
	$result = $statement->execute(array("id"=>$key));
	$srv = $statement->fetch();
	
	$input = round($data["input"] + $srv["input_traffic"],3);
	$output = round($data["output"] + $srv["output_traffic"],3);
	
	$statement = $pdo->prepare("UPDATE cdn_server set input_traffic = :input_traffic, output_traffic = :output_traffic WHERE id = :id");
	$result = $statement->execute(array('input_traffic' => $input,'output_traffic' => $output,'id' => $srv["id"]));
}


//Blocking folgt noch 
$statement = $pdo->prepare("SELECT id,cdn_traffic_input,cdn_traffic_output,user_class FROM users WHERE (cdn_traffic_input != '0' OR cdn_traffic_output != '0')");
$result = $statement->execute();
$users = $statement->fetchAll();
foreach($users as $user)
{	$summe = 0;
	$statement = $pdo->prepare("SELECT cdn_traffic FROM user_class WHERE id = :id");
	$result = $statement->execute(array("id"=>$user["user_class"]));
	$user_class = $statement->fetch();
	$summe = ($user["cdn_traffic_input"] + $user["cdn_traffic_output"]) / 1024;
	if($summe > $user_class["cdn_traffic"])
	{
		//Nur aktive Proxys/Portmapper abschalten - sonst setzt jeder Lauf schon abgeschaltete wieder auf 2/3 und cdn_bot.php
		//deaktiviert sie endlos neu (rm conf, nginx reload, Log-Eintrag), solange der Account ueber dem Limit ist
		$statement = $pdo->prepare("UPDATE cdn_domains set proxy = :proxy WHERE userid = :userid AND proxy = '1'");
		$result = $statement->execute(array('proxy' => 2,'userid' => $user["id"]));
		$changed = $statement->rowCount();
		$statement = $pdo->prepare("UPDATE cdn_domains set portmapper = :portmapper WHERE userid = :userid AND portmapper = '1'");
		$result = $statement->execute(array('portmapper' => 3,'userid' => $user["id"]));
		$changed += $statement->rowCount();
		if($changed > 0){ add_log($pdo,$user["id"],"0","CDN","Monthly CDN traffic limit reached. Proxy and Portmapper have been disabled."); }
	}
}

$mail->smtpClose();
		
?>