<?php 
include("header.php");
// Anzahl und Stand einer Datei unter blocklists/ (Zeilen = Netze; Stand = letzte Aenderung der Datei)
function bl_file_info(string $rel): array { $p = __DIR__ . '/blocklists/' . $rel; if(!is_file($p)) { return array(0, ''); } return array(count(file($p, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)), date('Y-m-d H:i:s', filemtime($p))); }
// Status nach Alter: aelter als 2 Tage = veraltet
function bl_status(string $updated): string { $old = $updated === '' || (time() - strtotime($updated)) > 2 * 86400; return '<span class="badge badge-' . ($old ? 'warning">Outdated' : 'success">Ok') . '</span>'; }
?>

 <div class="jumbotron jumbotron-fluid d-none d-xl-block p-3">
	<div class="container">
	  <h1 class="display-3"><img src="https://ipv64.net/img/logo_64.png" height="80" alt="IPv64 Logo" class="mb-3">
	   IPv64 Blocklists - First Level Protection <i class="fa-solid fa-shield-halved text-success"></i></h1>
	  <p class="lead">The <strong>IPv64.net blocklists</strong> make use of the already known and <strong>well-established blocklists</strong> and prepare them for the 
	  further operation of your systems. IPv64 processes the lists and you can easily integrate them into your infrastructure
	  immediately and always up-to-date. </p>

	</div>
  </div>
	<div class="container">
		<?php $node64_hint = "The v64 Blocklist grows from Honeypot64 reports – run your own sensor with Node64, the homelab container by ipv64.net."; $node64_hint_btn = "More about Node64"; $node64_hint_href = "/node64.php?lang=en"; include("node64_hint.php"); ?>
		<div class="row">

	  <div class="col-7">
		<div class="card shadow-sm">
		  <div class="card-header">
			<i class="fa-solid fa-microchip text-info"></i>
			IPv64.net Blocklists - Collections</strong>
		  </div>
		  <div class="card-body p-0">
			<table class="table table-striped" style="table-layout: fixed;over-flow: break-word;">
			  <thead>
				<tr>
				  <th scope="col" width="3%"></th>
				  <th scope="col">Source Blocklist</th>
				  <th scope="col">Blocked (IP/Net)</th>
				  <th scope="col">Status | Updated</th>
				  <th scope="col">Link to List</th>
				</tr>
			  </thead>
				  <tbody>
					<?php [$cnt, $upd] = bl_file_info('ipv64_blocklist_v64.txt'); ?>
					<tr class="table-info">
					<td><i class="fa-solid fa-crown text-warning"></i>
					<td>v64 Blocklist (Honeypot64) <span class="badge badge-info">Honeypot</span> <span class="badge badge-light" title="Not part of the combined list &quot;All&quot;">not in All</span>
					<br><small class="text-muted">Own data of IPv64.net: attackers confirmed by several independent Honeypot64 sensors. Daily list free for everyone;
					live list (every 30 min) for contributors and plans from VIP: token at <a href="/honeypot/token.php">/honeypot/token.php</a></small>
					<td><span class="badge badge-dark" title="<?php echo $cnt;?>"><?php echo formatLargeNumber($cnt);?></span>
					<td><?php echo bl_status($upd); ?>
					<span class="badge badge-primary"> <?php echo $upd !== '' ? timeago2($upd,date("Y-m-d H:i:s",time())) : '-'; ?></span>
					<td><a href="https://ipv64.net/blocklists/ipv64_blocklist_v64.txt" target="_blank" title="v64 Blocklist RAW Format">
					<span class="badge badge-success">All</span></a>
					<a href="https://ipv64.net/blocklists/ipv64_blocklist_v4_v64.txt" target="_blank" title="v64 Blocklist only IPv4 RAW Format">
					<span class="badge badge-dark">Only v4</span></a>
					<a href="https://ipv64.net/blocklists/ipv64_blocklist_v6_v64.txt" target="_blank" title="v64 Blocklist only IPv6 RAW Format">
					<span class="badge badge-secondary">Only v6</span></a>
					</tr>
					<?php 
					$statement = $pdo->prepare("SELECT * FROM blocklisten");
					$result = $statement->execute();
					$blocklisten = $statement->fetchAll();
					foreach($blocklisten as $blockliste)
					{
					?>
					<tr>
						<td><i class="fa-solid fa-check-double"></i>
						<td><?php echo $blockliste["name"];?>
						<?php if(!empty($blockliste["category"]) AND $blockliste["category"] != "attack") { ?><span class="badge badge-info"><?php echo htmlspecialchars(ucfirst($blockliste["category"]));?></span><?php } ?>
						<?php if(isset($blockliste["in_all"]) AND $blockliste["in_all"] == 0) { ?><span class="badge badge-light" title="Not part of the combined list &quot;All&quot;">not in All</span><?php } ?>
						<?php if(!empty($blockliste["description"])) { ?><br><small class="text-muted"><?php echo htmlspecialchars($blockliste["description"]);?><?php if(!empty($blockliste["license"])) { ?> &middot; <?php echo htmlspecialchars($blockliste["license"]);?><?php } ?></small><?php } ?>
						<td><span class="badge badge-dark" title="<?php echo $blockliste["ips"];?>"><?php echo formatLargeNumber($blockliste["ips"]);?></span>
						<td><?php echo bl_status((string)$blockliste["last_updated"]); ?>
						<span class="badge badge-primary"> <?php echo timeago2($blockliste["last_updated"],date("Y-m-d H:i:s",time())); ?></span>
						<td><a href="https://ipv64.net/blocklists/ipv64_blocklist_<?php echo $blockliste["file_name"];?>.txt" target="_blank" title="<?php echo $blockliste["name"];?> RAW Format">
						<span class="badge badge-success">All</span></a>
						<?php if($blockliste["db_name"] != "bl_sh_drop_v4" AND $blockliste["db_name"] != "bl_sh_drop_v6") { ?>
						<a href="https://ipv64.net/blocklists/ipv64_blocklist_v4_<?php echo $blockliste["file_name"];?>.txt" target="_blank" title="<?php echo $blockliste["name"];?> Blocklist only IPv4 RAW Format">
						<span class="badge badge-dark">Only v4</span></a>
						<a href="https://ipv64.net/blocklists/ipv64_blocklist_v6_<?php echo $blockliste["file_name"];?>.txt" target="_blank" title="<?php echo $blockliste["name"];?> Blocklist only IPv6 RAW Format">
						<span class="badge badge-secondary">Only v6</span></a>
						<?php } ?>
					</tr>
					<?php
					}
					?>
					<?php // KI-Bots (bots/blocklist/ai_bots.php), nicht in "all" ?>
					<?php [$cnt, $upd] = bl_file_info('ipv64_blocklist_ai_bots.txt'); if($upd !== '') { ?>
					<tr>
						<td><i class="fa-solid fa-robot"></i>
						<td>v64 AI Bots (IP) <span class="badge badge-info">AI</span> <span class="badge badge-light" title="Not part of the combined list &quot;All&quot;">not in All</span>
						<br><small class="text-muted">Official IP ranges published by AI operators: OpenAI (GPTBot, OAI-SearchBot, ChatGPT-User), Perplexity (PerplexityBot, Perplexity-User),
						Common Crawl (CCBot), Mistral (MistralAI-User), Google-Agent. Includes fetches on behalf of users. Ranges shared with normal search (Googlebot, Bingbot, Applebot) are not included.
						Checked daily; if an operator is unreachable, its last good list is kept.
						<a href="https://ipv64.net/blocklists/ipv64_blocklist_ai_bots_sources.txt" target="_blank">Networks with source</a></small>
						<td><span class="badge badge-dark" title="<?php echo $cnt;?>"><?php echo formatLargeNumber($cnt);?></span>
						<td><?php echo bl_status($upd); ?>
						<span class="badge badge-primary"> <?php echo timeago2($upd,date("Y-m-d H:i:s",time())); ?></span>
						<td><a href="https://ipv64.net/blocklists/ipv64_blocklist_ai_bots.txt" target="_blank" title="v64 AI Bots (IP) RAW Format">
						<span class="badge badge-success">All</span></a>
						<a href="https://ipv64.net/blocklists/ipv64_blocklist_v4_ai_bots.txt" target="_blank" title="v64 AI Bots (IP) only IPv4 RAW Format">
						<span class="badge badge-dark">Only v4</span></a>
						<a href="https://ipv64.net/blocklists/ipv64_blocklist_v6_ai_bots.txt" target="_blank" title="v64 AI Bots (IP) only IPv6 RAW Format">
						<span class="badge badge-secondary">Only v6</span></a>
					</tr>
					<?php } [$cnt, $upd] = bl_file_info('ipv64_ai_useragents.txt'); if($upd !== '') { ?>
					<tr>
						<td><i class="fa-solid fa-robot"></i>
						<td>v64 AI Bots (User-Agent) <span class="badge badge-info">AI</span> <span class="badge badge-light">User-Agent list</span>
						<br><small class="text-muted">User agent tokens of AI crawlers, assistants and agents, mirrored daily from
						<a href="https://github.com/ai-robots-txt/ai.robots.txt" target="_blank" rel="noopener">ai.robots.txt</a> (MIT). Text: one token per line;
						JSON with operator, function and a flag for fetches on behalf of users; robots.txt block. Match case-insensitively in the User-Agent header (web server, reverse proxy, Node64 PROXY64).</small>
						<td><span class="badge badge-dark" title="<?php echo $cnt;?>"><?php echo formatLargeNumber($cnt);?></span>
						<td><?php echo bl_status($upd); ?>
						<span class="badge badge-primary"> <?php echo timeago2($upd,date("Y-m-d H:i:s",time())); ?></span>
						<td><a href="https://ipv64.net/blocklists/ipv64_ai_useragents.txt" target="_blank" title="One user agent token per line">
						<span class="badge badge-success">TXT</span></a>
						<a href="https://ipv64.net/blocklists/ipv64_ai_useragents.json" target="_blank" title="JSON with operator, function and user flag">
						<span class="badge badge-dark">JSON</span></a>
						<a href="https://ipv64.net/blocklists/ipv64_ai_robots.txt" target="_blank" title="robots.txt block (Disallow for all listed AI bots)">
						<span class="badge badge-secondary">robots.txt</span></a>
					</tr>
					<?php } ?>
					<?php [$cnt, $upd] = bl_file_info('ipv64_blocklist_all.txt'); ?>
					<tr class="table-info">
						<td><i class="fa-solid fa-crown text-warning"></i>
						<td>All lists combined <small>(includes Tor)</small>
						<td><span class="badge badge-dark" title="<?php echo $cnt;?>"><?php echo formatLargeNumber($cnt);?></span>
						<td><?php echo bl_status($upd); ?>
						<span class="badge badge-primary"> <?php echo $upd !== '' ? timeago2($upd,date("Y-m-d H:i:s",time())) : '-'; ?></span>
						<td><a href="https://ipv64.net/blocklists/ipv64_blocklist_all.txt" target="_blank" title="IPv64.net All lists combined (includes Tor) RAW Format">
						<span class="badge badge-success">All</span></a>
						<a href="https://ipv64.net/blocklists/ipv64_blocklist_v4_all.txt" target="_blank" title="IPv64.net All lists combined (includes Tor) only IPv4 RAW Format">
						<span class="badge badge-dark">Only v4</span></a>
						<a href="https://ipv64.net/blocklists/ipv64_blocklist_v6_all.txt" target="_blank" title="IPv64.net All lists combined (includes Tor) only IPv6 RAW Format">
						<span class="badge badge-secondary">Only v6</span></a>
					</tr>
					<?php [$cnt, $upd] = bl_file_info('ipv64_blocklist_all_notor.txt'); ?>
					<tr class="table-info">
						<td><i class="fa-solid fa-crown text-warning"></i>
						<td>All lists without Tor
						<td><span class="badge badge-dark" title="<?php echo $cnt;?>"><?php echo formatLargeNumber($cnt);?></span>
						<td><?php echo bl_status($upd); ?>
						<span class="badge badge-primary"> <?php echo $upd !== '' ? timeago2($upd,date("Y-m-d H:i:s",time())) : '-'; ?></span>
						<td><a href="https://ipv64.net/blocklists/ipv64_blocklist_all_notor.txt" target="_blank" title="IPv64.net All lists without Tor RAW Format">
						<span class="badge badge-success">All</span></a>
						<a href="https://ipv64.net/blocklists/ipv64_blocklist_v4_all_notor.txt" target="_blank" title="IPv64.net All lists without Tor only IPv4 RAW Format">
						<span class="badge badge-dark">Only v4</span></a>
						<a href="https://ipv64.net/blocklists/ipv64_blocklist_v6_all_notor.txt" target="_blank" title="IPv64.net All lists without Tor only IPv6 RAW Format">
						<span class="badge badge-secondary">Only v6</span></a>
					</tr>
					<tr class="table-secondary">
					<td><i class="fa-solid fa-globe"></i>
					<td><strong>Continent Blocklists</strong>
					<td><strong>Blocked (IP/Net)</strong>
					<td><strong>Status | Updated</strong>
					<td><strong>Link to List</strong>
					</tr>
					<tr>
						<td><i class="fa-solid fa-earth-europe"></i>
						<td>Europe
						<?php [$cnt, $upd] = bl_file_info('countries/ipv64_blocklist_europe.txt'); ?>
						<td><span class="badge badge-dark" title="<?php echo $cnt;?>"><?php echo formatLargeNumber($cnt);?></span>
						<td><?php echo bl_status($upd); ?>
						<span class="badge badge-primary"> <?php echo $upd !== '' ? timeago2($upd,date("Y-m-d H:i:s",time())) : '-'; ?></span>
						<td><a href="https://ipv64.net/blocklists/countries/ipv64_blocklist_europe.txt" target="_blank" title="Europe Blocklist RAW Format">
						<span class="badge badge-success">All</span></a>
						<a href="https://ipv64.net/blocklists/countries/ipv64_blocklist_v4_europe.txt" target="_blank" title="Europe Blocklist only IPv4 RAW Format">
						<span class="badge badge-dark">Only v4</span></a>
						<a href="https://ipv64.net/blocklists/countries/ipv64_blocklist_v6_europe.txt" target="_blank" title="Europe Blocklist only IPv6 RAW Format">
						<span class="badge badge-secondary">Only v6</span></a>
					</tr>
					<tr>
						<td><i class="fa-solid fa-earth-asia"></i>
						<td>Asia
						<?php [$cnt, $upd] = bl_file_info('countries/ipv64_blocklist_asia.txt'); ?>
						<td><span class="badge badge-dark" title="<?php echo $cnt;?>"><?php echo formatLargeNumber($cnt);?></span>
						<td><?php echo bl_status($upd); ?>
						<span class="badge badge-primary"> <?php echo $upd !== '' ? timeago2($upd,date("Y-m-d H:i:s",time())) : '-'; ?></span>
						<td><a href="https://ipv64.net/blocklists/countries/ipv64_blocklist_asia.txt" target="_blank" title="Asia Blocklist RAW Format">
						<span class="badge badge-success">All</span></a>
						<a href="https://ipv64.net/blocklists/countries/ipv64_blocklist_v4_asia.txt" target="_blank" title="Asia Blocklist only v4 RAW Format">
						<span class="badge badge-dark">Only v4</span></a>
						<a href="https://ipv64.net/blocklists/countries/ipv64_blocklist_v6_asia.txt" target="_blank" title="Asia Blocklist only v6 RAW Format">
						<span class="badge badge-secondary">Only v6</span></a>
					</tr>
					<tr>
						<td><i class="fa-solid fa-earth-africa"></i>
						<td>Africa
						<?php [$cnt, $upd] = bl_file_info('countries/ipv64_blocklist_africa.txt'); ?>
						<td><span class="badge badge-dark" title="<?php echo $cnt;?>"><?php echo formatLargeNumber($cnt);?></span>
						<td><?php echo bl_status($upd); ?>
						<span class="badge badge-primary"> <?php echo $upd !== '' ? timeago2($upd,date("Y-m-d H:i:s",time())) : '-'; ?></span>
						<td><a href="https://ipv64.net/blocklists/countries/ipv64_blocklist_africa.txt" target="_blank" title="Africa Blocklist RAW Format">
						<span class="badge badge-success">All</span></a>
						<a href="https://ipv64.net/blocklists/countries/ipv64_blocklist_v4_africa.txt" target="_blank" title="Africa Blocklist only IPv4 RAW Format">
						<span class="badge badge-dark">Only v4</span></a>
						<a href="https://ipv64.net/blocklists/countries/ipv64_blocklist_v6_africa.txt" target="_blank" title="Africa Blocklist only IPv6 RAW Format">
						<span class="badge badge-secondary">Only v6</span></a>
					</tr>
					<tr>
						<td><i class="fa-solid fa-earth-americas"></i>
						<td>North America
						<?php [$cnt, $upd] = bl_file_info('countries/ipv64_blocklist_north_america.txt'); ?>
						<td><span class="badge badge-dark" title="<?php echo $cnt;?>"><?php echo formatLargeNumber($cnt);?></span>
						<td><?php echo bl_status($upd); ?>
						<span class="badge badge-primary"> <?php echo $upd !== '' ? timeago2($upd,date("Y-m-d H:i:s",time())) : '-'; ?></span>
						<td><a href="https://ipv64.net/blocklists/countries/ipv64_blocklist_north_america.txt" target="_blank" title="North America Blocklist RAW Format">
						<span class="badge badge-success">All</span></a>
						<a href="https://ipv64.net/blocklists/countries/ipv64_blocklist_v4_north_america.txt" target="_blank" title="North America Blocklist only IPv4 RAW Format">
						<span class="badge badge-dark">Only v4</span></a>
						<a href="https://ipv64.net/blocklists/countries/ipv64_blocklist_v6_north_america.txt" target="_blank" title="North America Blocklist only IPv6 RAW Format">
						<span class="badge badge-secondary">Only v6</span></a>
					</tr>
					<tr>
						<td><i class="fa-solid fa-earth-americas"></i>
						<td>South America
						<?php [$cnt, $upd] = bl_file_info('countries/ipv64_blocklist_south_america.txt'); ?>
						<td><span class="badge badge-dark" title="<?php echo $cnt;?>"><?php echo formatLargeNumber($cnt);?></span>
						<td><?php echo bl_status($upd); ?>
						<span class="badge badge-primary"> <?php echo $upd !== '' ? timeago2($upd,date("Y-m-d H:i:s",time())) : '-'; ?></span>
						<td><a href="https://ipv64.net/blocklists/countries/ipv64_blocklist_south_america.txt" target="_blank" title="South America Blocklist RAW Format">
						<span class="badge badge-success">All</span></a>
						<a href="https://ipv64.net/blocklists/countries/ipv64_blocklist_v4_south_america.txt" target="_blank" title="South America Blocklist only IPv4 RAW Format">
						<span class="badge badge-dark">Only v4</span></a>
						<a href="https://ipv64.net/blocklists/countries/ipv64_blocklist_v6_south_america.txt" target="_blank" title="South America Blocklist only IPv6 RAW Format">
						<span class="badge badge-secondary">Only v6</span></a>
					</tr>
					<tr>
						<td><i class="fa-solid fa-earth-oceania"></i>
						<td>Oceania
						<?php [$cnt, $upd] = bl_file_info('countries/ipv64_blocklist_oceania.txt'); ?>
						<td><span class="badge badge-dark" title="<?php echo $cnt;?>"><?php echo formatLargeNumber($cnt);?></span>
						<td><?php echo bl_status($upd); ?>
						<span class="badge badge-primary"> <?php echo $upd !== '' ? timeago2($upd,date("Y-m-d H:i:s",time())) : '-'; ?></span>
						<td><a href="https://ipv64.net/blocklists/countries/ipv64_blocklist_oceania.txt" target="_blank" title="Oceania Blocklist RAW Format">
						<span class="badge badge-success">All</span></a>
						<a href="https://ipv64.net/blocklists/countries/ipv64_blocklist_v4_oceania.txt" target="_blank" title="Oceania Blocklist only IPv4 RAW Format">
						<span class="badge badge-dark">Only v4</span></a>
						<a href="https://ipv64.net/blocklists/countries/ipv64_blocklist_v6_oceania.txt" target="_blank" title="Oceania Blocklist only IPv6 RAW Format">
						<span class="badge badge-secondary">Only v6</span></a>
					</tr>
					<tr class="table-secondary">
					<td><i class="fa-solid fa-flag"></i>
					<td><strong>Countries Blocklists</strong>
					<td><strong>Blocked (IP/Net)</strong>
					<td><strong>Status | Updated</strong>
					<td><strong>Link to List</strong>
					</tr>
					<?php 
					$statement = $pdo->prepare("SELECT * FROM blocklisten_countries ORDER BY country");
					$result = $statement->execute();
					$blocklisten = $statement->fetchAll();
					foreach($blocklisten as $blockliste)
					{
					?>
					<tr>
						<td><!-- <img src="/img/country/<?php echo strtolower($blockliste["country"]);?>.svg" width="20"> -->
						<td><?php echo $blockliste["country_name"];?>
						<td><span class="badge badge-dark" title="<?php echo $blockliste["ips"];?>"><?php echo formatLargeNumber($blockliste["ips"]);?></span>
						<td><?php echo bl_status((string)$blockliste["last_updated"]); ?>
						<span class="badge badge-primary"> <?php echo timeago2($blockliste["last_updated"],date("Y-m-d H:i:s",time())); ?></span>
						<td>
						<a href="https://ipv64.net/blocklists/countries/ipv64_blocklist_<?php echo $blockliste["file_name"];?>.txt" target="_blank" title="IP/Network List for <?php echo $blockliste["country_name"];?>">
						<span class="badge badge-success">All</span>
						</a>
						<a href="https://ipv64.net/blocklists/countries/ipv64_blocklist_v4_<?php echo $blockliste["file_name"];?>.txt" target="_blank" title="IP/Network List for <?php echo $blockliste["country_name"];?>">
						<span class="badge badge-dark">Only v4</span>
						</a>
						<a href="https://ipv64.net/blocklists/countries/ipv64_blocklist_v6_<?php echo $blockliste["file_name"];?>.txt" target="_blank" title="IP/Network List for <?php echo $blockliste["country_name"];?>">
						<span class="badge badge-secondary">Only v6</span>
						</a>
					</tr>
					<?php 
					} 
					?>
				</tbody>
			</table>
		  </div>
		</div>
	  </div>
	  <div class="col-5">
	      <div class="card shadow-sm">
			<div class="card-header">
			<i class="fa-solid fa-info text-info"></i>
				Further information about the IPv64.net blocklists</strong>
			  </div>
			  <div class="card-body">
				<p>
				The <strong>IPv64.net Blocklists</strong> are various common and already tested blocklists replicated from the Internet. 
				We process these automatically and make them available to you free of charge. 
				</p>
				<p>
				The advantage of these processed blocklists is that they do not contain any comments, notes or other entries, but really 
				only IP addresses and entire subnets. Duplicates, networks contained in larger ones and reserved ranges have been removed. 
				The entries come from the source projects; if an address is listed by mistake, ask the source project to remove it. 
				The lists are regenerated several times a day, country lists daily from the regional Internet registries (RIR).
				</p>
				<p>
					<ul><li><a href="v64_blocklist_integration_guide">Read the IPv64 Blocklist integration Guide <i class="fa-solid fa-book"></i></a></li>
					<li><a href="/blocklists/index.json" target="_blank">index.json: all lists with count, update, source and license (for scripts)</a></li></ul>
				</p>
			  </div>
		  </div>
		  <p></p>
		  <div class="card shadow-sm">
			<div class="card-header">
			<i class="fa-solid fa-info text-info"></i>
				Why should I use blocklists?</strong>
			  </div>
			  <div class="card-body">
				<p>
				Blocklists are in the <strong>"first line of defense"</strong> of your systems. If an attacker can't access your system in the first place 
				or even get as far as it, then you have already achieved 95% of your goal. Of course, there are many other ways into your 
				infrastructure, but this direct route remains completely blocked for third parties. 
				</p>
				<p>
				You need another Blocklist, which should be listed here in this list? Then please write to the forum with all the 
				information you need. At best, directly with a source where this list comes from.
				</p>
				<p>
				<a href="https://v64.tech/c/ipv64-services/v64-secure/9" target="_blank" alt="v64.tech Forum" class="btn btn-sm btn-primary">v64.tech Forum</a>
				</p>
			  </div>
		  </div>
	  </div>
	  </div>
		
		</div>
<div class="bd-masthead mb-3" id="content">
  <div class="container-xxl bd-gutter">
	<div class="col-md-8 mx-auto text-center">
	  <img src="/img/logo_64.png" height="165" alt="IPv64 Logo Minimal" class="d-block mx-auto mb-3">
	  <h1 class="mb-3 fw-semibold lh-1">First Level Protection with IPv64.net</h1>
	  <p class="lead mb-4">
		With IPv64.net you can effectively protect your systems and infrastructures against various attacks from the Internet. 
	  </p>
	</div>
  </div>
</div>
			
			
			
		</div>
	 </div>
	</div>
	</div>
	</div>
<p></p>
<?php 
include("footer.php");
?>
<script>
function hide_show_url() {
  var x = document.getElementById("dau");
    x.classList.toggle("inputdisc");
}
function copy_url1() {
  // Get the text field
  var copyText = document.getElementById("dau");
  // Select the text field
  copyText.select();
  copyText.setSelectionRange(0, 99999); // For mobile devices
   // Copy the text inside the text field
  navigator.clipboard.writeText(copyText.value);
}
</script>