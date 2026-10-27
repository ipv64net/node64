<?php
include("header.php");

// Integrationsleitfaden fuer die IPv64-Blocklisten (Englisch, Deutsch mit ?lang=de).
// Die Linux-Skripte liegen unter /blocklists/tools/ und werden hier direkt angezeigt (eine Quelle).
$blgDe = (($_GET['lang'] ?? '') === 'de');
function blg(string $en, string $de): string { global $blgDe; return $blgDe ? $de : $en; }
function blg_code(string $code): string { return '<pre class="bg-light border rounded p-2 small mb-2" style="white-space:pre-wrap"><code>' . htmlspecialchars($code, ENT_QUOTES) . '</code></pre>'; }
function blg_tool(string $file): string { $p = __DIR__ . '/blocklists/tools/' . basename($file); return is_file($p) ? blg_code((string)file_get_contents($p)) : ''; }
$blgBase = 'https://ipv64.net/blocklists/';
?>
<div class="jumbotron jumbotron-fluid p-3 mb-3">
	<div class="container">
		<h1 class="display-4"><img src="https://ipv64.net/img/logo_64.png" height="70" alt="IPv64 Logo" class="mb-2"> <?php echo blg('Blocklists – Integration Guide', 'Blocklisten – Integrationsleitfaden'); ?> <i class="fa-solid fa-shield-halved text-success"></i></h1>
		<p class="lead mb-1"><?php echo blg('Step-by-step instructions for firewalls, servers and reverse proxies. The Linux scripts and the nginx and CrowdSec examples were tested with the live lists.',
			'Schritt-für-Schritt-Anleitungen für Firewalls, Server und Reverse-Proxys. Die Linux-Skripte sowie die Beispiele für nginx und CrowdSec sind mit den echten Listen getestet.'); ?></p>
		<p class="mb-0"><a href="?lang=en"<?php echo $blgDe ? '' : ' class="font-weight-bold"'; ?>>English</a> · <a href="?lang=de"<?php echo $blgDe ? ' class="font-weight-bold"' : ''; ?>>Deutsch</a> · <a href="/v64_blocklists"><?php echo blg('All lists and download links', 'Alle Listen und Download-Links'); ?></a></p>
	</div>
</div>
<div class="container mb-4">
	<div class="alert alert-warning">
		<strong><?php echo blg('Before you start', 'Bevor du loslegst'); ?>:</strong>
		<?php echo blg('A blocklist drops all traffic from the listed networks. Try it on a test system first, keep a way to access your device (console, VPN) and start with a list with few false positives (Spamhaus DROP or FireHOL Level 1).',
			'Eine Blockliste verwirft allen Verkehr aus den gelisteten Netzen. Probiere sie zuerst auf einem Testsystem, behalte einen Zugang zum Gerät (Konsole, VPN) und beginne mit einer Liste mit wenigen Fehlalarmen (Spamhaus DROP oder FireHOL Level 1).'); ?>
	</div>

	<div class="card mb-3" id="choose">
		<div class="card-header"><i class="fa-solid fa-list-check"></i> 1. <?php echo blg('Choose a list', 'Liste wählen'); ?></div>
		<div class="card-body">
			<div class="table-responsive"><table class="table table-sm">
				<thead><tr><th><?php echo blg('List (ID)', 'Liste (ID)'); ?></th><th><?php echo blg('Content', 'Inhalt'); ?></th><th><?php echo blg('False positives', 'Fehlalarme'); ?></th><th><?php echo blg('Recommended for', 'Empfohlen für'); ?></th></tr></thead>
				<tbody>
					<tr><td><code>spamhaus_drop</code></td><td><?php echo blg('Hijacked and criminal networks (Spamhaus DROP)', 'Gekaperte und kriminelle Netze (Spamhaus DROP)'); ?></td><td><span class="badge badge-success"><?php echo blg('very low', 'sehr gering'); ?></span></td><td><?php echo blg('everyone, inbound and outbound', 'alle, eingehend und ausgehend'); ?></td></tr>
					<tr><td><code>firehole_l1</code></td><td><?php echo blg('FireHOL Level 1: DROP, Feodo, bogons and more', 'FireHOL Level 1: DROP, Feodo, reservierte Netze u. a.'); ?></td><td><span class="badge badge-success"><?php echo blg('low', 'gering'); ?></span></td><td><?php echo blg('routers and servers (good default)', 'Router und Server (guter Standard)'); ?></td></tr>
					<tr><td><code>blocklistde_all</code></td><td><?php echo blg('Attackers reported to blocklist.de in the last 48 hours (SSH, mail, web)', 'Angreifer, die blocklist.de in den letzten 48 Stunden gemeldet wurden (SSH, Mail, Web)'); ?></td><td><span class="badge badge-warning"><?php echo blg('medium', 'mittel'); ?></span></td><td><?php echo blg('servers reachable from the Internet', 'Server, die aus dem Internet erreichbar sind'); ?></td></tr>
					<tr><td><code>dshield1</code></td><td><?php echo blg('DShield: top 20 attacking /24 networks', 'DShield: die 20 aktivsten angreifenden /24-Netze'); ?></td><td><span class="badge badge-success"><?php echo blg('low', 'gering'); ?></span></td><td><?php echo blg('in addition to one of the lists above', 'zusätzlich zu einer Liste oben'); ?></td></tr>
					<tr><td><code>tor_exit</code>, <code>tor_all</code></td><td><?php echo blg('Tor exit nodes / all Tor relays', 'Tor-Exit-Knoten / alle Tor-Relays'); ?></td><td><span class="badge badge-secondary"><?php echo blg('by design', 'gewollt'); ?></span></td><td><?php echo blg('only if you want to lock out Tor users', 'nur, wenn du Tor-Nutzer aussperren willst'); ?></td></tr>
					<tr><td><code>feodo</code></td><td><?php echo blg('Botnet command and control servers (abuse.ch Feodo Tracker)', 'Steuerserver von Botnetzen (abuse.ch Feodo Tracker)'); ?></td><td><span class="badge badge-success"><?php echo blg('very low', 'sehr gering'); ?></span></td><td><?php echo blg('outbound, so infected devices cannot reach their servers', 'ausgehend, damit infizierte Geräte ihre Server nicht erreichen'); ?></td></tr>
					<tr><td><code>et_compromised</code></td><td><?php echo blg('Known compromised hosts (Emerging Threats)', 'Bekannt kompromittierte Hosts (Emerging Threats)'); ?></td><td><span class="badge badge-success"><?php echo blg('low', 'gering'); ?></span></td><td><?php echo blg('in addition to one of the lists above', 'zusätzlich zu einer Liste oben'); ?></td></tr>
					<tr><td><code>all</code></td><td><?php echo blg('The lists above combined', 'Die Listen oben zusammen'); ?></td><td><span class="badge badge-warning"><?php echo blg('medium', 'mittel'); ?></span></td><td><?php echo blg('<strong>contains the Tor lists</strong> – Tor users are blocked too', '<strong>enthält die Tor-Listen</strong> – Tor-Nutzer werden mit gesperrt'); ?></td></tr>
					<tr><td><code>all_notor</code></td><td><?php echo blg('The lists above combined, without Tor', 'Die Listen oben zusammen, ohne Tor'); ?></td><td><span class="badge badge-warning"><?php echo blg('medium', 'mittel'); ?></span></td><td><?php echo blg('servers that should block attackers but not Tor users', 'Server, die Angreifer sperren sollen, aber keine Tor-Nutzer'); ?></td></tr>
					<tr class="table-secondary"><td colspan="4"><?php echo blg('Not part of <code>all</code>:', 'Nicht in <code>all</code> enthalten:'); ?></td></tr>
					<tr><td><code>cins_army</code>, <code>ipsum_l3</code></td><td><?php echo blg('Large reputation lists: CINS Army, IPsum (on at least 3 blocklists)', 'Große Reputationslisten: CINS Army, IPsum (auf mindestens 3 Sperrlisten)'); ?></td><td><span class="badge badge-warning"><?php echo blg('medium', 'mittel'); ?></span></td><td><?php echo blg('servers that see a lot of scanning', 'Server, die viel gescannt werden'); ?></td></tr>
					<tr><td><code>doh_servers</code></td><td><?php echo blg('Public DNS over HTTPS servers', 'Öffentliche DNS-over-HTTPS-Server'); ?></td><td><span class="badge badge-secondary"><?php echo blg('by design', 'gewollt'); ?></span></td><td><?php echo blg('<strong>outbound only</strong> (LAN rule with destination = list), so devices use your own DNS', '<strong>nur ausgehend</strong> (LAN-Regel mit Ziel = Liste), damit Geräte deinen eigenen DNS nutzen'); ?></td></tr>
					<tr><td><code>cloudflare</code>, <code>aws</code>, <code>gcp</code></td><td><?php echo blg('Networks of Cloudflare, Amazon AWS and Google Cloud', 'Netze von Cloudflare, Amazon AWS und Google Cloud'); ?></td><td><span class="badge badge-secondary"><?php echo blg('by design', 'gewollt'); ?></span></td><td><?php echo blg('<code>cloudflare</code> as an <strong>allow list</strong> for servers behind Cloudflare; <code>aws</code>/<code>gcp</code> to block data centers', '<code>cloudflare</code> als <strong>Freigabeliste</strong> für Server hinter Cloudflare; <code>aws</code>/<code>gcp</code> zum Sperren von Rechenzentren'); ?></td></tr>
					<tr class="table-secondary"><td colspan="4"><?php echo blg('v64 Blocklist (Honeypot64), not part of <code>all</code> – <a href="#live">live state with list token</a>:', 'v64 Blocklist (Honeypot64), nicht in <code>all</code> enthalten – <a href="#live">Live-Stand mit Listen-Token</a>:'); ?></td></tr>
					<tr><td><code>v64</code></td><td><?php echo blg('Attackers reported by several independent <a href="/honeypot/">Honeypot64</a> sensors (logins, exploits, scans), without research scanners', 'Angreifer, die mehrere unabhängige <a href="/honeypot/">Honeypot64</a>-Sensoren gemeldet haben (Logins, Exploits, Scans), ohne Forschungs-Scanner'); ?></td><td><span class="badge badge-info"><?php echo blg('new', 'neu'); ?></span></td><td><?php echo blg('servers reachable from the Internet, in addition to one of the lists above', 'Server, die aus dem Internet erreichbar sind, zusätzlich zu einer Liste oben'); ?></td></tr>
				</tbody>
			</table></div>
			<p class="mb-1"><?php echo blg('Every list is available in three variants; replace <code>&lt;id&gt;</code> with the ID from the table:', 'Jede Liste gibt es in drei Varianten; <code>&lt;id&gt;</code> durch die ID aus der Tabelle ersetzen:'); ?></p>
			<ul class="mb-2">
				<li><?php echo blg('IPv4 and IPv6', 'IPv4 und IPv6'); ?>: <code><?php echo $blgBase; ?>ipv64_blocklist_&lt;id&gt;.txt</code></li>
				<li><?php echo blg('IPv4 only', 'nur IPv4'); ?>: <code><?php echo $blgBase; ?>ipv64_blocklist_v4_&lt;id&gt;.txt</code></li>
				<li><?php echo blg('IPv6 only', 'nur IPv6'); ?>: <code><?php echo $blgBase; ?>ipv64_blocklist_v6_&lt;id&gt;.txt</code></li>
				<li>MikroTik RouterOS: <code><?php echo $blgBase; ?>v64_mikrotik_v4_&lt;id&gt;.rsc</code> <?php echo blg('and', 'und'); ?> <code>…_v6_&lt;id&gt;.rsc</code></li>
			</ul>
			<p class="mb-0 small text-muted"><?php echo blg('Format: one address or network (CIDR) per line, no comments. The lists are regenerated several times a day. Please fetch them at most every 30 minutes; every 1 to 6 hours is enough. Country and continent lists are on the <a href="/v64_blocklists">list page</a>. For scripts: <a href="/blocklists/index.json">index.json</a> lists every list with count, last update, source, license and file names.',
				'Format: eine Adresse oder ein Netz (CIDR) je Zeile, ohne Kommentare. Die Listen werden mehrmals täglich neu erzeugt. Bitte höchstens alle 30 Minuten abrufen; alle 1 bis 6 Stunden reicht. Länder- und Kontinentlisten stehen auf der <a href="/v64_blocklists">Listenseite</a>. Für Skripte: <a href="/blocklists/index.json">index.json</a> nennt jede Liste mit Anzahl, Stand, Quelle, Lizenz und Dateinamen.'); ?></p>
			<div id="live" class="border-top mt-3 pt-3">
				<p class="mb-1"><strong><?php echo blg('Live state of the v64 Blocklist (list token)', 'Live-Stand der v64 Blocklist (Listen-Token)'); ?></strong></p>
				<p class="mb-1"><?php echo blg('The addresses above deliver the v64 lists as a daily state (up to 24 hours old), free for everyone. The live state is updated every 30 minutes and is available for contributors (one of your Honeypot64 sensors reported in the last 7 days) and for all plans except Standard. Create your list token while logged in under <a href="/honeypot/token.php">Honeypot64 › List token</a> and use this address:',
					'Die Adressen oben liefern die v64-Listen als Tagesstand (bis zu 24 Stunden alt), frei für alle. Der Live-Stand wird alle 30 Minuten aktualisiert und steht Beitragenden (einer deiner Honeypot64-Sensoren hat in den letzten 7 Tagen gemeldet) und allen Klassen außer Standard zur Verfügung. Dein Listen-Token erzeugst du eingeloggt unter <a href="/honeypot/token.php">Honeypot64 › Listen-Token</a>, dann diese Adresse verwenden:'); ?></p>
				<?php echo blg_code("https://ipv64.net/blocklists/live/<token>/ipv64_blocklist_v4_v64.txt"); ?>
				<ul class="mb-0 small">
					<li><?php echo blg('Same file names as above, only for the v64 Blocklist (<code>v64</code>, also <code>v4</code>/<code>v6</code> and MikroTik <code>.rsc</code>).', 'Dieselben Dateinamen wie oben, nur für die v64 Blocklist (<code>v64</code>, auch <code>v4</code>/<code>v6</code> und MikroTik-<code>.rsc</code>).'); ?></li>
					<li><?php echo blg('The token is part of the path. No header and no login are needed, so every firewall that accepts a URL can use it.', 'Das Token steht im Pfad. Es braucht keine Kopfzeile und keine Anmeldung, jede Firewall, die eine URL annimmt, kann es nutzen.'); ?></li>
					<li><?php echo blg('<strong>Keep the token secret</strong> like a password: not in screenshots, tickets or shared configurations. If it leaks, create a new one; the old one stops working immediately.', '<strong>Das Token geheim halten</strong> wie ein Passwort: nicht in Screenshots, Tickets oder weitergegebene Konfigurationen. Ist es bekannt geworden, ein neues erzeugen; das alte gilt sofort nicht mehr.'); ?></li>
					<li><?php echo blg('Fetch every <strong>30 minutes or less often</strong>; the live state does not change more often. The same file can be fetched at most every 5 minutes per token (otherwise HTTP 429 with Retry-After), at most 60 requests per 5 minutes in total.', 'Abruf <strong>alle 30 Minuten oder seltener</strong>; häufiger ändert sich der Live-Stand nicht. Dieselbe Datei geht je Token höchstens alle 5 Minuten (sonst HTTP 429 mit Retry-After), insgesamt höchstens 60 Abrufe in 5 Minuten.'); ?></li>
					<li><?php echo blg('Without the live entitlement the same address delivers the daily state (header <code>X-IPv64-List: daily</code>); an unknown or deleted token gets HTTP 404.', 'Ohne Berechtigung für Live liefert dieselbe Adresse den Tagesstand (Kopfzeile <code>X-IPv64-List: daily</code>); ein unbekanntes oder gelöschtes Token bekommt HTTP 404.'); ?></li>
				</ul>
			</div>
		</div>
	</div>

	<div class="card mb-3" id="nftables">
		<div class="card-header"><i class="fa-brands fa-linux"></i> 2. Linux: nftables <span class="badge badge-success"><?php echo blg('recommended, tested', 'empfohlen, getestet'); ?></span></div>
		<div class="card-body">
			<p><?php echo blg('For current Debian, Ubuntu, Fedora, Proxmox and most routers on Linux. The script loads IPv4 and IPv6 into a separate table <code>inet ipv64</code> and replaces it atomically. It does not touch your other rules. If a download fails, the old list stays active. Traffic forwarded to Docker containers or NATed hosts is filtered too.',
				'Für aktuelle Debian-, Ubuntu-, Fedora- und Proxmox-Systeme und die meisten Linux-Router. Das Skript lädt IPv4 und IPv6 in eine eigene Tabelle <code>inet ipv64</code> und tauscht sie in einem Schritt aus. Deine übrigen Regeln bleiben unberührt. Schlägt ein Download fehl, bleibt die alte Liste aktiv. Auch Verkehr, der an Docker-Container oder per NAT weitergeleitet wird, wird gefiltert.'); ?></p>
			<p class="mb-1"><strong><?php echo blg('Install (as root)', 'Einrichten (als root)'); ?>:</strong></p>
			<?php echo blg_code("apt install -y nftables curl\ncurl -fsSo /usr/local/sbin/ipv64-blocklist-nft.sh https://ipv64.net/blocklists/tools/ipv64-blocklist-nft.sh\nchmod +x /usr/local/sbin/ipv64-blocklist-nft.sh\n/usr/local/sbin/ipv64-blocklist-nft.sh firehole_l1"); ?>
			<p class="mb-1"><strong><?php echo blg('Update every 4 hours and after a reboot (cron)', 'Alle 4 Stunden und nach einem Neustart aktualisieren (cron)'); ?>:</strong></p>
			<?php echo blg_code("cat > /etc/cron.d/ipv64-blocklist <<'EOF'\n17 */4 * * * root /usr/local/sbin/ipv64-blocklist-nft.sh firehole_l1 >/dev/null\n@reboot      root sleep 30 && /usr/local/sbin/ipv64-blocklist-nft.sh firehole_l1 >/dev/null\nEOF"); ?>
			<p class="mb-1"><strong><?php echo blg('Check and remove', 'Prüfen und entfernen'); ?>:</strong></p>
			<?php echo blg_code("nft list chain inet ipv64 input     # counters show dropped packets\nnft delete table inet ipv64          # remove the blocklist completely"); ?>
			<details><summary class="small"><?php echo blg('Show the script', 'Skript anzeigen'); ?></summary><?php echo blg_tool('ipv64-blocklist-nft.sh'); ?></details>
		</div>
	</div>

	<div class="card mb-3" id="ipset">
		<div class="card-header"><i class="fa-brands fa-linux"></i> 3. Linux: iptables + ipset <span class="badge badge-success"><?php echo blg('tested', 'getestet'); ?></span></div>
		<div class="card-body">
			<p><?php echo blg('For systems that still use iptables. The script fills one set each for IPv4 and IPv6 via <code>ipset restore</code>, swaps it in and adds the DROP rules only once (INPUT, FORWARD and, if present, Docker\'s DOCKER-USER chain).',
				'Für Systeme, die noch iptables nutzen. Das Skript füllt je ein Set für IPv4 und IPv6 per <code>ipset restore</code>, tauscht es ein und legt die DROP-Regeln nur einmal an (INPUT, FORWARD und, falls vorhanden, Dockers Kette DOCKER-USER).'); ?></p>
			<?php echo blg_code("apt install -y ipset iptables curl\ncurl -fsSo /usr/local/sbin/ipv64-blocklist-ipset.sh https://ipv64.net/blocklists/tools/ipv64-blocklist-ipset.sh\nchmod +x /usr/local/sbin/ipv64-blocklist-ipset.sh\n/usr/local/sbin/ipv64-blocklist-ipset.sh firehole_l1\necho '17 */4 * * * root /usr/local/sbin/ipv64-blocklist-ipset.sh firehole_l1 >/dev/null' > /etc/cron.d/ipv64-blocklist\necho '@reboot root sleep 30 && /usr/local/sbin/ipv64-blocklist-ipset.sh firehole_l1 >/dev/null' >> /etc/cron.d/ipv64-blocklist"); ?>
			<p class="small text-muted"><?php echo blg('The @reboot line restores sets and rules after a restart, so ipset-persistent is not needed. Docker restarts its chains when the daemon restarts; run the script again afterwards.',
				'Die @reboot-Zeile stellt Sets und Regeln nach einem Neustart wieder her, ipset-persistent ist dafür nicht nötig. Docker legt seine Ketten beim Neustart des Dienstes neu an; danach das Skript einmal erneut ausführen.'); ?></p>
			<details><summary class="small"><?php echo blg('Show the script', 'Skript anzeigen'); ?></summary><?php echo blg_tool('ipv64-blocklist-ipset.sh'); ?></details>
		</div>
	</div>

	<div class="card mb-3" id="pfsense">
		<div class="card-header"><i class="fa-solid fa-shield"></i> 4. pfSense</div>
		<div class="card-body">
			<ol class="mb-2">
				<li><?php echo blg('<strong>Firewall › Aliases › URLs › Add</strong>: Type <em>URL Table (IPs)</em>, name e.g. <code>IPv64_firehol</code>, URL <code>https://ipv64.net/blocklists/ipv64_blocklist_firehole_l1.txt</code>, update frequency <code>1</code> day. Save and <em>Apply Changes</em>.',
					'<strong>Firewall › Aliases › URLs › Add</strong>: Typ <em>URL Table (IPs)</em>, Name z. B. <code>IPv64_firehol</code>, URL <code>https://ipv64.net/blocklists/ipv64_blocklist_firehole_l1.txt</code>, Aktualisierung <code>1</code> Tag. Speichern und <em>Apply Changes</em>.'); ?></li>
				<li><?php echo blg('<strong>Firewall › Rules › WAN › Add (arrow up = top)</strong>: Action <em>Block</em>, Address Family <em>IPv4+IPv6</em>, Protocol <em>Any</em>, <strong>Source</strong>: <em>Single host or alias</em> = <code>IPv64_firehol</code>, Destination <em>any</em>. Save and apply.',
					'<strong>Firewall › Rules › WAN › Add (Pfeil nach oben = ganz oben)</strong>: Action <em>Block</em>, Address Family <em>IPv4+IPv6</em>, Protocol <em>Any</em>, <strong>Source</strong>: <em>Single host or alias</em> = <code>IPv64_firehol</code>, Destination <em>any</em>. Speichern und übernehmen.'); ?></li>
				<li><?php echo blg('Optional, recommended for Spamhaus DROP: <strong>Firewall › Rules › LAN</strong>, Block rule at the top with <strong>Destination</strong> = the alias. This stops infected devices from contacting the listed networks.',
					'Optional, für Spamhaus DROP empfohlen: <strong>Firewall › Rules › LAN</strong>, Block-Regel ganz oben mit <strong>Destination</strong> = Alias. So erreichen infizierte Geräte die gelisteten Netze nicht.'); ?></li>
			</ol>
			<p class="small text-muted mb-0"><?php echo blg('Large lists (countries) may exceed <em>Firewall Maximum Table Entries</em> under System › Advanced › Firewall &amp; NAT; raise the value if the alias stays empty. Diagnostics › Tables shows the loaded entries. pfSense checks URL tables once per day, so the live state of the v64 lists brings no advantage here.',
				'Große Listen (Länder) können <em>Firewall Maximum Table Entries</em> unter System › Advanced › Firewall &amp; NAT überschreiten; den Wert erhöhen, wenn der Alias leer bleibt. Unter Diagnostics › Tables siehst du die geladenen Einträge. pfSense prüft URL-Tabellen einmal täglich, der Live-Stand der v64-Listen bringt hier also keinen Vorteil.'); ?></p>
		</div>
	</div>

	<div class="card mb-3" id="opnsense">
		<div class="card-header"><i class="fa-solid fa-shield"></i> 5. OPNsense</div>
		<div class="card-body">
			<ol class="mb-2">
				<li><?php echo blg('<strong>Firewall › Aliases › +</strong>: Type <em>URL Table (IPs)</em>, name e.g. <code>IPv64_firehol</code>, refresh frequency <code>0</code> days <code>4</code> hours, content <code>https://ipv64.net/blocklists/ipv64_blocklist_firehole_l1.txt</code>. Save and <em>Apply</em>.',
					'<strong>Firewall › Aliases › +</strong>: Typ <em>URL Table (IPs)</em>, Name z. B. <code>IPv64_firehol</code>, Aktualisierung <code>0</code> Tage <code>4</code> Stunden, Inhalt <code>https://ipv64.net/blocklists/ipv64_blocklist_firehole_l1.txt</code>. Speichern und <em>Apply</em>.'); ?></li>
				<li><?php echo blg('<strong>Firewall › Rules › WAN › +</strong>: Action <em>Block</em>, Direction <em>in</em>, TCP/IP Version <em>IPv4+IPv6</em>, Protocol <em>any</em>, <strong>Source</strong> = <code>IPv64_firehol</code>, Destination <em>any</em>. Save, drag the rule to the top and apply.',
					'<strong>Firewall › Rules › WAN › +</strong>: Action <em>Block</em>, Direction <em>in</em>, TCP/IP Version <em>IPv4+IPv6</em>, Protocol <em>any</em>, <strong>Source</strong> = <code>IPv64_firehol</code>, Destination <em>any</em>. Speichern, Regel ganz nach oben ziehen und übernehmen.'); ?></li>
				<li><?php echo blg('Optional on LAN: Block rule with <strong>Destination</strong> = alias (outbound).', 'Optional auf LAN: Block-Regel mit <strong>Destination</strong> = Alias (ausgehend).'); ?></li>
			</ol>
			<p class="small text-muted mb-0"><?php echo blg('Firewall › Diagnostics › Aliases shows the loaded entries and the last update.', 'Unter Firewall › Diagnostics › Aliases siehst du die geladenen Einträge und die letzte Aktualisierung.'); ?></p>
		</div>
	</div>

	<div class="card mb-3" id="enterprise">
		<div class="card-header"><i class="fa-solid fa-building"></i> 6. <?php echo blg('Business firewalls: Palo Alto, FortiGate, Sophos', 'Firmen-Firewalls: Palo Alto, FortiGate, Sophos'); ?> <span class="badge badge-secondary"><?php echo blg('not tested live', 'nicht live getestet'); ?></span></div>
		<div class="card-body">
			<p><?php echo blg('These firewalls load a plain text list from a URL themselves. Steps follow the vendor documentation (PAN-OS 11.1, FortiOS 7.6, Sophos Firewall 21.5). The examples use the v64 Blocklist; every other list works the same way. For the <a href="#live">live state</a> enter the address with your list token. Set the update interval to <strong>30 minutes or more</strong> – FortiGate refreshes every 5 minutes by default.',
				'Diese Firewalls laden eine Textliste selbst von einer URL. Die Schritte folgen der Herstellerdoku (PAN-OS 11.1, FortiOS 7.6, Sophos Firewall 21.5). Die Beispiele nutzen die v64 Blocklist; jede andere Liste geht genauso. Für den <a href="#live">Live-Stand</a> die Adresse mit deinem Listen-Token eintragen. Das Aktualisierungsintervall auf <strong>30 Minuten oder mehr</strong> stellen – FortiGate aktualisiert ab Werk alle 5 Minuten.'); ?></p>

			<p class="mb-1"><strong>Palo Alto Networks (PAN-OS): External Dynamic List</strong></p>
			<ol class="mb-2">
				<li><?php echo blg('<strong>Objects › External Dynamic Lists › Add</strong>: name e.g. <code>IPv64_v64</code>, Type <em>IP List</em>, Source <code>https://ipv64.net/blocklists/ipv64_blocklist_v64.txt</code>, optionally a <em>Certificate Profile</em> with the CA of the ipv64.net certificate (server authentication), Check for updates <em>Hourly</em>. <em>OK</em>.',
					'<strong>Objects › External Dynamic Lists › Add</strong>: Name z. B. <code>IPv64_v64</code>, Type <em>IP List</em>, Source <code>https://ipv64.net/blocklists/ipv64_blocklist_v64.txt</code>, optional ein <em>Certificate Profile</em> mit der CA des ipv64.net-Zertifikats (Server-Prüfung), Check for updates <em>Hourly</em>. <em>OK</em>.'); ?></li>
				<li><?php echo blg('<strong>Policies › Security › Add</strong>: on the <em>Source</em> tab the list as <em>Source Address</em> (inbound from the Internet zone), Action <em>Deny</em>. Move the rule above your allow rules. For outbound traffic, use the list as <em>Destination Address</em> in a second rule.',
					'<strong>Policies › Security › Add</strong>: im Reiter <em>Source</em> die Liste als <em>Source Address</em> (eingehend aus der Internet-Zone), Action <em>Deny</em>. Die Regel über die Allow-Regeln schieben. Für ausgehenden Verkehr die Liste in einer zweiten Regel als <em>Destination Address</em> nutzen.'); ?></li>
				<li><?php echo blg('<em>Commit</em>. <em>Import Now</em> on the list fetches it immediately.', '<em>Commit</em>. <em>Import Now</em> an der Liste lädt sie sofort.'); ?></li>
			</ol>
			<p class="small text-muted"><?php echo blg('PAN-OS accepts IPv4 and IPv6 addresses, ranges and networks. All IP lists together may hold 50,000 addresses on most models (150,000 on PA-3200, PA-5200 and PA-7000); see <em>List Capacities</em> under Objects › External Dynamic Lists. If the server cannot be reached, the firewall keeps the last list.',
				'PAN-OS nimmt IPv4- und IPv6-Adressen, Bereiche und Netze. Alle IP-Listen zusammen dürfen auf den meisten Modellen 50.000 Adressen enthalten (150.000 auf PA-3200, PA-5200 und PA-7000); siehe <em>List Capacities</em> unter Objects › External Dynamic Lists. Ist der Server nicht erreichbar, nutzt die Firewall die zuletzt geladene Liste.'); ?></p>

			<p class="mb-1"><strong>Fortinet FortiGate (FortiOS): <?php echo blg('IP address feed', 'IP-Adress-Feed'); ?></strong></p>
			<ol class="mb-2">
				<li><?php echo blg('<strong>Security Fabric › External Connectors › Create New</strong>, under <em>External Feeds</em> (older versions: <em>Threat Feeds</em>) choose <em>IP Address</em>: name e.g. <code>IPv64_v64</code>, URL of external resource <code>https://ipv64.net/blocklists/ipv64_blocklist_v64.txt</code>, Refresh Rate <code>60</code> minutes. <em>OK</em>.',
					'<strong>Security Fabric › External Connectors › Create New</strong>, unter <em>External Feeds</em> (ältere Versionen: <em>Threat Feeds</em>) <em>IP Address</em> wählen: Name z. B. <code>IPv64_v64</code>, URL of external resource <code>https://ipv64.net/blocklists/ipv64_blocklist_v64.txt</code>, Refresh Rate <code>60</code> Minuten. <em>OK</em>.'); ?></li>
				<li><?php echo blg('<strong>Policy &amp; Objects › Firewall Policy</strong>: rule from the WAN interface with <em>Source</em> = the feed (section <em>IP ADDRESS FEED</em>), Action <em>DENY</em>, above the allow rules. For outbound traffic, a rule with the feed as <em>Destination</em>.',
					'<strong>Policy &amp; Objects › Firewall Policy</strong>: Regel vom WAN-Interface mit <em>Source</em> = Feed (Abschnitt <em>IP ADDRESS FEED</em>), Action <em>DENY</em>, über den Allow-Regeln. Für ausgehenden Verkehr eine Regel mit dem Feed als <em>Destination</em>.'); ?></li>
			</ol>
			<p class="mb-1 small"><?php echo blg('The same on the CLI, plus a local-in policy that also protects the FortiGate itself (VPN, admin access); use a free policy number:', 'Dasselbe in der CLI, dazu eine Local-in-Policy, die auch die FortiGate selbst schützt (VPN, Admin-Zugang); eine freie Policy-Nummer verwenden:'); ?></p>
			<?php echo blg_code("config system external-resource\n    edit \"IPv64_v64\"\n        set type address\n        set resource \"https://ipv64.net/blocklists/ipv64_blocklist_v64.txt\"\n        set refresh-rate 60\n        set server-identity-check full\n    next\nend\nconfig firewall local-in-policy\n    edit 100\n        set intf \"any\"\n        set srcaddr \"IPv64_v64\"\n        set dstaddr \"all\"\n        set service \"ALL\"\n        set schedule \"always\"\n    next\nend"); ?>
			<p class="small text-muted"><?php echo blg('FortiOS accepts IPv4 and IPv6 addresses, ranges and networks, one per line. <code>server-identity-check</code> checks the server certificate (default <code>none</code>).',
				'FortiOS nimmt IPv4- und IPv6-Adressen, Bereiche und Netze, je Zeile eine. <code>server-identity-check</code> prüft das Server-Zertifikat (Standard <code>none</code>).'); ?></p>

			<p class="mb-1"><strong>Sophos Firewall: <?php echo blg('Third-party threat feeds', 'Third-party threat feeds'); ?></strong></p>
			<ol class="mb-2">
				<li><?php echo blg('<strong>Active threat response › Third-party threat feeds › Add</strong>: name e.g. <code>IPv64_v64</code>, Action <em>Block</em>, Indicator type <em>IPv4 address</em>, External URL <code>https://ipv64.net/blocklists/ipv64_blocklist_v4_v64.txt</code>, Authorization <em>No authentication</em>, <em>Validate server certificate</em> on, Polling interval <em>1 hour</em> (or 30 minutes). Save.',
					'<strong>Active threat response › Third-party threat feeds › Add</strong>: Name z. B. <code>IPv64_v64</code>, Action <em>Block</em>, Indicator type <em>IPv4 address</em>, External URL <code>https://ipv64.net/blocklists/ipv64_blocklist_v4_v64.txt</code>, Authorization <em>No authentication</em>, <em>Validate server certificate</em> an, Polling interval <em>1 hour</em> (oder 30 Minuten). Speichern.'); ?></li>
				<li><?php echo blg('<em>Synchronize now</em> loads the feed immediately; check the log for matches.', '<em>Synchronize now</em> lädt den Feed sofort; Treffer im Log prüfen.'); ?></li>
			</ol>
			<p class="small text-muted mb-0"><?php echo blg('Requires the license for third-party threat feeds (Xstream Protection). According to Sophos, these feeds take single IPv4 addresses only, no IPv6, ranges or networks. The ipv64.net lists contain networks and write single addresses as <code>/32</code>; whether Sophos accepts these entries has not been tested. XGS 87, 88 and 107 offer only 24 hours, 7 days or 30 days as polling interval.',
				'Benötigt die Lizenz für Third-party threat feeds (Xstream Protection). Laut Sophos nehmen diese Feeds nur einzelne IPv4-Adressen, keine IPv6-Adressen, Bereiche oder Netze. Die Listen von ipv64.net enthalten Netze und schreiben einzelne Adressen als <code>/32</code>; ob Sophos diese Einträge annimmt, ist nicht getestet. XGS 87, 88 und 107 bieten als Polling interval nur 24 Stunden, 7 Tage oder 30 Tage.'); ?></p>
		</div>
	</div>

	<div class="card mb-3" id="mikrotik">
		<div class="card-header"><i class="fa-solid fa-network-wired"></i> 7. MikroTik RouterOS 7</div>
		<div class="card-body">
			<p><?php echo blg('ipv64.net provides ready-made import files. Each file first removes its own old entries and then adds the current ones to the address list <code>IPv64-&lt;id&gt;</code>. The following script downloads the file, imports it and is run by the scheduler every 6 hours. Paste it into the terminal (Winbox › New Terminal):',
				'ipv64.net stellt fertige Importdateien bereit. Jede Datei entfernt zuerst ihre eigenen alten Einträge und trägt dann die aktuellen in die Adressliste <code>IPv64-&lt;id&gt;</code> ein. Das folgende Skript lädt die Datei, importiert sie und läuft per Scheduler alle 6 Stunden. Im Terminal einfügen (Winbox › New Terminal):'); ?></p>
			<?php echo blg_code("/system script add name=ipv64-blocklist policy=read,write,test source={\n  :foreach v in={\"v4\";\"v6\"} do={\n    :local f (\"ipv64-\" . \$v . \".rsc\")\n    /tool fetch url=(\"https://ipv64.net/blocklists/v64_mikrotik_\" . \$v . \"_firehole_l1.rsc\") dst-path=\$f\n    :delay 2s\n    /import file-name=\$f\n    /file remove \$f\n  }\n}\n/system scheduler add name=ipv64-blocklist interval=6h start-time=startup on-event=\"/system script run ipv64-blocklist\"\n/system script run ipv64-blocklist\n/ip firewall raw add chain=prerouting src-address-list=IPv64-firehole_l1 action=drop comment=\"IPv64 blocklist\"\n/ipv6 firewall raw add chain=prerouting src-address-list=IPv64-firehole_l1 action=drop comment=\"IPv64 blocklist\""); ?>
			<p class="small text-muted mb-0"><?php echo blg('The raw rules drop the traffic before connection tracking, for the router and the LAN. Move them to the top of the raw table if you have other raw rules. The import of large lists takes a few seconds. /ip firewall address-list print count-only where list=IPv64-firehole_l1 shows the number of entries. For the live state of the v64 Blocklist use the URL <code>("https://ipv64.net/blocklists/live/&lt;token&gt;/v64_mikrotik_" . $v . "_v64.rsc")</code>, the list name <code>IPv64-v64</code> and <code>interval=30m</code>.',
				'Die raw-Regeln verwerfen den Verkehr vor dem Connection-Tracking, für Router und LAN. Hast du weitere raw-Regeln, diese nach oben schieben. Der Import großer Listen dauert einige Sekunden. /ip firewall address-list print count-only where list=IPv64-firehole_l1 zeigt die Anzahl der Einträge. Für den Live-Stand der v64 Blocklist die URL <code>("https://ipv64.net/blocklists/live/&lt;token&gt;/v64_mikrotik_" . $v . "_v64.rsc")</code>, den Listennamen <code>IPv64-v64</code> und <code>interval=30m</code> verwenden.'); ?></p>
		</div>
	</div>

	<div class="card mb-3" id="nginx">
		<div class="card-header"><i class="fa-solid fa-server"></i> 8. nginx <span class="badge badge-success"><?php echo blg('tested', 'getestet'); ?></span></div>
		<div class="card-body">
			<p><?php echo blg('For a web server or reverse proxy without firewall access. The <code>geo</code> module checks networks efficiently, even with tens of thousands of entries. Blocked clients get HTTP 403.',
				'Für einen Webserver oder Reverse-Proxy ohne Zugriff auf die Firewall. Das Modul <code>geo</code> prüft Netze effizient, auch bei Zehntausenden Einträgen. Gesperrte Clients bekommen HTTP 403.'); ?></p>
			<p class="mb-1"><strong><?php echo blg('1. Fetch the list as a geo file (cron, e.g. every 4 hours)', '1. Liste als geo-Datei holen (cron, z. B. alle 4 Stunden)'); ?>:</strong></p>
			<?php echo blg_code("curl -fsS https://ipv64.net/blocklists/ipv64_blocklist_blocklistde_all.txt \\\n  | awk '/^[0-9A-Fa-f:.]+(\\/[0-9]+)?\$/ {print \$1\" 1;\"}' > /etc/nginx/ipv64-geo.conf.new \\\n  && [ -s /etc/nginx/ipv64-geo.conf.new ] && mv /etc/nginx/ipv64-geo.conf.new /etc/nginx/ipv64-geo.conf \\\n  && nginx -t -q && systemctl reload nginx"); ?>
			<p class="mb-1"><strong><?php echo blg('2. Use it in nginx.conf', '2. In der nginx.conf verwenden'); ?>:</strong></p>
			<?php echo blg_code("http {\n    geo \$ipv64_blocked { default 0; include /etc/nginx/ipv64-geo.conf; }\n    server {\n        # ...\n        if (\$ipv64_blocked) { return 403; }\n    }\n}"); ?>
			<p class="small text-muted mb-0"><?php echo blg('Behind Cloudflare or another proxy, configure <code>real_ip_header</code> first, otherwise nginx sees the proxy address.', 'Hinter Cloudflare oder einem anderen Proxy zuerst <code>real_ip_header</code> einrichten, sonst sieht nginx die Adresse des Proxys.'); ?></p>
		</div>
	</div>

	<div class="card mb-3" id="crowdsec">
		<div class="card-header"><i class="fa-solid fa-users-viewfinder"></i> 9. CrowdSec <span class="badge badge-success"><?php echo blg('tested with 1.6', 'getestet mit 1.6'); ?></span></div>
		<div class="card-body">
			<p><?php echo blg('Import the list as decisions; all your bouncers (firewall, nginx, Traefik …) apply it. The decisions expire after 6 hours, so import again every 4 hours via cron:',
				'Die Liste als Entscheidungen importieren; alle Bouncer (Firewall, nginx, Traefik …) setzen sie um. Die Entscheidungen laufen nach 6 Stunden ab, deshalb alle 4 Stunden per cron neu importieren:'); ?></p>
			<?php echo blg_code("curl -fsSo /tmp/ipv64.txt https://ipv64.net/blocklists/ipv64_blocklist_firehole_l1.txt \\\n  && cscli decisions import -i /tmp/ipv64.txt --format values --duration 6h --reason ipv64-blocklist"); ?>
		</div>
	</div>

	<div class="card mb-3" id="node64">
		<div class="card-header"><i class="fa-solid fa-cube"></i> 10. Node64</div>
		<div class="card-body">
			<p class="mb-0"><?php echo blg('The Node64 container uses the IPv64 blocklists in its reverse proxy CDN64 with one click: <em>CDN64 › Access › Blocklists</em>. It refreshes them every 30 minutes and lets you define exceptions. With your list token stored there, it loads the v64 lists live.',
				'Der Node64-Container nutzt die IPv64-Blocklisten in seinem Reverse-Proxy CDN64 mit einem Klick: <em>CDN64 › Zugriff › Blocklisten</em>. Er aktualisiert sie alle 30 Minuten, Ausnahmen kannst du selbst festlegen. Mit dort hinterlegtem Listen-Token lädt er die v64-Listen live.'); ?></p>
		</div>
	</div>

	<div class="card mb-3" id="sources">
		<div class="card-header"><i class="fa-solid fa-scale-balanced"></i> 11. <?php echo blg('Sources, false positives and terms', 'Quellen, Fehlalarme und Bedingungen'); ?></div>
		<div class="card-body">
			<p><?php echo blg('ipv64.net combines and cleans public lists: it converts everything to networks, removes duplicates, contained networks and reserved ranges. The entries themselves come from these projects:',
				'ipv64.net fasst öffentliche Listen zusammen und bereinigt sie: alles wird in Netze umgewandelt, Doppelte, enthaltene Netze und reservierte Bereiche fallen weg. Die Einträge selbst stammen aus diesen Projekten:'); ?></p>
			<ul>
				<li><a href="https://www.spamhaus.org/blocklists/do-not-route-or-peer/" target="_blank" rel="noopener">Spamhaus DROP</a></li>
				<li><a href="https://iplists.firehol.org/?ipset=firehol_level1" target="_blank" rel="noopener">FireHOL Level 1</a></li>
				<li><a href="https://www.blocklist.de/en/index.html" target="_blank" rel="noopener">blocklist.de</a></li>
				<li><a href="https://www.dshield.org/" target="_blank" rel="noopener">DShield (SANS ISC)</a></li>
				<li><a href="https://metrics.torproject.org/collector.html" target="_blank" rel="noopener">Tor Project</a></li>
				<li><a href="https://feodotracker.abuse.ch/blocklist/" target="_blank" rel="noopener">abuse.ch Feodo Tracker</a> (CC0)</li>
				<li><a href="https://rules.emergingthreats.net/blockrules/" target="_blank" rel="noopener">Emerging Threats</a></li>
				<li><a href="https://cinsscore.com/" target="_blank" rel="noopener">CINS Army</a></li>
				<li><a href="https://github.com/stamparm/ipsum" target="_blank" rel="noopener">IPsum</a> (Unlicense)</li>
				<li><a href="https://github.com/dibdot/DoH-IP-blocklists" target="_blank" rel="noopener">DoH-IP-blocklists</a> (GPL-3.0)</li>
				<li><a href="/honeypot/">Honeypot64</a> (ipv64.net, CC BY 4.0): <?php echo blg('v64 Blocklist and its parts', 'v64 Blocklist und Teillisten'); ?></li>
				<li><?php echo blg('Cloud networks as published by', 'Cloud-Netze, wie veröffentlicht von'); ?> <a href="https://www.cloudflare.com/ips/" target="_blank" rel="noopener">Cloudflare</a>, <a href="https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html" target="_blank" rel="noopener">AWS</a>, <a href="https://cloud.google.com/compute/docs/faq#find_ip_range" target="_blank" rel="noopener">Google Cloud</a></li>
			</ul>
			<p class="mb-0"><?php echo blg('If one of your addresses is listed by mistake, ask the source project to remove it; the change reaches the IPv64 lists with the next update. For the v64 lists, request the removal in the <a href="/honeypot/ip.php">IP lookup</a>. The lists are free to use; please respect the terms of the source projects and do not use them as the only protection.',
				'Ist eine deiner Adressen fälschlich gelistet, beantrage die Löschung beim jeweiligen Projekt; mit der nächsten Aktualisierung verschwindet sie auch aus den IPv64-Listen. Für die v64-Listen die Freigabe in der <a href="/honeypot/ip.php">IP-Auskunft</a> beantragen. Die Listen sind kostenlos nutzbar; bitte beachte die Bedingungen der Quellprojekte und verlass dich nicht allein auf sie.'); ?></p>
		</div>
	</div>
</div>
<?php
include("footer.php");
?>
