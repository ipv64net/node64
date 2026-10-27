<?php
/**
 * IPv64 Secure – Uebersicht der Schutzfunktionen (Menue „Secure“). Kern ist die v64 Blocklist aus den
 * Honeypot64-Sensoren der Community (Node64): Tagesstand frei, Live-Stand (alle 30 Minuten) fuer Beitragende und alle
 * Klassen ausser Standard. Die Seite zeigt beide Staende nebeneinander (Anzahl und Alter), damit sichtbar ist, was die
 * Live-Liste gerade mehr enthaelt. Zahlen nur aus Dateien und Zaehlern, keine IPs, keine Accounts.
 *
 *   v64_secure            Englisch
 *   v64_secure?lang=de    Deutsch
 */
include("header.php");
$vsDe = (($_GET['lang'] ?? '') === 'de');
function vs_t(string $en, string $de): string { global $vsDe; return $vsDe ? $de : $en; }
function vs_h($s): string { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
/** Zeilen und Stand einer Listendatei: [Anzahl, Unix-Zeit] (fehlt sie: [0, 0]) */
function vs_list(string $path): array {
	if(!is_file($path)) { return array(0, 0); }
	return array(count(file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)), (int)filemtime($path));
}
/** Alter als Text: „12 min ago“, „8 h ago“, „2 days ago“ */
function vs_ago(int $ts): string {
	if($ts <= 0) { return '–'; }
	$d = max(0, time() - $ts);
	if($d < 3600) { $n = max(1, intdiv($d, 60)); return vs_t("$n min ago", "vor $n min"); }
	if($d < 172800) { $n = intdiv($d, 3600); return vs_t("$n h ago", "vor $n h"); }
	$n = intdiv($d, 86400); return vs_t("$n days ago", "vor $n Tagen");
}

// v64 Blocklist: Tagesstand (oeffentlich) und Live-Stand (nicht oeffentlicher Ordner neben web/, nur die Anzahl)
[$vsDaily, $vsDailyAt] = vs_list(__DIR__ . '/blocklists/ipv64_blocklist_v64.txt');
[$vsLive, $vsLiveAt] = vs_list(dirname(__DIR__) . '/private/blocklists_live/ipv64_blocklist_v64.txt');
// weitere Zahlen; Fehler nur ins Log, die Seite bleibt
$vsSensors = 0; $vsIps = 0; $vsLists = 0;
try {
	$vsSensors = (int)$pdo->query("SELECT COUNT(*) FROM hp_sensors WHERE disabled = 0 AND last_seen >= UTC_TIMESTAMP() - INTERVAL 1 DAY")->fetchColumn();
} catch(Throwable $e) { error_log('v64_secure sensors: ' . $e->getMessage()); }
try {
	$vsIps = (int)$pdo->query("SELECT COALESCE(SUM(ips), 0) FROM blocklisten")->fetchColumn();
	$vsLists = (int)$pdo->query("SELECT COUNT(*) FROM blocklisten")->fetchColumn() + (int)$pdo->query("SELECT COUNT(*) FROM blocklisten_countries")->fetchColumn();
} catch(Throwable $e) { error_log('v64_secure lists: ' . $e->getMessage()); }
$vsLang = $vsDe ? '?lang=de' : '';
?>

<div class="jumbotron jumbotron-fluid d-none d-xl-block p-3">
	<div class="container">
		<a class="float-right small" href="<?php echo $vsDe ? 'v64_secure' : 'v64_secure?lang=de'; ?>"><?php echo $vsDe ? 'English' : 'Deutsch'; ?></a>
		<h1 class="display-3"><img src="https://ipv64.net/img/logo_64.png" height="80" alt="IPv64 Logo" class="mb-3">
			IPv64 Secure - First Level Protection <i class="fa-solid fa-shield-halved text-success"></i></h1>
		<p class="lead"><?php echo vs_t('Keep the dirt of the Internet away from your services: <strong>blocklists</strong> for pfSense, OPNsense, MikroTik, Linux and other firewalls, and the <strong>v64 Blocklist</strong> with attackers that the <strong>Honeypot64</strong> sensors of the community report – updated every 30 minutes.',
			'Halte den Dreck des Internets von deinen Diensten fern: <strong>Blocklisten</strong> für pfSense, OPNsense, MikroTik, Linux und andere Firewalls und die <strong>v64 Blocklist</strong> mit Angreifern, die die <strong>Honeypot64</strong>-Sensoren der Community melden – alle 30 Minuten neu.'); ?></p>
	</div>
</div>

<div class="container">
	<p class="d-xl-none text-right small mb-1"><a href="<?php echo $vsDe ? 'v64_secure' : 'v64_secure?lang=de'; ?>"><?php echo $vsDe ? 'English' : 'Deutsch'; ?></a></p>

	<!-- v64 Blocklist: Tagesstand gegen Live-Stand -->
	<div class="card shadow-sm mb-3 border-success">
		<div class="card-header"><i class="fa-solid fa-crown text-warning"></i> <strong>v64 Blocklist</strong> <span class="badge badge-success">Honeypot64</span>
			<span class="badge badge-info float-right"><?php echo vs_t('live', 'live'); ?></span></div>
		<div class="card-body">
			<div class="row">
				<div class="col-md-4 pb-3"><div class="card bg-light h-100" style="border-left:4px solid var(--secondary)"><div class="card-body p-2">
					<i class="fa-solid fa-calendar-day fa-2xl float-right pt-4 text-secondary"></i>
					<p class="lead m-0"><?php echo vs_t('Daily list (free)', 'Tagesstand (frei)'); ?></p>
					<p class="card-text h2 mb-0"><?php echo formatLargeNumber($vsDaily); ?> <small class="h6 text-muted">IPs</small></p>
					<small class="text-muted"><?php echo vs_t('as of', 'Stand'); ?> <?php echo vs_ago($vsDailyAt); ?></small>
				</div></div></div>
				<div class="col-md-4 pb-3"><div class="card bg-light h-100" style="border-left:4px solid var(--danger)"><div class="card-body p-2">
					<i class="fa-solid fa-bolt fa-2xl float-right pt-4 text-danger"></i>
					<p class="lead m-0"><?php echo vs_t('Live list right now', 'Live-Stand gerade'); ?></p>
					<p class="card-text h2 mb-0 text-danger"><?php echo formatLargeNumber($vsLive); ?> <small class="h6 text-muted">IPs</small></p>
					<small class="text-muted"><?php echo vs_t('updated', 'aktualisiert'); ?> <?php echo vs_ago($vsLiveAt); ?></small>
				</div></div></div>
				<div class="col-md-4 pb-3"><div class="card bg-light h-100" style="border-left:4px solid var(--success)"><div class="card-body p-2">
					<i class="fa-solid fa-satellite-dish fa-2xl float-right pt-4 text-success"></i>
					<p class="lead m-0"><?php echo vs_t('Sensors reporting (24 h)', 'Meldende Sensoren (24 h)'); ?></p>
					<p class="card-text h2 mb-0"><?php echo formatLargeNumber($vsSensors); ?></p>
					<small class="text-muted"><a href="/honeypot/live.php<?php echo $vsDe ? '' : '?lang=en'; ?>"><?php echo vs_t('watch the live map', 'zur Live-Karte'); ?></a></small>
				</div></div></div>
			</div>
			<?php if($vsLive > $vsDaily) { ?>
			<div class="alert alert-warning mb-3"><i class="fa-solid fa-circle-exclamation"></i>
				<?php echo vs_t('Right now the live list holds <strong>' . formatLargeNumber($vsLive) . ' attackers</strong>, the free daily list (' . vs_ago($vsDailyAt) . ') only <strong>' . formatLargeNumber($vsDaily) . '</strong>. The live list is updated every 30 minutes – new attackers are blocked within the hour instead of the next day.',
					'Auf der Live-Liste stehen gerade <strong>' . formatLargeNumber($vsLive) . ' Angreifer</strong>, auf dem freien Tagesstand (' . vs_ago($vsDailyAt) . ') nur <strong>' . formatLargeNumber($vsDaily) . '</strong>. Die Live-Liste wird alle 30 Minuten neu bewertet – neue Angreifer sind innerhalb einer Stunde gesperrt statt erst am nächsten Tag.'); ?>
			</div>
			<?php } ?>
			<p><?php echo vs_t('The v64 Blocklist is IPv64.net\'s own list: <a href="https://node64.de" target="_blank" rel="noopener">Node64</a> users run the <strong>Honeypot64</strong> sensor and report attacks (logins, exploits, scans) every 10 minutes. Every 30 minutes IPv64.net rates the reports; an address is listed only when several <strong>independent accounts</strong> have seen it. Research scanners (Shodan, Censys …), own networks and CDNs stay off the list.',
				'Die v64 Blocklist ist die eigene Liste von IPv64.net: Nutzer von <a href="https://node64.de" target="_blank" rel="noopener">Node64</a> betreiben den <strong>Honeypot64</strong>-Sensor und melden Angriffe (Logins, Exploits, Scans) alle 10 Minuten. Alle 30 Minuten bewertet IPv64.net die Meldungen; gelistet wird nur, was mehrere <strong>unabhängige Accounts</strong> gesehen haben. Forschungs-Scanner (Shodan, Censys …), eigene Netze und CDNs bleiben draußen.'); ?></p>
			<div class="row">
				<div class="col-md-6"><h6><i class="fa-solid fa-unlock text-secondary"></i> <?php echo vs_t('Daily list – for everyone', 'Tagesstand – für alle'); ?></h6>
					<p class="small"><?php echo vs_t('Free, once a day (up to 24 h old):', 'Frei, einmal täglich (bis 24 h alt):'); ?>
					<code>https://ipv64.net/blocklists/ipv64_blocklist_v64.txt</code><br>
					<?php echo vs_t('Also as IPv4/IPv6 only and MikroTik script, see the', 'Auch nur IPv4/IPv6 und als MikroTik-Skript, siehe'); ?> <a href="v64_blocklist_integration_guide<?php echo $vsLang; ?>"><?php echo vs_t('integration guide', 'Integrationsleitfaden'); ?></a>.</p></div>
				<div class="col-md-6"><h6><i class="fa-solid fa-bolt text-danger"></i> <?php echo vs_t('Live list – every 30 minutes', 'Live-Stand – alle 30 Minuten'); ?></h6>
					<p class="small"><?php echo vs_t('For <strong>contributors</strong> (one of your Honeypot64 sensors reported in the last 7 days) and <strong>all plans except Standard</strong>. In Node64 (PROXY64, firewall helper) it works automatically with your API key; for other firewalls use your personal list token:',
						'Für <strong>Beitragende</strong> (einer deiner Honeypot64-Sensoren hat in den letzten 7 Tagen gemeldet) und <strong>alle Klassen außer Standard</strong>. In Node64 (PROXY64, Firewall-Helfer) automatisch über deinen API-Key; für andere Firewalls mit deinem persönlichen Listen-Token:'); ?>
					<a href="/honeypot/token.php"><?php echo vs_t('get list token', 'Listen-Token holen'); ?></a>.</p></div>
			</div>
			<a href="https://node64.de" target="_blank" rel="noopener" class="btn btn-sm btn-success"><i class="fa-solid fa-satellite-dish"></i> <?php echo vs_t('Contribute with a Honeypot64 sensor', 'Mit einem Honeypot64-Sensor beitragen'); ?></a>
			<a href="/honeypot/stats.php<?php echo $vsDe ? '' : '?lang=en'; ?>" class="btn btn-sm btn-outline-primary"><i class="fa-solid fa-chart-line"></i> <?php echo vs_t('Statistics', 'Statistik'); ?></a>
			<a href="/honeypot/live.php<?php echo $vsDe ? '' : '?lang=en'; ?>" class="btn btn-sm btn-outline-danger"><i class="fa-solid fa-earth-europe"></i> <?php echo vs_t('Live map', 'Live-Karte'); ?></a>
			<a href="/honeypot/ip.php<?php echo $vsDe ? '' : '?lang=en'; ?>" class="btn btn-sm btn-outline-secondary"><i class="fa-solid fa-magnifying-glass"></i> <?php echo vs_t('Check an IP', 'IP prüfen'); ?></a>
		</div>
	</div>

	<div class="row">
		<!-- Blocklisten -->
		<div class="col-lg-6 pb-3">
			<div class="card shadow-sm h-100">
				<div class="card-header"><i class="fa-solid fa-shield text-success"></i> <strong><?php echo vs_t('IPv64 Blocklists', 'IPv64 Blocklisten'); ?></strong></div>
				<div class="card-body">
					<div class="row">
						<div class="col-6 pb-3"><div class="card text-white bg-danger"><div class="card-body p-2">
							<p class="lead m-0"><?php echo vs_t('IPs on the lists', 'IPs auf den Listen'); ?></p><p class="card-text h2 mb-0"><?php echo formatLargeNumber($vsIps); ?></p>
						</div></div></div>
						<div class="col-6 pb-3"><div class="card bg-light"><div class="card-body p-2">
							<p class="lead m-0"><?php echo vs_t('Lists', 'Listen'); ?></p><p class="card-text h2 mb-0"><?php echo formatLargeNumber($vsLists); ?></p>
						</div></div></div>
					</div>
					<p><?php echo vs_t('<strong>Start with an effective blocklist</strong> on your firewall or server: Spamhaus DROP, FireHOL Level 1, DShield, Tor exit nodes, countries and continents – prepared by IPv64.net in the format your system needs, no regex, no conversion.',
						'<strong>Fang mit einer wirksamen Blockliste an</strong>, auf der Firewall oder dem Server: Spamhaus DROP, FireHOL Level 1, DShield, Tor-Exit-Nodes, Länder und Kontinente – von IPv64.net im passenden Format aufbereitet, ohne Regex, ohne Umwandeln.'); ?></p>
					<a href="/v64_blocklists" class="btn btn-sm btn-primary"><i class="fa-solid fa-road-barrier"></i> <?php echo vs_t('All blocklists', 'Alle Blocklisten'); ?></a>
					<a href="v64_blocklist_integration_guide<?php echo $vsLang; ?>" class="btn btn-sm btn-outline-primary"><i class="fa-solid fa-book"></i> <?php echo vs_t('Integration guide', 'Integrationsleitfaden'); ?></a>
				</div>
			</div>
		</div>
		<!-- Einsatz -->
		<div class="col-lg-6 pb-3">
			<div class="card shadow-sm h-100">
				<div class="card-header"><i class="fa-solid fa-plug text-info"></i> <strong><?php echo vs_t('Where you can use it', 'Wo du es einsetzt'); ?></strong></div>
				<div class="card-body">
					<ul class="mb-3">
						<li><?php echo vs_t('<strong>Node64 PROXY64</strong> (reverse proxy): blocklists per click, the v64 Blocklist live automatically with your API key.', '<strong>Node64 PROXY64</strong> (Reverse Proxy): Blocklisten per Klick, die v64 Blocklist live automatisch über deinen API-Key.'); ?></li>
						<li><?php echo vs_t('<strong>Node64 firewall helper</strong>: writes the v64 Blocklist into nftables on Linux hosts.', '<strong>Node64 Firewall-Helfer</strong>: trägt die v64 Blocklist in nftables auf Linux-Hosts ein.'); ?></li>
						<li><?php echo vs_t('<strong>pfSense, OPNsense, MikroTik, FortiGate</strong>: as URL table or address list, see the integration guide.', '<strong>pfSense, OPNsense, MikroTik, FortiGate</strong>: als URL-Tabelle oder Adressliste, siehe Integrationsleitfaden.'); ?></li>
					</ul>
					<p class="mb-1"><?php echo vs_t('Your forwarded traffic shrinks, applications no longer answer unwanted requests or fill log files, and spam, malware and brute force attacks drop noticeably.',
						'Weitergeleiteter Verkehr wird deutlich weniger, Anwendungen beantworten keine unerwünschten Anfragen mehr und schreiben keine Logs voll, Spam, Malware und Brute-Force-Angriffe gehen spürbar zurück.'); ?></p>
					<p class="small text-muted mb-2"><strong><?php echo vs_t('Important:', 'Wichtig:'); ?></strong> <?php echo vs_t('This is the first line of defense and does not replace updates, strong passwords and a well-configured firewall.', 'Das ist die erste Verteidigungslinie und ersetzt keine Updates, starken Passwörter und gut eingestellte Firewall.'); ?></p>
					<a href="https://v64.tech/c/ipv64-services/v64-secure/9" target="_blank" rel="noopener" class="btn btn-sm btn-outline-secondary"><?php echo vs_t('Need help? v64 forum', 'Hilfe? v64-Forum'); ?></a>
				</div>
			</div>
		</div>
	</div>
</div>
<p></p>
<?php include("footer.php"); ?>
