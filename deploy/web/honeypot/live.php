<?php
/**
 * Honeypot64 – Live-Karte (oeffentlich, verlinkt aus der Statistik und "Secure"). Boegen vom Land der Angreifer zum
 * Land des Sensors auf einer flachen Weltkarte, darunter die letzten Angriffe. Daten: live.json (alle 2 Minuten von
 * bots/honeypot_live.php geschrieben, statisch – die Seite selbst fragt keine Datenbank), Karte: worldmap.json
 * (Natural Earth 1:110m, aus Node64 erzeugt). Quellen nur maskiert, Ziel nur als Land, keine Zugangsdaten.
 *
 *   live.php            Deutsch
 *   live.php?lang=en    Englisch
 */
include("../header.php");
echo '<link rel="stylesheet" href="flags.css?v=1">'; // Flaggen auch unter Windows
$hlEn = (($_GET['lang'] ?? '') === 'en');
function hl_t(string $de, string $en): string { global $hlEn; return $hlEn ? $en : $de; }
?>
<p></p>
<div class="container hl-vars">
	<div class="card mb-3"><div class="card-body">
		<a class="float-right small" href="<?php echo $hlEn ? 'live.php' : 'live.php?lang=en'; ?>"><?php echo $hlEn ? 'Deutsch' : 'English'; ?></a>
		<h4 class="mb-2"><i class="fa-solid fa-earth-europe text-primary"></i> Honeypot64 – <?php echo hl_t('Live-Karte', 'Live map'); ?>
			<span class="badge badge-danger align-middle small" id="hlLiveBadge">LIVE</span></h4>
		<p class="mb-1"><?php echo hl_t('Angriffe auf die Honeypot64-Sensoren der Community, vom Land des Angreifers zum Land des Sensors. Die Sensoren melden alle 10 Minuten – die Karte zeigt die letzte Stunde zeitversetzt und spielt sie fortlaufend ab; ist gerade nichts Neues da, werden ältere Angriffe blasser wiederholt.',
			'Attacks on the community\'s Honeypot64 sensors, from the attacker\'s country to the sensor\'s country. Sensors report every 10 minutes – the map shows the last hour with a delay and plays it continuously; when nothing new comes in, older attacks are replayed fainter.'); ?></p>
		<p class="mb-0 small text-muted"><?php echo hl_t('Angreifer nur gekürzt (IPv4 /24, IPv6 /48), Sensoren nur als Land, keine Zugangsdaten. Mehr Zahlen:', 'Attackers only shortened (IPv4 /24, IPv6 /48), sensors only as country, no credentials. More numbers:'); ?>
			<a href="stats.php<?php echo $hlEn ? '?lang=en' : ''; ?>"><?php echo hl_t('Statistik', 'Statistics'); ?></a> · <?php echo hl_t('IP prüfen:', 'Check an IP:'); ?> <a href="ip.php<?php echo $hlEn ? '?lang=en' : ''; ?>">ip.php</a> · <?php echo hl_t('IP-Länderdaten:', 'IP country data:'); ?> <a href="https://db-ip.com" target="_blank" rel="noopener">DB-IP.com</a></p>
	</div></div>

	<div class="row">
		<?php foreach(array(array('events', hl_t('Angriffe (60 min)', 'Attacks (60 min)'), 'fa-bug', 'primary'), array('sources', hl_t('Angreifer-Netze', 'Attacker networks'), 'fa-network-wired', 'danger'),
			array('targets', hl_t('Länder mit Sensoren', 'Countries with sensors'), 'fa-satellite-dish', 'success'), array('top', hl_t('Häufigstes Herkunftsland', 'Top source country'), 'fa-flag', 'info')) as [$k, $label, $icon, $color]) { ?>
		<div class="col-6 col-md pb-3"><div class="card bg-light h-100" style="border-left:4px solid var(--<?php echo $color; ?>)"><div class="card-body p-2"><i class="fa-solid <?php echo $icon; ?> fa-2xl float-right pt-4 text-<?php echo $color; ?>"></i>
			<p class="lead m-0"><?php echo htmlspecialchars($label); ?></p><p class="card-text h3" data-hl-stat="<?php echo $k; ?>">–</p>
		</div></div></div>
		<?php } ?>
	</div>

	<div class="card mb-3">
		<div class="card-header p-2 d-flex flex-wrap align-items-center" style="gap:.6rem">
			<span><i class="fa-solid fa-map text-primary"></i> <?php echo hl_t('Angriffe der letzten Stunde', 'Attacks of the last hour'); ?></span>
			<span class="small d-flex flex-wrap align-items-center" style="gap:.6rem">
				<span><span class="hl-sw hl-g-login"></span> <?php echo hl_t('Login', 'Login'); ?></span>
				<span><span class="hl-sw hl-g-exploit"></span> <?php echo hl_t('Exploit', 'Exploit'); ?></span>
				<span><span class="hl-sw hl-g-scan"></span> <?php echo hl_t('Scan', 'Scan'); ?></span>
				<span><span class="hl-sw hl-g-probe"></span> <?php echo hl_t('Sondierung', 'Probe'); ?></span>
				<span><span class="hl-sw hl-g-log"></span> <?php echo hl_t('aus Logs', 'from logs'); ?></span>
			</span>
			<span class="ml-auto">
				<button type="button" class="btn btn-sm btn-outline-danger py-0" id="hlPause"><i class="fa-solid fa-pause"></i> <?php echo hl_t('Anhalten', 'Pause'); ?></button>
				<button type="button" class="btn btn-sm btn-outline-secondary py-0" id="hlFull"><i class="fa-solid fa-expand"></i> <?php echo hl_t('Vollbild', 'Full screen'); ?></button>
			</span>
		</div>
		<div class="card-body p-2">
			<div class="hl-stage" id="hlStage">
				<div class="hl-mapwrap"><svg id="hlMap" class="hl-map" viewBox="0 0 1000 436" role="img" aria-label="<?php echo hl_t('Weltkarte mit Angriffen', 'World map with attacks'); ?>"><g id="hlLand"></g><g id="hlNames"></g><g id="hlSel"></g><g id="hlArcs"></g><g id="hlLabels"></g></svg>
				<a class="hl-logo" href="https://node64.de" target="_blank" rel="noopener" title="Node64 – Honeypot64"><img src="/img/node64/node64.svg" alt="Node64" class="hl-logo-l"><img src="/img/node64/node64_dark.svg" alt="Node64" class="hl-logo-d"></a></div>
				<div class="hl-panel small" id="hlPanel">
					<div class="hl-fs-only">
						<div class="d-flex align-items-center mb-2" style="gap:.5rem"><b>Honeypot64 – <?php echo hl_t('Live-Karte', 'Live map'); ?></b> <span class="badge badge-danger" data-hl-badge>LIVE</span>
							<button type="button" class="btn btn-sm btn-outline-secondary py-0 ml-auto" data-hl-exit title="<?php echo hl_t('Vollbild beenden (Esc)', 'Exit full screen (Esc)'); ?>"><i class="fa-solid fa-compress"></i></button></div>
						<div class="hl-p-stats mb-2">
							<span><b data-hl-stat="events">–</b> <?php echo hl_t('Angriffe', 'attacks'); ?></span> · <span><b data-hl-stat="sources">–</b> <?php echo hl_t('Netze', 'networks'); ?></span> · <span><b data-hl-stat="targets">–</b> <?php echo hl_t('Ziel-Länder', 'target countries'); ?></span>
						</div>
						<div class="d-flex flex-wrap mb-2" style="gap:.2rem .6rem">
							<span><span class="hl-sw hl-g-login"></span> Login</span><span><span class="hl-sw hl-g-exploit"></span> Exploit</span><span><span class="hl-sw hl-g-scan"></span> Scan</span>
							<span><span class="hl-sw hl-g-probe"></span> <?php echo hl_t('Sondierung', 'Probe'); ?></span><span><span class="hl-sw hl-g-log"></span> <?php echo hl_t('aus Logs', 'from logs'); ?></span>
						</div>
						<div class="hl-p-title"><?php echo hl_t('Gerade auf der Karte', 'On the map right now'); ?></div>
						<div id="hlNow" class="mb-2"></div>
						<div class="hl-p-title"><?php echo hl_t('Häufigste Verbindungen (60 min)', 'Top connections (60 min)'); ?></div>
						<div id="hlPairs" class="mb-2"></div>
					</div>
					<div id="hlSelBox" hidden>
						<div class="hl-p-title d-flex align-items-center"><span id="hlSelTitle"></span>
							<button type="button" class="btn btn-sm btn-link py-0 ml-auto" id="hlSelClear" title="<?php echo hl_t('Auswahl aufheben', 'Clear selection'); ?>"><i class="fa-solid fa-xmark"></i></button></div>
						<div id="hlSelList"></div>
					</div>
				</div>
			</div>
			<div class="hl-strip small d-flex flex-wrap align-items-center my-1" id="hlStrip"></div>
			<div class="small text-muted"><span id="hlUpdated"></span> · <?php echo hl_t('Land anklicken zeigt alle Verbindungen von und nach dort.', 'Click a country to see all its connections.'); ?></div>
		</div>
	</div>

	<div class="card mb-3">
		<div class="card-header p-2"><i class="fa-solid fa-list text-primary"></i> <?php echo hl_t('Letzte Angriffe (echte Einträge, neueste zuerst)', 'Latest attacks (real entries, newest first)'); ?></div>
		<div class="table-responsive"><table class="table table-sm table-striped mb-0 small">
			<thead><tr><th><?php echo hl_t('Zeit', 'Time'); ?></th><th><?php echo hl_t('Angreifer', 'Attacker'); ?></th><th><?php echo hl_t('Art', 'Kind'); ?></th><th><?php echo hl_t('Dienst', 'Service'); ?></th><th><?php echo hl_t('Ziel', 'Target'); ?></th><th class="text-right"><?php echo hl_t('Anzahl', 'Count'); ?></th></tr></thead>
			<tbody id="hlTable"><tr><td colspan="6" class="text-muted"><?php echo hl_t('Lade …', 'Loading …'); ?></td></tr></tbody>
		</table></div>
	</div>
</div>
<style>
	/* Farben als Variablen: hell und dunkel (html[data-theme="dark"] aus header.php) */
	.hl-vars { --hl-sea: #f4f7fa; --hl-land: #e3e6ea; --hl-edge: #fff; --hl-hover: #333; --hl-m1: #fde6cf; --hl-m2: #fdd3ab; --hl-m3: #fdbd86; --hl-m4: #fca562; --hl-m5: #f68c45;
		--hl-login: #dc3545; --hl-exploit: #fd7e14; --hl-scan: #17a2b8; --hl-probe: #6c757d; --hl-log: #007bff; --hl-panel: rgba(255,255,255,.88); --hl-new: #fff3cd; --hl-text: #343a40; --hl-hit: #ffe08a; }
	html[data-theme="dark"] .hl-vars { --hl-sea: #161a1f; --hl-land: #2b3138; --hl-edge: #121417; --hl-hover: #e9ecef; --hl-m1: #4a3020; --hl-m2: #6b3d1f;
		--hl-m3: #8f4c1e; --hl-m4: #b65c1f; --hl-m5: #dc6d22; --hl-login: #ff6b78; --hl-exploit: #ffa44f; --hl-scan: #4dd4ec; --hl-probe: #b8c0c8; --hl-log: #74aefe;
		--hl-panel: rgba(27,31,36,.88); --hl-new: #4d3f12; --hl-text: #e9ecef; --hl-hit: #f5d76e; }
	.hl-stage { position: relative; background: var(--hl-sea); border-radius: .25rem; }
	.hl-mapwrap { position: relative; }
	.hl-map { display: block; width: 100%; height: auto; }
	.hl-map #hlLand path { fill: var(--hl-land); stroke: var(--hl-edge); stroke-width: .4; stroke-linejoin: round; cursor: pointer; }
	/* hell gehalten (dunkel: gedeckt), damit die Boegen darauf sichtbar bleiben */
	.hl-map #hlLand path.hl-m1 { fill: var(--hl-m1); } .hl-map #hlLand path.hl-m2 { fill: var(--hl-m2); } .hl-map #hlLand path.hl-m3 { fill: var(--hl-m3); }
	.hl-map #hlLand path.hl-m4 { fill: var(--hl-m4); } .hl-map #hlLand path.hl-m5 { fill: var(--hl-m5); }
	.hl-map #hlLand circle.hl-pt { fill: var(--hl-land); stroke: var(--hl-edge); stroke-width: .6; cursor: pointer; }
	.hl-map #hlLand circle.hl-m1 { fill: var(--hl-m1); } .hl-map #hlLand circle.hl-m2 { fill: var(--hl-m2); } .hl-map #hlLand circle.hl-m3 { fill: var(--hl-m3); }
	.hl-map #hlLand circle.hl-m4 { fill: var(--hl-m4); } .hl-map #hlLand circle.hl-m5 { fill: var(--hl-m5); }
	.hl-map #hlLand circle.hl-pt:hover, .hl-map #hlLand circle.hl-on { stroke: var(--hl-hover); stroke-width: 1; }
	.hl-map #hlLand path:hover, .hl-map #hlLand path.hl-on { filter: brightness(1.1); stroke: var(--hl-hover); stroke-width: .8; }
	.hl-map path.hl-arc { fill: none; stroke-width: 2.4; stroke-linecap: round; filter: drop-shadow(0 0 1.5px rgba(0,0,0,.35)); }
	.hl-map path.hl-replay { stroke-width: 1.8; stroke-opacity: .7; }
	.hl-map path.hl-hot { stroke-width: 4; stroke-opacity: 1; }
	.hl-map #hlSel path { fill: none; stroke-linecap: round; stroke-opacity: .75; pointer-events: stroke; }
	.hl-map #hlSel path:hover, .hl-map #hlSel path.hl-hot { stroke-opacity: 1; filter: drop-shadow(0 0 2px rgba(0,0,0,.5)); }
	.hl-map circle.hl-src { stroke: var(--hl-edge); stroke-width: .6; }
	/* Beschriftung: Flagge und Code an Quelle und Ziel (mit dem Bogen), schwache Laendernamen der aktiven Laender */
	.hl-map text { font-family: "Twemoji Country Flags", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; pointer-events: none;
		paint-order: stroke; stroke: var(--hl-sea); stroke-width: 2.4px; stroke-linejoin: round; }
	.hl-map .hl-lbl { pointer-events: none; } /* Klicks und Tooltips gehen an das Land darunter */
	.hl-map .hl-lbl rect { fill: rgba(33,37,41,.72); }
	.hl-map .hl-lbl text { fill: #f8f9fa; stroke: none; }
	.hl-map .hl-lbl-dst text { font-weight: 600; }
	.hl-map text.hl-name { fill: var(--hl-text); opacity: .4; text-anchor: middle; }
	.hl-map #hlLand path.hl-hit, .hl-map #hlLand circle.hl-hit { fill: var(--hl-hit); transition: fill .4s; }
	.hl-strip { gap: .3rem 1rem; }
	.hl-strip b { font-weight: 600; }
	.hl-map .hl-dst { fill: none; stroke: var(--hl-login); stroke-width: 1; transform-box: fill-box; transform-origin: center; animation: hlPulse 2s ease-out infinite; }
	@keyframes hlPulse { from { transform: scale(.6); opacity: .9; } to { transform: scale(3); opacity: 0; } }
	@media (prefers-reduced-motion: reduce) { .hl-map .hl-dst { animation: none; } }
	.hl-g-login { stroke: var(--hl-login); fill: var(--hl-login); } .hl-g-exploit { stroke: var(--hl-exploit); fill: var(--hl-exploit); } .hl-g-scan { stroke: var(--hl-scan); fill: var(--hl-scan); }
	.hl-g-probe { stroke: var(--hl-probe); fill: var(--hl-probe); } .hl-g-log { stroke: var(--hl-log); fill: var(--hl-log); }
	.hl-sw { display: inline-block; width: .7rem; height: .7rem; border-radius: 50%; vertical-align: -.05rem; flex: 0 0 .7rem; }
	.hl-sw.hl-g-login { background: var(--hl-login); } .hl-sw.hl-g-exploit { background: var(--hl-exploit); } .hl-sw.hl-g-scan { background: var(--hl-scan); }
	.hl-sw.hl-g-probe { background: var(--hl-probe); } .hl-sw.hl-g-log { background: var(--hl-log); }
	#hlTable tr.hl-new { animation: hlNew 2s ease-out; }
	@keyframes hlNew { from { background: var(--hl-new); } to { background: transparent; } }
	/* Node64-Logo in der Kartenecke */
	.hl-logo { position: absolute; left: .5rem; bottom: .4rem; opacity: .75; line-height: 0; }
	.hl-logo:hover { opacity: 1; }
	.hl-logo img { height: 20px; }
	.hl-logo .hl-logo-d { display: none; }
	html[data-theme="dark"] .hl-logo .hl-logo-l { display: none; } html[data-theme="dark"] .hl-logo .hl-logo-d { display: inline; }
	/* Seitenleiste: ausserhalb des Vollbilds nur die Auswahl (unter der Karte) */
	.hl-panel .hl-fs-only { display: none; }
	.hl-panel #hlSelBox { padding: .4rem .2rem 0; }
	.hl-p-title { font-weight: 600; margin-bottom: .2rem; }
	.hl-row { display: flex; gap: .4rem; align-items: center; white-space: nowrap; overflow: hidden; padding: .05rem .2rem; border-radius: .2rem; cursor: default; }
	.hl-row > span:last-child { overflow: hidden; text-overflow: ellipsis; }
	.hl-row.hl-click { cursor: pointer; } .hl-row:hover { background: rgba(127,127,127,.15); }
	.hl-row.hl-rep { opacity: .65; }
	/* Vollbild (Fullscreen API, sonst Ersatz ueber die Klasse hl-fs) */
	.hl-stage.hl-fs { position: fixed; inset: 0; z-index: 1060; border-radius: 0; display: flex; align-items: center; justify-content: center; }
	.hl-stage.hl-fs .hl-mapwrap { position: static; width: 100%; height: 100%; }
	.hl-stage.hl-fs .hl-map { width: 100%; height: 100%; }
	.hl-stage.hl-fs .hl-logo { left: 1rem; top: 1rem; bottom: auto; } .hl-stage.hl-fs .hl-logo img { height: 30px; }
	.hl-stage.hl-fs .hl-panel { position: absolute; bottom: 1rem; left: 1rem; width: 22rem; max-height: calc(100% - 5rem); overflow-y: auto; background: var(--hl-panel);
		border-radius: .4rem; padding: .7rem; box-shadow: 0 .25rem 1rem rgba(0,0,0,.25); backdrop-filter: blur(4px); }
	html[data-theme="dark"] .hl-stage.hl-fs .hl-panel { color: #d8dde3; }
	.hl-stage.hl-fs .hl-panel .hl-fs-only { display: block; }
	.hl-stage.hl-fs .hl-panel #hlSelBox { padding: .4rem 0 0; border-top: 1px solid rgba(127,127,127,.3); }
	@media (max-width: 767.98px), (orientation: portrait) { .hl-stage.hl-fs .hl-panel { top: auto; bottom: 0; right: 0; left: 0; width: auto; max-height: 42%; border-radius: .4rem .4rem 0 0; } .hl-stage.hl-fs .hl-logo { top: 1rem; bottom: auto; } }
</style>
<script>window.HL_LANG = <?php echo json_encode($hlEn ? 'en' : 'de'); ?>; window.HL_T = <?php echo json_encode(array(
	'replay' => hl_t('Wiederholung', 'replay'), 'updated' => hl_t('Stand der Daten: {time} · neue Daten alle 2 Minuten', 'Data as of {time} · new data every 2 minutes'),
	'empty' => hl_t('In der letzten Stunde keine Angriffe gemeldet.', 'No attacks reported in the last hour.'), 'pause' => hl_t('Anhalten', 'Pause'), 'play' => hl_t('Weiter', 'Resume'),
	'unavailable' => hl_t('Die Live-Daten sind gerade nicht verfügbar.', 'Live data is currently not available.'), 'attacks' => hl_t('Angriffe', 'attacks'),
	'full' => hl_t('Vollbild', 'Full screen'), 'full_exit' => hl_t('Vollbild beenden', 'Exit full screen'), 'now_empty' => hl_t('Gerade kein Bogen.', 'No arc right now.'),
	'sel_country' => hl_t('Verbindungen von und nach {name}', 'Connections from and to {name}'), 'sel_pair' => hl_t('Verbindung {from} → {to}', 'Connection {from} → {to}'),
	'sel_empty' => hl_t('In der letzten Stunde keine Verbindungen.', 'No connections in the last hour.'),
	'strip_top' => hl_t('Top-Herkunft', 'Top origins'), 'strip_pair' => hl_t('Häufigste Verbindung', 'Top connection'), 'strip_kind' => hl_t('Häufigste Art', 'Top kind')), JSON_UNESCAPED_UNICODE); ?>;</script>
<script src="live.js?v=7"></script>
<?php include("../footer.php"); ?>
