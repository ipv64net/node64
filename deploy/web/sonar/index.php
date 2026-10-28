<?php
/**
 * Sonar64 – oeffentliche Karte (Teil W, Plan docs/PLAN-NODE64-SONAR64.md Abschnitt 7, Vertrag Abschnitt 5).
 * Deutschlandkarte aus de_map.json (eigene schlichte Umrisslinie, keine fremden Kacheln/CDNs), Knoten als Punkte nach
 * Vertrauensstufe, Verbindungen mit ms-Badges nach Latenz, Stoerungen, Zahlen live. Die Seite fragt keine Datenbank;
 * sonar.js holt alle 60 s GET /api/v2/sonar/public/map und /public/stats (ohne IPs, Standorte verschleiert).
 *
 *   index.php            Deutsch
 *   index.php?lang=en    Englisch
 */
include("../header.php");
require_once __DIR__ . '/s64_web.php';
s64w_head('map', s64w_t('Live-Karte', 'Live map'), s64w_t('Knoten der Community messen sich gegenseitig und die Anker – hier siehst du das Netz live: Punkte sind Knoten (Farbe = Vertrauensstufe), Linien die Messungen der letzten Stunde mit der mittleren Laufzeit.',
	'Community nodes measure each other and the anchors – this is the network live: dots are nodes (colour = trust level), lines are the measurements of the last hour with their median round-trip time.'));
?>
	<div class="row">
		<?php foreach(array(array('nodes_active', s64w_t('Aktive Knoten', 'Active nodes'), 'fa-tower-broadcast', 'success'), array('measurements_today', s64w_t('Messungen heute', 'Measurements today'), 'fa-wave-square', 'primary'),
			array('providers', s64w_t('Provider', 'Providers'), 'fa-network-wired', 'info'), array('anchors', s64w_t('Anker', 'Anchors'), 'fa-anchor', 'secondary')) as [$k, $label, $icon, $color]) { ?>
		<div class="col-6 col-md pb-3"><div class="card bg-light h-100" style="border-left:4px solid var(--<?php echo $color; ?>)"><div class="card-body p-2"><i class="fa-solid <?php echo $icon; ?> fa-2xl float-right pt-4 text-<?php echo $color; ?>"></i>
			<p class="lead m-0"><?php echo s64w_h($label); ?></p><p class="card-text h3" data-s64-stat="<?php echo $k; ?>">–</p>
		</div></div></div>
		<?php } ?>
	</div>

	<div id="s64Outages" class="mb-3" hidden></div>

	<div class="card mb-3">
		<div class="card-header p-2 d-flex flex-wrap align-items-center" style="gap:.6rem">
			<span><i class="fa-solid fa-map text-primary"></i> <?php echo s64w_h(s64w_t('Deutschland', 'Germany')); ?> <span class="badge badge-danger align-middle" id="s64Live">LIVE</span></span>
			<span class="small d-flex flex-wrap align-items-center s64-legend" id="s64LegendTrust"></span>
			<span class="small d-flex flex-wrap align-items-center s64-legend" id="s64LegendLat"></span>
			<span class="ml-auto">
				<button type="button" class="btn btn-sm btn-outline-secondary py-0" data-s64-zoom="1" title="<?php echo s64w_h(s64w_t('Vergrößern', 'Zoom in')); ?>"><i class="fa-solid fa-plus"></i></button>
				<button type="button" class="btn btn-sm btn-outline-secondary py-0" data-s64-zoom="-1" title="<?php echo s64w_h(s64w_t('Verkleinern', 'Zoom out')); ?>"><i class="fa-solid fa-minus"></i></button>
				<button type="button" class="btn btn-sm btn-outline-secondary py-0" data-s64-zoom="0" title="<?php echo s64w_h(s64w_t('Ganze Karte', 'Whole map')); ?>"><i class="fa-solid fa-expand"></i></button>
			</span>
		</div>
		<div class="card-body p-2">
			<div class="row">
				<div class="col-12 col-lg-8"><div class="s64-stage" id="s64Stage"><svg id="s64Map" class="s64-map" role="img" aria-label="<?php echo s64w_h(s64w_t('Karte der Sonar64-Knoten in Deutschland', 'Map of the Sonar64 nodes in Germany')); ?>"></svg></div></div>
				<div class="col-12 col-lg-4 small">
					<div id="s64Info" class="s64-info"><p class="text-muted mb-2"><?php echo s64w_h(s64w_t('Knoten anklicken für Details und seine Verbindungen.', 'Click a node for details and its connections.')); ?></p></div>
					<div class="s64-p-title"><?php echo s64w_h(s64w_t('Messungen der letzten Stunde', 'Measurements of the last hour')); ?></div>
					<div id="s64Ticker" class="s64-ticker"></div>
				</div>
			</div>
			<div class="small text-muted mt-1"><span id="s64Updated"></span> · <?php echo s64w_h(s64w_t('Standorte im Umkreis von etwa 1 km verschleiert, keine IP-Adressen. Linien: Median der letzten 60 Minuten.', 'Locations blurred within about 1 km, no IP addresses. Lines: median of the last 60 minutes.')); ?></div>
		</div>
	</div>

	<?php s64w_join(); ?>
<?php s64w_foot(); include("../footer.php"); ?>
