<?php
/**
 * Sonar64 – Bestenliste und Zahlen (Teil W, Plan Abschnitt 7): Zahlen live (alle 60 s), zuverlaessigste Knoten,
 * laengste Teilnahme, je Provider, Provider-Matrix (Median der letzten 24 h) und Stoerungen.
 * sonar.js holt GET /api/v2/sonar/public/stats, /public/top, /public/matrix, /public/outages.
 *
 *   top.php[?lang=en]
 */
include("../header.php");
require_once __DIR__ . '/s64_web.php';
s64w_head('top', s64w_t('Bestenliste & Zahlen', 'Leaderboard & numbers'), s64w_t('Wer ist am längsten dabei, wer am zuverlässigsten – und wie schnell kommen die Provider untereinander zusammen? Laufzeiten sind Mediane vieler Messungen, nie der Wert eines einzelnen Knotens.',
	'Who has been around longest, who is most reliable – and how fast do the providers reach each other? Round-trip times are medians of many measurements, never the value of a single node.'));
?>
	<div class="row">
		<?php foreach(array(array('nodes_active', s64w_t('Aktive Knoten', 'Active nodes'), 'fa-tower-broadcast', 'success'), array('nodes_total', s64w_t('Knoten gesamt', 'Nodes total'), 'fa-users', 'primary'),
			array('measurements_today', s64w_t('Messungen heute', 'Measurements today'), 'fa-wave-square', 'primary'), array('providers', s64w_t('Provider', 'Providers'), 'fa-network-wired', 'info'),
			array('regions', s64w_t('Regionen', 'Regions'), 'fa-map-location-dot', 'info'), array('anchors', s64w_t('Anker', 'Anchors'), 'fa-anchor', 'secondary')) as [$k, $label, $icon, $color]) { ?>
		<div class="col-6 col-md-4 col-xl-2 pb-3"><div class="card bg-light h-100" style="border-left:4px solid var(--<?php echo $color; ?>)"><div class="card-body p-2"><i class="fa-solid <?php echo $icon; ?> fa-xl float-right pt-3 text-<?php echo $color; ?>"></i>
			<p class="m-0 small"><?php echo s64w_h($label); ?></p><p class="card-text h4 mb-0" data-s64-stat="<?php echo $k; ?>">–</p>
		</div></div></div>
		<?php } ?>
	</div>
	<div class="card mb-3"><div class="card-body p-2 small d-flex flex-wrap align-items-center s64-legend" style="gap:.4rem .9rem" id="s64ByTrust"></div></div>

	<div id="s64Outages" class="mb-3"></div>

	<div class="row">
		<div class="col-12 col-lg-4 pb-3"><div class="card h-100"><div class="card-header p-2"><i class="fa-solid fa-medal text-warning"></i> <?php echo s64w_h(s64w_t('Am zuverlässigsten', 'Most reliable')); ?></div>
			<div class="card-body p-0"><table class="table table-sm mb-0 small"><tbody id="s64TopReliable"><tr><td class="text-muted"><?php echo s64w_h(s64w_t('Lade …', 'Loading …')); ?></td></tr></tbody></table></div></div></div>
		<div class="col-12 col-lg-4 pb-3"><div class="card h-100"><div class="card-header p-2"><i class="fa-solid fa-hourglass-half text-primary"></i> <?php echo s64w_h(s64w_t('Am längsten dabei', 'Longest participation')); ?></div>
			<div class="card-body p-0"><table class="table table-sm mb-0 small"><tbody id="s64TopLongest"><tr><td class="text-muted"><?php echo s64w_h(s64w_t('Lade …', 'Loading …')); ?></td></tr></tbody></table></div></div></div>
		<div class="col-12 col-lg-4 pb-3"><div class="card h-100"><div class="card-header p-2"><i class="fa-solid fa-network-wired text-info"></i> <?php echo s64w_h(s64w_t('Je Provider', 'By provider')); ?></div>
			<div class="card-body p-0"><table class="table table-sm mb-0 small"><thead><tr><th>Provider</th><th class="text-right"><?php echo s64w_h(s64w_t('Knoten', 'Nodes')); ?></th><th class="text-right">online</th><th><?php echo s64w_h(s64w_t('Zuverlässigster', 'Most reliable')); ?></th></tr></thead><tbody id="s64TopProviders"><tr><td colspan="4" class="text-muted"><?php echo s64w_h(s64w_t('Lade …', 'Loading …')); ?></td></tr></tbody></table></div></div></div>
	</div>

	<div class="card mb-3"><div class="card-header p-2"><i class="fa-solid fa-table-cells text-primary"></i> <?php echo s64w_h(s64w_t('Provider-Matrix – Median der letzten 24 Stunden', 'Provider matrix – median of the last 24 hours')); ?>
		<span class="small d-inline-flex flex-wrap align-items-center s64-legend ml-2" data-s64-latlegend></span></div>
		<div class="card-body p-2"><div class="table-responsive" id="s64Matrix"><span class="small text-muted"><?php echo s64w_h(s64w_t('Lade …', 'Loading …')); ?></span></div>
		<p class="small text-muted mb-0 mt-1"><?php echo s64w_h(s64w_t('Median beider Richtungen zwischen den Knoten zweier Provider (bis zu 20 Provider mit den meisten Knoten). Ein Feld erscheint erst mit Messungen.', 'Median of both directions between the nodes of two providers (up to 20 providers with the most nodes). A cell only appears with measurements.')); ?></p></div></div>

	<div class="card mb-3"><div class="card-header p-2"><i class="fa-solid fa-triangle-exclamation text-danger"></i> <?php echo s64w_h(s64w_t('Störungen (laufend und vergangen)', 'Outages (ongoing and past)')); ?></div>
		<div class="table-responsive"><table class="table table-sm table-striped mb-0 small"><thead><tr><th><?php echo s64w_h(s64w_t('Art', 'Kind')); ?></th><th><?php echo s64w_h(s64w_t('Betroffen', 'Affected')); ?></th><th><?php echo s64w_h(s64w_t('Beginn', 'Start')); ?></th><th><?php echo s64w_h(s64w_t('Ende', 'End')); ?></th><th class="text-right"><?php echo s64w_h(s64w_t('Knoten', 'Nodes')); ?></th></tr></thead>
		<tbody id="s64OutageList"><tr><td colspan="5" class="text-muted"><?php echo s64w_h(s64w_t('Lade …', 'Loading …')); ?></td></tr></tbody></table></div></div>

	<?php s64w_join(); ?>
<?php s64w_foot(); include("../footer.php"); ?>
