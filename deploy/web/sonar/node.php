<?php
/**
 * Sonar64 – oeffentliche Knotenseite (Teil W, Plan Abschnitt 7), teilbar: Stufe, dabei seit, Verfuegbarkeit, Provider,
 * Anschluss, Erreichbarkeit (nur die Art), Latenz zu den Ankern und ihr Verlauf ueber 7 Tage (je Stunde).
 * sonar.js holt GET /api/v2/sonar/public/node/{slug}; ohne IP, Standort verschleiert.
 *
 *   node.php?slug=sonar-falke-42[&lang=en]
 */
include("../header.php");
require_once __DIR__ . '/s64_web.php';
$slug = (string)($_GET['slug'] ?? '');
if(!preg_match('/^[a-z0-9][a-z0-9_-]{0,39}$/', $slug)) { $slug = ''; }
s64w_head('node', s64w_t('Knoten', 'Node'), s64w_t('Öffentliche Seite eines Sonar64-Knotens: Vertrauensstufe, Verfügbarkeit und die Laufzeit zu den Ankern – ein Beleg für die eigene Leitung, ohne IP-Adresse und mit verschleiertem Standort.',
	'Public page of a Sonar64 node: trust level, availability and the round-trip time to the anchors – evidence for your own line, without IP address and with a blurred location.'), array('slug' => $slug));
if($slug === '') { ?>
	<div class="alert alert-warning" role="alert"><?php echo s64w_h(s64w_t('Kein gültiger Knoten angegeben.', 'No valid node given.')); ?> <a href="<?php echo s64w_h(s64w_url('nodes.php')); ?>"><?php echo s64w_h(s64w_t('Zur Teilnehmerliste', 'To the participant list')); ?></a></div>
<?php } else { ?>
	<div id="s64NodeMsg"></div>
	<div class="row" id="s64NodeBody" hidden>
		<div class="col-12 col-lg-8 pb-3"><div class="card h-100"><div class="card-body p-3">
			<div class="d-flex flex-wrap align-items-center mb-2" style="gap:.5rem">
				<h4 class="mb-0" data-s64-f="name"></h4><span data-s64-f="trust"></span><span data-s64-f="online"></span>
				<button type="button" class="btn btn-sm btn-outline-secondary py-0 ml-auto" id="s64Share" title="<?php echo s64w_h(s64w_t('Link kopieren', 'Copy link')); ?>"><i class="fa-solid fa-share-nodes"></i> <?php echo s64w_h(s64w_t('Teilen', 'Share')); ?></button>
			</div>
			<table class="table table-sm small mb-0 s64-kv"><tbody>
				<tr><th><?php echo s64w_h(s64w_t('Provider', 'Provider')); ?></th><td data-s64-f="provider"></td></tr>
				<tr><th><?php echo s64w_h(s64w_t('Region', 'Region')); ?></th><td data-s64-f="place"></td></tr>
				<tr><th><?php echo s64w_h(s64w_t('Anschluss / Gerät', 'Access / device')); ?></th><td data-s64-f="access"></td></tr>
				<tr><th><?php echo s64w_h(s64w_t('Dabei seit', 'Member since')); ?></th><td data-s64-f="since"></td></tr>
				<tr><th><?php echo s64w_h(s64w_t('Verfügbarkeit (30 Tage)', 'Availability (30 days)')); ?></th><td data-s64-f="uptime30"></td></tr>
				<tr><th><?php echo s64w_h(s64w_t('Erreichbar für Messungen', 'Reachable for measurements')); ?></th><td data-s64-f="reach"></td></tr>
				<tr><th><?php echo s64w_h(s64w_t('Zu den Ankern (jetzt)', 'To the anchors (now)')); ?></th><td data-s64-f="anchors"></td></tr>
			</tbody></table>
			<p class="small text-muted mt-2 mb-0" data-s64-f="trustinfo"></p>
		</div></div></div>
		<div class="col-12 col-lg-4 pb-3"><div class="card h-100"><div class="card-body p-2">
			<svg id="s64Mini" class="s64-map s64-mini" role="img" aria-label="<?php echo s64w_h(s64w_t('Ungefährer Standort', 'Approximate location')); ?>"></svg>
			<p class="small text-muted mb-0 text-center"><?php echo s64w_h(s64w_t('Ungefährer Standort (verschleiert)', 'Approximate location (blurred)')); ?></p>
		</div></div></div>
		<div class="col-12 pb-3"><div class="card"><div class="card-header p-2"><i class="fa-solid fa-chart-line text-primary"></i> <?php echo s64w_h(s64w_t('Laufzeit zu den Ankern – 7 Tage, je Stunde (Median)', 'Round-trip time to the anchors – 7 days, hourly (median)')); ?></div>
			<div class="card-body p-2"><div class="s64-chart" id="s64Chart"></div><div class="small" id="s64ChartTip">&nbsp;</div>
			<div class="table-responsive"><table class="table table-sm small mb-0"><thead><tr><th><?php echo s64w_h(s64w_t('Anker', 'Anchor')); ?></th><th class="text-right">Median</th><th class="text-right">Min</th><th class="text-right">Max</th><th class="text-right"><?php echo s64w_h(s64w_t('Verlust', 'Loss')); ?></th><th class="text-right"><?php echo s64w_h(s64w_t('Stunden', 'Hours')); ?></th></tr></thead><tbody id="s64ChartSum"></tbody></table></div>
		</div></div></div>
	</div>
<?php } ?>
	<?php s64w_join(); ?>
<?php s64w_foot(); include("../footer.php"); ?>
