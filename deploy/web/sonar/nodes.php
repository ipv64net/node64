<?php
/**
 * Sonar64 – Teilnehmerliste (Teil W, Plan Abschnitt 7): alle oeffentlichen Knoten mit Stufe, Provider, Region, Geraet,
 * Verfuegbarkeit; filterbar nach Stufe, ASN und Name. sonar.js holt GET /api/v2/sonar/public/nodes?trust=&asn=&q=
 * (keine IPs, keine Koordinaten in der Tabelle). Die Filterwerte werden hier nur geprueft und vorbelegt.
 *
 *   nodes.php?trust=stable&asn=3320&q=falke&lang=en
 */
include("../header.php");
require_once __DIR__ . '/s64_web.php';
$fTrust = (string)($_GET['trust'] ?? '');
if(!in_array($fTrust, array('new', 'stable', 'trusted', 'pillar', 'anchor'), true)) { $fTrust = ''; }
$fAsn = (string)($_GET['asn'] ?? '');
if(!preg_match('/^[0-9]{1,10}$/', $fAsn) OR (int)$fAsn < 1 OR (int)$fAsn > 4294967295) { $fAsn = ''; }
$fQ = (string)($_GET['q'] ?? '');
if(!preg_match('/^[A-Za-z0-9 ._-]{1,32}$/', $fQ)) { $fQ = ''; }
s64w_head('nodes', s64w_t('Teilnehmer', 'Participants'), s64w_t('Alle Knoten, die gerade mitmachen – mit Vertrauensstufe, Provider, Region und Verfügbarkeit. Ein Klick auf den Namen öffnet die öffentliche Knotenseite.',
	'All nodes taking part – with trust level, provider, region and availability. Click a name for the public node page.'));
?>
	<div class="card mb-3"><div class="card-body p-2">
		<form id="s64Filter" class="form-inline small" style="gap:.5rem" autocomplete="off">
			<?php if(s64w_lang() === 'en') { ?><input type="hidden" name="lang" value="en"><?php } ?>
			<label class="mr-1" for="s64fTrust"><?php echo s64w_h(s64w_t('Stufe', 'Level')); ?></label>
			<select class="form-control form-control-sm" id="s64fTrust" name="trust">
				<option value=""><?php echo s64w_h(s64w_t('alle', 'all')); ?></option>
				<?php foreach(array('new', 'stable', 'trusted', 'pillar', 'anchor') as $t) { ?>
				<option value="<?php echo $t; ?>"<?php echo $t === $fTrust ? ' selected' : ''; ?>><?php echo s64w_h(s64w_trust($t)); ?></option>
				<?php } ?>
			</select>
			<label class="mr-1" for="s64fAsn">ASN</label>
			<input class="form-control form-control-sm" id="s64fAsn" name="asn" inputmode="numeric" pattern="[0-9]{1,10}" maxlength="10" size="8" placeholder="3320" value="<?php echo s64w_h($fAsn); ?>">
			<label class="mr-1" for="s64fQ"><?php echo s64w_h(s64w_t('Name', 'Name')); ?></label>
			<input class="form-control form-control-sm" id="s64fQ" name="q" maxlength="32" pattern="[A-Za-z0-9 ._\-]{1,32}" size="16" placeholder="<?php echo s64w_h(s64w_t('Suche', 'Search')); ?>" value="<?php echo s64w_h($fQ); ?>">
			<button class="btn btn-sm btn-primary" type="submit"><i class="fa-solid fa-filter"></i> <?php echo s64w_h(s64w_t('Filtern', 'Filter')); ?></button>
			<a class="btn btn-sm btn-outline-secondary" href="<?php echo s64w_h(s64w_url('nodes.php')); ?>"><?php echo s64w_h(s64w_t('Zurücksetzen', 'Reset')); ?></a>
			<span class="ml-auto text-muted" id="s64Count"></span>
		</form>
	</div></div>

	<div class="card mb-3"><div class="table-responsive">
		<table class="table table-sm table-striped table-hover mb-0 small s64-table" id="s64NodesTable">
			<thead><tr>
				<th data-s64-sort="name"><?php echo s64w_h(s64w_t('Name', 'Name')); ?></th>
				<th data-s64-sort="trust"><?php echo s64w_h(s64w_t('Stufe', 'Level')); ?></th>
				<th data-s64-sort="asname"><?php echo s64w_h(s64w_t('Provider', 'Provider')); ?></th>
				<th data-s64-sort="place"><?php echo s64w_h(s64w_t('Region', 'Region')); ?></th>
				<th data-s64-sort="access"><?php echo s64w_h(s64w_t('Anschluss', 'Access')); ?></th>
				<th data-s64-sort="device"><?php echo s64w_h(s64w_t('Gerät', 'Device')); ?></th>
				<th data-s64-sort="uptime30" class="text-right"><?php echo s64w_h(s64w_t('Verfügbarkeit 30 T.', 'Availability 30 d')); ?></th>
				<th data-s64-sort="since"><?php echo s64w_h(s64w_t('Dabei seit', 'Member since')); ?></th>
				<th data-s64-sort="online"><?php echo s64w_h(s64w_t('Status', 'Status')); ?></th>
			</tr></thead>
			<tbody id="s64Nodes"><tr><td colspan="9" class="text-muted"><?php echo s64w_h(s64w_t('Lade …', 'Loading …')); ?></td></tr></tbody>
		</table>
	</div></div>
	<p class="small text-muted"><?php echo s64w_h(s64w_t('Knoten in Quarantäne erscheinen nicht. Verfügbarkeit: Anteil der Zeit mit Meldung in den letzten 30 Tagen. Provider aus der öffentlichen IP der Verbindung (BGP-Daten), nicht vom Knoten behauptet.',
		'Nodes in quarantine are not listed. Availability: share of time with reports in the last 30 days. Provider from the public IP of the connection (BGP data), not claimed by the node.')); ?></p>
	<?php s64w_join(); ?>
<?php s64w_foot(); include("../footer.php"); ?>
