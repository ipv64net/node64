<?php
/** Healthchecks 2.0 – Umhängen (Ausführungsort ändern) mit Testlauf, einzeln oder mehrere Checks (Sync-Plan 3.11). */
ob_start(); // header.php gibt HTML aus; hc2_redirect()/hc2_json() verwerfen es
include("../header.php");
require_once(__DIR__ . '/hc2_lib.php');
hc2_require_login();
$uid = (int)$userid;
$nodes = hc2_nodes($uid); $acc = hc2_account($uid); $locs = hc2_locations();
$tokens = array(); foreach (explode(',', (string)($_GET['tokens'] ?? $_POST['tokens'] ?? '')) as $t) { if (preg_match('/^[A-Za-z0-9]{20,50}$/', $t)) { $tokens[] = $t; } }
$checks = array(); foreach ($tokens as $t) { if ($c = hc2_check($uid, $t)) { $checks[] = $c; } }
if (!$checks) { echo '<div class="container"><div class="alert alert-danger mt-3">Keine Checks gewählt.</div></div>'; include("../footer.php"); exit; }
$label = array('online' => 'Online bei ipv64', 'local' => 'Lokal auf Nodes', 'both' => 'Hybrid (Nodes + ipv64)');
$to = (string)($_POST['to'] ?? $_GET['to'] ?? ''); if (!isset($label[$to])) { $to = $checks[0]['execution'] === 'online' ? 'local' : 'online'; }
if (isset($_POST['nodes'])) { $nodesSel = (array)$_POST['nodes']; }
elseif (isset($_GET['nodes'])) { $nodesSel = array_filter(explode(',', (string)$_GET['nodes'])); }
elseif (isset($_GET['node'])) { $nodesSel = array((string)$_GET['node']); }
else { $nodesSel = hc2_check_nodes($checks[0]) ?: array_slice(array_keys($nodes), 0, 1); }
$nodesSel = array_values(array_unique(array_map('strval', $nodesSel)));
$locSel = (array)($_POST['locations'] ?? array_filter(explode(',', (string)($_GET['locations'] ?? $checks[0]['locations']))));
$runs = array(); $errors = array();
$start = (hc2_is_post() && hc2_csrf_ok() && ($_POST['start'] ?? '') === '1') || (!hc2_is_post() && ($_GET['auto'] ?? '') === '1' && hc2_csrf_ok()); // auto=1 nur mit Token aus edit.php, sonst Formular
if ($start) {
	foreach ($checks as $c) {
		if ($c['execution'] === $to && ($to === 'online' || hc2_same_list(hc2_check_nodes($c), $nodesSel)) && ($to === 'local' || implode(',', $locSel) === $c['locations'])) { $runs[] = array('token' => $c['token'], 'name' => $c['name'], 'id' => 0, 'skip' => 'unverändert'); continue; }
		$r = hc2_testrun_create($uid, $c, $to, $nodesSel, $locSel);
		$runs[] = array('token' => $c['token'], 'name' => $c['name'], 'id' => $r['id'], 'error' => $r['error']);
	}
}
?>
<p></p>
<div class="container">
	<?php echo hc2_subnav('index'); ?>
	<div class="card shadow-sm mb-3">
		<div class="card-header p-2"><i class="fa-solid fa-right-left"></i> Umhängen: <?php echo count($checks); ?> Check(s)</div>
		<div class="card-body">
			<p class="small text-muted">Vor dem Wechsel wird ein Testlauf gemacht: online von jedem gewählten Standort, lokal auf jeder gewählten Node. Erst wenn alle Messstellen OK melden, wird der Ausführungsort übernommen. Der Token und die Messhistorie bleiben erhalten.</p>
			<ul class="small mb-3"><?php foreach ($checks as $c) { echo '<li><a href="' . HC2_BASE . '/check.php?token=' . hc2_h($c['token']) . '">' . hc2_h($c['name']) . '</a> – derzeit ' . hc2_exec_badge($c, $nodes) . '</li>'; } ?></ul>
			<?php if (!$start) { ?>
			<form method="post" class="form-row align-items-end">
				<?php echo hc2_csrf_field(); ?><input type="hidden" name="tokens" value="<?php echo hc2_h(implode(',', $tokens)); ?>"><input type="hidden" name="start" value="1">
				<div class="form-group col-md-4"><label>Neuer Ausführungsort</label><select class="custom-select" name="to" id="to"><?php foreach ($label as $k => $v) { echo '<option value="' . $k . '"' . ($to === $k ? ' selected' : '') . (($k !== 'online' && !$nodes) ? ' disabled' : '') . '>' . $v . '</option>'; } ?></select></div>
				<div class="form-group col-md-4" id="nodebox"><label>Messende Nodes</label><div><?php foreach ($nodes as $id => $n) { echo '<div class="custom-control custom-checkbox"><input class="custom-control-input" type="checkbox" id="n_' . hc2_h($id) . '" name="nodes[]" value="' . hc2_h($id) . '"' . (in_array($id, $nodesSel, true) ? ' checked' : '') . '><label class="custom-control-label" for="n_' . hc2_h($id) . '">' . hc2_h(hc2_node_label($nodes, $id)) . ((int)$n['online'] ? '' : ' <span class="badge badge-secondary">offline</span>') . '</label></div>'; } ?></div></div>
				<div class="form-group col-md-4" id="locbox"><label>Standorte</label><div><?php $i = 0; foreach ($locs as $code => $name) { $i++; $ok = $i <= $acc['hc_locations']; echo '<div class="custom-control custom-checkbox custom-control-inline"><input class="custom-control-input" type="checkbox" id="l_' . $code . '" name="locations[]" value="' . $code . '"' . ((in_array($code, $locSel, true) && $ok) ? ' checked' : '') . ($ok ? '' : ' disabled') . '><label class="custom-control-label" for="l_' . $code . '">' . hc2_h($name) . '</label></div>'; } ?></div></div>
				<div class="form-group col-12"><button class="btn btn-primary" type="submit"><i class="fa-solid fa-flask"></i> Testlauf starten</button> <a class="btn btn-outline-secondary" href="<?php echo count($checks) === 1 ? HC2_BASE . '/check.php?token=' . hc2_h($checks[0]['token']) : HC2_BASE . '/'; ?>">Abbrechen</a></div>
			</form>
			<?php } else { ?>
			<p>Ziel: <strong><?php echo hc2_h($label[$to] ?? $to); ?></strong><?php echo $to !== 'online' ? ' · Nodes ' . hc2_h(hc2_nodes_label($nodes, $nodesSel)) : ''; echo $to !== 'local' ? ' · Standorte ' . hc2_h(implode(', ', array_map(function($l) use ($locs) { return $locs[$l] ?? $l; }, $locSel))) : ''; ?></p>
			<table class="table table-sm" id="runs"><thead><tr><th>Check</th><th>Status</th><th>Ergebnis</th></tr></thead><tbody>
			<?php foreach ($runs as $r) { ?>
				<tr data-id="<?php echo (int)$r['id']; ?>"><td><?php echo hc2_h($r['name']); ?></td>
				<td class="st"><?php if (!empty($r['skip'])) { echo '<span class="badge badge-secondary">' . hc2_h($r['skip']) . '</span>'; } elseif ($r['error']) { echo '<span class="badge badge-danger">abgelehnt</span>'; } else { echo '<span class="badge badge-info">läuft …</span>'; } ?></td>
				<td class="res small"><?php echo hc2_h($r['error']); ?></td></tr>
			<?php } ?>
			</tbody></table>
			<div id="done" style="display:none"><a class="btn btn-primary" href="<?php echo count($checks) === 1 ? HC2_BASE . '/check.php?token=' . hc2_h($checks[0]['token']) : HC2_BASE . '/'; ?>">Fertig</a> <a class="btn btn-outline-secondary" href="<?php echo HC2_BASE; ?>/move.php?tokens=<?php echo hc2_h(implode(',', $tokens)); ?>">Noch einmal</a></div>
			<?php } ?>
		</div>
	</div>
</div>
<?php include("../footer.php"); ?>
<script>
(function(){
	function sync(){ var t = $('#to').val(); $('#nodebox').toggle(t !== 'online'); $('#locbox').toggle(t !== 'local'); }
	$('#to').on('change', sync); sync();
	var open = $('#runs tr[data-id]').filter(function(){ return $(this).data('id') > 0; }).toArray();
	if (!open.length) { $('#done').show(); return; }
	var tries = 0;
	function poll(){
		tries++; var left = [];
		open.forEach(function(tr){
			var id = $(tr).data('id');
			$.getJSON('<?php echo HC2_BASE; ?>/testrun.php', {id: id}, function(d){
				var res = (d.results || []).map(function(r){ return (r.ok ? '✅ ' : '❌ ') + r.source + (r.message ? ': ' + r.message : ''); }).join('<br>');
				$(tr).find('.res').html(res + (d.error ? '<br><span class="text-danger">' + d.error + '</span>' : ''));
				if (d.status === 'ok') { $(tr).find('.st').html('<span class="badge badge-success">übernommen</span>'); }
				else if (d.status === 'failed') { $(tr).find('.st').html('<span class="badge badge-danger">fehlgeschlagen, bleibt wie bisher</span>'); }
				else if (d.status === 'expired' || d.status === 'missing') { $(tr).find('.st').html('<span class="badge badge-warning">keine Antwort</span>'); }
				else { left.push(tr); }
			});
		});
		setTimeout(function(){ open = left; if (open.length && tries < 40) { poll(); } else { if (open.length) { open.forEach(function(tr){ $(tr).find('.st').html('<span class="badge badge-warning">Zeit abgelaufen</span>'); }); } $('#done').show(); } }, 2000);
	}
	setTimeout(poll, 1500);
})();
</script>
