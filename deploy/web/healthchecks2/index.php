<?php
/** Healthchecks 2.0 – Übersicht. Ohne Menülink; nur über die URL erreichbar. */
ob_start(); // header.php gibt HTML aus; hc2_redirect()/hc2_json() verwerfen es
include("../header.php");
require_once(__DIR__ . '/hc2_lib.php');
hc2_require_login();
$uid = (int)$userid;
$nodes = hc2_nodes($uid); $acc = hc2_account($uid); $locs = hc2_locations();

// ---- Massenaktionen
if (hc2_is_post() && hc2_csrf_ok()) {
	$tokens = array(); foreach ((array)($_POST['tokens'] ?? array()) as $t) { if (preg_match('/^[A-Za-z0-9]{20,50}$/', $t)) { $tokens[] = $t; } }
	$action = (string)($_POST['action'] ?? '');
	// Knopf in einer Zeile: "aktion:token" gilt nur fuer diesen Check
	if (preg_match('/^(run|pause|resume):([A-Za-z0-9]{20,50})$/', (string)($_POST['one'] ?? ''), $om)) { $action = $om[1]; $tokens = array($om[2]); }
	$n = 0; $foWarn = $action === 'delete' ? hc2_failover_warning(hc2_failover_uses($uid, $tokens)) : '';
	try {
		foreach ($tokens as $t) {
			$c = hc2_check($uid, $t); if (!$c) { continue; }
			switch ($action) {
				case 'pause': if (!(int)$c['paused']) { hc2_set_check($uid, $t, array('paused' => 1)); $n++; } break;
				case 'resume': if ((int)$c['paused']) { hc2_set_check($uid, $t, array('paused' => 0)); $n++; } break;
				case 'delete': hc2_delete_check($uid, $t); $n++; break;
				case 'run':
					if ($c['type'] !== 'push' && $c['execution'] !== 'online' && !(int)$c['paused']) { foreach (hc2_check_nodes($c) as $rn) { hc2_command($rn, 'run_check', array('token' => $t)); } $n++; }
					break;
				case 'tag':
					$tag = mb_substr(trim((string)($_POST['tag'] ?? '')), 0, 40);
					if ($tag !== '' && !preg_match('/[,\s]/', $tag)) { $tags = array_filter(explode(',', $c['tags'])); if (!in_array($tag, $tags, true)) { $tags[] = $tag; hc2_set_check($uid, $t, array('tags' => implode(',', $tags))); $n++; } }
					break;
				case 'untag':
					$tag = mb_substr(trim((string)($_POST['tag'] ?? '')), 0, 40);
					$tags = array_values(array_filter(explode(',', $c['tags']), function($x) use ($tag) { return $x !== '' && $x !== $tag; }));
					if (implode(',', $tags) !== $c['tags']) { hc2_set_check($uid, $t, array('tags' => implode(',', $tags))); $n++; }
					break;
			}
		}
		if ($action === 'move' && $tokens) { hc2_redirect(HC2_BASE . '/move.php?tokens=' . implode(',', $tokens)); }
		if (in_array($action, array('pause','resume','delete','tag','untag'), true)) { hc2_flash($foWarn !== '' ? 'warning' : 'success', $n . ' Check(s) geändert.' . ($foWarn !== '' ? ' ' . $foWarn : '')); }
		if ($action === 'run') { hc2_flash('info', $n . ' Check(s) an die Nodes zur sofortigen Prüfung gegeben' . ($n < count($tokens) ? '; Online-, Push- und pausierte Checks werden im Intervall geprüft.' : '.')); }
	} catch (Throwable $e) { error_log('hc2 index: ' . $e->getMessage()); hc2_flash('danger', 'Aktion fehlgeschlagen.'); }
	hc2_redirect(HC2_BASE . '/' . (!empty($_SERVER['QUERY_STRING']) ? '?' . $_SERVER['QUERY_STRING'] : ''));
}

// ---- Daten
try { $all = hc2_checks($uid); } catch (Throwable $e) { error_log('hc2 index: ' . $e->getMessage()); $all = array(); echo '<div class="container"><div class="alert alert-danger mt-3">Healthchecks derzeit nicht abrufbar.</div></div>'; include("../footer.php"); exit; }
$stateOf = function(array $c): string { return hc2_check_state($c); };
// aktuelle Latenz je Check: letzte Messung einer Messstelle (hc2_checks.last_latency_ms aendert sich nur beim Zustandswechsel)
$curLat = array();
try { $st = hc2_pdo()->prepare("SELECT s.token, s.last_latency_ms FROM hc2_check_states s JOIN hc2_checks c ON c.token = s.token WHERE c.userid = :u AND c.deleted_at IS NULL ORDER BY s.updated_at"); $st->execute(array('u' => $uid)); foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $r) { $curLat[$r['token']] = (float)$r['last_latency_ms']; } } catch (Throwable $e) { error_log('hc2 index latency: ' . $e->getMessage()); }
foreach ($all as &$c) { if (isset($curLat[$c['token']])) { $c['last_latency_ms'] = $curLat[$c['token']]; } } unset($c);
$counts = array('up' => 0, 'down' => 0, 'degraded' => 0, 'paused' => 0, 'other' => 0, 'online' => 0, 'local' => 0, 'both' => 0);
$allTags = array(); $allGroups = array(); $stateCounts = array();
foreach ($all as $c) {
	$s = $stateOf($c); if (isset($counts[$s])) { $counts[$s]++; } else { $counts['other']++; }
	$stateCounts[$s] = ($stateCounts[$s] ?? 0) + 1;
	$counts[$c['execution']]++;
	foreach (explode(',', $c['tags']) as $t) { if ($t !== '') { $allTags[$t] = true; } }
	if ($c['group_name'] !== '') { $allGroups[$c['group_name']] = true; }
}
ksort($allTags); uksort($allGroups, 'strcasecmp');
// Filter
$q = trim((string)($_GET['q'] ?? '')); $fState = (string)($_GET['state'] ?? ''); $fType = (string)($_GET['type'] ?? ''); $fExec = (string)($_GET['exec'] ?? ''); $fNode = (string)($_GET['node'] ?? ''); $fTag = (string)($_GET['tag'] ?? ''); $fGroup = (string)($_GET['group'] ?? '');
$sort = (string)($_GET['sort'] ?? 'name'); $desc = ($_GET['dir'] ?? '') === 'desc';
$list = array_values(array_filter($all, function($c) use ($q, $fState, $fType, $fExec, $fNode, $fTag, $fGroup, $stateOf) {
	if ($q !== '' && stripos($c['name'] . ' ' . $c['target'] . ' ' . $c['tags'], $q) === false) { return false; }
	if ($fState !== '' && $stateOf($c) !== $fState) { return false; }
	if ($fType !== '' && $c['type'] !== $fType) { return false; }
	if ($fExec !== '' && $c['execution'] !== $fExec) { return false; }
	if ($fNode !== '' && !in_array($fNode, hc2_check_nodes($c), true)) { return false; }
	if ($fTag !== '' && !in_array($fTag, explode(',', $c['tags']), true)) { return false; }
	if ($fGroup !== '' && $c['group_name'] !== $fGroup) { return false; }
	return true;
}));
$rank = array('down' => 0, 'degraded' => 1, 'flapping' => 2, 'dependent' => 2, 'unchecked' => 3, 'stabilizing' => 3, 'quota' => 4, 'pending' => 4, 'up' => 5, 'paused' => 6);
usort($list, function($a, $b) use ($sort, $stateOf, $rank, $desc) {
	switch ($sort) {
		case 'state': $r = ($rank[$stateOf($a)] ?? 9) <=> ($rank[$stateOf($b)] ?? 9) ?: strcasecmp($a['name'], $b['name']); break;
		case 'changed': $r = strcmp((string)$b['state_since'], (string)$a['state_since']); break;
		case 'latency': $r = ((float)$b['last_latency_ms']) <=> ((float)$a['last_latency_ms']); break;
		case 'type': $r = strcmp($a['type'], $b['type']) ?: strcasecmp($a['name'], $b['name']); break;
		default: $r = strcasecmp($a['name'], $b['name']);
	}
	return $desc ? -$r : $r;
});
// Untergruppen in „Proxmox VE“ und „Docker“: je System bzw. Docker-Host (Name setzt die Node in params.system, live)
$subOf = function(array $c) use ($nodes): string {
	if (!in_array($c['group_name'], array('Proxmox VE', 'Docker'), true) || !in_array($c['type'], array('proxmox', 'docker'), true)) { return ''; }
	$sys = trim((string)(hc2_check_params($c)['system'] ?? ''));
	$nid = hc2_check_nodes($c)[0] ?? ''; $node = isset($nodes[$nid]) ? (string)$nodes[$nid]['name'] : '';
	if ($sys !== '' && !empty(hc2_check_params($c)['system_custom'])) { return $sys; } // Untergruppe von Hand (Node64)
	if ($c['type'] === 'proxmox') { return $sys !== '' ? $sys : ($node !== '' ? 'Node ' . $node : 'Proxmox VE'); }
	return $sys !== '' ? $sys . ($node !== '' ? ' · ' . $node : '') : ($node !== '' ? 'Node ' . $node : 'Docker');
};
if ($allGroups) {
	$order = array(); $i = 0; foreach (array_keys($allGroups) as $g) { $order[$g] = $i++; }
	$pos = array(); foreach ($list as $k => $c) { $pos[$c['token']] = $k; }
	usort($list, function($a, $b) use ($order, $pos, $subOf) { $ga = $order[$a['group_name']] ?? PHP_INT_MAX; $gb = $order[$b['group_name']] ?? PHP_INT_MAX; return $ga <=> $gb ?: strcasecmp($subOf($a), $subOf($b)) ?: $pos[$a['token']] <=> $pos[$b['token']]; });
}
$pills = hc2_pills_many(array_column($list, 'token'), 30, $nodes);
$used = hc2_online_used($uid); $limit = $acc['healthcheck_limit'];
$qs = function(array $over) { return HC2_BASE . '/?' . http_build_query(array_merge($_GET, $over)); };
?>
<p></p>
<div class="container">
	<?php echo hc2_subnav('index'); echo hc2_flash_out(); ?>
	<div class="row">
		<div class="col-6 col-md-3 mb-3"><a class="text-decoration-none text-body d-block h-100" href="<?php echo $qs(array('state' => 'up')); ?>"><div class="card bg-light h-100" style="border-left:4px solid var(--success)"><div class="card-body p-2"><i class="fa-solid fa-circle-check fa-2xl float-right pt-4 text-success"></i><p class="lead m-0">OK</p><p class="card-text h3"><?php echo $counts['up']; ?></p></div></div></a></div>
		<div class="col-6 col-md-3 mb-3"><a class="text-decoration-none text-body d-block h-100" href="<?php echo $qs(array('state' => 'down')); ?>"><div class="card bg-light h-100" style="border-left:4px solid var(--danger)"><div class="card-body p-2"><i class="fa-solid fa-circle-xmark fa-2xl float-right pt-4 text-danger"></i><p class="lead m-0">Gestört</p><p class="card-text h3"><?php echo $counts['down']; ?></p></div></div></a></div>
		<div class="col-6 col-md-3 mb-3"><a class="text-decoration-none text-body d-block h-100" href="<?php echo $qs(array('state' => 'degraded')); ?>"><div class="card bg-light h-100" style="border-left:4px solid var(--warning)"><div class="card-body p-2"><i class="fa-solid fa-triangle-exclamation fa-2xl float-right pt-4 text-warning"></i><p class="lead m-0">Teilweise gestört</p><p class="card-text h3"><?php echo $counts['degraded']; ?></p></div></div></a></div>
		<div class="col-6 col-md-3 mb-3"><a class="text-decoration-none text-body d-block h-100" href="<?php echo $qs(array('state' => 'paused')); ?>"><div class="card bg-light h-100" style="border-left:4px solid var(--secondary)"><div class="card-body p-2"><i class="fa-solid fa-circle-pause fa-2xl float-right pt-4 text-secondary"></i><p class="lead m-0">Pausiert</p><p class="card-text h3"><?php echo $counts['paused']; ?></p></div></div></a></div>
	</div>
	<div class="card shadow-sm mb-3">
		<div class="card-body p-2 d-flex flex-wrap align-items-center" style="gap:.5rem">
			<span class="badge badge-<?php echo ($limit > 0 && $used >= $limit) ? 'danger' : 'success'; ?>" title="Online-Messstellen (Check × Standorte) gegen dein Limit">Online-Messstellen <?php echo $used; ?> / <?php echo $limit > 0 ? $limit : '∞'; ?></span>
			<?php $today = hc2_checks_today($uid); $perDay = $acc['checks_per_day']; ?>
			<span class="badge badge-<?php echo ($perDay > 0 && $today >= $perDay) ? 'danger' : 'light'; ?>" title="Online-Messungen und Pushes heute; ist das Tageskontingent erreicht, pausieren die Online-Checks bis Mitternacht (lokale Messungen der Nodes laufen weiter)">Heute <?php echo $today; ?> / <?php echo $perDay > 0 ? $perDay : '∞'; ?> Online-Messungen</span>
			<span class="badge badge-light"><?php echo hc2_h($acc['class_name']); ?> · bis zu <?php echo $acc['hc_locations']; ?> Standort(e) je Check</span>
			<span class="badge badge-light"><i class="fa-solid fa-cloud"></i> online <?php echo $counts['online']; ?> · <i class="fa-solid fa-house"></i> lokal <?php echo $counts['local']; ?> · hybrid <?php echo $counts['both']; ?></span>
			<a class="badge badge-light" href="/nodes.php" title="Zur Node-Übersicht"><i class="fa-solid fa-server"></i> Nodes: <?php $on = 0; foreach ($nodes as $n) { if ((int)$n['online']) { $on++; } } echo $on . ' online / ' . count($nodes); ?></a>
			<span class="ml-auto"><a class="btn btn-sm btn-primary" href="<?php echo HC2_BASE; ?>/edit.php"><i class="fa-solid fa-plus"></i> Neuer Check</a></span>
		</div>
	</div>
	<form method="get" class="form-inline mb-2" style="gap:.4rem" id="hc2-filter">
		<input class="form-control form-control-sm" type="search" name="q" value="<?php echo hc2_h($q); ?>" placeholder="Suche Name, Ziel, Tag">
		<select class="custom-select custom-select-sm" name="state"><option value="">Alle Zustände</option><?php foreach (hc2_states() as $k => $v) { if (empty($stateCounts[$k]) && $fState !== $k) { continue; } echo '<option value="' . $k . '"' . ($fState === $k ? ' selected' : '') . '>' . hc2_h($v[0]) . ' (' . (int)($stateCounts[$k] ?? 0) . ')</option>'; } ?></select>
		<select class="custom-select custom-select-sm" name="type"><option value="">Alle Typen</option><?php foreach (hc2_types() as $k => $v) { echo '<option value="' . $k . '"' . ($fType === $k ? ' selected' : '') . '>' . hc2_h($v) . '</option>'; } ?></select>
		<select class="custom-select custom-select-sm" name="exec"><option value="">Alle Ausführungsorte</option><option value="online"<?php echo $fExec === 'online' ? ' selected' : ''; ?>>Online (ipv64)</option><option value="local"<?php echo $fExec === 'local' ? ' selected' : ''; ?>>Lokal (Node)</option><option value="both"<?php echo $fExec === 'both' ? ' selected' : ''; ?>>Hybrid</option></select>
		<?php if ($nodes) { ?><select class="custom-select custom-select-sm" name="node"><option value="">Alle Nodes</option><?php foreach ($nodes as $id => $n) { echo '<option value="' . hc2_h($id) . '"' . ($fNode === $id ? ' selected' : '') . '>' . hc2_h(hc2_node_label($nodes, $id)) . '</option>'; } ?></select><?php } ?>
		<?php if ($allGroups) { ?><select class="custom-select custom-select-sm" name="group"><option value="">Alle Gruppen</option><?php foreach (array_keys($allGroups) as $g) { echo '<option value="' . hc2_h($g) . '"' . ($fGroup === $g ? ' selected' : '') . '>' . hc2_h($g) . '</option>'; } ?></select><?php } ?>
		<?php if ($allTags) { ?><select class="custom-select custom-select-sm" name="tag"><option value="">Alle Tags</option><?php foreach (array_keys($allTags) as $t) { echo '<option value="' . hc2_h($t) . '"' . ($fTag === $t ? ' selected' : '') . '>' . hc2_h($t) . '</option>'; } ?></select><?php } ?>
		<select class="custom-select custom-select-sm" name="sort"><?php foreach (array('name' => 'Name', 'state' => 'Zustand', 'changed' => 'Zuletzt geändert', 'latency' => 'Latenz', 'type' => 'Typ') as $k => $v) { echo '<option value="' . $k . '"' . ($sort === $k ? ' selected' : '') . '>Sortierung: ' . $v . '</option>'; } ?></select>
		<select class="custom-select custom-select-sm" name="dir" title="Richtung"><option value="">aufsteigend</option><option value="desc"<?php echo $desc ? ' selected' : ''; ?>>absteigend</option></select>
		<button class="btn btn-sm btn-outline-secondary" type="submit">Filtern</button>
		<?php if ($q !== '' || $fState !== '' || $fType !== '' || $fExec !== '' || $fNode !== '' || $fTag !== '' || $fGroup !== '') { ?><a class="btn btn-sm btn-link" href="<?php echo HC2_BASE; ?>/">Zurücksetzen</a><?php } ?>
	</form>
	<script id="hc2-filter-auto">/* Filter sofort anwenden; Suche bei Enter, beim Verlassen des Feldes oder beim Leeren */
	(function () { var f = document.getElementById('hc2-filter'); if (!f) { return; }
		var go = function () { Array.prototype.forEach.call(f.querySelectorAll('input[name], select[name]'), function (el) { if (!el.value) { el.disabled = true; } }); f.submit(); };
		Array.prototype.forEach.call(f.querySelectorAll('select'), function (s) { s.addEventListener('change', go); });
		var q = f.querySelector('input[name=q]'); if (q) { q.addEventListener('change', go); q.addEventListener('search', function () { if (!q.value) { go(); } }); }
	})();</script>
	<form method="post" id="bulk">
		<?php echo hc2_csrf_field(); ?>
		<div class="card shadow-sm">
			<div class="card-header p-2 d-flex flex-wrap align-items-center" style="gap:.4rem">
				<span><i class="fa-solid fa-heart-pulse"></i> Healthchecks <span class="badge badge-secondary"><?php echo count($list); ?></span></span>
				<span class="ml-auto small">Markierte:</span>
				<button class="btn btn-sm btn-outline-secondary" name="action" value="run" type="submit" title="Lokale und hybride Checks sofort auf ihren Nodes prüfen"><i class="fa-solid fa-rotate"></i> Jetzt prüfen</button>
				<button class="btn btn-sm btn-outline-secondary" name="action" value="pause" type="submit"><i class="fa-solid fa-pause"></i> Pausieren</button>
				<button class="btn btn-sm btn-outline-secondary" name="action" value="resume" type="submit"><i class="fa-solid fa-play"></i> Fortsetzen</button>
				<button class="btn btn-sm btn-outline-secondary" name="action" value="move" type="submit" title="Ausführungsort ändern (Online / Node / Hybrid) mit Testlauf"><i class="fa-solid fa-right-left"></i> Umhängen</button>
				<span class="input-group input-group-sm" style="width:auto"><input class="form-control" name="tag" placeholder="Tag" maxlength="40"><div class="input-group-append"><button class="btn btn-outline-secondary" name="action" value="tag" type="submit" title="Tag hinzufügen">+</button><button class="btn btn-outline-secondary" name="action" value="untag" type="submit" title="Tag entfernen">−</button></div></span>
				<button class="btn btn-sm btn-outline-danger" name="action" value="delete" type="submit" onclick="return confirm('Markierte Checks mit allen Messdaten löschen?');"><i class="fa-solid fa-trash"></i> Löschen</button>
			</div>
			<div class="table-responsive"><table class="table table-sm table-hover mb-0">
				<thead><tr><th style="width:1%"><input type="checkbox" onclick="document.querySelectorAll('#bulk input[name=\'tokens[]\']').forEach(function(c){c.checked=event.target.checked&&c.closest('tr').style.display!=='none'});"></th><th>Zustand</th><th>Name</th><th>Ziel</th><th>Typ</th><th class="text-right">Latenz</th><th>Letzte Messungen</th><th>Seit</th><th></th></tr></thead>
				<tbody>
				<?php if (!$list) { echo '<tr><td colspan="9" class="text-muted p-3">Keine Checks' . ($all ? ' für diesen Filter' : '') . '. <a href="' . HC2_BASE . '/edit.php">Ersten Check anlegen</a>' . ($nodes ? '' : ' oder eine <a href="/link.php">Node verknüpfen</a>') . '.</td></tr>'; } ?>
				<?php $lastGroup = null; $lastSub = null; $gKey = ''; $sKey = ''; $gn = 0; $sn = 0;
				$cnt = function(array $rows) use ($stateOf): string { $u = 0; $d = 0; $o = 0; foreach ($rows as $x) { $xs = $stateOf($x); if ($xs === 'up') { $u++; } elseif ($xs === 'down') { $d++; } else { $o++; } }
					return ($u ? '<span class="badge badge-success">' . $u . '</span> ' : '') . ($d ? '<span class="badge badge-danger">' . $d . '</span> ' : '') . ($o ? '<span class="badge badge-secondary">' . $o . '</span>' : ''); };
				foreach ($list as $c) { $s = $stateOf($c);
					if ($allGroups && $c['group_name'] !== $lastGroup) { $lastGroup = $c['group_name']; $lastSub = null; $sKey = ''; $gKey = 'g' . (++$gn);
						$gName = $lastGroup !== '' ? $lastGroup : 'Ohne Gruppe';
						echo '<tr class="table-light hc2-grp" data-grp="' . $gKey . '" data-name="' . hc2_h($gName) . '"><td colspan="9" class="py-1" style="cursor:pointer"><i class="fa-solid fa-chevron-down hc2-chev text-muted mr-1"></i><i class="fa-solid fa-layer-group text-primary"></i> <strong>' . hc2_h($gName) . '</strong> <span class="ml-2 small">' . $cnt(array_filter($list, function($x) use ($lastGroup) { return $x['group_name'] === $lastGroup; })) . '</span></td></tr>';
					}
					$sub = $allGroups ? $subOf($c) : '';
					if ($sub !== '' && $sub !== $lastSub) { $lastSub = $sub; $sKey = $gKey . 's' . (++$sn); $g0 = $lastGroup;
						echo '<tr class="hc2-sub" data-g="' . $gKey . '" data-grp="' . $sKey . '" data-parent="' . $gKey . '" data-name="' . hc2_h(($lastGroup !== '' ? $lastGroup : 'Ohne Gruppe') . ' / ' . $sub) . '"><td colspan="9" class="py-1 pl-4" style="cursor:pointer"><i class="fa-solid fa-chevron-down hc2-chev text-muted mr-1"></i><i class="fa-solid ' . ($c['type'] === 'docker' ? 'fa-box' : 'fa-server') . ' text-secondary"></i> <strong>' . hc2_h($sub) . '</strong> <span class="ml-2 small">' . $cnt(array_filter($list, function($x) use ($g0, $sub, $subOf) { return $x['group_name'] === $g0 && $subOf($x) === $sub; })) . '</span></td></tr>';
					} elseif ($sub === '') { $sKey = ''; }
				?>
				<tr<?php if ($gKey !== '') { echo ' data-g="' . $gKey . '"' . ($sKey !== '' ? ' data-s="' . $sKey . '"' : ''); } ?>>
					<td><input type="checkbox" name="tokens[]" value="<?php echo hc2_h($c['token']); ?>"></td>
					<td><?php echo hc2_state_badge($s); if ($c['last_reason'] && $s !== 'up' && $s !== 'paused') { echo '<br><small class="text-muted">' . hc2_h(hc2_reason_text($c['last_reason'])) . '</small>'; } ?></td>
					<td><a class="font-weight-bold" href="<?php echo HC2_BASE; ?>/check.php?token=<?php echo hc2_h($c['token']); ?>"><?php echo hc2_h($c['name']); ?></a>
						<?php echo hc2_exec_short($c, $nodes); if ((int)$c['critical']) { echo ' <span class="badge badge-danger" title="Kritisch">!</span>'; } foreach (explode(',', $c['tags']) as $t) { if ($t !== '') { echo ' <a class="badge badge-pill badge-secondary" href="' . $qs(array('tag' => $t)) . '">' . hc2_h($t) . '</a>'; } } ?>
					</td>
					<td style="max-width:320px"><?php echo hc2_target_badge($c); ?></td>
					<td><span class="badge badge-light"><?php echo hc2_h(hc2_types()[$c['type']] ?? $c['type']); ?></span></td>
					<td class="text-right text-nowrap"><?php echo (float)$c['last_latency_ms'] > 0 ? round((float)$c['last_latency_ms'], 1) . ' ms' : '–'; ?></td>
					<td class="barr2 text-nowrap"><?php echo $pills[$c['token']] ?? '<span class="text-muted small">noch keine Messungen</span>'; ?></td>
					<td class="small text-nowrap" title="<?php echo hc2_dt($c['state_since']); ?>"><?php echo hc2_ago($c['state_since']); ?></td>
					<td class="text-right text-nowrap">
						<?php if ($c['type'] !== 'push' && $c['execution'] !== 'online' && !(int)$c['paused']) { ?><button class="btn btn-sm btn-outline-secondary" type="submit" name="one" value="run:<?php echo hc2_h($c['token']); ?>" title="Jetzt prüfen"><i class="fa-solid fa-rotate"></i></button><?php } ?>
						<button class="btn btn-sm btn-outline-secondary" type="submit" name="one" value="<?php echo (int)$c['paused'] ? 'resume' : 'pause'; ?>:<?php echo hc2_h($c['token']); ?>" title="<?php echo (int)$c['paused'] ? 'Fortsetzen' : 'Pausieren'; ?>"><i class="fa-solid fa-<?php echo (int)$c['paused'] ? 'play' : 'pause'; ?>"></i></button>
						<a class="btn btn-sm btn-outline-secondary" href="<?php echo HC2_BASE; ?>/edit.php?token=<?php echo hc2_h($c['token']); ?>" title="Bearbeiten"><i class="fa-solid fa-pen"></i></a></td>
				</tr>
				<?php } ?>
				</tbody>
			</table></div>
		</div>
	</form>
	<p class="small text-muted mt-2">Pillen: letzte 30 Messungen aller Messstellen (Maus darüber zeigt Zeit, Messstelle, Grund). Pausierte Checks werden nicht gemessen.</p>
	<?php $node64_hint = "Healthchecks auch lokal in deinem Heimnetz – mit Statusseiten und Proxmox-VE-Überwachung: Node64."; include("../node64_hint.php"); ?>
</div>
<?php include("../footer.php"); ?>
<script>$(function(){ $('[data-toggle="tooltip"]').tooltip(); });
// Gruppen und Untergruppen auf-/zuklappen (Zustand im Browser gemerkt)
(function () {
	var key = 'hc2_closed', closed = {};
	try { closed = JSON.parse(localStorage.getItem(key) || '{}'); } catch (e) { closed = {}; }
	var heads = document.querySelectorAll('tr[data-grp]');
	function isClosed(k) { var h = document.querySelector('tr[data-grp="' + k + '"]'); return !!(h && h.classList.contains('hc2-closed')); }
	function apply() {
		document.querySelectorAll('tr[data-g]').forEach(function (tr) {
			var hide = isClosed(tr.getAttribute('data-g')) || (tr.hasAttribute('data-s') && isClosed(tr.getAttribute('data-s')));
			tr.style.display = hide ? 'none' : '';
			if (hide) { var cb = tr.querySelector('input[name="tokens[]"]'); if (cb) { cb.checked = false; } }
		});
		heads.forEach(function (h) { var i = h.querySelector('.hc2-chev'); if (i) { i.style.transform = h.classList.contains('hc2-closed') ? 'rotate(-90deg)' : ''; } });
	}
	heads.forEach(function (h) {
		var name = h.getAttribute('data-name');
		if (closed[name]) { h.classList.add('hc2-closed'); }
		h.addEventListener('click', function () {
			h.classList.toggle('hc2-closed');
			if (h.classList.contains('hc2-closed')) { closed[name] = 1; } else { delete closed[name]; }
			try { localStorage.setItem(key, JSON.stringify(closed)); } catch (e) {}
			apply();
		});
	});
	apply();
})();
</script>
