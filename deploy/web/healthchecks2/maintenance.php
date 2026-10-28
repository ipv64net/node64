<?php
/** Healthchecks 2.0 – Wartungsfenster (keine Alarme, Messungen laufen weiter). */
ob_start(); // header.php gibt HTML aus; hc2_redirect()/hc2_json() verwerfen es
include("../header.php");
require_once(__DIR__ . '/hc2_lib.php');
hc2_require_login();
$uid = (int)$userid; $pdo = hc2_pdo();
$checks = hc2_checks($uid); $byToken = array(); foreach ($checks as $c) { $byToken[$c['token']] = $c['name']; }
$errors = array();
$toUTC = function(string $local): ?string { if ($local === '') { return null; } try { $t = new DateTime($local, new DateTimeZone(hc2_tz())); $t->setTimezone(new DateTimeZone('UTC')); return $t->format('Y-m-d H:i:s.000'); } catch (Throwable $e) { return null; } };
$toLocal = function(?string $utc): string { if (!$utc) { return ''; } return hc2_dt($utc, 'Y-m-d\TH:i'); };
if (hc2_is_post() && hc2_csrf_ok()) {
	$a = (string)($_POST['action'] ?? ''); $id = (int)($_POST['id'] ?? 0);
	try {
		if ($id > 0) { // nur eigene Wartungsfenster (loeschen, umschalten, bearbeiten)
			$st = $pdo->prepare("SELECT id FROM hc2_maintenance WHERE id = :i AND userid = :u AND deleted_at IS NULL"); $st->execute(array('i' => $id, 'u' => $uid));
			if (!$st->fetchColumn()) { hc2_flash('danger', 'Wartungsfenster nicht gefunden.'); hc2_redirect(HC2_BASE . '/maintenance.php'); }
		}
		if ($a === 'delete' && $id > 0) {
			hc2_log_change($uid, 'maintenance', (string)$id, 'delete', 'portal');
			hc2_flash('success', 'Wartungsfenster gelöscht.'); hc2_redirect(HC2_BASE . '/maintenance.php');
		}
		if ($a === 'toggle' && $id > 0) {
			$pdo->prepare("UPDATE hc2_maintenance SET active = 1 - active WHERE id = :i AND userid = :u AND deleted_at IS NULL")->execute(array('i' => $id, 'u' => $uid));
			hc2_log_change($uid, 'maintenance', (string)$id, 'upsert', 'portal');
			hc2_redirect(HC2_BASE . '/maintenance.php');
		}
		if ($a === 'save') {
			$name = mb_substr(trim((string)($_POST['name'] ?? '')), 0, 200);
			$start = $toUTC((string)($_POST['start_at'] ?? '')); $end = $toUTC((string)($_POST['end_at'] ?? ''));
			$repeat = (string)($_POST['repeat'] ?? 'none'); if (!in_array($repeat, array('none','daily','weekly','monthly'), true)) { $repeat = 'none'; }
			$until = $repeat === 'none' ? null : $toUTC((string)($_POST['repeat_until'] ?? ''));
			$tok = array(); foreach ((array)($_POST['tokens'] ?? array()) as $t) { if (isset($byToken[$t])) { $tok[] = $t; } }
			if ($name === '') { $errors[] = 'Name fehlt.'; }
			if (!$start || !$end) { $errors[] = 'Beginn und Ende angeben.'; } elseif ($end <= $start) { $errors[] = 'Ende muss nach dem Beginn liegen.'; }
			if (!$errors) {
				$p = array('u' => $uid, 'n' => $name, 's' => $start, 'e' => $end, 'r' => $repeat, 'ru' => $until, 't' => $tok ? implode(',', $tok) : null);
				if ($id > 0) {
					$p['i'] = $id;
					$pdo->prepare("UPDATE hc2_maintenance SET name = :n, start_at = :s, end_at = :e, `repeat` = :r, repeat_until = :ru, tokens = :t WHERE id = :i AND userid = :u AND deleted_at IS NULL")->execute($p);
				} else {
					$pdo->prepare("INSERT INTO hc2_maintenance (userid, name, start_at, end_at, `repeat`, repeat_until, tokens, active, created_at, updated_at) VALUES (:u, :n, :s, :e, :r, :ru, :t, 1, UTC_TIMESTAMP(3), UTC_TIMESTAMP(3))")->execute($p);
					$id = (int)$pdo->lastInsertId();
				}
				hc2_log_change($uid, 'maintenance', (string)$id, 'upsert', 'portal');
				hc2_flash('success', 'Wartungsfenster gespeichert.'); hc2_redirect(HC2_BASE . '/maintenance.php');
			}
		}
	} catch (Throwable $e) { error_log('hc2 maintenance: ' . $e->getMessage()); $errors[] = 'Speichern fehlgeschlagen.'; }
}
$edit = null;
if (isset($_GET['edit'])) { $st = $pdo->prepare("SELECT * FROM hc2_maintenance WHERE id = :i AND userid = :u AND deleted_at IS NULL"); $st->execute(array('i' => (int)$_GET['edit'], 'u' => $uid)); $edit = $st->fetch(PDO::FETCH_ASSOC) ?: null; }
$st = $pdo->prepare("SELECT * FROM hc2_maintenance WHERE userid = :u AND deleted_at IS NULL ORDER BY start_at DESC"); $st->execute(array('u' => $uid)); $list = $st->fetchAll(PDO::FETCH_ASSOC);
$f = array('name' => '', 'start_at' => '', 'end_at' => '', 'repeat' => 'none', 'repeat_until' => '', 'tokens' => array());
if ($edit) { $f = array('name' => $edit['name'], 'start_at' => $toLocal($edit['start_at']), 'end_at' => $toLocal($edit['end_at']), 'repeat' => $edit['repeat'], 'repeat_until' => $toLocal($edit['repeat_until']), 'tokens' => array_filter(explode(',', (string)$edit['tokens']))); }
if (hc2_is_post() && $errors) { foreach (array('name','start_at','end_at','repeat','repeat_until') as $k) { $f[$k] = (string)($_POST[$k] ?? ''); } $f['tokens'] = (array)($_POST['tokens'] ?? array()); }
$now = gmdate('Y-m-d H:i:s');
?>
<p></p>
<div class="container">
	<?php echo hc2_subnav('maintenance'); echo hc2_flash_out(); foreach ($errors as $e) { echo '<div class="alert alert-danger">' . hc2_h($e) . '</div>'; } ?>
	<div class="row">
		<div class="col-lg-7">
			<div class="card shadow-sm mb-3">
				<div class="card-header p-2"><i class="fa-solid fa-wrench"></i> Wartungsfenster</div>
				<div class="table-responsive"><table class="table table-sm mb-0">
					<thead><tr><th>Name</th><th>Zeitraum</th><th>Wiederholung</th><th>Checks</th><th></th></tr></thead><tbody>
					<?php if (!$list) { echo '<tr><td colspan="5" class="text-muted">Keine Wartungsfenster. Während eines Fensters werden keine Alarme verschickt; die Messungen laufen weiter.</td></tr>'; } ?>
					<?php foreach ($list as $m) { $active = (int)$m['active'] === 1; $running = $active && $m['start_at'] <= $now && $m['end_at'] >= $now; ?>
					<tr class="<?php echo $active ? '' : 'text-muted'; ?>"><td><?php echo hc2_h($m['name']); echo $running ? ' <span class="badge badge-warning">läuft</span>' : ''; echo $active ? '' : ' <span class="badge badge-secondary">aus</span>'; ?></td>
						<td class="small text-nowrap"><?php echo hc2_dt($m['start_at'], 'd.m.Y H:i'); ?> – <?php echo hc2_dt($m['end_at'], 'd.m.Y H:i'); ?></td>
						<td class="small"><?php echo array('none' => 'einmalig', 'daily' => 'täglich', 'weekly' => 'wöchentlich', 'monthly' => 'monatlich')[$m['repeat']] ?? $m['repeat']; echo $m['repeat_until'] ? ' bis ' . hc2_dt($m['repeat_until'], 'd.m.Y') : ''; ?></td>
						<td class="small"><?php $tk = array_filter(explode(',', (string)$m['tokens'])); echo $tk ? count($tk) . ' Check(s)' : 'alle'; ?></td>
						<td class="text-right text-nowrap"><a class="btn btn-sm btn-outline-secondary" href="?edit=<?php echo (int)$m['id']; ?>"><i class="fa-solid fa-pen"></i></a>
							<form method="post" class="d-inline"><?php echo hc2_csrf_field(); ?><input type="hidden" name="id" value="<?php echo (int)$m['id']; ?>"><button class="btn btn-sm btn-outline-secondary" name="action" value="toggle" title="<?php echo $active ? 'Deaktivieren' : 'Aktivieren'; ?>"><i class="fa-solid <?php echo $active ? 'fa-toggle-on' : 'fa-toggle-off'; ?>"></i></button> <button class="btn btn-sm btn-outline-danger" name="action" value="delete" onclick="return confirm('Wartungsfenster löschen?');"><i class="fa-solid fa-trash"></i></button></form></td></tr>
					<?php } ?>
					</tbody></table></div>
			</div>
		</div>
		<div class="col-lg-5">
			<div class="card shadow-sm mb-3">
				<div class="card-header p-2"><i class="fa-solid fa-plus"></i> <?php echo $edit ? 'Wartungsfenster bearbeiten' : 'Neues Wartungsfenster'; ?></div>
				<div class="card-body">
					<form method="post"><?php echo hc2_csrf_field(); ?><input type="hidden" name="action" value="save"><?php if ($edit) { echo '<input type="hidden" name="id" value="' . (int)$edit['id'] . '">'; } ?>
						<div class="form-group"><label>Name</label><input class="form-control" name="name" value="<?php echo hc2_h($f['name']); ?>" required maxlength="200"></div>
						<div class="form-row"><div class="form-group col-6"><label>Beginn</label><input class="form-control" type="datetime-local" name="start_at" value="<?php echo hc2_h($f['start_at']); ?>" required></div><div class="form-group col-6"><label>Ende</label><input class="form-control" type="datetime-local" name="end_at" value="<?php echo hc2_h($f['end_at']); ?>" required></div></div>
						<div class="form-row"><div class="form-group col-6"><label>Wiederholung</label><select class="custom-select" name="repeat"><?php foreach (array('none' => 'einmalig', 'daily' => 'täglich', 'weekly' => 'wöchentlich', 'monthly' => 'monatlich') as $k => $v) { echo '<option value="' . $k . '"' . ($f['repeat'] === $k ? ' selected' : '') . '>' . $v . '</option>'; } ?></select></div><div class="form-group col-6"><label>Wiederholen bis (optional)</label><input class="form-control" type="datetime-local" name="repeat_until" value="<?php echo hc2_h($f['repeat_until']); ?>"></div></div>
						<div class="form-group"><label>Checks (keine Auswahl = alle)</label><div style="max-height:220px;overflow:auto;border:1px solid #dee2e6;border-radius:.25rem;padding:.4rem">
							<?php foreach ($checks as $c) { echo '<div class="custom-control custom-checkbox"><input class="custom-control-input" type="checkbox" id="t_' . hc2_h($c['token']) . '" name="tokens[]" value="' . hc2_h($c['token']) . '"' . (in_array($c['token'], (array)$f['tokens'], true) ? ' checked' : '') . '><label class="custom-control-label" for="t_' . hc2_h($c['token']) . '">' . hc2_h($c['name']) . '</label></div>'; } ?>
						</div><small class="form-text text-muted">Zeiten in <?php echo hc2_h(hc2_tz()); ?> (änderbar unter Benachrichtigungen).</small></div>
						<button class="btn btn-primary" type="submit">Speichern</button> <?php if ($edit) { echo '<a class="btn btn-outline-secondary" href="' . HC2_BASE . '/maintenance.php">Abbrechen</a>'; } ?>
					</form>
				</div>
			</div>
		</div>
	</div>
</div>
<?php include("../footer.php"); ?>
