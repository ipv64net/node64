<?php
/**
 * Healthchecks 2.0 – Benachrichtigungskanäle, Ruhezeiten, Zustellprotokoll (ersetzt integrations.php für die neue Welt).
 * Bewusst ohne Menülink. Mail/SMS werden NACH dem Login per Code bestätigt (kein Link ohne Anmeldung).
 */
ob_start(); // header.php gibt HTML aus; hc2_redirect()/hc2_json() verwerfen es
include("header.php");
require_once(__DIR__ . '/healthchecks2/hc2_lib.php');
require_once(__DIR__ . '/honeypot/hp_release_lib.php'); // hpr_rl(): gleiche Toepfe wie rl_enforce() der API
hc2_require_login();
$uid = (int)$userid; $pdo = hc2_pdo(); $acc = hc2_account($uid); $types = hc2_channel_types(); $nodes = hc2_nodes($uid);
$errors = array();
$editId = (int)($_GET['edit'] ?? $_POST['id'] ?? 0);
$edit = $editId > 0 ? hc2_channel($uid, $editId, true) : null;
if ($edit && $edit['node_id']) { $errors[] = 'Kanäle einer Node werden in der Node bearbeitet.'; $edit = null; }

if (hc2_is_post() && hc2_csrf_ok()) {
	$a = (string)($_POST['action'] ?? ''); $id = (int)($_POST['id'] ?? 0);
	try {
		if ($a === 'save') {
			$type = $edit ? $edit['type'] : (string)($_POST['type'] ?? '');
			$name = mb_substr(trim((string)($_POST['name'] ?? '')), 0, 100);
			if ($name === '') { $errors[] = 'Name fehlt.'; }
			if (!isset($types[$type])) { $errors[] = 'Unbekannter Kanaltyp.'; }
			$cfg = $errors ? array('config_enc' => '{}', 'errors' => array()) : hc2_channel_config($type, $_POST, $edit);
			$errors = array_merge($errors, $cfg['errors']);
			if (!$errors) {
				$lang = ($_POST['lang'] ?? 'de') === 'en' ? 'en' : 'de';
				$p = array('u' => $uid, 'n' => $name, 'c' => $cfg['config_enc'], 'e' => !empty($_POST['enabled']) ? 1 : 0, 'd' => !empty($_POST['is_default']) ? 1 : 0, 'l' => $lang, 'nd' => !empty($_POST['notify_down']) ? 1 : 0, 'nu' => !empty($_POST['notify_up']) ? 1 : 0);
				$needsVerify = !empty($types[$type]['verify']);
				if ($edit) {
					$p['i'] = $edit['id'];
					$addrChanged = $needsVerify && $cfg['config_enc'] !== $edit['config_enc'];
					$pdo->prepare("UPDATE hc2_channels SET name = :n, config_enc = :c, enabled = :e, is_default = :d, lang = :l, notify_down = :nd, notify_up = :nu" . ($addrChanged ? ", verified = 0" : "") . " WHERE id = :i AND userid = :u AND deleted_at IS NULL")->execute($p);
					$id = (int)$edit['id'];
				} else {
					$p['t'] = $type; $p['v'] = $needsVerify ? 0 : 1;
					$pdo->prepare("INSERT INTO hc2_channels (userid, type, name, config_enc, enabled, is_default, lang, notify_down, notify_up, verified, created_at, updated_at) VALUES (:u, :t, :n, :c, :e, :d, :l, :nd, :nu, :v, UTC_TIMESTAMP(3), UTC_TIMESTAMP(3))")->execute($p);
					$id = (int)$pdo->lastInsertId();
				}
				hc2_log_change($uid, 'channel', (string)$id, 'upsert', 'portal');
				$ch = hc2_channel($uid, $id);
				if ($ch && !(int)$ch['verified']) { hc2_redirect('/notifications.php?verify=' . $id); }
				hc2_flash('success', 'Kanal gespeichert.'); hc2_redirect('/notifications.php');
			}
		}
		if (in_array($a, array('delete', 'toggle', 'default'), true) && $id > 0 && !hc2_channel($uid, $id)) { hc2_flash('danger', 'Kanal nicht gefunden.'); hc2_redirect('/notifications.php'); } // nur eigene Kanaele
		if ($a === 'delete' && $id > 0) {
			hc2_log_change($uid, 'channel', (string)$id, 'delete', 'portal');
			foreach (hc2_checks($uid) as $c) { $ids = hc2_check_channels($c); if (in_array($id, $ids, true)) { hc2_set_check($uid, $c['token'], array('channels' => implode(',', array_diff($ids, array($id))))); } }
			hc2_flash('success', 'Kanal gelöscht.'); hc2_redirect('/notifications.php');
		}
		if ($a === 'toggle' && $id > 0) {
			$pdo->prepare("UPDATE hc2_channels SET enabled = 1 - enabled WHERE id = :i AND userid = :u AND deleted_at IS NULL")->execute(array('i' => $id, 'u' => $uid));
			hc2_log_change($uid, 'channel', (string)$id, 'upsert', 'portal'); hc2_redirect('/notifications.php');
		}
		if ($a === 'default' && $id > 0) {
			$pdo->prepare("UPDATE hc2_channels SET is_default = 1 - is_default WHERE id = :i AND userid = :u AND deleted_at IS NULL")->execute(array('i' => $id, 'u' => $uid));
			hc2_log_change($uid, 'channel', (string)$id, 'upsert', 'portal'); hc2_redirect('/notifications.php');
		}
		if ($a === 'test' && $id > 0) {
			$ch = hc2_channel($uid, $id);
			if (!$ch) { hc2_flash('danger', 'Kanal nicht gefunden.'); }
			elseif (!(int)$ch['verified']) { hc2_redirect('/notifications.php?verify=' . $id); }
			else {
				$r = hc2_hub_call('/v1/portal/channel-test', array('userid' => $uid, 'channel_id' => $id, 'kind' => 'test', 'lang' => $ch['lang']));
				if (!empty($r['ok'])) { hc2_flash('success', !empty($r['queued']) ? 'Test an die Node übergeben; sie sendet selbst.' : 'Testnachricht gesendet.'); }
				else { hc2_flash('danger', 'Test fehlgeschlagen: ' . ($r['error'] ?? 'unbekannt')); }
			}
			hc2_redirect('/notifications.php');
		}
		if ($a === 'verify_send' && $id > 0) {
			$ch = hc2_channel($uid, $id);
			if ($ch && !(int)$ch['verified'] && !hpr_rl('hc2verify:' . $uid, 5, 5 / 3600)[0]) { hc2_flash('danger', 'Zu viele Codes angefordert. Bitte später erneut versuchen.'); }
			elseif ($ch && !(int)$ch['verified']) {
				$code = (string)random_int(100000, 999999);
				$pdo->prepare("UPDATE hc2_channels SET verify_key = :k, verify_expires = UTC_TIMESTAMP(3) + INTERVAL 15 MINUTE WHERE id = :i AND userid = :u")->execute(array('k' => $code, 'i' => $id, 'u' => $uid));
				$r = hc2_hub_call('/v1/portal/channel-test', array('userid' => $uid, 'channel_id' => $id, 'kind' => 'verify', 'code' => $code, 'lang' => $ch['lang']));
				if (!empty($r['ok'])) { hc2_flash('info', 'Code gesendet. Bitte innerhalb von 15 Minuten eingeben.'); } else { hc2_flash('danger', 'Code konnte nicht gesendet werden: ' . ($r['error'] ?? 'unbekannt')); }
			}
			hc2_redirect('/notifications.php?verify=' . $id);
		}
		if ($a === 'verify_check' && $id > 0) {
			if (!hpr_rl('hc2verifycheck:' . $uid, 10, 10 / 3600)[0]) { hc2_flash('danger', 'Zu viele Versuche. Bitte später erneut versuchen.'); hc2_redirect('/notifications.php?verify=' . $id); }
			$st = $pdo->prepare("SELECT verify_key, verify_expires FROM hc2_channels WHERE id = :i AND userid = :u AND deleted_at IS NULL"); $st->execute(array('i' => $id, 'u' => $uid)); $row = $st->fetch(PDO::FETCH_ASSOC);
			$code = preg_replace('/[^0-9]/', '', (string)($_POST['code'] ?? ''));
			if ($row && $row['verify_key'] && $code !== '' && hash_equals((string)$row['verify_key'], $code) && $row['verify_expires'] > gmdate('Y-m-d H:i:s')) {
				$pdo->prepare("UPDATE hc2_channels SET verified = 1, verify_key = NULL, verify_expires = NULL WHERE id = :i")->execute(array('i' => $id));
				hc2_log_change($uid, 'channel', (string)$id, 'upsert', 'portal');
				hc2_flash('success', 'Kanal bestätigt.'); hc2_redirect('/notifications.php');
			}
			hc2_flash('danger', 'Code falsch oder abgelaufen.'); hc2_redirect('/notifications.php?verify=' . $id);
		}
		if ($a === 'settings') {
			$q = array('notify.quiet_enabled' => !empty($_POST['quiet_enabled']) ? '1' : '0', 'notify.quiet_from' => preg_match('/^([01]\d|2[0-3]):[0-5]\d$/', (string)($_POST['quiet_from'] ?? '')) ? $_POST['quiet_from'] : '22:00',
				'notify.quiet_to' => preg_match('/^([01]\d|2[0-3]):[0-5]\d$/', (string)($_POST['quiet_to'] ?? '')) ? $_POST['quiet_to'] : '07:00', 'notify.quiet_days' => implode(',', array_filter(array_map('intval', (array)($_POST['quiet_days'] ?? array())), function($d) { return $d >= 1 && $d <= 7; })),
				'notify.quiet_tz' => in_array((string)($_POST['quiet_tz'] ?? ''), timezone_identifiers_list(), true) ? (string)$_POST['quiet_tz'] : 'Europe/Berlin', 'notify.rate_per_hour' => (string)max(0, min(1000, (int)($_POST['rate_per_hour'] ?? 60))), 'notify.batch_threshold' => (string)max(0, min(100, (int)($_POST['batch_threshold'] ?? 3))), 'notify.batch_window_seconds' => (string)max(0, min(600, (int)($_POST['batch_window'] ?? 10))));
			foreach ($q as $k => $v) { hc2_set_setting($uid, $k, $v); }
			hc2_log_change($uid, 'settings', 'notify', 'upsert', 'portal');
			hc2_flash('success', 'Einstellungen gespeichert.'); hc2_redirect('/notifications.php');
		}
	} catch (Throwable $e) { error_log('notifications: ' . $e->getMessage()); $errors[] = 'Aktion fehlgeschlagen.'; }
}
$channels = hc2_channels($uid); $settings = hc2_settings($uid);
$verify = isset($_GET['verify']) ? hc2_channel($uid, (int)$_GET['verify']) : null;
$st = $pdo->prepare("SELECT d.*, c.name cname FROM hc2_deliveries d LEFT JOIN hc2_channels c ON c.id = d.channel_id WHERE d.userid = :u ORDER BY d.id DESC LIMIT 40"); $st->execute(array('u' => $uid)); $deliveries = $st->fetchAll(PDO::FETCH_ASSOC);
$newType = (string)($_GET['new'] ?? $_POST['type'] ?? ''); if (!isset($types[$newType])) { $newType = ''; }
$formType = $edit ? $edit['type'] : $newType;
$fv = function(string $k) use ($edit) { return hc2_h($_POST['f_' . $k] ?? ($edit['config'][$k] ?? '')); };
?>
<p></p>
<div class="container">
	<?php echo hc2_subnav('notifications'); echo hc2_flash_out(); foreach ($errors as $e) { echo '<div class="alert alert-danger">' . hc2_h($e) . '</div>'; } ?>
	<?php if ($verify && !(int)$verify['verified']) { ?>
	<div class="card shadow-sm mb-3 border-warning"><div class="card-header p-2"><i class="fa-solid fa-shield-halved"></i> Kanal „<?php echo hc2_h($verify['name']); ?>“ bestätigen</div>
		<div class="card-body"><p class="small">An <code><?php echo hc2_h($verify['config']['email'] ?? $verify['config']['number'] ?? ''); ?></code> wird ein 6-stelliger Code geschickt. Erst nach der Bestätigung sendet ipv64.net über diesen Kanal.</p>
			<form method="post" class="form-inline" style="gap:.4rem"><?php echo hc2_csrf_field(); ?><input type="hidden" name="id" value="<?php echo (int)$verify['id']; ?>">
				<button class="btn btn-outline-primary" name="action" value="verify_send">Code senden</button>
				<input class="form-control" name="code" placeholder="Code" maxlength="6" inputmode="numeric" autocomplete="one-time-code"><button class="btn btn-primary" name="action" value="verify_check">Bestätigen</button>
				<a class="btn btn-link" href="/notifications.php">Später</a></form></div></div>
	<?php } ?>
	<div class="row">
		<div class="col-lg-7">
			<div class="card shadow-sm mb-3">
				<div class="card-header p-2 d-flex align-items-center"><span><i class="fa-solid fa-bell"></i> Kanäle</span>
					<div class="dropdown ml-auto"><button class="btn btn-sm btn-primary dropdown-toggle" data-toggle="dropdown"><i class="fa-solid fa-plus"></i> Neuer Kanal</button><div class="dropdown-menu dropdown-menu-right"><?php foreach ($types as $k => $t) { echo '<a class="dropdown-item" href="/notifications.php?new=' . $k . '"><i class="fa-solid ' . $t['icon'] . ' fa-fw"></i> ' . hc2_h($t['label']) . '</a>'; } ?></div></div></div>
				<div class="table-responsive"><table class="table table-sm mb-0">
					<thead><tr><th>Name</th><th>Typ</th><th>Status</th><th>Zuletzt</th><th></th></tr></thead><tbody>
					<?php if (!$channels) { echo '<tr><td colspan="5" class="text-muted p-3">Noch keine Kanäle. Ohne Kanal gehen keine Benachrichtigungen raus.</td></tr>'; } ?>
					<?php foreach ($channels as $ch) { $t = $types[$ch['type']] ?? array('label' => $ch['type'], 'icon' => 'fa-bell'); ?>
					<tr class="<?php echo (int)$ch['enabled'] ? '' : 'text-muted'; ?>"><td><?php echo hc2_h($ch['name']); echo (int)$ch['is_default'] ? ' <span class="badge badge-primary" title="Standardkanal: gilt für Checks ohne eigene Auswahl">Standard</span>' : ''; echo $ch['node_id'] ? ' <span class="badge badge-light" title="Kanal der Node; Versand durch die Node"><i class="fa-solid fa-house"></i> ' . hc2_h(hc2_node_label($nodes, $ch['node_id'])) . '</span>' : ''; ?><br><small class="text-muted"><?php $show = array(); foreach ($ch['config'] as $k => $v) { if ($v !== '' && !in_array($k, $ch['has_secret'], true) && in_array($k, array('email','number','chat_id','server','topic','url','host','to','username','device'), true)) { $show[] = $v; } } echo hc2_h(mb_substr(implode(' · ', $show), 0, 80)); ?></small></td>
						<td><i class="fa-solid <?php echo $t['icon']; ?>"></i> <?php echo hc2_h($t['label']); ?><?php echo $ch['lang'] === 'en' ? ' <small>(en)</small>' : ''; ?></td>
						<td><?php if (!(int)$ch['verified']) { echo '<a class="badge badge-warning" href="/notifications.php?verify=' . (int)$ch['id'] . '">nicht bestätigt</a>'; } elseif (!(int)$ch['enabled']) { echo '<span class="badge badge-secondary">aus</span>'; } else { echo '<span class="badge badge-success">aktiv</span>'; } echo $ch['last_error'] ? '<br><small class="text-danger" title="' . hc2_h($ch['last_error']) . '">' . hc2_h(mb_substr($ch['last_error'], 0, 50)) . '</small>' : ''; ?></td>
						<td class="small text-nowrap"><?php echo $ch['last_used'] ? hc2_ago($ch['last_used']) : '–'; ?></td>
						<td class="text-right text-nowrap"><form method="post" class="d-inline"><?php echo hc2_csrf_field(); ?><input type="hidden" name="id" value="<?php echo (int)$ch['id']; ?>">
							<button class="btn btn-sm btn-outline-secondary" name="action" value="test" title="Testnachricht"><i class="fa-solid fa-paper-plane"></i></button>
							<?php if (!$ch['node_id']) { ?><a class="btn btn-sm btn-outline-secondary" href="/notifications.php?edit=<?php echo (int)$ch['id']; ?>" title="Bearbeiten"><i class="fa-solid fa-pen"></i></a><?php } ?>
							<button class="btn btn-sm btn-outline-secondary" name="action" value="default" title="Standard umschalten"><i class="fa-solid fa-star"></i></button>
							<button class="btn btn-sm btn-outline-secondary" name="action" value="toggle" title="<?php echo (int)$ch['enabled'] ? 'Deaktivieren' : 'Aktivieren'; ?>"><i class="fa-solid <?php echo (int)$ch['enabled'] ? 'fa-toggle-on' : 'fa-toggle-off'; ?>"></i></button>
							<button class="btn btn-sm btn-outline-danger" name="action" value="delete" onclick="return confirm('Kanal löschen?');"><i class="fa-solid fa-trash"></i></button></form></td></tr>
					<?php } ?>
					</tbody></table></div>
			</div>
			<div class="card shadow-sm mb-3">
				<div class="card-header p-2"><i class="fa-solid fa-clipboard-list"></i> Zustellprotokoll</div>
				<div class="table-responsive"><table class="table table-sm mb-0"><thead><tr><th>Zeit</th><th>Kanal</th><th>Art</th><th>Ergebnis</th></tr></thead><tbody>
					<?php if (!$deliveries) { echo '<tr><td colspan="4" class="text-muted">Noch keine Zustellungen.</td></tr>'; } ?>
					<?php foreach ($deliveries as $d) { ?><tr><td class="small text-nowrap"><?php echo hc2_dt($d['time']); ?></td><td class="small"><?php echo hc2_h($d['cname'] ?? ('#' . $d['channel_id'])); ?></td><td class="small"><?php echo hc2_h($d['kind']); ?></td><td class="small"><?php echo $d['ok'] === null ? '…' : ((int)$d['ok'] ? '<span class="text-success">OK</span>' : '<span class="text-danger">' . hc2_h(mb_substr($d['error'], 0, 100)) . '</span>'); ?></td></tr><?php } ?>
					</tbody></table></div>
			</div>
		</div>
		<div class="col-lg-5">
			<?php if ($formType !== '') { $t = $types[$formType]; ?>
			<div class="card shadow-sm mb-3">
				<div class="card-header p-2"><i class="fa-solid <?php echo $t['icon']; ?>"></i> <?php echo $edit ? 'Kanal bearbeiten' : 'Neuer Kanal'; ?>: <?php echo hc2_h($t['label']); ?></div>
				<div class="card-body">
					<form method="post" autocomplete="off"><?php echo hc2_csrf_field(); ?><input type="hidden" name="action" value="save"><input type="hidden" name="type" value="<?php echo hc2_h($formType); ?>"><?php if ($edit) { echo '<input type="hidden" name="id" value="' . (int)$edit['id'] . '">'; } ?>
						<?php if (!empty($t['hint'])) { ?><div class="alert alert-info small py-2"><i class="fa-solid fa-circle-info"></i> <?php echo hc2_h($t['hint']); ?> <a href="https://node64.de/docs/notifications/#<?php echo hc2_h((string)$formType); ?>" target="_blank" rel="noopener">Anleitung</a></div><?php } ?>
						<div class="form-group"><label>Name</label><input class="form-control" name="name" value="<?php echo hc2_h($_POST['name'] ?? ($edit['name'] ?? $t['label'])); ?>" maxlength="100" required></div>
						<?php foreach ($t['fields'] as $f) { $k = $f['key']; $kind = $f['kind'] ?? 'text'; $isSecretSet = $edit && in_array($k, $edit['has_secret'], true); ?>
						<?php if ($kind === 'bool') { ?><div class="custom-control custom-checkbox mb-2"><input class="custom-control-input" type="checkbox" id="f_<?php echo $k; ?>" name="f_<?php echo $k; ?>" value="1"<?php echo !empty($_POST['f_' . $k]) || ($edit && ($edit['config'][$k] ?? '') === 'true') ? ' checked' : ''; ?>><label class="custom-control-label" for="f_<?php echo $k; ?>"><?php echo hc2_h($f['label']); ?></label></div>
						<?php } elseif ($kind === 'select') { ?><div class="form-group"><label><?php echo hc2_h($f['label']); ?></label><select class="custom-select" name="f_<?php echo $k; ?>"><?php $cur = $_POST['f_' . $k] ?? ($edit['config'][$k] ?? ($f['default'] ?? '')); foreach ($f['options'] as $o) { echo '<option value="' . hc2_h($o) . '"' . ((string)$cur === (string)$o ? ' selected' : '') . '>' . hc2_h($o) . '</option>'; } ?></select></div>
						<?php } elseif ($kind === 'textarea') { ?><div class="form-group"><label><?php echo hc2_h($f['label']); ?></label><textarea class="form-control" name="f_<?php echo $k; ?>" rows="3" placeholder="<?php echo $isSecretSet ? 'gespeichert – leer lassen zum Beibehalten' : ''; ?>"><?php echo $fv($k); ?></textarea></div>
						<?php } else { ?><div class="form-group"><label><?php echo hc2_h($f['label']); ?><?php echo !empty($f['required']) ? ' *' : ''; ?></label><input class="form-control" type="<?php echo $kind === 'password' ? 'password' : ($kind === 'number' ? 'number' : ($kind === 'email' ? 'email' : 'text')); ?>" name="f_<?php echo $k; ?>" value="<?php echo $kind === 'password' ? '' : ($fv($k) !== '' ? $fv($k) : hc2_h($f['default'] ?? '')); ?>" placeholder="<?php echo $isSecretSet ? 'gespeichert – leer lassen zum Beibehalten' : hc2_h($f['default'] ?? ''); ?>"<?php echo (!empty($f['required']) && !$isSecretSet) ? ' required' : ''; ?> autocomplete="new-password"></div>
						<?php } } ?>
						<div class="form-row">
							<div class="form-group col-6"><label>Sprache</label><select class="custom-select" name="lang"><option value="de"<?php echo (($_POST['lang'] ?? ($edit['lang'] ?? 'de')) === 'de') ? ' selected' : ''; ?>>Deutsch</option><option value="en"<?php echo (($_POST['lang'] ?? ($edit['lang'] ?? 'de')) === 'en') ? ' selected' : ''; ?>>English</option></select></div>
							<div class="form-group col-6 pt-4">
								<div class="custom-control custom-checkbox"><input class="custom-control-input" type="checkbox" id="enabled" name="enabled" value="1"<?php echo (!hc2_is_post() ? ($edit ? (int)$edit['enabled'] : 1) : !empty($_POST['enabled'])) ? ' checked' : ''; ?>><label class="custom-control-label" for="enabled">aktiv</label></div>
								<div class="custom-control custom-checkbox"><input class="custom-control-input" type="checkbox" id="is_default" name="is_default" value="1"<?php echo (!hc2_is_post() ? ($edit ? (int)$edit['is_default'] : 1) : !empty($_POST['is_default'])) ? ' checked' : ''; ?>><label class="custom-control-label" for="is_default">Standardkanal</label></div>
								<div class="custom-control custom-checkbox"><input class="custom-control-input" type="checkbox" id="notify_down" name="notify_down" value="1"<?php echo (!hc2_is_post() ? ($edit ? (int)$edit['notify_down'] : 1) : !empty($_POST['notify_down'])) ? ' checked' : ''; ?>><label class="custom-control-label" for="notify_down">bei Störung</label></div>
								<div class="custom-control custom-checkbox"><input class="custom-control-input" type="checkbox" id="notify_up" name="notify_up" value="1"<?php echo (!hc2_is_post() ? ($edit ? (int)$edit['notify_up'] : 1) : !empty($_POST['notify_up'])) ? ' checked' : ''; ?>><label class="custom-control-label" for="notify_up">bei Entwarnung</label></div>
							</div>
						</div>
						<?php if (!empty($t['verify'])) { echo '<p class="small text-muted">Nach dem Speichern wird ein Bestätigungscode geschickt.</p>'; } ?>
						<?php if ($formType === 'webhook') { echo '<p class="small text-muted">Body-Standard: JSON mit kind, title, text, check (name, token, type, target), status, reason, message, time, url.</p>'; } ?>
						<button class="btn btn-primary" type="submit">Speichern</button> <a class="btn btn-outline-secondary" href="/notifications.php">Abbrechen</a>
					</form>
				</div>
			</div>
			<?php } ?>
			<div class="card shadow-sm mb-3">
				<div class="card-header p-2"><i class="fa-solid fa-moon"></i> Ruhezeiten und Sammelmeldung</div>
				<div class="card-body">
					<form method="post"><?php echo hc2_csrf_field(); ?><input type="hidden" name="action" value="settings">
						<div class="custom-control custom-checkbox mb-2"><input class="custom-control-input" type="checkbox" id="quiet_enabled" name="quiet_enabled" value="1"<?php echo ($settings['notify.quiet_enabled'] ?? '0') === '1' ? ' checked' : ''; ?>><label class="custom-control-label" for="quiet_enabled">Ruhezeit aktiv (kritische Checks melden trotzdem)</label></div>
						<div class="form-group"><label>Zeitzone</label><select class="custom-select" name="quiet_tz"><?php $ctz = $settings['notify.quiet_tz'] ?? 'Europe/Berlin'; foreach (hc2_timezones() as $z) { echo '<option value="' . hc2_h($z) . '"' . ($z === $ctz ? ' selected' : '') . '>' . hc2_h($z) . '</option>'; } ?></select><small class="form-text text-muted">Gilt für alle Zeitangaben in Healthchecks 2.0, Wartungsfenster und Ruhezeiten. Standard: Europe/Berlin (UTC+1, Sommerzeit UTC+2).</small></div>
						<div class="form-row"><div class="form-group col-6"><label>von</label><input class="form-control" type="time" name="quiet_from" value="<?php echo hc2_h($settings['notify.quiet_from'] ?? '22:00'); ?>"></div><div class="form-group col-6"><label>bis</label><input class="form-control" type="time" name="quiet_to" value="<?php echo hc2_h($settings['notify.quiet_to'] ?? '07:00'); ?>"></div></div>
						<div class="form-group"><label>Tage</label><div><?php $qd = isset($settings['notify.quiet_days']) ? array_filter(explode(',', (string)$settings['notify.quiet_days'])) : array('1','2','3','4','5','6','7'); foreach (array(1 => 'Mo', 2 => 'Di', 3 => 'Mi', 4 => 'Do', 5 => 'Fr', 6 => 'Sa', 7 => 'So') as $d => $l) { echo '<div class="custom-control custom-checkbox custom-control-inline"><input class="custom-control-input" type="checkbox" id="qd' . $d . '" name="quiet_days[]" value="' . $d . '"' . (in_array((string)$d, $qd, true) ? ' checked' : '') . '><label class="custom-control-label" for="qd' . $d . '">' . $l . '</label></div>'; } ?></div></div>
						<div class="form-row"><div class="form-group col-4"><label>Sammeln ab</label><input class="form-control" type="number" name="batch_threshold" value="<?php echo hc2_h($settings['notify.batch_threshold'] ?? '3'); ?>" min="0" max="100"><small class="form-text text-muted">Störungen gleichzeitig</small></div><div class="form-group col-4"><label>Fenster (s)</label><input class="form-control" type="number" name="batch_window" value="<?php echo hc2_h($settings['notify.batch_window_seconds'] ?? '10'); ?>" min="0" max="600"></div><div class="form-group col-4"><label>Max./Stunde</label><input class="form-control" type="number" name="rate_per_hour" value="<?php echo hc2_h($settings['notify.rate_per_hour'] ?? '60'); ?>" min="0" max="1000"><small class="form-text text-muted">je Kanal, 0 = unbegrenzt</small></div></div>
						<button class="btn btn-primary" type="submit">Speichern</button>
						<small class="form-text text-muted mt-2">Gilt für den ganzen Account: Portal und alle verknüpften Nodes übernehmen diese Einstellungen. Was während der Ruhezeit passiert, kommt danach als eine Sammelmeldung.</small>
					</form>
				</div>
			</div>
			<div class="card shadow-sm mb-3"><div class="card-body small text-muted"><i class="fa-solid fa-circle-info"></i> SMS: <?php echo $acc['sms_limit'] > 0 ? $acc['sms_limit'] . ' pro Tag' : 'unbegrenzt'; ?> in deiner Klasse (<?php echo hc2_h($acc['class_name']); ?>). Kanäle einer Node (<i class="fa-solid fa-house"></i>) sendet die Node selbst; ipv64.net gibt ihr den Auftrag.</div></div>
		</div>
	</div>
</div>
<?php include("footer.php"); ?>
