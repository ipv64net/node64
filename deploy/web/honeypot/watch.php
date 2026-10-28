<?php
/**
 * Honeypot64 – Fruehwarnung fuer eigene Netze (Phase H5), nur fuer Eingeloggte, ohne Menuelink.
 *
 *   watch.php            Netze anzeigen, eintragen, loeschen; DynDNS-IPs (automatisch); letzte Treffer
 *   &lang=en             Englisch
 *
 * POST action=add (cidr, label) und action=delete (id), beide mit CSRF-Token aus der Sitzung. Dieselbe Logik wie
 * die API (GET/POST/DELETE /threat/watch, GET /threat/watch/alerts): hp_limits_lib.php. Treffer erzeugt der Cron
 * bots/honeypot_watch.php alle 30 Minuten. Planung: docs/PLAN-NODE64-HONEYPOT64.md (Abschnitt 11).
 */
include("../header.php");
require_once __DIR__ . '/hp_limits_lib.php';

$hpvEn = (($_GET['lang'] ?? ($_POST['lang'] ?? '')) === 'en');
function hpv_t(string $de, string $en): string { global $hpvEn; return $hpvEn ? $en : $de; }
function hpv_h($s): string { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
/** ISO (Z) -> Ortszeit der Seite */
function hpv_time($iso): string { global $hpvEn; return ($iso === null OR $iso === '') ? '–' : date($hpvEn ? 'Y-m-d H:i' : 'd.m.Y H:i', (int)strtotime($iso)); }
function hpv_alert(string $type, string $html): string { return '<div class="alert alert-' . $type . '" role="alert">' . $html . '</div>'; }
function hpv_url(array $q = array()): string { global $hpvEn; if($hpvEn) { $q['lang'] = 'en'; } return 'watch.php' . ($q ? '?' . http_build_query($q) : ''); }

$hpvUid = (isset($userid) AND (string)$userid !== '' AND (string)$userid !== '0') ? (int)$userid : 0;
echo '<p></p><div class="container">';
if($hpvUid === 0) {
	echo hpv_alert('info', hpv_t('Bitte zuerst anmelden.', 'Please log in first.')) . '</div>';
	include("../footer.php");
	exit;
}
if(empty($_SESSION['hpr_csrf'])) { $_SESSION['hpr_csrf'] = bin2hex(random_bytes(16)); }
$hpvCsrf = (string)$_SESSION['hpr_csrf'];
$msg = ''; $form = array('cidr' => '', 'label' => '');

try {
	$class = hpl_class($pdo, $hpvUid);
	$lim = hpl_limits($class);
	if(($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
		$act = (string)($_POST['action'] ?? '');
		if(!hash_equals($hpvCsrf, (string)($_POST['csrf'] ?? ''))) {
			$msg = hpv_alert('danger', hpv_t('Die Sitzung ist abgelaufen. Bitte lade die Seite neu und versuche es noch einmal.', 'Your session has expired. Please reload the page and try again.'));
		} elseif($act === 'add') {
			$form = array('cidr' => trim((string)($_POST['cidr'] ?? '')), 'label' => (string)($_POST['label'] ?? ''));
			[$err, $net] = hpl_net_add($pdo, $hpvUid, $class, mb_substr($form['cidr'], 0, 64), $form['label']);
			if($err === null) {
				add_log($pdo, $userid, "0", "Honeypot64", "Fruehwarnung: Netz " . $net['cidr'] . " eingetragen.");
				$msg = hpv_alert('success', hpv_t('Netz <code>' . hpv_h($net['cidr']) . '</code> eingetragen. Treffer kommen mit der nächsten Prüfung (alle 30 Minuten).',
					'Network <code>' . hpv_h($net['cidr']) . '</code> added. Hits arrive with the next check (every 30 minutes).'));
				$form = array('cidr' => '', 'label' => '');
			} else {
				$txt = array(
					'invalid_cidr' => hpv_t('Bitte ein Netz in CIDR-Form (z. B. 203.0.113.0/24) oder eine einzelne IP-Adresse angeben.', 'Please enter a network in CIDR form (e.g. 203.0.113.0/24) or a single IP address.'),
					'prefix_too_large' => hpv_t("Netze dürfen höchstens /{$lim['min_prefix_v4']} (IPv4) bzw. /{$lim['min_prefix_v6']} (IPv6) groß sein.", "Networks may be at most /{$lim['min_prefix_v4']} (IPv4) or /{$lim['min_prefix_v6']} (IPv6)."),
					'not_public' => hpv_t('Private, reservierte und besondere Netze lassen sich nicht überwachen.', 'Private, reserved and special networks cannot be watched.'),
					'duplicate' => hpv_t('Dieses Netz steht schon in deiner Liste.', 'This network is already on your list.'),
					'limit_reached' => hpv_t("Mit deiner Klasse sind höchstens {$lim['max']} Netze möglich.", "Your plan allows at most {$lim['max']} networks."),
				);
				$msg = hpv_alert('danger', hpv_h($txt[$err] ?? $err));
			}
		} elseif($act === 'delete') {
			$id = (int)($_POST['id'] ?? 0);
			if($id > 0 AND hpl_net_delete($pdo, $hpvUid, $id)) {
				add_log($pdo, $userid, "0", "Honeypot64", "Fruehwarnung: Netz #" . $id . " geloescht.");
				$msg = hpv_alert('warning', hpv_t('Netz gelöscht. Frühere Treffer bleiben in der Liste unten.', 'Network deleted. Earlier hits stay in the list below.'));
			} else {
				$msg = hpv_alert('danger', hpv_t('Netz nicht gefunden.', 'Network not found.'));
			}
		}
	}
	$nets = hpl_nets($pdo, $hpvUid);
	$dyn = hpl_dyndns($pdo, $hpvUid);
	$alerts = array_map('hpl_alert_out', hpr_all($pdo, "SELECT * FROM hp_watch_alerts WHERE userid = :u ORDER BY created_at DESC, id DESC LIMIT 50", array('u' => $hpvUid)));
} catch(Throwable $e) {
	error_log('honeypot/watch.php: ' . $e->getMessage());
	echo hpv_alert('danger', hpv_t('Die Frühwarnung ist gerade nicht verfügbar. Bitte versuche es später noch einmal.', 'The early warning is currently unavailable. Please try again later.')) . '</div>';
	include("../footer.php");
	exit;
}
?>
	<div class="card mb-3"><div class="card-body">
		<h4 class="mb-2"><i class="fa-solid fa-tower-broadcast text-primary"></i> <?php echo hpv_t('Honeypot64 – Frühwarnung für eigene Netze', 'Honeypot64 – early warning for your networks'); ?></h4>
		<p class="mb-2"><?php echo hpv_t('Trage deine öffentlichen Netze ein. Fällt eine Adresse daraus bei den Honeypot64-Sensoren als Angreifer auf, bekommst du eine Mail – meist steckt ein befallenes Gerät dahinter (Kamera, Router, NAS, alter PC). Deine <b>DynDNS-Adressen</b> bei IPv64.net werden automatisch überwacht.',
			'Enter your public networks. If an address from them attracts attention as an attacker at the Honeypot64 sensors, you get an e-mail – usually an infected device is behind it (camera, router, NAS, old PC). Your <b>DynDNS addresses</b> at IPv64.net are watched automatically.'); ?></p>
		<p class="mb-2 small text-muted"><?php echo hpv_t('Für eingetragene Netze ohne Nachweis und für DynDNS-Adressen gibt es nur Treffer für Adressen, die auf der v64 Blocklist stehen (die ist ohnehin öffentlich). Mit Nachweis (z. B. RIR-Eintrag, auf Anfrage über den Support) meldet schon jede Sichtung. Geprüft wird alle 30 Minuten nach der Bewertung; dieselbe Adresse höchstens einmal am Tag, außer sie kommt neu auf die Liste.',
			'For networks without proof and for DynDNS addresses there are only hits for addresses on the v64 blocklist (which is public anyway). With proof (e.g. RIR entry, on request via support) every sighting is reported. Checked every 30 minutes after the evaluation; the same address at most once a day unless it is newly listed.'); ?></p>
		<p class="mb-0 small"><a href="watch.php"<?php echo $hpvEn ? '' : ' class="font-weight-bold"'; ?>>Deutsch</a> · <a href="watch.php?lang=en"<?php echo $hpvEn ? ' class="font-weight-bold"' : ''; ?>>English</a></p>
	</div></div>

	<?php echo $msg; ?>

	<div class="card mb-3"><div class="card-header p-2"><i class="fa-solid fa-network-wired text-primary"></i> <?php echo hpv_t('Deine Netze', 'Your networks'); ?>
		<small class="text-muted">(<?php echo count($nets) . ' / ' . (int)$lim['max'] . hpv_t(', IPv4 bis /', ', IPv4 up to /') . (int)$lim['min_prefix_v4'] . hpv_t(', IPv6 bis /', ', IPv6 up to /') . (int)$lim['min_prefix_v6']; ?>)</small></div>
	<div class="card-body p-2">
		<?php if($nets) { ?>
		<div class="table-responsive"><table class="table table-sm mb-2 small"><thead><tr>
			<th><?php echo hpv_t('Netz', 'Network'); ?></th><th><?php echo hpv_t('Bezeichnung', 'Label'); ?></th><th><?php echo hpv_t('Nachweis', 'Proof'); ?></th><th><?php echo hpv_t('Eingetragen', 'Added'); ?></th><th></th>
		</tr></thead><tbody>
		<?php foreach($nets as $n) { ?>
			<tr><td><code><?php echo hpv_h($n['cidr']); ?></code></td><td><?php echo hpv_h($n['label']); ?></td>
			<td><?php echo $n['verified'] ? '<span class="badge badge-success">' . hpv_t('ja – jede Sichtung', 'yes – every sighting') . '</span>' : '<span class="badge badge-secondary">' . hpv_t('nein – nur gelistete', 'no – listed only') . '</span>'; ?></td>
			<td><?php echo hpv_h(hpv_time($n['created_at'])); ?></td>
			<td class="text-right"><form method="post" action="<?php echo hpv_h(hpv_url()); ?>" class="d-inline" onsubmit="return confirm('<?php echo hpv_t('Netz löschen?', 'Delete network?'); ?>')">
				<input type="hidden" name="csrf" value="<?php echo hpv_h($hpvCsrf); ?>"><input type="hidden" name="action" value="delete"><input type="hidden" name="id" value="<?php echo (int)$n['id']; ?>">
				<?php if($hpvEn) { echo '<input type="hidden" name="lang" value="en">'; } ?>
				<button class="btn btn-sm btn-outline-danger" title="<?php echo hpv_t('Löschen', 'Delete'); ?>"><i class="fa-solid fa-trash"></i></button></form></td></tr>
		<?php } ?>
		</tbody></table></div>
		<?php } else { ?>
		<p class="small mb-2"><?php echo hpv_t('Noch keine Netze eingetragen.', 'No networks yet.'); ?></p>
		<?php } ?>
		<?php if(count($nets) < (int)$lim['max']) { ?>
		<form method="post" action="<?php echo hpv_h(hpv_url()); ?>" class="form-inline">
			<input type="hidden" name="csrf" value="<?php echo hpv_h($hpvCsrf); ?>"><input type="hidden" name="action" value="add">
			<?php if($hpvEn) { echo '<input type="hidden" name="lang" value="en">'; } ?>
			<input type="text" name="cidr" class="form-control form-control-sm mr-2 mb-1" maxlength="64" required placeholder="<?php echo hpv_t('z. B. 203.0.113.0/24', 'e.g. 203.0.113.0/24'); ?>" value="<?php echo hpv_h($form['cidr']); ?>" autocomplete="off" spellcheck="false">
			<input type="text" name="label" class="form-control form-control-sm mr-2 mb-1" maxlength="<?php echo HPL_LABEL_MAX; ?>" placeholder="<?php echo hpv_t('Bezeichnung (optional)', 'Label (optional)'); ?>" value="<?php echo hpv_h($form['label']); ?>">
			<button type="submit" class="btn btn-sm btn-primary mb-1"><i class="fa-solid fa-plus"></i> <?php echo hpv_t('Eintragen', 'Add'); ?></button>
		</form>
		<?php } else { ?>
		<p class="small text-muted mb-0"><?php echo hpv_t('Das Limit deiner Klasse ist erreicht.', 'The limit of your plan is reached.'); ?> <a href="/pricing"><?php echo hpv_t('Preise', 'Pricing'); ?></a></p>
		<?php } ?>
	</div></div>

	<div class="card mb-3"><div class="card-header p-2"><i class="fa-solid fa-house-signal text-primary"></i> <?php echo hpv_t('DynDNS-Adressen (automatisch)', 'DynDNS addresses (automatic)'); ?></div>
	<div class="card-body p-2">
		<?php if($dyn) { ?>
		<div class="table-responsive"><table class="table table-sm mb-0 small"><tbody>
		<?php foreach($dyn as $d) { ?><tr><td style="width:18em"><code><?php echo hpv_h($d['ip']); ?></code></td><td><?php echo hpv_h($d['domain']); ?></td></tr><?php } ?>
		</tbody></table></div>
		<?php } else { ?>
		<p class="small mb-0"><?php echo hpv_t('Keine öffentlichen A/AAAA-Einträge in deinen Domains.', 'No public A/AAAA records in your domains.'); ?></p>
		<?php } ?>
	</div></div>

	<div class="card mb-3"><div class="card-header p-2"><i class="fa-solid fa-triangle-exclamation text-primary"></i> <?php echo hpv_t('Letzte Treffer', 'Latest hits'); ?> <small class="text-muted"><?php echo hpv_t('(90 Tage, höchstens 50)', '(90 days, at most 50)'); ?></small></div>
	<div class="card-body p-2">
		<?php if($alerts) { ?>
		<div class="table-responsive"><table class="table table-sm mb-0 small"><thead><tr>
			<th><?php echo hpv_t('Zeit', 'Time'); ?></th><th>IP</th><th><?php echo hpv_t('Quelle', 'Source'); ?></th><th><?php echo hpv_t('Status', 'Status'); ?></th><th><?php echo hpv_t('Arten und Details', 'Kinds and details'); ?></th><th><?php echo hpv_t('Gesehen', 'Seen'); ?></th>
		</tr></thead><tbody>
		<?php foreach($alerts as $a) { ?>
			<tr><td><?php echo hpv_h(hpv_time($a['created_at'])); ?></td>
			<td><a href="ip.php?<?php echo hpv_h(http_build_query($hpvEn ? array('ip' => $a['ip'], 'lang' => 'en') : array('ip' => $a['ip']))); ?>"><code><?php echo hpv_h($a['ip']); ?></code></a></td>
			<td><?php echo $a['source'] === 'dyndns' ? 'DynDNS ' . hpv_h($a['label']) : '<code>' . hpv_h($a['cidr']) . '</code> ' . hpv_h($a['label']); ?></td>
			<td><?php echo $a['listed'] ? '<span class="badge badge-danger">' . hpv_t('gelistet', 'listed') . '</span>' : '<span class="badge badge-warning">' . hpv_t('gesehen', 'seen') . '</span>'; ?> <small class="text-muted"><?php echo (int)$a['score']; ?>/100</small></td>
			<td><?php echo hpv_h(implode(', ', $a['kinds'])); if(($why = hpl_details_text($a['details'], $hpvEn)) !== '') { echo '<div class="text-muted">' . hpv_h($why) . '</div>'; } ?></td>
			<td><?php echo hpv_h($a['first_seen'] . ($a['last_seen'] !== $a['first_seen'] ? ' – ' . $a['last_seen'] : '')); ?></td></tr>
		<?php } ?>
		</tbody></table></div>
		<?php } else { ?>
		<p class="small mb-0"><?php echo hpv_t('Bisher keine Treffer – gut so.', 'No hits so far – good.'); ?></p>
		<?php } ?>
	</div></div>

	<div class="card mb-3"><div class="card-body small">
		<p class="mb-2"><b><?php echo hpv_t('Auch in Node64:', 'Also in Node64:'); ?></b> <?php echo hpv_t('Im Modul Honeypot64 von <a href="https://node64.de/docs/honeypot/" target="_blank" rel="noopener">Node64</a> verwaltest du dieselben Netze und bekommst die Treffer als Benachrichtigung der Node.',
			'In the Honeypot64 module of <a href="https://node64.de/docs/honeypot/" target="_blank" rel="noopener">Node64</a> you manage the same networks and get the hits as notifications of the node.'); ?></p>
		<p class="mb-0"><?php echo hpv_t('Für Programme: <code>GET/POST https://ipv64.net/api/v2/threat/watch</code>, <code>DELETE …/threat/watch/&lt;id&gt;</code>, <code>GET …/threat/watch/alerts?since=&lt;Zeit&gt;</code> mit deinem API-Key.',
			'For programs: <code>GET/POST https://ipv64.net/api/v2/threat/watch</code>, <code>DELETE …/threat/watch/&lt;id&gt;</code>, <code>GET …/threat/watch/alerts?since=&lt;time&gt;</code> with your API key.'); ?></p>
	</div></div>
</div>
<?php include("../footer.php"); ?>
