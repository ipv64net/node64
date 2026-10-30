<?php
/**
 * Honeypot64 – IP-Auskunft "Warum ist diese IP gelistet?" mit Freigabe-Antrag (Phase H3). Oeffentlich, ohne Menuelink.
 *
 *   ip.php?ip=<adresse>                  Auskunft (Drossel je Client-IP bzw. Account, gemeinsam mit GET /threat/ip/{ip})
 *   ip.php?request=<token>               Status eines Antrags (Link auf der Seite und in den Mails)
 *   ip.php?request=<token>&confirm=<t>   Bestaetigung eines anonymen Antrags: zeigt einen Knopf (POST), damit
 *                                        Link-Scanner in Mailprogrammen nichts bestaetigen
 *   &lang=en                             Englisch
 *
 * POST action=request (Antrag) und action=confirm (Bestaetigung), beide mit CSRF-Token aus der Sitzung. Antraege nur
 * fuer gelistete IPs; Drossel ohne Captcha: hoechstens HPR_MAX_PER_DAY je Absender-IP und je E-Mail/Account in 24 h.
 * Logik und Datenschutz der Auskunft: hp_release_lib.php. Planung: docs/PLAN-NODE64-HONEYPOT64.md (Abschnitte 7, 9).
 */
include("../header.php");
echo '<link rel="stylesheet" href="flags.css?v=1">'; // Flaggen auch unter Windows
require_once __DIR__ . '/hp_release_lib.php';

$hpiEn = (($_GET['lang'] ?? ($_POST['lang'] ?? '')) === 'en');
function hpi_t(string $de, string $en): string { global $hpiEn; return $hpiEn ? $en : $de; }
function hpi_h($s): string { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
/** UTC aus der DB -> Ortszeit der Seite */
function hpi_time($utc): string { global $hpiEn; return ($utc === null OR $utc === '') ? '–' : date($hpiEn ? 'Y-m-d H:i' : 'd.m.Y H:i', (int)strtotime($utc . ' UTC')); }
/** ISO (Z) bzw. Tag -> Anzeige */
function hpi_iso($iso, bool $day = false): string { global $hpiEn; if($iso === null) { return '–'; } $t = (int)strtotime($iso); return $day ? gmdate($hpiEn ? 'Y-m-d' : 'd.m.Y', $t) : date($hpiEn ? 'Y-m-d H:i' : 'd.m.Y H:i', $t); }
function hpi_url(array $q): string { global $hpiEn; if($hpiEn) { $q['lang'] = 'en'; } return 'ip.php?' . http_build_query($q); }
function hpi_alert(string $type, string $html): string { return '<div class="alert alert-' . $type . '" role="alert">' . $html . '</div>'; }
/** Drossel der Auskunft: eingeloggt je Account, sonst je Client-IP (gleiche Toepfe wie die API). */
function hpi_limit(): bool {
	global $hpiUid, $hpiClient;
	[$ok] = $hpiUid > 0 ? hpr_rl('threat:user:' . $hpiUid, HPR_RL_KEY_CAP, HPR_RL_KEY_REFILL) : hpr_rl('threat:anon:' . hpr_rl_key($hpiClient), HPR_RL_ANON_CAP, HPR_RL_ANON_REFILL);
	return $ok;
}

if(empty($_SESSION['hpr_csrf'])) { $_SESSION['hpr_csrf'] = bin2hex(random_bytes(16)); }
$hpiCsrf = (string)$_SESSION['hpr_csrf'];
$hpiUid = (isset($userid) AND (string)$userid !== '' AND (string)$userid !== '0') ? (int)$userid : 0;
$hpiClient = hpr_client_ip();
$now = time();
$msg = ''; $res = null; $reqRow = null; $confirmTok = '';
$ipIn = isset($_GET['ip']) ? (string)$_GET['ip'] : '';
$form = array('reason' => '', 'email' => '');
$limitMsg = hpi_alert('warning', hpi_t('Zu viele Abfragen. Bitte warte einen Moment und versuche es dann erneut.', 'Too many lookups. Please wait a moment and try again.'));

try {
	// ---------------------------------------------------------------- POST: Antrag / Bestaetigung
	if(($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
		$act = (string)($_POST['action'] ?? '');
		if(!hash_equals($hpiCsrf, (string)($_POST['csrf'] ?? ''))) {
			$msg = hpi_alert('danger', hpi_t('Die Sitzung ist abgelaufen. Bitte lade die Seite neu und sende das Formular noch einmal.', 'Your session has expired. Please reload the page and submit the form again.'));
		} elseif($act === 'request') {
			$ipIn = (string)($_POST['ip'] ?? '');
			$ip = hpr_ip($ipIn);
			$form['reason'] = trim((string)preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', (string)($_POST['reason'] ?? '')));
			$form['email'] = trim((string)($_POST['email'] ?? ''));
			$err = '';
			if((string)($_POST['website'] ?? '') !== '') { $err = hpi_t('Der Antrag konnte nicht angenommen werden.', 'The request could not be accepted.'); } // Feld fuer Bots
			elseif($ip === null OR !hpr_public(inet_pton($ip))) { $err = hpi_t('Bitte eine gültige öffentliche IPv4- oder IPv6-Adresse angeben.', 'Please enter a valid public IPv4 or IPv6 address.'); }
			elseif(!hpi_limit()) { $err = hpi_t('Zu viele Abfragen. Bitte warte einen Moment.', 'Too many lookups. Please wait a moment.'); }
			else {
				$res = hpr_lookup($pdo, $ip);
				$len = mb_strlen($form['reason']);
				if($res['status'] !== 'listed') { $err = hpi_t('Diese IP ist nicht gelistet – ein Antrag ist nicht nötig.', 'This IP is not listed – no request needed.'); }
				elseif($res['release']['status'] === 'in_review') { $err = hpi_t('Für diese IP wird bereits ein Antrag geprüft.', 'A request for this IP is already being reviewed.'); }
				elseif($len < 10 OR $len > 2000) { $err = hpi_t('Bitte beschreibe in 10 bis 2000 Zeichen, warum die IP freigegeben werden soll.', 'Please explain in 10 to 2000 characters why the IP should be released.'); }
				elseif($hpiUid === 0 AND (strlen($form['email']) > 254 OR !filter_var($form['email'], FILTER_VALIDATE_EMAIL))) { $err = hpi_t('Bitte eine gültige E-Mail-Adresse angeben.', 'Please enter a valid e-mail address.'); }
				else {
					$since = hpr_dt($now - 86400);
					$chash = hash('sha256', 'hpr|' . hpr_rl_key($hpiClient)); // IPv6 je /64
					$n1 = (int)hpr_one($pdo, "SELECT COUNT(*) c FROM hp_release_requests WHERE client_hash = :h AND created_at >= :d", array('h' => $chash, 'd' => $since))['c'];
					$n2 = $hpiUid > 0 ? (int)hpr_one($pdo, "SELECT COUNT(*) c FROM hp_release_requests WHERE userid = :u AND created_at >= :d", array('u' => $hpiUid, 'd' => $since))['c']
						: (int)hpr_one($pdo, "SELECT COUNT(*) c FROM hp_release_requests WHERE email = :e AND created_at >= :d", array('e' => $form['email'], 'd' => $since))['c'];
					if($n1 >= HPR_MAX_PER_DAY OR $n2 >= HPR_MAX_PER_DAY) {
						$err = hpi_t('Es sind höchstens ' . HPR_MAX_PER_DAY . ' Anträge am Tag möglich. Bitte versuche es morgen wieder.', 'At most ' . HPR_MAX_PER_DAY . ' requests per day are possible. Please try again tomorrow.');
					} else {
						$tok = hpr_token(); $ctok = $hpiUid > 0 ? '' : hpr_token();
						hpr_q($pdo, "INSERT INTO hp_release_requests (ip, ip_bin, userid, email, reason, status, created_at, confirmed_at, token, confirm_hash, client_hash, lang)
							VALUES (:ip, UNHEX(:b), :u, :e, :r, 'open', :t, :c, :tok, :ch, :cl, :l)",
							array('ip' => $ip, 'b' => bin2hex(inet_pton($ip)), 'u' => $hpiUid > 0 ? $hpiUid : null, 'e' => $hpiUid > 0 ? '' : $form['email'], 'r' => $form['reason'],
								't' => hpr_dt($now), 'c' => $hpiUid > 0 ? hpr_dt($now) : null, 'tok' => $tok, 'ch' => $ctok === '' ? '' : hash('sha256', $ctok), 'cl' => $chash, 'l' => $hpiEn ? 'en' : 'de'));
						$status = HPR_URL . '?request=' . $tok . ($hpiEn ? '&lang=en' : '');
						if($hpiUid > 0) {
							$msg = hpi_alert('success', hpi_t('Antrag gestellt. Er wird automatisch geprüft: Greift die IP 24 Stunden lang keinen Sensor mehr an, wird sie freigegeben und 30 Tage geschützt. ', 'Request submitted. It is checked automatically: if the IP does not touch any sensor for 24 hours, it is released and protected for 30 days. ')
								. '<a href="' . hpi_h($status) . '">' . hpi_t('Status des Antrags', 'Request status') . '</a>');
						} else {
							$link = HPR_URL . '?request=' . $tok . '&confirm=' . $ctok . ($hpiEn ? '&lang=en' : '');
							$sent = hpr_mail($pdo, $form['email'], hpi_t("Honeypot64: Freigabe-Antrag für $ip bestätigen", "Honeypot64: confirm the release request for $ip"),
								hpi_t("Für die IP $ip wurde bei IPv64.net eine Freigabe von der v64 Blocklist beantragt und diese E-Mail-Adresse angegeben.\n\nBitte bestätige den Antrag über diesen Link:\n$link\n\nWarst du das nicht, ignoriere diese Mail; der Antrag wird nach 48 Stunden gelöscht.\n\nStatus: $status",
									"A release of the IP $ip from the v64 blocklist was requested at IPv64.net with this e-mail address.\n\nPlease confirm the request with this link:\n$link\n\nIf this was not you, ignore this e-mail; the request is deleted after 48 hours.\n\nStatus: $status"));
							if(!$sent) {
								hpr_q($pdo, "DELETE FROM hp_release_requests WHERE token = :t", array('t' => $tok));
								$msg = hpi_alert('danger', hpi_t('Die Bestätigungs-Mail konnte nicht gesendet werden. Bitte versuche es später noch einmal.', 'The confirmation e-mail could not be sent. Please try again later.'));
							} else {
								$msg = hpi_alert('success', hpi_t('Fast geschafft: Wir haben dir eine E-Mail geschickt. Bitte bestätige den Antrag über den Link darin (gültig 48 Stunden).', 'Almost done: we have sent you an e-mail. Please confirm the request with the link in it (valid for 48 hours).'));
							}
						}
						$form = array('reason' => '', 'email' => '');
						$res = hpr_lookup($pdo, $ip);
					}
				}
			}
			if($err !== '') { $msg = hpi_alert('danger', hpi_h($err)); }
		} elseif($act === 'confirm') {
			$tok = (string)($_POST['request'] ?? ''); $ctok = (string)($_POST['confirm'] ?? '');
			$row = preg_match('/^[A-Za-z0-9]{32}$/', $tok) ? hpr_one($pdo, "SELECT * FROM hp_release_requests WHERE token = :t", array('t' => $tok)) : null;
			if($row !== null AND $row['confirmed_at'] === null AND $row['confirm_hash'] !== '' AND preg_match('/^[A-Za-z0-9]{32}$/', $ctok)
				AND hash_equals((string)$row['confirm_hash'], hash('sha256', $ctok)) AND hpr_ts($row['created_at']) >= $now - HPR_CONFIRM_TTL) {
				hpr_q($pdo, "UPDATE hp_release_requests SET confirmed_at = :t, confirm_hash = '' WHERE id = :id AND confirmed_at IS NULL", array('t' => hpr_dt($now), 'id' => $row['id']));
				$msg = hpi_alert('success', hpi_t('Danke, der Antrag ist bestätigt und wird jetzt automatisch geprüft.', 'Thank you, the request is confirmed and is now checked automatically.'));
			} elseif($row !== null AND $row['confirmed_at'] !== null) {
				$msg = hpi_alert('info', hpi_t('Dieser Antrag ist bereits bestätigt.', 'This request has already been confirmed.'));
			} else {
				$msg = hpi_alert('danger', hpi_t('Der Bestätigungslink ist ungültig oder abgelaufen.', 'The confirmation link is invalid or has expired.'));
			}
			if(preg_match('/^[A-Za-z0-9]{32}$/', $tok)) { $_GET['request'] = $tok; }
		}
	}

	// ---------------------------------------------------------------- GET: Status eines Antrags / Auskunft
	if(isset($_GET['request']) AND is_string($_GET['request'])) {
		if(preg_match('/^[A-Za-z0-9]{32}$/', $_GET['request'])) {
			$reqRow = hpr_one($pdo, "SELECT id, ip, status, created_at, confirmed_at, decided_at, protected_until, token FROM hp_release_requests WHERE token = :t", array('t' => $_GET['request']));
		}
		if($reqRow === null) { $msg .= hpi_alert('warning', hpi_t('Antrag nicht gefunden (unbestätigte Anträge werden nach 48 Stunden gelöscht).', 'Request not found (unconfirmed requests are deleted after 48 hours).')); }
		elseif($reqRow['confirmed_at'] === null AND isset($_GET['confirm']) AND is_string($_GET['confirm']) AND preg_match('/^[A-Za-z0-9]{32}$/', $_GET['confirm'])) { $confirmTok = $_GET['confirm']; }
	} elseif($res === null AND $ipIn !== '') {
		$ip = hpr_ip($ipIn);
		if($ip === null) { $msg .= hpi_alert('warning', hpi_t('Bitte genau eine IPv4- oder IPv6-Adresse angeben (keine Netze, keine Hostnamen).', 'Please enter exactly one IPv4 or IPv6 address (no networks, no host names).')); }
		elseif(!hpr_public(inet_pton($ip))) { $msg .= hpi_alert('info', hpi_t('Das ist eine private oder reservierte Adresse. Solche Adressen kommen nie auf die Liste.', 'This is a private or reserved address. Such addresses are never listed.')); }
		elseif(!hpi_limit()) { $msg .= $limitMsg; }
		else { $res = hpr_lookup($pdo, $ip); }
	}
} catch(Throwable $e) {
	error_log('honeypot/ip.php: ' . $e->getMessage());
	$msg .= hpi_alert('danger', hpi_t('Die Auskunft ist gerade nicht verfügbar. Bitte versuche es später noch einmal.', 'The lookup is currently unavailable. Please try again later.'));
	$res = null;
}
$langLink = function(bool $en): string {
	$q = array_intersect_key($_GET, array('ip' => 1, 'request' => 1, 'confirm' => 1));
	$q = array_filter($q, 'is_string');
	if($en) { $q['lang'] = 'en'; }
	return 'ip.php' . ($q ? '?' . http_build_query($q) : '');
};
?>
<p></p>
<div class="container">
	<div class="card mb-3"><div class="card-body">
		<h4 class="mb-2"><i class="fa-solid fa-magnifying-glass text-primary"></i> <?php echo hpi_t('Honeypot64 – IP-Auskunft', 'Honeypot64 – IP lookup'); ?></h4>
		<p class="mb-2"><?php echo hpi_t('Prüfe, ob eine IP-Adresse auf der <b>v64 Blocklist</b> steht und warum. Die Liste entsteht aus den Meldungen vieler unabhängiger Honeypot64-Sensoren: Eine Adresse kommt erst darauf, wenn Sensoren <b>mehrerer verschiedener Accounts</b> Angriffe von ihr gesehen haben.',
			'Check whether an IP address is on the <b>v64 blocklist</b> and why. The list is built from the reports of many independent Honeypot64 sensors: an address is only added when sensors of <b>several different accounts</b> have seen attacks from it.'); ?></p>
		<p class="mb-0 small"><a href="<?php echo hpi_h($langLink(false)); ?>"<?php echo $hpiEn ? '' : ' class="font-weight-bold"'; ?>>Deutsch</a> · <a href="<?php echo hpi_h($langLink(true)); ?>"<?php echo $hpiEn ? ' class="font-weight-bold"' : ''; ?>>English</a></p>
	</div></div>

	<form method="get" action="ip.php" class="mb-3">
		<?php if($hpiEn) { echo '<input type="hidden" name="lang" value="en">'; } ?>
		<div class="input-group">
			<input type="text" name="ip" class="form-control" maxlength="45" placeholder="<?php echo hpi_t('IP-Adresse, z. B. 203.0.113.7 oder 2001:db8::1', 'IP address, e.g. 203.0.113.7 or 2001:db8::1'); ?>" value="<?php echo hpi_h($res['ip'] ?? $ipIn); ?>" autocomplete="off" spellcheck="false">
			<div class="input-group-append"><button type="submit" class="btn btn-primary"><?php echo hpi_t('Prüfen', 'Check'); ?></button></div>
		</div>
		<?php if($hpiClient !== '' AND filter_var($hpiClient, FILTER_VALIDATE_IP)) { echo '<small class="text-muted">' . hpi_t('Deine IP: ', 'Your IP: ') . '<a href="' . hpi_h(hpi_url(array('ip' => $hpiClient))) . '">' . hpi_h($hpiClient) . '</a></small>'; } ?>
	</form>

	<?php echo $msg; ?>

<?php if($reqRow !== null) {
	// ---------------------------------------------------------------- Status eines Antrags
	$conf = $reqRow['confirmed_at'] !== null;
	switch($reqRow['status']) {
		case 'released':
			$st = '<span class="badge badge-success">' . hpi_t('freigegeben', 'released') . '</span> ' . ($reqRow['protected_until'] === null ? hpi_t('dauerhaft', 'permanently')
				: hpi_t('geschützt bis ', 'protected until ') . hpi_h(hpi_time($reqRow['protected_until'])));
			break;
		case 'rejected': $st = '<span class="badge badge-danger">' . hpi_t('abgelehnt', 'declined') . '</span> ' . hpi_t('Von dieser Adresse werden weiter Angriffe gemeldet.', 'Attacks from this address are still being reported.'); break;
		case 'escalated': $st = '<span class="badge badge-warning">' . hpi_t('in Prüfung', 'under review') . '</span> ' . hpi_t('Die automatische Prüfung war nicht eindeutig; der Antrag wird von Hand geprüft.', 'The automatic check was not conclusive; the request is reviewed manually.'); break;
		default:
			$st = $conf ? '<span class="badge badge-info">' . hpi_t('offen', 'open') . '</span> ' . hpi_t('Wird automatisch geprüft: frühestens 24 Stunden nach der Bestätigung (seit ', 'Checked automatically: at the earliest 24 hours after confirmation (since ') . hpi_h(hpi_time($reqRow['confirmed_at'])) . ').'
				: '<span class="badge badge-secondary">' . hpi_t('unbestätigt', 'unconfirmed') . '</span> ' . hpi_t('Bitte bestätige den Antrag über den Link in der E-Mail.', 'Please confirm the request with the link in the e-mail.');
	} ?>
	<div class="card mb-3"><div class="card-header p-2"><i class="fa-solid fa-file-circle-check text-primary"></i> <?php echo hpi_t('Freigabe-Antrag', 'Release request'); ?> #<?php echo (int)$reqRow['id']; ?></div>
	<div class="card-body">
		<table class="table table-sm mb-2"><tbody>
			<tr><th style="width:12em"><?php echo hpi_t('IP-Adresse', 'IP address'); ?></th><td><a href="<?php echo hpi_h(hpi_url(array('ip' => $reqRow['ip']))); ?>"><code><?php echo hpi_h($reqRow['ip']); ?></code></a></td></tr>
			<tr><th><?php echo hpi_t('Gestellt', 'Submitted'); ?></th><td><?php echo hpi_h(hpi_time($reqRow['created_at'])); ?></td></tr>
			<tr><th><?php echo hpi_t('Status', 'Status'); ?></th><td><?php echo $st; ?></td></tr>
			<?php if($reqRow['decided_at'] !== null) { ?><tr><th><?php echo hpi_t('Entschieden', 'Decided'); ?></th><td><?php echo hpi_h(hpi_time($reqRow['decided_at'])); ?></td></tr><?php } ?>
		</tbody></table>
		<?php if($confirmTok !== '') { ?>
		<form method="post" action="<?php echo hpi_h(hpi_url(array('request' => $reqRow['token']))); ?>">
			<input type="hidden" name="action" value="confirm"><input type="hidden" name="csrf" value="<?php echo hpi_h($hpiCsrf); ?>">
			<input type="hidden" name="request" value="<?php echo hpi_h($reqRow['token']); ?>"><input type="hidden" name="confirm" value="<?php echo hpi_h($confirmTok); ?>">
			<?php if($hpiEn) { echo '<input type="hidden" name="lang" value="en">'; } ?>
			<button type="submit" class="btn btn-success"><?php echo hpi_t('Antrag jetzt bestätigen', 'Confirm the request now'); ?></button>
		</form>
		<?php } ?>
		<p class="small text-muted mb-0"><?php echo hpi_t('Nach einer Freigabe verschwindet die Adresse mit der nächsten Bewertung (alle 30 Minuten) aus den Live-Listen und mit der nächsten Tagesaktualisierung aus dem Tagesstand.',
			'After a release the address leaves the live lists with the next evaluation (every 30 minutes) and the daily lists with the next daily update.'); ?></p>
	</div></div>
<?php } elseif($res !== null) {
	// ---------------------------------------------------------------- Auskunft
	$r = $res; ?>
	<div class="card mb-3"><div class="card-header p-2"><code><?php echo hpi_h($r['ip']); ?></code></div>
	<div class="card-body">
	<?php if($r['status'] === 'listed') { ?>
		<h5><span class="badge badge-danger"><?php echo hpi_t('Gelistet', 'Listed'); ?></span> <?php echo hpi_t('Diese Adresse steht auf der v64 Blocklist.', 'This address is on the v64 blocklist.'); ?></h5>
		<p><?php echo hpi_t('Honeypot64-Sensoren von <b>' . (int)$r['accounts'] . ' verschiedenen Accounts</b> haben Angriffe von dieser Adresse gemeldet. Honeypots sind Fallen ohne echten Dienst – jede Verbindung dorthin ist verdächtig.',
			'Honeypot64 sensors of <b>' . (int)$r['accounts'] . ' different accounts</b> have reported attacks from this address. Honeypots are traps without a real service – every connection to them is suspicious.'); ?></p>
		<table class="table table-sm mb-0"><tbody>
			<tr><th style="width:12em"><?php echo hpi_t('Vertrauenswert', 'Confidence'); ?></th><td><?php echo (int)$r['score']; ?> / 100 <small class="text-muted"><?php echo hpi_t('(je höher, desto sicherer ein Angreifer)', '(the higher, the more certain an attacker)'); ?></small></td></tr>
			<tr><th><?php echo hpi_t('Erste Sichtung', 'First seen'); ?></th><td><?php echo hpi_h(hpi_iso($r['first_seen'], true)); ?></td></tr>
			<tr><th><?php echo hpi_t('Letzte Sichtung', 'Last seen'); ?></th><td><?php echo hpi_h(hpi_iso($r['last_seen'], true)); ?> <small class="text-muted"><?php echo hpi_t('(ohne neue Angriffe fällt die Adresse nach 14 Tagen von selbst heraus)', '(without new attacks the address drops off by itself after 14 days)'); ?></small></td></tr>
			<tr><th><?php echo hpi_t('Art der Angriffe', 'Type of attacks'); ?></th><td><?php
				if(empty($r['kinds'])) { echo '–'; }
				foreach($r['kinds'] as $k) {
					$base = isset(HPR_KINDS_TEXT[$k]) ? $k : (string)preg_replace('/^(http:exploit):.*$/', '$1', $k);
					$txt = HPR_KINDS_TEXT[$base] ?? null;
					echo '<div>' . ($txt !== null ? hpi_h($txt[$hpiEn ? 1 : 0]) . ' ' : '') . '<code class="small">' . hpi_h($k) . '</code></div>';
				} ?></td></tr>
			<tr><th><?php echo hpi_t('Angegriffene Ports', 'Attacked ports'); ?></th><td><?php
				echo empty($r['ports']) ? '–' : implode(', ', array_map(fn($p) => hpi_h($p['port']) . ' <small class="text-muted">' . hpi_h($p['service']) . '</small>', $r['ports'])); ?></td></tr>
			<tr><th><?php echo hpi_t('Listen', 'Lists'); ?></th><td><?php echo 'v64' . (empty($r['lists']) ? '' : ' · ' . implode(' · ', array_map(fn($l) => 'v64_' . hpi_h($l), $r['lists']))); ?></td></tr>
			<?php if($r['country'] !== null OR $r['asn'] !== null) { ?>
			<tr><th><?php echo hpi_t('Herkunft', 'Origin'); ?></th><td><?php echo hpi_h(trim(($r['country'] ?? '') . ($r['asn'] !== null ? ' · AS' . $r['asn'] : ''), ' ·')); ?><?php if($r['country'] !== null) { ?> <small class="text-muted">(<?php echo hpi_t('IP-Länderdaten:', 'IP country data:'); ?> <a href="https://db-ip.com" target="_blank" rel="noopener">DB-IP.com</a>)</small><?php } ?></td></tr>
			<?php } ?>
		</tbody></table>
	<?php } elseif($r['status'] === 'released' OR $r['status'] === 'allowlisted') { ?>
		<h5><span class="badge badge-success"><?php echo hpi_t('Freigegeben', 'Released'); ?></span>
		<?php echo $r['release']['protected_until'] === null ? hpi_t('Diese Adresse ist dauerhaft freigegeben und kommt nicht auf die Liste.', 'This address is permanently released and is not listed.')
			: hpi_t('Diese Adresse ist freigegeben und geschützt bis ', 'This address is released and protected until ') . hpi_h(hpi_iso($r['release']['protected_until'])) . '.'; ?></h5>
		<p class="mb-0 small text-muted"><?php echo hpi_t('Aus den Live-Listen verschwindet sie mit der nächsten Bewertung (alle 30 Minuten), aus dem Tagesstand mit der nächsten Tagesaktualisierung. Fällt sie nach dem Schutz wieder auf, wird sie neu bewertet.',
			'It leaves the live lists with the next evaluation (every 30 minutes) and the daily lists with the next daily update. If it attracts attention again after the protection, it is evaluated again.'); ?></p>
	<?php } else { ?>
		<h5><span class="badge badge-success"><?php echo hpi_t('Nicht gelistet', 'Not listed'); ?></span> <?php echo hpi_t('Diese Adresse steht nicht auf der v64 Blocklist.', 'This address is not on the v64 blocklist.'); ?></h5>
		<p class="mb-0 small text-muted"><?php echo hpi_t('Andere Blocklisten (z. B. Spamhaus, blocklist.de) prüft diese Seite nicht.', 'This page does not check other blocklists (e.g. Spamhaus, blocklist.de).'); ?></p>
	<?php }
	if($r['release']['status'] === 'in_review') { echo '<div class="alert alert-info mt-3 mb-0">' . hpi_t('Für diese Adresse wird gerade ein Freigabe-Antrag geprüft.', 'A release request for this address is currently being reviewed.') . '</div>'; }
	elseif($r['release']['status'] === 'rejected' AND $r['status'] === 'listed') { echo '<div class="alert alert-secondary mt-3 mb-0">' . hpi_t('Ein früherer Freigabe-Antrag wurde abgelehnt, weil weiter Angriffe gemeldet wurden.', 'An earlier release request was declined because attacks were still being reported.') . '</div>'; } ?>
	</div></div>

	<?php if($r['status'] === 'listed') { ?>
	<div class="card mb-3"><div class="card-header p-2"><i class="fa-solid fa-circle-question text-primary"></i> <?php echo hpi_t('Fehlalarm? Das kannst du tun', 'False positive? What you can do'); ?></div>
	<div class="card-body">
		<p class="mb-2"><?php echo hpi_t('Ist das deine Adresse, steckt meist eines davon dahinter:', 'If this is your address, it is usually one of these:'); ?></p>
		<ul class="mb-3">
			<li><?php echo hpi_t('Ein <b>befallenes Gerät</b> in deinem Netz (Kamera, Router, NAS, alter PC) greift unbemerkt andere an. Geräte prüfen, Firmware aktualisieren, Standard-Passwörter ändern.', 'An <b>infected device</b> in your network (camera, router, NAS, old PC) attacks others unnoticed. Check your devices, update the firmware, change default passwords.'); ?></li>
			<li><?php echo hpi_t('Du teilst die Adresse mit anderen (<b>Mobilfunk, CGNAT, VPN, Tor, öffentliches WLAN</b>).', 'You share the address with others (<b>mobile network, CGNAT, VPN, Tor, public Wi-Fi</b>).'); ?></li>
			<li><?php echo hpi_t('Dein Anbieter hat dir die Adresse <b>neu zugeteilt</b>, vorher nutzte sie jemand anderes. Ein Neustart des Routers bringt oft eine neue Adresse.', 'Your provider has <b>newly assigned</b> the address; someone else used it before. Restarting the router often gives you a new address.'); ?></li>
			<li><?php echo hpi_t('Ein eigener Dienst (Scanner, Monitoring) verbindet sich zu vielen fremden Adressen.', 'A service of your own (scanner, monitoring) connects to many foreign addresses.'); ?></li>
		</ul>
		<?php if($r['release']['status'] === 'in_review') { ?>
		<p class="mb-0"><?php echo hpi_t('Ein Antrag läuft bereits – ein weiterer ist nicht nötig.', 'A request is already in progress – another one is not needed.'); ?></p>
		<?php } else { ?>
		<h6><?php echo hpi_t('Freigabe beantragen', 'Request a release'); ?></h6>
		<p class="small text-muted"><?php echo hpi_t('Ablauf: Greift die Adresse ab dem Antrag 24 Stunden lang keinen Sensor mehr an, wird sie automatisch freigegeben und 30 Tage geschützt. Greift sie weiter an, gibt es mehrere Anträge oder gehört sie zu einem Provider-Netz, prüfen wir von Hand.',
			'How it works: if the address does not touch any sensor for 24 hours after the request, it is released automatically and protected for 30 days. If it keeps attacking, if there are several requests or if it belongs to a provider network, we check by hand.'); ?></p>
		<form method="post" action="<?php echo hpi_h(hpi_url(array('ip' => $r['ip']))); ?>">
			<input type="hidden" name="action" value="request"><input type="hidden" name="csrf" value="<?php echo hpi_h($hpiCsrf); ?>">
			<input type="hidden" name="ip" value="<?php echo hpi_h($r['ip']); ?>">
			<?php if($hpiEn) { echo '<input type="hidden" name="lang" value="en">'; } ?>
			<div style="position:absolute;left:-10000px" aria-hidden="true"><input type="text" name="website" tabindex="-1" autocomplete="off" value=""></div>
			<div class="form-group">
				<label for="hpi-reason"><?php echo hpi_t('Begründung', 'Reason'); ?></label>
				<textarea id="hpi-reason" name="reason" class="form-control" rows="4" minlength="10" maxlength="2000" required placeholder="<?php echo hpi_t('z. B. Das ist die Adresse unseres Büros; wir haben eine befallene Kamera gefunden und entfernt.', 'e.g. This is our office address; we found and removed an infected camera.'); ?>"><?php echo hpi_h($form['reason']); ?></textarea>
			</div>
			<?php if($hpiUid > 0) { ?>
			<p class="small"><?php echo hpi_t('Du bist angemeldet: Der Antrag gilt sofort, den Bescheid bekommst du an die E-Mail-Adresse deines Accounts.', 'You are logged in: the request is valid immediately, the decision is sent to the e-mail address of your account.'); ?></p>
			<?php } else { ?>
			<div class="form-group">
				<label for="hpi-email"><?php echo hpi_t('E-Mail-Adresse', 'E-mail address'); ?></label>
				<input type="email" id="hpi-email" name="email" class="form-control" maxlength="254" required value="<?php echo hpi_h($form['email']); ?>">
				<small class="form-text text-muted"><?php echo hpi_t('Nur für die Bestätigung und den Bescheid; sie wird 90 Tage nach der Entscheidung gelöscht.', 'Only for the confirmation and the decision; it is deleted 90 days after the decision.'); ?></small>
			</div>
			<?php } ?>
			<button type="submit" class="btn btn-primary"><?php echo hpi_t('Freigabe beantragen', 'Request release'); ?></button>
		</form>
		<?php } ?>
	</div></div>
	<?php }
} ?>

	<div class="card mb-3"><div class="card-body small">
		<p class="mb-2"><b><?php echo hpi_t('Wie zuverlässig ist die Liste?', 'How reliable is the list?'); ?></b>
		<?php echo hpi_t('Fehlalarme sind selten, aber möglich – vor allem bei geteilten oder neu zugeteilten Adressen. Deshalb zählen nur Meldungen mehrerer unabhängiger Accounts, ältere Treffer verlieren an Gewicht, und ohne neue Angriffe fällt eine Adresse nach 14 Tagen von selbst heraus.',
			'False positives are rare but possible – especially with shared or newly assigned addresses. That is why only reports of several independent accounts count, older hits lose weight, and without new attacks an address drops off by itself after 14 days.'); ?></p>
		<p class="mb-2"><?php echo hpi_t('Diese Seite zeigt keine Angaben zu den meldenden Sensoren oder Accounts. Für nicht gelistete Adressen gibt es keine Einzelheiten.',
			'This page shows no details about the reporting sensors or accounts. There are no details for addresses that are not listed.'); ?></p>
		<p class="mb-0"><?php echo hpi_t('Für Programme: <code>GET https://ipv64.net/api/v2/threat/ip/&lt;ip&gt;</code> (ohne API-Key mit engem Limit, mit API-Key großzügiger).', 'For programs: <code>GET https://ipv64.net/api/v2/threat/ip/&lt;ip&gt;</code> (without an API key with a tight limit, with an API key more generous).'); ?>
		<?php echo hpi_t('Mitmachen mit einem eigenen Sensor:', 'Contribute with your own sensor:'); ?> <a href="https://node64.de/docs/honeypot/" target="_blank" rel="noopener">node64.de/docs/honeypot/</a></p>
	</div></div>
</div>
<?php include("../footer.php"); ?>
