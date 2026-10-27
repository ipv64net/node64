<?php
/**
 * Honeypot64 (Phase H3) – Listen-Token fuer den Live-Stand der v64 Blocklist: anzeigen (maskiert, aufdeckbar),
 * erzeugen/neu erzeugen (der alte wird sofort ungueltig), loeschen. Tabelle hp_list_tokens, Abruf ueber
 * blocklists/live.php. Token: genau 32 Zeichen [A-Za-z0-9] (so erwartet es auch PROXY64 in Node64).
 * Ohne Menuelink; nur per URL bzw. Link auf honeypot/. Planung: docs/PLAN-NODE64-HONEYPOT64.md (Abschnitt 8).
 */
include("../header.php");

function hpt_h($s): string { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
function hpt_time($utc): string { return ($utc === null OR $utc === '') ? '–' : date('d.m.Y H:i', strtotime($utc . ' UTC')); }
function hpt_q(string $sql, array $p = array()): PDOStatement { global $pdo; $st = $pdo->prepare($sql); $st->execute($p); return $st; }
/** 32 Zeichen aus [A-Za-z0-9], gleichverteilt (random_int) */
function hpt_new_token(): string {
	$a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'; $t = '';
	for($i = 0; $i < 32; $i++) { $t .= $a[random_int(0, 61)]; }
	return $t;
}
?>
<p></p>
<div class="container">
<?php
if($userid == "") {
	echo '<div class="alert alert-info" role="alert">Bitte zuerst anmelden.</div></div>';
	include("../footer.php");
	exit;
}
$u = (int)$userid; $now = time(); $info = '';
if(empty($_SESSION['hpt_csrf'])) { $_SESSION['hpt_csrf'] = bin2hex(random_bytes(16)); }
$csrf = $_SESSION['hpt_csrf'];

try {
	if($_SERVER['REQUEST_METHOD'] === 'POST') {
		if(!hash_equals($csrf, (string)($_POST['csrf'] ?? ''))) {
			$info = '<div class="alert alert-danger" role="alert">Sitzung abgelaufen, bitte noch einmal versuchen.</div>';
		} elseif(($_POST['action'] ?? '') === 'new') {
			$ts = gmdate('Y-m-d H:i:s', $now);
			for($try = 0; ; $try++) {
				try {
					hpt_q("INSERT INTO hp_list_tokens (userid, token, created_at, last_used, uses_window_start, uses_in_window) VALUES (:u, :t, :c, NULL, NULL, 0)
						ON DUPLICATE KEY UPDATE token = VALUES(token), created_at = VALUES(created_at), last_used = NULL, uses_window_start = NULL, uses_in_window = 0",
						array('u' => $u, 't' => hpt_new_token(), 'c' => $ts));
					break;
				} catch(PDOException $e) { if($try >= 2 OR ($e->errorInfo[1] ?? 0) != 1062) { throw $e; } } // Token schon vergeben (praktisch nie): neu wuerfeln
			}
			hpt_q("DELETE FROM hp_list_token_files WHERE userid = :u", array('u' => $u));
			add_log($pdo, $userid, "0", "Honeypot64", "Listen-Token erzeugt.");
			$info = '<div class="alert alert-success" role="alert">Neues Listen-Token erzeugt. Ein bisheriges Token gilt ab sofort nicht mehr – Adressen in Firewall bzw. PROXY64 anpassen.</div>';
		} elseif(($_POST['action'] ?? '') === 'delete') {
			hpt_q("DELETE FROM hp_list_tokens WHERE userid = :u", array('u' => $u));
			hpt_q("DELETE FROM hp_list_token_files WHERE userid = :u", array('u' => $u));
			add_log($pdo, $userid, "0", "Honeypot64", "Listen-Token geloescht.");
			$info = '<div class="alert alert-warning" role="alert">Listen-Token gelöscht. Abrufe damit enden mit 404.</div>';
		}
	}
	$tok = hpt_q("SELECT token, created_at, last_used FROM hp_list_tokens WHERE userid = :u", array('u' => $u))->fetch(PDO::FETCH_ASSOC);
	$cls = hpt_q("SELECT u.user_class, c.name FROM users u LEFT JOIN user_class c ON c.id = u.user_class WHERE u.id = :u", array('u' => $u))->fetch(PDO::FETCH_ASSOC);
	$contrib = hpt_q("SELECT MAX(last_seen) FROM hp_sensors WHERE userid = :u AND disabled = 0 AND last_seen >= :d", array('u' => $u, 'd' => gmdate('Y-m-d H:i:s', $now - 7 * 86400)))->fetchColumn();
} catch(Throwable $e) {
	error_log('honeypot/token.php: ' . $e->getMessage());
	echo '<div class="alert alert-danger" role="alert">Das Listen-Token ist gerade nicht verfügbar.</div></div>';
	include("../footer.php");
	exit;
}
$classLive = (int)($cls['user_class'] ?? 1) !== 1;
$live = $classLive || $contrib !== null && $contrib !== false;
$base = 'https://ipv64.net/blocklists/live/';
$examples = array('ipv64_blocklist_v64.txt' => 'v64 Blocklist (IPv4 + IPv6)', 'ipv64_blocklist_v4_v64.txt' => 'nur IPv4', 'ipv64_blocklist_v6_v64.txt' => 'nur IPv6',
	'v64_mikrotik_v4_v64.rsc' => 'MikroTik (Adressliste IPv64-v64)', 'v64_mikrotik_v6_v64.rsc' => 'MikroTik IPv6');
?>
	<?php echo $info; ?>
	<div class="card mb-3"><div class="card-body">
		<h4 class="mb-2"><i class="fa-solid fa-key text-primary"></i> Honeypot64 – Listen-Token</h4>
		<p class="mb-1">Die <b>v64 Blocklist</b> bekommt jede/r vollständig und frei als <b>Tagesstand</b> (einmal täglich, bis 24 h alt) unter
		<a href="/v64_blocklists">/v64_blocklists</a>. Den <b>Live-Stand</b> (nach jeder Bewertung, alle 30 Minuten) bekommen
		<b>alle Klassen außer Standard</b> und <b>Beitragende</b> (mindestens ein Honeypot64-Sensor hat in den letzten 7 Tagen gemeldet).</p>
		<p class="mb-0 small text-muted">Das Token steht in der Adresse, weil Firewalls (pfSense, OPNsense, MikroTik, FortiGate) keine Kopfzeilen mitschicken können.
		Es ist getrennt vom API-Key und berechtigt nur zum Abruf der Listen. Die Berechtigung wird bei jedem Abruf geprüft; ohne sie liefert dieselbe Adresse den Tagesstand
		(Kopfzeile <code>X-IPv64-List: daily</code> statt <code>live</code>). Dieselbe Datei höchstens alle 5 Minuten abrufen.</p>
	</div></div>

	<div class="card mb-3"><div class="card-header p-2"><i class="fa-solid fa-signal text-primary"></i> Dein Stand</div><div class="card-body p-2 small">
		<?php if($live) { ?>
		<span class="badge badge-success">Live</span> Du bekommst den Live-Stand –
		<?php echo $classLive ? 'Klasse ' . hpt_h($cls['name'] ?? '') : 'als Beitragende/r (letzte Meldung ' . hpt_h(hpt_time($contrib)) . ')'; ?>.
		<?php } else { ?>
		<span class="badge badge-secondary">Tagesstand</span> Mit Klasse Standard und ohne Sensor gibt es über das Token den Tagesstand.
		Live-Stand: Honeypot64 in <a href="https://node64.de/docs/honeypot/" target="_blank" rel="noopener">Node64</a> einschalten und melden lassen, oder eine Klasse ab VIP (<a href="/pricing">Preise</a>).
		<?php } ?>
	</div></div>

	<div class="card mb-3"><div class="card-header p-2"><i class="fa-solid fa-key text-primary"></i> Token</div><div class="card-body p-2">
	<?php if($tok) { ?>
		<div class="input-group input-group-sm mb-2" style="max-width:40em">
			<input type="password" class="form-control text-monospace" id="hpt_token" value="<?php echo hpt_h($tok['token']); ?>" readonly>
			<div class="input-group-append">
				<button class="btn btn-outline-secondary" type="button" onclick="hptToggle()" title="Anzeigen/verbergen"><i class="fa-solid fa-eye"></i></button>
				<button class="btn btn-outline-secondary" type="button" onclick="navigator.clipboard.writeText(document.getElementById('hpt_token').value)" title="Kopieren"><i class="fa-solid fa-copy"></i></button>
			</div>
		</div>
		<p class="small text-muted mb-2">Erzeugt <?php echo hpt_h(hpt_time($tok['created_at'])); ?>, zuletzt benutzt <?php echo hpt_h(hpt_time($tok['last_used'])); ?>.</p>
		<form method="post" class="d-inline" onsubmit="return confirm('Neues Token erzeugen? Das bisherige gilt sofort nicht mehr.')">
			<input type="hidden" name="csrf" value="<?php echo $csrf; ?>"><input type="hidden" name="action" value="new">
			<button class="btn btn-sm btn-primary"><i class="fa-solid fa-rotate"></i> Neu erzeugen</button></form>
		<form method="post" class="d-inline" onsubmit="return confirm('Token löschen? Abrufe damit enden danach mit 404.')">
			<input type="hidden" name="csrf" value="<?php echo $csrf; ?>"><input type="hidden" name="action" value="delete">
			<button class="btn btn-sm btn-outline-danger"><i class="fa-solid fa-trash"></i> Löschen</button></form>
	<?php } else { ?>
		<p class="small mb-2">Noch kein Listen-Token.</p>
		<form method="post"><input type="hidden" name="csrf" value="<?php echo $csrf; ?>"><input type="hidden" name="action" value="new">
			<button class="btn btn-sm btn-primary"><i class="fa-solid fa-plus"></i> Token erzeugen</button></form>
	<?php } ?>
	</div></div>

	<?php if($tok) { ?>
	<div class="card mb-3"><div class="card-header p-2"><i class="fa-solid fa-link text-primary"></i> Adressen</div><div class="card-body p-0"><div class="table-responsive">
		<table class="table table-sm mb-0 small"><tbody>
		<?php foreach($examples as $f => $label) { ?>
			<tr><td style="width:16em"><?php echo hpt_h($label); ?></td>
			<td><code class="hpt-url" data-full="<?php echo hpt_h($base . $tok['token'] . '/' . $f); ?>"><?php echo hpt_h($base . substr($tok['token'], 0, 4) . str_repeat('•', 8) . '/' . $f); ?></code></td></tr>
		<?php } ?>
		</tbody></table>
	</div></div></div>
	<p class="small text-muted">In Node64 (PROXY64, Blocklisten) das Token hinterlegen: die v64-Listen kommen dann automatisch live.
	Antwortcodes: <code>200</code> Liste, <code>304</code> unverändert (ETag), <code>429</code> zu oft (Kopfzeile <code>Retry-After</code>), <code>404</code> unbekanntes Token.</p>
	<?php } ?>
</div>
<script>
function hptToggle() {
	var i = document.getElementById('hpt_token'); var show = i.type === 'password';
	i.type = show ? 'text' : 'password';
	document.querySelectorAll('.hpt-url').forEach(function(c) {
		if(!c.dataset.masked) { c.dataset.masked = c.textContent; }
		c.textContent = show ? c.dataset.full : c.dataset.masked;
	});
}
</script>
<?php include("../footer.php"); ?>
