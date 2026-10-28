<?php
/**
 * Sonar64 – gemeinsame Seitenteile der Seiten unter /sonar (Teil W, Vertrag docs/SONAR64-VERTRAG.md): Sprache
 * (?lang=en wie honeypot/), Escaping, Kopf mit Navigation, Einbinden von sonar.css/sonar.js. Keine Datenbank, keine
 * Eingaben ausser lang (und die erlaubten Parameter fuer den Sprach-Link, die nur escaped wieder ausgegeben werden).
 * Wird nach ../header.php eingebunden: require_once __DIR__ . '/s64_web.php';
 */
if(defined('S64W_VER')) { return; }
const S64W_VER = '1'; // Cache-Zaehler fuer sonar.css/sonar.js/de_map.json

$s64wEn = (($_GET['lang'] ?? '') === 'en');

function s64w_t(string $de, string $en): string { global $s64wEn; return $s64wEn ? $en : $de; }
function s64w_h($s): string { return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function s64w_lang(): string { global $s64wEn; return $s64wEn ? 'en' : 'de'; }
/** URL-Parameter nur als Text (Arrays wie trust[]=x zaehlen als leer, keine "Array to string"-Warnung) */
function s64w_get(string $k): string { return isset($_GET[$k]) && is_string($_GET[$k]) ? $_GET[$k] : ''; }

/** Link auf eine Sonar-Seite, Sprache bleibt erhalten. */
function s64w_url(string $page, array $q = array()): string {
	global $s64wEn;
	if($s64wEn) { $q['lang'] = 'en'; }
	return $page . ($q ? '?' . http_build_query($q) : '');
}

/** Link auf dieselbe Seite in der anderen Sprache (nur bekannte, kurze Parameter). */
function s64w_lang_url(): string {
	global $s64wEn;
	$q = array();
	foreach(array('slug', 'trust', 'asn', 'q', 'node') as $k) {
		if(isset($_GET[$k]) AND is_string($_GET[$k]) AND $_GET[$k] !== '' AND strlen($_GET[$k]) <= 64) { $q[$k] = $_GET[$k]; }
	}
	if(!$s64wEn) { $q['lang'] = 'en'; }
	return basename($_SERVER['SCRIPT_NAME'] ?? 'index.php') . ($q ? '?' . http_build_query($q) : '');
}

/** Name und Farbe einer Vertrauensstufe (Plan Abschnitt 6). */
function s64w_trust(string $trust): string {
	$n = array('new' => array('Neu', 'New'), 'stable' => array('Stabil', 'Stable'), 'trusted' => array('Vertraut', 'Trusted'),
		'pillar' => array('Säule', 'Pillar'), 'anchor' => array('Anker', 'Anchor'), 'quarantine' => array('Quarantäne', 'Quarantine'));
	$x = $n[$trust] ?? $n['new'];
	return s64w_t($x[0], $x[1]);
}
function s64w_trust_badge(string $trust): string {
	$k = in_array($trust, array('new', 'stable', 'trusted', 'pillar', 'anchor', 'quarantine'), true) ? $trust : 'new';
	return '<span class="s64-badge s64-t-' . $k . '">' . s64w_h(s64w_trust($k)) . '</span>';
}

/** Kopf: Stylesheet, Container mit data-page/data-lang (fuer sonar.js), Titel, Sprache, Navigation. */
function s64w_head(string $page, string $title, string $intro, array $data = array()): void {
	$attrs = '';
	foreach($data as $k => $v) { $attrs .= ' data-' . s64w_h($k) . '="' . s64w_h($v) . '"'; }
	echo '<link rel="stylesheet" href="sonar.css?v=' . S64W_VER . '">' . "\n";
	echo '<p></p><div class="container s64" id="s64" data-page="' . s64w_h($page) . '" data-lang="' . s64w_lang() . '" data-ver="' . S64W_VER . '"' . $attrs . '>' . "\n";
	echo '<div class="card mb-3"><div class="card-body">';
	echo '<a class="float-right small" href="' . s64w_h(s64w_lang_url()) . '">' . (s64w_lang() === 'en' ? 'Deutsch' : 'English') . '</a>';
	echo '<h4 class="mb-2"><i class="fa-solid fa-tower-broadcast text-primary"></i> Sonar64 – ' . s64w_h($title) . '</h4>';
	echo '<p class="mb-2">' . s64w_h($intro) . '</p>';
	echo '<ul class="nav nav-pills s64-nav small">';
	foreach(array(array('map', 'index.php', s64w_t('Karte', 'Map'), 'fa-map'), array('nodes', 'nodes.php', s64w_t('Teilnehmer', 'Participants'), 'fa-list'),
		array('top', 'top.php', s64w_t('Bestenliste & Zahlen', 'Leaderboard & numbers'), 'fa-trophy'), array('me', 'me.php', s64w_t('Mein Knoten', 'My node'), 'fa-user')) as [$k, $href, $label, $icon]) {
		echo '<li class="nav-item"><a class="nav-link py-1' . ($k === $page ? ' active' : '') . '" href="' . s64w_h(s64w_url($href)) . '"><i class="fa-solid ' . $icon . '"></i> ' . s64w_h($label) . '</a></li>';
	}
	echo '</ul></div></div>' . "\n";
}

/** Mitmachen-Box (Community): Wege zur Teilnahme, ohne externe Skripte. */
function s64w_join(): void { ?>
	<div class="card mb-3 s64-join"><div class="card-body p-3">
		<h5 class="mb-2"><i class="fa-solid fa-hand-holding-heart text-primary"></i> <?php echo s64w_h(s64w_t('Mitmachen', 'Join in')); ?></h5>
		<p class="small mb-2"><?php echo s64w_h(s64w_t('Sonar64 lebt von Knoten bei euch zu Hause: Jeder Knoten misst ein paar andere und die Anker – sparsam, nach festem Plan, ohne fremde Ziele. Dafür siehst du, wie deine Leitung im Vergleich dasteht.',
			'Sonar64 lives from nodes in your homes: every node measures a few others and the anchors – sparingly, on a fixed plan, never arbitrary targets. In return you see how your line compares.')); ?></p>
		<ul class="small mb-2 pl-3">
			<li><b>Node64:</b> <?php echo s64w_h(s64w_t('Modul Sonar64 einschalten – fertig.', 'switch on the Sonar64 module – done.')); ?></li>
			<li><b><?php echo s64w_h(s64w_t('Ohne Node64', 'Without Node64')); ?>:</b> <?php echo s64w_h(s64w_t('das kleine Programm sonar64 als Container oder einzelne Datei (bis hinunter zum Raspberry Pi Zero), mit einem Sonar-Token aus „Mein Knoten“.',
				'the small sonar64 program as a container or single file (down to a Raspberry Pi Zero), with a Sonar token from “My node”.')); ?></li>
		</ul>
		<a class="btn btn-sm btn-primary" href="<?php echo s64w_h(s64w_url('me.php')); ?>"><i class="fa-solid fa-key"></i> <?php echo s64w_h(s64w_t('Sonar-Token holen', 'Get a Sonar token')); ?></a>
		<a class="btn btn-sm btn-outline-secondary" href="https://node64.de/docs/sonar64/" target="_blank" rel="noopener"><i class="fa-solid fa-book"></i> <?php echo s64w_h(s64w_t('Anleitung', 'Guide')); ?></a>
		<a class="btn btn-sm btn-outline-secondary" href="<?php echo s64w_h(s64w_lang() === 'en' ? '/node64.php?lang=en' : '/node64.php'); ?>"><i class="fa-solid fa-server"></i> Node64</a>
	</div></div>
<?php }

/** Fuss: Container schliessen, sonar.js laden. */
function s64w_foot(): void {
	echo "</div>\n" . '<script src="sonar.js?v=' . S64W_VER . '"></script>' . "\n";
}
