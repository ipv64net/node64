/*
 * Pruefung sonar.js (Sonar64 Teil W) unter Node (node:22-alpine, ohne Pakete): reine Hilfen (Farben, Normalisierung,
 * Projektion, Badges), Quelltext ohne innerHTML/eval/externe Quellen, de_map.json (Groesse, Pfade) und – wenn
 * vorhanden – die echten oeffentlichen JSON-Antworten aus run_tests.php (Verzeichnis als erstes Argument).
 *   node sonar_test.js [<out>]
 */
'use strict';
const fs = require('fs');
const path = require('path');
const DIR = path.join(__dirname, '..', '..');
const S = require(path.join(DIR, 'sonar.js'));
let pass = 0, failed = 0;
function check(name, ok, info) {
	if (ok) { pass++; console.log('  ok    ' + name); }
	else { failed++; console.log('  FEHLER ' + name + ' ' + (info === undefined ? '' : JSON.stringify(info).slice(0, 400))); }
}

// Farben nach Latenz (Vertrag/Auftrag: <15 gruen, <30 hellgruen, <60 orange, sonst rot)
const lc = [[0, 's64-l1'], [14.99, 's64-l1'], [15, 's64-l2'], [29.9, 's64-l2'], [30, 's64-l3'], [59.9, 's64-l3'], [60, 's64-l4'], [900, 's64-l4'],
	[null, 's64-l0'], [-1, 's64-l0'], ['12', 's64-l1'], ['x', 's64-l0'], [undefined, 's64-l0'], [NaN, 's64-l0']];
check('latClass Grenzen', lc.every(([v, c]) => S.latClass(v) === c), lc.map(([v]) => S.latClass(v)));
check('trustOf', S.trustOf('pillar') === 'pillar' && S.trustOf('root') === 'new' && S.trustOf(undefined) === 'new');
S.setLang('de');
check('fmtMs de', S.fmtMs(9.84) === '9,8 ms' && S.fmtMs(14.6) === '15 ms' && S.fmtMs(null) === '–', [S.fmtMs(9.84), S.fmtMs(14.6)]);
S.setLang('en');
check('fmtMs en', S.fmtMs(9.84) === '9.8 ms', S.fmtMs(9.84));
check('fmtPct', S.fmtPct(0.9567) === '95.7 %' && S.fmtPct(2) === '100.0 %' && S.fmtPct('x') === '–', S.fmtPct(0.9567));
S.setLang('de');

// Normalisierung
const n = S.normNode({ id: 'n1aaaaaaaaaa', slug: 'falke-1', name: 'Fa\u0000lke\u001b' + 'x'.repeat(60), trust: 'stable', role: 'node', lat: 50.1, lon: 8.6, asn: 3320,
	asname: 'DTAG', access: 'fiber', device: 'pi', online: true, since: '2026-10-01T00:00:00Z', uptime30: 0.95,
	anchor_ms: { a_fsn: 12.3, a_nbg: '9.8', __proto__x: 1, 'a_<x>': 3, a_bad: -1 } });
check('normNode Felder', n.id === 'n1aaaaaaaaaa' && n.slug === 'falke-1' && n.trust === 'stable' && n.asn === 3320 && n.online === true && n.since === Date.parse('2026-10-01T00:00:00Z'), n);
check('normNode Steuerzeichen raus, Laenge begrenzt', n.name.indexOf('\u0000') < 0 && n.name.indexOf('\u001b') < 0 && n.name.length === 40, n.name);
check('normNode anchor_ms nur a_*, Zahlen >= 0', JSON.stringify(n.anchor_ms) === JSON.stringify({ a_fsn: 12.3, a_nbg: 9.8 }), n.anchor_ms);
const bad = S.normNode({ id: '../x', slug: 'A B', name: { toString() { return 'x'; } }, trust: 'root', lat: 95, lon: 8, access: 'isdn', asn: -4, online: 'yes', since: 'gestern' });
check('normNode boese Werte', bad.id === '' && bad.slug === '' && bad.name === '' && bad.trust === 'new' && bad.lat === null && bad.lon === null && bad.access === ''
	&& bad.asn === null && bad.online === false && bad.since === null, bad);
check('normNode Anker ohne trust', S.normNode({ id: 'a_fsn', role: 'anchor' }).trust === 'anchor');
check('normNode kein Objekt', S.normNode(null) === null && S.normNode('x') === null);
const ids = { n1aaaaaaaaaa: 1, n2bbbbbbbbbb: 1 };
check('normLink gueltig', JSON.stringify(S.normLink({ a: 'n1aaaaaaaaaa', b: 'n2bbbbbbbbbb', fam: 6, ms: 14.2, loss: 0, n: 24 }, ids)) === JSON.stringify({ a: 'n1aaaaaaaaaa', b: 'n2bbbbbbbbbb', fam: 6, ms: 14.2, loss: 0, n: 24 }));
check('normLink voller Verlust ohne ms', S.normLink({ a: 'n1aaaaaaaaaa', b: 'n2bbbbbbbbbb', ms: null, loss: 1, n: 3 }, ids).ms === null);
check('normLink verworfen', [{ a: 'n1aaaaaaaaaa', b: 'n1aaaaaaaaaa', ms: 1 }, { a: 'n1aaaaaaaaaa', b: 'nXXXXXXXXXXX', ms: 1 }, { a: 'n1aaaaaaaaaa', b: 'n2bbbbbbbbbb', ms: -3 },
	{ a: 'n1aaaaaaaaaa', b: 'n2bbbbbbbbbb', ms: null, loss: 0.2 }, { a: 'n1aaaaaaaaaa', b: 'n9zzzzzzzzzz', ms: 3 }, null].every((l) => S.normLink(l, ids) === null));
const o = S.normOutage({ id: 3, kind: 'region', key: '50.0,8.5', label: 'x'.repeat(200), started: '2026-10-28T10:00:00Z', ended: null, affected: 5, total: 8 });
check('normOutage', o.kind === 'region' && o.key === '50.0,8.5' && o.label.length === 120 && o.ended === null && o.affected === 5, o);
check('normOutage unbekannte Art -> asn', S.normOutage({ kind: 'x' }).kind === 'asn');
check('regionCell', JSON.stringify(S.regionCell('50.0,8.5')) === '[50,8.5]' && S.regionCell('DE-BY') === null && S.regionCell('99,8') === null);

// Verlauf je Anker und Familie
const hist = S.normHistory({ a_fsn: [{ hour: '2026-10-28T09:00:00Z', fam: 4, ms: 12.1, loss: 0 }, { hour: '2026-10-28T08:00:00Z', fam: 4, ms: 12.4 }, { hour: '2026-10-28T09:00:00Z', fam: 6, ms: 13 }],
	a_nbg: [{ hour: 'kaputt', ms: 1 }, { hour: '2026-10-28T09:00:00Z', ms: -1 }, { hour: '2026-10-28T09:00:00Z', fam: 4, ms: 9.7 }], evil: [{ hour: '2026-10-28T09:00:00Z', ms: 1 }] });
check('normHistory Reihen', hist.length === 3 && hist[0].label === 'FSN IPv4' && hist[1].label === 'FSN IPv6' && hist[2].label === 'NBG IPv4' && hist[0].pts[0].ms === 12.4, hist);
const hl = S.normHistory([{ anchor: 'a_fsn', hour: '2026-10-28T09:00:00Z', ms: 3 }]);
check('normHistory Liste, nur IPv4 ohne Zusatz', hl.length === 1 && hl[0].label === 'FSN', hl);

// Projektion und Badges
const g = JSON.parse(fs.readFileSync(path.join(DIR, 'de_map.json'), 'utf8'));
const xy = S.project(g.proj, 50.11, 8.68), ll = S.unproject(g.proj, xy[0], xy[1]);
check('project/unproject', Math.abs(ll[0] - 50.11) < 1e-9 && Math.abs(ll[1] - 8.68) < 1e-9 && xy[0] > 0 && xy[0] < g.proj.w && xy[1] > 0 && xy[1] < g.proj.h, [xy, ll]);
const pos = { n1aaaaaaaaaa: [0, 0], n2bbbbbbbbbb: [100, 0], n3cccccccccc: [5, 0] };
const links = [{ a: 'n1aaaaaaaaaa', b: 'n2bbbbbbbbbb', ms: 5, n: 2 }, { a: 'n1aaaaaaaaaa', b: 'n3cccccccccc', ms: 5, n: 50 }, { a: 'n2bbbbbbbbbb', b: 'n3cccccccccc', ms: null, n: 9 }];
const pb = S.pickBadges(links, pos, 5, 20);
check('pickBadges: zu kurze weg, nach Messungen', pb.length === 2 && pb[0].n === 9 && pb[1].n === 2, pb);
check('median', S.median([3, 1, 2]) === 2 && S.median([4, 1, 2, 3]) === 2.5 && S.median([]) === null);
check('asList', S.asList([1], []).length === 1 && S.asList({ nodes: [1, 2] }, ['nodes']).length === 2 && S.asList('x', ['a']).length === 0);
check('providerName', S.providerName({ asn: 3320, asname: 'DTAG' }) === 'AS3320 DTAG' && S.providerName({ asn: null, asname: '' }) === '–');

// Texte: beide Sprachen gleich vollstaendig
const src = fs.readFileSync(path.join(DIR, 'sonar.js'), 'utf8');
const keys = (l) => { const m = src.match(new RegExp('\\n\\t\\t' + l + ': \\{([\\s\\S]*?)\\n\\t\\t\\}')); return m ? (m[1].match(/(?:^|\s)[a-z][a-z_0-9]*: '/g) || []).map((k) => k.trim().slice(0, -3)).sort() : []; };
check('Texte de/en gleich', keys('de').length > 40 && JSON.stringify(keys('de')) === JSON.stringify(keys('en')), [keys('de').length, keys('en').length]);
S.setLang('en');
check('t() mit Platzhalter', S.t('outage_aff', { a: 5, t: 8 }) === '5 of 8 nodes affected');
S.setLang('de');

// Quelltext: keine HTML-Einfuegung, kein eval, keine externen Quellen
const code = src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
check('sonar.js ohne innerHTML/outerHTML/insertAdjacentHTML/document.write/eval/Function', !/(innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\s*\(|new Function)/.test(code));
check('sonar.js ohne externe Adressen', !/https?:\/\//.test(code.replace("'http://www.w3.org/2000/svg'", '')));
check('sonar.css ohne externe Quellen', !/(url\(|@import|https?:)/.test(fs.readFileSync(path.join(DIR, 'sonar.css'), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '')));

// de_map.json
const raw = fs.readFileSync(path.join(DIR, 'de_map.json'));
check('de_map.json <= 40 KB', raw.length <= 40960, raw.length);
check('de_map.json Quelle genannt', typeof g._source === 'string' && g._source.length > 40);
check('de_map.json Pfade nur M/Z/Zahlen', Array.isArray(g.land) && g.land.length >= 1 && g.land.every((d) => /^[MZ0-9 .\-]+$/.test(d)));
check('de_map.json Staedte in der Karte', g.cities.every((c) => c.x > 0 && c.x < g.proj.w && c.y > 0 && c.y < g.proj.h && typeof c.n === 'string'));
const pts = g.land[0].replace(/[MZ]/g, ' ').trim().split(/\s+/).map(Number);
check('de_map.json Umriss in der viewBox', pts.length > 300 && pts.every((v, i) => v >= 0 && v <= (i % 2 ? g.proj.h : g.proj.w)));
const ber = S.project(g.proj, 52.52, 13.405), muc = S.project(g.proj, 48.137, 11.575), ham = S.project(g.proj, 53.55, 9.99);
check('Staedte in sinnvoller Lage (Berlin ost, Muenchen sued, Hamburg nord)', ber[0] > ham[0] && muc[1] > ber[1] && ham[1] < ber[1]);

// Echte Antworten der oeffentlichen API (Teil A) – Form passt zu den Normalisierern
const out = process.argv[2];
function load(k) { try { return JSON.parse(fs.readFileSync(path.join(out, k + '.json'), 'utf8')).data; } catch (e) { return undefined; } }
if (out && fs.existsSync(path.join(out, 'map.json'))) {
	const map = load('map');
	const mn = S.asList(map.nodes, []).map(S.normNode).filter((x) => x && x.id && x.lat !== null);
	check('API map: Knoten normalisierbar (mit Ankern, ohne Quarantaene)', mn.length === map.nodes.length && mn.some((x) => x.role === 'anchor') && !mn.some((x) => x.trust === 'quarantine'), map.nodes);
	const byId = {}; mn.forEach((x) => { byId[x.id] = 1; });
	const ml = S.asList(map.links, []).map((l) => S.normLink(l, byId)).filter(Boolean);
	check('API map: Verbindungen normalisierbar', ml.length === map.links.length && ml.length >= 1, map.links);
	check('API map: Anker-ms am Knoten', mn.some((x) => Object.keys(x.anchor_ms).length >= 1), mn.map((x) => x.anchor_ms));
	check('API map: Stoerungen', S.asList(map.outages, []).map(S.normOutage).filter((x) => x && x.ended === null).length >= 1);
	const nl = S.asList(load('nodes'), ['nodes']).map(S.normNode);
	check('API nodes: Liste mit since/uptime/place', nl.length >= 3 && nl.every((x) => x && x.slug && x.since !== null && x.uptime30 !== null), nl);
	const node = load('node'), nn = S.normNode(node), hs = S.normHistory(node.history);
	check('API node: Knoten und Verlauf je Anker/Familie', nn.slug === 'falke-1' && hs.length >= 2 && hs.every((s) => s.pts.length >= 20) && hs.some((s) => / IPv6$/.test(s.label)), [nn, hs.map((s) => s.label)]);
	const st = load('stats');
	check('API stats: Felder', ['nodes_active', 'nodes_total', 'anchors', 'measurements_today', 'providers', 'regions'].every((k) => typeof st[k] === 'number') && typeof st.by_trust === 'object', st);
	const top = load('top');
	check('API top: Listen', Array.isArray(top.reliable) && Array.isArray(top.longest) && Array.isArray(top.providers) && top.longest.map(S.normNode).every((x) => x && x.slug), top);
	const mx = load('matrix');
	check('API matrix: asns/cells', Array.isArray(mx.asns) && Array.isArray(mx.cells), mx);
	const og = S.asList(load('outages'), ['outages']).map(S.normOutage);
	check('API outages: laufend und vergangen', og.some((x) => x.ended === null) && og.some((x) => x.ended !== null), og);
} else {
	console.log('  (keine API-Antworten: Formpruefung uebersprungen)');
}

console.log('\nsonar.js: ' + pass + ' ok, ' + failed + ' Fehler');
process.exit(failed > 0 ? 1 : 0);
