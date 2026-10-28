/*
 * Sonar64 – Seiten unter ipv64.net/sonar (Teil W, Vertrag docs/SONAR64-VERTRAG.md Abschnitt 3/5):
 * Karte (index.php), Teilnehmer (nodes.php), Knotenseite (node.php), Bestenliste (top.php), Standortwahl (me.php).
 * Vanilla-JS ohne Bibliotheken und ohne externe Quellen; Daten nur aus /api/v2/sonar/public/* und de_map.json.
 * Sicherheit: Werte aus den Antworten werden streng normalisiert und nur per textContent/setAttribute ausgegeben,
 * nie per innerHTML. Die Seite (div#s64) traegt data-page, data-lang und data-ver.
 */
(function (G) {
	'use strict';
	var API = '/api/v2/sonar/public/';
	var SVGNS = 'http://www.w3.org/2000/svg';
	var REFRESH = 60000;
	var TRUSTS = ['new', 'stable', 'trusted', 'pillar', 'anchor', 'quarantine'];
	var ACCESS = ['fiber', 'dsl', 'cable', 'mobile', 'satellite', 'datacenter', 'other'];
	var SLUG = /^[a-z0-9][a-z0-9_-]{0,39}$/;
	var NODEID = /^(n[a-z0-9]{11}|a_[a-z0-9_-]{1,13})$/;
	var ANCHOR = /^a_[a-z0-9_-]{1,13}$/;
	var LANG = 'de';

	var TX = {
		de: {
			loading: 'Lade …', unavailable: 'Die Daten sind gerade nicht verfügbar.', updated: 'Stand {time} · neu alle 60 s', paused: 'PAUSE',
			t_new: 'Neu', t_stable: 'Stabil', t_trusted: 'Vertraut', t_pillar: 'Säule', t_anchor: 'Anker', t_quarantine: 'Quarantäne',
			td_new: 'Neu dabei (unter 7 Tagen): misst und wird gemessen, zählt in Auswertungen noch kaum.',
			td_stable: 'Stabil: mindestens 7 Tage dabei, Verfügbarkeit ≥ 90 %, plausible Werte – zählt normal.',
			td_trusted: 'Vertraut: mindestens 60 Tage dabei, Verfügbarkeit ≥ 97 %, kaum Abweichungen – zählt doppelt und dient Nachbarn als Bezugspunkt.',
			td_pillar: 'Säule: mindestens 180 Tage dabei, sehr stabil und wird gemessen – Referenzziel für neue Knoten.',
			td_anchor: 'Anker: von ipv64 betriebener oder freigegebener fester Messpunkt.',
			td_quarantine: 'Quarantäne: misst weiter, zählt aber nicht.',
			acc_fiber: 'Glasfaser', acc_dsl: 'DSL', acc_cable: 'Kabel', acc_mobile: 'LTE/5G', acc_satellite: 'Satellit', acc_datacenter: 'Rechenzentrum', acc_other: 'Sonstiges',
			online: 'online', offline: 'offline', role_anchor: 'Anker', role_node: 'Knoten',
			provider: 'Provider', access: 'Anschluss', device: 'Gerät', place: 'Region', since: 'Dabei seit', uptime: 'Verfügbarkeit (30 T.)', anchors: 'Zu den Ankern',
			links_n: '{n} Verbindungen in der letzten Stunde', node_page: 'Zur Knotenseite', clear: 'Auswahl aufheben',
			outage: 'Störung', outage_asn: 'Provider', outage_region: 'Region', outage_since: 'seit {time}', outage_aff: '{a} von {t} Knoten betroffen',
			outages_none: 'Keine Störungen erkannt.', ongoing: 'läuft',
			nodes_count: '{n} Knoten', nodes_none: 'Keine Knoten gefunden.',
			reach_udp: 'UDP 6464 (bis zum Knoten)', reach_icmp: 'ICMP (am Router)', reach_none: 'nur ausgehend',
			not_found: 'Diesen Knoten gibt es nicht (oder er ist gerade nicht öffentlich).', copied: 'Link kopiert',
			chart_none: 'Noch keine Verlaufsdaten.', ticker_empty: 'Noch keine Messungen in der letzten Stunde.',
			top_none: 'Noch keine Einträge.', matrix_none: 'Noch zu wenige Messungen für die Matrix.', days: '{n} Tage',
			geo_fail: 'Der Browser hat keinen Standort geliefert.', loss: 'Verlust', measurements: '{n} Messungen'
		},
		en: {
			loading: 'Loading …', unavailable: 'Data is currently not available.', updated: 'As of {time} · refreshed every 60 s', paused: 'PAUSED',
			t_new: 'New', t_stable: 'Stable', t_trusted: 'Trusted', t_pillar: 'Pillar', t_anchor: 'Anchor', t_quarantine: 'Quarantine',
			td_new: 'New (less than 7 days): measures and is measured, hardly counts in evaluations yet.',
			td_stable: 'Stable: at least 7 days, availability ≥ 90 %, plausible values – counts normally.',
			td_trusted: 'Trusted: at least 60 days, availability ≥ 97 %, hardly any deviations – counts double and is a reference for neighbours.',
			td_pillar: 'Pillar: at least 180 days, very stable and measured – reference target for new nodes.',
			td_anchor: 'Anchor: fixed measuring point run or approved by ipv64.',
			td_quarantine: 'Quarantine: keeps measuring, but does not count.',
			acc_fiber: 'Fibre', acc_dsl: 'DSL', acc_cable: 'Cable', acc_mobile: 'LTE/5G', acc_satellite: 'Satellite', acc_datacenter: 'Data centre', acc_other: 'Other',
			online: 'online', offline: 'offline', role_anchor: 'Anchor', role_node: 'Node',
			provider: 'Provider', access: 'Access', device: 'Device', place: 'Region', since: 'Member since', uptime: 'Availability (30 d)', anchors: 'To the anchors',
			links_n: '{n} connections in the last hour', node_page: 'To the node page', clear: 'Clear selection',
			outage: 'Outage', outage_asn: 'Provider', outage_region: 'Region', outage_since: 'since {time}', outage_aff: '{a} of {t} nodes affected',
			outages_none: 'No outages detected.', ongoing: 'ongoing',
			nodes_count: '{n} nodes', nodes_none: 'No nodes found.',
			reach_udp: 'UDP 6464 (to the node)', reach_icmp: 'ICMP (at the router)', reach_none: 'outgoing only',
			not_found: 'This node does not exist (or is not public right now).', copied: 'Link copied',
			chart_none: 'No history yet.', ticker_empty: 'No measurements in the last hour yet.',
			top_none: 'No entries yet.', matrix_none: 'Not enough measurements for the matrix yet.', days: '{n} days',
			geo_fail: 'The browser did not provide a location.', loss: 'Loss', measurements: '{n} measurements'
		}
	};

	function t(k, v) {
		var s = (TX[LANG] && TX[LANG][k]) || TX.de[k] || k;
		if (v) { Object.keys(v).forEach(function (n) { s = s.split('{' + n + '}').join(String(v[n])); }); }
		return s;
	}

	// ------------------------------------------------------------ reine Hilfen (auch fuer tests/web/sonar_test.js)

	function num(x) {
		var n = typeof x === 'number' ? x : (typeof x === 'string' && x.trim() !== '' ? Number(x) : NaN);
		return isFinite(n) ? n : null;
	}
	function str(x, max) {
		if (x === null || x === undefined || typeof x === 'object') { return ''; }
		var s = String(x).replace(/[\u0000-\u001f\u007f]/g, '');
		return s.length > max ? s.slice(0, max) : s;
	}
	function own(o, k) { return Object.prototype.hasOwnProperty.call(o, k); }
	/** Farbe nach Latenz: < 15 gruen, < 30 hellgruen, < 60 orange, sonst rot; unbekannt grau */
	function latClass(ms) {
		var v = num(ms);
		if (v === null || v < 0) { return 's64-l0'; }
		return v < 15 ? 's64-l1' : (v < 30 ? 's64-l2' : (v < 60 ? 's64-l3' : 's64-l4'));
	}
	function trustOf(x) { return TRUSTS.indexOf(x) >= 0 ? x : 'new'; }
	function locale() { return LANG === 'en' ? 'en-GB' : 'de-DE'; }
	function fmtNum(n, dec) {
		var v = num(n);
		if (v === null) { return '–'; }
		return v.toLocaleString(locale(), { minimumFractionDigits: dec || 0, maximumFractionDigits: dec || 0 });
	}
	function fmtMs(ms) { var v = num(ms); return v === null ? '–' : fmtNum(v, v < 10 ? 1 : 0) + ' ms'; }
	function fmtPct(x) { var v = num(x); return v === null ? '–' : fmtNum(Math.max(0, Math.min(1, v)) * 100, 1) + ' %'; }
	function parseTime(s) { if (typeof s !== 'string' || s.length > 40) { return null; } var d = Date.parse(s); return isFinite(d) ? d : null; }
	function fmtDate(ms) { return ms === null ? '–' : new Date(ms).toLocaleDateString(locale(), { year: 'numeric', month: '2-digit', day: '2-digit' }); }
	function fmtTime(ms) { return ms === null ? '–' : new Date(ms).toLocaleTimeString(locale(), { hour: '2-digit', minute: '2-digit' }); }
	function fmtDateTime(ms) { return ms === null ? '–' : fmtDate(ms) + ' ' + fmtTime(ms); }
	function project(p, lat, lon) { return [(lon - p.lon0) * p.kx, (p.lat0 - lat) * p.ky]; }
	function unproject(p, x, y) { return [p.lat0 - y / p.ky, x / p.kx + p.lon0]; }
	function asList(d, keys) {
		if (Array.isArray(d)) { return d; }
		if (d && typeof d === 'object') { for (var i = 0; i < keys.length; i++) { if (Array.isArray(d[keys[i]])) { return d[keys[i]]; } } }
		return [];
	}
	function trustName(x) { return t('t_' + trustOf(x)); }
	function accessName(a) { return ACCESS.indexOf(a) >= 0 ? t('acc_' + a) : ''; }
	function providerName(n) { return n.asname ? (n.asn ? 'AS' + n.asn + ' ' : '') + n.asname : (n.asn ? 'AS' + n.asn : '–'); }
	function anchorName(id) { return ANCHOR.test(id) ? id.slice(2).toUpperCase() : id; }
	function reachName(r) { return r === 'udp' ? t('reach_udp') : (r === 'icmp' ? t('reach_icmp') : t('reach_none')); }

	/** Knoten aus einer oeffentlichen Antwort (map, nodes, node, top) – nur bekannte Felder, Laengen begrenzt. */
	function normNode(n) {
		if (!n || typeof n !== 'object') { return null; }
		var id = str(n.id !== undefined ? n.id : n.node_id, 16);
		if (!NODEID.test(id)) { id = ''; }
		var slug = str(n.slug, 40);
		if (!SLUG.test(slug)) { slug = ''; }
		var am = {};
		if (n.anchor_ms && typeof n.anchor_ms === 'object' && !Array.isArray(n.anchor_ms)) {
			Object.keys(n.anchor_ms).slice(0, 8).forEach(function (k) { var v = num(n.anchor_ms[k]); if (ANCHOR.test(k) && v !== null && v >= 0) { am[k] = v; } });
		}
		var lat = num(n.lat !== undefined ? n.lat : n.pub_lat), lon = num(n.lon !== undefined ? n.lon : n.pub_lon);
		if (lat === null || lon === null || lat < -90 || lat > 90 || lon < -180 || lon > 180) { lat = null; lon = null; }
		var role = n.role === 'anchor' ? 'anchor' : 'node';
		var asn = num(n.asn !== undefined ? n.asn : n.asn4);
		return {
			id: id, slug: slug, name: str(n.name, 40) || id, role: role, trust: n.trust === undefined && role === 'anchor' ? 'anchor' : trustOf(n.trust),
			asn: asn !== null && asn > 0 && asn < 4294967296 ? Math.floor(asn) : null, asname: str(n.asname !== undefined ? n.asname : n.asname4, 100),
			access: ACCESS.indexOf(n.access) >= 0 ? n.access : '', device: str(n.device, 16), place: str(n.place, 80),
			since: parseTime(n.since !== undefined ? n.since : n.first_seen), uptime30: num(n.uptime30), online: n.online === true || n.online === 1,
			lat: lat, lon: lon, anchor_ms: am, reach4: str(n.reach4, 8), reach6: str(n.reach6, 8)
		};
	}
	function normLink(l, ids) {
		if (!l || typeof l !== 'object') { return null; }
		var a = str(l.a, 16), b = str(l.b, 16), ms = num(l.ms), n = num(l.n), loss = num(l.loss);
		if (!NODEID.test(a) || !NODEID.test(b) || a === b || (ids && (!ids[a] || !ids[b])) || (ms !== null && ms < 0)) { return null; }
		loss = loss === null ? (ms === null ? 1 : 0) : Math.max(0, Math.min(1, loss));
		if (ms === null && loss < 1) { return null; } // ohne Wert nur bei vollem Verlust (graue Linie)
		return { a: a, b: b, fam: l.fam === 6 ? 6 : 4, ms: ms, loss: loss, n: n === null ? 1 : Math.max(1, Math.floor(n)) };
	}
	function normOutage(o) {
		if (!o || typeof o !== 'object') { return null; }
		return {
			id: num(o.id), kind: o.kind === 'region' ? 'region' : 'asn', key: str(o.key !== undefined ? o.key : o.keyval, 32), label: str(o.label, 120),
			started: parseTime(o.started), ended: parseTime(o.ended), affected: num(o.affected), total: num(o.total)
		};
	}
	/** Verlauf je Anker und Adressfamilie: akzeptiert {a_x: [{hour, fam, ms, loss}]} oder [{hour, anchor, fam, ms}] */
	function normHistory(h) {
		var by = {};
		function add(id, p) {
			if (!ANCHOR.test(id) || !p || typeof p !== 'object') { return; }
			var tt = parseTime(p.hour !== undefined ? p.hour : (p.t !== undefined ? p.t : p.at));
			var ms = num(p.ms !== undefined ? p.ms : (p.p50_ms !== undefined ? p.p50_ms : (p.p50 !== undefined ? p.p50 : p.avg)));
			if (tt === null || ms === null || ms < 0) { return; }
			var loss = num(p.loss), key = id + (num(p.fam) === 6 ? '|6' : '|4');
			(by[key] = by[key] || []).push({ t: tt, ms: ms, loss: loss === null ? null : Math.max(0, Math.min(1, loss)) });
		}
		if (Array.isArray(h)) { h.slice(0, 5000).forEach(function (p) { if (p) { add(str(p.anchor !== undefined ? p.anchor : p.dst, 16), p); } }); }
		else if (h && typeof h === 'object') { Object.keys(h).forEach(function (k) { if (Array.isArray(h[k])) { h[k].slice(0, 2000).forEach(function (p) { add(k, p); }); } }); }
		var keys = Object.keys(by).sort(), fams = {};
		keys.forEach(function (k) { fams[k.slice(-1)] = true; });
		return keys.slice(0, 4).map(function (k) {
			var id = k.slice(0, -2);
			return { id: id, fam: Number(k.slice(-1)), label: anchorName(id) + (Object.keys(fams).length > 1 ? ' IPv' + k.slice(-1) : ''), pts: by[k].sort(function (x, y) { return x.t - y.t; }) };
		});
	}
	/** Verbindungen mit ms-Badge: die mit den meisten Messungen, lang genug fuer ein Badge */
	function pickBadges(links, pos, max, minLen) {
		return links.filter(function (l) {
			var a = pos[l.a], b = pos[l.b];
			return a && b && Math.hypot(a[0] - b[0], a[1] - b[1]) >= minLen;
		}).sort(function (x, y) { return y.n - x.n || (x.ms === null) - (y.ms === null) || x.ms - y.ms; }).slice(0, max);
	}
	function median(a) {
		if (!a.length) { return null; }
		var s = a.slice().sort(function (x, y) { return x - y; }), m = s.length >> 1;
		return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
	}
	/** Region-Schluessel "50.0,8.5" (Raster 0,5 Grad) -> [lat, lon], sonst null */
	function regionCell(key) {
		var m = /^(-?\d{1,2}(?:\.\d{1,3})?)[,_:\/](-?\d{1,3}(?:\.\d{1,3})?)$/.exec(key || '');
		if (!m) { return null; }
		var la = Number(m[1]), lo = Number(m[2]);
		return la >= -90 && la <= 90 && lo >= -180 && lo <= 180 ? [la, lo] : null;
	}

	// ------------------------------------------------------------ DOM-Hilfen

	function $(id) { return document.getElementById(id); }
	function el(tag, cls, text) {
		var e = document.createElement(tag);
		if (cls) { e.className = cls; }
		if (text !== undefined && text !== null) { e.textContent = String(text); }
		return e;
	}
	function sv(tag, attrs, text) {
		var e = document.createElementNS(SVGNS, tag);
		if (attrs) { Object.keys(attrs).forEach(function (k) { e.setAttribute(k, String(attrs[k])); }); }
		if (text !== undefined && text !== null) { e.textContent = String(text); }
		return e;
	}
	function clear(e) { while (e && e.firstChild) { e.removeChild(e.firstChild); } return e; }
	function badge(trust) { var k = trustOf(trust); return el('span', 's64-badge s64-t-' + k, trustName(k)); }
	function msBadge(ms) { return el('span', 's64-ms ' + latClass(ms), fmtMs(ms)); }
	function pageUrl(page, q) {
		var p = new URLSearchParams(q || {});
		if (LANG === 'en') { p.set('lang', 'en'); }
		var s = p.toString();
		return page + (s ? '?' + s : '');
	}
	function nodeLink(n) {
		if (!n.slug) { return el('span', '', n.name); }
		var a = el('a', '', n.name);
		a.href = pageUrl('node.php', { slug: n.slug });
		return a;
	}
	function rowMsg(tbody, cols, text) {
		clear(tbody);
		var tr = el('tr'), td = el('td', 'text-muted', text);
		td.colSpan = cols; tr.appendChild(td); tbody.appendChild(tr);
	}

	function getJSON(url, cb) {
		var ctl = typeof AbortController !== 'undefined' ? new AbortController() : null;
		var to = setTimeout(function () { if (ctl) { ctl.abort(); } }, 15000);
		fetch(url, { credentials: 'same-origin', headers: { Accept: 'application/json' }, signal: ctl ? ctl.signal : undefined })
			.then(function (r) {
				if (!r.ok) { var e = new Error('HTTP ' + r.status); e.status = r.status; throw e; }
				return r.json();
			})
			.then(function (j) { clearTimeout(to); cb(null, j && typeof j === 'object' && !Array.isArray(j) && own(j, 'data') ? j.data : j); })
			.catch(function (e) { clearTimeout(to); cb(e || new Error('fetch')); });
	}
	var geoCache = null;
	function loadGeo(cb) {
		if (geoCache) { cb(geoCache); return; }
		var root = $('s64');
		getJSON('de_map.json?v=' + encodeURIComponent((root && root.getAttribute('data-ver')) || '1'), function (err, g) {
			if (err || !g || !g.proj || !Array.isArray(g.land)) { cb(null); return; }
			var p = g.proj;
			if (!(num(p.kx) > 0 && num(p.ky) > 0 && num(p.w) > 0 && num(p.h) > 0)) { cb(null); return; }
			geoCache = g;
			cb(g);
		});
	}
	/** Land und Staedte in ein SVG (Pfade aus de_map.json enthalten nur Zahlen und M/Z, geprueft) */
	function drawLand(svg, g, cities, fs) {
		svg.setAttribute('viewBox', '0 0 ' + g.proj.w + ' ' + g.proj.h);
		var land = sv('g');
		g.land.forEach(function (d) { if (typeof d === 'string' && /^[MZ0-9 .\-]+$/.test(d)) { land.appendChild(sv('path', { d: d, 'class': 's64-land' })); } });
		svg.appendChild(land);
		if (cities && Array.isArray(g.cities)) {
			var cg = sv('g', { 'class': 's64-city' });
			g.cities.forEach(function (c) {
				var x = num(c.x), y = num(c.y);
				if (x === null || y === null) { return; }
				cg.appendChild(sv('circle', { cx: x, cy: y, r: 1.6 }));
				cg.appendChild(sv('text', { x: x + 4, y: y + 3.5, 'font-size': fs || 11 }, str(c.n, 30)));
			});
			svg.appendChild(cg);
		}
		return land;
	}
	function reducedMotion() { return !!(G.matchMedia && G.matchMedia('(prefers-reduced-motion: reduce)').matches); }

	function legendTrust(box, counts) {
		clear(box);
		['new', 'stable', 'trusted', 'pillar', 'anchor'].forEach(function (k) {
			var s = el('span');
			s.appendChild(el('span', 's64-sw s64-t-' + k));
			s.appendChild(document.createTextNode(trustName(k) + (counts && num(counts[k]) !== null ? ' ' + fmtNum(counts[k]) : '')));
			s.title = t('td_' + k);
			box.appendChild(s);
		});
	}
	function legendLat(box) {
		clear(box);
		[['s64-l1', '< 15 ms'], ['s64-l2', '< 30 ms'], ['s64-l3', '< 60 ms'], ['s64-l4', '≥ 60 ms']].forEach(function (x) {
			var s = el('span'); s.appendChild(el('span', 's64-sw ' + x[0])); s.appendChild(document.createTextNode(x[1])); box.appendChild(s);
		});
	}
	function fillStats(d) {
		if (!d || typeof d !== 'object') { return; }
		document.querySelectorAll('[data-s64-stat]').forEach(function (e) {
			var k = e.getAttribute('data-s64-stat');
			e.textContent = num(d[k]) === null ? '–' : fmtNum(d[k]);
		});
	}
	function outageBox(box, list) {
		clear(box);
		var act = list.filter(function (o) { return o.ended === null; });
		box.hidden = act.length === 0;
		act.slice(0, 10).forEach(function (o) {
			var a = el('div', 'alert alert-danger py-2 mb-2 small');
			a.setAttribute('role', 'alert');
			a.appendChild(el('i', 'fa-solid fa-triangle-exclamation'));
			a.appendChild(document.createTextNode(' '));
			a.appendChild(el('b', '', t('outage') + ' – ' + (o.kind === 'region' ? t('outage_region') : t('outage_asn')) + ': ' + (o.label || o.key)));
			var parts = [];
			if (o.started !== null) { parts.push(t('outage_since', { time: fmtDateTime(o.started) })); }
			if (o.affected !== null && o.total !== null) { parts.push(t('outage_aff', { a: fmtNum(o.affected), t: fmtNum(o.total) })); }
			if (parts.length) { a.appendChild(document.createTextNode(' · ' + parts.join(' · '))); }
			box.appendChild(a);
		});
	}

	// ------------------------------------------------------------ Karte (index.php)

	function pageMap() {
		var svg = $('s64Map'), info = $('s64Info'), ticker = $('s64Ticker'), upd = $('s64Updated'), live = $('s64Live');
		var st = { g: null, nodes: [], byId: {}, pos: {}, links: [], outages: [], sel: '', z: 1, cx: 0, cy: 0, last: 0, anim: 0 };
		var L = {};
		legendTrust($('s64LegendTrust'), null);
		legendLat($('s64LegendLat'));
		var infoDefault = info ? info.cloneNode(true) : null;

		loadGeo(function (g) {
			if (!g) { if (upd) { upd.textContent = t('unavailable'); } return; }
			st.g = g; st.cx = g.proj.w / 2; st.cy = g.proj.h / 2;
			drawLand(svg, g, true, 11);
			['out', 'links', 'sel', 'badges', 'anim', 'nodes'].forEach(function (k) { L[k] = sv('g'); svg.appendChild(L[k]); });
			bind();
			refresh();
			setInterval(function () { if (!document.hidden) { refresh(); } }, REFRESH);
			document.addEventListener('visibilitychange', function () { if (!document.hidden && Date.now() - st.last > REFRESH) { refresh(); } });
			if (!reducedMotion()) { st.anim = setInterval(animate, 1400); }
		});

		function refresh() {
			getJSON(API + 'map', function (err, d) {
				if (err || !d || typeof d !== 'object') {
					if (upd) { upd.textContent = t('unavailable'); }
					if (live) { live.className = 'badge badge-secondary align-middle'; live.textContent = t('paused'); }
					return;
				}
				st.last = Date.now();
				if (live) { live.className = 'badge badge-danger align-middle'; live.textContent = 'LIVE'; }
				var nodes = asList(d.nodes, []).slice(0, 20000).map(normNode).filter(function (n) { return n && n.id && n.lat !== null && n.trust !== 'quarantine'; });
				st.byId = {}; st.pos = {};
				nodes.forEach(function (n) { st.byId[n.id] = n; st.pos[n.id] = project(st.g.proj, n.lat, n.lon); });
				st.nodes = nodes;
				st.links = asList(d.links, []).slice(0, 2000).map(function (l) { return normLink(l, st.byId); }).filter(Boolean);
				st.outages = asList(d.outages, []).slice(0, 100).map(normOutage).filter(Boolean);
				outageBox($('s64Outages'), st.outages);
				if (upd) { upd.textContent = t('updated', { time: fmtTime(parseTime(d.generated) || Date.now()) }); }
				if (st.sel && !st.byId[st.sel]) { st.sel = ''; }
				draw();
				if (st.sel) { showInfo(st.byId[st.sel]); }
			});
			getJSON(API + 'stats', function (err, d) {
				if (err || !d) { return; }
				fillStats(d);
				if (d.by_trust && typeof d.by_trust === 'object') { legendTrust($('s64LegendTrust'), d.by_trust); }
			});
		}

		function k() { return 1 / st.z; }
		function draw() {
			var s = k();
			['out', 'links', 'sel', 'badges', 'nodes'].forEach(function (x) { clear(L[x]); });
			// Stoerungen: Region als Rasterfeld, Provider als Ring um die Knoten
			var outAsn = {};
			st.outages.forEach(function (o) {
				if (o.ended !== null) { return; }
				if (o.kind === 'asn' && /^\d{1,10}$/.test(o.key)) { outAsn[o.key] = true; }
				var c = o.kind === 'region' ? regionCell(o.key) : null;
				if (c) {
					var p1 = project(st.g.proj, c[0] + 0.5, c[1]), p2 = project(st.g.proj, c[0], c[1] + 0.5);
					var r = sv('rect', { x: p1[0], y: p1[1], width: p2[0] - p1[0], height: p2[1] - p1[1], 'class': 's64-outcell', 'stroke-width': s });
					r.appendChild(sv('title', null, t('outage') + ': ' + (o.label || o.key)));
					L.out.appendChild(r);
				}
			});
			svg.classList.toggle('s64-dim', !!st.sel);
			st.links.forEach(function (l) {
				var a = st.pos[l.a], b = st.pos[l.b];
				L.links.appendChild(sv('line', { x1: a[0], y1: a[1], x2: b[0], y2: b[1], 'class': 's64-link ' + latClass(l.ms), 'stroke-width': (0.7 + Math.min(1.6, l.n / 20)) * s }));
			});
			var sel = st.sel ? st.links.filter(function (l) { return l.a === st.sel || l.b === st.sel; }) : [];
			sel.forEach(function (l) {
				var a = st.pos[l.a], b = st.pos[l.b];
				L.sel.appendChild(sv('line', { x1: a[0], y1: a[1], x2: b[0], y2: b[1], 'class': 's64-link s64-sel ' + latClass(l.ms), 'stroke-width': 2.2 * s }));
			});
			var lab = st.sel ? pickBadges(sel, st.pos, 40, 18 * s) : pickBadges(st.links, st.pos, Math.round(30 * Math.min(3, st.z)), 46 * s);
			lab.forEach(function (l) { drawBadge(l, s); });
			// Knoten: Anker zuletzt (oben), Auswahl hervorgehoben
			st.nodes.slice().sort(function (x, y) { return (x.role === 'anchor') - (y.role === 'anchor'); }).forEach(function (n) {
				var p = st.pos[n.id], r = (n.role === 'anchor' ? 6.5 : (n.trust === 'pillar' ? 5 : 4.2)) * s;
				if (n.asn !== null && outAsn[String(n.asn)]) { L.nodes.appendChild(sv('circle', { cx: p[0], cy: p[1], r: r + 3 * s, 'class': 's64-outring', 'stroke-width': 1.6 * s })); }
				var c = n.role === 'anchor'
					? sv('rect', { x: p[0] - r * 0.8, y: p[1] - r * 0.8, width: r * 1.6, height: r * 1.6, transform: 'rotate(45 ' + p[0] + ' ' + p[1] + ')' })
					: sv('circle', { cx: p[0], cy: p[1], r: r });
				c.setAttribute('class', 's64-node s64-t-' + n.trust + (n.online || n.role === 'anchor' ? '' : ' s64-off') + (n.id === st.sel ? ' s64-hit' : ''));
				c.setAttribute('stroke-width', String((n.id === st.sel ? 2.2 : 1) * s));
				c.setAttribute('data-id', n.id);
				c.setAttribute('tabindex', '0');
				c.setAttribute('role', 'button');
				c.setAttribute('aria-label', n.name + ' – ' + trustName(n.trust));
				c.appendChild(sv('title', null, n.name + ' · ' + trustName(n.trust) + (n.asname ? ' · ' + n.asname : '')));
				L.nodes.appendChild(c);
			});
		}
		function drawBadge(l, s) {
			var a = st.pos[l.a], b = st.pos[l.b], x = (a[0] + b[0]) / 2, y = (a[1] + b[1]) / 2, txt = l.ms === null ? '✕' : fmtMs(l.ms);
			var fs = 8.5 * s, w = (txt.length * 4.9 + 6) * s, h = 11 * s;
			var g = sv('g', { 'class': 's64-mbadge ' + latClass(l.ms) });
			g.appendChild(sv('rect', { x: x - w / 2, y: y - h / 2, width: w, height: h, rx: h / 2 }));
			g.appendChild(sv('text', { x: x, y: y + 0.3 * s, 'font-size': fs }, txt));
			L.badges.appendChild(g);
		}

		function showInfo(n) {
			if (!info) { return; }
			clear(info);
			if (!n) { if (infoDefault) { Array.prototype.forEach.call(infoDefault.childNodes, function (c) { info.appendChild(c.cloneNode(true)); }); } return; }
			var head = el('div', 'd-flex flex-wrap align-items-center mb-1');
			head.style.gap = '.4rem';
			head.appendChild(el('b', 'h6 mb-0', n.name));
			head.appendChild(badge(n.trust));
			head.appendChild(el('span', 'badge ' + (n.online || n.role === 'anchor' ? 'badge-success' : 'badge-secondary'), n.online || n.role === 'anchor' ? t('online') : t('offline')));
			var x = el('button', 'btn btn-sm btn-link py-0 ml-auto');
			x.type = 'button'; x.title = t('clear'); x.appendChild(el('i', 'fa-solid fa-xmark'));
			x.addEventListener('click', function () { select(''); });
			head.appendChild(x);
			info.appendChild(head);
			var tb = el('table', 'table table-sm mb-1 s64-kv'), body = el('tbody');
			function row(k, v) { var tr = el('tr'); tr.appendChild(el('th', '', k)); var td = el('td'); if (typeof v === 'string') { td.textContent = v; } else { td.appendChild(v); } tr.appendChild(td); body.appendChild(tr); }
			row(t('provider'), providerName(n));
			if (n.role === 'anchor') { row(t('role_anchor'), t('td_anchor')); }
			row(t('access'), [accessName(n.access), n.device].filter(Boolean).join(' · ') || '–');
			if (n.place) { row(t('place'), n.place); }
			var am = el('span');
			Object.keys(n.anchor_ms).forEach(function (a) {
				var w = el('span', 'mr-2 text-nowrap');
				w.appendChild(document.createTextNode(anchorName(a) + ' '));
				w.appendChild(msBadge(n.anchor_ms[a]));
				am.appendChild(w);
			});
			if (!am.firstChild) { am.textContent = '–'; }
			if (n.role !== 'anchor') { row(t('anchors'), am); }
			tb.appendChild(body); info.appendChild(tb);
			var cnt = st.links.filter(function (l) { return l.a === n.id || l.b === n.id; }).length;
			info.appendChild(el('div', 'text-muted mb-1', t('links_n', { n: fmtNum(cnt) })));
			if (n.slug) { var a = nodeLink({ slug: n.slug, name: t('node_page') + ' →' }); info.appendChild(a); }
		}
		function select(id) {
			st.sel = id && st.byId[id] ? id : '';
			draw();
			showInfo(st.sel ? st.byId[st.sel] : null);
		}

		// Zoom (Knoepfe, Doppelklick) und Verschieben (Ziehen), Auswahl per Klick/Enter
		function setView() {
			var w = st.g.proj.w / st.z, h = st.g.proj.h / st.z;
			st.cx = Math.max(w / 2, Math.min(st.g.proj.w - w / 2, st.cx));
			st.cy = Math.max(h / 2, Math.min(st.g.proj.h - h / 2, st.cy));
			svg.setAttribute('viewBox', [st.cx - w / 2, st.cy - h / 2, w, h].map(function (v) { return Math.round(v * 10) / 10; }).join(' '));
			if (svg.parentNode && svg.parentNode.classList) { svg.parentNode.classList.toggle('s64-zoomed', st.z > 1); }
		}
		function zoom(f, cx, cy) {
			var z = f === 0 ? 1 : Math.max(1, Math.min(8, st.z * (f > 0 ? 1.6 : 1 / 1.6)));
			if (f === 0) { st.cx = st.g.proj.w / 2; st.cy = st.g.proj.h / 2; } else if (cx !== undefined) { st.cx = cx; st.cy = cy; }
			st.z = z;
			setView(); draw();
		}
		function svgPoint(ev) {
			var r = svg.getBoundingClientRect(), vb = svg.viewBox.baseVal;
			return [vb.x + (ev.clientX - r.left) / r.width * vb.width, vb.y + (ev.clientY - r.top) / r.height * vb.height];
		}
		function bind() {
			document.querySelectorAll('[data-s64-zoom]').forEach(function (b) {
				b.addEventListener('click', function () { zoom(Number(b.getAttribute('data-s64-zoom'))); });
			});
			svg.addEventListener('dblclick', function (ev) { var p = svgPoint(ev); zoom(1, p[0], p[1]); ev.preventDefault(); });
			var drag = null;
			svg.addEventListener('pointerdown', function (ev) { drag = { x: ev.clientX, y: ev.clientY, cx: st.cx, cy: st.cy, moved: false }; });
			svg.addEventListener('pointermove', function (ev) {
				if (!drag || st.z === 1) { return; }
				var dx = ev.clientX - drag.x, dy = ev.clientY - drag.y;
				if (Math.abs(dx) + Math.abs(dy) > 4) { drag.moved = true; }
				if (!drag.moved) { return; }
				var r = svg.getBoundingClientRect(), vb = svg.viewBox.baseVal;
				st.cx = drag.cx - dx / r.width * vb.width; st.cy = drag.cy - dy / r.height * vb.height;
				setView();
			});
			svg.addEventListener('pointerup', function (ev) {
				var moved = drag && drag.moved; drag = null;
				if (moved) { return; }
				var tg = ev.target && ev.target.closest ? ev.target.closest('[data-id]') : null;
				select(tg ? tg.getAttribute('data-id') : '');
			});
			svg.addEventListener('pointerleave', function () { drag = null; });
			svg.addEventListener('keydown', function (ev) {
				if (ev.key !== 'Enter' && ev.key !== ' ') { return; }
				var tg = ev.target && ev.target.getAttribute ? ev.target.getAttribute('data-id') : null;
				if (tg) { select(tg); ev.preventDefault(); }
			});
		}

		// Puls: eine Messung der letzten Stunde laeuft sichtbar von A nach B, am Ziel ein Ring; dazu die Liste
		function animate() {
			if (document.hidden || !st.links.length) {
				if (!st.links.length && ticker && !ticker.firstChild && st.last) { ticker.appendChild(el('div', 'text-muted', t('ticker_empty'))); }
				return;
			}
			var pool = st.sel ? st.links.filter(function (l) { return l.a === st.sel || l.b === st.sel; }) : st.links;
			if (!pool.length) { return; }
			var sum = 0; pool.forEach(function (l) { sum += l.n; });
			var r = Math.random() * sum, l = pool[0];
			for (var i = 0; i < pool.length; i++) { r -= pool[i].n; if (r <= 0) { l = pool[i]; break; } }
			var a = st.pos[l.a], b = st.pos[l.b], s = k(), cls = latClass(l.ms);
			if (!a || !b) { return; }
			var dot = sv('circle', { cx: a[0], cy: a[1], r: 2.2 * s, 'class': 's64-dot' });
			L.anim.appendChild(dot);
			var t0 = null, dur = 1100;
			function step(ts) {
				if (t0 === null) { t0 = ts; }
				var f = Math.min(1, (ts - t0) / dur), e = f < 0.5 ? 2 * f * f : 1 - Math.pow(-2 * f + 2, 2) / 2;
				dot.setAttribute('cx', String(a[0] + (b[0] - a[0]) * e)); dot.setAttribute('cy', String(a[1] + (b[1] - a[1]) * e));
				if (f < 1) { G.requestAnimationFrame(step); return; }
				dot.remove();
				var ring = sv('circle', { cx: b[0], cy: b[1], r: 4 * s, 'class': 's64-pulse ' + cls, 'stroke-width': 1.2 * s });
				L.anim.appendChild(ring);
				setTimeout(function () { ring.remove(); }, 1700);
			}
			G.requestAnimationFrame(step);
			if (ticker) {
				if (ticker.firstChild && ticker.firstChild.className === 'text-muted') { clear(ticker); }
				var na = st.byId[l.a], nb = st.byId[l.b], row = el('div', 's64-row');
				row.appendChild(msBadge(l.ms));
				row.appendChild(el('span', 's64-grow', na.name + ' → ' + nb.name));
				row.appendChild(el('span', 'text-muted', 'IPv' + l.fam));
				ticker.insertBefore(row, ticker.firstChild);
				while (ticker.childNodes.length > 14) { ticker.removeChild(ticker.lastChild); }
			}
		}
	}

	// ------------------------------------------------------------ Teilnehmer (nodes.php)

	function pageNodes() {
		var form = $('s64Filter'), body = $('s64Nodes'), cnt = $('s64Count');
		var st = { rows: [], sort: 'name', dir: 1 };
		var order = { anchor: 0, pillar: 1, trusted: 2, stable: 3, new: 4, quarantine: 5 };
		function params() {
			var q = {}, tr = $('s64fTrust').value, asn = $('s64fAsn').value.trim(), s = $('s64fQ').value.trim();
			if (['new', 'stable', 'trusted', 'pillar', 'anchor'].indexOf(tr) >= 0) { q.trust = tr; }
			if (/^\d{1,10}$/.test(asn)) { q.asn = asn; }
			if (/^[A-Za-z0-9 ._-]{1,32}$/.test(s)) { q.q = s; }
			return q;
		}
		function load() {
			var q = params();
			if (G.history && G.history.replaceState) { G.history.replaceState(null, '', pageUrl('nodes.php', q)); }
			rowMsg(body, 9, t('loading'));
			getJSON(API + 'nodes?' + new URLSearchParams(q).toString(), function (err, d) {
				if (err) { rowMsg(body, 9, t('unavailable')); if (cnt) { cnt.textContent = ''; } return; }
				st.rows = asList(d, ['nodes', 'items']).slice(0, 5000).map(normNode).filter(function (n) { return n && n.trust !== 'quarantine'; });
				render();
			});
		}
		function key(n) {
			switch (st.sort) {
				case 'trust': return order[n.trust];
				case 'uptime30': return n.uptime30 === null ? -1 : n.uptime30;
				case 'since': return n.since === null ? Infinity : n.since;
				case 'online': return n.online ? 0 : 1;
				case 'asname': return (n.asname || '').toLowerCase();
				case 'access': return accessName(n.access).toLowerCase();
				default: return String(n[st.sort] || '').toLowerCase();
			}
		}
		function render() {
			if (cnt) { cnt.textContent = t('nodes_count', { n: fmtNum(st.rows.length) }); }
			if (!st.rows.length) { rowMsg(body, 9, t('nodes_none')); return; }
			var cmp = function (x, y) { return typeof x === 'string' && typeof y === 'string' ? x.localeCompare(y, locale(), { numeric: true }) : (x < y ? -1 : (x > y ? 1 : 0)); };
			var rows = st.rows.slice().sort(function (a, b) { return cmp(key(a), key(b)) * st.dir || cmp(a.name, b.name); });
			clear(body);
			rows.forEach(function (n) {
				var tr = el('tr'), td = el('td');
				td.appendChild(nodeLink(n)); tr.appendChild(td);
				td = el('td'); td.appendChild(badge(n.trust)); tr.appendChild(td);
				tr.appendChild(el('td', '', providerName(n)));
				tr.appendChild(el('td', '', n.place || '–'));
				tr.appendChild(el('td', '', accessName(n.access) || '–'));
				tr.appendChild(el('td', '', n.device || '–'));
				tr.appendChild(el('td', 'text-right', fmtPct(n.uptime30)));
				tr.appendChild(el('td', 'text-nowrap', fmtDate(n.since)));
				td = el('td'); td.appendChild(el('span', 'badge ' + (n.online ? 'badge-success' : 'badge-secondary'), n.online ? t('online') : t('offline'))); tr.appendChild(td);
				body.appendChild(tr);
			});
		}
		document.querySelectorAll('[data-s64-sort]').forEach(function (th) {
			th.addEventListener('click', function () {
				var s = th.getAttribute('data-s64-sort');
				st.dir = st.sort === s ? -st.dir : (s === 'uptime30' ? -1 : 1); st.sort = s;
				document.querySelectorAll('[data-s64-sort]').forEach(function (x) { x.classList.remove('s64-asc', 's64-desc'); });
				th.classList.add(st.dir > 0 ? 's64-asc' : 's64-desc');
				render();
			});
		});
		form.addEventListener('submit', function (ev) { ev.preventDefault(); load(); });
		$('s64fTrust').addEventListener('change', load);
		load();
	}

	// ------------------------------------------------------------ Knotenseite (node.php)

	function pageNode(root) {
		var slug = root.getAttribute('data-slug') || '', msg = $('s64NodeMsg'), body = $('s64NodeBody');
		if (!SLUG.test(slug) || !body) { return; }
		msg.textContent = t('loading');
		getJSON(API + 'node/' + encodeURIComponent(slug), function (err, d) {
			if (err) {
				clear(msg);
				msg.appendChild(el('div', 'alert ' + (err.status === 404 ? 'alert-warning' : 'alert-danger'), err.status === 404 ? t('not_found') : t('unavailable')));
				return;
			}
			var src = d && d.node && typeof d.node === 'object' ? Object.assign({}, d.node, { history: d.history }) : d;
			var n = normNode(src);
			if (!n) { msg.textContent = t('unavailable'); return; }
			clear(msg); body.hidden = false;
			function f(k) { return body.querySelector('[data-s64-f="' + k + '"]'); }
			f('name').textContent = n.name;
			if (document.title !== undefined) { document.title = n.name + ' – Sonar64'; }
			clear(f('trust')).appendChild(badge(n.trust));
			clear(f('online')).appendChild(el('span', 'badge ' + (n.online || n.role === 'anchor' ? 'badge-success' : 'badge-secondary'), n.online || n.role === 'anchor' ? t('online') : t('offline')));
			f('provider').textContent = providerName(n);
			f('place').textContent = n.place || '–';
			f('access').textContent = [accessName(n.access), n.device].filter(Boolean).join(' · ') || '–';
			f('since').textContent = n.since === null ? '–' : fmtDate(n.since) + ' (' + t('days', { n: fmtNum(Math.max(0, Math.floor((Date.now() - n.since) / 86400000))) }) + ')';
			f('uptime30').textContent = fmtPct(n.uptime30);
			f('reach').textContent = 'IPv4: ' + reachName(n.reach4) + ' · IPv6: ' + reachName(n.reach6);
			var am = clear(f('anchors'));
			Object.keys(n.anchor_ms).forEach(function (a) { var w = el('span', 'mr-2 text-nowrap', anchorName(a) + ' '); w.appendChild(msBadge(n.anchor_ms[a])); am.appendChild(w); });
			if (!am.firstChild) { am.textContent = '–'; }
			f('trustinfo').textContent = t('td_' + n.trust);
			var share = $('s64Share');
			if (share) {
				share.addEventListener('click', function () {
					if (navigator.clipboard) { navigator.clipboard.writeText(G.location.href).then(function () { share.title = t('copied'); share.classList.add('btn-success'); }, function () {}); }
				});
			}
			var series = normHistory(src.history);
			drawChart($('s64Chart'), $('s64ChartTip'), series);
			summary($('s64ChartSum'), series);
			loadGeo(function (g) {
				var svg = $('s64Mini');
				if (!g || !svg) { return; }
				drawLand(svg, g, true, 16);
				if (n.lat !== null) {
					var p = project(g.proj, n.lat, n.lon);
					svg.appendChild(sv('circle', { cx: p[0], cy: p[1], r: 14, 'class': 's64-pinring' }));
					svg.appendChild(sv('circle', { cx: p[0], cy: p[1], r: 5, 'class': 's64-pin' }));
				}
			});
		});
	}
	function summary(tbody, series) {
		if (!tbody) { return; }
		clear(tbody);
		series.forEach(function (s, i) {
			var ms = s.pts.map(function (p) { return p.ms; }), ls = s.pts.map(function (p) { return p.loss; }).filter(function (x) { return x !== null; });
			var tr = el('tr'), td = el('td');
			td.appendChild(el('span', 's64-c' + i, '● '));
			td.appendChild(document.createTextNode(s.label));
			tr.appendChild(td);
			var c = el('td', 'text-right'); c.appendChild(msBadge(median(ms))); tr.appendChild(c);
			tr.appendChild(el('td', 'text-right', fmtMs(Math.min.apply(null, ms))));
			tr.appendChild(el('td', 'text-right', fmtMs(Math.max.apply(null, ms))));
			tr.appendChild(el('td', 'text-right', ls.length ? fmtPct(ls.reduce(function (a, b) { return a + b; }, 0) / ls.length) : '–'));
			tr.appendChild(el('td', 'text-right', fmtNum(s.pts.length)));
			tbody.appendChild(tr);
		});
		if (!series.length) { rowMsg(tbody, 6, t('chart_none')); }
	}
	/** Linien je Anker ueber 7 Tage; Luecken > 2 h unterbrechen die Linie; Zeiger zeigt die Werte der Stunde */
	function drawChart(box, tip, series) {
		if (!box) { return; }
		clear(box);
		if (!series.length) { box.appendChild(el('p', 'small text-muted mb-0', t('chart_none'))); return; }
		var W = 800, H = 220, l = 44, r = 10, tp = 10, b = 24;
		var t1 = Date.now(), t0 = t1 - 7 * 86400000, max = 0;
		series.forEach(function (s) { s.pts.forEach(function (p) { if (p.t >= t0 && p.ms > max) { max = p.ms; } }); });
		var step = max <= 20 ? 5 : (max <= 50 ? 10 : (max <= 100 ? 20 : (max <= 250 ? 50 : 100)));
		var ymax = Math.max(step, Math.ceil(max * 1.1 / step) * step);
		function X(tt) { return l + (tt - t0) / (t1 - t0) * (W - l - r); }
		function Y(ms) { return tp + (1 - ms / ymax) * (H - tp - b); }
		var svg = sv('svg', { viewBox: '0 0 ' + W + ' ' + H, role: 'img', 'aria-label': t('anchors') });
		for (var v = 0; v <= ymax; v += step) {
			svg.appendChild(sv('line', { x1: l, x2: W - r, y1: Y(v), y2: Y(v), 'class': 's64-grid' }));
			svg.appendChild(sv('text', { x: l - 6, y: Y(v) + 4, 'text-anchor': 'end' }, v + ' ms'));
		}
		var d0 = new Date(t0); d0.setHours(24, 0, 0, 0);
		for (var d = d0.getTime(); d < t1; d += 86400000) {
			svg.appendChild(sv('line', { x1: X(d), x2: X(d), y1: tp, y2: H - b, 'class': 's64-grid' }));
			svg.appendChild(sv('text', { x: X(d) + 3, y: H - 8 }, new Date(d).toLocaleDateString(locale(), { weekday: 'short', day: '2-digit', month: '2-digit' })));
		}
		series.forEach(function (s, i) {
			var dd = '', prev = null;
			s.pts.forEach(function (p) {
				if (p.t < t0) { return; }
				dd += (prev === null || p.t - prev > 2 * 3600000 ? 'M' : 'L') + X(p.t).toFixed(1) + ' ' + Y(p.ms).toFixed(1) + ' ';
				prev = p.t;
			});
			if (dd) { svg.appendChild(sv('path', { d: dd.trim(), 'class': 's64-series s64-c' + i })); }
		});
		var cur = sv('line', { x1: -10, x2: -10, y1: tp, y2: H - b, 'class': 's64-cursor' });
		svg.appendChild(cur);
		svg.addEventListener('mousemove', function (ev) {
			var rc = svg.getBoundingClientRect(), x = (ev.clientX - rc.left) / rc.width * W;
			if (x < l || x > W - r) { return; }
			var tt = t0 + (x - l) / (W - l - r) * (t1 - t0), parts = [];
			series.forEach(function (s) {
				var best = null;
				s.pts.forEach(function (p) { if (Math.abs(p.t - tt) < 5400000 && (best === null || Math.abs(p.t - tt) < Math.abs(best.t - tt))) { best = p; } });
				if (best) { parts.push(s.label + ' ' + fmtMs(best.ms) + (best.loss ? ' (' + t('loss') + ' ' + fmtPct(best.loss) + ')' : '')); }
			});
			cur.setAttribute('x1', String(x)); cur.setAttribute('x2', String(x));
			if (tip) { tip.textContent = fmtDateTime(tt) + (parts.length ? ' · ' + parts.join(' · ') : ''); }
		});
		box.appendChild(svg);
	}

	// ------------------------------------------------------------ Bestenliste (top.php)

	function pageTop() {
		function stats() {
			getJSON(API + 'stats', function (err, d) {
				if (err || !d) { return; }
				fillStats(d);
				var box = $('s64ByTrust');
				if (box && d.by_trust && typeof d.by_trust === 'object') { legendTrust(box, d.by_trust); }
			});
		}
		function outages() {
			getJSON(API + 'outages', function (err, d) {
				var body = $('s64OutageList');
				if (err) { rowMsg(body, 5, t('unavailable')); return; }
				var list = asList(d, ['outages', 'items']).slice(0, 200).map(normOutage).filter(Boolean);
				outageBox($('s64Outages'), list);
				if (!list.length) { rowMsg(body, 5, t('outages_none')); return; }
				clear(body);
				list.slice(0, 50).forEach(function (o) {
					var tr = el('tr', o.ended === null ? 'table-danger' : '');
					tr.appendChild(el('td', '', o.kind === 'region' ? t('outage_region') : t('outage_asn')));
					tr.appendChild(el('td', '', o.label || o.key));
					tr.appendChild(el('td', 'text-nowrap', fmtDateTime(o.started)));
					tr.appendChild(el('td', 'text-nowrap', o.ended === null ? t('ongoing') : fmtDateTime(o.ended)));
					tr.appendChild(el('td', 'text-right', o.affected !== null && o.total !== null ? fmtNum(o.affected) + ' / ' + fmtNum(o.total) : '–'));
					body.appendChild(tr);
				});
			});
		}
		function nodeTable(id, list, value) {
			var body = $(id);
			if (!list.length) { rowMsg(body, 3, t('top_none')); return; }
			clear(body);
			list.slice(0, 20).forEach(function (n, i) {
				var tr = el('tr');
				tr.appendChild(el('td', 'text-muted text-right', String(i + 1)));
				var td = el('td'); td.appendChild(nodeLink(n)); td.appendChild(document.createTextNode(' ')); td.appendChild(badge(n.trust));
				if (n.asname) { td.appendChild(el('div', 'text-muted', n.asname)); }
				tr.appendChild(td);
				tr.appendChild(el('td', 'text-right text-nowrap', value(n)));
				body.appendChild(tr);
			});
		}
		getJSON(API + 'top', function (err, d) {
			if (err || !d || typeof d !== 'object') { ['s64TopReliable', 's64TopLongest'].forEach(function (id) { rowMsg($(id), 3, t('unavailable')); }); rowMsg($('s64TopProviders'), 4, t('unavailable')); return; }
			var norm = function (x) { return asList(x, []).slice(0, 50).map(normNode).filter(function (n) { return n && n.trust !== 'quarantine'; }); };
			nodeTable('s64TopReliable', norm(d.reliable !== undefined ? d.reliable : d.most_reliable), function (n) { return fmtPct(n.uptime30); });
			nodeTable('s64TopLongest', norm(d.longest !== undefined ? d.longest : d.longest_running), function (n) { return n.since === null ? '–' : t('days', { n: fmtNum(Math.floor((Date.now() - n.since) / 86400000)) }); });
			var prov = asList(d.providers !== undefined ? d.providers : d.by_provider, []).slice(0, 50), body = $('s64TopProviders');
			if (!prov.length) { rowMsg(body, 4, t('top_none')); return; }
			clear(body);
			prov.forEach(function (p) {
				if (!p || typeof p !== 'object') { return; }
				var tr = el('tr'), asn = num(p.asn);
				var a = el('a', '', providerName({ asn: asn, asname: str(p.asname !== undefined ? p.asname : p.name, 100) }));
				if (asn !== null && asn > 0) { a.href = pageUrl('nodes.php', { asn: String(Math.floor(asn)) }); }
				var td = el('td'); td.appendChild(a); tr.appendChild(td);
				tr.appendChild(el('td', 'text-right', fmtNum(p.nodes)));
				tr.appendChild(el('td', 'text-right', fmtNum(p.online)));
				var best = normNode(p.best), c = el('td');
				if (best) { c.appendChild(nodeLink(best)); c.appendChild(document.createTextNode(' ' + fmtPct(best.uptime30))); } else { c.textContent = '–'; }
				tr.appendChild(c);
				body.appendChild(tr);
			});
		});
		getJSON(API + 'matrix', function (err, d) {
			var box = $('s64Matrix');
			document.querySelectorAll('[data-s64-latlegend]').forEach(legendLat);
			if (err || !d) { clear(box).appendChild(el('span', 'small text-muted', t('unavailable'))); return; }
			var asns = asList(d.asns, []).slice(0, 30).map(function (a) { return a && typeof a === 'object' ? { asn: num(a.asn), name: str(a.name !== undefined ? a.name : a.asname, 100) } : null; })
				.filter(function (a) { return a && a.asn !== null && a.asn > 0; });
			var cells = {};
			asList(d.cells, []).slice(0, 2000).forEach(function (c) { if (c && num(c.a) !== null && num(c.b) !== null && num(c.avg) !== null) { cells[num(c.a) + ':' + num(c.b)] = { ms: num(c.avg), n: num(c.n) }; } });
			clear(box);
			if (asns.length < 2 || !Object.keys(cells).length) { box.appendChild(el('span', 'small text-muted', t('matrix_none'))); return; }
			var tb = el('table', 'table table-sm table-bordered mb-0 small s64-matrix'), head = el('tr');
			head.appendChild(el('th'));
			asns.forEach(function (a) { var th = el('th', 's64-colh', a.name || 'AS' + a.asn); th.title = 'AS' + a.asn + ' ' + a.name; head.appendChild(th); });
			var thead = el('thead'); thead.appendChild(head); tb.appendChild(thead);
			var body = el('tbody');
			asns.forEach(function (ra) {
				var tr = el('tr'), th = el('th', 's64-rowh', ra.name || 'AS' + ra.asn);
				th.title = 'AS' + ra.asn; tr.appendChild(th);
				asns.forEach(function (ca) {
					var c = cells[ra.asn + ':' + ca.asn] || cells[ca.asn + ':' + ra.asn], td = el('td');
					if (c) { td.appendChild(msBadge(c.ms)); td.title = (ra.name || 'AS' + ra.asn) + ' → ' + (ca.name || 'AS' + ca.asn) + (c.n !== null ? ' · ' + t('measurements', { n: fmtNum(c.n) }) : ''); }
					else { td.textContent = '·'; td.className = 'text-muted'; }
					tr.appendChild(td);
				});
				body.appendChild(tr);
			});
			tb.appendChild(body); box.appendChild(tb);
		});
		stats(); outages();
		setInterval(function () { if (!document.hidden) { stats(); outages(); } }, REFRESH);
	}

	// ------------------------------------------------------------ Mein Knoten (me.php): Standort per Karte

	function pageMe() {
		var svg = $('s64Pick'), lat = $('s64Lat'), lon = $('s64Lon'), geo = $('s64Geo');
		if (!svg || !lat || !lon) { return; }
		loadGeo(function (g) {
			if (!g) { svg.hidden = true; return; }
			drawLand(svg, g, true, 18);
			var ring = sv('circle', { r: 16, 'class': 's64-pinring' }), pin = sv('circle', { r: 6, 'class': 's64-pin' });
			ring.style.display = pin.style.display = 'none';
			svg.appendChild(ring); svg.appendChild(pin);
			function show() {
				var la = num(lat.value.replace(',', '.')), lo = num(lon.value.replace(',', '.'));
				var ok = la !== null && lo !== null && la >= -90 && la <= 90 && lo >= -180 && lo <= 180;
				ring.style.display = pin.style.display = ok ? '' : 'none';
				if (!ok) { return; }
				var p = project(g.proj, la, lo);
				[ring, pin].forEach(function (c) { c.setAttribute('cx', String(p[0])); c.setAttribute('cy', String(p[1])); });
			}
			svg.addEventListener('click', function (ev) {
				var r = svg.getBoundingClientRect(), vb = svg.viewBox.baseVal;
				var ll = unproject(g.proj, vb.x + (ev.clientX - r.left) / r.width * vb.width, vb.y + (ev.clientY - r.top) / r.height * vb.height);
				lat.value = ll[0].toFixed(5); lon.value = ll[1].toFixed(5);
				show();
			});
			lat.addEventListener('input', show); lon.addEventListener('input', show);
			show();
			if (geo) {
				geo.addEventListener('click', function () {
					if (!navigator.geolocation) { geo.title = t('geo_fail'); return; }
					navigator.geolocation.getCurrentPosition(function (pos) {
						lat.value = pos.coords.latitude.toFixed(5); lon.value = pos.coords.longitude.toFixed(5); show();
					}, function () { geo.title = t('geo_fail'); geo.classList.add('btn-outline-danger'); }, { enableHighAccuracy: false, timeout: 10000, maximumAge: 600000 });
				});
			}
		});
	}

	// ------------------------------------------------------------ Start

	function common() {
		document.querySelectorAll('[data-s64-copy]').forEach(function (b) {
			b.addEventListener('click', function () {
				var i = $(b.getAttribute('data-s64-copy'));
				if (!i) { return; }
				i.select();
				if (navigator.clipboard) { navigator.clipboard.writeText(i.value).catch(function () {}); }
			});
		});
		document.querySelectorAll('form[data-s64-confirm]').forEach(function (f) {
			f.addEventListener('submit', function (ev) { if (!G.confirm(f.getAttribute('data-s64-confirm'))) { ev.preventDefault(); } });
		});
	}
	function start() {
		var root = $('s64');
		if (!root) { return; }
		LANG = root.getAttribute('data-lang') === 'en' ? 'en' : 'de';
		common();
		var p = root.getAttribute('data-page');
		if (p === 'map') { pageMap(); } else if (p === 'nodes') { pageNodes(); } else if (p === 'node') { pageNode(root); }
		else if (p === 'top') { pageTop(); } else if (p === 'me') { pageMe(); }
	}

	var api = { latClass: latClass, trustOf: trustOf, fmtMs: fmtMs, fmtPct: fmtPct, project: project, unproject: unproject, normNode: normNode, normLink: normLink,
		normOutage: normOutage, normHistory: normHistory, pickBadges: pickBadges, median: median, regionCell: regionCell, asList: asList, providerName: providerName,
		setLang: function (l) { LANG = l === 'en' ? 'en' : 'de'; }, t: t };
	if (typeof module !== 'undefined' && module.exports) { module.exports = api; }
	if (typeof document !== 'undefined') {
		if (document.readyState === 'loading') { document.addEventListener('DOMContentLoaded', start); } else { start(); }
	}
}(typeof window !== 'undefined' ? window : this));
