/* Monitor64: Oberflaeche aller Seiten (Uebersicht, Host mit Diensten und Diagrammen, Probleme, Wartung, Schwellen,
 * Benachrichtigung, Einstellungen, Assistent "Host hinzufuegen"). Aufbau wie im abgenommenen Entwurf.
 * Startdaten und Texte kommen aus #m64-data (JSON), Aenderungen ueber /api/monitor64/... mit X-CSRF-Token.
 * Texte von Hosts werden immer escaped (esc) bzw. als textContent gesetzt. */
(function () {
'use strict';
var root = document.getElementById('m64');
var dataEl = document.getElementById('m64-data');
if (!root || !dataEl) { return; }
var D = {};
try { D = JSON.parse(dataEl.textContent || '{}') || {}; } catch (e) { D = {}; }
var TX = D.t || {};

// ---------- Hilfen ----------
function hasText(k) { return Object.prototype.hasOwnProperty.call(TX, k) && typeof TX[k] === 'string' && TX[k] !== ''; }
function L(k, a) {
	var s = hasText(k) ? TX[k] : k; // nur eigene Texte: "constructor" u. ae. aus Geraetetexten sind keine Schluessel
	if (a) { Object.keys(a).forEach(function (n) { s = s.split('{' + n + '}').join(a[n]); }); }
	return s;
}
function esc(s) {
	return String(s === undefined || s === null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; });
}
// splitTarget: "group|Name" am ersten | trennen (Gruppen und Tags duerfen selbst | enthalten).
function splitTarget(v) { var i = String(v).indexOf('|'); return i < 0 ? [String(v), ''] : [v.slice(0, i), v.slice(i + 1)]; }
function $(sel, ctx) { return (ctx || document).querySelector(sel); }
function $$(sel, ctx) { return Array.prototype.slice.call((ctx || document).querySelectorAll(sel)); }
var LOC = D.lang === 'de' ? 'de-DE' : (D.lang || undefined);
function fmtNum(v, d) {
	if (v === null || v === undefined || isNaN(v)) { return '–'; }
	if (d === undefined) { d = Math.abs(v) < 10 && v % 1 !== 0 ? (Math.abs(v) < 0.1 ? 3 : 1) : 0; }
	return Number(v).toLocaleString(LOC, { minimumFractionDigits: 0, maximumFractionDigits: d });
}
// parseNum liest eine Zahl unabhaengig von der Sprache: genau ein Komma oder Punkt ist der Dezimaltrenner
// ("3.5" und "3,5" = 3,5); Tausendertrenner nur bei eindeutigem Muster ("1.000.000", "1.234,5", "1,234.5").
// Leer = null, alles andere (Buchstaben, "1,2,3") = NaN -> Fehlermeldung statt stiller Umdeutung.
function thousandsOK(s, t) { return new RegExp('^\\d{1,3}(\\' + t + '\\d{3})+$').test(s); }
function parseNum(s) {
	s = String(s === undefined || s === null ? '' : s).replace(/[\s  ']/g, '');
	if (s === '') { return null; }
	var sign = '';
	if (s.charAt(0) === '-' || s.charAt(0) === '+') { sign = s.charAt(0) === '-' ? '-' : ''; s = s.slice(1); }
	if (!/^[0-9.,]+$/.test(s) || !/[0-9]/.test(s)) { return NaN; }
	var dots = (s.match(/\./g) || []).length, commas = (s.match(/,/g) || []).length;
	if (dots && commas) {
		var dec = s.lastIndexOf('.') > s.lastIndexOf(',') ? '.' : ',', th = dec === '.' ? ',' : '.', parts = s.split(dec);
		if (parts.length !== 2 || !thousandsOK(parts[0], th)) { return NaN; }
		s = parts[0].split(th).join('') + '.' + parts[1];
	} else if (dots + commas > 1) {
		var t = dots ? '.' : ',';
		if (!thousandsOK(s, t)) { return NaN; }
		s = s.split(t).join('');
	} else if ((dots ? '.' : ',') === (LOC === 'de-DE' ? '.' : ',') && /^[1-9][0-9]{0,2}[.,][0-9]{3}$/.test(s)) {
		s = s.replace(/[.,]/, ''); // einzelner Tausendertrenner der Sprache ("1.000" auf Deutsch, "1,000" auf Englisch)
	} else {
		s = s.replace(',', '.');
	}
	var v = Number(sign + s);
	return isFinite(v) ? v : NaN;
}
// Geraete-APIs (Prometheus, NUT, TrueNAS, Unraid, Redfish, Proxmox Mail Gateway, mailcow): zusaetzliche Felder je Zugangsart.
var DEVAPI = ['prom', 'nut', 'truenas', 'unraid', 'redfish', 'pmg', 'mailcow', 'fritzbox'];
var DEVSPEC = {
	prom: { url: 'http://{a}:9100/metrics', user: true, extra: ['metrics'] },
	nut: { url: '{a}:3493', user: true, extra: ['ups', 'tls'] },
	truenas: { url: 'https://{a}', user: true, extra: ['api'] },
	unraid: { url: 'http://{a}', user: false, extra: [] },
	redfish: { url: 'https://{a}', user: true, extra: ['session'] },
	pmg: { url: 'https://{a}:8006', user: true, extra: [] },
	mailcow: { url: 'https://{a}', user: false, extra: [] },
	fritzbox: { url: 'https://{a}:49443', user: true, extra: [] }
};
// urlHost: Host-Teil einer URL aus der Adresse eines Hosts - ein Port der Adresse entfaellt, IPv6 kommt in Klammern
// ("nas:2222" -> "nas", "2001:db8::1" und "[2001:db8::1]:22" -> "[2001:db8::1]").
function urlHost(a) {
	a = String(a || '').trim();
	var m = /^\[([^\]]+)\](?::\d+)?$/.exec(a);
	if (m) { return '[' + m[1] + ']'; }
	if ((a.match(/:/g) || []).length >= 2) { return '[' + a + ']'; }
	return a.replace(/:\d+$/, '');
}
function devURL(t, addr) { return DEVSPEC[t].url.replace('{a}', urlHost(addr) || '10.0.0.21'); }
// Texte je Art und Feld (ausgeschrieben, damit die Pruefung der Texte sie findet)
function devSecretHint(t) { return { prom: L('acc.secret_prom'), nut: L('acc.secret_nut'), truenas: L('acc.secret_truenas'), unraid: L('acc.secret_unraid'), redfish: L('acc.secret_redfish'), pmg: L('acc.secret_pmg'), mailcow: L('acc.secret_mailcow'), fritzbox: L('acc.secret_fritzbox') }[t]; }
function devHint(t) { return { prom: L('new.hint_prom'), nut: L('new.hint_nut'), truenas: L('new.hint_truenas'), unraid: L('new.hint_unraid'), redfish: L('new.hint_redfish'), pmg: L('new.hint_pmg'), mailcow: L('new.hint_mailcow'), fritzbox: L('new.hint_fritzbox') }[t]; }
function devText(k) {
	return { ups: L('acc.ups'), tls: L('acc.tls'), api: L('acc.api'), session: L('acc.session'), metrics: L('acc.metrics'), tls_auto: L('acc.tls_auto'), tls_require: L('acc.tls_require'), tls_off: L('acc.tls_off'),
		api_auto: L('acc.api_auto'), api_jsonrpc: L('acc.api_jsonrpc'), api_rest: L('acc.api_rest') }[k];
}
// devFields: Zusatzfelder. p = "af": Host-Seite, alle Felder mit data-af (Werte aus der Konfiguration c);
// p = "w": Assistent, nur die Felder der Art t (Werte aus dem Zustand c, data-w).
function devFields(c, p, t) {
	c = c || {};
	var ids = p === 'w' ? DEVSPEC[t].extra : ['ups', 'tls', 'api', 'session', 'metrics'];
	var owner = { ups: 'nut', tls: 'nut', api: 'truenas', session: 'redfish', metrics: 'prom' };
	var val = function (id) { return id === 'metrics' && p === 'af' ? (c.metrics ? JSON.stringify(c.metrics, null, 1) : '') : c[id] || ''; };
	var attr = function (id) { return ' id="m64-' + p + '-' + id + '"' + (p === 'w' ? ' data-w="' + id + '"' : ''); };
	var opts = function (id, list) { return list.map(function (x) { return '<option value="' + x + '"' + (val(id) === x ? ' selected' : '') + '>' + esc(devText(id + '_' + (x || 'auto'))) + '</option>'; }).join(''); };
	return ids.map(function (id) {
		var lab = '<label class="form-label" for="m64-' + p + '-' + id + '">' + esc(devText(id)) + '</label>', inner, cls = 'col-md-6';
		if (id === 'ups') { inner = lab + '<input class="form-control"' + attr(id) + ' maxlength="512" value="' + esc(val(id)) + '" placeholder="ups1, ups2"><div class="form-text">' + esc(L('acc.ups_hint')) + '</div>'; }
		if (id === 'tls') { inner = lab + '<select class="form-select"' + attr(id) + '>' + opts(id, ['', 'require', 'off']) + '</select>'; }
		if (id === 'api') { inner = lab + '<select class="form-select"' + attr(id) + '>' + opts(id, ['', 'jsonrpc', 'rest']) + '</select>'; }
		if (id === 'session') { cls = 'col-12'; inner = '<div class="form-check"><input class="form-check-input" type="checkbox"' + attr(id) + (val(id) ? ' checked' : '') + '><label class="form-check-label small" for="m64-' + p + '-session">' + esc(devText('session')) + '</label></div>'; }
		if (id === 'metrics') { cls = 'col-12'; inner = lab + '<textarea class="form-control font-monospace small"' + attr(id) + ' rows="3" spellcheck="false" placeholder="' + esc('[{"name":"nginx_connections_active","title":"Verbindungen"}]') + '">' + esc(val(id)) + '</textarea><div class="form-text">' + esc(L('acc.metrics_hint')) + '</div>'; }
		return '<div class="' + cls + '"' + (p === 'af' ? ' data-af="' + owner[id] + '"' : '') + '>' + inner + '</div>';
	}).join('');
}
// devCfg: Konfiguration der Zusatzfelder einer Art aus get(id) (null = eigene Metriken kein gueltiges JSON-Array).
function devCfg(t, get) {
	var o = {}, spec = DEVSPEC[t];
	if (spec.user) { o.user = get('user') || ''; }
	for (var i = 0; i < spec.extra.length; i++) {
		var id = spec.extra[i], v = get(id);
		if (id === 'session') { o.session = !!v; continue; }
		if (id === 'metrics') {
			if (!v) { continue; }
			try { o.metrics = JSON.parse(v); } catch (e) { return null; }
			if (!Array.isArray(o.metrics)) { return null; }
			continue;
		}
		o[id] = v || '';
	}
	return o;
}
// SNMP: Felder des Zugangs (p = "af": Host-Seite, p = "w": Assistent mit data-w="s_<feld>"). Community bzw.
// v3-Passwoerter werden einzeln eingegeben und als ein Geheimnis (JSON) gesendet; leere Felder behalten beim Aendern
// den gespeicherten Wert.
var SNMP_AUTH = ['SHA256', 'SHA', 'SHA224', 'SHA384', 'SHA512', 'MD5'];
var SNMP_PRIV = ['AES', 'AES256', 'AES192', 'AES256C', 'AES192C', 'DES'];
var SNMP_PASS = ['community', 'authpass', 'privpass'];
// snmpVal: Wert eines Feldes aus der gespeicherten Konfiguration (Geheimnisse nie).
function snmpVal(c, x) {
	c = c || {};
	var v = { version: c.snmp_version || '2c', port: c.port || '', user: c.user || '', level: c.level || 'authPriv', auth: c.auth_proto || 'SHA256', priv: c.priv_proto || 'AES',
		context: c.context || '', traps: !!c.traps, engine: c.trap_engine_id || '', custom: c.custom ? JSON.stringify(c.custom, null, 1) : '', profiles: c.profiles || '' }[x];
	return v === undefined ? '' : v;
}
function snmpLevelText(v) { return { authPriv: L('acc.snmp_level_priv'), authNoPriv: L('acc.snmp_level_auth'), noAuthNoPriv: L('acc.snmp_level_none') }[v]; }
// snmpFields: Formular; get(x) liefert den Startwert, stored = Geheimnis gespeichert (Platzhalter "unveraendert").
function snmpFields(p, get, stored) {
	var id = function (x) { return 'm64-' + p + '-s' + x; };
	var at = function (x) { return ' id="' + id(x) + '"' + (p === 'w' ? ' data-w="s_' + x + '"' : ''); };
	var lab = function (x, t) { return '<label class="form-label" for="' + id(x) + '">' + esc(t) + '</label>'; };
	var sel = function (x, list, txt) { return '<select class="form-select"' + at(x) + '>' + list.map(function (v) { return '<option value="' + esc(v) + '"' + (v === get(x) ? ' selected' : '') + '>' + esc(txt ? txt(v) : v) + '</option>'; }).join('') + '</select>'; };
	var pass = function (x, t) { return lab(x, t) + '<input class="form-control" type="password" autocomplete="new-password" maxlength="256"' + at(x) + (p === 'w' ? ' value="' + esc(get(x)) + '"' : '') + (stored && (x === 'community') === (get('version') !== '3') ? ' placeholder="' + esc(L('acc.secret_keep')) + '"' : '') + '>'; }; // Platzhalter nur beim Geheimnis der gespeicherten Version
	var txt = function (x, t, attrs) { return lab(x, t) + '<input class="form-control"' + at(x) + ' value="' + esc(get(x)) + '"' + (attrs || '') + '>'; };
	var open = get('context') || get('engine') || get('custom');
	return '<div class="col-md-6">' + lab('version', L('acc.snmp_version')) + sel('version', ['3', '2c', '1'], function (v) { return 'SNMP v' + v; }) + '</div>' +
		'<div class="col-md-6">' + txt('port', L('acc.port'), ' type="number" min="1" max="65535" placeholder="161"') + '</div>' +
		'<div class="col-md-6" data-snmp="c">' + pass('community', L('acc.snmp_community')) + '</div>' +
		'<div class="col-12 small text-warning-emphasis" data-snmp="c"><i class="bi bi-unlock"></i> ' + esc(L('acc.snmp_warn_v2c')) + '</div>' +
		'<div class="col-md-6" data-snmp="v3">' + txt('user', L('acc.snmp_user'), ' maxlength="32"') + '</div>' +
		'<div class="col-md-6" data-snmp="v3">' + lab('level', L('acc.snmp_level')) + sel('level', ['authPriv', 'authNoPriv', 'noAuthNoPriv'], snmpLevelText) + '</div>' +
		'<div class="col-md-6" data-snmp="auth">' + lab('auth', L('acc.snmp_auth')) + sel('auth', SNMP_AUTH) + '</div>' +
		'<div class="col-md-6" data-snmp="auth">' + pass('authpass', L('acc.snmp_auth_pass')) + '</div>' +
		'<div class="col-md-6" data-snmp="priv">' + lab('priv', L('acc.snmp_priv')) + sel('priv', SNMP_PRIV) + '</div>' +
		'<div class="col-md-6" data-snmp="priv">' + pass('privpass', L('acc.snmp_priv_pass')) + '</div>' +
		'<div class="col-12"><div class="form-check"><input class="form-check-input" type="checkbox"' + at('traps') + (get('traps') ? ' checked' : '') + '><label class="form-check-label small" for="' + id('traps') + '">' + esc(L('acc.snmp_traps')) + '</label></div>' +
		'<div class="form-text">' + esc(L('acc.snmp_traps_hint')) + '</div></div>' +
		'<div class="col-12"><details' + (open ? ' open' : '') + '><summary class="small text-body-secondary">' + esc(L('advanced')) + '</summary><div class="pt-2 row g-2">' +
		'<div class="col-md-6" data-snmp="v3">' + txt('context', L('acc.snmp_context'), ' maxlength="32"') + '</div>' +
		'<div class="col-md-6" data-snmp="v3">' + txt('engine', L('acc.snmp_engine'), ' maxlength="66" placeholder="80001f88…"') + '</div>' +
		'<div class="col-12">' + lab('custom', L('acc.snmp_custom')) + '<textarea class="form-control font-monospace small"' + at('custom') + ' rows="3" spellcheck="false" placeholder="' + esc('[{"oid":"1.3.6.1.4.1.2021.10.1.5.1","name":"Load 1 min","factor":0.01}]') + '">' + esc(get('custom')) + '</textarea>' +
		'<div class="form-text">' + esc(L('acc.snmp_custom_hint')) + '</div></div></div></details></div>';
}
// snmpShow blendet die Felder nach Version und Stufe ein.
function snmpShow(box, p) {
	var v = $('#m64-' + p + '-sversion', box), l = $('#m64-' + p + '-slevel', box);
	if (!v) { return; }
	var v3 = v.value === '3', lv = l ? l.value : 'authPriv';
	$$('[data-snmp]', box).forEach(function (x) {
		var k = x.dataset.snmp, on = k === 'c' ? !v3 : k === 'v3' ? v3 : k === 'auth' ? v3 && lv !== 'noAuthNoPriv' : v3 && lv === 'authPriv';
		x.classList.toggle('d-none', !on);
	});
}
// snmpRead liest Konfiguration und Geheimnis aus get(x) (null = eigene OIDs kein gueltiges JSON-Array).
function snmpRead(get) {
	var v = get('version') || '2c', cfg = { snmp_version: v }, sec = {}, port = parseInt(get('port'), 10);
	if (port) { cfg.port = port; }
	if (v === '3') {
		cfg.user = get('user') || '';
		cfg.level = get('level') || 'authPriv';
		if (cfg.level !== 'noAuthNoPriv') { cfg.auth_proto = get('auth') || 'SHA256'; if (get('authpass')) { sec.auth = get('authpass'); } }
		if (cfg.level === 'authPriv') { cfg.priv_proto = get('priv') || 'AES'; if (get('privpass')) { sec.priv = get('privpass'); } }
		cfg.context = get('context') || '';
		cfg.trap_engine_id = get('engine') || '';
	} else if (get('community')) {
		sec.community = get('community');
	}
	cfg.traps = !!get('traps');
	var cu = get('custom');
	if (cu) {
		try { cfg.custom = JSON.parse(cu); } catch (e) { return null; }
		if (!Array.isArray(cfg.custom)) { return null; }
	}
	var pr = get('profiles'); // feste Profile (nur in der gespeicherten Konfiguration, kein Formularfeld): beim Aendern behalten
	if (Array.isArray(pr) && pr.length) { cfg.profiles = pr.slice(); }
	return { config: cfg, secret: Object.keys(sec).length ? JSON.stringify(sec) : '' };
}
// snmpTestHTML: Ergebnis "Verbindung testen" bei SNMP (Geraeteart, Profile mit Hinweis "nicht geprueft", Abfragen).
function snmpTestHTML(r) {
	if (!r.ok || (!r.device && !(r.profiles || []).length && !(r.queries || []).length)) { return ''; }
	var dev = { nas: L('acc.snmp_dev_nas'), ups: L('acc.snmp_dev_ups'), printer: L('acc.snmp_dev_printer'), 'switch': L('acc.snmp_dev_switch'), router: L('acc.snmp_dev_router'),
		ap: L('acc.snmp_dev_ap'), server: L('acc.snmp_dev_server'), device: L('acc.snmp_dev_device') }[r.device] || r.device || '';
	var html = dev ? '<div class="small mt-1">' + esc(L('acc.snmp_device', { d: dev })) + '</div>' : '';
	(r.profiles || []).forEach(function (pr) {
		html += '<div class="small">' + esc(L('acc.snmp_profile', { p: pr.name })) + (pr.verified ? '' : ' <span class="badge text-bg-light" title="' + esc(L('acc.snmp_unverified')) + '">' + esc(L('acc.snmp_unverified_short')) + '</span>') + '</div>';
	});
	if ((r.queries || []).length) {
		html += '<details class="small mt-1"><summary class="text-body-secondary">' + esc(L('acc.snmp_queries')) + '</summary><ul class="mb-0 ps-3">' + r.queries.map(function (q) { return '<li>' + esc(q) + '</li>'; }).join('') + '</ul></details>';
	}
	return html;
}
// numIn zeigt einen Wert exakt im Eingabefeld (ohne Rundung der Anzeige; Dezimalkomma auf Deutsch).
function numIn(v) {
	if (v === null || v === undefined || v === 'off' || isNaN(v)) { return ''; }
	var s = String(+Number(v).toPrecision(12));
	return LOC === 'de-DE' ? s.replace('.', ',') : s;
}
// tx uebersetzt Texte des Kerns und der Sammler (wie model.Translate in Go): Token
// "i18n:monitor64.detail.vanished?since=2026-11-09T10:00:00Z", auch mehrere mit festen Teilen dazwischen
// ("ONLINE · i18n:monitor64.txt.free?v=3+GB"). Werte sind URL-kodiert; since/at sind Zeitpunkte und werden
// formatiert, ein Wert mit Token wird mit uebersetzt. Nur Schluessel unter monitor64. zaehlen; das Ergebnis enthaelt
// keine Token mehr (txRaw entschaerft den Rest). Der Aufrufer escaped danach wie bisher.
var reI18n = /i18n:([a-z0-9_]+(?:\.[a-z0-9_]+)*)(?:\?([A-Za-z0-9%+=&_.~-]*))?/g;
function txRaw(s) { return s.replace(/i18n:(?=[a-z0-9_])/g, 'i18n: '); }
// Die Sammler schreiben Groessen mit Komma ("4,4 GB"): ausserhalb des Deutschen vor einer Einheit als Punkt zeigen.
var reDec = /(\d),(\d{1,2})(?=\s?(?:%|°C|[KMGTP]?B\/s|[KMGTP]?B(?![A-Za-z])|[kMG]?bit\/s))/g;
function tx(s) {
	s = txT(s, 0);
	return D.lang === 'de' ? s : s.replace(reDec, '$1.$2');
}
function txT(s, depth) {
	if (s === undefined || s === null) { return ''; }
	s = String(s);
	if (s.indexOf('i18n:') < 0) { return s; }
	depth = depth > 0 ? depth : 0;
	if (depth > 4) { return txRaw(s); }
	return s.replace(reI18n, function (all, key, q) {
		if (key.indexOf('monitor64.') !== 0) { return txRaw(all); }
		var k = key.slice(10), a = {}, vals = [];
		if (q) {
			try {
				new URLSearchParams(q).forEach(function (v, n) { a[n] = (n === 'since' || n === 'at') && toDate(v) ? fmtTime(v) : txT(v, depth + 1); vals.push(a[n]); });
			} catch (e) { return txRaw(all); }
		}
		if (!hasText(k)) { return vals.length ? k + ' (' + vals.join(', ') + ')' : k; }
		return L(k, a);
	});
}
function quote(t) { return L('quote', { t: tx(t) }); }
function fmtBytes(b) {
	if (b === null || b === undefined) { return '–'; }
	var u = ['B', 'kB', 'MB', 'GB', 'TB', 'PB'], i = 0;
	while (Math.abs(b) >= 1000 && i < u.length - 1) { b /= 1000; i++; }
	return fmtNum(b, b < 10 && i > 0 ? 1 : 0) + ' ' + u[i];
}
function fmtVal(v, unit) {
	switch (unit) {
	case '%': return fmtNum(v) + ' %';
	case '°C': return fmtNum(v, 1) + ' °C';
	case 'B': return fmtBytes(v);
	case 'B/s': return fmtBytes(v) + '/s';
	case 'Mbit/s': return v >= 1000 ? fmtNum(v / 1000, 1) + ' Gbit/s' : fmtNum(v, v < 10 ? 1 : 0) + ' Mbit/s';
	case '': case undefined: case null: return fmtNum(v);
	}
	return fmtNum(v) + ' ' + unit;
}
function pad(x) { return (x < 10 ? '0' : '') + x; }
function toDate(s) { var d = s instanceof Date ? s : new Date(s); return isNaN(d.getTime()) || d.getFullYear() < 2000 ? null : d; }
function fmtTime(s) {
	var d = toDate(s); if (!d) { return '–'; }
	var now = new Date(), y = new Date(now.getTime() - 86400000), hm = pad(d.getHours()) + ':' + pad(d.getMinutes());
	if (d.toDateString() === now.toDateString()) { return L('time.today', { t: hm }); }
	if (d.toDateString() === y.toDateString()) { return L('time.yesterday', { t: hm }); }
	return fmtDay(d, d.getFullYear() !== now.getFullYear()) + ' ' + hm;
}
// fmtDay: Tag und Monat (optional Jahr) im Format der Sprache (de 09.11., en 11/09).
function fmtDay(d, year) {
	var o = { day: '2-digit', month: '2-digit' };
	if (year) { o.year = '2-digit'; }
	try { return d.toLocaleDateString(LOC, o); } catch (e) { return pad(d.getDate()) + '.' + pad(d.getMonth() + 1) + '.'; }
}
function fmtDur(sec) {
	sec = Math.max(0, Math.round(sec || 0));
	var d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60);
	var out = [];
	if (d) { out.push(d === 1 ? L('du.day', { n: d }) : L('du.days', { n: d })); }
	if (h) { out.push(L('du.h', { n: h })); }
	if (!d && (m || !h)) { out.push(L('du.m', { n: m })); }
	return out.join(' ');
}
function since(s) { var d = toDate(s); return d ? L('time.since', { d: fmtDur((Date.now() - d.getTime()) / 1000) }) : ''; }
function ago(s) { var d = toDate(s); return d ? L('time.ago', { d: fmtDur((Date.now() - d.getTime()) / 1000) }) : ''; }
function cssVar(n) { return getComputedStyle(document.documentElement).getPropertyValue(n).trim(); }
var ST = { ok: L('state.ok'), warn: L('state.warn'), crit: L('state.crit'), unknown: L('state.unknown'), unreachable: L('state.unreachable') };
function stLabel(s) { return ST[s] || s; }
function stBadge(s, txt) { var c = s === 'unreachable' ? 'unknown' : s; return '<span class="st-badge ' + esc(c) + '">' + esc(txt || stLabel(s)) + '</span>'; }
function tag(t) { return '<span class="tag">' + esc(t) + '</span>'; }
function kindLabel(k) { return (D.kind_labels && D.kind_labels[k]) || k; }
function kindMeta(k) { var r = null; (D.kinds || []).forEach(function (x) { if (x.kind === k) { r = x; } }); return r; }
function accLabel(t) { return (D.access_labels && D.access_labels[t]) || t; }
function targetLabel(tt, t) { return tt === 'tag' ? L('target.tag', { n: t }) : L('target.group', { n: t }); }

function toast(text, bad) {
	var t = document.getElementById('m64-toast'), x = document.getElementById('m64-toast-text');
	if (!t || !x || !window.bootstrap) { return; }
	x.textContent = text;
	t.className = 'toast align-items-center border-0 ' + (bad ? 'text-bg-danger' : 'text-bg-success');
	window.bootstrap.Toast.getOrCreateInstance(t, { delay: bad ? 5000 : 2500 }).show();
}
// api: JSON-Anfrage; Fehler kommen als {error, message} und werden als Meldung gezeigt.
function api(method, url, body) {
	var opt = { method: method, credentials: 'same-origin', headers: { 'Accept': 'application/json' } };
	if (method !== 'GET') { opt.headers['X-CSRF-Token'] = D.csrf || ''; }
	if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
	return fetch(url, opt).then(function (r) {
		return r.json().catch(function () { return {}; }).then(function (j) {
			if (r.status === 401 || r.status === 403) { var se = new Error(L('err_session')); se.code = 'session'; se.session = true; throw se; }
			if (!r.ok) {
				var msg = j.message || (j.error === 'internal' ? L('err.internal') : j.error) || ('HTTP ' + r.status);
				var e = new Error(msg); e.code = j.error; throw e;
			}
			return j;
		});
	});
}
function fail(e) { toast(e && e.message ? tx(e.message) : String(e), true); }
// failQuiet: Fehler bei Hintergrund-Aktualisierungen nur zeigen, wenn die Sitzung abgelaufen ist (einmal).
var sessionShown = false;
function failQuiet(e) { if (e && e.session && !sessionShown) { sessionShown = true; fail(e); } }
// lock sperrt einen Knopf, bis die Aktion fertig ist (kein doppeltes Absenden per Doppelklick).
function lock(btn, fn) {
	if (btn && btn.disabled) { return Promise.resolve(); }
	if (btn) { btn.disabled = true; }
	var p;
	try { p = Promise.resolve(fn()); } catch (e) { p = Promise.reject(e); }
	return p.then(function (v) { if (btn) { btn.disabled = false; } return v; }, function (e) { if (btn) { btn.disabled = false; } throw e; });
}

// modal: Dialog mit eigenem Inhalt; buttons = [{label, cls, click(close)}].
var modalEl = document.getElementById('m64-modal');
function modal(title, body, buttons, wide) {
	if (!modalEl || !window.bootstrap) { return null; }
	$('#m64-modal-title').textContent = title;
	// frischer Koerper je Dialog: Klick-Handler frueherer Dialoge (mit deren Zugang) haengen sonst weiter daran
	var oldBody = $('#m64-modal-body'), freshBody = oldBody.cloneNode(false);
	oldBody.parentNode.replaceChild(freshBody, oldBody);
	freshBody.innerHTML = body;
	$('.modal-dialog', modalEl).classList.toggle('modal-lg', !!wide);
	var foot = $('#m64-modal-foot');
	foot.innerHTML = '';
	var inst = window.bootstrap.Modal.getOrCreateInstance(modalEl);
	(buttons || []).forEach(function (b) {
		var btn = document.createElement('button');
		btn.type = 'button';
		btn.className = 'btn ' + (b.cls || 'btn-outline-secondary');
		btn.textContent = b.label;
		btn.onclick = function () {
			if (!b.click) { inst.hide(); return; }
			lock(btn, function () { return b.click(function () { inst.hide(); }, btn); }).catch(fail);
		};
		foot.appendChild(btn);
	});
	inst.show();
	return $('#m64-modal-body');
}
function confirmBox(title, text, okLabel, cb) {
	modal(title, '<p class="mb-0">' + esc(text) + '</p>', [{ label: L('cancel') }, { label: okLabel, cls: 'btn-danger', click: function (close) { return Promise.resolve(cb()).then(close); } }]);
}
function store(k, v) { try { if (v === undefined) { return localStorage.getItem('m64.' + k); } localStorage.setItem('m64.' + k, v); } catch (e) {} return null; }
function spark(vals, cls) {
	if (!vals || vals.length < 2) { return ''; }
	var min = Math.min.apply(null, vals), max = Math.max.apply(null, vals), rg = (max - min) || 1, pts = [];
	for (var i = 0; i < vals.length; i++) { pts.push((i / (vals.length - 1) * 100).toFixed(1) + ',' + (26 - (vals[i] - min) / rg * 24).toFixed(1)); }
	return '<svg class="spark ' + (cls || '') + '" viewBox="0 0 100 28" preserveAspectRatio="none" aria-hidden="true"><polygon points="0,28 ' + pts.join(' ') + ' 100,28"/><polyline points="' + pts.join(' ') + '"/></svg>';
}
function who(a) {
	a = a || {};
	if (a.kind === 'system') { return '<span class="who"><span class="who-av sys"><i class="bi bi-cpu"></i></span>' + esc(L('who.system')) + '</span>'; }
	if (a.kind === 'api') { return '<span class="who"><span class="who-av sys"><i class="bi bi-key"></i></span>' + esc(L('who.api', { n: a.name || '' })) + '</span>'; }
	if (!a.name) { return ''; }
	var m = a.method ? ' <span class="who-m">' + esc(a.method === 'sso' ? L('method.sso') : a.method === 'ldap' ? L('method.ldap') : L('method.local')) + '</span>' : '';
	return '<span class="who"><span class="who-av">' + esc(a.name.slice(0, 2).toUpperCase()) + '</span>' + esc(a.name) + m + '</span>';
}
function whoTxt(a) {
	a = a || {};
	if (a.kind === 'system') { return L('who.system'); }
	if (a.kind === 'api') { return L('who.api', { n: a.name || '' }); }
	return a.name || '';
}
// Cluster: welche Node einen Host ueberwacht (HostView.cluster: node, name, here, reporting, reachable, note, at).
// selfName = Name dieser Node (der Kern liefert ihn fuer eigene Hosts nicht mit).
function clName(ref, selfName) { return ref.name || (ref.here ? selfName : '') || ref.node || ''; }
function clBy(ref, selfName) {
	if (!ref) { return ''; }
	var n = clName(ref, selfName);
	return '<span class="text-nowrap" title="' + esc(L('cluster.by', { n: n })) + '"><i class="bi bi-diagram-3"></i> ' + esc(n) + '</span>';
}
function clNote(ref, selfName) {
	if (!ref) { return ''; }
	var n = clName(ref, selfName);
	switch (ref.note) {
	case 'owner_unreachable': return L('cluster.note.owner_unreachable', { n: n });
	case 'no_data': return L('cluster.note.no_data', { n: n });
	case 'measure_only': return L('cluster.note.measure_only');
	}
	return !ref.here && !ref.reporting ? L('cluster.note.remote_measure', { n: n }) : '';
}
function clRole(r) { return { report: L('cluster.role.report'), measure: L('cluster.role.measure'), idle: L('cluster.role.idle') }[r] || r || ''; }
// clOrphans: Hinweis-Karte der Uebersicht "Hosts ohne ueberwachende Node" (ihre Node gehoert nicht mehr zum Cluster):
// dieser Node zuweisen oder entfernen, einzeln und alle - nie automatisch. list: [{uid, name, address, reason,
// node_name}], reload: Stand danach neu laden.
var clOrphReload = null;
function clOrphans(list, reload) {
	var box = $('#m64-orphans');
	if (!box) { return; }
	clOrphReload = reload;
	list = list || [];
	var sig = JSON.stringify(list);
	if (box.dataset.sig === sig) { return; } // unveraendert: nicht neu zeichnen (gesperrter Knopf und Fokus bleiben)
	box.dataset.sig = sig;
	if (!box.dataset.bound) {
		box.dataset.bound = '1';
		box.addEventListener('click', function (ev) { var b = ev.target.closest('[data-orph]'); if (b) { ev.stopPropagation(); clOrphAct(b); } });
	}
	if (!list.length) { box.innerHTML = ''; return; }
	box.innerHTML = '<div class="card border-warning mb-3"><div class="card-header d-flex flex-wrap align-items-center gap-2 py-2"><span class="fw-semibold"><i class="bi bi-diagram-3"></i> ' + esc(L('cluster.orph_title', { n: list.length })) + '</span>' +
		'<span class="ms-auto d-flex flex-wrap gap-2"><button class="btn btn-sm btn-outline-primary" type="button" data-orph="assign"><i class="bi bi-box-arrow-in-down"></i> ' + esc(L('cluster.orph_assign_all')) + '</button>' +
		'<button class="btn btn-sm btn-outline-danger" type="button" data-orph="remove" data-n="' + list.length + '"><i class="bi bi-trash"></i> ' + esc(L('cluster.orph_remove_all')) + '</button></span></div>' +
		'<div class="card-body small py-2"><div class="text-body-secondary">' + esc(L('cluster.orph_hint')) + '</div><div class="list-group list-group-flush mt-1">' + list.map(function (o) {
			var why = o.reason === 'no_candidate' ? L('cluster.orph_no_candidate', { n: o.node_name || o.node }) : L('cluster.orph_node_gone', { n: o.node_name || o.node });
			return '<div class="list-group-item px-0 d-flex flex-wrap align-items-center gap-2"><div class="me-auto min-w-0"><a class="fw-semibold" href="/monitor64/host/' + encodeURIComponent(o.uid) + '">' + esc(o.name) + '</a>' + (o.address ? ' <span class="text-body-secondary">' + esc(o.address) + '</span>' : '') +
				'<div class="text-body-secondary">' + esc(why) + '</div></div>' +
				'<button class="btn btn-sm btn-outline-primary" type="button" data-orph="assign" data-uid="' + esc(o.uid) + '">' + esc(L('cluster.orph_assign')) + '</button>' +
				'<button class="btn btn-sm btn-outline-danger" type="button" data-orph="remove" data-uid="' + esc(o.uid) + '" data-name="' + esc(o.name) + '">' + esc(L('cluster.orph_remove')) + '</button></div>';
		}).join('') + '</div></div></div>';
}
function clOrphAct(btn) {
	var act = btn.dataset.orph === 'remove' ? 'remove' : 'assign', uid = btn.dataset.uid || '';
	function run() {
		return api('POST', '/api/monitor64/cluster/orphans/' + act, uid ? { uids: [uid] } : { all: true }).then(function (r) {
			toast(act === 'remove' ? L('cluster.orph_removed_toast', { n: r.done }) : L('cluster.orph_assigned_toast', { n: r.done }));
			return clOrphReload ? clOrphReload() : null;
		});
	}
	if (act === 'remove') { // entfernen nur nach Bestaetigung (einzeln und alle)
		confirmBox(uid ? L('cluster.orph_remove') : L('cluster.orph_remove_all'), uid ? L('cluster.orph_remove_confirm', { n: btn.dataset.name || '' }) : L('cluster.orph_remove_all_confirm', { n: btn.dataset.n || '' }),
			uid ? L('cluster.orph_remove') : L('cluster.orph_remove_all'), function () { return run().catch(fail); });
		return;
	}
	lock(btn, run).catch(fail);
}
// Schwellen (eval.Effective: Zahl oder "off")
function lim(x) { return x === 'off' || x === undefined || x === null ? null : x; }
function durLabel(sec) {
	sec = sec || 0;
	if (!sec) { return L('dur.0'); }
	return fmtDur(sec);
}
function srcLabel(lv) {
	if (!lv) { return ''; }
	var e = lv.eff, f = e.mode === 'free' ? 'warn_free' : 'warn', st = (e.origin && e.origin[f]) || 'default';
	if (st === 'override' && lv.override) { return { t: targetLabel(lv.override.target_type, lv.override.target), own: false }; }
	if (st === 'host') { return { t: L('src.host_kind'), own: true }; }
	if (st === 'service') { return { t: L('src.service'), own: true }; }
	return { t: L('src.default'), own: false };
}
function thrVals(e, unit) {
	if (!e) { return ''; }
	var m = kindMeta(e.kind) || {}, f = m.factor || 1, u = m.unit === 'min' ? L('unit.min') : m.unit === 'days' ? L('unit.days') : (unit || m.unit || '');
	if (e.mode === 'free') {
		var wf = lim(e.warn_free), cf = lim(e.crit_free);
		return '&lt; ' + (wf === null ? '–' : fmtNum(wf)) + ' / &lt; ' + (cf === null ? '–' : fmtNum(cf)) + ' ' + esc(L('unit.gb_free'));
	}
	var w = lim(e.warn), c = lim(e.crit), op = e.dir === 'down' ? '&lt;' : '≥';
	return op + ' ' + (w === null ? '–' : fmtNum(w / f)) + ' / ' + op + ' ' + (c === null ? '–' : fmtNum(c / f)) + (u ? ' ' + esc(u) : '');
}
function sevLabel(s) { return s === 'crit' ? ST.crit : s === 'warn' ? ST.warn : L('rl.sev_off'); }

// ---------- Uebersicht ----------
function pageOverview() {
	// group: null = alle, '' = ohne Gruppe, sonst der Name (gespeichert als JSON)
	var OV = { group: null, only: store('only') === '1', q: '', view: store('view') || 'tiles' };
	try { var gs = store('groupsel'); OV.group = gs ? JSON.parse(gs) : null; } catch (e) { OV.group = null; }
	if (OV.group !== null && typeof OV.group !== 'string') { OV.group = null; }
	var data = D.overview || { hosts: [], problems: [], recent: [], counts: {}, groups: [] };
	var sparks = {}, CLV = D.cluster || { refs: {} };
	function clRef(h) { return (CLV.refs || {})[h.uid] || null; }
	function clOn() { return !!(CLV.active || Object.keys(CLV.refs || {}).length); }
	function statCard(cls, label, val, sub, icon) {
		return '<div class="col-6 col-md-3"><div class="card stat ' + cls + '"><div class="card-body"><div class="stat-text"><div class="stat-label">' + esc(label) + '</div><div class="stat-value">' + esc(String(val)) + '</div><div class="stat-sub">' + esc(sub) + '</div></div><i class="bi ' + icon + ' stat-icon"></i></div></div></div>';
	}
	function meter(m) {
		var cls = m.state === 'crit' ? 'crit' : m.state === 'warn' ? 'warn' : '';
		return '<div class="meter"><span class="meter-label">' + esc(m.label === 'cpu' ? L('ov.m_cpu') : m.label === 'ram' ? L('ov.m_ram') : L('ov.m_disk')) + '</span><div class="bar"><span class="' + cls + '" style="width:' + Math.max(0, Math.min(100, m.value)) + '%"></span></div><span class="meter-val">' + fmtNum(m.value, 0) + ' %</span></div>';
	}
	function hostState(h) { return h.view === 'unreachable' ? 'unknown' : h.state; }
	function tile(h) {
		var st = hostState(h), foot, ref = clRef(h), note = clNote(ref, CLV.self_name), away = ref && (ref.note === 'owner_unreachable' || ref.note === 'no_data');
		if (away) { st = 'unknown'; }
		if (away && !h.maint && !h.paused) { foot = stBadge('unknown'); }
		else if (h.maint) { foot = '<span class="st-badge maint"><i class="bi bi-cone-striped"></i> ' + esc(L('ov.maint')) + '</span>'; }
		else if (h.paused) { foot = '<span class="st-badge unknown"><i class="bi bi-pause-circle"></i> ' + esc(L('ov.paused')) + '</span>'; }
		else if (h.view === 'unreachable') { foot = stBadge('unknown', L('state.unreachable')); }
		else if (h.problems) { foot = stBadge(st, h.problems === 1 ? L('ov.problem_one') : L('ov.problem_n', { n: h.problems })); }
		else if (!h.checked) { foot = '<span class="small text-body-secondary">' + esc(L('ov.waiting')) + '</span>'; }
		else { foot = '<span class="small text-body-secondary">' + esc(L('ov.services_ok', { n: h.services })) + '</span>'; }
		var body = '';
		if (away) { body = ''; } // Stand der zustaendigen Node fehlt: nur der Hinweis
		else if (h.view === 'unreachable') { body = '<div class="small text-body-secondary mt-2"><i class="bi bi-plug"></i> ' + esc(tx(h.unreach) || L('state.unreachable')) + '</div>'; }
		else {
			body = (h.meters || []).map(meter).join('');
			if (!body && h.text) { body = '<div class="small text-body-secondary mt-2 text-truncate">' + esc(tx(h.text)) + '</div>'; }
			if (sparks[h.uid]) { body += '<div class="mt-2">' + spark(sparks[h.uid], st === 'ok' ? '' : 's-' + st) + '</div>'; }
		}
		if (note) { body += '<div class="small text-body-secondary mt-2" data-cl-note><i class="bi bi-diagram-3"></i> ' + esc(note) + '</div>'; }
		var extra = '';
		if (h.new) { extra += ' <span class="badge text-bg-primary" title="' + esc(L('ov.new_services', { n: h.new })) + '">' + esc(L('ov.new_short', { n: h.new })) + '</span>'; }
		return '<div class="col-12 col-sm-6 col-xl-4 col-xxl-3"><a class="card host-tile text-reset text-decoration-none s-' + esc(st) + (h.maint ? ' s-maint' : '') + (h.paused ? ' s-paused' : '') + '" href="' + esc(hostURL(h.uid)) + '" data-host="' + esc(h.uid) + '"><div class="card-body">' +
			'<div class="d-flex align-items-center gap-2"><i class="bi ' + esc(h.icon) + ' text-body-secondary"></i><span class="host-name">' + esc(h.name) + '</span>' + extra + '<span class="ms-auto">' + foot + '</span></div>' +
			'<div class="host-kind">' + esc(((D.host_kind_labels || {})[h.kind] || [h.kind])[0] || '') + (h.address ? ' · ' + esc(h.address) : '') + (ref ? ' · ' + clBy(ref, CLV.self_name) : '') + '</div>' +
			'<div class="mt-1">' + (h.tags || []).map(tag).join('') + '</div>' + body + '</div></a></div>';
	}
	function row(h) {
		var st = hostState(h), ref = clRef(h), note = clNote(ref, CLV.self_name);
		if (ref && (ref.note === 'owner_unreachable' || ref.note === 'no_data')) { st = 'unknown'; }
		return '<tr data-host="' + esc(h.uid) + '" class="clickable"><td><span class="st-dot st-' + esc(st) + '"></span></td><td class="fw-semibold"><a class="text-reset text-decoration-none" href="' + esc(hostURL(h.uid)) + '">' + esc(h.name) + '</a><div class="small text-body-secondary fw-normal">' + esc(((D.host_kind_labels || {})[h.kind] || [h.kind])[0] || '') + (ref ? ' · ' + clBy(ref, CLV.self_name) : '') + '</div>' +
			(note ? '<div class="small text-body-secondary fw-normal">' + esc(note) + '</div>' : '') + '</td>' +
			'<td class="d-none d-md-table-cell small">' + esc(h.address) + '</td><td class="d-none d-lg-table-cell">' + (h.tags || []).map(tag).join('') + '</td>' +
			'<td class="svc-val">' + (h.has_cpu ? fmtNum(h.cpu, 0) + ' %' : '–') + '</td><td class="svc-val">' + (h.has_ram ? fmtNum(h.ram, 0) + ' %' : '–') + '</td>' +
			'<td>' + (h.problems ? stBadge(st, String(h.problems)) : '<span class="text-body-secondary small">–</span>') + '</td></tr>';
	}
	function probRow(p) {
		var title = p.unreach ? L('ov.unreachable') : tx(p.name);
		var icon = p.maint ? '<i class="bi bi-cone-striped text-body-secondary" title="' + esc(L('ov.maint')) + '"></i>' : '<span class="st-dot ' + (p.acked ? 'st-ack' : 'st-' + esc(p.state === 'unreachable' ? 'unknown' : p.state)) + '" title="' + esc(stLabel(p.state)) + '"></span>';
		return '<div class="prob-row' + (p.acked ? ' acked' : '') + '" data-host="' + esc(p.host_uid) + '" data-key="' + esc(p.key) + '" role="link" tabindex="0">' + icon +
			'<div class="prob-main"><a class="prob-title d-block text-reset text-decoration-none" href="' + esc(hostURL(p.host_uid, p.key)) + '" tabindex="-1">' + esc(p.host) + ' · ' + esc(title) + '</a><div class="prob-sub">' + esc(tx(p.detail)) + '</div></div>' +
			'<span class="prob-since d-none d-sm-inline">' + (p.acked ? '<i class="bi bi-check2"></i> ' + esc(L('ov.acked')) : esc(since(p.since))) + '</span>' +
			'<button class="btn btn-sm btn-outline-secondary" type="button" data-ack="' + (p.acked ? 'unack' : 'ack') + '" title="' + esc(p.acked ? L('ov.unack') : L('ov.ack_hint')) + '" aria-label="' + esc(p.acked ? L('ov.unack') : L('ov.ack')) + '"><i class="bi ' + (p.acked ? 'bi-arrow-counterclockwise' : 'bi-check2') + '"></i></button></div>';
	}
	function recentRow(r) {
		var icon = 'bi-arrow-repeat text-success', t = '', sub = '';
		var name = (r.host || '') + (r.name ? ' · ' + tx(r.name) : '');
		switch (r.kind) {
		case 'ok': t = L('ov.r_ok', { n: name }); sub = L('ov.r_ok_sub'); break;
		case 'resolved': icon = 'bi-person-check text-primary'; t = L('ov.r_resolved', { n: name }); sub = L('ov.r_by', { w: whoTxt(r.by) }) + (r.text ? ' – ' + quote(r.text) : ''); break;
		case 'maint': icon = 'bi-cone-striped text-body-secondary'; t = L('ov.r_maint', { n: tx(r.text || '') }); sub = L('ov.r_by', { w: whoTxt(r.by) }); break;
		case 'maint_end': icon = 'bi-cone-striped text-body-secondary'; t = L('ov.r_maint_end', { n: tx(r.text || '') }); sub = L('ov.r_by', { w: whoTxt(r.by) }); break;
		}
		return '<div class="prob-row" data-goto="/monitor64/problems?status=closed" role="link" tabindex="0"><i class="bi ' + icon + '"></i><div class="prob-main"><div class="prob-title">' + esc(t) + '</div><div class="prob-sub">' + esc(sub) + '</div></div><span class="prob-since">' + esc(ago(r.at)) + '</span></div>';
	}
	function render() {
		var c = data.counts || {};
		var total = (c.ok || 0) + (c.warn || 0) + (c.crit || 0) + (c.unknown || 0);
		$('#m64-stats').innerHTML = statCard('stat-down', ST.crit, c.crit || 0, L('ov.services'), 'bi-x-octagon') + statCard('stat-warn', ST.warn, c.warn || 0, L('ov.services'), 'bi-exclamation-triangle') +
			statCard('stat-muted', ST.unknown, c.unknown || 0, data.unreachable ? L('ov.unreachable_n', { n: data.unreachable }) : L('ov.services'), 'bi-question-circle') +
			statCard('stat-ok', ST.ok, c.ok || 0, L('ov.totals', { h: data.hosts.length, s: total }), 'bi-check-circle');
		$('#m64-prob-count').textContent = String(data.problems.length);
		$('#m64-problems').innerHTML = data.problems.length ? data.problems.map(probRow).join('') : '<div class="p-3 small text-body-secondary"><i class="bi bi-check-circle text-success"></i> ' + esc(L('ov.no_problems')) + '</div>';
		$('#m64-recent').innerHTML = data.recent.length ? data.recent.map(recentRow).join('') : '<div class="p-3 small text-body-secondary">' + esc(L('ov.no_recent')) + '</div>';
		var groups = data.groups || [];
		if (OV.group !== null && groups.indexOf(OV.group) < 0) { OV.group = null; }
		$('#m64-groups').innerHTML = '<span class="chip' + (OV.group === null ? ' active' : '') + '" data-group-all="1" role="button" tabindex="0" aria-pressed="' + (OV.group === null) + '">' + esc(L('ov.all')) + '</span>' +
			groups.map(function (g) { var on = g === OV.group; return '<span class="chip' + (on ? ' active' : '') + '" data-group="' + esc(g) + '" role="button" tabindex="0" aria-pressed="' + on + '">' + esc(g === '' ? L('ov.no_group') : g) + '</span>'; }).join('');
		$('#m64-only-prob').checked = OV.only;
		$$('[data-view]').forEach(function (b) { b.classList.toggle('active', b.dataset.view === OV.view); });
		var q = OV.q.toLowerCase();
		var hs = data.hosts.filter(function (h) {
			if (OV.group !== null && h.group !== OV.group) { return false; }
			if (OV.only && hostState(h) === 'ok' && !h.vanished) { return false; }
			if (!q) { return true; }
			return (h.name + ' ' + h.address + ' ' + h.kind + ' ' + (h.tags || []).join(' ') + ' ' + h.group).toLowerCase().indexOf(q) >= 0;
		});
		var html = '', seen = [];
		hs.forEach(function (h) { if (seen.indexOf(h.group) < 0) { seen.push(h.group); } });
		var inGroup = function (g) { return hs.filter(function (h) { return h.group === g; }); };
		if (!data.hosts.length) { html = ''; }
		else if (!hs.length) { html = '<div class="text-body-secondary p-4 text-center">' + esc(L('ov.no_match')) + '</div>'; }
		else if (OV.view === 'list') {
			// Gruppen als Trennzeilen: table-sort.js sortiert damit je Gruppe. Die Tabelle bleibt beim Auffrischen stehen
			// (nur die Zeilen neu), sonst ginge die gewaehlte Sortierung alle 15 s verloren.
			var rows = seen.map(function (g) {
				var gh = inGroup(g);
				return '<tr class="table-group" data-sort-sep><td colspan="7" class="small fw-semibold text-body-secondary">' + esc(g || L('ov.no_group')) + ' <span class="fw-normal text-body-tertiary">' + gh.length + '</span></td></tr>' + gh.map(row).join('');
			}).join('');
			var tb = $('#m64-hosts table tbody');
			if (tb) { tb.innerHTML = rows; html = null; }
			else { html = '<div class="card"><div class="table-responsive"><table class="table table-hover mb-0 align-middle"><thead><tr><th style="width:2rem"></th><th>' + esc(L('col.host')) + '</th><th class="d-none d-md-table-cell">' + esc(L('col.address')) + '</th><th class="d-none d-lg-table-cell">' + esc(L('col.tags')) + '</th><th>CPU</th><th>RAM</th><th>' + esc(L('ov.problems')) + '</th></tr></thead><tbody>' + rows + '</tbody></table></div></div>'; }
		} else {
			seen.forEach(function (g) {
				var gh = inGroup(g);
				html += '<div class="group-head">' + esc(g || L('ov.no_group')) + ' <span class="fw-normal text-body-tertiary">' + gh.length + '</span></div><div class="row g-3">' + gh.map(tile).join('') + '</div>';
			});
		}
		if (html !== null) { $('#m64-hosts').innerHTML = html; }
		$('#m64-empty').classList.toggle('d-none', data.hosts.length > 0);
		$('#m64-filter').classList.toggle('d-none', data.hosts.length === 0);
		clOrphans(CLV.orphans, function () { return api('GET', '/api/monitor64/cluster/views').then(function (v) { CLV = v || CLV; render(); refresh(); }); }); // Cluster: verwaiste Hosts
	}
	function hostURL(uid, key) { return '/monitor64/host/' + encodeURIComponent(uid) + (key ? '#svc=' + encodeURIComponent(key) : ''); }
	function go(el) {
		if (el.dataset.goto) { location.href = el.dataset.goto; return; }
		location.href = hostURL(el.dataset.host, el.dataset.key);
	}
	root.addEventListener('click', function (ev) {
		var b = ev.target.closest('[data-ack]');
		if (b) {
			ev.stopPropagation();
			var r = b.closest('.prob-row');
			lock(b, function () {
				return api('POST', '/api/monitor64/problems/action', { host: r.dataset.host, key: r.dataset.key, action: b.dataset.ack, comment: '' }).then(function () {
					toast(b.dataset.ack === 'ack' ? L('ov.acked_toast') : L('ov.unacked_toast'));
					refresh();
				});
			}).catch(fail);
			return;
		}
		var g = ev.target.closest('[data-group],[data-group-all]');
		if (g) { OV.group = g.dataset.groupAll ? null : g.dataset.group; store('groupsel', JSON.stringify(OV.group)); render(); return; }
		var v = ev.target.closest('[data-view]');
		if (v) { OV.view = v.dataset.view; store('view', OV.view); render(); return; }
		if (ev.target.closest('a[href]')) { return; } // echte Links oeffnet der Browser (auch im neuen Tab)
		var t = ev.target.closest('[data-host],[data-goto]');
		if (t && t.closest('#m64')) { go(t); }
	});
	root.addEventListener('keydown', function (ev) {
		if (ev.key !== 'Enter' && ev.key !== ' ') { return; }
		if (ev.target.closest('button, a, input, select, textarea')) { return; } // Knoepfe (z. B. Quittieren) bedient der Browser selbst
		var t = ev.target.closest('[data-host],[data-goto],[data-group],[data-group-all]');
		if (t) { ev.preventDefault(); t.click(); }
	});
	$('#m64-only-prob').onchange = function () { OV.only = this.checked; store('only', OV.only ? '1' : '0'); render(); };
	$('#m64-q').oninput = function () { OV.q = this.value; render(); };
	function refresh() {
		var p = [api('GET', '/api/monitor64/overview')];
		if (clOn()) { p.push(api('GET', '/api/monitor64/cluster/views').catch(function () { return null; })); } // "ueberwacht von" je Host
		Promise.all(p).then(function (r) { data = r[0]; if (r[1]) { CLV = r[1]; } render(); }).catch(failQuiet);
	}
	function loadSparks() { api('GET', '/api/monitor64/sparks').then(function (s) { sparks = s || {}; render(); }).catch(failQuiet); }
	render();
	loadSparks();
	setInterval(function () { if (!document.hidden) { refresh(); } }, 15000);
	setInterval(function () { if (!document.hidden) { loadSparks(); } }, 300000);
}

// ---------- Diagramme ----------
var RANGES = { '6h': L('chart.r6h'), '24h': L('chart.r24h'), '7d': L('chart.r7d'), '30d': L('chart.r30d'), '1y': L('chart.r1y') };
function chartColors() { return [cssVar('--bs-primary') || '#0d6efd', cssVar('--ipv64-orange') || '#f59c1a', cssVar('--bs-success') || '#198754', cssVar('--bs-info') || '#0dcaf0']; }
function tickFmt(span) {
	return function (v) {
		var d = new Date(v * 1000);
		if (span > 40 * 86400) { return fmtDay(d, true); }
		if (span > 2 * 86400) { return fmtDay(d, false) + ' ' + pad(d.getHours()) + ':00'; }
		return pad(d.getHours()) + ':' + pad(d.getMinutes());
	};
}
// toPoints: Punkte der API in Chart.js-Punkte; Luecken (mehr als 3 Schritte) unterbrechen die Linie. Bei gemischter
// Aufloesung zaehlt die groessere Breite der beiden Punkte (s, 0 = Rohwert), sonst verschwinden aufgefuellte
// groebere Punkte.
function toPoints(s, factor) {
	var out = [], pts = s.points || [], step = s.step || 0;
	if (!step && pts.length > 1) { step = Math.max(60, (pts[pts.length - 1].t - pts[0].t) / pts.length); }
	for (var i = 0; i < pts.length; i++) {
		var gap = i ? Math.max(step, pts[i - 1].s || 0, pts[i].s || 0) : 0;
		if (i && gap && pts[i].t - pts[i - 1].t > 3 * gap) { out.push({ x: pts[i - 1].t + gap, y: null }); }
		out.push({ x: pts[i].t, y: pts[i].avg / (factor || 1) });
	}
	return out;
}
function lineChart(canvas, opt) {
	if (!window.Chart) { return null; }
	var txt = cssVar('--bs-secondary-color'), grid = cssVar('--bs-border-color'), cols = chartColors();
	var ds = opt.series.map(function (s, i) {
		return { label: s.label, data: s.data, borderColor: cols[i % cols.length], backgroundColor: i === 0 ? 'rgba(' + (cssVar('--bs-primary-rgb') || '13,110,253') + ',.08)' : 'transparent', fill: i === 0 && opt.series.length === 1, borderWidth: 1.6, pointRadius: 0, tension: 0.25, spanGaps: false };
	});
	[['warn', cssVar('--bs-warning')], ['crit', cssVar('--bs-danger')]].forEach(function (x) {
		var v = opt[x[0]];
		if (v === null || v === undefined) { return; }
		ds.push({ label: '_' + x[0], data: [{ x: opt.from, y: v }, { x: opt.to, y: v }], borderColor: x[1], borderDash: [5, 4], borderWidth: 1, pointRadius: 0, fill: false });
	});
	var span = opt.to - opt.from;
	return new window.Chart(canvas, {
		type: 'line', data: { datasets: ds },
		options: {
			animation: false, maintainAspectRatio: false, parsing: false, interaction: { mode: 'nearest', axis: 'x', intersect: false },
			plugins: {
				legend: { display: opt.series.length > 1, labels: { color: txt, boxWidth: 10, filter: function (i) { return i.text.charAt(0) !== '_'; } } },
				tooltip: { filter: function (i) { return i.dataset.label.charAt(0) !== '_'; }, callbacks: {
					title: function (items) { return items.length ? fmtTime(new Date(items[0].parsed.x * 1000)) : ''; },
					label: function (c) { return c.dataset.label + ': ' + (opt.fmt ? opt.fmt(c.parsed.y) : fmtNum(c.parsed.y)); } } }
			},
			scales: {
				x: { type: 'linear', min: opt.from, max: opt.to, ticks: { color: txt, maxTicksLimit: 7, maxRotation: 0, callback: tickFmt(span) }, grid: { display: false } },
				y: { beginAtZero: true, max: opt.max, ticks: { color: txt, maxTicksLimit: 5 }, grid: { color: grid } }
			}
		}
	});
}
// dragZoom: Bereich im Diagramm aufziehen -> onZoom(von, bis) in Unix-Sekunden. Liefert eine Funktion, die den
// Listener am Fenster wieder entfernt (beim Zerstoeren des Diagramms).
function dragZoom(canvas, chart, onZoom) {
	var box = canvas.parentNode, sel = $('.zoom-sel', box), x0 = null;
	canvas.addEventListener('mousedown', function (e) { x0 = e.offsetX; sel.style.left = x0 + 'px'; sel.style.width = '0'; sel.style.display = 'block'; });
	canvas.addEventListener('mousemove', function (e) { if (x0 === null) { return; } sel.style.left = Math.min(x0, e.offsetX) + 'px'; sel.style.width = Math.abs(e.offsetX - x0) + 'px'; });
	function up(e) {
		if (x0 === null) { return; }
		var r = canvas.getBoundingClientRect(), x1 = e.clientX - r.left, start = x0;
		x0 = null;
		sel.style.display = 'none';
		if (Math.abs(x1 - start) < 4) { return; }
		var a = chart.scales.x.getValueForPixel(Math.min(start, x1)), b = chart.scales.x.getValueForPixel(Math.max(start, x1));
		if (b - a < 120) { return; }
		onZoom(Math.round(a), Math.round(b));
	}
	window.addEventListener('mouseup', up);
	return function () { window.removeEventListener('mouseup', up); };
}
// chartFail zeigt einen Fehler im Diagramm (statt ihn stumm zu schlucken).
function chartFail(canvas, e) {
	var box = canvas && canvas.parentNode;
	if (!box) { return; }
	box.innerHTML = '<div class="small text-body-secondary p-3"><i class="bi bi-exclamation-triangle"></i> ' + esc(L('chart.error', { e: e && e.message ? tx(e.message) : String(e) })) + '</div>';
}
// destroyable: Diagramm, dessen destroy auch den Zoom-Listener entfernt.
function destroyable(ch, off) {
	var d = ch.destroy.bind(ch);
	ch.destroy = function () { if (off) { off(); off = null; } d(); };
	return ch;
}
function unitFmt(unit) {
	if (unit === 'B/s') { return { factor: 1e6, label: 'MB/s', fmt: function (v) { return fmtNum(v, 1) + ' MB/s'; } }; }
	return { factor: 1, label: unit, fmt: function (v) { return fmtNum(v, unit === '%' ? 0 : 1) + ' ' + unit; } };
}

// ---------- Verbindung testen (Host-Seite und Assistent) ----------
// testHTML: Ergebnis von "Verbindung testen"; bei API-Zugaengen ohne bestaetigtes Zertifikat bzw. Host-Key ein
// Knopf "Fingerabdruck bestaetigen" (data-fp-confirm), der ihn als Pin uebernimmt und erneut testet.
function testHTML(r) {
	var fp = r.fingerprint ? '<div class="small mt-1">' + esc(L('new.fp')) + ' <code>' + esc(r.fingerprint) + '</code>' + (r.cert_subject ? ' <span class="text-body-secondary">' + esc(r.cert_subject) + '</span>' : '') + '</div>' : '';
	// Agent/SSH: womit wurde wirklich gesprochen (hilft, wenn ein Name im Container anders aufloest)
	var diag = [r.peer ? L('new.test_peer', { a: r.peer }) : '', r.key_type ? L('new.test_keytype', { k: r.key_type }) : ''].filter(Boolean).join(' · ');
	if (diag) { fp += '<div class="small text-body-secondary mt-1"><i class="bi bi-hdd-network"></i> ' + esc(diag) + '</div>'; }
	if (r.need_confirm) {
		return '<span class="text-warning-emphasis"><i class="bi bi-shield-exclamation"></i> ' + esc(L('new.fp_confirm')) + '</span>' + fp +
			(r.fingerprint ? '<button class="btn btn-sm btn-outline-primary mt-1" type="button" data-fp-confirm="' + esc(r.fingerprint) + '"><i class="bi bi-check2"></i> ' + esc(L('new.fp_accept')) + '</button>' : '');
	}
	if (r.cert_changed && r.fingerprint) { // gemerktes Zertifikat passt nicht mehr: neuen Fingerabdruck uebernehmen, Geheimnis neu eingeben
		return '<span class="text-danger"><i class="bi bi-shield-exclamation"></i> ' + esc(L('new.fp_changed')) + '</span>' + fp +
			'<button class="btn btn-sm btn-outline-primary mt-1" type="button" data-fp-confirm="' + esc(r.fingerprint) + '"><i class="bi bi-check2"></i> ' + esc(L('new.fp_accept_changed')) + '</button>';
	}
	var n = (r.services || []).length, extra = '';
	if (r.summary || r.version) { extra += '<div class="small text-body-secondary mt-1">' + esc([r.version ? L('new.version', { v: r.version }) : '', r.cluster ? L('new.cluster', { c: r.cluster }) : '', tx(r.summary || '')].filter(Boolean).join(' · ')) + '</div>'; }
	if (r.warning) { extra += '<div class="small text-warning-emphasis mt-1"><i class="bi bi-exclamation-triangle"></i> ' + esc(tx(r.warning)) + '</div>'; }
	extra += snmpTestHTML(r);
	if (r.ok && !r.error) { return '<span class="text-success"><i class="bi bi-check-circle-fill"></i> ' + esc(L('new.test_ok', { n: n, ms: r.ms })) + '</span>' + extra + fp; }
	if (r.ok) { return '<span class="text-warning-emphasis"><i class="bi bi-exclamation-triangle"></i> ' + esc(L('new.test_partial', { n: n, e: tx(r.error) })) + '</span>' + extra + fp; }
	return '<span class="text-danger"><i class="bi bi-x-circle-fill"></i> ' + esc(r.error ? tx(r.error) : L('new.test_fail')) + '</span>' + fp;
}
// setHTML setzt Inhalt nur bei Aenderung (die 15-s-Aktualisierung zerstoert sonst Fokus, Auswahl und Zustand).
function setHTML(el, html) {
	if (!el || el._m64html === html) { return false; }
	el._m64html = html;
	el.innerHTML = html;
	return true;
}

// ---------- Host ----------
function pageHost() {
	var uid = root.dataset.host, H = D.host, sparks = {}, charts = [], HV = { range: store('range') || '24h', off: 0, zoom: null, gen: 0 };
	var detailFor = null, newSel = {}, ignOpen = false, CH = D.cluster || null; // CH: Zustaendigkeit im Cluster (nur mit Cluster)
	function svcName(s) { return tx(s.name); }
	// clAway: zustaendige Node nicht erreichbar bzw. noch kein Stand von ihr (Werte veraltet: Zustand unbekannt)
	function clAway() { var r = CH && CH.ref; return !!(r && (r.note === 'owner_unreachable' || r.note === 'no_data')); }
	function accState(a) {
		if (!a.enabled) { return '<i class="bi bi-dash-circle" title="' + esc(L('host.acc_off')) + '"></i>'; }
		if (!a.known) { return '<i class="bi bi-hourglass-split text-body-secondary" title="' + esc(L('host.acc_wait')) + '"></i>'; }
		return a.ok ? '<i class="bi bi-check-circle-fill"></i>' : '<i class="bi bi-x-circle-fill" title="' + esc(tx(a.error || '')) + '"></i>';
	}
	function renderHead() {
		var h = H.host, st = H.view === 'unreachable' ? 'unknown' : H.state;
		var badge = H.view === 'maintenance' ? '<span class="st-badge maint"><i class="bi bi-cone-striped"></i> ' + esc(L('ov.maint')) + '</span>' : H.view === 'unreachable' ? stBadge('unknown', L('state.unreachable')) : H.checked ? stBadge(st) : '<span class="st-badge unknown">' + esc(L('ov.waiting')) + '</span>';
		if (h.paused) { badge += ' <span class="st-badge unknown"><i class="bi bi-pause-circle"></i> ' + esc(L('ov.paused')) + '</span>'; }
		var ref = CH && CH.ref, away = clAway();
		if (away && H.view !== 'maintenance') { badge = stBadge('unknown'); }
		if (ref) { badge += ' <span class="badge text-bg-light border fw-normal" id="m64-cl-badge"><i class="bi bi-diagram-3"></i> ' + esc(L('cluster.by', { n: clName(ref, clSelf()) })) + '</span>'; }
		var kl = ((D.host_kind_labels || {})[h.kind] || [h.kind])[0] || '';
		setHTML($('#m64-host-head'), '<div class="d-flex align-items-center gap-2"><i class="bi ' + esc(H.icon) + ' fs-4 text-body-secondary"></i><h1 class="h3 mb-0">' + esc(h.name) + '</h1>' + badge + '</div>' +
			'<div class="text-body-secondary small mt-1">' + esc(kl) + ' · ' + esc(h.address) + (h.group ? ' · ' + esc(L('host.group')) + ' ' + esc(h.group) : '') + ' ' + (h.tags || []).map(tag).join('') +
			(H.checked ? ' · ' + esc(L('host.checked', { t: ago(H.checked) })) : '') + '</div>' +
			'<div class="d-flex flex-wrap gap-2 mt-2">' + H.accesses.map(function (a) { return '<span class="access-chip access-row">' + accState(a) + esc(accLabel(a.type)) + '</span>'; }).join('') +
			'<a href="#" class="small align-self-center" data-act="access-add"><i class="bi bi-plus"></i> ' + esc(L('host.access_add')) + '</a></div>');
		var pl = $('[data-pause-label]');
		if (pl) { pl.textContent = h.paused ? L('host.resume') : L('host.pause'); }
		var al = '';
		if (H.maint) { al += '<div class="alert alert-warning py-2 small"><i class="bi bi-cone-striped"></i> ' + esc(L('host.in_maint', { r: H.maint.reason || '–', t: H.maint.end ? fmtTime(H.maint.end) : L('mt.until_ended') })) + '</div>'; }
		if (H.view === 'unreachable' && !away) { al += '<div class="alert alert-secondary d-flex align-items-center gap-2"><i class="bi bi-plug fs-5"></i><div><strong>' + esc(L('state.unreachable')) + '.</strong> ' + esc(tx(H.unreach || '')) + ' ' + esc(L('host.unreach_hint')) + '</div></div>'; }
		var note = clNote(ref, clSelf()), at = ref && !ref.here && toDate(ref.at);
		if (note || at) {
			al += '<div class="alert alert-secondary py-2 small d-flex align-items-center gap-2" id="m64-cl-note"><i class="bi bi-diagram-3"></i><div>' + esc(note) +
				(at ? (note ? ' ' : '') + '<span class="text-body-secondary">' + esc(L('cluster.state_at', { n: clName(ref, clSelf()), t: ago(ref.at) })) + '</span>' : '') + '</div></div>';
		}
		setHTML($('#m64-host-alerts'), al);
		// Dienste erkennen kann nur die Node, die den Host abfragt
		var db = $('[data-act=discover]'), remote = !!(ref && !ref.here);
		if (db) { db.disabled = remote; db.title = remote ? L('cluster.discover_remote', { n: clName(ref, clSelf()) }) : ''; }
	}
	// Neue Dienste: Haekchen merken (newSel), damit die Aktualisierung die Auswahl nicht zuruecksetzt.
	function renderNew() {
		var n = H.new || [], html = '';
		if (n.length) {
			html = '<div class="card mb-3 new-svc"><div class="card-body py-2"><div class="d-flex flex-wrap align-items-center gap-2 mb-2"><i class="bi bi-stars text-primary"></i><strong>' + esc(L('host.new_n', { n: n.length })) + '</strong><span class="small text-body-secondary">' + esc(L('host.new_hint')) + '</span>' +
				'<div class="ms-auto d-flex gap-2"><button class="btn btn-sm btn-primary" type="button" data-new="1"><i class="bi bi-check2"></i> ' + esc(L('host.adopt')) + '</button><button class="btn btn-sm btn-outline-secondary" type="button" data-new="-1"><i class="bi bi-eye-slash"></i> ' + esc(L('host.ignore')) + '</button></div></div>' +
				(n.length > 1 ? '<div class="mb-1"><button class="btn btn-sm btn-link p-0 me-3" type="button" data-newall="1">' + esc(L('new.all')) + '</button><button class="btn btn-sm btn-link p-0" type="button" data-newall="0">' + esc(L('new.none')) + '</button></div>' : '') +
				'<div class="row g-1">' + n.map(function (s, i) { return '<div class="col-md-6 col-xl-4"><div class="form-check"><input class="form-check-input" type="checkbox" id="m64n' + i + '" data-newsel="' + esc(s.key) + '"' + (newSel[s.key] === false ? '' : ' checked') + '><label class="form-check-label small" for="m64n' + i + '">' + esc(tx(s.name) || s.key) + ' <span class="text-body-tertiary">' + esc(s.key) + '</span></label></div></div>'; }).join('') + '</div></div></div>';
		}
		var gone = H.services.filter(function (s) { return s.vanished; });
		if (gone.length) {
			html += '<div class="alert alert-warning py-2 small d-flex flex-wrap align-items-center gap-2"><i class="bi bi-question-diamond"></i> ' + esc(L('host.vanished_n', { n: gone.length })) + ' <span class="text-body-secondary">' + esc(gone.map(svcName).join(', ')) + '</span>' +
				'<button class="btn btn-sm btn-outline-danger ms-auto" type="button" data-remove-gone="1"><i class="bi bi-trash"></i> ' + esc(L('host.remove_all')) + '</button></div>';
		}
		setHTML($('#m64-new'), html);
	}
	function isFree(lv) { return !!(lv && lv.eff && lv.eff.mode === 'free'); }
	function valueCell(s) {
		var mt = s.primary >= 0 ? s.metrics[s.primary] : (s.metrics && s.metrics.length && !s.text ? s.metrics[0] : null);
		var st = H.view === 'unreachable' || clAway() ? 'unknown' : s.state, html = '';
		if (mt) {
			html = '<span class="fw-semibold">' + esc(fmtVal(mt.value, mt.unit)) + '</span>';
			if (mt.unit === '%') { html += '<span class="bar"><span class="' + (st === 'ok' ? '' : esc(st)) + '" style="width:' + Math.max(0, Math.min(100, mt.value)) + '%"></span></span>'; }
			var p = mt.status || {};
			if ((p.pending === 'warn' || p.pending === 'crit') && toDate(p.pending_since)) {
				html += '<div class="small text-warning-emphasis"><i class="bi bi-hourglass-split"></i> ' + esc(pendText(p, mt.unit, s.primary >= 0 && isFree(s.levels))) + '</div>';
			}
			if (s.text) { html += '<div class="small text-body-secondary">' + esc(tx(s.text)) + '</div>'; }
		} else {
			html = '<span class="small">' + esc(tx(s.text || '')) + '</span>';
		}
		if (s.cause && st !== 'ok') { html += '<div class="small text-danger-emphasis">' + esc(tx(s.cause)) + '</div>'; }
		if (s.vanished) { html += '<div class="small text-warning-emphasis"><i class="bi bi-question-diamond"></i> ' + esc(L('host.vanished')) + '</div>'; }
		return html;
	}
	// pendText: "seit N Min. ueber X" – im Modus "GB frei" ist die Schwelle in GB frei.
	function pendText(p, unit, free) {
		var s = toDate(p.pending_since), a = toDate(p.pending_at), v = lim(p.pending_limit);
		var mins = Math.max(0, Math.round((Date.now() - s.getTime()) / 60000)), need = a ? Math.round((a.getTime() - s.getTime()) / 60000) : 0;
		var a2 = { m: mins, v: free ? fmtNum(v) + ' ' + L('unit.gb_free') : fmtVal(v, unit), s: stLabel(p.pending), n: need };
		return free ? L('host.pending_free', a2) : L('host.pending', a2);
	}
	function thrCell(s) {
		if (!s.levels) { return '<span class="text-body-tertiary">–</span>'; }
		var src = srcLabel(s.levels), e = s.levels.eff;
		return thrVals(e, s.metrics[s.primary].unit) + '<div class="src' + (src.own ? ' src-own' : '') + '">' + esc(src.t) + (e['for'] ? ' · ' + esc(durLabel(e['for'])) : '') + (e.report === 'show' ? ' · ' + esc(L('rl.show')) : '') +
			((s.rules || []).length > 1 ? ' · ' + esc(L('host.more_rules', { n: s.rules.length - 1 })) : '') + '</div>';
	}
	function renderServices() {
		var cats = D.cat_order || [], html = '';
		var list = H.services.slice();
		$('#m64-svc-count').textContent = String(list.length);
		cats.forEach(function (c) {
			var rows = list.filter(function (s) { return s.category === c; });
			if (!rows.length) { return; }
			html += '<tr class="svc-cat"><td colspan="6">' + esc((D.cats || {})[c] || c) + '</td></tr>';
			rows.forEach(function (s) {
				var st = H.view === 'unreachable' || clAway() ? 'unknown' : s.state;
				var badge = stBadge(st) + (s.show_only ? ' <i class="bi bi-eye text-body-tertiary" title="' + esc(L('rl.show')) + '"></i>' : '') + (s.ack ? ' <i class="bi bi-check2-square text-primary" title="' + esc(L('ov.acked')) + '"></i>' : '');
				html += '<tr data-svc="' + esc(s.key) + '" tabindex="0"' + (s.vanished ? ' class="vanished"' : '') + '><td>' + badge + '</td><td class="fw-semibold m64-svc-name">' + esc(svcName(s)) + (s.since && st !== 'ok' ? '<div class="small fw-normal text-body-secondary">' + esc(since(s.since)) + '</div>' : '') + '</td><td class="svc-val">' + valueCell(s) + '</td>' +
					'<td class="d-none d-lg-table-cell spark-cell">' + (sparks[s.key] ? spark(sparks[s.key], st === 'ok' ? '' : 's-' + st) : '') + '</td>' +
					'<td class="d-none d-md-table-cell thr">' + thrCell(s) + '</td><td class="d-none d-xl-table-cell small text-body-secondary text-nowrap">' + esc(tx(s.via || '')) + '</td></tr>';
			});
		});
		if (!list.length) { html = '<tr><td colspan="6" class="text-center text-body-secondary p-4">' + esc(H.checked ? L('host.no_services') : L('host.no_services_yet')) + '</td></tr>'; }
		setHTML($('#m64-svcs'), html);
	}
	function accSummary(a) {
		var c = a.config || {}, p = [];
		if (a.type === 'snmp') { p.push('SNMP v' + (c.snmp_version || '2c')); }
		if (c.traps) { p.push(L('acc.snmp_traps_short')); }
		if (c.user) { p.push(L('acc.user') + ' ' + c.user); }
		if (c.port) { p.push(L('acc.port') + ' ' + c.port); }
		if (c.url) { p.push(c.url); }
		if (c.token_id) { p.push(c.token_id); }
		if (c.node) { p.push(L('new.node_short', { n: c.node })); }
		if (c.pin) { p.push(L('acc.pinned')); }
		if (c.smart) { p.push('SMART'); }
		if (a.secret_set) { p.push(L('acc.secret_set')); }
		return p.join(' · ');
	}
	function renderAccesses() {
		var html = H.accesses.map(function (a) {
			return '<div class="list-group-item d-flex flex-wrap align-items-center gap-2 access-row" data-acc="' + esc(a.uid) + '">' + accState(a) + '<div class="me-auto min-w-0"><div class="fw-semibold">' + esc(accLabel(a.type)) + (a.enabled ? '' : ' <span class="badge text-bg-secondary">' + esc(L('host.acc_off')) + '</span>') + '</div>' +
				'<div class="small text-body-secondary text-truncate">' + esc(accSummary(a)) + (a.hostkey ? ' · ' + esc(L('acc.hostkey')) + ' <code>' + esc(a.hostkey) + '</code>' : '') + '</div>' +
				(a.error ? '<div class="small text-danger-emphasis">' + esc(tx(a.error)) + '</div>' : '') + agentAccLine(a.agent) + '</div>' +
				'<div class="btn-group btn-group-sm"><button class="btn btn-outline-secondary" type="button" data-acc-act="test"><i class="bi bi-plug"></i> ' + esc(L('acc.test')) + '</button>' +
				'<button class="btn btn-outline-secondary" type="button" data-acc-act="edit" title="' + esc(L('acc.edit')) + '" aria-label="' + esc(L('acc.edit')) + '"><i class="bi bi-pencil"></i></button>' +
				(a.hostkey ? '<button class="btn btn-outline-secondary" type="button" data-acc-act="hostkey" title="' + esc(L('acc.hostkey_reset')) + '" aria-label="' + esc(L('acc.hostkey_reset')) + '"><i class="bi bi-key"></i></button>' : '') +
				'<button class="btn btn-outline-secondary" type="button" data-acc-act="delete" title="' + esc(L('acc.delete')) + '" aria-label="' + esc(L('acc.delete')) + '"><i class="bi bi-trash"></i></button></div></div>';
		}).join('');
		setHTML($('#m64-accesses'), html || '<div class="list-group-item small text-body-secondary">' + esc(L('host.no_access')) + '</div>');
		var ig = H.ignored || [];
		setHTML($('#m64-ignored'), ig.length ? '<details class="mb-3" data-ign-box' + (ignOpen ? ' open' : '') + '><summary class="small text-body-secondary">' + esc(L('host.ignored_n', { n: ig.length })) + '</summary><div class="list-group mt-2">' +
			ig.map(function (s) { return '<div class="list-group-item d-flex align-items-center gap-2 small"><span class="me-auto">' + esc(tx(s.name) || s.key) + ' <span class="text-body-tertiary">' + esc(s.key) + '</span></span><button class="btn btn-sm btn-outline-secondary" type="button" data-ign="' + esc(s.key) + '">' + esc(L('host.adopt')) + '</button></div>'; }).join('') + '</div></details>' : '');
	}
	root.addEventListener('toggle', function (ev) { if (ev.target.matches && ev.target.matches('[data-ign-box]')) { ignOpen = ev.target.open; } }, true);
	root.addEventListener('change', function (ev) { var k = ev.target.dataset && ev.target.dataset.newsel; if (k !== undefined) { newSel[k] = ev.target.checked; } });
	// Zustaendigkeit im Cluster (Karte unter den Zugaengen): wer ueberwacht, bevorzugte und Ersatz-Nodes, Uebernahmen
	function clSelf() { var n = ''; ((CH && CH.nodes) || []).forEach(function (x) { if (x.self) { n = x.name; } }); return n; }
	function clNodeName(id) { var n = id; ((CH && CH.nodes) || []).forEach(function (x) { if (x.id === id) { n = x.name || id; } }); return n; }
	function renderCluster() {
		var box = $('#m64-cl-body');
		if (!box || !CH) { return; }
		var c = CH.host || {}, ref = CH.ref, html = '<div class="row g-2">';
		html += '<div class="col-sm-4"><div class="text-body-secondary">' + esc(L('cluster.owner')) + '</div><div class="fw-semibold">' + esc(c.owner_name || clNodeName(c.owner)) +
			(c.reachable ? '' : ' <span class="badge text-bg-secondary">' + esc(L('cluster.offline')) + '</span>') + '</div><div class="text-body-secondary">' + esc(clRole(c.role)) + '</div></div>';
		html += '<div class="col-sm-4"><div class="text-body-secondary">' + esc(L('cluster.preferred')) + '</div><div class="fw-semibold">' + esc(clNodeName(c.preferred)) + '</div></div>';
		html += '<div class="col-sm-4"><div class="text-body-secondary">' + esc(L('cluster.backups')) + '</div><div class="fw-semibold">' + esc((c.backups || []).length ? c.backups.map(clNodeName).join(', ') : L('cluster.backups_none')) + '</div></div></div>';
		if (!(c.backups || []).length && CH.active) { html += '<div class="text-body-secondary mt-2">' + esc(L('cluster.backups_hint')) + '</div>'; }
		var evs = CH.events || [];
		if (evs.length) { html += '<details class="mt-2"><summary class="text-body-secondary">' + esc(L('cluster.history_n', { n: evs.length })) + '</summary>' + timeline(evs, {}) + '</details>'; }
		setHTML(box, html);
		var eb = $('[data-act=cluster-edit]');
		if (eb) { eb.classList.toggle('d-none', !CH.active); }
	}
	function reloadCluster() { return api('GET', '/api/monitor64/cluster/hosts/' + encodeURIComponent(uid)).then(function (d) { CH = d; renderHead(); renderCluster(); }); }
	// clusterDialog: bevorzugte Node und Ersatz-Nodes waehlen; "Erreichbarkeit pruefen" testet die Zugaenge von allen Nodes.
	function clusterDialog() {
		var c = CH.host || {}, nodes = CH.nodes || [], back = {};
		(c.backups || []).forEach(function (b) { back[b] = true; });
		var body = modal(L('cluster.edit'), '<div class="mb-3"><label class="form-label" for="m64-cl-pref">' + esc(L('cluster.preferred')) + '</label><select class="form-select" id="m64-cl-pref">' +
			nodes.map(function (n) { return '<option value="' + esc(n.id) + '"' + (n.id === c.preferred ? ' selected' : '') + '>' + esc(n.name + (n.self ? ' (' + L('cluster.this_node') + ')' : '') + (n.online ? '' : ' – ' + L('cluster.offline'))) + '</option>'; }).join('') + '</select>' +
			'<div class="form-text">' + esc(L('cluster.preferred_hint')) + '</div></div>' +
			'<div class="form-label">' + esc(L('cluster.backups')) + '</div><div id="m64-cl-backs">' + nodes.map(function (n, i) {
				return '<div class="form-check" data-cl-node="' + esc(n.id) + '"><input class="form-check-input" type="checkbox" id="m64-cl-b' + i + '" value="' + esc(n.id) + '"' + (back[n.id] ? ' checked' : '') + '><label class="form-check-label" for="m64-cl-b' + i + '">' + esc(n.name) +
					(n.self ? ' <span class="text-body-tertiary">' + esc(L('cluster.this_node')) + '</span>' : '') + (n.online ? '' : ' <span class="badge text-bg-secondary">' + esc(L('cluster.offline')) + '</span>') + ' <span class="small" data-cl-reach></span></label></div>';
			}).join('') + '</div><div class="form-text">' + esc(L('cluster.backups_hint')) + '</div>' +
			// Zugaenge, die nur auf dieser Node gehen (lokaler Docker-Socket): eine Ersatz-Node erreicht sie nie
			(H.accesses.some(function (a) { var u = (a.config && a.config.url) || ''; return a.type === 'docker' && (u === '' || u.indexOf('unix://') === 0); }) ?
				'<div class="form-text text-warning-emphasis"><i class="bi bi-exclamation-triangle"></i> ' + esc(L('cluster.local_access_hint')) + '</div>' : '') +
			'<div class="mt-3"><button class="btn btn-sm btn-outline-primary" type="button" id="m64-cl-reach"><i class="bi bi-broadcast"></i> ' + esc(L('cluster.reach')) + '</button></div><div class="small mt-2" id="m64-cl-reach-res"></div>',
		[{ label: L('cancel') }, { label: L('save'), cls: 'btn-primary', click: function (close) {
			var pref = $('#m64-cl-pref', body).value, list = [];
			(c.backups || []).forEach(function (b) { $$('#m64-cl-backs input:checked', body).forEach(function (x) { if (x.value === b && b !== pref) { list.push(b); } }); }); // bisherige Reihenfolge bleibt
			$$('#m64-cl-backs input:checked', body).forEach(function (x) { if (x.value !== pref && list.indexOf(x.value) < 0) { list.push(x.value); } });
			return api('PUT', '/api/monitor64/cluster/hosts/' + encodeURIComponent(uid), { preferred_node: pref, backup_nodes: list }).then(function () { close(); toast(L('cluster.saved_toast')); return reloadCluster(); });
		} }], true);
		if (!body) { return; }
		function backBox(id) { var r = null; $$('#m64-cl-backs [data-cl-node]', body).forEach(function (d) { if (d.dataset.clNode === id) { r = d; } }); return r; }
		function prefShow() { // die bevorzugte Node ist keine Ersatz-Node
			var pref = $('#m64-cl-pref', body).value;
			$$('#m64-cl-backs [data-cl-node]', body).forEach(function (d) { var x = $('input', d), on = d.dataset.clNode === pref; x.disabled = on; if (on) { x.checked = false; } d.classList.toggle('opacity-50', on); });
			$$('#m64-cl-reach-res [data-cl-add]', body).forEach(function (b) { b.classList.toggle('d-none', b.dataset.clAdd === pref); }); // kein Vorschlag fuer die bevorzugte Node
		}
		$('#m64-cl-pref', body).onchange = prefShow;
		prefShow();
		var rb = $('#m64-cl-reach', body);
		rb.onclick = function () {
			var res = $('#m64-cl-reach-res', body);
			res.innerHTML = '<span class="spinner-border spinner-border-sm"></span> ' + esc(L('cluster.reaching'));
			lock(rb, function () {
				return api('POST', '/api/monitor64/cluster/hosts/' + encodeURIComponent(uid) + '/reach').then(function (r) {
					var pref = $('#m64-cl-pref', body).value;
					res.innerHTML = reachHTML(r.nodes || [], pref, function (id) { var d = backBox(id); return !d || $('input', d).checked; });
					(r.nodes || []).forEach(function (n) {
						var d = backBox(n.node), m = d && $('[data-cl-reach]', d);
						if (m) { m.innerHTML = n.ok ? '<i class="bi bi-check-circle-fill text-success" title="' + esc(L('cluster.reach_ok', { n: n.name })) + '"></i>' : '<i class="bi bi-x-circle-fill text-danger" title="' + esc(L('cluster.reach_fail', { n: n.name })) + '"></i>'; }
					});
				}).catch(function (e) { res.innerHTML = '<span class="text-danger">' + esc(tx(e.message)) + '</span>'; });
			});
		};
		// Vorschlag "als Ersatz eintragen": setzt das Haekchen der Node
		body.addEventListener('click', function (ev) {
			var a = ev.target.closest('[data-cl-add]');
			if (!a) { return; }
			var d = backBox(a.dataset.clAdd), x = d && $('input', d);
			if (x && !x.disabled) { x.checked = true; a.outerHTML = '<span class="text-success"><i class="bi bi-check2"></i> ' + esc(L('cluster.reach_added')) + '</span>'; }
		});
	}
	// reachHTML: Ergebnis je Node mit Vorschlag "als Ersatz eintragen" (erreichbare Nodes ausser der bevorzugten, noch nicht gewaehlt).
	function reachHTML(list, pref, chosen) {
		return '<ul class="list-unstyled mb-0">' + list.map(function (n) {
			var head;
			if (n.ok) { head = '<i class="bi bi-check-circle-fill text-success"></i> ' + esc(L('cluster.reach_ok', { n: n.name })) + (n.self ? ' <span class="text-body-tertiary">' + esc(L('cluster.this_node')) + '</span>' : ''); }
			else if (n.error === 'offline') { head = '<i class="bi bi-dash-circle text-body-secondary"></i> ' + esc(L('cluster.reach_offline', { n: n.name })); }
			else { head = '<i class="bi bi-x-circle-fill text-danger"></i> ' + esc(L('cluster.reach_fail', { n: n.name })) + (n.error ? ' <span class="text-body-secondary">' + esc(tx(n.error)) + '</span>' : ''); }
			if (n.ok && n.node !== pref && !chosen(n.node)) { head += ' <button class="btn btn-sm btn-link p-0 ms-1" type="button" data-cl-add="' + esc(n.node) + '"><i class="bi bi-plus"></i> ' + esc(L('cluster.reach_add')) + '</button>'; }
			var acc = (n.accesses || []).map(function (a) {
				var st = a.skip ? '<span class="text-body-secondary">' + esc(L('cluster.reach_skip')) + '</span>' : a.ok ? '<span class="text-success">' + esc(L('cluster.reach_ms', { ms: a.ms })) + '</span>' : '<span class="text-danger-emphasis">' + esc(tx(a.error || '')) + '</span>';
				return '<div class="ps-4">' + esc(accLabel(a.type)) + ': ' + st + '</div>';
			}).join('');
			return '<li class="mb-1">' + head + acc + '</li>';
		}).join('') + '</ul>';
	}
	function renderAll() { renderHead(); renderNew(); renderServices(); renderAccesses(); renderCluster(); }
	function reload() {
		var p = [api('GET', '/api/monitor64/hosts/' + encodeURIComponent(uid))];
		if (CH) { p.push(api('GET', '/api/monitor64/cluster/views?host=' + encodeURIComponent(uid)).catch(function () { return null; })); } // "ueberwacht von"
		return Promise.all(p).then(function (r) {
			H = r[0];
			if (r[1] && CH) { CH.ref = (r[1].refs || {})[uid] || null; }
			renderAll();
			return H;
		});
	}
	function loadSparks() { api('GET', '/api/monitor64/sparks?host=' + encodeURIComponent(uid)).then(function (s) { sparks = s || {}; renderServices(); }).catch(failQuiet); }

	// Diagramme
	function chartTitle(id) { return { cpu: L('chart.cpu'), ram: L('chart.ram'), net: L('chart.net'), disk: L('chart.disk') }[id] || id; }
	function buildCharts() {
		charts.forEach(function (c) { c.destroy(); });
		charts = [];
		var gen = ++HV.gen; // aeltere Antworten werden verworfen
		var defs = H.charts || [], miss = {};
		setHTML($('#m64-chart-note'), '');
		$('#m64-chart-bar').classList.toggle('d-none', !defs.length);
		var box = $('#m64-charts');
		box.innerHTML = defs.map(function (c) {
			var u = unitFmt(c.unit);
			return '<div class="col-12 col-xl-6"><div class="card"><div class="card-body py-2"><div class="small fw-semibold mb-1">' + esc(chartTitle(c.id)) + ' <span class="text-body-secondary fw-normal">' + esc(u.label) + '</span></div><div class="chart-box"><canvas id="m64-ch-' + esc(c.id) + '"></canvas><div class="zoom-sel"></div></div></div></div></div>';
		}).join('');
		if (!defs.length) { return; }
		$$('[data-range]').forEach(function (b) { b.classList.toggle('active', b.dataset.range === HV.range); });
		$('#m64-newer').disabled = HV.off === 0 && !HV.zoom;
		$('#m64-chart-span').textContent = HV.zoom ? '' : HV.off ? L('chart.until_ago', { n: HV.off, r: RANGES[HV.range] }) : L('chart.until_now');
		$('#m64-zoom').innerHTML = HV.zoom ? '<button class="btn btn-sm btn-outline-primary" type="button" id="m64-zoom-reset"><i class="bi bi-zoom-out"></i> ' + esc(L('chart.zoom_reset')) + '</button>' : '<span class="small text-body-secondary d-none d-md-inline"><i class="bi bi-mouse"></i> ' + esc(L('chart.zoom_hint')) + '</span>';
		var zr = $('#m64-zoom-reset');
		if (zr) { zr.onclick = function () { HV.zoom = null; buildCharts(); }; }
		defs.forEach(function (c) {
			var qs = 'host=' + encodeURIComponent(uid) + c.series.map(function (s) { return '&s=' + encodeURIComponent(s.svc + '|' + s.metric); }).join('');
			qs += HV.zoom ? '&from=' + HV.zoom[0] + '&to=' + HV.zoom[1] : '&range=' + HV.range + '&off=' + HV.off;
			api('GET', '/api/monitor64/series?' + qs).then(function (res) {
				var cv = document.getElementById('m64-ch-' + c.id);
				if (!cv || gen !== HV.gen) { return; }
				clMissing(res, miss, $('#m64-chart-note'));
				var old = window.Chart && window.Chart.getChart ? window.Chart.getChart(cv) : null;
				if (old) { old.destroy(); }
				var u = unitFmt(c.unit);
				var ch = lineChart(cv, { from: res.from, to: res.to, max: c.max, warn: c.warn, crit: c.crit, fmt: u.fmt,
					series: c.series.map(function (s, i) { return { label: tx(s.label), data: toPoints(res.series[i] || {}, u.factor) }; }) });
				if (!ch) { return; }
				charts.push(destroyable(ch, dragZoom(cv, ch, function (a, b) { HV.zoom = [a, b]; buildCharts(); })));
			}).catch(function (e) { if (gen === HV.gen) { chartFail(document.getElementById('m64-ch-' + c.id), e); } });
		});
	}
	$$('[data-range]').forEach(function (b) { b.onclick = function () { HV.range = b.dataset.range; HV.off = 0; HV.zoom = null; store('range', HV.range); buildCharts(); }; });
	$('#m64-older').onclick = function () { HV.zoom = null; HV.off++; buildCharts(); };
	$('#m64-newer').onclick = function () { if (HV.zoom) { HV.zoom = null; } else { HV.off = Math.max(0, HV.off - 1); } buildCharts(); };

	// clMissing: Cluster – Stuecke des Verlaufs auf nicht erreichbaren Nodes (series.cluster) als Hinweis unter dem Diagramm.
	function clMissing(res, miss, el) {
		(res.cluster || []).forEach(function (x) { if (x.missing) { miss[x.name || x.node] = true; } });
		var names = Object.keys(miss);
		setHTML(el, names.length ? '<i class="bi bi-diagram-3"></i> ' + esc(L('cluster.chart_missing', { n: names.join(', ') })) : '');
	}

	// Dienst-Details (Offcanvas): Verlauf, je Messgroesse bzw. Zustandsregel die Stufen der Schwelle mit eigener
	// Einstellung "dieser Host", Soll-Zustand, Erweitert
	var sdChart = null, sdGen = 0;
	function lvlBox(active, icon, title, vals) {
		return '<div class="lvl' + (active ? ' active' : '') + '"><div class="lvl-head"><span><i class="bi ' + icon + '"></i> ' + title + '</span><span class="lvl-vals">' + vals + '</span></div></div>';
	}
	function ruleVals(r, e, unit) {
		// Werte einer einzelnen Stufe (nur gesetzte Felder), sonst "keine Abweichung"
		if (!r) { return '<span class="text-body-tertiary">' + esc(L('sd.none')) + '</span>'; }
		var m = kindMeta(e.kind) || {}, f = m.factor || 1, parts = [];
		if (r.mode === 'free' || (r.warn_free !== undefined && e.mode === 'free')) {
			parts.push('&lt; ' + (lim(r.warn_free) === null ? '–' : fmtNum(r.warn_free)) + ' / &lt; ' + (lim(r.crit_free) === null ? '–' : fmtNum(r.crit_free)) + ' ' + esc(L('unit.gb_free')));
		} else if (r.warn !== undefined || r.crit !== undefined) {
			var op = e.dir === 'down' ? '&lt;' : '≥';
			parts.push(op + ' ' + (r.warn === undefined ? '…' : lim(r.warn) === null ? '–' : fmtNum(r.warn / f)) + ' / ' + (r.crit === undefined ? '…' : lim(r.crit) === null ? '–' : fmtNum(r.crit / f)) + ' ' + esc(unit || ''));
		}
		if (r.severity) { parts.push(esc(sevLabel(r.severity))); }
		if (r['for'] !== undefined) { parts.push(esc(durLabel(r['for']))); }
		if (r.report === 'show') { parts.push('<span class="badge text-bg-secondary">' + esc(L('rl.show')) + '</span>'); }
		return parts.join(' · ') || '<span class="text-body-tertiary">' + esc(L('sd.none')) + '</span>';
	}
	function stdVals(r, kind) { // Standard einer Art als Anzeige-Werte (Felder der Effective-Form)
		var e = { warn: 'off', crit: 'off', warn_free: 'off', crit_free: 'off', dir: 'up', mode: 'used', kind: kind };
		if (r) { Object.keys(r).forEach(function (k) { e[k] = r[k]; }); }
		return e;
	}
	function metricByName(s, n) { var r = null; (s.metrics || []).forEach(function (m) { if (n && m.name === n) { r = m; } }); return r; }
	function unitOf(lv, s) {
		var meta = kindMeta(lv.kind) || {}, mt = metricByName(s, lv.metric);
		if (meta.unit === 'min') { return L('unit.min'); }
		if (meta.unit === 'days') { return L('unit.days'); }
		return (mt && mt.unit) || meta.unit || '';
	}
	function durOpts(cur, inherit) {
		var list = [0, 300, 900, 3600, 86400];
		if (cur !== undefined && list.indexOf(cur) < 0) { list.push(cur); }
		return '<option value="">' + esc(L('sd.inherits', { v: durLabel(inherit) })) + '</option>' + list.map(function (x) { return '<option value="' + x + '"' + (cur === x ? ' selected' : '') + '>' + esc(durLabel(x)) + '</option>'; }).join('');
	}
	// ruleBlock: eine Regel-Art des Dienstes mit den drei Stufen und der eigenen Einstellung am Host.
	function ruleBlock(s, lv, i) {
		var meta = kindMeta(lv.kind) || {}, e = lv.eff, unit = unitOf(lv, s), mt = metricByName(s, lv.metric);
		var own = !!(lv.service || lv.host_kind), grp = !own && !!lv.override, cur = lv.service || lv.host_kind || {}, scopeKind = !lv.service && !!lv.host_kind;
		var id = 'm64-sd' + i + '-', free = cur.mode === 'free' || (!cur.mode && e.mode === 'free');
		var sv = lv.state ? esc(sevLabel(lv.std && lv.std.severity)) : thrVals(stdVals(lv.std, lv.kind), unit);
		sv += lv.std && lv.std['for'] ? ' · ' + esc(durLabel(lv.std['for'])) : '';
		var html = '<div class="rule-block mb-3" data-rk="' + esc(lv.kind) + '"><div class="d-flex align-items-baseline gap-2 mb-1"><span class="fw-semibold me-auto">' + esc(kindLabel(lv.kind)) + '</span>' + (mt ? '<span class="small">' + esc(fmtVal(mt.value, mt.unit)) + '</span>' : '') + '</div>' +
			lvlBox(!grp && !own, 'bi-globe2', esc(L('sd.lvl_std')), sv) +
			lvlBox(grp, 'bi-tags', lv.override ? esc(targetLabel(lv.override.target_type, lv.override.target)) + ' <span class="text-body-tertiary small">' + esc(L('sd.ovr_no', { n: lv.override.index + 1 })) + '</span>' : esc(L('sd.lvl_ovr')), lv.override ? ruleVals(lv.override.rule, e, unit) : '<span class="text-body-tertiary">' + esc(L('sd.none')) + '</span>');
		html += '<div class="lvl' + (own ? ' active' : '') + '"><div class="lvl-head mb-2"><span><i class="bi bi-hdd"></i> ' + esc(L('sd.lvl_host')) + '</span>' +
			(own ? '<button class="btn btn-link btn-sm p-0" type="button" data-sd-reset="' + esc(lv.kind) + '"><i class="bi bi-arrow-counterclockwise"></i> ' + esc(L('sd.reset')) + '</button>' : '<span class="text-body-tertiary small">' + esc(L('sd.not_set')) + '</span>') + '</div>';
		if (lv.state) {
			html += '<div class="row g-2"><div class="col-6"><label class="form-label small mb-0" for="' + id + 'sev">' + esc(L('sd.on_fault')) + '</label><select class="form-select form-select-sm rb-sev" id="' + id + 'sev"><option value="">' + esc(L('sd.inherits', { v: sevLabel(e.severity) })) + '</option>' +
				['crit', 'warn', 'off'].map(function (x) { return '<option value="' + x + '"' + (cur.severity === x ? ' selected' : '') + '>' + esc(sevLabel(x)) + '</option>'; }).join('') + '</select></div>' +
				'<div class="col-6"><label class="form-label small mb-0" for="' + id + 'f">' + esc(L('rl.for')) + '</label><select class="form-select form-select-sm rb-for" id="' + id + 'f">' + durOpts(cur['for'], e['for']) + '</select></div></div>';
		} else {
			html += (meta.store ? '<div class="btn-group btn-group-sm mb-2" role="group"><input type="radio" class="btn-check rb-mode" name="' + id + 'mode" id="' + id + 'mp" value="used"' + (free ? '' : ' checked') + '><label class="btn btn-outline-secondary" for="' + id + 'mp">' + esc(L('sd.mode_used')) + '</label>' +
				'<input type="radio" class="btn-check rb-mode" name="' + id + 'mode" id="' + id + 'mf" value="free"' + (free ? ' checked' : '') + '><label class="btn btn-outline-secondary" for="' + id + 'mf">' + esc(L('sd.mode_free')) + '</label></div>' : '') +
				'<div class="row g-2"><div class="col-4"><label class="form-label small mb-0 rb-lw" for="' + id + 'w">' + esc(L('rl.warn')) + '</label><div class="input-group input-group-sm"><input class="form-control rb-w" id="' + id + 'w" inputmode="decimal"><span class="input-group-text rb-u"></span></div></div>' +
				'<div class="col-4"><label class="form-label small mb-0 rb-lc" for="' + id + 'c">' + esc(L('rl.crit')) + '</label><div class="input-group input-group-sm"><input class="form-control rb-c" id="' + id + 'c" inputmode="decimal"><span class="input-group-text rb-u"></span></div></div>' +
				'<div class="col-4"><label class="form-label small mb-0" for="' + id + 'f">' + esc(L('rl.for')) + '</label><select class="form-select form-select-sm rb-for" id="' + id + 'f">' + durOpts(cur['for'], e['for']) + '</select></div>' +
				'<div class="col-4"><label class="form-label small mb-0" for="' + id + 'h">' + esc(L('sd.hyst')) + '</label><div class="input-group input-group-sm"><input class="form-control rb-h" id="' + id + 'h" inputmode="decimal" placeholder="' + esc(L('sd.inherits', { v: fmtNum(e.hyst) })) + '" value="' + esc(numIn(cur.hyst)) + '"><span class="input-group-text rb-u"></span></div></div>' +
				'<div class="col-8 small text-body-secondary align-self-end rb-hint"></div></div>';
		}
		html += '<div class="d-flex flex-wrap align-items-center gap-2 mt-2 small"><label class="text-body-secondary" for="' + id + 'r">' + esc(L('sd.report')) + '</label><select class="form-select form-select-sm w-auto rb-r" id="' + id + 'r"><option value="">' + esc(L('sd.inherits', { v: e.report === 'show' ? L('rl.show') : L('rl.notify') })) + '</option><option value="notify"' + (cur.report === 'notify' ? ' selected' : '') + '>' + esc(L('rl.notify')) + '</option><option value="show"' + (cur.report === 'show' ? ' selected' : '') + '>' + esc(L('rl.show')) + '</option></select>' +
			'<span class="text-body-tertiary">' + esc(L('sd.show_hint')) + '</span></div>' +
			'<div class="mt-2 small"><span class="text-body-secondary me-2">' + esc(L('sd.applies')) + '</span>' +
			'<div class="form-check form-check-inline"><input class="form-check-input rb-scope" type="radio" name="' + id + 'scope" id="' + id + 's1" value="service"' + (scopeKind ? '' : ' checked') + '><label class="form-check-label" for="' + id + 's1">' + esc(L('sd.scope_service')) + '</label></div>' +
			'<div class="form-check form-check-inline"><input class="form-check-input rb-scope" type="radio" name="' + id + 'scope" id="' + id + 's2" value="kind"' + (scopeKind ? ' checked' : '') + '><label class="form-check-label" for="' + id + 's2">' + esc(L('sd.scope_kind', { c: kindLabel(lv.kind) })) + '</label></div></div></div></div>';
		return html;
	}
	// Block: Eingaben vorbelegen (exakte Werte), Modus umschalten, Stand merken (nur geaenderte Arten werden gesendet).
	function initBlock(el, lv, s) {
		var meta = kindMeta(lv.kind) || {}, f = meta.factor || 1, e = lv.eff, unit = unitOf(lv, s), mt = metricByName(s, lv.metric), cur = lv.service || lv.host_kind || {};
		var b = { el: el, lv: lv, f: f, store: !!meta.store, unit: unit };
		function q(c) { return $('.' + c, el); }
		if (q('rb-h')) { // Hysterese in der angezeigten Einheit (wie Warnung/Kritisch; gespeichert in der Basiseinheit)
			q('rb-h').placeholder = L('sd.inherits', { v: fmtNum(e.hyst == null ? e.hyst : e.hyst / f) });
			q('rb-h').value = cur.hyst == null ? '' : numIn(cur.hyst / f);
		}
		b.mode = function () { var r = $('.rb-mode:checked', el); return r ? r.value : (e.mode === 'free' ? 'free' : 'used'); };
		function capGB() { return mt && mt.max ? mt.max / 1e9 : 0; }
		function setMode(changed) {
			var free = b.mode() === 'free';
			$$('.rb-u', el).forEach(function (x) { x.textContent = free ? L('unit.gb_free') : (unit || '–'); });
			q('rb-lw').textContent = free ? L('sd.warn_below') : L('rl.warn');
			q('rb-lc').textContent = free ? L('sd.crit_below') : L('rl.crit');
			var iw = free ? lim(e.warn_free) : lim(e.warn), ic = free ? lim(e.crit_free) : lim(e.crit);
			if (!free && iw !== null) { iw /= f; }
			if (!free && ic !== null) { ic /= f; }
			var same = (e.mode === 'free') === free;
			q('rb-w').placeholder = same && iw !== null ? L('sd.inherits', { v: fmtNum(iw) }) : (free ? L('sd.example', { v: fmtNum(Math.round(capGB() * 0.1)) }) : '');
			q('rb-c').placeholder = same && ic !== null ? L('sd.inherits', { v: fmtNum(ic) }) : (free ? L('sd.example', { v: fmtNum(Math.round(capGB() * 0.05)) }) : '');
			if (!changed) {
				var cw = free ? cur.warn_free : cur.warn, cc = free ? cur.crit_free : cur.crit;
				q('rb-w').value = cw === undefined || lim(cw) === null ? '' : numIn(free ? cw : cw / f);
				q('rb-c').value = cc === undefined || lim(cc) === null ? '' : numIn(free ? cc : cc / f);
			} else { q('rb-w').value = ''; q('rb-c').value = ''; }
			var hint = '';
			if (b.store && mt) { hint = free ? L('sd.hint_free', { f: fmtNum(capGB() * (100 - mt.value) / 100), c: fmtNum(capGB()) }) : L('sd.hint_used', { v: fmtNum(mt.value) }); }
			else if (!free && lim(e.warn) !== null) { hint = L('sd.hyst_hint', { v: fmtNum(lim(e.warn) / f), h: fmtNum(e.hyst == null ? e.hyst : e.hyst / f) }); }
			q('rb-hint').textContent = hint;
		}
		if (!lv.state) {
			setMode(false);
			$$('.rb-mode', el).forEach(function (r) { r.onchange = function () { setMode(true); }; });
		}
		b.snap = snapshot(el);
		return b;
	}
	function snapshot(el) { return $$('input, select', el).map(function (x) { return x.type === 'radio' || x.type === 'checkbox' ? (x.checked ? '1' : '0') : x.value; }).join('|'); }
	// ruleOf: Regel aus den Eingaben eines Blocks (null = ungueltige Zahl).
	function ruleOf(b) {
		var el = b.el, lv = b.lv, rule = {};
		function v(c) { var x = $('.' + c, el); return x ? x.value : ''; }
		if (lv.state) {
			if (v('rb-sev')) { rule.severity = v('rb-sev'); }
		} else {
			var free = b.mode() === 'free', w = parseNum(v('rb-w')), c = parseNum(v('rb-c')), h = parseNum(v('rb-h'));
			if ((w !== null && isNaN(w)) || (c !== null && isNaN(c)) || (h !== null && (isNaN(h) || h < 0))) { return null; }
			if (b.store && (free !== (lv.eff.mode === 'free') || (lv.service || lv.host_kind || {}).mode)) { rule.mode = free ? 'free' : 'used'; }
			if (w !== null) { rule[free ? 'warn_free' : 'warn'] = free ? w : w * b.f; }
			if (c !== null) { rule[free ? 'crit_free' : 'crit'] = free ? c : c * b.f; }
			if (h !== null) { rule.hyst = h * b.f; }
		}
		if (v('rb-for') !== '') { rule['for'] = parseInt(v('rb-for'), 10); }
		if (v('rb-r')) { rule.report = v('rb-r'); }
		return rule;
	}
	function openDetail(key) {
		var s = null;
		H.services.forEach(function (x) { if (x.key === key) { s = x; } });
		if (!s) { return; }
		detailFor = key;
		$('#m64-sd-host').textContent = H.host.name + ' · ' + ((D.cats || {})[s.category] || s.category);
		$('#m64-sd-title').textContent = svcName(s);
		var st = H.view === 'unreachable' || clAway() ? 'unknown' : s.state, lv = s.levels, mt = s.primary >= 0 ? s.metrics[s.primary] : null, rules = s.rules || [];
		var html = '<div class="d-flex align-items-center gap-2 mb-3 flex-wrap">' + stBadge(st) + '<span>' + esc(mt ? fmtVal(mt.value, mt.unit) : '') + (mt && s.text ? ' · ' : '') + esc(tx(s.text || '')) + '</span></div>';
		if (s.cause && st !== 'ok') { html += '<div class="alert alert-' + (st === 'crit' ? 'danger' : 'warning') + ' py-2 small">' + esc(tx(s.cause)) + '</div>'; }
		if (s.vanished) { html += '<div class="alert alert-warning py-2 small"><i class="bi bi-question-diamond"></i> ' + esc(L('sd.vanished')) + '</div>'; }
		if (mt && mt.status && (mt.status.pending === 'warn' || mt.status.pending === 'crit') && toDate(mt.status.pending_since)) {
			var p = mt.status, ps = toDate(p.pending_since), pa = toDate(p.pending_at), need = pa ? (pa.getTime() - ps.getTime()) / 60000 : 1, done = (Date.now() - ps.getTime()) / 60000;
			html += '<div class="pend mb-3"><div class="small mb-1"><i class="bi bi-hourglass-split"></i> ' + esc(pendText(p, mt.unit, isFree(lv))) + '</div><div class="progress" style="height:.35rem"><div class="progress-bar bg-warning" style="width:' + Math.min(100, Math.round(done / Math.max(need, 1) * 100)) + '%"></div></div><div class="small text-body-secondary mt-1">' + esc(L('sd.pending_hint')) + '</div></div>';
		}
		(s.metrics || []).forEach(function (m) {
			if ((m.rule_kind || m.rule) === 'fs.trend_days' && m.value < 1e5) { html += '<div class="alert alert-danger py-2 small"><i class="bi bi-graph-up-arrow"></i> ' + esc(L('sd.trend', { n: fmtNum(m.value, 1) })) + '</div>'; }
		});
		var chartMetric = mt || ((s.metrics || []).length ? s.metrics[0] : null);
		if (s.kind === 'traps') { // letzte Traps statt Diagramm
			chartMetric = null;
			html += '<div class="mb-3" id="m64-sd-traps"><span class="spinner-border spinner-border-sm"></span></div>';
		}
		if (chartMetric) { html += '<div class="chart-box mb-1"><canvas id="m64-sd-chart"></canvas><div class="zoom-sel"></div></div><div class="small text-warning-emphasis mb-3" id="m64-sd-chart-note"></div>'; }
		if (rules.length) {
			html += '<h6 class="mt-2">' + esc(rules.length > 1 ? L('sd.thresholds') : L('sd.threshold')) + ' <span class="small text-body-secondary fw-normal">– ' + esc(L('sd.threshold_sub')) + '</span></h6>';
			rules.forEach(function (r, i) { html += ruleBlock(s, r, i); });
		}
		if (s.guest) {
			html += '<h6 class="mt-3">' + esc(L('sd.soll')) + '</h6><div class="lvl active"><div class="btn-group btn-group-sm mb-2" role="group">' +
				'<input type="radio" class="btn-check" name="m64-sd-soll" id="m64-sd-so0" value=""' + (!s.soll ? ' checked' : '') + '><label class="btn btn-outline-secondary" for="m64-sd-so0"><i class="bi bi-magic"></i> ' + esc(L('sd.soll_auto')) + '</label>' +
				'<input type="radio" class="btn-check" name="m64-sd-soll" id="m64-sd-so1" value="run"' + (s.soll === 'run' ? ' checked' : '') + '><label class="btn btn-outline-secondary" for="m64-sd-so1"><i class="bi bi-play-fill"></i> ' + esc(L('sd.soll_run')) + '</label>' +
				'<input type="radio" class="btn-check" name="m64-sd-soll" id="m64-sd-so2" value="off"' + (s.soll === 'off' ? ' checked' : '') + '><label class="btn btn-outline-secondary" for="m64-sd-so2"><i class="bi bi-pause-fill"></i> ' + esc(L('sd.soll_off')) + '</label></div>' +
				'<div class="small text-body-secondary"><i class="bi bi-magic"></i> ' + esc(L('sd.soll_hint')) + '</div></div>';
		}
		html += '<details class="mt-3"><summary class="small text-body-secondary">' + esc(L('advanced')) + '</summary><div class="pt-2">' +
			'<div class="mb-2"><label class="form-label small mb-0" for="m64-sd-name">' + esc(L('sd.display_name')) + '</label><input class="form-control form-control-sm" id="m64-sd-name" maxlength="200" value="' + esc(tx(s.custom_name || '')) + '" placeholder="' + esc(svcName(s)) + '"></div>' +
			'<div class="small text-body-secondary mt-1">' + esc(L('sd.access_info', { a: tx(s.via || '') || '–', i: fmtDur(H.host.interval_sec) })) + '</div><div class="small text-body-tertiary">' + esc(s.key) + '</div></div></details>';
		var canAck = st !== 'ok' && s.since;
		html += '<div class="d-flex flex-wrap gap-2 mt-3"><button class="btn btn-primary btn-sm" type="button" data-sd="save">' + esc(L('save')) + '</button>' +
			(canAck && !s.ack ? '<button class="btn btn-outline-secondary btn-sm" type="button" data-sd="ack"><i class="bi bi-check2"></i> ' + esc(L('ov.ack')) + '</button>' : '') +
			(s.ack ? '<button class="btn btn-outline-secondary btn-sm" type="button" data-sd="unack"><i class="bi bi-arrow-counterclockwise"></i> ' + esc(L('ov.unack')) + '</button>' : '') +
			(s.vanished ? '<button class="btn btn-outline-danger btn-sm ms-auto" type="button" data-sd="remove"><i class="bi bi-trash"></i> ' + esc(L('sd.remove')) + '</button>' :
				s.kind !== 'access' ? '<button class="btn btn-outline-secondary btn-sm ms-auto" type="button" data-sd="ignore"><i class="bi bi-eye-slash"></i> ' + esc(L('sd.ignore')) + '</button>' : '') + '</div>';
		var body = $('#m64-sd-body');
		body.innerHTML = html;
		var blocks = $$('[data-rk]', body).map(function (el, i) { return initBlock(el, rules[i], s); });
		var svcURL = '/api/monitor64/hosts/' + encodeURIComponent(uid) + '/service';
		function after(msg) { return function () { toast(msg); closeDetail(); return reload(); }; }
		$$('[data-sd-reset]', body).forEach(function (b) {
			b.onclick = function () {
				var rq = { key: s.key, rules: {} };
				rq.rules[b.dataset.sdReset] = { reset: true };
				lock(b, function () { return api('PUT', svcURL, rq).then(after(L('sd.reset_toast'))); }).catch(fail);
			};
		});
		$$('[data-sd]', body).forEach(function (b) {
			b.onclick = function () {
				var a = b.dataset.sd;
				if (a === 'ack' || a === 'unack') {
					lock(b, function () { return api('POST', '/api/monitor64/problems/action', { host: uid, key: s.key, action: a, comment: '' }).then(after(a === 'ack' ? L('ov.acked_toast') : L('ov.unacked_toast'))); }).catch(fail);
				} else if (a === 'ignore') {
					lock(b, function () { return api('POST', '/api/monitor64/hosts/' + encodeURIComponent(uid) + '/services/adopt', { keys: [s.key], state: -1 }).then(after(L('sd.ignored_toast'))); }).catch(fail);
				} else if (a === 'remove') {
					confirmBox(L('sd.remove'), L('sd.remove_confirm', { n: svcName(s) }), L('sd.remove'), function () {
						return api('POST', '/api/monitor64/hosts/' + encodeURIComponent(uid) + '/services/remove', { keys: [s.key] }).then(after(L('sd.removed_toast'))).catch(fail);
					});
				} else if (a === 'save') { lock(b, save).catch(fail); }
			};
		});
		function save() {
			var req = { key: s.key };
			var nm = $('#m64-sd-name', body).value.trim();
			if (nm !== tx(s.custom_name || '')) { req.name = nm; } // angezeigt wird der uebersetzte Name: unveraendert = nicht senden
			var so = $('[name=m64-sd-soll]:checked', body);
			if (so && so.value !== (s.soll || '')) { req.soll = so.value; }
			var changes = {}, bad = false;
			blocks.forEach(function (b) {
				if (snapshot(b.el) === b.snap) { return; } // unveraendert: nicht senden
				var rule = ruleOf(b), sc = $('.rb-scope:checked', b.el);
				if (rule === null) { bad = true; return; }
				changes[b.lv.kind] = { rule: rule, scope: sc ? sc.value : 'service' };
			});
			if (bad) { toast(L('err_number'), true); return Promise.resolve(); }
			if (Object.keys(changes).length) { req.rules = changes; }
			if (Object.keys(req).length === 1) { closeDetail(); return Promise.resolve(); }
			return api('PUT', svcURL, req).then(after(L('sd.saved_toast')));
		}
		var oc = window.bootstrap.Offcanvas.getOrCreateInstance(document.getElementById('m64-detail'));
		oc.show();
		if (s.kind === 'traps') { loadTraps(key); }
		if (sdChart) { sdChart.destroy(); sdChart = null; }
		if (chartMetric) {
			var gen = ++sdGen;
			api('GET', '/api/monitor64/series?host=' + encodeURIComponent(uid) + '&s=' + encodeURIComponent(s.key + '|' + chartMetric.name) + '&range=24h').then(function (res) {
				var cv = document.getElementById('m64-sd-chart');
				if (!cv || detailFor !== key || gen !== sdGen) { return; }
				if (sdChart) { sdChart.destroy(); sdChart = null; }
				clMissing(res, {}, document.getElementById('m64-sd-chart-note'));
				var u = unitFmt(chartMetric.unit), w = null, c = null;
				if (lv && lv.eff.mode !== 'free' && chartMetric === mt) { w = lim(lv.eff.warn); c = lim(lv.eff.crit); } // Schwellen in der Einheit der Messgroesse
				sdChart = lineChart(cv, { from: res.from, to: res.to, warn: w, crit: c, fmt: u.fmt, max: chartMetric.unit === '%' ? 100 : undefined, series: [{ label: svcName(s), data: toPoints(res.series[0] || {}, u.factor) }] });
			}).catch(function (e) { if (gen === sdGen) { chartFail(document.getElementById('m64-sd-chart'), e); } });
		}
	}
	// loadTraps zeigt die letzten Traps des Hosts im Dienst "traps" (Texte vom Geraet, immer escaped).
	function loadTraps(key) {
		var trapsURL = '/api/monitor64/hosts/' + encodeURIComponent(uid) + '/traps';
		api('GET', trapsURL).then(function (r) {
			var box = document.getElementById('m64-sd-traps');
			if (!box || detailFor !== key) { return; }
			var html = '<div class="d-flex align-items-center small mb-1"><span class="me-auto text-body-secondary">' + esc(L('sd.traps_pending', { n: r.pending, t: r.total })) + '</span>' +
				(r.pending ? '<button class="btn btn-sm btn-link p-0" type="button" data-traps-reset><i class="bi bi-arrow-counterclockwise"></i> ' + esc(L('sd.traps_reset')) + '</button>' : '') + '</div>';
			if (r.rejected) { html += '<div class="small text-warning-emphasis mb-1"><i class="bi bi-shield-x"></i> ' + esc(L('sd.traps_rejected', { n: r.rejected, r: r.reject_reason || '', at: fmtTime(r.rejected_at) })) + '</div>'; }
			html += (r.list || []).length ? '<div class="list-group list-group-flush small">' + r.list.map(function (e) {
				var vb = (e.varbinds || []).map(function (v) { return esc(v.oid) + ' = ' + esc(v.value); }).join('<br>');
				return '<div class="list-group-item px-0"><div class="d-flex gap-2"><span class="me-auto fw-semibold text-break">' + esc(e.trap_name || e.trap_oid || 'Trap') + '</span>' +
					(e.handled ? '<span class="badge text-bg-light" title="' + esc(L('sd.traps_handled_hint')) + '">' + esc(L('sd.traps_handled')) + '</span>' : '') +
					'<span class="text-body-secondary text-nowrap">' + esc(fmtTime(e.time)) + '</span></div>' +
					'<div class="text-body-secondary">v' + esc(e.version) + (e.inform ? ' · Inform' : '') + (e.user ? ' · ' + esc(e.user) : '') + (e.trap_name && e.trap_oid ? ' · ' + esc(e.trap_oid) : '') + '</div>' +
					(vb ? '<details><summary class="text-body-secondary">' + esc(L('sd.traps_values', { n: (e.varbinds || []).length })) + '</summary><div class="font-monospace text-break">' + vb + (e.truncated ? '<br>…' : '') + '</div></details>' : '') + '</div>';
			}).join('') + '</div>' : '<div class="small text-body-secondary">' + esc(L('sd.traps_none')) + '</div>';
			box.innerHTML = html;
			var rb = $('[data-traps-reset]', box);
			if (rb) { rb.onclick = function () { lock(rb, function () { return api('POST', trapsURL + '/reset').then(function () { toast(L('sd.traps_reset_toast')); closeDetail(); return reload(); }); }).catch(fail); }; }
		}).catch(function (e) { var box = document.getElementById('m64-sd-traps'); if (box) { box.innerHTML = '<span class="small text-danger">' + esc(tx(e.message)) + '</span>'; } });
	}
	function closeDetail() { var oc = window.bootstrap.Offcanvas.getInstance(document.getElementById('m64-detail')); if (oc) { oc.hide(); } detailFor = null; }
	document.getElementById('m64-detail').addEventListener('hidden.bs.offcanvas', function () {
		detailFor = null;
		sdGen++;
		if (sdChart) { sdChart.destroy(); sdChart = null; }
		if (location.hash.indexOf('#svc=') === 0) { history.replaceState(null, '', location.pathname); }
	});

	// Dialoge: Host bearbeiten, Zugang, Wartung, Entfernen
	function intervalOpts(cur) {
		return [30, 60, 120, 300, 600, 900].map(function (s) { return '<option value="' + s + '"' + (s === cur ? ' selected' : '') + '>' + esc(s < 60 ? L('iv.sec', { n: s }) : fmtDur(s)) + '</option>'; }).join('');
	}
	function hostForm(h) {
		var groups = (D.targets && D.targets.groups) || [];
		return '<div class="row g-3"><div class="col-md-6"><label class="form-label" for="m64-hf-name">' + esc(L('f.name')) + '</label><input class="form-control" id="m64-hf-name" maxlength="100" value="' + esc(h.name) + '"></div>' +
			'<div class="col-md-6"><label class="form-label" for="m64-hf-addr">' + esc(L('f.address')) + '</label><input class="form-control" id="m64-hf-addr" maxlength="253" value="' + esc(h.address) + '"></div>' +
			'<div class="col-md-6"><label class="form-label" for="m64-hf-group">' + esc(L('f.group')) + '</label><input class="form-control" id="m64-hf-group" maxlength="64" list="m64-groups-dl" value="' + esc(h.group) + '"><datalist id="m64-groups-dl">' + groups.map(function (g) { return '<option value="' + esc(g) + '">'; }).join('') + '</datalist></div>' +
			'<div class="col-md-6"><label class="form-label" for="m64-hf-tags">' + esc(L('f.tags')) + '</label><input class="form-control" id="m64-hf-tags" value="' + esc((h.tags || []).join(', ')) + '"><div class="form-text">' + esc(L('f.tags_hint')) + '</div></div>' +
			'<div class="col-md-6"><label class="form-label" for="m64-hf-iv">' + esc(L('f.interval')) + '</label><select class="form-select" id="m64-hf-iv">' + intervalOpts(h.interval_sec) + '</select></div>' +
			'<div class="col-md-6 d-flex align-items-end"><div class="form-check form-switch"><input class="form-check-input" type="checkbox" id="m64-hf-auto"' + (h.agent_autoupdate ? ' checked' : '') + '><label class="form-check-label" for="m64-hf-auto">' + esc(L('f.autoupdate')) + '</label></div></div>' +
			'<div class="col-12"><label class="form-label" for="m64-hf-notes">' + esc(L('f.notes')) + '</label><textarea class="form-control" id="m64-hf-notes" rows="2" maxlength="1000">' + esc(h.notes || '') + '</textarea></div></div>';
	}
	function hostFromForm(h) {
		return { name: $('#m64-hf-name').value, address: $('#m64-hf-addr').value, kind: h.kind, group: $('#m64-hf-group').value, tags: $('#m64-hf-tags').value.split(/[,\s]+/).filter(Boolean),
			interval_sec: parseInt($('#m64-hf-iv').value, 10), notes: $('#m64-hf-notes').value, paused: h.paused, agent_autoupdate: $('#m64-hf-auto').checked };
	}
	function hostPut(body) { return api('PUT', '/api/monitor64/hosts/' + encodeURIComponent(uid), body); }
	function accessForm(a) {
		var t = a ? a.type : 'agent', c = (a && a.config) || {};
		var types = ['agent', 'ssh', 'pve', 'pbs', 'docker'].concat(DEVAPI, ['snmp']);
		return '<div class="row g-3"><div class="col-md-6"><label class="form-label" for="m64-af-type">' + esc(L('acc.type')) + '</label><select class="form-select" id="m64-af-type"' + (a ? ' disabled' : '') + '>' + types.map(function (x) { return '<option value="' + x + '"' + (x === t ? ' selected' : '') + '>' + esc(accLabel(x)) + '</option>'; }).join('') + '</select></div>' +
			'<div class="col-md-6 d-flex align-items-end"><div class="form-check form-switch"><input class="form-check-input" type="checkbox" id="m64-af-en"' + (!a || a.enabled ? ' checked' : '') + '><label class="form-check-label" for="m64-af-en">' + esc(L('acc.enabled')) + '</label></div></div>' +
			'<div class="col-md-8" data-af="agent"><label class="form-label" for="m64-af-mode">' + esc(L('push.mode_label')) + '</label><select class="form-select" id="m64-af-mode"><option value="">' + esc(L('push.mode_pull')) + '</option><option value="push"' + (c.mode === 'push' ? ' selected' : '') + '>' + esc(L('push.mode_push')) + '</option></select></div>' +
			(c.mode === 'push' && c.token ? '<div class="col-12" data-af="agent"><div class="form-label">' + esc(L('push.token')) + '</div><code class="small">' + esc(c.token) + '</code><div class="form-text">' + esc(L('push.token_hint')) + '</div>' +
				'<div class="form-check"><input class="form-check-input" type="checkbox" id="m64-af-newtok"><label class="form-check-label small" for="m64-af-newtok">' + esc(L('push.token_new')) + '</label></div></div>' : '') +
			'<div class="col-md-4" data-af="agent ssh"><label class="form-label" for="m64-af-port">' + esc(L('acc.port')) + '</label><input class="form-control" id="m64-af-port" type="number" min="0" max="65535" value="' + esc(c.port || '') + '" placeholder="' + esc(t === 'ssh' ? '22' : String(D.port || 6465)) + '"></div>' +
			'<div class="col-md-8" data-af="ssh prom nut truenas redfish"><label class="form-label" for="m64-af-user">' + esc(L('acc.user')) + '</label><input class="form-control" id="m64-af-user" maxlength="32" value="' + esc(c.user || '') + '" placeholder="monitor64"></div>' +
			'<div class="col-12" data-af="ssh"><div class="form-check"><input class="form-check-input" type="checkbox" id="m64-af-smart"' + (c.smart ? ' checked' : '') + '><label class="form-check-label small" for="m64-af-smart">' + esc(L('new.smart')) + '</label></div></div>' +
			'<div class="col-12" data-af="pve pbs docker ' + DEVAPI.join(' ') + '"><label class="form-label" for="m64-af-url">URL</label><input class="form-control" id="m64-af-url" maxlength="512" value="' + esc(c.url || '') + '" placeholder="https://10.0.0.21:8006"><div class="form-text" data-af="docker">' + esc(L('new.docker_hint')) + '</div></div>' +
			'<div class="col-md-6" data-af="pve pbs"><label class="form-label" for="m64-af-tid">' + esc(L('new.token_id')) + '</label><input class="form-control" id="m64-af-tid" maxlength="128" value="' + esc(c.token_id || '') + '" placeholder="monitor@pve!node64"></div>' +
			'<div class="col-md-6" data-af="pve"><label class="form-label" for="m64-af-node">' + esc(L('new.node')) + '</label><input class="form-control" id="m64-af-node" maxlength="64" value="' + esc(c.node || '') + '"></div>' +
			'<div class="col-md-6" data-af="pbs"><label class="form-label" for="m64-af-bmax">' + esc(L('acc.backup_max_age')) + '</label><input class="form-control" id="m64-af-bmax" type="number" min="1" max="8760" placeholder="26" value="' + esc(c.backup_max_age_h || '') + '"><div class="form-text">' + esc(L('acc.backup_max_age_hint')) + '</div></div>' +
			devFields(c, 'af') +
			'<div class="col-12" data-af="snmp"><div class="row g-3">' + snmpFields('af', function (x) { return snmpVal(c, x); }, !!(a && a.secret_set && a.type === 'snmp')) + '</div></div>' +
			'<div class="col-12" data-af="pve pbs docker ' + DEVAPI.join(' ') + '"><label class="form-label" for="m64-af-pin">' + esc(L('new.pin')) + '</label><input class="form-control" id="m64-af-pin" maxlength="128" value="' + esc(c.pin || '') + '"></div>' +
			'<div class="col-12" data-af="ssh pve pbs ' + DEVAPI.join(' ') + '"><label class="form-label" for="m64-af-secret">' + esc(L('acc.secret')) + '</label><input class="form-control" id="m64-af-secret" type="password" autocomplete="new-password" placeholder="' + esc(a && a.secret_set ? L('acc.secret_keep') : '') + '">' +
			'<div class="form-text" id="m64-af-shint">' + esc(L('acc.secret_hint')) + '</div></div>' +
			'<div class="col-12" data-af="docker"><label class="form-label" for="m64-af-dsecret">' + esc(L('acc.docker_secret')) + '</label><textarea class="form-control font-monospace small" id="m64-af-dsecret" rows="4" spellcheck="false" autocomplete="off" placeholder="' + esc(a && a.secret_set ? L('acc.secret_keep') : '-----BEGIN …') + '"></textarea>' +
			'<div class="form-text">' + esc(L('acc.docker_secret_hint')) + '</div></div>' +
			(a && a.secret_set ? '<div class="col-12" data-af="ssh pve pbs docker snmp ' + DEVAPI.join(' ') + '"><div class="form-check"><input class="form-check-input" type="checkbox" id="m64-af-clear"><label class="form-check-label small" for="m64-af-clear">' + esc(L('acc.secret_clear')) + '</label></div></div>' : '') + '</div>';
	}
	function accessShow(body) {
		var t = $('#m64-af-type', body).value;
		$$('[data-af]', body).forEach(function (x) { x.classList.toggle('d-none', x.dataset.af.split(' ').indexOf(t) < 0); });
		$('#m64-af-url', body).placeholder = DEVAPI.indexOf(t) >= 0 ? devURL(t, H.host.address) : t === 'docker' ? 'unix:///var/run/docker.sock' : 'https://' + (urlHost(H.host.address) || '10.0.0.21') + ':' + (t === 'pbs' ? 8007 : 8006);
		$('#m64-af-shint', body).textContent = DEVAPI.indexOf(t) >= 0 ? devSecretHint(t) : L('acc.secret_hint');
		snmpShow(body, 'af');
	}
	// accessFromForm liest den Zugang aus dem Formular (a = gespeicherter Zugang beim Aendern, sonst null).
	function accessFromForm(body, a) {
		var t = $('#m64-af-type', body).value, cfg = {};
		var port = parseInt($('#m64-af-port', body).value, 10);
		if ((t === 'agent' || t === 'ssh') && port) { cfg.port = port; }
		if (t === 'agent' && $('#m64-af-mode', body).value === 'push') { cfg.mode = 'push'; delete cfg.port; }
		if (t === 'ssh') { cfg.user = $('#m64-af-user', body).value.trim(); cfg.smart = $('#m64-af-smart', body).checked; }
		if (t === 'pve' || t === 'pbs' || t === 'docker') { cfg.url = $('#m64-af-url', body).value.trim(); cfg.pin = $('#m64-af-pin', body).value.trim(); }
		if (t === 'pve' || t === 'pbs') { cfg.token_id = $('#m64-af-tid', body).value.trim(); }
		if (t === 'pve') { cfg.node = $('#m64-af-node', body).value.trim(); }
		if (t === 'pbs') { var bm = parseInt($('#m64-af-bmax', body).value, 10); if (bm > 0) { cfg.backup_max_age_h = bm; } }
		if (DEVAPI.indexOf(t) >= 0) {
			var m = devCfg(t, function (id) { var x = $('#m64-af-' + id, body); return x ? (x.type === 'checkbox' ? x.checked : x.value.trim()) : ''; });
			if (m === null) { throw new Error(L('acc.metrics_bad')); }
			cfg.url = $('#m64-af-url', body).value.trim();
			cfg.pin = $('#m64-af-pin', body).value.trim();
			Object.keys(m).forEach(function (x) { cfg[x] = m[x]; });
		}
		var secret = t === 'docker' ? $('#m64-af-dsecret', body).value.trim() : $('#m64-af-secret', body).value;
		if (t === 'snmp') {
			var sr = snmpRead(function (id) {
				if (id === 'profiles') { return a && a.type === 'snmp' ? snmpVal(a.config, id) : ''; }
				var x = $('#m64-af-s' + id, body);
				return x ? (x.type === 'checkbox' ? x.checked : SNMP_PASS.indexOf(id) >= 0 ? x.value : x.value.trim()) : '';
			});
			if (sr === null) { throw new Error(L('acc.snmp_custom_bad')); }
			cfg = sr.config;
			secret = sr.secret;
		}
		var out = { type: t, config: cfg, secret: secret, enabled: $('#m64-af-en', body).checked };
		var nt = $('#m64-af-newtok', body);
		if (nt && nt.checked) { out.new_token = true; }
		var cl = $('#m64-af-clear', body);
		if (cl && cl.checked) { out.clear_secret = true; }
		return out;
	}
	// accessDialog: Zugang anlegen (a = null) bzw. aendern, mit "Verbindung testen" und Bestaetigung des Fingerabdrucks.
	function accessDialog(a) {
		var au = a ? '/api/monitor64/access/' + encodeURIComponent(a.uid) : '';
		var hk = ''; // in diesem Dialog bestaetigter Hostschluessel (SSH mit Passwort)
		var body = modal(a ? L('acc.edit') + ' · ' + accLabel(a.type) : L('host.access_add'), accessForm(a), [{ label: L('cancel') }, { label: L('acc.test'), click: function () {
			var res = $('#m64-af-res', body), acc;
			try { acc = accessFromForm(body, a); } catch (e) { res.innerHTML = '<span class="text-danger">' + esc(e.message) + '</span>'; return null; }
			// gemerkter Schluessel nur, wenn schon ein Passwort hinterlegt war: wird erstmals eines gesetzt, muss der
			// (bisher nur gelernte) Schluessel erst bestaetigt werden
			if (acc.type === 'ssh' && (hk || (a && a.hostkey && a.secret_set))) { acc.hostkey = hk || a.hostkey; }
			var tq = accessTestReq(a, acc);
			if (!tq) { // gespeichertes Geheimnis gibt es nur zur gespeicherten Konfiguration
				res.innerHTML = '<span class="text-warning-emphasis">' + esc(L('acc.save_first')) + '</span>';
				return null;
			}
			res.innerHTML = '<span class="spinner-border spinner-border-sm"></span> ' + esc(L('new.testing'));
			var p = tq.stored ? api('POST', au + '/test') : api('POST', '/api/monitor64/test', tq.body);
			return p.then(function (r) { res.innerHTML = testHTML(r); }).catch(function (e) { res.innerHTML = '<span class="text-danger">' + esc(tx(e.message)) + '</span>'; });
		} }, { label: L('save'), cls: 'btn-primary', click: function (close) {
			var acc = accessFromForm(body, a);
			if (hk && acc.type === 'ssh') { acc.hostkey = hk; }
			if (a) { delete acc.type; }
			return api(a ? 'PUT' : 'POST', a ? au : '/api/monitor64/hosts/' + encodeURIComponent(uid) + '/access', acc).then(function () { close(); toast(L('acc.saved_toast')); return reload(); });
		} }], true);
		body.insertAdjacentHTML('beforeend', '<div class="mt-3 small" id="m64-af-res"></div>');
		$('#m64-af-type', body).onchange = function () { accessShow(body); $('#m64-af-res', body).innerHTML = ''; };
		$$('#m64-af-sversion, #m64-af-slevel', body).forEach(function (x) { x.onchange = function () { snmpShow(body, 'af'); }; });
		body.addEventListener('click', function (ev) {
			var fb = ev.target.closest('[data-fp-confirm]');
			if (!fb) { return; }
			if ((a ? a.type : $('#m64-af-type', body).value) === 'ssh') { // SSH mit Passwort: Hostschluessel bestaetigt
				hk = fb.dataset.fpConfirm;
				$('#m64-af-res', body).innerHTML = '<span class="small text-body-secondary">' + esc(L('acc.hostkey_set')) + '</span>';
				return;
			}
			$('#m64-af-pin', body).value = fb.dataset.fpConfirm;
			$('#m64-af-res', body).innerHTML = '<span class="small text-body-secondary">' + esc(L('acc.pin_set')) + '</span>';
		});
		accessShow(body);
	}
	// accessTestReq: wie "Verbindung testen" beim Zugang a (null = neu) mit den Formularwerten acc prueft.
	// {stored: true}: gespeicherten Zugang testen (Geheimnis, Hostschluessel; Push: Stand der laufenden Verbindung);
	// {body}: Test mit den Formularwerten; null: Konfiguration geaendert, Geheimnis nur gespeichert -> erst speichern.
	// access_uid: der Server ergaenzt ein Teil-Geheimnis (SNMP v3 nur ein Passwort neu) aus dem gespeicherten bzw.
	// meldet bei Push den Stand der Verbindung dieses Zugangs.
	function accessTestReq(a, acc) {
		var keep = a && !acc.secret && !acc.clear_secret, same = a && JSON.stringify(acc.config) === JSON.stringify(cleanCfg(a.config, a.type));
		if (keep && same) { return { stored: true }; }
		if (keep && a.secret_set) { return null; }
		var b = { address: H.host.address, access: acc };
		if (a && !acc.clear_secret && ((a.type === 'snmp' && a.secret_set && acc.secret) || (acc.type === 'agent' && acc.config.mode === 'push'))) { b.access_uid = a.uid; }
		return { body: b };
	}
	// cleanCfg: gespeicherte Konfiguration in der Form des Formulars (Vergleich "geaendert?").
	function cleanCfg(c, t) {
		c = c || {};
		var o = {};
		if ((t === 'agent' || t === 'ssh') && c.port && c.mode !== 'push') { o.port = c.port; }
		if (t === 'agent' && c.mode === 'push') { o.mode = 'push'; }
		if (t === 'ssh') { o.user = c.user || ''; o.smart = !!c.smart; }
		if (t === 'pve' || t === 'pbs' || t === 'docker') { o.url = c.url || ''; o.pin = c.pin || ''; }
		if (t === 'pve' || t === 'pbs') { o.token_id = c.token_id || ''; }
		if (t === 'pve') { o.node = c.node || ''; }
		if (t === 'pbs' && c.backup_max_age_h) { o.backup_max_age_h = c.backup_max_age_h; }
		if (DEVAPI.indexOf(t) >= 0) {
			o.url = c.url || '';
			o.pin = c.pin || '';
			var m = devCfg(t, function (id) { return id === 'metrics' ? (c.metrics ? JSON.stringify(c.metrics) : '') : id === 'session' ? !!c.session : (c[id] || ''); }) || {};
			Object.keys(m).forEach(function (x) { o[x] = m[x]; });
		}
		if (t === 'snmp') { o = (snmpRead(function (x) { return snmpVal(c, x); }) || {}).config || {}; }
		return o;
	}
	root.addEventListener('click', function (ev) {
		var act = ev.target.closest('[data-act]');
		if (act) {
			ev.preventDefault();
			var h = H.host;
			switch (act.dataset.act) {
			case 'discover':
				lock(act, function () {
					return api('POST', '/api/monitor64/hosts/' + encodeURIComponent(uid) + '/discover').then(function (r) {
						toast(L('host.discovered', { a: r.added, n: r['new'], v: r.vanished }));
						return reload();
					});
				}).catch(fail);
				break;
			case 'edit':
				modal(L('host.edit'), hostForm(h), [{ label: L('cancel') }, { label: L('save'), cls: 'btn-primary', click: function (close) {
					return hostPut(hostFromForm(h)).then(function () { close(); toast(L('host.saved_toast')); return reload().then(buildCharts); });
				} }], true);
				break;
			case 'pause':
				var b = { name: h.name, address: h.address, kind: h.kind, group: h.group, tags: h.tags || [], interval_sec: h.interval_sec, notes: h.notes || '', paused: !h.paused, agent_autoupdate: h.agent_autoupdate };
				lock(act, function () { return hostPut(b).then(function () { toast(b.paused ? L('host.paused_toast') : L('host.resumed_toast')); return reload(); }); }).catch(fail);
				break;
			case 'delete':
				modal(L('host.delete'), '<p>' + esc(L('host.delete_text', { n: h.name })) + '</p><div class="form-check"><input class="form-check-input" type="radio" name="m64-del-hist" id="m64-dh1" value="keep" checked><label class="form-check-label" for="m64-dh1">' + esc(L('host.delete_keep')) + '</label></div>' +
					'<div class="form-check"><input class="form-check-input" type="radio" name="m64-del-hist" id="m64-dh2" value="delete"><label class="form-check-label" for="m64-dh2">' + esc(L('host.delete_hist')) + '</label></div><div class="small text-body-secondary mt-2">' + esc(L('host.delete_hint')) + '</div>',
				[{ label: L('cancel') }, { label: L('host.delete'), cls: 'btn-danger', click: function (close) {
					var hist = $('[name=m64-del-hist]:checked').value;
					return api('DELETE', '/api/monitor64/hosts/' + encodeURIComponent(uid) + '?history=' + hist).then(function () { close(); location.href = '/monitor64'; });
				} }]);
				break;
			case 'maint':
				modal(L('host.maint'), '<div class="row g-3"><div class="col-md-6"><label class="form-label" for="m64-hm-d">' + esc(L('mt.duration')) + '</label><select class="form-select" id="m64-hm-d">' +
					[[30, L('mt.for', { d: fmtDur(1800) })], [60, L('mt.for', { d: fmtDur(3600) })], [120, L('mt.for', { d: fmtDur(7200) })], [240, L('mt.for', { d: fmtDur(14400) })], [0, L('mt.until_ended')]].map(function (o, i) { return '<option value="' + o[0] + '"' + (i === 1 ? ' selected' : '') + '>' + esc(o[1]) + '</option>'; }).join('') +
					'</select></div><div class="col-md-6"><label class="form-label" for="m64-hm-r">' + esc(L('mt.reason')) + '</label><input class="form-control" id="m64-hm-r" maxlength="200" placeholder="' + esc(L('mt.reason_ph')) + '"></div></div><div class="small text-body-secondary mt-2">' + esc(L('mt.intro')) + '</div>',
				[{ label: L('cancel') }, { label: L('mt.save'), cls: 'btn-primary', click: function (close) {
					return api('POST', '/api/monitor64/maintenance', { title: $('#m64-hm-r').value, hosts: [uid], mode: 'now', minutes: parseInt($('#m64-hm-d').value, 10) }).then(function () { close(); toast(L('mt.saved_toast')); return reload(); });
				} }]);
				break;
			case 'access-add':
				accessDialog(null);
				break;
			case 'cluster-edit':
				if (CH && CH.active) { clusterDialog(); }
				break;
			}
			return;
		}
		var aa = ev.target.closest('[data-acc-act]');
		if (aa) {
			var row = aa.closest('[data-acc]'), acc = null;
			H.accesses.forEach(function (x) { if (x.uid === row.dataset.acc) { acc = x; } });
			if (!acc) { return; }
			var au = '/api/monitor64/access/' + encodeURIComponent(acc.uid);
			switch (aa.dataset.accAct) {
			case 'test':
				lock(aa, function () {
					return api('POST', au + '/test').then(function (r) {
						var mb = modal(L('acc.test') + ' · ' + accLabel(acc.type), '<div>' + testHTML(r) + '</div>', [{ label: L('close') }]);
						var fb = mb && $('[data-fp-confirm]', mb);
						if (fb) {
							fb.onclick = function () {
								// SSH mit Passwort: der bestaetigte Fingerabdruck wird der Hostschluessel (erst danach geht das Passwort raus)
								var put = acc.type === 'ssh' ? { config: acc.config || {}, hostkey: fb.dataset.fpConfirm } : { config: Object.assign({}, acc.config || {}, { pin: fb.dataset.fpConfirm }) };
								lock(fb, function () { return api('PUT', au, put).then(function () { return api('POST', au + '/test'); }).then(function (r2) { mb.innerHTML = '<div>' + testHTML(r2) + '</div>'; return reload(); }); }).catch(fail);
							};
						}
					});
				}).catch(fail);
				break;
			case 'edit':
				accessDialog(acc);
				break;
			case 'hostkey':
				confirmBox(L('acc.hostkey_reset'), L('acc.hostkey_confirm'), L('acc.hostkey_reset'), function () { return api('POST', au + '/hostkey-reset').then(function () { toast(L('acc.saved_toast')); return reload(); }).catch(fail); });
				break;
			case 'delete':
				confirmBox(L('acc.delete'), L('acc.delete_confirm', { n: accLabel(acc.type) }), L('acc.delete'), function () { return api('DELETE', au).then(function () { toast(L('acc.deleted_toast')); return reload(); }).catch(fail); });
				break;
			}
			return;
		}
		var na = ev.target.closest('[data-newall]');
		if (na) { // neue Dienste: alle bzw. keine auswaehlen
			$$('#m64-new input[data-newsel]').forEach(function (x) { x.checked = na.dataset.newall === '1'; newSel[x.dataset.newsel] = x.checked; });
			return;
		}
		var nb = ev.target.closest('[data-new]');
		if (nb) {
			var keys = $$('#m64-new input[data-newsel]:checked').map(function (x) { return x.dataset.newsel; });
			if (!keys.length) { return; }
			lock(nb, function () {
				return api('POST', '/api/monitor64/hosts/' + encodeURIComponent(uid) + '/services/adopt', { keys: keys, state: parseInt(nb.dataset['new'], 10) }).then(function (r) {
					toast(nb.dataset['new'] === '1' ? L('host.adopted_toast', { n: r.changed }) : L('host.ignored_toast', { n: r.changed }));
					keys.forEach(function (k) { delete newSel[k]; });
					return reload();
				});
			}).catch(fail);
			return;
		}
		if (ev.target.closest('[data-remove-gone]')) {
			var gone = H.services.filter(function (s) { return s.vanished; }).map(function (s) { return s.key; });
			confirmBox(L('host.remove_all'), L('host.remove_all_confirm', { n: gone.length }), L('host.remove_all'), function () {
				return api('POST', '/api/monitor64/hosts/' + encodeURIComponent(uid) + '/services/remove', { keys: gone }).then(function () { toast(L('sd.removed_toast')); return reload(); }).catch(fail);
			});
			return;
		}
		var ig = ev.target.closest('[data-ign]');
		if (ig) {
			lock(ig, function () { return api('POST', '/api/monitor64/hosts/' + encodeURIComponent(uid) + '/services/adopt', { keys: [ig.dataset.ign], state: 1 }).then(function () { toast(L('host.adopted_toast', { n: 1 })); return reload(); }); }).catch(fail);
			return;
		}
		var tr = ev.target.closest('tr[data-svc]');
		if (tr) { history.replaceState(null, '', '#svc=' + encodeURIComponent(tr.dataset.svc)); openDetail(tr.dataset.svc); }
	});
	root.addEventListener('keydown', function (ev) {
		if ((ev.key === 'Enter' || ev.key === ' ') && ev.target.matches('tr[data-svc]')) { ev.preventDefault(); ev.target.click(); }
	});
	renderAll();
	buildCharts();
	loadSparks();
	function openHash() {
		if (location.hash.indexOf('#svc=') !== 0) { return; }
		var key;
		try { key = decodeURIComponent(location.hash.slice(5)); } catch (e) { return; } // kaputter Link: sonst liefen Neuladen und hashchange nicht
		openDetail(key);
	}
	openHash();
	window.addEventListener('hashchange', openHash); // Link auf einen Dienst derselben Seite (kein Neuladen)
	setInterval(function () { if (!document.hidden && !detailFor && !(modalEl && modalEl.classList.contains('show'))) { reload().catch(failQuiet); } }, 15000);
	setInterval(function () { if (!document.hidden) { loadSparks(); } }, 300000);
}

// ---------- Probleme ----------
var TLI = { warn: ['bi-exclamation-triangle-fill', 'text-warning'], crit: ['bi-x-octagon-fill', 'text-danger'], unknown: ['bi-question-circle-fill', 'text-body-secondary'], unreachable: ['bi-plug-fill', 'text-danger'],
	ok: ['bi-check-circle-fill', 'text-success'], bell: ['bi-bell', 'text-body-secondary'], held: ['bi-moon-stars', 'text-body-secondary'], ack: ['bi-check2-square', 'text-primary'], unack: ['bi-arrow-counterclockwise', 'text-body-secondary'],
	comment: ['bi-chat-left-text', 'text-primary'], resolved: ['bi-person-check', 'text-primary'], maint: ['bi-cone-striped', 'text-body-secondary'], takeover: ['bi-diagram-3', 'text-body-secondary'],
	handover: ['bi-arrow-left-right', 'text-body-secondary'], pause: ['bi-pause-circle', 'text-body-secondary'], resume: ['bi-play-circle', 'text-body-secondary'] };
function evText(e, chans) {
	var t = tx(e.text || ''), w = whoTxt(e.actor);
	switch (e.kind) {
	case 'warn': case 'crit': case 'unknown': return stLabel(e.kind) + (t ? ': ' + t : '');
	case 'unreachable': return L('ev.unreachable') + (t ? ': ' + t : '');
	case 'ok': return L('ev.ok');
	case 'bell':
		var p = t.split(': '), ids = (p[1] || '').split(','), names = ids.map(function (id) { return id === 'default' ? L('nf.default') : (chans[id] || id); });
		var cs = { c: names.join(', ') };
		return p[0] === 'ok' || p[0] === 'better' ? L('ev.bell_ok', cs) : p[0] === 'reminder' ? L('ev.bell_reminder', cs) : L('ev.bell_problem', cs);
	case 'held': return L('ev.held');
	case 'ack': return L('ev.ack', { w: w }) + (t ? ': ' + quote(t) : '');
	case 'unack': return e.actor && e.actor.kind === 'system' ? L('ev.unack_auto') : L('ev.unack', { w: w });
	case 'comment': return L('ev.comment', { w: w }) + ': ' + quote(t);
	case 'resolved': return L('ev.resolved', { w: w }) + (t ? ': ' + quote(t) : '');
	case 'maint': return L('ev.maint') + (t ? ': ' + t : '');
	case 'maint_end': return L('ev.maint_end') + (t ? ': ' + t : '');
	case 'takeover': return t || L('ev.takeover'); // Cluster: Text nennt die Nodes ("von node01 an node02")
	case 'handover': return t || L('ev.handover');
	case 'pause': return L('ev.pause', { w: w });
	case 'resume': return L('ev.resume', { w: w });
	}
	return e.kind + (t ? ': ' + t : '');
}
function timeline(evs, chans) {
	return '<ul class="tl">' + evs.map(function (e) {
		var i = TLI[e.kind] || ['bi-dot', 'text-body-secondary'];
		return '<li><span class="tl-t">' + esc(fmtTime(e.at)) + '</span><i class="bi ' + i[0] + ' ' + i[1] + '"></i><span>' + esc(evText(e, chans)) + (e.actor && e.actor.ip && e.actor.kind !== 'system' ? ' <span class="text-body-tertiary small">(' + esc(e.actor.ip) + ')</span>' : '') + '</span></li>';
	}).join('') + '</ul>';
}
function howText(p) {
	switch (p.how) {
	case 'auto': return L('how.auto');
	case 'user': return L('how.user', { w: whoTxt(p.closed_by) });
	case 'api': return L('how.api', { w: whoTxt(p.closed_by) });
	case 'maint': return L('how.maint');
	case 'handover': return L('how.handover');
	case 'removed': return L('how.removed', { w: whoTxt(p.closed_by) });
	}
	return p.how || '';
}
function pageProblems() {
	var qs = new URLSearchParams(location.search);
	var PB = { tab: qs.get('status') || 'open', range: qs.get('range') || '7d', who: qs.get('who') || '', q: qs.get('q') || '', open: null, list: [], people: [] };
	$('#m64-range').value = PB.range;
	$('#m64-q').value = PB.q;
	function query() {
		var p = new URLSearchParams();
		p.set('status', PB.tab); p.set('range', PB.range);
		if (PB.who) { p.set('who', PB.who); }
		if (PB.q) { p.set('q', PB.q); }
		return p.toString();
	}
	function load() {
		$('#m64-csv').href = '/api/monitor64/problems.csv?' + query();
		history.replaceState(null, '', '?' + query());
		api('GET', '/api/monitor64/problems?' + query()).then(function (d) {
			PB.list = d.problems || []; PB.people = d.people || [];
			$('[data-count=open]').textContent = d.counts.open;
			$('[data-count=closed]').textContent = d.counts.closed;
			$('[data-count=all]').textContent = d.counts.open + d.counts.closed;
			renderWho(); render();
		}).catch(fail);
	}
	function renderWho() {
		var sel = $('#m64-who'), opts = '<option value="">' + esc(L('pb.all_people')) + '</option><option value="system">' + esc(L('pb.system')) + '</option>';
		PB.people.forEach(function (a) { if (a.kind === 'user') { opts += '<option value="user:' + esc(a.uid || a.name) + '">' + esc(a.name) + '</option>'; } });
		opts += '<option value="api">' + esc(L('pb.api_keys')) + '</option>';
		sel.innerHTML = opts;
		sel.value = PB.who;
	}
	function render() {
		$$('[data-tab]').forEach(function (c) { c.classList.toggle('active', c.dataset.tab === PB.tab); });
		var html = '';
		PB.list.forEach(function (p) {
			var open = !p.closed, acked = !!p.ack;
			var badge = open ? stBadge(p.state) : '<span class="st-badge ok"><i class="bi bi-check2"></i> ' + esc(L('pb.resolved')) + '</span>';
			var maxSt = !open ? ' <span class="small text-body-secondary text-nowrap"><span class="st-dot st-' + esc(p.worst === 'unreachable' ? 'unknown' : p.worst) + '" style="width:.5rem;height:.5rem"></span> ' + esc(L('pb.max', { s: stLabel(p.worst) })) + '</span>' : '';
			var how = open ? (acked ? '<span class="text-primary small"><i class="bi bi-check2-square"></i> ' + esc(L('ov.acked')) + '</span> ' + who(p.ack.by) : '<span class="text-body-secondary">' + esc(L('pb.open_state')) + '</span>') :
				(p.how === 'maint' ? '<i class="bi bi-cone-striped"></i> ' + esc(L('pb.maint')) : p.how === 'handover' ? '<span class="text-body-secondary"><i class="bi bi-diagram-3"></i> ' + esc(L('how.handover')) + '</span>' : who(p.closed_by));
			var name = p.key ? tx(p.name) : L('ov.unreachable');
			html += '<tr data-row="' + esc(p.uid) + '" tabindex="0"><td>' + badge + '</td><td><span class="fw-semibold">' + esc(p.host) + '</span>' + (p.host_gone ? ' <span class="badge text-bg-light">' + esc(L('pb.host_gone')) + '</span>' : '') + ' · ' + esc(name) + maxSt + '</td><td class="d-none d-md-table-cell small">' + esc(fmtTime(p.opened)) + '</td><td class="d-none d-sm-table-cell small">' + esc(fmtDur(p.duration)) + '</td><td class="small">' + how + '</td><td class="d-none d-lg-table-cell small text-body-secondary">' + esc(p.channels.map(function (c) { return c === 'default' ? L('nf.default') : c; }).join(', ') || '–') + '</td></tr>';
			if (PB.open === p.uid) { html += '<tr class="pb-detail"><td colspan="6" id="m64-pb-detail"><span class="spinner-border spinner-border-sm"></span></td></tr>'; }
		});
		if (!PB.list.length) { html = '<tr><td colspan="6" class="text-center text-body-secondary p-4">' + esc(L('pb.none')) + '</td></tr>'; }
		$('#m64-pb').innerHTML = html;
		if (PB.open) { loadDetail(PB.open); }
	}
	function loadDetail(puid) {
		var p = null;
		PB.list.forEach(function (x) { if (x.uid === puid) { p = x; } });
		if (!p) { return; }
		api('GET', '/api/monitor64/problems/' + encodeURIComponent(puid)).then(function (d) {
			var box = $('#m64-pb-detail');
			if (!box || PB.open !== puid) { return; } // inzwischen ein anderes Problem aufgeklappt: Antwort verwerfen
			var right;
			if (!p.closed) {
				right = '<div class="small fw-semibold mb-1">' + esc(L('pb.ack_title')) + '</div><textarea class="form-control form-control-sm mb-2" rows="2" id="m64-ack-c" maxlength="500" placeholder="' + esc(L('pb.ack_ph')) + '">' + esc(p.ack ? p.ack.comment || '' : '') + '</textarea>' +
					'<div class="d-flex flex-wrap gap-2"><button class="btn btn-sm btn-primary" type="button" data-pa="' + (p.ack ? 'comment' : 'ack') + '">' + (p.ack ? esc(L('pb.comment_save')) : '<i class="bi bi-check2"></i> ' + esc(L('ov.ack'))) + '</button>' +
					(p.ack ? '<button class="btn btn-sm btn-outline-secondary" type="button" data-pa="unack">' + esc(L('ov.unack')) + '</button>' : '') +
					'<button class="btn btn-sm btn-outline-secondary" type="button" data-pa="resolve"><i class="bi bi-person-check"></i> ' + esc(L('pb.resolve')) + '</button>' +
					(p.host_gone ? '' : '<a class="btn btn-sm btn-outline-secondary" href="/monitor64/host/' + encodeURIComponent(p.host_uid) + (p.key ? '#svc=' + encodeURIComponent(p.key) : '') + '">' + esc(L('pb.to_host')) + '</a>') + '</div>' +
					'<div class="small text-body-secondary mt-2">' + esc(L('pb.ack_hint')) + '</div>';
			} else {
				right = '<div class="small fw-semibold mb-1">' + esc(L('pb.result')) + '</div><div class="small">' + esc(howText(p)) + '</div><div class="small text-body-secondary mt-1">' + esc(L('pb.result_sub', { d: fmtDur(p.duration), a: fmtTime(p.opened), b: fmtTime(p.closed) })) + '</div>' +
					(p.host_gone ? '' : '<a class="btn btn-sm btn-outline-secondary mt-2" href="/monitor64/host/' + encodeURIComponent(p.host_uid) + '">' + esc(L('pb.to_host')) + '</a>');
			}
			box.innerHTML = '<div class="row g-3"><div class="col-lg-7"><div class="small fw-semibold mb-1">' + esc(L('pb.timeline')) + '</div>' + timeline(d.events || [], d.channels || {}) + '</div><div class="col-lg-5">' + right + '</div></div>';
			$$('[data-pa]', box).forEach(function (b) {
				b.onclick = function (ev) {
					ev.stopPropagation();
					var a = b.dataset.pa, c = ($('#m64-ack-c', box) || {}).value || '';
					if (a === 'comment' && !c.trim()) { toast(L('pb.comment_empty'), true); return; }
					lock(b, function () {
						return api('POST', '/api/monitor64/problems/action', { host: p.host_uid, key: p.key, action: a, comment: c }).then(function () {
							toast({ ack: L('pb.done_ack'), unack: L('pb.done_unack'), comment: L('pb.done_comment'), resolve: L('pb.done_resolve') }[a]); load();
						});
					}).catch(fail);
				};
			});
		}).catch(fail);
	}
	root.addEventListener('click', function (ev) {
		var t = ev.target.closest('[data-tab]');
		if (t) { PB.tab = t.dataset.tab; PB.open = null; load(); return; }
		if (ev.target.closest('.pb-detail')) { return; }
		var r = ev.target.closest('tr[data-row]');
		if (r) { PB.open = PB.open === r.dataset.row ? null : r.dataset.row; render(); }
	});
	root.addEventListener('keydown', function (ev) { if ((ev.key === 'Enter' || ev.key === ' ') && ev.target.matches('[data-tab],tr[data-row]')) { ev.preventDefault(); ev.target.click(); } });
	$('#m64-range').onchange = function () { PB.range = this.value; PB.open = null; load(); };
	$('#m64-who').onchange = function () { PB.who = this.value; PB.open = null; load(); };
	var qt = null;
	$('#m64-q').oninput = function () { var v = this.value; clearTimeout(qt); qt = setTimeout(function () { PB.q = v.trim(); PB.open = null; load(); }, 300); };
	load();
}

// ---------- Wartung ----------
var DAYS = [1, 2, 3, 4, 5, 6, 0];
var DAYN = [L('day.0'), L('day.1'), L('day.2'), L('day.3'), L('day.4'), L('day.5'), L('day.6')];
function dayName(d) { return DAYN[d]; }
function pageMaint() {
	var M = { items: [], hosts: [], targets: { groups: [], tags: [] }, form: null, tz: '', now: '' };
	// Zeiten kommen und gehen als Wanduhrzeit der Node ("2006-01-02T15:04", Zeitzone M.tz), nicht des Browsers.
	function wall(s) {
		var m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/.exec(s || '');
		return m ? new Date(+m[1], +m[2] - 1, +m[3], +m[4], +m[5]) : null;
	}
	function wallStr(d) { return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + 'T' + pad(d.getHours()) + ':' + pad(d.getMinutes()); }
	function fmtWall(s) { var d = wall(s); return d ? fmtTime(d) : '–'; }
	function hostName(u) { var n = u; M.hosts.forEach(function (h) { if (h.uid === u) { n = h.name; } }); return n; }
	function targetsText(m) {
		var p = (m.hosts || []).map(hostName);
		(m.groups || []).forEach(function (g) { p.push(targetLabel('group', g)); });
		(m.tags || []).forEach(function (t) { p.push(targetLabel('tag', t)); });
		return p.join(', ');
	}
	function timeText(m) {
		if (m.recur) {
			var days = (m.recur.days && m.recur.days.length && m.recur.days.length < 7) ? DAYS.filter(function (d) { return m.recur.days.indexOf(d) >= 0; }).map(dayName).join(', ') : L('mt.every_day');
			return esc(m.recur.from + ' – ' + m.recur.to) + '<div class="text-body-secondary">' + esc(days) + '</div>';
		}
		var end = m.ended && (!m.end || m.ended < m.end) ? m.ended_local : m.end_local;
		return esc(fmtWall(m.start_local)) + ' – ' + esc(end ? fmtWall(end) : L('mt.until_ended'));
	}
	var MST = { running: L('mt.st_running'), planned: L('mt.st_planned'), recurring: L('mt.st_recurring'), ended: L('mt.st_ended') };
	var CLS = { running: 'text-bg-warning', planned: 'text-bg-primary', recurring: 'text-bg-info', ended: 'text-bg-secondary' };
	function render() {
		var tzEl = $('#m64-maint-tz');
		if (tzEl) { tzEl.textContent = M.tz ? L('mt.tz', { z: M.tz }) : ''; }
		$('#m64-maint-list').innerHTML = M.items.length ? M.items.map(function (m) {
			var btns = '';
			if (m.status === 'running' || (m.status === 'recurring')) { btns += '<button class="btn btn-sm btn-outline-secondary" type="button" data-end="' + esc(m.uid) + '">' + esc(m.status === 'recurring' ? L('mt.stop') : L('mt.end')) + '</button> '; }
			if (m.status !== 'ended') { btns += '<button class="btn btn-sm btn-outline-secondary" type="button" data-edit="' + esc(m.uid) + '" title="' + esc(L('mt.edit')) + '" aria-label="' + esc(L('mt.edit')) + '"><i class="bi bi-pencil"></i></button> '; }
			btns += '<button class="btn btn-sm btn-outline-secondary" type="button" data-del="' + esc(m.uid) + '" title="' + esc(L('mt.delete')) + '" aria-label="' + esc(L('mt.delete')) + '"><i class="bi bi-trash"></i></button>';
			return '<tr' + (m.status === 'ended' ? ' class="text-body-secondary"' : '') + '><td class="fw-semibold">' + esc(m.title || L('mt.no_title')) + '<div class="small fw-normal text-body-secondary">' + esc(L('mt.by', { w: whoTxt(m.by) })) + '</div></td><td class="small">' + esc(targetsText(m)) + '</td>' +
				'<td class="d-none d-md-table-cell small">' + timeText(m) + '</td><td><span class="badge ' + CLS[m.status] + '">' + esc(MST[m.status] || m.status) + '</span>' + (m.status === 'recurring' && m.running ? ' <span class="badge text-bg-warning">' + esc(L('mt.st_running')) + '</span>' : '') + '</td><td class="text-end text-nowrap">' + btns + '</td></tr>';
		}).join('') : '<tr><td colspan="5" class="text-center text-body-secondary p-4">' + esc(L('mt.none')) + '</td></tr>';
	}
	function load() { return api('GET', '/api/monitor64/maintenance').then(function (d) { M.items = d.items || []; M.hosts = d.hosts || []; M.targets = d.targets || M.targets; M.tz = d.tz || ''; M.now = d.now_local || ''; render(); }).catch(fail); }
	function form(m) {
		var f = M.form = { uid: m ? m.uid : '', mode: m ? (m.recur ? 'recur' : 'plan') : 'now' };
		var sel = { hosts: (m && m.hosts) || [], groups: (m && m.groups) || [], tags: (m && m.tags) || [] };
		var groups = [];
		M.hosts.forEach(function (h) { if (groups.indexOf(h.group) < 0) { groups.push(h.group); } });
		var now = wall(M.now) || new Date(), later = new Date(now.getTime() + 3600000);
		var html = '<div class="card mb-3 border-primary"><div class="card-body"><div class="row g-3"><div class="col-lg-6"><div class="form-label">' + esc(L('mt.systems')) + '</div><div class="maint-pick">' +
			groups.map(function (g) {
				return '<div class="small fw-semibold mt-1"><input class="form-check-input me-1" type="checkbox" data-mg="' + esc(g) + '"' + (sel.groups.indexOf(g) >= 0 ? ' checked' : '') + ' id="m64-mg-' + esc(g) + '" aria-label="' + esc(targetLabel('group', g)) + '"><label for="m64-mg-' + esc(g) + '">' + esc(g ? targetLabel('group', g) : L('ov.no_group')) + '</label></div>' +
					M.hosts.filter(function (h) { return h.group === g; }).map(function (h) { return '<div class="form-check ms-3"><input class="form-check-input" type="checkbox" data-mh="' + esc(h.uid) + '" id="m64-mh-' + esc(h.uid) + '"' + (sel.hosts.indexOf(h.uid) >= 0 ? ' checked' : '') + '><label class="form-check-label small" for="m64-mh-' + esc(h.uid) + '">' + esc(h.name) + '</label></div>'; }).join('');
			}).join('') + (M.hosts.length ? '' : '<div class="small text-body-secondary">' + esc(L('mt.no_hosts')) + '</div>') + '</div>' +
			(M.targets.tags.length ? '<div class="small text-body-secondary mt-1">' + esc(L('mt.by_tag')) + ' ' + M.targets.tags.map(function (t) { return '<span class="chip' + (sel.tags.indexOf(t) >= 0 ? ' active' : '') + '" data-mt="' + esc(t) + '" role="button" tabindex="0">' + esc(t) + '</span>'; }).join(' ') + '</div>' : '') +
			'<div class="small text-body-secondary mt-1">' + esc(L('mt.group_hint')) + '</div></div>' +
			'<div class="col-lg-6"><div class="form-label">' + esc(L('mt.when')) + '</div><div class="btn-group btn-group-sm w-100 mb-2">' + [['now', L('mt.m_now')], ['plan', L('mt.m_plan')], ['recur', L('mt.m_recur')]].map(function (x) { return '<button class="btn btn-outline-secondary' + (f.mode === x[0] ? ' active' : '') + '" type="button" data-mode="' + x[0] + '">' + esc(x[1]) + '</button>'; }).join('') + '</div>' +
			'<div data-mm="now"><select class="form-select form-select-sm" id="m64-mf-dur" aria-label="' + esc(L('mt.duration')) + '">' + [[30, L('mt.for', { d: fmtDur(1800) })], [60, L('mt.for', { d: fmtDur(3600) })], [120, L('mt.for', { d: fmtDur(7200) })], [240, L('mt.for', { d: fmtDur(14400) })], [0, L('mt.until_ended')]].map(function (o, i) { return '<option value="' + o[0] + '"' + (i === 1 ? ' selected' : '') + '>' + esc(o[1]) + '</option>'; }).join('') + '</select></div>' +
			'<div data-mm="plan" class="row g-2"><div class="col-6"><label class="small" for="m64-mf-from">' + esc(L('mt.from')) + '</label><input class="form-control form-control-sm" type="datetime-local" id="m64-mf-from" value="' + esc(m && m.start_local && !m.recur ? m.start_local : wallStr(now)) + '"></div><div class="col-6"><label class="small" for="m64-mf-to">' + esc(L('mt.to')) + '</label><input class="form-control form-control-sm" type="datetime-local" id="m64-mf-to" value="' + esc(m && m.end_local && !m.recur ? m.end_local : wallStr(later)) + '"></div>' +
				(M.tz ? '<div class="col-12 small text-body-secondary"><i class="bi bi-globe2"></i> ' + esc(L('mt.tz', { z: M.tz })) + '</div>' : '') + '</div>' +
			'<div data-mm="recur" class="row g-2"><div class="col-12 d-flex flex-wrap gap-2">' + DAYS.map(function (d) { var on = m && m.recur ? (!m.recur.days || !m.recur.days.length || m.recur.days.indexOf(d) >= 0) : d === 0; return '<div class="form-check form-check-inline me-1"><input class="form-check-input" type="checkbox" data-day="' + d + '" id="m64-md-' + d + '"' + (on ? ' checked' : '') + '><label class="form-check-label small" for="m64-md-' + d + '">' + esc(dayName(d)) + '</label></div>'; }).join('') + '</div>' +
			'<div class="col-6"><label class="small" for="m64-mf-rf">' + esc(L('mt.from')) + '</label><input class="form-control form-control-sm" type="time" id="m64-mf-rf" value="' + esc(m && m.recur ? m.recur.from : '02:00') + '"></div><div class="col-6"><label class="small" for="m64-mf-rt">' + esc(L('mt.to')) + '</label><input class="form-control form-control-sm" type="time" id="m64-mf-rt" value="' + esc(m && m.recur ? m.recur.to : '04:00') + '"></div>' +
				(M.tz ? '<div class="col-12 small text-body-secondary"><i class="bi bi-globe2"></i> ' + esc(L('mt.tz', { z: M.tz })) + '</div>' : '') + '</div>' +
			'<label class="form-label mt-2" for="m64-mf-title">' + esc(L('mt.reason')) + '</label><input class="form-control form-control-sm" id="m64-mf-title" maxlength="200" value="' + esc(m ? m.title : '') + '" placeholder="' + esc(L('mt.reason_ph')) + '"></div></div></div>' +
			'<div class="card-footer d-flex gap-2"><button class="btn btn-outline-secondary btn-sm" type="button" id="m64-mf-cancel">' + esc(L('cancel')) + '</button><button class="btn btn-primary btn-sm ms-auto" type="button" id="m64-mf-save">' + esc(m ? L('save') : L('mt.save')) + '</button></div></div>';
		var box = $('#m64-maint-form');
		box.innerHTML = html;
		function showMode() { $$('[data-mm]', box).forEach(function (x) { x.classList.toggle('d-none', x.dataset.mm !== f.mode); }); $$('[data-mode]', box).forEach(function (b) { b.classList.toggle('active', b.dataset.mode === f.mode); }); }
		showMode();
		$$('[data-mode]', box).forEach(function (b) { b.onclick = function () { f.mode = b.dataset.mode; showMode(); }; });
		$$('[data-mt]', box).forEach(function (c) {
			c.setAttribute('aria-pressed', c.classList.contains('active') ? 'true' : 'false');
			c.onclick = function () { c.classList.toggle('active'); c.setAttribute('aria-pressed', c.classList.contains('active') ? 'true' : 'false'); };
			c.onkeydown = function (ev) { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); c.click(); } };
		});
		$('#m64-mf-cancel').onclick = function () { box.innerHTML = ''; };
		$('#m64-mf-save').onclick = function () {
			var body = { title: $('#m64-mf-title').value, mode: f.mode,
				hosts: $$('[data-mh]:checked', box).map(function (x) { return x.dataset.mh; }),
				groups: $$('[data-mg]:checked', box).map(function (x) { return x.dataset.mg; }).filter(function (g) { return g !== ''; }),
				tags: $$('[data-mt].active', box).map(function (x) { return x.dataset.mt; }) };
			if (f.mode === 'now') { body.minutes = parseInt($('#m64-mf-dur').value, 10); }
			if (f.mode === 'plan') { body.start = $('#m64-mf-from').value; body.end = $('#m64-mf-to').value; }
			if (f.mode === 'recur') {
				body.days = $$('[data-day]:checked', box).map(function (x) { return parseInt(x.dataset.day, 10); });
				if (body.days.length === 7) { body.days = []; }
				body.from = $('#m64-mf-rf').value; body.to = $('#m64-mf-rt').value;
			}
			lock(this, function () { return api(f.uid ? 'PUT' : 'POST', '/api/monitor64/maintenance' + (f.uid ? '/' + encodeURIComponent(f.uid) : ''), body).then(function () { box.innerHTML = ''; toast(L('mt.saved_toast')); return load(); }); }).catch(fail);
		};
		box.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
	}
	$('#m64-maint-new').onclick = function () { form(null); };
	root.addEventListener('click', function (ev) {
		var e = ev.target.closest('[data-end]');
		if (e) { lock(e, function () { return api('POST', '/api/monitor64/maintenance/' + encodeURIComponent(e.dataset.end) + '/end').then(function () { toast(L('mt.ended_toast')); return load(); }); }).catch(fail); return; }
		var ed = ev.target.closest('[data-edit]');
		if (ed) { M.items.forEach(function (m) { if (m.uid === ed.dataset.edit) { form(m); } }); return; }
		var d = ev.target.closest('[data-del]');
		if (d) { confirmBox(L('mt.delete'), L('mt.delete_confirm'), L('mt.delete'), function () { return api('DELETE', '/api/monitor64/maintenance/' + encodeURIComponent(d.dataset.del)).then(function () { toast(L('mt.deleted_toast')); return load(); }).catch(fail); }); }
	});
	load();
}

// ---------- Schwellen ----------
function pageRules() {
	var R = { overrides: [], own: [], targets: { groups: [], tags: [] }, std: D.std || {} };
	// Standard-Tabelle speichern
	$('#m64-std-form').onsubmit = function (ev) {
		ev.preventDefault();
		var rules = {}, bad = false;
		$$('#m64-std-form tr[data-kind]').forEach(function (tr) {
			var f = parseFloat(tr.dataset.factor || '1') || 1, r = {};
			['warn', 'crit'].forEach(function (n) {
				var v = parseNum($('[name=' + n + ']', tr).value);
				if (v !== null && isNaN(v)) { bad = true; }
				r[n] = v === null ? 'off' : v * f;
			});
			var fo = $('[name=for]', tr);
			if (fo) { r['for'] = parseInt(fo.value, 10); }
			rules[tr.dataset.kind] = r;
		});
		$$('#m64-std-form li[data-kind]').forEach(function (li) { rules[li.dataset.kind] = { severity: $('[name=severity]', li).value }; });
		if (bad) { toast(L('err_number'), true); return; }
		var sb = $('#m64-std-form [type=submit]');
		lock(sb, function () { return api('PUT', '/api/monitor64/rules/std', { rules: rules }).then(function (r) { toast(L('rl.std_saved', { n: (r.changed || []).length })); loadOvr(); }); }).catch(fail);
	};
	function ovrVals(o) {
		var meta = kindMeta(o.kind) || {}, r = o.rule || {}, f = meta.factor || 1;
		var unit = meta.unit === 'min' ? L('unit.min') : meta.unit === 'days' ? L('unit.days') : meta.unit || '';
		if (meta.state) { return esc(sevLabel(r.severity || '')); }
		if (r.mode === 'free') { return '&lt; ' + (lim(r.warn_free) === null ? '–' : fmtNum(r.warn_free)) + ' / &lt; ' + (lim(r.crit_free) === null ? '–' : fmtNum(r.crit_free)) + ' ' + esc(L('unit.gb_free')); }
		var op = meta.down ? '&lt;' : '≥';
		return op + ' ' + (r.warn === undefined ? '…' : lim(r.warn) === null ? '–' : fmtNum(r.warn / f)) + ' / ' + (r.crit === undefined ? '…' : lim(r.crit) === null ? '–' : fmtNum(r.crit / f)) + ' ' + esc(unit);
	}
	function effectText(e) {
		if (!e) { return ''; }
		var sub = [L('rl.affects', { s: e.services, h: e.hosts.length })];
		if (e.own && e.own.length) { sub.push(L('rl.own_n', { n: e.own.length, h: e.own.join(', ') })); }
		return sub;
	}
	function renderOvr() {
		var list = R.overrides;
		$('#m64-ovr-count').textContent = String(list.length);
		var html = '<div class="card mb-3"><div class="card-header small text-body-secondary"><i class="bi bi-sort-down"></i> ' + esc(L('rl.top_wins')) + '</div><div class="list-group list-group-flush">' +
			list.map(function (o, i) {
				var e = o.effect || { hosts: [], own: [], shadow: {} }, sub = effectText(e).map(esc);
				sub.push(esc(L('rl.changed_by', { w: whoTxt(o.by), t: fmtTime(o.at) })));
				var sh = Object.keys(e.shadow || {}).map(function (j) { var oj = list[+j]; return '<div class="small text-warning-emphasis"><i class="bi bi-layers"></i> ' + esc(L('rl.shadowed', { h: e.shadow[j].join(', '), n: +j + 1, t: oj ? targetLabel(oj.target_type, oj.target) : '' })) + '</div>'; }).join('');
				return '<div class="list-group-item d-flex gap-2 align-items-start ovr-row"><span class="ovr-num">' + (i + 1) + '</span><div class="flex-grow-1 min-w-0">' +
					'<div><span class="tag">' + esc(targetLabel(o.target_type, o.target)) + '</span> <strong class="ms-1">' + esc(kindLabel(o.kind)) + '</strong> <span class="ms-1 lvl-vals">' + ovrVals(o) + '</span>' + (o.rule && o.rule['for'] !== undefined ? ' <span class="small text-body-secondary">· ' + esc(durLabel(o.rule['for'])) + '</span>' : '') +
					(o.rule && o.rule.report === 'show' ? ' <span class="badge text-bg-secondary">' + esc(L('rl.show')) + '</span>' : '') + '</div><div class="small text-body-secondary">' + sub.join(' · ') + '</div>' + sh + '</div>' +
					'<div class="btn-group btn-group-sm flex-shrink-0"><button class="btn btn-outline-secondary" type="button" data-mv="' + esc(o.uid) + '" data-dir="-1"' + (i === 0 ? ' disabled' : '') + ' title="' + esc(L('rl.up')) + '" aria-label="' + esc(L('rl.up')) + '"><i class="bi bi-arrow-up"></i></button>' +
					'<button class="btn btn-outline-secondary" type="button" data-mv="' + esc(o.uid) + '" data-dir="1"' + (i === list.length - 1 ? ' disabled' : '') + ' title="' + esc(L('rl.down')) + '" aria-label="' + esc(L('rl.down')) + '"><i class="bi bi-arrow-down"></i></button>' +
					'<button class="btn btn-outline-secondary" type="button" data-ed="' + esc(o.uid) + '" title="' + esc(L('rl.edit')) + '" aria-label="' + esc(L('rl.edit')) + '"><i class="bi bi-pencil"></i></button>' +
					'<button class="btn btn-outline-secondary" type="button" data-rm="' + esc(o.uid) + '" title="' + esc(L('rl.delete')) + '" aria-label="' + esc(L('rl.delete')) + '"><i class="bi bi-trash"></i></button></div></div>';
			}).join('') + (list.length ? '' : '<div class="list-group-item small text-body-secondary">' + esc(L('rl.no_overrides')) + '</div>') + '</div>' +
			'<div class="card-footer"><button class="btn btn-outline-primary btn-sm" type="button" id="m64-ovr-add"><i class="bi bi-plus-lg"></i> ' + esc(L('rl.add')) + '</button></div></div>';
		$('#m64-ovr').innerHTML = html;
		$('#m64-ovr-add').onclick = function () { ovrForm(null); };
		var own = R.own;
		$('#m64-own').innerHTML = '<div class="card"><div class="card-header fw-semibold">' + esc(L('rl.own')) + ' <span class="badge text-bg-secondary">' + own.length + '</span> <span class="small text-body-secondary fw-normal">– ' + esc(L('rl.own_sub')) + '</span></div><div class="table-responsive"><table class="table table-sm mb-0 align-middle"><tbody>' +
			own.map(function (x) {
				var kl = x.key ? tx(x.name) + ' · ' + kindLabel(x.kind) : L('rl.own_kind', { c: kindLabel(x.kind) });
				return '<tr class="clickable" tabindex="0" data-goto="/monitor64/host/' + encodeURIComponent(x.host_uid) + (x.key ? '#svc=' + encodeURIComponent(x.key) : '') + '"><td class="fw-semibold">' + esc(x.host) + '</td><td>' + esc(kl) + '</td><td class="text-end small">' + esc(ruleSummary(x.rule, x.kind)) + '</td><td class="text-end"><i class="bi bi-chevron-right text-body-tertiary"></i></td></tr>';
			}).join('') + (own.length ? '' : '<tr><td class="small text-body-secondary">' + esc(L('rl.own_none')) + '</td></tr>') + '</tbody></table></div></div>';
	}
	function ruleSummary(r, kind) {
		var p = [], f = (kindMeta(kind) || {}).factor || 1, n = function (v) { return lim(v) === null ? '–' : fmtNum(lim(v) / f); };
		if (r.mode === 'free') { p.push('< ' + fmtNum(lim(r.warn_free)) + ' / < ' + fmtNum(lim(r.crit_free)) + ' ' + L('unit.gb_free')); }
		else if (r.warn !== undefined || r.crit !== undefined) { p.push((r.warn === undefined ? '…' : n(r.warn)) + ' / ' + (r.crit === undefined ? '…' : n(r.crit))); }
		if (r.severity) { p.push(sevLabel(r.severity)); }
		if (r['for'] !== undefined) { p.push(durLabel(r['for'])); }
		if (r.report === 'show') { p.push(L('rl.show')); }
		return p.join(' · ');
	}
	function loadOvr() {
		api('GET', '/api/monitor64/rules').then(function (d) { R.overrides = d.overrides || []; R.own = d.own || []; R.targets = d.targets || R.targets; R.std = d.std || R.std; renderOvr(); }).catch(fail);
	}
	function ovrForm(o) {
		var r = (o && o.rule) || {};
		var tOpts = R.targets.groups.map(function (g) { return ['group|' + g, targetLabel('group', g)]; }).concat(R.targets.tags.map(function (t) { return ['tag|' + t, targetLabel('tag', t)]; }));
		var curT = o ? o.target_type + '|' + o.target : (tOpts.length ? tOpts[0][0] : '');
		if (o && !tOpts.some(function (x) { return x[0] === curT; })) { tOpts.push([curT, targetLabel(o.target_type, o.target)]); }
		var kinds = (D.kinds || []);
		var html = '<div class="card mb-3 border-primary"><div class="card-header fw-semibold">' + esc(o ? L('rl.edit') : L('rl.new')) + (o ? '' : ' <span class="small text-body-secondary fw-normal">– ' + esc(L('rl.new_sub')) + '</span>') + '</div><div class="card-body"><div class="row g-2">' +
			'<div class="col-md-4"><label class="form-label small mb-0" for="m64-nf-t">' + esc(L('rl.for_target')) + '</label><select class="form-select form-select-sm" id="m64-nf-t">' + tOpts.map(function (x) { return '<option value="' + esc(x[0]) + '"' + (x[0] === curT ? ' selected' : '') + '>' + esc(x[1]) + '</option>'; }).join('') + '</select>' +
			'<div class="input-group input-group-sm mt-1"><select class="form-select" id="m64-nf-tt" aria-label="' + esc(L('rl.new_target')) + '"><option value="group">' + esc(L('f.group')) + '</option><option value="tag">' + esc(L('f.tag')) + '</option></select><input class="form-control" id="m64-nf-tn" maxlength="64" placeholder="' + esc(L('rl.new_target')) + '"></div></div>' +
			'<div class="col-md-4"><label class="form-label small mb-0" for="m64-nf-k">' + esc(L('rl.value')) + '</label><select class="form-select form-select-sm" id="m64-nf-k">' + kinds.map(function (k) { return '<option value="' + esc(k.kind) + '"' + ((o ? o.kind : 'fs.used') === k.kind ? ' selected' : '') + '>' + esc(kindLabel(k.kind)) + '</option>'; }).join('') + '</select></div>' +
			'<div class="col-md-4" data-num><label class="form-label small mb-0" for="m64-nf-u">' + esc(L('rl.unit')) + '</label><select class="form-select form-select-sm" id="m64-nf-u"></select></div>' +
			'<div class="col-4 col-md-2" data-num><label class="form-label small mb-0" for="m64-nf-w">' + esc(L('rl.warn')) + '</label><input class="form-control form-control-sm" id="m64-nf-w" inputmode="decimal"></div>' +
			'<div class="col-4 col-md-2" data-num><label class="form-label small mb-0" for="m64-nf-c">' + esc(L('rl.crit')) + '</label><input class="form-control form-control-sm" id="m64-nf-c" inputmode="decimal"></div>' +
			'<div class="col-md-4" data-sev><label class="form-label small mb-0" for="m64-nf-s">' + esc(L('sd.on_fault')) + '</label><select class="form-select form-select-sm" id="m64-nf-s">' + ['crit', 'warn', 'off'].map(function (x) { return '<option value="' + x + '"' + (r.severity === x ? ' selected' : '') + '>' + esc(sevLabel(x)) + '</option>'; }).join('') + '</select></div>' +
			'<div class="col-4 col-md-2"><label class="form-label small mb-0" for="m64-nf-f">' + esc(L('rl.for')) + '</label><select class="form-select form-select-sm" id="m64-nf-f"><option value="">' + esc(L('rl.inherit')) + '</option>' + [0, 300, 900, 3600, 86400].map(function (x) { return '<option value="' + x + '"' + (r['for'] === x ? ' selected' : '') + '>' + esc(durLabel(x)) + '</option>'; }).join('') + '</select></div>' +
			'<div class="col-md-3"><label class="form-label small mb-0" for="m64-nf-r">' + esc(L('sd.report')) + '</label><select class="form-select form-select-sm" id="m64-nf-r"><option value="">' + esc(L('rl.inherit')) + '</option><option value="notify"' + (r.report === 'notify' ? ' selected' : '') + '>' + esc(L('rl.notify')) + '</option><option value="show"' + (r.report === 'show' ? ' selected' : '') + '>' + esc(L('rl.show')) + '</option></select></div></div>' +
			'<div class="preview mt-3" id="m64-nf-p"></div></div><div class="card-footer d-flex gap-2"><button class="btn btn-primary btn-sm" type="button" id="m64-nf-save">' + esc(L('rl.save')) + '</button><button class="btn btn-outline-secondary btn-sm" type="button" id="m64-nf-cancel">' + esc(L('cancel')) + '</button></div></div>';
		var box = $('#m64-ovr-form');
		box.innerHTML = html;
		function units(first) {
			var k = $('#m64-nf-k').value, meta = kindMeta(k) || {}, u = $('#m64-nf-u');
			var lbl = meta.unit === 'min' ? L('unit.min') : meta.unit === 'days' ? L('unit.days') : meta.unit || '–';
			u.innerHTML = meta.store ? '<option value="used">' + esc(L('sd.mode_used')) + '</option><option value="free">' + esc(L('sd.mode_free')) + '</option>' : '<option value="used">' + esc(lbl) + '</option>';
			if (first && r.mode === 'free') { u.value = 'free'; }
			$$('[data-num]', box).forEach(function (x) { x.classList.toggle('d-none', !!meta.state); });
			$$('[data-sev]', box).forEach(function (x) { x.classList.toggle('d-none', !meta.state); });
			if (first) {
				var f = meta.factor || 1, free = u.value === 'free';
				var w = free ? r.warn_free : r.warn, c = free ? r.crit_free : r.crit;
				$('#m64-nf-w').value = w === undefined || lim(w) === null ? '' : numIn(free ? w : w / f);
				$('#m64-nf-c').value = c === undefined || lim(c) === null ? '' : numIn(free ? c : c / f);
			}
		}
		function cur() {
			var t = splitTarget($('#m64-nf-t').value), tn = $('#m64-nf-tn').value.trim();
			if (tn) { t = [$('#m64-nf-tt').value, tn]; }
			var k = $('#m64-nf-k').value, meta = kindMeta(k) || {}, f = meta.factor || 1, rule = {};
			if (meta.state) { rule.severity = $('#m64-nf-s').value; }
			else {
				var free = $('#m64-nf-u').value === 'free', w = parseNum($('#m64-nf-w').value), c = parseNum($('#m64-nf-c').value);
				if ((w !== null && isNaN(w)) || (c !== null && isNaN(c))) { return null; }
				if (meta.store) { rule.mode = free ? 'free' : 'used'; }
				if (w !== null) { rule[free ? 'warn_free' : 'warn'] = free ? w : w * f; }
				if (c !== null) { rule[free ? 'crit_free' : 'crit'] = free ? c : c * f; }
			}
			var fv = $('#m64-nf-f').value;
			if (fv !== '') { rule['for'] = parseInt(fv, 10); }
			var rv = $('#m64-nf-r').value;
			if (rv) { rule.report = rv; }
			return { target_type: t[0] || 'group', target: t[1] || '', kind: k, rule: rule };
		}
		var pt = null;
		function preview() {
			clearTimeout(pt);
			pt = setTimeout(function () {
				var c = cur(), p = $('#m64-nf-p');
				if (!c) { p.textContent = L('err_number'); return; }
				if (!c.target) { p.textContent = L('rl.pick_target'); return; }
				var body = { target_type: c.target_type, target: c.target, kind: c.kind, rule: c.rule };
				if (o) { body.uid = o.uid; }
				api('POST', '/api/monitor64/rules/preview', body).then(function (e) {
					var shadowN = 0;
					Object.keys(e.shadow || {}).forEach(function (j) { shadowN += e.shadow[j].length; });
					var meta = kindMeta(c.kind) || {};
					p.innerHTML = '<div class="fw-semibold mb-1"><i class="bi bi-eye"></i> ' + esc(L('rl.preview')) + '</div>' +
						'<div>' + esc(L('rl.affects', { s: e.services, h: e.hosts.length })) + (e.hosts.length ? ' (' + esc(e.hosts.join(', ')) + ')' : '') + '.</div>' +
						(meta.state ? '' : '<div>' + esc(L('rl.after')) + ' <span class="st-badge warn">' + esc(L('rl.n_warn', { n: e.after.warn })) + '</span> <span class="st-badge crit">' + esc(L('rl.n_crit', { n: e.after.crit })) + '</span> <span class="text-body-secondary small">' + esc(L('rl.before', { w: e.before.warn, c: e.before.crit })) + '</span></div>') +
						(shadowN || e.own.length ? '<div class="small text-body-secondary mt-1">' + esc(L('rl.not_affected', { s: shadowN, o: e.own.length })) + '</div>' : '');
				}).catch(function (err) { p.textContent = tx(err.message); });
			}, 250);
		}
		units(true);
		preview();
		['m64-nf-t', 'm64-nf-tt', 'm64-nf-tn', 'm64-nf-u', 'm64-nf-w', 'm64-nf-c', 'm64-nf-f', 'm64-nf-r', 'm64-nf-s'].forEach(function (id) { var el = document.getElementById(id); el.oninput = el.onchange = preview; });
		$('#m64-nf-k').onchange = function () { units(false); preview(); };
		$('#m64-nf-cancel').onclick = function () { box.innerHTML = ''; };
		$('#m64-nf-save').onclick = function () {
			var c = cur();
			if (!c) { toast(L('err_number'), true); return; }
			lock(this, function () { return api(o ? 'PUT' : 'POST', '/api/monitor64/rules/overrides' + (o ? '/' + encodeURIComponent(o.uid) : ''), c).then(function () { box.innerHTML = ''; toast(L('rl.saved_toast')); loadOvr(); }); }).catch(fail);
		};
		box.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
	}
	root.addEventListener('click', function (ev) {
		var mv = ev.target.closest('[data-mv]');
		if (mv) { lock(mv, function () { return api('POST', '/api/monitor64/rules/overrides/' + encodeURIComponent(mv.dataset.mv) + '/move', { dir: parseInt(mv.dataset.dir, 10) }).then(function () { toast(L('rl.moved_toast')); loadOvr(); }); }).catch(fail); return; }
		var ed = ev.target.closest('[data-ed]');
		if (ed) { R.overrides.forEach(function (o) { if (o.uid === ed.dataset.ed) { ovrForm(o); } }); return; }
		var rm = ev.target.closest('[data-rm]');
		if (rm) { confirmBox(L('rl.delete'), L('rl.delete_confirm'), L('rl.delete'), function () { return api('DELETE', '/api/monitor64/rules/overrides/' + encodeURIComponent(rm.dataset.rm)).then(function () { toast(L('rl.deleted_toast')); loadOvr(); }).catch(fail); }); return; }
		var g = ev.target.closest('[data-goto]');
		if (g) { location.href = g.dataset.goto; }
	});
	root.addEventListener('keydown', function (ev) { if ((ev.key === 'Enter' || ev.key === ' ') && ev.target.matches('[data-goto]')) { ev.preventDefault(); ev.target.click(); } });
	if (location.hash === '#overrides') { var t = document.getElementById('m64-tab-ovr'); if (t && window.bootstrap) { window.bootstrap.Tab.getOrCreateInstance(t).show(); } }
	loadOvr();
}

// ---------- Benachrichtigung ----------
var CH_ICON = { smtp: 'bi-envelope', telegram: 'bi-telegram', discord: 'bi-discord', slack: 'bi-slack', teams: 'bi-microsoft-teams', matrix: 'bi-chat-dots', ntfy: 'bi-bell', gotify: 'bi-bell', pushover: 'bi-phone', app: 'bi-phone', homeassistant: 'bi-house', webhook: 'bi-link-45deg', browser: 'bi-window' };
function pageNotify() {
	var N = { config: { channels: [] }, channels: [], overrides: [], targets: { groups: [], tags: [] } };
	function chanName(id) { if (id === 'default') { return L('nf.default'); } var n = id; N.channels.forEach(function (c) { if (String(c.id) === id) { n = c.name; } }); return n; }
	function route(id) { var r = null; (N.config.channels || []).forEach(function (c) { if (c.id === id) { r = c; } }); return r; }
	function render() {
		var rows = [{ id: 'default', name: L('nf.default'), type: '', sub: L('nf.default_sub') }].concat(N.channels.map(function (c) { return { id: String(c.id), name: c.name, type: c.type, off: !c.enabled, def: c['default'] }; }));
		$('#m64-nf-channels').innerHTML = rows.map(function (c) {
			var r = route(c.id) || {};
			return '<tr data-ch="' + esc(c.id) + '"><td><i class="bi ' + esc(CH_ICON[c.type] || 'bi-broadcast') + '"></i> ' + esc(c.name) + (c.off ? ' <span class="badge text-bg-secondary">' + esc(L('nf.ch_off')) + '</span>' : '') + (c.def ? ' <span class="badge text-bg-light">' + esc(L('nf.ch_default')) + '</span>' : '') + (c.sub ? '<div class="small text-body-secondary">' + esc(c.sub) + '</div>' : '') + '</td>' +
				'<td class="text-center"><input class="form-check-input" type="checkbox" name="warn" aria-label="' + esc(ST.warn + ' ' + c.name) + '"' + (r.warn ? ' checked' : '') + '></td><td class="text-center"><input class="form-check-input" type="checkbox" name="crit" aria-label="' + esc(ST.crit + ' ' + c.name) + '"' + (r.crit ? ' checked' : '') + '></td></tr>';
		}).join('');
		$('#m64-remind-crit').value = String(N.config.remind_crit || 0);
		$('#m64-remind-warn').value = String(N.config.remind_warn || 0);
		$('#m64-crit-quiet').checked = !!N.config.crit_in_quiet;
		var q = N.quiet || {};
		$('#m64-quiet').textContent = q.enabled && q.from ? L('nf.quiet_range', { a: q.from, b: q.to }) : L('nf.quiet_off');
		renderOvr();
	}
	function remindText(d) { return d >= 86400 ? L('nf.daily') : d >= 14400 ? L('nf.every4h') : d ? fmtDur(d) : L('nf.never'); }
	function ovrSummary(o) {
		var n = o.notify || {}, p = [];
		if (n.channels && n.channels.length) {
			var cl = { c: n.channels.map(function (c) { return chanName(c.id) + (c.warn ? '' : ' (' + ST.crit + ')'); }).join(', ') };
			p.push(n.replace ? L('nf.only_ch', cl) : L('nf.plus_ch', cl));
		}
		if (n.only_crit !== undefined && n.only_crit !== null) { p.push(n.only_crit ? L('nf.only_crit') : L('nf.warn_too')); }
		if (n.crit_in_quiet !== undefined && n.crit_in_quiet !== null) { p.push(n.crit_in_quiet ? L('nf.crit_in_quiet') : L('nf.no_crit_in_quiet')); }
		if (n.remind_crit !== undefined && n.remind_crit !== null) { p.push(L('nf.remind_crit_x', { x: remindText(n.remind_crit) })); }
		if (n.remind_warn !== undefined && n.remind_warn !== null) { p.push(L('nf.remind_warn_x', { x: remindText(n.remind_warn) })); }
		return p.join(' · ') || L('nf.no_change');
	}
	function renderOvr() {
		var list = N.overrides;
		$('#m64-nf-ovr').innerHTML = list.map(function (o, i) {
			return '<div class="list-group-item d-flex gap-2 align-items-center"><span class="ovr-num">' + (i + 1) + '</span><div class="flex-grow-1 min-w-0"><span class="tag">' + esc(targetLabel(o.target_type, o.target)) + '</span> <span class="small">' + esc(ovrSummary(o)) + '</span><div class="small text-body-secondary">' + esc(L('rl.changed_by', { w: whoTxt(o.by), t: fmtTime(o.at) })) + '</div></div>' +
				'<div class="btn-group btn-group-sm flex-shrink-0"><button class="btn btn-outline-secondary" type="button" data-mv="' + esc(o.uid) + '" data-dir="-1"' + (i ? '' : ' disabled') + ' aria-label="' + esc(L('rl.up')) + '"><i class="bi bi-arrow-up"></i></button><button class="btn btn-outline-secondary" type="button" data-mv="' + esc(o.uid) + '" data-dir="1"' + (i < list.length - 1 ? '' : ' disabled') + ' aria-label="' + esc(L('rl.down')) + '"><i class="bi bi-arrow-down"></i></button>' +
				'<button class="btn btn-outline-secondary" type="button" data-ed="' + esc(o.uid) + '" aria-label="' + esc(L('rl.edit')) + '"><i class="bi bi-pencil"></i></button><button class="btn btn-outline-secondary" type="button" data-rm="' + esc(o.uid) + '" aria-label="' + esc(L('rl.delete')) + '"><i class="bi bi-trash"></i></button></div></div>';
		}).join('') || '<div class="list-group-item small text-body-secondary">' + esc(L('rl.no_overrides')) + '</div>';
	}
	function triSel(id, v, yes, no) {
		return '<select class="form-select form-select-sm" id="' + id + '"><option value="">' + esc(L('rl.inherit')) + '</option><option value="1"' + (v === true ? ' selected' : '') + '>' + esc(yes) + '</option><option value="0"' + (v === false ? ' selected' : '') + '>' + esc(no) + '</option></select>';
	}
	function remSel(id, v) {
		return '<select class="form-select form-select-sm" id="' + id + '"><option value="">' + esc(L('rl.inherit')) + '</option>' + [0, 14400, 86400].map(function (x) { return '<option value="' + x + '"' + (v === x ? ' selected' : '') + '>' + esc(remindText(x)) + '</option>'; }).join('') + '</select>';
	}
	function ovrForm(o) {
		var n = (o && o.notify) || {};
		var tOpts = N.targets.groups.map(function (g) { return ['group|' + g, targetLabel('group', g)]; }).concat(N.targets.tags.map(function (t) { return ['tag|' + t, targetLabel('tag', t)]; }));
		var curT = o ? o.target_type + '|' + o.target : (tOpts.length ? tOpts[0][0] : '');
		if (o && !tOpts.some(function (x) { return x[0] === curT; })) { tOpts.push([curT, targetLabel(o.target_type, o.target)]); }
		var chans = [{ id: 'default', name: L('nf.default') }].concat(N.channels.map(function (c) { return { id: String(c.id), name: c.name }; }));
		function chv(id) { var r = ''; (n.channels || []).forEach(function (c) { if (c.id === id) { r = c.warn ? 'both' : 'crit'; } }); return r; }
		var html = '<div class="card-body border-top"><div class="row g-2">' +
			'<div class="col-md-6"><label class="form-label small mb-0" for="m64-no-t">' + esc(L('rl.for_target')) + '</label><select class="form-select form-select-sm" id="m64-no-t">' + tOpts.map(function (x) { return '<option value="' + esc(x[0]) + '"' + (x[0] === curT ? ' selected' : '') + '>' + esc(x[1]) + '</option>'; }).join('') + '</select></div>' +
			'<div class="col-md-6"><label class="form-label small mb-0" for="m64-no-rep">' + esc(L('nf.channels_mode')) + '</label><select class="form-select form-select-sm" id="m64-no-rep"><option value="0"' + (n.replace ? '' : ' selected') + '>' + esc(L('nf.mode_add')) + '</option><option value="1"' + (n.replace ? ' selected' : '') + '>' + esc(L('nf.mode_replace')) + '</option></select></div>' +
			'<div class="col-12"><div class="small text-body-secondary mb-1">' + esc(L('nf.channel')) + '</div>' + chans.map(function (c) { var v = chv(c.id); return '<div class="d-flex align-items-center gap-2 mb-1"><span class="small me-auto">' + esc(c.name) + '</span><select class="form-select form-select-sm w-auto" data-och="' + esc(c.id) + '" aria-label="' + esc(c.name) + '"><option value="">–</option><option value="both"' + (v === 'both' ? ' selected' : '') + '>' + esc(ST.warn + ' + ' + ST.crit) + '</option><option value="crit"' + (v === 'crit' ? ' selected' : '') + '>' + esc(L('nf.only_crit')) + '</option></select></div>'; }).join('') + '</div>' +
			'<div class="col-md-6"><label class="form-label small mb-0" for="m64-no-oc">' + esc(L('nf.only_crit')) + '</label>' + triSel('m64-no-oc', n.only_crit, L('yes'), L('no')) + '</div>' +
			'<div class="col-md-6"><label class="form-label small mb-0" for="m64-no-cq">' + esc(L('nf.crit_in_quiet')) + '</label>' + triSel('m64-no-cq', n.crit_in_quiet, L('yes'), L('no')) + '</div>' +
			'<div class="col-md-6"><label class="form-label small mb-0" for="m64-no-rc">' + esc(L('nf.remind') + ' · ' + ST.crit) + '</label>' + remSel('m64-no-rc', n.remind_crit) + '</div>' +
			'<div class="col-md-6"><label class="form-label small mb-0" for="m64-no-rw">' + esc(L('nf.remind') + ' · ' + ST.warn) + '</label>' + remSel('m64-no-rw', n.remind_warn) + '</div></div>' +
			'<div class="d-flex gap-2 mt-3"><button class="btn btn-primary btn-sm" type="button" id="m64-no-save">' + esc(L('save')) + '</button><button class="btn btn-outline-secondary btn-sm" type="button" id="m64-no-cancel">' + esc(L('cancel')) + '</button></div></div>';
		var box = $('#m64-nf-ovr-form');
		box.innerHTML = html;
		function tri(id) { var v = $('#' + id).value; return v === '' ? null : v === '1'; }
		function rem(id) { var v = $('#' + id).value; return v === '' ? null : parseInt(v, 10); }
		$('#m64-no-cancel').onclick = function () { box.innerHTML = ''; };
		$('#m64-no-save').onclick = function () {
			var t = splitTarget($('#m64-no-t').value);
			if (!t[1]) { toast(L('rl.pick_target'), true); return; }
			var body = { target_type: t[0], target: t[1], replace: $('#m64-no-rep').value === '1', channels: [] };
			$$('[data-och]', box).forEach(function (s) { if (s.value) { body.channels.push({ id: s.dataset.och, warn: s.value === 'both', crit: true }); } });
			var oc = tri('m64-no-oc'), cq = tri('m64-no-cq'), rc = rem('m64-no-rc'), rw = rem('m64-no-rw');
			if (oc !== null) { body.only_crit = oc; }
			if (cq !== null) { body.crit_in_quiet = cq; }
			if (rc !== null) { body.remind_crit = rc; }
			if (rw !== null) { body.remind_warn = rw; }
			lock(this, function () { return api(o ? 'PUT' : 'POST', '/api/monitor64/notify/overrides' + (o ? '/' + encodeURIComponent(o.uid) : ''), body).then(function () { box.innerHTML = ''; toast(L('rl.saved_toast')); load(); }); }).catch(fail);
		};
	}
	function load() { api('GET', '/api/monitor64/notify').then(function (d) { N.config = d.config || N.config; N.channels = d.channels || []; N.overrides = d.overrides || []; N.quiet = d.quiet; N.targets = d.targets || N.targets; render(); }).catch(fail); }
	$('#m64-nf-save').onclick = function () {
		var body = { channels: [], remind_warn: parseInt($('#m64-remind-warn').value, 10), remind_crit: parseInt($('#m64-remind-crit').value, 10), crit_in_quiet: $('#m64-crit-quiet').checked };
		$$('#m64-nf-channels tr[data-ch]').forEach(function (tr) {
			var w = $('[name=warn]', tr).checked, c = $('[name=crit]', tr).checked;
			if (w || c) { body.channels.push({ id: tr.dataset.ch, warn: w, crit: c }); }
		});
		lock(this, function () { return api('PUT', '/api/monitor64/notify', body).then(function () { toast(L('nf.saved_toast')); load(); }); }).catch(fail);
	};
	$('#m64-nf-test').onclick = function () { lock(this, function () { return api('POST', '/api/monitor64/notify/test').then(function (r) { toast(L('nf.test_toast', { n: r.channels })); }); }).catch(fail); };
	$('#m64-nf-add').onclick = function () { ovrForm(null); };
	$$('#m64-pv-tabs [data-pv]').forEach(function (a) {
		a.onclick = function (e) {
			e.preventDefault();
			$$('#m64-pv-tabs [data-pv]').forEach(function (x) { x.classList.toggle('active', x === a); });
			$$('[data-pv-box]').forEach(function (b) { b.classList.toggle('d-none', b.dataset.pvBox !== a.dataset.pv); });
		};
	});
	root.addEventListener('click', function (ev) {
		var mv = ev.target.closest('[data-mv]');
		if (mv) { lock(mv, function () { return api('POST', '/api/monitor64/notify/overrides/' + encodeURIComponent(mv.dataset.mv) + '/move', { dir: parseInt(mv.dataset.dir, 10) }).then(function () { toast(L('rl.moved_toast')); load(); }); }).catch(fail); return; }
		var ed = ev.target.closest('[data-ed]');
		if (ed) { N.overrides.forEach(function (o) { if (o.uid === ed.dataset.ed) { ovrForm(o); } }); return; }
		var rm = ev.target.closest('[data-rm]');
		if (rm) { confirmBox(L('rl.delete'), L('rl.delete_confirm'), L('rl.delete'), function () { return api('DELETE', '/api/monitor64/notify/overrides/' + encodeURIComponent(rm.dataset.rm)).then(function () { toast(L('rl.deleted_toast')); load(); }).catch(fail); }); }
	});
	load();
}

// ---------- Einstellungen ----------
function pageSettings() {
	$('#m64-settings-form').onsubmit = function (ev) {
		ev.preventDefault();
		var sb = $('#m64-settings-form [type=submit]');
		var body = { interval: parseInt($('#m64-interval').value, 10), workers: parseInt($('#m64-workers').value, 10) }, tp = $('#m64-trap-port');
		if (tp) { body.trap_port = parseInt(tp.value, 10) || 0; }
		var pp = $('#m64-push-port');
		if (pp) { body.push_port = parseInt(pp.value, 10) || 0; }
		lock(sb, function () { return api('PUT', '/api/monitor64/settings', body).then(function () { toast(L('st.saved_toast')); }); }).catch(fail);
	};
	// Traps unbekannter Absender: nie automatisch angelegt, Knopf oeffnet den Assistenten mit Adresse und Art SNMP
	function renderUnknown(list) {
		var box = $('#m64-trap-unknown');
		if (!box) { return; }
		box.innerHTML = list.length ? list.map(function (u) {
			var what = u.user ? L('st.traps_user', { u: u.user }) : (u.trap_name || u.trap_oid || '');
			return '<div class="list-group-item px-0 d-flex flex-wrap align-items-center gap-2"><div class="me-auto min-w-0"><code>' + esc(u.addr) + '</code> <span class="text-body-secondary">v' + esc(u.version) + ' · ' + esc(L('st.traps_count', { n: u.count })) + ' · ' + esc(fmtTime(u.last)) + '</span>' +
				(what ? '<div class="text-body-secondary text-truncate">' + esc(what) + '</div>' : '') + '</div>' +
				'<a class="btn btn-sm btn-outline-primary" href="/monitor64/new?kind=snmp&amp;address=' + encodeURIComponent(u.addr) + '"><i class="bi bi-plus-lg"></i> ' + esc(L('st.traps_add_host')) + '</a></div>';
		}).join('') : '<div class="list-group-item px-0 text-body-secondary">' + esc(L('st.traps_none')) + '</div>';
		var cl = $('#m64-trap-clear');
		if (cl) { cl.hidden = !list.length; }
	}
	renderUnknown((D.traps && D.traps.unknown) || []);
	var clr = $('#m64-trap-clear');
	if (clr) { clr.onclick = function () { lock(clr, function () { return api('DELETE', '/api/monitor64/traps/unknown').then(function () { renderUnknown([]); }); }).catch(fail); }; }
	if (D.cluster) { clusterKeys(D.cluster.key || {}); clusterKeyActions(); }
}
// clusterKeys: Karte Cluster – gemeinsamer Schluessel (Fingerabdruck, Zeile fuer authorized_keys), Schluessel wechseln,
// offene Umstellungen der Agents bzw. SSH-Hosts, alte Schluessel verwerfen.
function clusterKeys(k) {
	var box = $('#m64-cl-key'), pend = $('#m64-cl-pending');
	if (!box || !pend) { return; }
	var old = k.old_keys || [], list = k.pending || [];
	box.innerHTML = '<div>' + esc(k.cluster ? L('cluster.key_shared', { t: fmtTime(k.at) }) : L('cluster.key_own')) + '</div>' +
		'<div class="mt-1">' + esc(L('cluster.key_fp')) + ' <code id="m64-cl-fp">' + esc(k.fingerprint || '–') + '</code></div>' +
		'<div class="d-flex align-items-center mt-2">' + esc(L('cluster.key_line')) + '<button class="btn btn-sm btn-link ms-auto p-0" type="button" data-copy-target="#m64-cl-line"><i class="bi bi-clipboard"></i> ' + esc(L('copy')) + '</button></div>' +
		'<div class="cmd" id="m64-cl-line">' + esc(k.authorized_key || '') + '</div>' +
		(old.length ? '<div class="text-warning-emphasis mt-2"><i class="bi bi-hourglass-split"></i> ' + esc(L('cluster.key_old', { n: old.length })) + ' <span class="text-body-secondary">' + esc(old.join(', ')) + '</span></div>' : '');
	pend.innerHTML = list.length ? list.map(function (p) {
		var what = p.manual ? L('cluster.pending_ssh') : L('cluster.pending_agent', { n: p.tries, t: fmtTime(p.last_try) });
		return '<div class="list-group-item px-0 d-flex flex-wrap align-items-center gap-2"><div class="me-auto min-w-0"><a href="/monitor64/host/' + encodeURIComponent(p.host_uid) + '" class="fw-semibold">' + esc(p.host_name || p.host_uid) + '</a> <span class="text-body-secondary">' + esc(accLabel(p.type)) + '</span>' +
			'<div class="text-body-secondary">' + esc(what) + '</div>' + (p.error ? '<div class="text-danger-emphasis text-truncate">' + esc(tx(p.error)) + '</div>' : '') + '</div>' +
			(p.manual ? '<button class="btn btn-sm btn-outline-primary" type="button" data-cl-confirm="' + esc(p.access_uid) + '"><i class="bi bi-check2"></i> ' + esc(L('cluster.confirm')) + '</button>' : '') + '</div>';
	}).join('') : '<div class="list-group-item px-0 text-body-secondary">' + esc(L('cluster.pending_none')) + '</div>';
	var retry = $('#m64-cl-retry'), retire = $('#m64-cl-retire');
	if (retry) { retry.hidden = !list.some(function (p) { return !p.manual; }); }
	if (retire) { retire.hidden = !old.length && !list.length; }
}
function clusterKeyActions() {
	var card = $('#m64-cluster');
	if (!card) { return; }
	// Umstellung laeuft im Hintergrund (running): Stand alle 3 s neu holen, bis sie fertig ist
	var poll = null;
	function follow(k) {
		clusterKeys(k);
		if (k && k.running && !poll) {
			poll = setInterval(function () {
				api('GET', '/api/monitor64/cluster/keys').then(function (n) { clusterKeys(n); if (!n.running) { clearInterval(poll); poll = null; } }).catch(function () { clearInterval(poll); poll = null; });
			}, 3000);
		}
	}
	function keyCall(path, body, msg) { return api('POST', '/api/monitor64/cluster/keys/' + path, body).then(function (k) { follow(k); toast(msg); }); }
	card.addEventListener('click', function (ev) {
		var b = ev.target.closest('[data-cl-confirm]');
		if (b) { lock(b, function () { return keyCall('confirm', { access_uid: b.dataset.clConfirm }, L('cluster.confirmed_toast')); }).catch(fail); return; }
		var a = ev.target.closest('#m64-cl-rotate, #m64-cl-retry, #m64-cl-retire');
		if (!a) { return; }
		if (a.id === 'm64-cl-retry') { lock(a, function () { return keyCall('retry', undefined, L('cluster.retry_toast')); }).catch(fail); }
		if (a.id === 'm64-cl-rotate') { confirmBox(L('cluster.key_rotate'), L('cluster.key_rotate_confirm'), L('cluster.key_rotate'), function () { return keyCall('rotate', undefined, L('cluster.key_rotated_toast')).catch(fail); }); }
		if (a.id === 'm64-cl-retire') { confirmBox(L('cluster.retire'), L('cluster.retire_confirm'), L('cluster.retire'), function () { return keyCall('retire', undefined, L('cluster.retired_toast')).catch(fail); }); }
	});
}

// pushTarget: Ziel des Push-Agents token@node:port; IPv6 in Klammern, nur Zeichen von Namen und Adressen (der Befehl
// wird in eine Shell kopiert).
function pushTarget(tok, node, port) {
	var h = String(node || '').trim().replace(/[^0-9A-Za-z.:%_\-\[\]]/g, '');
	if (h.indexOf(':') >= 0 && h.charAt(0) !== '[') { h = '[' + h.replace(/[\[\]]/g, '') + ']'; }
	return tok + '@' + h + ':' + port;
}
// ---------- Assistent "Host hinzufuegen" ----------
function pageNew() {
	var WZ = { step: 1, kind: null, name: '', address: '', port: '', user: 'monitor64', smart: false, usePw: false, password: '', url: '', token_id: '', token_secret: '', node: '', bmax: '', pin: '', docker_secret: '',
		duser: '', dsecret: '', ups: '', tls: '', api: '', session: false, metrics: '', mode: '', pushNode: location.hostname, token: '', pushPort: 0,
		s_version: '2c', s_port: '', s_community: '', s_user: '', s_level: 'authPriv', s_auth: 'SHA256', s_authpass: '', s_priv: 'AES', s_privpass: '', s_context: '', s_engine: '', s_custom: '', s_traps: false,
		test: null, nodeAddr: '', group: '', tags: '', interval: D.interval || 60, adopt: {}, nodes: {}, clPref: '', clBack: {} };
	// Cluster: bevorzugte Node (Standard diese) und Ersatz-Nodes (Standard keine), nur bei aktivem Cluster
	var CLW = D.cluster && D.cluster.active ? D.cluster : null, clFailed = false;
	// Felder, deren Aenderung ein Testergebnis ungueltig macht (anderes Ziel bzw. andere Zugangsdaten)
	var CONN = ['address', 'port', 'user', 'usePw', 'password', 'url', 'token_id', 'token_secret', 'node', 'bmax', 'pin', 'docker_secret', 'smart', 'duser', 'dsecret', 'ups', 'tls', 'api', 'session', 'metrics',
		's_version', 's_port', 's_community', 's_user', 's_level', 's_auth', 's_authpass', 's_priv', 's_privpass', 's_context', 's_engine', 's_custom', 's_traps'];
	// Vorbelegung aus der Adresse (z. B. "als Host anlegen" bei Traps unbekannter Absender): ?kind=snmp&address=10.0.0.5
	(function () {
		var q = new URLSearchParams(location.search), k = q.get('kind'), a = (q.get('address') || '').trim();
		var hk = (D.host_kinds || []).filter(function (x) { return x.kind === k && !x.soon; })[0];
		if (!hk) { return; }
		WZ.kind = hk.kind;
		if (a && a.length <= 253) { WZ.address = a; WZ.name = a; }
		if (hk.access === 'snmp' && a) { WZ.s_traps = true; }
		WZ.step = 2;
	})();
	var key = D.public_key || L('new.no_key');
	function kind() { var k = null; (D.host_kinds || []).forEach(function (x) { if (x.kind === WZ.kind) { k = x; } }); return k; }
	function kl(k) { return ((D.host_kind_labels || {})[k] || [k, ''])[0]; }
	function steps() {
		var names = [L('new.s1'), L('new.s2'), L('new.s3'), L('new.s4')];
		$('#m64-steps').innerHTML = names.map(function (n, i) {
			var c = i + 1 < WZ.step ? ' done' : i + 1 === WZ.step ? ' on' : '';
			return (i ? '<span class="step-sep"></span>' : '') + '<span class="step' + c + '"><span class="num">' + (i + 1 < WZ.step ? '<i class="bi bi-check"></i>' : i + 1) + '</span>' + esc(n) + '</span>';
		}).join('');
	}
	function field(id, label, val, attrs) { return '<label class="form-label" for="m64-w-' + id + '">' + esc(label) + '</label><input class="form-control" id="m64-w-' + id + '" value="' + esc(val) + '"' + (attrs || '') + '>'; }
	function access() {
		var k = kind(), t = k ? k.access : 'agent', cfg = {}, out = { type: t, config: cfg, secret: '' };
		if (t === 'agent' && WZ.port) { cfg.port = parseInt(WZ.port, 10) || 0; }
		if (t === 'agent' && WZ.mode === 'push') { cfg.mode = 'push'; cfg.token = WZ.token; delete cfg.port; }
		if (t === 'ssh') { cfg.user = WZ.user; cfg.smart = WZ.smart; if (WZ.port) { cfg.port = parseInt(WZ.port, 10) || 0; } if (WZ.usePw) { out.secret = WZ.password; } if (WZ.hostkey) { out.hostkey = WZ.hostkey; } }
		if (t === 'pve' || t === 'pbs' || t === 'docker') { cfg.url = WZ.url; cfg.pin = WZ.pin; }
		if (t === 'pve' || t === 'pbs') { cfg.token_id = WZ.token_id; out.secret = WZ.token_secret; }
		if (t === 'docker') { out.secret = WZ.docker_secret; }
		if (t === 'pve') { cfg.node = WZ.node; }
		if (t === 'pbs' && parseInt(WZ.bmax, 10) > 0) { cfg.backup_max_age_h = parseInt(WZ.bmax, 10); }
		if (DEVAPI.indexOf(t) >= 0) {
			var m = devCfg(t, function (id) { return id === 'user' ? WZ.duser : WZ[id]; });
			if (m === null) { throw new Error(L('acc.metrics_bad')); }
			cfg.url = WZ.url;
			cfg.pin = WZ.pin;
			Object.keys(m).forEach(function (x) { cfg[x] = m[x]; });
			out.secret = WZ.dsecret;
		}
		if (t === 'snmp') {
			var sr = snmpRead(function (id) { return WZ['s_' + id]; });
			if (sr === null) { throw new Error(L('acc.snmp_custom_bad')); }
			out.config = sr.config;
			out.secret = sr.secret;
		}
		return out;
	}
	function collect() {
		// Passwortfelder unveraendert (Leerzeichen am Rand koennen zum Passwort gehoeren)
		$$('#m64-wizard [data-w]').forEach(function (el) { WZ[el.dataset.w] = el.type === 'checkbox' ? el.checked : el.type === 'password' ? el.value : el.value.trim(); });
	}
	// weitere Nodes eines Proxmox-Clusters (Vorschlag "als eigene Hosts anlegen")
	function otherNodes() {
		var r = WZ.test;
		if (!r || !r.nodes || r.nodes.length < 2) { return []; }
		return r.nodes.filter(function (n) { return !n.local && n.name !== r.node; });
	}
	function render() {
		steps();
		var html = '', k = kind();
		if (WZ.step === 1) {
			html = '<p class="text-body-secondary">' + esc(L('new.intro')) + '</p><div class="row g-3">' + (D.host_kinds || []).map(function (x) {
				var lb = (D.host_kind_labels || {})[x.kind] || [x.kind, ''];
				return '<div class="col-6 col-md-3"><div class="card kind-tile' + (WZ.kind === x.kind ? ' sel' : '') + (x.soon ? ' disabled' : '') + '" data-kind="' + esc(x.kind) + '" role="button" tabindex="' + (x.soon ? '-1' : '0') + '" aria-disabled="' + !!x.soon + '" aria-pressed="' + (WZ.kind === x.kind) + '"><div class="card-body"><i class="bi ' + esc(x.icon) + '"></i><div class="fw-semibold mt-1">' + esc(lb[0]) + '</div><div class="small">' + esc(lb[1]) + '</div>' + (x.soon ? '<span class="badge text-bg-light mt-1">' + esc(L('new.soon')) + '</span>' : '') + '</div></div></div>';
			}).join('') + '</div>';
		} else if (WZ.step === 2) {
			html = '<div class="row g-3"><div class="col-md-6">' + field('name', L('f.name'), WZ.name, ' data-w="name" maxlength="100" placeholder="nas02"') + '</div><div class="col-md-6">' + field('addr', L('f.address'), WZ.address, ' data-w="address" maxlength="253" placeholder="10.0.0.21"') + '</div>';
			if (k.access === 'agent') {
				var push = WZ.mode === 'push', tgt = pushTarget(WZ.token, WZ.pushNode || location.hostname, WZ.pushPort || 6466);
				// Befehl je System (agentCmd); Quelle der Dateien - Internet oder diese Node - wie auf der Seite Agent
				var src = agentSrc(), cmd = agentCmd(WZ.kind === 'windows' || WZ.kind === 'freebsd' ? WZ.kind : 'linux', agentBase(src), key, push ? tgt : '');
				html +='<div class="col-md-6"><label class="form-label" for="m64-w-mode">' + esc(L('push.mode_label')) + '</label><select class="form-select" id="m64-w-mode" data-w="mode"><option value=""' + (push ? '' : ' selected') + '>' + esc(L('push.mode_pull')) + '</option><option value="push"' + (push ? ' selected' : '') + '>' + esc(L('push.mode_push')) + '</option></select></div>' +
					(push ? '<div class="col-md-6">' + field('pnode', L('push.node_addr'), WZ.pushNode, ' data-w="pushNode" maxlength="253"') + '</div>' : '') +
					'<div class="col-12"><div class="form-label d-flex align-items-center">' + esc(L('new.agent_step1')) + '<button class="btn btn-sm btn-link ms-auto p-0" type="button" data-copy-target="#m64-w-cmd"><i class="bi bi-clipboard"></i> ' + esc(L('copy')) + '</button></div><div class="cmd" id="m64-w-cmd">' + esc(push && !WZ.token ? '…' : cmd) + '</div>' + agentSrcHTML(src) +
					'<div class="small text-body-secondary mt-1"><i class="bi bi-shield-lock"></i> ' + esc(push ? L('push.hint', { port: WZ.pushPort || 6466 }) : L('new.agent_safe', { p: D.port || 6465 })) + '</div></div>' +
					(push ? '<div class="col-12 small">' + esc(L('push.test_after')) + '</div>' :
					'<div class="col-12"><div class="form-label">' + esc(L('new.agent_step2')) + '</div><div class="small">' + esc(L('new.agent_fp')) + '</div></div>' +
					'<div class="col-12"><details><summary class="small text-body-secondary">' + esc(L('advanced')) + '</summary><div class="pt-2" style="max-width:12rem">' + field('port', L('acc.port'), WZ.port, ' data-w="port" type="number" min="1" max="65535" placeholder="' + (D.port || 6465) + '"') + '</div></details></div>');
			} else if (k.access === 'ssh') {
				var line = 'restrict,from="' + (WZ.nodeAddr || (WZ.nodeBridge ? L('new.docker_host_ip') : L('new.node_ip'))) + '" ' + key, u = WZ.user || 'monitor64';
				html += '<div class="col-md-6">' + field('user', L('acc.user'), WZ.user, ' data-w="user" maxlength="32"') + '</div>' +
					'<div class="col-12"><div class="form-label d-flex align-items-center">' + esc(L('new.ssh_key')) + '<button class="btn btn-sm btn-link ms-auto p-0" type="button" data-copy-target="#m64-w-cmd"><i class="bi bi-clipboard"></i> ' + esc(L('copy')) + '</button></div><div class="cmd" id="m64-w-cmd">' + esc("echo '" + line + "' >> ~" + u + '/.ssh/authorized_keys') + '</div>' +
					(WZ.nodeBridge && !WZ.nodeAddr ? '<div class="small text-warning-emphasis mt-1"><i class="bi bi-info-circle"></i> ' + esc(L('new.from_bridge')) + '</div>' : '') +
					'<div class="small text-body-secondary mt-1"><i class="bi bi-shield-lock"></i> ' + esc(L('new.ssh_safe')) + '</div>' +
					// sudoers nur fuer die beiden Aufrufe des Skripts (Platten suchen, Werte lesen ohne Aufwecken)
					'<div class="form-check mt-2"><input class="form-check-input" type="checkbox" id="m64-w-smart" data-w="smart"' + (WZ.smart ? ' checked' : '') + '><label class="form-check-label small" for="m64-w-smart">' + esc(L('new.smart')) + '</label></div>' +
					'<div class="cmd small mt-1" id="m64-w-sudo">' + esc(u + ' ALL=(root) NOPASSWD: /usr/sbin/smartctl -V, /usr/sbin/smartctl --scan-open, /usr/sbin/smartctl -j -a -n standby /dev/*, /usr/sbin/smartctl -j -a -n standby -d * /dev/*') + '</div>' +
					'<div class="small text-body-secondary">' + esc(L('new.smart_hint')) + '</div>' +
					'<details class="mt-2"' + (WZ.usePw ? ' open' : '') + '><summary class="small text-body-secondary">' + esc(L('advanced')) + '</summary><div class="pt-2 row g-2"><div class="col-md-4">' + field('port', L('acc.port'), WZ.port, ' data-w="port" type="number" min="1" max="65535" placeholder="22"') + '</div>' +
					'<div class="col-12"><div class="form-check"><input class="form-check-input" type="checkbox" id="m64-w-pw" data-w="usePw"' + (WZ.usePw ? ' checked' : '') + '><label class="form-check-label small" for="m64-w-pw">' + esc(L('new.pw_auth')) + '</label></div>' +
					'<input class="form-control form-control-sm mt-1' + (WZ.usePw ? '' : ' d-none') + '" type="password" id="m64-w-pass" data-w="password" autocomplete="new-password" aria-label="' + esc(L('acc.secret')) + '" value="' + esc(WZ.password) + '"></div></div></details></div>';
			} else if (k.access === 'pve' || k.access === 'pbs') {
				var port = k.access === 'pve' ? 8006 : 8007;
				html += '<div class="col-12">' + field('url', 'URL', WZ.url, ' data-w="url" maxlength="512" placeholder="https://' + esc(urlHost(WZ.address) || '10.0.0.21') + ':' + port + '"') + '</div>' +
					'<div class="col-md-6">' + field('tid', L('new.token_id'), WZ.token_id, ' data-w="token_id" maxlength="128" placeholder="' + (k.access === 'pve' ? 'monitor@pve!node64' : 'monitor@pbs!node64') + '"') + '</div>' +
					'<div class="col-md-6">' + field('tsec', L('new.token_secret'), WZ.token_secret, ' data-w="token_secret" type="password" autocomplete="new-password"') + '</div>' +
					'<div class="col-12"><div class="form-label d-flex align-items-center">' + esc(L('new.token_cmd')) + '<button class="btn btn-sm btn-link ms-auto p-0" type="button" data-copy-target="#m64-w-cmd"><i class="bi bi-clipboard"></i> ' + esc(L('copy')) + '</button></div><div class="cmd" id="m64-w-cmd">' + esc(k.access === 'pve' ?
						'pveum user add monitor@pve\npveum aclmod / -user monitor@pve -role PVEAuditor\npveum user token add monitor@pve node64 --privsep 0' :
						// PBS: ein Token darf nur, was auch sein Benutzer darf - beide brauchen Audit
						'proxmox-backup-manager user create monitor@pbs\nproxmox-backup-manager user generate-token monitor@pbs node64\nproxmox-backup-manager acl update / Audit --auth-id monitor@pbs\nproxmox-backup-manager acl update / Audit --auth-id \'monitor@pbs!node64\'') + '</div>' +
					'<div class="small text-body-secondary mt-1"><i class="bi bi-info-circle"></i> ' + esc(L('new.api_hint')) + '</div></div>' +
					'<div class="col-12"><details' + (WZ.pin || WZ.node || WZ.bmax ? ' open' : '') + '><summary class="small text-body-secondary">' + esc(L('advanced')) + '</summary><div class="pt-2 row g-2">' + (k.access === 'pve' ? '<div class="col-md-6">' + field('node', L('new.node'), WZ.node, ' data-w="node" maxlength="64"') + '</div>' : '<div class="col-md-6">' + field('bmax', L('acc.backup_max_age'), WZ.bmax, ' data-w="bmax" type="number" min="1" max="8760" placeholder="26"') + '<div class="form-text">' + esc(L('acc.backup_max_age_hint')) + '</div></div>') + '<div class="col-md-6">' + field('pin', L('new.pin'), WZ.pin, ' data-w="pin" maxlength="128"') + '</div></div></details></div>';
			} else if (DEVAPI.indexOf(k.access) >= 0) {
				var ta = k.access, open = WZ.pin || WZ.ups || WZ.tls || WZ.api || WZ.session || WZ.metrics;
				html += '<div class="col-12">' + field('url', 'URL', WZ.url, ' data-w="url" maxlength="512" placeholder="' + esc(devURL(ta, WZ.address)) + '"') + '</div>' +
					(DEVSPEC[ta].user ? '<div class="col-md-6">' + field('duser', L('acc.user'), WZ.duser, ' data-w="duser" maxlength="32"') + '</div>' : '') +
					'<div class="col-md-6">' + field('dsec', L('acc.secret'), WZ.dsecret, ' data-w="dsecret" type="password" autocomplete="new-password"') + '</div>' +
					'<div class="col-12 small text-body-secondary"><i class="bi bi-info-circle"></i> ' + esc(devHint(ta)) + '<div class="mt-1">' + esc(devSecretHint(ta)) + '</div></div>' +
					'<div class="col-12"><details' + (open ? ' open' : '') + '><summary class="small text-body-secondary">' + esc(L('advanced')) + '</summary><div class="pt-2 row g-2">' +
					devFields(WZ, 'w', ta) + '<div class="col-md-6">' + field('pin', L('new.pin'), WZ.pin, ' data-w="pin" maxlength="128"') + '</div></div></details></div>';
			} else if (k.access === 'snmp') {
				html += '<div class="col-12 small text-body-secondary"><i class="bi bi-info-circle"></i> ' + esc(L('new.hint_snmp')) + '</div>' +
					snmpFields('w', function (x) { return WZ['s_' + x]; }, false);
			} else if (k.access === 'docker') {
				html += '<div class="col-12">' + field('url', 'URL', WZ.url, ' data-w="url" maxlength="512" placeholder="unix:///var/run/docker.sock"') + '<div class="form-text">' + esc(L('new.docker_hint')) + '</div></div>' +
					'<div class="col-12"><details' + (WZ.pin || WZ.docker_secret ? ' open' : '') + '><summary class="small text-body-secondary">' + esc(L('advanced')) + '</summary><div class="pt-2 row g-2"><div class="col-12">' + field('pin', L('new.pin'), WZ.pin, ' data-w="pin" maxlength="128"') + '</div>' +
					'<div class="col-12"><label class="form-label" for="m64-w-dsec">' + esc(L('acc.docker_secret')) + '</label><textarea class="form-control font-monospace small" id="m64-w-dsec" data-w="docker_secret" rows="4" spellcheck="false" autocomplete="off" placeholder="-----BEGIN …">' + esc(WZ.docker_secret) + '</textarea><div class="form-text">' + esc(L('acc.docker_secret_hint')) + '</div></div></div></details></div>';
			}
			if (!(k.access === 'agent' && WZ.mode === 'push')) html += '<div class="col-12"><button class="btn btn-outline-primary btn-sm" type="button" id="m64-w-test"><i class="bi bi-plug"></i> ' + esc(L('new.test')) + '</button> <span class="small ms-2" id="m64-w-res">' + (WZ.test ? testHTML(WZ.test) : '') + '</span></div></div>';
		} else if (WZ.step === 3) {
			var svcs = (WZ.test && WZ.test.services) || [];
			if (!svcs.length) {
				html = WZ.test && WZ.test.need_confirm ? '<p class="text-warning-emphasis"><i class="bi bi-shield-exclamation"></i> ' + esc(L('new.unconfirmed')) + '</p>' :
					'<p class="text-body-secondary"><i class="bi bi-info-circle"></i> ' + esc(L('new.no_test')) + '</p>';
			} else {
				var cats = {};
				svcs.forEach(function (s) { var c = catOfKind(s.kind); (cats[c] = cats[c] || []).push(s); });
				html = '<p class="text-body-secondary">' + esc(L('new.found', { n: svcs.length })) + '</p><div class="mb-2"><button class="btn btn-sm btn-link p-0 me-3" type="button" data-all="1">' + esc(L('new.all')) + '</button><button class="btn btn-sm btn-link p-0" type="button" data-all="0">' + esc(L('new.none')) + '</button></div>';
				(D.cat_order || []).forEach(function (c) {
					if (!cats[c]) { return; }
					html += '<div class="fw-semibold small mt-2">' + esc((D.cats || {})[c] || c) + '</div><div class="row g-1">' + cats[c].map(function (s) {
						var id = 'm64-wa-' + btoa(unescape(encodeURIComponent(s.key))).replace(/[^a-z0-9]/gi, '');
						return '<div class="col-md-6 col-xl-4"><div class="form-check"><input class="form-check-input" type="checkbox" data-adopt="' + esc(s.key) + '" id="' + id + '"' + (WZ.adopt[s.key] ? ' checked' : '') + '><label class="form-check-label small" for="' + id + '">' + esc(tx(s.name) || s.key) + '</label></div></div>';
					}).join('') + '</div>';
				});
			}
			var others = otherNodes();
			if (others.length) {
				html += '<div class="card mt-3"><div class="card-body py-2"><div class="fw-semibold small mb-1"><i class="bi bi-diagram-3"></i> ' + esc(L('new.cluster_nodes', { c: WZ.test.cluster || '' })) + '</div><div class="small text-body-secondary mb-2">' + esc(L('new.cluster_hint')) + '</div>' +
					others.map(function (n, i) { return '<div class="form-check"><input class="form-check-input" type="checkbox" data-wnode="' + esc(n.name) + '" id="m64-wn' + i + '"' + (WZ.nodes[n.name] ? ' checked' : '') + '><label class="form-check-label small" for="m64-wn' + i + '">' + esc(n.name) + (n.ip ? ' <span class="text-body-tertiary">' + esc(n.ip) + '</span>' : '') + (n.online ? '' : ' <span class="badge text-bg-secondary">' + esc(L('new.node_offline')) + '</span>') + '</label></div>'; }).join('') + '</div></div>';
			}
		} else {
			var groups = (D.targets && D.targets.groups) || [], extra = selectedNodes().length;
			html = '<div class="row g-3"><div class="col-md-6"><label class="form-label" for="m64-w-group">' + esc(L('f.group')) + '</label><input class="form-control" id="m64-w-group" data-w="group" list="m64-w-groups" maxlength="64" value="' + esc(WZ.group) + '"><datalist id="m64-w-groups">' + groups.map(function (g) { return '<option value="' + esc(g) + '">'; }).join('') + '</datalist></div>' +
				'<div class="col-md-6"><label class="form-label" for="m64-w-tags">' + esc(L('f.tags')) + '</label><input class="form-control" id="m64-w-tags" data-w="tags" value="' + esc(WZ.tags) + '"><div class="form-text">' + esc(L('new.tags_hint')) + '</div></div>' +
				'<div class="col-md-6"><label class="form-label" for="m64-w-iv">' + esc(L('f.interval')) + '</label><select class="form-select" id="m64-w-iv" data-w="interval">' + [30, 60, 120, 300, 600, 900].map(function (s) { return '<option value="' + s + '"' + (String(s) === String(WZ.interval) ? ' selected' : '') + '>' + esc(s < 60 ? L('iv.sec', { n: s }) : fmtDur(s)) + '</option>'; }).join('') + '</select></div>' +
				'<div class="col-12 small text-body-secondary">' + esc(L('new.summary', { n: WZ.name, a: WZ.address, k: kl(WZ.kind), s: Object.keys(WZ.adopt).filter(function (x) { return WZ.adopt[x]; }).length })) + (extra ? ' ' + esc(L('new.summary_nodes', { n: extra })) : '') + '</div>' + clusterStep() + '</div>';
		}
		$('#m64-wizard').innerHTML = html;
		var back = $('#m64-back');
		back.textContent = WZ.step > 1 ? L('back') : L('cancel');
		var next = $('#m64-next');
		next.textContent = WZ.step === 4 ? L('new.create') : L('new.next');
		next.disabled = WZ.step === 1 && !WZ.kind;
		var pw = $('#m64-w-pw');
		if (pw) { pw.onchange = function () { $('#m64-w-pass').classList.toggle('d-none', !pw.checked); }; }
		var addr = $('#m64-w-addr');
		if (addr && k && k.access === 'ssh') { addr.onchange = function () { collect(); nodeAddr(); }; }
		var us = $('#m64-w-user');
		if (us) { us.onchange = function () { collect(); render(); }; }
		var md = $('#m64-w-mode');
		if (md) { md.onchange = function () { collect(); if (WZ.mode === 'push' && !WZ.token) { pushTok(); } render(); }; }
		var pn = $('#m64-w-pnode');
		if (pn) { pn.onchange = function () { collect(); render(); }; }
		agentSrcBind(function () { collect(); render(); }); // Quelle der Agent-Dateien geaendert: Befehl neu
		var t = $('#m64-w-test');
		if (t) { t.onclick = function () { lock(t, testConn); }; }
		snmpShow($('#m64-wizard'), 'w');
		$$('#m64-w-sversion, #m64-w-slevel').forEach(function (x) { x.onchange = function () { snmpShow($('#m64-wizard'), 'w'); }; });
	}
	// pushTok holt einen Token fuer den Installationsbefehl (wird mit dem Zugang gespeichert).
	function pushTok() {
		// collect vor render: was inzwischen eingetippt wurde, bliebe sonst nicht stehen
		api('GET', '/api/monitor64/push/token').then(function (r) { collect(); WZ.token = r.token; WZ.pushPort = r.port; render(); }).catch(fail);
	}
	function selectedNodes() { return otherNodes().filter(function (n) { return WZ.nodes[n.name]; }); }
	// clusterStep: letzter Schritt, Abschnitt "Ueberwachung im Cluster" (zugeklappt, solange nichts gewaehlt ist).
	function clBackList() { var pref = WZ.clPref || CLW.self; return (CLW.nodes || []).filter(function (n) { return WZ.clBack[n.id] && n.id !== pref; }).map(function (n) { return n.id; }); }
	function clusterStep() {
		if (!CLW) { return ''; }
		var pref = WZ.clPref || CLW.self, open = pref !== CLW.self || clBackList().length;
		return '<div class="col-12"><details' + (open ? ' open' : '') + '><summary class="small text-body-secondary"><i class="bi bi-diagram-3"></i> ' + esc(L('cluster.wiz_title')) + '</summary><div class="pt-2 row g-2">' +
			'<div class="col-md-6"><label class="form-label" for="m64-w-clpref">' + esc(L('cluster.preferred')) + '</label><select class="form-select" id="m64-w-clpref" data-w="clPref">' + (CLW.nodes || []).map(function (n) {
				return '<option value="' + esc(n.id) + '"' + (n.id === pref ? ' selected' : '') + '>' + esc(n.name + (n.self ? ' (' + L('cluster.this_node') + ')' : '') + (n.online ? '' : ' – ' + L('cluster.offline'))) + '</option>';
			}).join('') + '</select></div>' +
			'<div class="col-md-6"><div class="form-label">' + esc(L('cluster.backups')) + '</div>' + (CLW.nodes || []).filter(function (n) { return n.id !== pref; }).map(function (n, i) {
				return '<div class="form-check"><input class="form-check-input" type="checkbox" id="m64-w-clb' + i + '" data-wcl="' + esc(n.id) + '"' + (WZ.clBack[n.id] ? ' checked' : '') + '><label class="form-check-label small" for="m64-w-clb' + i + '">' + esc(n.name) + (n.online ? '' : ' <span class="badge text-bg-secondary">' + esc(L('cluster.offline')) + '</span>') + '</label></div>';
			}).join('') + '</div>' +
			'<div class="col-12 small text-body-secondary">' + esc(L('cluster.wiz_hint')) + '</div></div></details></div>';
	}
	// clApply: Wahl im Cluster nach dem Anlegen setzen (nur wenn vom Standard abweichend; Fehler nur melden).
	function clApply(hostUID) {
		if (!CLW || !hostUID) { return Promise.resolve(); }
		var pref = WZ.clPref || CLW.self, back = clBackList();
		if (pref === CLW.self && !back.length) { return Promise.resolve(); }
		return api('PUT', '/api/monitor64/cluster/hosts/' + encodeURIComponent(hostUID), { preferred_node: pref, backup_nodes: back }).catch(function () { clFailed = true; });
	}
	function catOfKind(k) { var m = { cpu: 'system', load: 'system', mem: 'system', swap: 'system', temp: 'system', systemd: 'system', updates: 'system', reboot: 'system', cluster: 'system', ha: 'system', ceph: 'system', alerts: 'system', system: 'system', uptime: 'system', traps: 'system', ups: 'devices', fan: 'devices', psu: 'devices', power: 'devices', printer: 'devices', supply: 'devices', tray: 'devices', hw: 'devices', ctrl: 'storage', fs: 'fs', zfs: 'storage', btrfs: 'storage', raid: 'storage', store: 'storage', ds: 'storage', disk: 'disks', 'if': 'network', bond: 'network', poe: 'network', wlan: 'network', wan: 'network', dsl: 'network', vm: 'guests', ct: 'guests', backup: 'guests', job: 'guests', ctr: 'docker', winsvc: 'winsvc', local: 'local', mailq: 'mail', mail: 'mail', quarantine: 'mail' }; return m[k] || 'other'; }
	function nodeAddr() {
		if (!WZ.address) { return; }
		api('GET', '/api/monitor64/nodeaddr?target=' + encodeURIComponent(WZ.address)).then(function (r) { if ((r.addr || '') !== WZ.nodeAddr || !!r.bridge !== !!WZ.nodeBridge) { collect(); WZ.nodeAddr = r.addr || ''; WZ.nodeBridge = !!r.bridge; render(); } }).catch(failQuiet);
	}
	function testConn() {
		collect();
		if (!WZ.address) { toast(L('new.need_address'), true); return null; }
		var res = $('#m64-w-res'), acc;
		try { acc = access(); } catch (e) { res.innerHTML = '<span class="text-danger">' + esc(e.message) + '</span>'; return null; } // z. B. eigene Metriken kein JSON
		res.innerHTML = '<span class="spinner-border spinner-border-sm"></span> ' + esc(L('new.testing'));
		return api('POST', '/api/monitor64/test', { address: WZ.address, access: acc }).then(function (r) {
			WZ.test = r;
			WZ.adopt = {};
			WZ.nodes = {};
			(r.services || []).forEach(function (s) { WZ.adopt[s.key] = !!s['default']; });
			var cur = $('#m64-w-res');
			if (cur) { cur.innerHTML = testHTML(r); }
		}).catch(function (e) { var cur = $('#m64-w-res'); if (cur) { cur.innerHTML = '<span class="text-danger">' + esc(tx(e.message)) + '</span>'; } });
	}
	$('#m64-wizard').addEventListener('click', function (ev) {
		var t = ev.target.closest('[data-kind]');
		if (t && !t.classList.contains('disabled')) { WZ.kind = t.dataset.kind; WZ.test = null; WZ.hostkey = ''; render(); return; }
		var fp = ev.target.closest('[data-fp-confirm]');
		if (fp) { // Fingerabdruck bestaetigt: als Pin (API) bzw. Hostschluessel (SSH mit Passwort) uebernehmen und erneut testen
			collect();
			if (kind() && kind().access === 'ssh') { WZ.hostkey = fp.dataset.fpConfirm; } else { WZ.pin = fp.dataset.fpConfirm; }
			WZ.test = null;
			render();
			var tb = $('#m64-w-test');
			lock(tb, testConn);
			return;
		}
		var a = ev.target.closest('[data-all]');
		if (a) { $$('[data-adopt]').forEach(function (c) { c.checked = a.dataset.all === '1'; WZ.adopt[c.dataset.adopt] = c.checked; }); }
	});
	$('#m64-wizard').addEventListener('change', function (ev) {
		if (ev.target.dataset.adopt !== undefined) { WZ.adopt[ev.target.dataset.adopt] = ev.target.checked; }
		if (ev.target.dataset.wnode !== undefined) { WZ.nodes[ev.target.dataset.wnode] = ev.target.checked; }
		if (ev.target.dataset.wcl !== undefined) { WZ.clBack[ev.target.dataset.wcl] = ev.target.checked; }
		if (ev.target.id === 'm64-w-clpref') { collect(); render(); }
	});
	// Adresse, Port oder Zugangsdaten geaendert: altes Testergebnis (Dienste, Fingerabdruck) verwerfen
	$('#m64-wizard').addEventListener('input', function (ev) {
		var w = ev.target.dataset && ev.target.dataset.w;
		if (WZ.step !== 2 || !w || CONN.indexOf(w) < 0) { return; }
		WZ.hostkey = ''; // ein bestaetigter Hostschluessel gilt nur fuer genau dieses Ziel
		if (!WZ.test) { return; }
		WZ.test = null;
		WZ.adopt = {};
		WZ.nodes = {};
		var res = $('#m64-w-res');
		if (res) { res.innerHTML = '<span class="text-body-secondary">' + esc(L('new.test_stale')) + '</span>'; }
	});
	$('#m64-wizard').addEventListener('keydown', function (ev) { if ((ev.key === 'Enter' || ev.key === ' ') && ev.target.dataset.kind) { ev.preventDefault(); ev.target.click(); } });
	$('#m64-back').addEventListener('click', function (ev) { if (WZ.step > 1) { ev.preventDefault(); collect(); WZ.step--; render(); } });
	$('#m64-next').onclick = function () {
		collect();
		if (WZ.step === 2) {
			if (!WZ.name || !WZ.address) { toast(L('new.need_name'), true); return; }
		}
		if (WZ.step < 4) { WZ.step++; render(); if (WZ.step === 2 && kind() && kind().access === 'ssh') { nodeAddr(); } return; }
		var acc, nodes = selectedNodes();
		try { acc = access(); } catch (e) { toast(e.message, true); return; }
		// Fingerabdruck aus dem Test nur, wenn er dort schon galt (Anmeldung gelungen). Wartet er noch auf die Bestaetigung
		// (SSH mit Passwort), kommt nur der bestaetigte aus access() mit - sonst ginge das Passwort an einen ungeprueften Host.
		if (WZ.test && WZ.test.fingerprint && !WZ.test.need_confirm && (acc.type === 'agent' || acc.type === 'ssh')) { acc.hostkey = WZ.test.fingerprint; }
		if (acc.type === 'pve' && nodes.length && !acc.config.node && WZ.test.node) { acc.config.node = WZ.test.node; } // weitere Nodes bekommen eigene Hosts
		var tags = WZ.tags.split(/[,\s]+/).filter(Boolean), iv = parseInt(WZ.interval, 10) || 0;
		var body = { name: WZ.name, address: WZ.address, kind: WZ.kind, group: WZ.group, tags: tags, interval_sec: iv, notes: '', paused: false,
			agent_autoupdate: true, accesses: [acc], services: (WZ.test && WZ.test.services) || [], adopt: Object.keys(WZ.adopt).filter(function (x) { return WZ.adopt[x]; }) };
		var next = $('#m64-next');
		lock(next, function () {
			return api('POST', '/api/monitor64/hosts', body).then(function (r) {
				// je weitere Cluster-Node ein Host mit gleichem Token und Pin, Abfrage ueber dieselbe Adresse (Node gesetzt)
				var chain = clApply(r.uid), failed = [];
				nodes.forEach(function (n) {
					var na = { type: 'pve', config: { url: acc.config.url || ('https://' + urlHost(WZ.address) + ':8006'), token_id: acc.config.token_id, pin: acc.config.pin, node: n.name }, secret: acc.secret };
					var addr = n.ip || n.name;
					chain = chain.then(function () {
						// Dienste der Node erkennen und die vorgeschlagenen gleich uebernehmen (wie beim ersten Host im
						// Assistenten); scheitert der Test, entsteht der Host ohne Dienste (Erkennung in der Runde)
						return api('POST', '/api/monitor64/test', { address: addr, access: na }).catch(function () { return {}; }).then(function (t) {
							var svcs = (t && t.ok && t.services) || [];
							return api('POST', '/api/monitor64/hosts', { name: n.name, address: addr, kind: 'pve', group: WZ.group, tags: tags, interval_sec: iv, notes: '', paused: false, agent_autoupdate: true, accesses: [na],
								services: svcs, adopt: svcs.filter(function (x) { return x['default']; }).map(function (x) { return x.key; }) }).then(function (r2) { return clApply(r2.uid); });
						}).catch(function () { failed.push(n.name); });
					});
				});
				return chain.then(function () {
					var msg = [];
					if (failed.length) { msg.push(L('new.nodes_failed', { n: failed.join(', ') })); }
					if (clFailed) { msg.push(L('cluster.wiz_failed')); }
					if (msg.length) { toast(msg.join(' '), true); }
					setTimeout(function () { location.href = '/monitor64/host/' + encodeURIComponent(r.uid); }, failed.length || clFailed ? 2500 : 0);
				});
			});
		}).catch(fail);
	};
	render();
}

// ---------- Agent ----------
// Quelle der Agent-Dateien fuer die Installationsbefehle: Internet (ipv64.net) oder diese Node (Hosts ohne Internet;
// die Node liefert unter /monitor64/agent/ nur Dateien aus, deren Signatur sie geprueft hat). Die Wahl gilt fuer die
// Seite Agent und den Assistenten und wird im Browser gemerkt.
var AG = D.agent || {}, agentSrcMem = null;
function agentSrc() {
	if (agentSrcMem) { return agentSrcMem; }
	var s = { mode: 'net', node: '' };
	try { s.mode = localStorage.getItem('m64-agent-src') === 'node' ? 'node' : 'net'; s.node = localStorage.getItem('m64-agent-node') || ''; } catch (e) { s.mode = 'net'; }
	if (!s.node) { s.node = location.origin; }
	return s;
}
// agentNodeURL: Adresse der Node fuer den Befehl (nur Schema, Host und Port; sonst die Adresse dieser Seite).
function agentNodeURL(v) {
	v = String(v || '').trim().replace(/\/+$/, '');
	if (v && !/^https?:\/\//i.test(v)) { v = 'http://' + v; }
	return /^https?:\/\/[0-9A-Za-z.\-_:\[\]%]+$/i.test(v) ? v : location.origin;
}
function agentBase(s) { return s.mode === 'node' ? agentNodeURL(s.node) + '/monitor64/agent/' : (AG.internet || 'https://ipv64.net/node64/agent/'); }
function agentHost(u) { var m = /^https?:\/\/([^\/]+)/i.exec(u || ''); return m ? m[1] : (u || ''); }
// agentCmd: Installationsbefehl je System (linux, windows, freebsd). base = Ordner mit den Dateien (Schraegstrich am
// Ende), push = token@node:port im Push-Betrieb. Skript und Dateien kommen immer aus demselben Ordner (--base).
function agentCmd(os, base, key, push) {
	if (os === 'windows') {
		// TLS 1.2 einschalten, bevor irm laedt (Server 2016 bietet sonst nur TLS 1.0/1.1 an)
		return '[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12; ' +
			'& ([scriptblock]::Create((irm ' + base + 'install.ps1))) -Base "' + base + '" -Key "' + key + '"' + (push ? ' -Connect "' + push + '" -NoListen' : '');
	}
	var opts = ' \\\n  --base ' + base + ' \\\n  --key "' + key + '"' + (push ? ' \\\n  --connect \'' + push + '\' --no-listen' : '');
	if (os === 'freebsd') { return 'fetch -o /tmp/install.sh ' + base + 'install.sh && sh /tmp/install.sh' + opts; }
	return 'curl -fsSL ' + base + 'install.sh | sudo sh -s --' + opts;
}
// agentSrcHTML: Auswahl der Quelle mit Hinweis, was der Weg schuetzt und was nicht.
function agentSrcHTML(s) {
	var node = s.mode === 'node', base = agentBase(s), warn = false, hint;
	if (!node) {
		hint = L('agent.hint_net', { h: agentHost(base) });
	} else if (/^http:/i.test(base)) {
		hint = L('agent.hint_node_http');
		warn = true;
	} else {
		hint = AG.http_port ? L('agent.hint_node_https', { u: 'http://' + location.hostname + ':' + AG.http_port }) : L('agent.hint_node_https_only');
	}
	return '<div class="row g-2 mt-1"><div class="col-sm-5"><label class="form-label small mb-1" for="m64-ag-srcmode">' + esc(L('agent.src_label')) + '</label><select class="form-select form-select-sm" id="m64-ag-srcmode">' +
		'<option value="net"' + (node ? '' : ' selected') + '>' + esc(L('agent.src_net', { h: agentHost(AG.internet || 'ipv64.net') })) + '</option><option value="node"' + (node ? ' selected' : '') + '>' + esc(L('agent.src_node')) + '</option></select></div>' +
		(node ? '<div class="col-sm-7"><label class="form-label small mb-1" for="m64-ag-srcnode">' + esc(L('agent.node_addr')) + '</label><input class="form-control form-control-sm" id="m64-ag-srcnode" maxlength="253" spellcheck="false" autocomplete="off" value="' + esc(agentNodeURL(s.node)) + '"></div>' : '') + '</div>' +
		'<div class="small mt-1 ' + (warn ? 'text-warning-emphasis' : 'text-body-secondary') + '" id="m64-ag-srchint"><i class="bi ' + (warn ? 'bi-exclamation-triangle' : 'bi-info-circle') + '"></i> ' + esc(hint) + '</div>';
}
// agentSrcBind: Aenderung der Auswahl merken und cb aufrufen (zeichnet Befehl und Auswahl neu).
function agentSrcBind(cb) {
	var md = $('#m64-ag-srcmode'), nd = $('#m64-ag-srcnode');
	function save() {
		var cur = agentSrc();
		agentSrcMem = { mode: md.value === 'node' ? 'node' : 'net', node: nd ? agentNodeURL(nd.value) : cur.node };
		try { localStorage.setItem('m64-agent-src', agentSrcMem.mode); localStorage.setItem('m64-agent-node', agentSrcMem.node); } catch (e) { /* ohne Speicher gilt die Wahl nur fuer diese Ansicht */ }
		cb();
	}
	if (md) { md.onchange = save; }
	if (nd) { nd.onchange = save; }
}
// agentAccLine: Version und Update-Stand des Agents an seinem Zugang (Host-Seite).
function agentAccLine(g) {
	if (!g || (!g.version && !g.error && !g.busy)) { return ''; }
	var t = g.version ? L('agent.acc_version', { v: g.version }) : L('agent.title');
	if (g.busy) { t += ' · ' + L('agent.st_busy'); } else if (g.state === 'pending') { t += ' · ' + L('agent.st_pending', { l: g.latest || '' }); } else if (g.state === 'current') { t += ' · ' + L('agent.st_current'); }
	return '<div class="small text-body-secondary" data-acc-agent><a class="text-reset" href="/monitor64/agent">' + esc(t) + '</a></div>' +
		(g.error ? '<div class="small text-danger-emphasis">' + esc(L('agent.failed', { t: fmtTime(g.tried), e: tx(g.error) })) + '</div>' : '');
}
// Seite Agent: verfuegbare Version und Downloads von der Node, Installationsbefehl, Hosts mit ihrer Agent-Version.
function pageAgent() {
	var A = AG, osSel = $('#m64-ag-os'), refreshBtn = $('#m64-ag-refresh');
	try { var os = localStorage.getItem('m64-agent-os'); if (os && osSel && /^(linux|windows|freebsd)$/.test(os)) { osSel.value = os; } } catch (e) { /* Standard: Linux */ }
	function renderInstall() {
		var src = agentSrc();
		$('#m64-ag-cmd').textContent = agentCmd(osSel.value, agentBase(src), A.public_key || L('new.no_key'), '');
		$('#m64-ag-src').innerHTML = agentSrcHTML(src);
		agentSrcBind(renderInstall);
	}
	function renderSource() {
		var s = A.source || {}, html;
		if (!A.running) { setHTML($('#m64-ag-source'), '<span class="text-body-secondary">' + esc(L('not_running')) + '</span>'); return; }
		html = A.version ? '<div class="fs-5 fw-semibold">' + esc(L('agent.version', { v: A.version })) + '</div>' + (toDate(A.date) ? '<div class="text-body-secondary">' + esc(L('agent.released', { d: fmtDay(toDate(A.date), true) })) + '</div>' : '') :
			'<div class="text-body-secondary"><i class="bi bi-info-circle"></i> ' + esc(L('agent.none')) + '</div>';
		html += '<div class="text-body-secondary mt-2">' + esc(toDate(s.ok) ? L('agent.src_ok', { t: fmtTime(s.ok), s: agentHost(s.source) }) : A.version ? L('agent.src_stored') : L('agent.src_never')) + '</div>';
		if (s.error) { html += '<div class="text-danger-emphasis mt-1"><i class="bi bi-exclamation-triangle"></i> ' + esc(L('agent.src_err', { t: fmtTime(s.checked), e: s.error })) + '</div>'; }
		html += '<div class="text-body-secondary mt-1">' + esc(L('agent.src_from', { s: (s.bases || []).map(agentHost).join(', ') })) + '</div>';
		setHTML($('#m64-ag-source'), html);
	}
	function fileRow(f, cached) {
		return '<tr><td><a href="/monitor64/agent/' + encodeURIComponent(f.name) + '" download>' + esc(f.name) + '</a>' + (cached ? ' <i class="bi bi-check-circle text-success" title="' + esc(L('agent.cached')) + '"></i>' : '') + '</td>' +
			'<td class="text-end text-nowrap">' + esc(fmtBytes(f.size)) + '</td><td class="d-none d-sm-table-cell"><code title="' + esc(f.sha256 || '') + '">' + esc(String(f.sha256 || '').slice(0, 12)) + '…</code></td></tr>';
	}
	function renderFiles() {
		var rows = (A.files || []).map(function (f) { return fileRow(f, f.cached); }).concat((A.scripts || []).map(function (f) { return fileRow(f, false); }));
		if (rows.length) { rows.push('<tr><td colspan="3"><a href="/monitor64/agent/SHA256SUMS">SHA256SUMS</a> <span class="text-body-secondary">· ' + esc(L('agent.files_hint')) + '</span></td></tr>'); }
		setHTML($('#m64-ag-files'), rows.join('') || '<tr><td colspan="3" class="text-body-secondary">' + esc(L('agent.none')) + '</td></tr>');
	}
	function stateHTML(h) {
		var html;
		if (h.busy) { html = '<span class="spinner-border spinner-border-sm"></span> ' + esc(L('agent.st_busy')); }
		else if (h.state === 'current') { html = stBadge('ok', L('agent.st_current')); }
		else if (h.state === 'pending') { html = stBadge('warn', L('agent.st_pending', { l: h.latest || '' })) + (toDate(h.next) && toDate(h.next) > new Date() ? ' <span class="small text-body-secondary">' + esc(L('agent.next_try', { t: fmtTime(h.next) })) + '</span>' : ''); }
		else if (h.state === 'nofile') { html = stBadge('unknown', L('agent.st_nofile', { p: h.platform || '' })); }
		else if (h.state === 'elsewhere') { html = '<span class="small text-body-secondary"><i class="bi bi-diagram-3"></i> ' + esc(L('agent.st_elsewhere', { n: h.node || '' })) + '</span>'; }
		else if (h.state === 'off') { html = '<span class="small text-body-secondary">' + esc(L('host.acc_off')) + '</span>'; }
		else { html = stBadge('unknown', L('agent.st_unknown')); }
		return html + (h.error && !h.busy ? '<div class="small text-danger-emphasis mt-1">' + esc(L('agent.failed', { t: fmtTime(h.tried), e: tx(h.error) })) + '</div>' : '');
	}
	function renderHosts() {
		var rows = (A.hosts || []).map(function (h) {
			var can = !h.busy && A.version && (h.state === 'pending' || h.state === 'unknown');
			return '<tr data-ag-host="' + esc(h.uid) + '"><td><a href="/monitor64/host/' + encodeURIComponent(h.uid) + '">' + esc(h.name) + '</a>' + (h.push ? ' <span class="badge text-bg-light">Push</span>' : '') + '</td>' +
				'<td class="text-nowrap">' + esc(h.version || '–') + (h.platform ? ' <span class="small text-body-tertiary">' + esc(h.platform) + '</span>' : '') + '</td><td>' + stateHTML(h) + '</td>' +
				'<td><div class="form-check form-switch mb-0"><input class="form-check-input" type="checkbox" data-ag-auto' + (h.auto ? ' checked' : '') + ' aria-label="' + esc(L('f.autoupdate')) + '" title="' + esc(L('f.autoupdate')) + '"></div></td>' +
				'<td class="text-end">' + (can ? '<button class="btn btn-sm btn-outline-primary text-nowrap" type="button" data-ag-update><i class="bi bi-arrow-up-circle"></i> ' + esc(L('agent.update_now')) + '</button>' : '') + '</td></tr>';
		});
		setHTML($('#m64-ag-hosts'), rows.join('') || '<tr><td colspan="5" class="small text-body-secondary">' + esc(L('agent.no_hosts')) + '</td></tr>');
	}
	function renderEvents() {
		var rows = (A.events || []).map(function (e) {
			return '<div class="d-flex align-items-center gap-2 px-3 py-2 border-top small"><i class="bi bi-arrow-up-circle text-success"></i><div class="me-auto"><span class="fw-semibold">' + esc(e.host || '–') + '</span> · ' + esc(tx(e.text || '')) +
				' <span class="text-body-secondary">(' + esc(whoTxt(e.actor)) + ')</span></div><span class="text-body-secondary text-nowrap">' + esc(fmtTime(e.at)) + '</span></div>';
		});
		setHTML($('#m64-ag-events'), rows.join('') || '<div class="p-3 small text-body-secondary">' + esc(L('agent.no_events')) + '</div>');
	}
	function render() {
		renderSource();
		renderFiles();
		renderHosts();
		renderEvents();
		var fp = $('#m64-ag-fp');
		if (fp) { fp.textContent = A.fingerprint || ''; }
	}
	function take(r) { A = r; AG = r; render(); }
	function load() { return api('GET', '/api/monitor64/agent').then(take); }
	function refresh() { return lock(refreshBtn, function () { return api('POST', '/api/monitor64/agent/refresh').then(take); }); }
	if (osSel) { osSel.onchange = function () { try { localStorage.setItem('m64-agent-os', osSel.value); } catch (e) { /* nur diese Ansicht */ } renderInstall(); }; }
	if (refreshBtn) { refreshBtn.onclick = function () { refresh().then(function () { toast((A.source || {}).error ? L('agent.refresh_failed') : L('agent.refresh_ok'), !!(A.source || {}).error); }).catch(fail); }; }
	root.addEventListener('click', function (ev) {
		var b = ev.target.closest('[data-ag-update]');
		if (!b) { return; }
		var uid = b.closest('[data-ag-host]').dataset.agHost;
		lock(b, function () {
			return api('POST', '/api/monitor64/hosts/' + encodeURIComponent(uid) + '/agent/update').then(function () { toast(L('agent.update_started')); return load(); });
		}).catch(fail);
	});
	root.addEventListener('change', function (ev) {
		if (!ev.target.matches || !ev.target.matches('[data-ag-auto]')) { return; }
		var uid = ev.target.closest('[data-ag-host]').dataset.agHost, on = ev.target.checked;
		api('PUT', '/api/monitor64/hosts/' + encodeURIComponent(uid) + '/agent', { autoupdate: on }).then(function () { toast(on ? L('agent.auto_on') : L('agent.auto_off')); return load(); }).catch(function (e) { ev.target.checked = !on; fail(e); });
	});
	renderInstall();
	render();
	if (A.running && A.due) { refresh().catch(failQuiet); } // erster Aufruf bzw. Stand aelter als 6 h: Verzeichnis holen
	setInterval(function () { if (!document.hidden && A.running) { load().catch(failQuiet); } }, 5000);
}

var PAGES = { overview: pageOverview, host: pageHost, problems: pageProblems, maint: pageMaint, rules: pageRules, notify: pageNotify, settings: pageSettings, 'new': pageNew, agent: pageAgent };
var fn = PAGES[root.dataset.m64Page];
if (fn) { fn(); }
})();
