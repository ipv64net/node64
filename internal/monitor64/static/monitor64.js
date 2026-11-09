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
function L(k, a) {
	var s = TX[k] || k;
	if (a) { Object.keys(a).forEach(function (n) { s = s.split('{' + n + '}').join(a[n]); }); }
	return s;
}
function esc(s) {
	return String(s === undefined || s === null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; });
}
function $(sel, ctx) { return (ctx || document).querySelector(sel); }
function $$(sel, ctx) { return Array.prototype.slice.call((ctx || document).querySelectorAll(sel)); }
var LOC = D.lang === 'de' ? 'de-DE' : (D.lang || undefined);
function fmtNum(v, d) {
	if (v === null || v === undefined || isNaN(v)) { return '–'; }
	if (d === undefined) { d = Math.abs(v) < 10 && v % 1 !== 0 ? (Math.abs(v) < 0.1 ? 3 : 1) : 0; }
	return Number(v).toLocaleString(LOC, { minimumFractionDigits: 0, maximumFractionDigits: d });
}
function parseNum(s) {
	s = String(s || '').trim();
	if (s === '') { return null; }
	if (LOC === 'de-DE') { s = s.replace(/\./g, '').replace(',', '.'); } else { s = s.replace(/,/g, ''); }
	var v = parseFloat(s);
	return isNaN(v) ? NaN : v;
}
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
	return pad(d.getDate()) + '.' + pad(d.getMonth() + 1) + '.' + (d.getFullYear() !== now.getFullYear() ? String(d.getFullYear()).slice(2) : '') + ' ' + hm;
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
var RANK = { crit: 4, unreachable: 4, unknown: 2, warn: 1, ok: 0 };
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
			if (!r.ok) { var e = new Error(j.message || j.error || ('HTTP ' + r.status)); e.code = j.error; throw e; }
			return j;
		});
	});
}
function fail(e) { toast(e && e.message ? e.message : String(e), true); }

// modal: Dialog mit eigenem Inhalt; buttons = [{label, cls, click(close)}].
var modalEl = document.getElementById('m64-modal');
function modal(title, body, buttons, wide) {
	if (!modalEl || !window.bootstrap) { return null; }
	$('#m64-modal-title').textContent = title;
	$('#m64-modal-body').innerHTML = body;
	$('.modal-dialog', modalEl).classList.toggle('modal-lg', !!wide);
	var foot = $('#m64-modal-foot');
	foot.innerHTML = '';
	var inst = window.bootstrap.Modal.getOrCreateInstance(modalEl);
	(buttons || []).forEach(function (b) {
		var btn = document.createElement('button');
		btn.type = 'button';
		btn.className = 'btn ' + (b.cls || 'btn-outline-secondary');
		btn.textContent = b.label;
		btn.onclick = function () { if (b.click) { b.click(function () { inst.hide(); }, btn); } else { inst.hide(); } };
		foot.appendChild(btn);
	});
	inst.show();
	return $('#m64-modal-body');
}
function confirmBox(title, text, okLabel, cb) {
	modal(title, '<p class="mb-0">' + esc(text) + '</p>', [{ label: L('cancel') }, { label: okLabel, cls: 'btn-danger', click: function (close) { close(); cb(); } }]);
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
	var OV = { group: store('group') || '', only: store('only') === '1', q: '', view: store('view') || 'tiles' };
	var data = D.overview || { hosts: [], problems: [], recent: [], counts: {}, groups: [] };
	var sparks = {};
	function statCard(cls, label, val, sub, icon) {
		return '<div class="col-6 col-md-3"><div class="card stat ' + cls + '"><div class="card-body"><div class="stat-text"><div class="stat-label">' + esc(label) + '</div><div class="stat-value">' + esc(String(val)) + '</div><div class="stat-sub">' + esc(sub) + '</div></div><i class="bi ' + icon + ' stat-icon"></i></div></div></div>';
	}
	function meter(m) {
		var cls = m.state === 'crit' ? 'crit' : m.state === 'warn' ? 'warn' : '';
		return '<div class="meter"><span class="meter-label">' + esc(m.label === 'cpu' ? L('ov.m_cpu') : m.label === 'ram' ? L('ov.m_ram') : L('ov.m_disk')) + '</span><div class="bar"><span class="' + cls + '" style="width:' + Math.max(0, Math.min(100, m.value)) + '%"></span></div><span class="meter-val">' + fmtNum(m.value, 0) + ' %</span></div>';
	}
	function hostState(h) { return h.view === 'unreachable' ? 'unknown' : h.state; }
	function tile(h) {
		var st = hostState(h), foot;
		if (h.maint) { foot = '<span class="st-badge maint"><i class="bi bi-cone-striped"></i> ' + esc(L('ov.maint')) + '</span>'; }
		else if (h.paused) { foot = '<span class="st-badge unknown"><i class="bi bi-pause-circle"></i> ' + esc(L('ov.paused')) + '</span>'; }
		else if (h.view === 'unreachable') { foot = stBadge('unknown', L('state.unreachable')); }
		else if (h.problems) { foot = stBadge(st, h.problems === 1 ? L('ov.problem_one') : L('ov.problem_n', { n: h.problems })); }
		else if (!h.checked) { foot = '<span class="small text-body-secondary">' + esc(L('ov.waiting')) + '</span>'; }
		else { foot = '<span class="small text-body-secondary">' + esc(L('ov.services_ok', { n: h.services })) + '</span>'; }
		var body = '';
		if (h.view === 'unreachable') { body = '<div class="small text-body-secondary mt-2"><i class="bi bi-plug"></i> ' + esc(h.unreach || L('state.unreachable')) + '</div>'; }
		else {
			body = (h.meters || []).map(meter).join('');
			if (!body && h.text) { body = '<div class="small text-body-secondary mt-2 text-truncate">' + esc(h.text) + '</div>'; }
			if (sparks[h.uid]) { body += '<div class="mt-2">' + spark(sparks[h.uid], st === 'ok' ? '' : 's-' + st) + '</div>'; }
		}
		var extra = '';
		if (h.new) { extra += ' <span class="badge text-bg-primary" title="' + esc(L('ov.new_services', { n: h.new })) + '">' + esc(L('ov.new_short', { n: h.new })) + '</span>'; }
		return '<div class="col-12 col-sm-6 col-xl-4 col-xxl-3"><div class="card host-tile s-' + esc(st) + (h.maint ? ' s-maint' : '') + (h.paused ? ' s-paused' : '') + '" data-host="' + esc(h.uid) + '" role="link" tabindex="0"><div class="card-body">' +
			'<div class="d-flex align-items-center gap-2"><i class="bi ' + esc(h.icon) + ' text-body-secondary"></i><span class="host-name">' + esc(h.name) + '</span>' + extra + '<span class="ms-auto">' + foot + '</span></div>' +
			'<div class="host-kind">' + esc(((D.host_kind_labels || {})[h.kind] || [h.kind])[0] || '') + (h.address ? ' · ' + esc(h.address) : '') + '</div>' +
			'<div class="mt-1">' + (h.tags || []).map(tag).join('') + '</div>' + body + '</div></div></div>';
	}
	function row(h) {
		var st = hostState(h);
		return '<tr data-host="' + esc(h.uid) + '" class="clickable"><td><span class="st-dot st-' + esc(st) + '"></span></td><td class="fw-semibold">' + esc(h.name) + '<div class="small text-body-secondary fw-normal">' + esc(((D.host_kind_labels || {})[h.kind] || [h.kind])[0] || '') + '</div></td>' +
			'<td class="d-none d-md-table-cell small">' + esc(h.address) + '</td><td class="d-none d-lg-table-cell">' + (h.tags || []).map(tag).join('') + '</td>' +
			'<td class="svc-val">' + (h.has_cpu ? fmtNum(h.cpu, 0) + ' %' : '–') + '</td><td class="svc-val">' + (h.has_ram ? fmtNum(h.ram, 0) + ' %' : '–') + '</td>' +
			'<td>' + (h.problems ? stBadge(st, String(h.problems)) : '<span class="text-body-secondary small">–</span>') + '</td></tr>';
	}
	function probRow(p) {
		var title = p.unreach ? L('ov.unreachable') : p.name;
		var icon = p.maint ? '<i class="bi bi-cone-striped text-body-secondary" title="' + esc(L('ov.maint')) + '"></i>' : '<span class="st-dot ' + (p.acked ? 'st-ack' : 'st-' + esc(p.state === 'unreachable' ? 'unknown' : p.state)) + '" title="' + esc(stLabel(p.state)) + '"></span>';
		return '<div class="prob-row' + (p.acked ? ' acked' : '') + '" data-host="' + esc(p.host_uid) + '" data-key="' + esc(p.key) + '" role="link" tabindex="0">' + icon +
			'<div class="prob-main"><div class="prob-title">' + esc(p.host) + ' · ' + esc(title) + '</div><div class="prob-sub">' + esc(p.detail || '') + '</div></div>' +
			'<span class="prob-since d-none d-sm-inline">' + (p.acked ? '<i class="bi bi-check2"></i> ' + esc(L('ov.acked')) : esc(since(p.since))) + '</span>' +
			'<button class="btn btn-sm btn-outline-secondary" type="button" data-ack="' + (p.acked ? 'unack' : 'ack') + '" title="' + esc(p.acked ? L('ov.unack') : L('ov.ack_hint')) + '" aria-label="' + esc(p.acked ? L('ov.unack') : L('ov.ack')) + '"><i class="bi ' + (p.acked ? 'bi-arrow-counterclockwise' : 'bi-check2') + '"></i></button></div>';
	}
	function recentRow(r) {
		var icon = 'bi-arrow-repeat text-success', t = '', sub = '';
		var name = (r.host || '') + (r.name ? ' · ' + r.name : '');
		switch (r.kind) {
		case 'ok': t = L('ov.r_ok', { n: name }); sub = L('ov.r_ok_sub'); break;
		case 'resolved': icon = 'bi-person-check text-primary'; t = L('ov.r_resolved', { n: name }); sub = L('ov.r_by', { w: whoTxt(r.by) }) + (r.text ? ' – „' + r.text + '“' : ''); break;
		case 'maint': icon = 'bi-cone-striped text-body-secondary'; t = L('ov.r_maint', { n: r.text || '' }); sub = L('ov.r_by', { w: whoTxt(r.by) }); break;
		case 'maint_end': icon = 'bi-cone-striped text-body-secondary'; t = L('ov.r_maint_end', { n: r.text || '' }); sub = L('ov.r_by', { w: whoTxt(r.by) }); break;
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
		$('#m64-groups').innerHTML = [''].concat(groups).map(function (g) { return '<span class="chip' + (g === OV.group ? ' active' : '') + '" data-group="' + esc(g) + '" role="button" tabindex="0">' + esc(g === '' ? L('ov.all') : g || L('ov.no_group')) + '</span>'; }).join('');
		$('#m64-only-prob').checked = OV.only;
		$$('[data-view]').forEach(function (b) { b.classList.toggle('active', b.dataset.view === OV.view); });
		var q = OV.q.toLowerCase();
		var hs = data.hosts.filter(function (h) {
			if (OV.group && h.group !== OV.group) { return false; }
			if (OV.only && hostState(h) === 'ok' && !h.vanished) { return false; }
			if (!q) { return true; }
			return (h.name + ' ' + h.address + ' ' + h.kind + ' ' + (h.tags || []).join(' ') + ' ' + h.group).toLowerCase().indexOf(q) >= 0;
		});
		var html = '';
		if (!data.hosts.length) { html = ''; }
		else if (!hs.length) { html = '<div class="text-body-secondary p-4 text-center">' + esc(L('ov.no_match')) + '</div>'; }
		else if (OV.view === 'list') {
			html = '<div class="card"><div class="table-responsive"><table class="table table-hover mb-0 align-middle"><thead><tr><th style="width:2rem"></th><th>' + esc(L('col.host')) + '</th><th class="d-none d-md-table-cell">' + esc(L('col.address')) + '</th><th class="d-none d-lg-table-cell">' + esc(L('col.tags')) + '</th><th>CPU</th><th>RAM</th><th>' + esc(L('ov.problems')) + '</th></tr></thead><tbody>' + hs.map(row).join('') + '</tbody></table></div></div>';
		} else {
			var seen = [];
			hs.forEach(function (h) { if (seen.indexOf(h.group) < 0) { seen.push(h.group); } });
			seen.forEach(function (g) {
				var gh = hs.filter(function (h) { return h.group === g; });
				html += '<div class="group-head">' + esc(g || L('ov.no_group')) + ' <span class="fw-normal text-body-tertiary">' + gh.length + '</span></div><div class="row g-3">' + gh.map(tile).join('') + '</div>';
			});
		}
		$('#m64-hosts').innerHTML = html;
		$('#m64-empty').classList.toggle('d-none', data.hosts.length > 0);
		$('#m64-filter').classList.toggle('d-none', data.hosts.length === 0);
	}
	function go(el) {
		if (el.dataset.goto) { location.href = el.dataset.goto; return; }
		var url = '/monitor64/host/' + encodeURIComponent(el.dataset.host);
		if (el.dataset.key) { url += '#svc=' + encodeURIComponent(el.dataset.key); }
		location.href = url;
	}
	root.addEventListener('click', function (ev) {
		var b = ev.target.closest('[data-ack]');
		if (b) {
			ev.stopPropagation();
			var r = b.closest('.prob-row');
			api('POST', '/api/monitor64/problems/action', { host: r.dataset.host, key: r.dataset.key, action: b.dataset.ack, comment: '' }).then(function () {
				toast(b.dataset.ack === 'ack' ? L('ov.acked_toast') : L('ov.unacked_toast'));
				refresh();
			}).catch(fail);
			return;
		}
		var g = ev.target.closest('[data-group]');
		if (g) { OV.group = g.dataset.group; store('group', OV.group); render(); return; }
		var v = ev.target.closest('[data-view]');
		if (v) { OV.view = v.dataset.view; store('view', OV.view); render(); return; }
		var t = ev.target.closest('[data-host],[data-goto]');
		if (t && t.closest('#m64')) { go(t); }
	});
	root.addEventListener('keydown', function (ev) {
		if (ev.key !== 'Enter' && ev.key !== ' ') { return; }
		var t = ev.target.closest('[data-host],[data-goto],[data-group]');
		if (t) { ev.preventDefault(); t.click(); }
	});
	$('#m64-only-prob').onchange = function () { OV.only = this.checked; store('only', OV.only ? '1' : '0'); render(); };
	$('#m64-q').oninput = function () { OV.q = this.value; render(); };
	function refresh() { api('GET', '/api/monitor64/overview').then(function (d) { data = d; render(); }).catch(function () {}); }
	function loadSparks() { api('GET', '/api/monitor64/sparks').then(function (s) { sparks = s || {}; render(); }).catch(function () {}); }
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
		if (span > 40 * 86400) { return pad(d.getDate()) + '.' + pad(d.getMonth() + 1) + '.' + String(d.getFullYear()).slice(2); }
		if (span > 2 * 86400) { return pad(d.getDate()) + '.' + pad(d.getMonth() + 1) + '. ' + pad(d.getHours()) + ':00'; }
		return pad(d.getHours()) + ':' + pad(d.getMinutes());
	};
}
// toPoints: Punkte der API in Chart.js-Punkte; Luecken (mehr als 3 Schritte) unterbrechen die Linie.
function toPoints(s, factor) {
	var out = [], pts = s.points || [], step = s.step || 0;
	if (!step && pts.length > 1) { step = Math.max(60, (pts[pts.length - 1].t - pts[0].t) / pts.length); }
	for (var i = 0; i < pts.length; i++) {
		if (i && step && pts[i].t - pts[i - 1].t > 3 * step) { out.push({ x: pts[i - 1].t + step, y: null }); }
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
// dragZoom: Bereich im Diagramm aufziehen -> onZoom(von, bis) in Unix-Sekunden.
function dragZoom(canvas, chart, onZoom) {
	var box = canvas.parentNode, sel = $('.zoom-sel', box), x0 = null;
	canvas.addEventListener('mousedown', function (e) { x0 = e.offsetX; sel.style.left = x0 + 'px'; sel.style.width = '0'; sel.style.display = 'block'; });
	canvas.addEventListener('mousemove', function (e) { if (x0 === null) { return; } sel.style.left = Math.min(x0, e.offsetX) + 'px'; sel.style.width = Math.abs(e.offsetX - x0) + 'px'; });
	window.addEventListener('mouseup', function (e) {
		if (x0 === null) { return; }
		var r = canvas.getBoundingClientRect(), x1 = e.clientX - r.left, start = x0;
		x0 = null;
		sel.style.display = 'none';
		if (Math.abs(x1 - start) < 4) { return; }
		var a = chart.scales.x.getValueForPixel(Math.min(start, x1)), b = chart.scales.x.getValueForPixel(Math.max(start, x1));
		if (b - a < 120) { return; }
		onZoom(Math.round(a), Math.round(b));
	});
}
function unitFmt(unit) {
	if (unit === 'B/s') { return { factor: 1e6, label: 'MB/s', fmt: function (v) { return fmtNum(v, 1) + ' MB/s'; } }; }
	return { factor: 1, label: unit, fmt: function (v) { return fmtNum(v, unit === '%' ? 0 : 1) + ' ' + unit; } };
}

// ---------- Host ----------
function pageHost() {
	var uid = root.dataset.host, H = D.host, sparks = {}, charts = [], HV = { range: store('range') || '24h', off: 0, zoom: null };
	var detailFor = null;
	function svcName(s) { return s.name; }
	function accState(a) {
		if (!a.enabled) { return '<i class="bi bi-dash-circle" title="' + esc(L('host.acc_off')) + '"></i>'; }
		if (!a.known) { return '<i class="bi bi-hourglass-split text-body-secondary" title="' + esc(L('host.acc_wait')) + '"></i>'; }
		return a.ok ? '<i class="bi bi-check-circle-fill"></i>' : '<i class="bi bi-x-circle-fill"></i>';
	}
	function renderHead() {
		var h = H.host, st = H.view === 'unreachable' ? 'unknown' : H.state;
		var badge = H.view === 'maintenance' ? '<span class="st-badge maint"><i class="bi bi-cone-striped"></i> ' + esc(L('ov.maint')) + '</span>' : H.view === 'unreachable' ? stBadge('unknown', L('state.unreachable')) : H.checked ? stBadge(st) : '<span class="st-badge unknown">' + esc(L('ov.waiting')) + '</span>';
		if (h.paused) { badge += ' <span class="st-badge unknown"><i class="bi bi-pause-circle"></i> ' + esc(L('ov.paused')) + '</span>'; }
		var kl = ((D.host_kind_labels || {})[h.kind] || [h.kind])[0] || '';
		$('#m64-host-head').innerHTML = '<div class="d-flex align-items-center gap-2"><i class="bi ' + esc(H.icon) + ' fs-4 text-body-secondary"></i><h1 class="h3 mb-0">' + esc(h.name) + '</h1>' + badge + '</div>' +
			'<div class="text-body-secondary small mt-1">' + esc(kl) + ' · ' + esc(h.address) + (h.group ? ' · ' + esc(L('host.group')) + ' ' + esc(h.group) : '') + ' ' + (h.tags || []).map(tag).join('') +
			(H.checked ? ' · ' + esc(L('host.checked', { t: ago(H.checked) })) : '') + '</div>' +
			'<div class="d-flex flex-wrap gap-2 mt-2">' + H.accesses.map(function (a) { return '<span class="access-chip access-row">' + accState(a) + esc(accLabel(a.type)) + '</span>'; }).join('') +
			'<a href="#" class="small align-self-center" data-act="access-add"><i class="bi bi-plus"></i> ' + esc(L('host.access_add')) + '</a></div>';
		var pl = $('[data-pause-label]');
		if (pl) { pl.textContent = h.paused ? L('host.resume') : L('host.pause'); }
		var al = '';
		if (H.maint) { al += '<div class="alert alert-warning py-2 small"><i class="bi bi-cone-striped"></i> ' + esc(L('host.in_maint', { r: H.maint.reason || '–', t: H.maint.end ? fmtTime(H.maint.end) : L('mt.until_ended') })) + '</div>'; }
		if (H.view === 'unreachable') { al += '<div class="alert alert-secondary d-flex align-items-center gap-2"><i class="bi bi-plug fs-5"></i><div><strong>' + esc(L('state.unreachable')) + '.</strong> ' + esc(H.unreach || '') + ' ' + esc(L('host.unreach_hint')) + '</div></div>'; }
		if (!H.running) { al += ''; }
		$('#m64-host-alerts').innerHTML = al;
	}
	function renderNew() {
		var n = H.new || [], html = '';
		if (n.length) {
			html = '<div class="card mb-3 new-svc"><div class="card-body py-2"><div class="d-flex flex-wrap align-items-center gap-2 mb-2"><i class="bi bi-stars text-primary"></i><strong>' + esc(L('host.new_n', { n: n.length })) + '</strong><span class="small text-body-secondary">' + esc(L('host.new_hint')) + '</span>' +
				'<div class="ms-auto d-flex gap-2"><button class="btn btn-sm btn-primary" type="button" data-new="1"><i class="bi bi-check2"></i> ' + esc(L('host.adopt')) + '</button><button class="btn btn-sm btn-outline-secondary" type="button" data-new="-1"><i class="bi bi-eye-slash"></i> ' + esc(L('host.ignore')) + '</button></div></div>' +
				'<div class="row g-1">' + n.map(function (s, i) { return '<div class="col-md-6 col-xl-4"><div class="form-check"><input class="form-check-input" type="checkbox" id="m64n' + i + '" value="' + esc(s.key) + '" checked><label class="form-check-label small" for="m64n' + i + '">' + esc(s.name || s.key) + ' <span class="text-body-tertiary">' + esc(s.key) + '</span></label></div></div>'; }).join('') + '</div></div></div>';
		}
		var gone = H.services.filter(function (s) { return s.vanished; });
		if (gone.length) {
			html += '<div class="alert alert-warning py-2 small d-flex flex-wrap align-items-center gap-2"><i class="bi bi-question-diamond"></i> ' + esc(L('host.vanished_n', { n: gone.length })) + ' <span class="text-body-secondary">' + esc(gone.map(svcName).join(', ')) + '</span>' +
				'<button class="btn btn-sm btn-outline-danger ms-auto" type="button" data-remove-gone="1"><i class="bi bi-trash"></i> ' + esc(L('host.remove_all')) + '</button></div>';
		}
		$('#m64-new').innerHTML = html;
	}
	function valueCell(s) {
		var mt = s.primary >= 0 ? s.metrics[s.primary] : (s.metrics && s.metrics.length && !s.text ? s.metrics[0] : null);
		var st = H.view === 'unreachable' ? 'unknown' : s.state, html = '';
		if (mt) {
			html = '<span class="fw-semibold">' + esc(fmtVal(mt.value, mt.unit)) + '</span>';
			if (mt.unit === '%') { html += '<span class="bar"><span class="' + (st === 'ok' ? '' : esc(st)) + '" style="width:' + Math.max(0, Math.min(100, mt.value)) + '%"></span></span>'; }
			var p = mt.status || {};
			if ((p.pending === 'warn' || p.pending === 'crit') && toDate(p.pending_since)) {
				html += '<div class="small text-warning-emphasis"><i class="bi bi-hourglass-split"></i> ' + esc(pendText(p, mt.unit)) + '</div>';
			}
			if (s.text) { html += '<div class="small text-body-secondary">' + esc(s.text) + '</div>'; }
		} else {
			html = '<span class="small">' + esc(s.text || '') + '</span>';
		}
		if (s.cause && st !== 'ok') { html += '<div class="small text-danger-emphasis">' + esc(s.cause) + '</div>'; }
		if (s.vanished) { html += '<div class="small text-warning-emphasis"><i class="bi bi-question-diamond"></i> ' + esc(L('host.vanished')) + '</div>'; }
		return html;
	}
	function pendText(p, unit) {
		var s = toDate(p.pending_since), a = toDate(p.pending_at);
		var mins = Math.max(0, Math.round((Date.now() - s.getTime()) / 60000)), need = a ? Math.round((a.getTime() - s.getTime()) / 60000) : 0;
		return L('host.pending', { m: mins, v: fmtVal(lim(p.pending_limit), unit), s: stLabel(p.pending), n: need });
	}
	function thrCell(s) {
		if (!s.levels) { return '<span class="text-body-tertiary">–</span>'; }
		var src = srcLabel(s.levels), e = s.levels.eff;
		return thrVals(e, s.metrics[s.primary].unit) + '<div class="src' + (src.own ? ' src-own' : '') + '">' + esc(src.t) + (e['for'] ? ' · ' + esc(durLabel(e['for'])) : '') + (e.report === 'show' ? ' · ' + esc(L('rl.show')) : '') + '</div>';
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
				var st = H.view === 'unreachable' ? 'unknown' : s.state;
				var badge = stBadge(st) + (s.show_only ? ' <i class="bi bi-eye text-body-tertiary" title="' + esc(L('rl.show')) + '"></i>' : '') + (s.ack ? ' <i class="bi bi-check2-square text-primary" title="' + esc(L('ov.acked')) + '"></i>' : '');
				html += '<tr data-svc="' + esc(s.key) + '"' + (s.vanished ? ' class="vanished"' : '') + '><td>' + badge + '</td><td class="fw-semibold m64-svc-name">' + esc(s.name) + (s.since && st !== 'ok' ? '<div class="small fw-normal text-body-secondary">' + esc(since(s.since)) + '</div>' : '') + '</td><td class="svc-val">' + valueCell(s) + '</td>' +
					'<td class="d-none d-lg-table-cell spark-cell">' + (sparks[s.key] ? spark(sparks[s.key], st === 'ok' ? '' : 's-' + st) : '') + '</td>' +
					'<td class="d-none d-md-table-cell thr">' + thrCell(s) + '</td><td class="d-none d-xl-table-cell small text-body-secondary">' + esc(s.via || '') + '</td></tr>';
			});
		});
		if (!list.length) { html = '<tr><td colspan="6" class="text-center text-body-secondary p-4">' + esc(H.checked ? L('host.no_services') : L('host.no_services_yet')) + '</td></tr>'; }
		$('#m64-svcs').innerHTML = html;
	}
	function accSummary(a) {
		var c = a.config || {}, p = [];
		if (c.user) { p.push(L('acc.user') + ' ' + c.user); }
		if (c.port) { p.push(L('acc.port') + ' ' + c.port); }
		if (c.url) { p.push(c.url); }
		if (c.token_id) { p.push(c.token_id); }
		if (c.smart) { p.push('SMART'); }
		if (a.secret_set) { p.push(L('acc.secret_set')); }
		return p.join(' · ');
	}
	function renderAccesses() {
		var html = H.accesses.map(function (a) {
			return '<div class="list-group-item d-flex flex-wrap align-items-center gap-2 access-row" data-acc="' + esc(a.uid) + '">' + accState(a) + '<div class="me-auto min-w-0"><div class="fw-semibold">' + esc(accLabel(a.type)) + (a.enabled ? '' : ' <span class="badge text-bg-secondary">' + esc(L('host.acc_off')) + '</span>') + '</div>' +
				'<div class="small text-body-secondary text-truncate">' + esc(accSummary(a)) + (a.hostkey ? ' · ' + esc(L('acc.hostkey')) + ' <code>' + esc(a.hostkey) + '</code>' : '') + '</div>' +
				(a.error ? '<div class="small text-danger-emphasis">' + esc(a.error) + '</div>' : '') + '</div>' +
				'<div class="btn-group btn-group-sm"><button class="btn btn-outline-secondary" type="button" data-acc-act="test"><i class="bi bi-plug"></i> ' + esc(L('acc.test')) + '</button>' +
				'<button class="btn btn-outline-secondary" type="button" data-acc-act="edit" title="' + esc(L('acc.edit')) + '" aria-label="' + esc(L('acc.edit')) + '"><i class="bi bi-pencil"></i></button>' +
				(a.hostkey ? '<button class="btn btn-outline-secondary" type="button" data-acc-act="hostkey" title="' + esc(L('acc.hostkey_reset')) + '" aria-label="' + esc(L('acc.hostkey_reset')) + '"><i class="bi bi-key"></i></button>' : '') +
				'<button class="btn btn-outline-secondary" type="button" data-acc-act="delete" title="' + esc(L('acc.delete')) + '" aria-label="' + esc(L('acc.delete')) + '"><i class="bi bi-trash"></i></button></div></div>';
		}).join('');
		$('#m64-accesses').innerHTML = html || '<div class="list-group-item small text-body-secondary">' + esc(L('host.no_access')) + '</div>';
		var ig = H.ignored || [];
		$('#m64-ignored').innerHTML = ig.length ? '<details class="mb-3"><summary class="small text-body-secondary">' + esc(L('host.ignored_n', { n: ig.length })) + '</summary><div class="list-group mt-2">' +
			ig.map(function (s) { return '<div class="list-group-item d-flex align-items-center gap-2 small"><span class="me-auto">' + esc(s.name || s.key) + ' <span class="text-body-tertiary">' + esc(s.key) + '</span></span><button class="btn btn-sm btn-outline-secondary" type="button" data-ign="' + esc(s.key) + '">' + esc(L('host.adopt')) + '</button></div>'; }).join('') + '</div></details>' : '';
	}
	function renderAll() { renderHead(); renderNew(); renderServices(); renderAccesses(); }
	function reload() { return api('GET', '/api/monitor64/hosts/' + encodeURIComponent(uid)).then(function (d) { H = d; renderAll(); return d; }); }
	function loadSparks() { api('GET', '/api/monitor64/sparks?host=' + encodeURIComponent(uid)).then(function (s) { sparks = s || {}; renderServices(); }).catch(function () {}); }

	// Diagramme
	function chartTitle(id) { return { cpu: L('chart.cpu'), ram: L('chart.ram'), net: L('chart.net'), disk: L('chart.disk') }[id] || id; }
	function buildCharts() {
		charts.forEach(function (c) { c.destroy(); });
		charts = [];
		var defs = H.charts || [];
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
				if (!cv) { return; }
				var u = unitFmt(c.unit);
				var ch = lineChart(cv, { from: res.from, to: res.to, max: c.max, warn: c.warn, crit: c.crit, fmt: u.fmt,
					series: c.series.map(function (s, i) { return { label: s.label, data: toPoints(res.series[i] || {}, u.factor) }; }) });
				if (!ch) { return; }
				charts.push(ch);
				dragZoom(cv, ch, function (a, b) { HV.zoom = [a, b]; buildCharts(); });
			}).catch(function () {});
		});
	}
	$$('[data-range]').forEach(function (b) { b.onclick = function () { HV.range = b.dataset.range; HV.off = 0; HV.zoom = null; store('range', HV.range); buildCharts(); }; });
	$('#m64-older').onclick = function () { HV.zoom = null; HV.off++; buildCharts(); };
	$('#m64-newer').onclick = function () { if (HV.zoom) { HV.zoom = null; } else { HV.off = Math.max(0, HV.off - 1); } buildCharts(); };

	// Dienst-Details (Offcanvas): Verlauf, drei Stufen der Schwelle, Soll-Zustand, Melden, Erweitert
	var sdChart = null;
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
	function openDetail(key) {
		var s = null;
		H.services.forEach(function (x) { if (x.key === key) { s = x; } });
		if (!s) { return; }
		detailFor = key;
		$('#m64-sd-host').textContent = H.host.name + ' · ' + ((D.cats || {})[s.category] || s.category);
		$('#m64-sd-title').textContent = s.name;
		var st = H.view === 'unreachable' ? 'unknown' : s.state, lv = s.levels, mt = s.primary >= 0 ? s.metrics[s.primary] : null;
		var html = '<div class="d-flex align-items-center gap-2 mb-3 flex-wrap">' + stBadge(st) + '<span>' + esc(mt ? fmtVal(mt.value, mt.unit) : '') + (mt && s.text ? ' · ' : '') + esc(s.text || '') + '</span></div>';
		if (s.cause && st !== 'ok') { html += '<div class="alert alert-' + (st === 'crit' ? 'danger' : 'warning') + ' py-2 small">' + esc(s.cause) + '</div>'; }
		if (s.vanished) { html += '<div class="alert alert-warning py-2 small"><i class="bi bi-question-diamond"></i> ' + esc(L('sd.vanished')) + '</div>'; }
		if (mt && mt.status && (mt.status.pending === 'warn' || mt.status.pending === 'crit') && toDate(mt.status.pending_since)) {
			var p = mt.status, ps = toDate(p.pending_since), pa = toDate(p.pending_at), need = pa ? (pa.getTime() - ps.getTime()) / 60000 : 1, done = (Date.now() - ps.getTime()) / 60000;
			html += '<div class="pend mb-3"><div class="small mb-1"><i class="bi bi-hourglass-split"></i> ' + esc(pendText(p, mt.unit)) + '</div><div class="progress" style="height:.35rem"><div class="progress-bar bg-warning" style="width:' + Math.min(100, Math.round(done / Math.max(need, 1) * 100)) + '%"></div></div><div class="small text-body-secondary mt-1">' + esc(L('sd.pending_hint')) + '</div></div>';
		}
		(s.metrics || []).forEach(function (m) {
			if (m.rule === 'fs.trend_days' && m.value < 1e5) { html += '<div class="alert alert-danger py-2 small"><i class="bi bi-graph-up-arrow"></i> ' + esc(L('sd.trend', { n: fmtNum(m.value, 1) })) + '</div>'; }
		});
		var chartMetric = mt || ((s.metrics || []).length ? s.metrics[0] : null);
		if (chartMetric) { html += '<div class="chart-box mb-3"><canvas id="m64-sd-chart"></canvas><div class="zoom-sel"></div></div>'; }
		var store_ = false, unit = '';
		if (lv) {
			var meta = kindMeta(lv.kind) || {}, e = lv.eff, f = meta.factor || 1;
			unit = meta.unit === 'min' ? L('unit.min') : meta.unit === 'days' ? L('unit.days') : (mt ? mt.unit : meta.unit) || '';
			store_ = !!meta.store;
			var own = !!(lv.service || lv.host_kind), grp = !own && !!lv.override;
			var cur = lv.service || lv.host_kind || {};
			var scopeKind = !lv.service && !!lv.host_kind;
			html += '<h6 class="mt-2">' + esc(L('sd.threshold')) + ' <span class="small text-body-secondary fw-normal">– ' + esc(L('sd.threshold_sub')) + '</span></h6>' +
				lvlBox(!grp && !own, 'bi-globe2', esc(L('sd.lvl_std')), thrVals(eval1(lv.std, lv.kind), unit) + (lv.std && lv.std['for'] ? ' · ' + esc(durLabel(lv.std['for'])) : '')) +
				lvlBox(grp, 'bi-tags', lv.override ? esc(targetLabel(lv.override.target_type, lv.override.target)) + ' <span class="text-body-tertiary small">' + esc(L('sd.ovr_no', { n: lv.override.index + 1 })) + '</span>' : esc(L('sd.lvl_ovr')), lv.override ? ruleVals(lv.override.rule, e, unit) : '<span class="text-body-tertiary">' + esc(L('sd.none')) + '</span>');
			var free = cur.mode === 'free' || (!cur.mode && e.mode === 'free');
			html += '<div class="lvl' + (own ? ' active' : '') + '"><div class="lvl-head mb-2"><span><i class="bi bi-hdd"></i> ' + esc(L('sd.lvl_host')) + '</span>' +
				(own ? '<button class="btn btn-link btn-sm p-0" type="button" data-sd="reset"><i class="bi bi-arrow-counterclockwise"></i> ' + esc(L('sd.reset')) + '</button>' : '<span class="text-body-tertiary small">' + esc(L('sd.not_set')) + '</span>') + '</div>' +
				(store_ ? '<div class="btn-group btn-group-sm mb-2" role="group"><input type="radio" class="btn-check" name="m64-sd-mode" id="m64-sd-mp" value="used"' + (free ? '' : ' checked') + '><label class="btn btn-outline-secondary" for="m64-sd-mp">' + esc(L('sd.mode_used')) + '</label>' +
					'<input type="radio" class="btn-check" name="m64-sd-mode" id="m64-sd-mf" value="free"' + (free ? ' checked' : '') + '><label class="btn btn-outline-secondary" for="m64-sd-mf">' + esc(L('sd.mode_free')) + '</label></div>' : '') +
				'<div class="row g-2"><div class="col-4"><label class="form-label small mb-0" for="m64-sd-w" id="m64-sd-lw">' + esc(L('rl.warn')) + '</label><div class="input-group input-group-sm"><input class="form-control" id="m64-sd-w" inputmode="decimal"><span class="input-group-text m64-sd-u"></span></div></div>' +
				'<div class="col-4"><label class="form-label small mb-0" for="m64-sd-c" id="m64-sd-lc">' + esc(L('rl.crit')) + '</label><div class="input-group input-group-sm"><input class="form-control" id="m64-sd-c" inputmode="decimal"><span class="input-group-text m64-sd-u"></span></div></div>' +
				'<div class="col-4"><label class="form-label small mb-0" for="m64-sd-f">' + esc(L('rl.for')) + '</label><select class="form-select form-select-sm" id="m64-sd-f"><option value="">' + esc(L('sd.inherits', { v: durLabel(e['for']) })) + '</option>' +
				[0, 300, 900, 3600].map(function (x) { return '<option value="' + x + '"' + (cur['for'] === x ? ' selected' : '') + '>' + esc(durLabel(x)) + '</option>'; }).join('') + '</select></div></div>' +
				'<div class="small text-body-secondary mt-1" id="m64-sd-hint"></div>' +
				'<div class="mt-2 small"><span class="text-body-secondary me-2">' + esc(L('sd.applies')) + '</span>' +
				'<div class="form-check form-check-inline"><input class="form-check-input" type="radio" name="m64-sd-scope" id="m64-sd-s1" value="service"' + (scopeKind ? '' : ' checked') + '><label class="form-check-label" for="m64-sd-s1">' + esc(L('sd.scope_service')) + '</label></div>' +
				'<div class="form-check form-check-inline"><input class="form-check-input" type="radio" name="m64-sd-scope" id="m64-sd-s2" value="kind"' + (scopeKind ? ' checked' : '') + '><label class="form-check-label" for="m64-sd-s2">' + esc(L('sd.scope_kind', { c: (D.cats || {})[s.category] || s.category })) + '</label></div></div></div>';
			html += '<div class="d-flex flex-wrap align-items-center gap-2 mt-2 small"><label class="text-body-secondary" for="m64-sd-r">' + esc(L('sd.report')) + '</label><select class="form-select form-select-sm w-auto" id="m64-sd-r"><option value="">' + esc(L('sd.inherits', { v: e.report === 'show' ? L('rl.show') : L('rl.notify') })) + '</option><option value="notify"' + (cur.report === 'notify' ? ' selected' : '') + '>' + esc(L('rl.notify')) + '</option><option value="show"' + (cur.report === 'show' ? ' selected' : '') + '>' + esc(L('rl.show')) + '</option></select>' +
				'<span class="text-body-tertiary">' + esc(L('sd.show_hint')) + '</span></div>';
		}
		if (s.guest) {
			html += '<h6 class="mt-3">' + esc(L('sd.soll')) + '</h6><div class="lvl active"><div class="btn-group btn-group-sm mb-2" role="group">' +
				'<input type="radio" class="btn-check" name="m64-sd-soll" id="m64-sd-so0" value=""' + (!s.soll ? ' checked' : '') + '><label class="btn btn-outline-secondary" for="m64-sd-so0"><i class="bi bi-magic"></i> ' + esc(L('sd.soll_auto')) + '</label>' +
				'<input type="radio" class="btn-check" name="m64-sd-soll" id="m64-sd-so1" value="run"' + (s.soll === 'run' ? ' checked' : '') + '><label class="btn btn-outline-secondary" for="m64-sd-so1"><i class="bi bi-play-fill"></i> ' + esc(L('sd.soll_run')) + '</label>' +
				'<input type="radio" class="btn-check" name="m64-sd-soll" id="m64-sd-so2" value="off"' + (s.soll === 'off' ? ' checked' : '') + '><label class="btn btn-outline-secondary" for="m64-sd-so2"><i class="bi bi-pause-fill"></i> ' + esc(L('sd.soll_off')) + '</label></div>' +
				'<div class="small text-body-secondary"><i class="bi bi-magic"></i> ' + esc(L('sd.soll_hint')) + '</div></div>';
		}
		if (!lv && s.state_levels) {
			var sl = s.state_levels, scur = (sl.service && sl.service.severity) || '';
			html += '<div class="small text-body-secondary mb-2 mt-2"><i class="bi bi-info-circle"></i> ' + esc(L('sd.state_info')) + '</div>' +
				'<div class="d-flex align-items-center gap-2 small"><label class="text-body-secondary" for="m64-sd-sev">' + esc(L('sd.on_fault')) + '</label><select class="form-select form-select-sm w-auto" id="m64-sd-sev"><option value="">' + esc(L('sd.inherits', { v: sevLabel(sl.eff.severity) })) + '</option>' +
				['crit', 'warn', 'off'].map(function (x) { return '<option value="' + x + '"' + (scur === x ? ' selected' : '') + '>' + esc(sevLabel(x)) + '</option>'; }).join('') + '</select></div>';
		}
		html += '<details class="mt-3"><summary class="small text-body-secondary">' + esc(L('advanced')) + '</summary><div class="pt-2">' +
			'<div class="mb-2"><label class="form-label small mb-0" for="m64-sd-name">' + esc(L('sd.display_name')) + '</label><input class="form-control form-control-sm" id="m64-sd-name" maxlength="200" value="' + esc(s.custom_name || '') + '" placeholder="' + esc(s.name) + '"></div>' +
			(lv && lv.eff.mode !== 'free' ? '<div class="row g-2 align-items-center mb-2"><div class="col-auto small"><label for="m64-sd-h">' + esc(L('sd.hyst')) + '</label></div><div class="col-auto"><div class="input-group input-group-sm" style="width:8rem"><input class="form-control" id="m64-sd-h" inputmode="decimal" placeholder="' + esc(L('sd.inherits', { v: fmtNum(lv.eff.hyst) })) + '" value="' + (lv.service && lv.service.hyst !== undefined ? esc(fmtNum(lv.service.hyst)) : '') + '"><span class="input-group-text">' + esc(unit || '–') + '</span></div></div>' +
				'<div class="col small text-body-secondary">' + esc(L('sd.hyst_hint', { v: fmtNum(lim(lv.eff.warn)), h: fmtNum(lv.eff.hyst) })) + '</div></div>' : '') +
			'<div class="small text-body-secondary mt-1">' + esc(L('sd.access_info', { a: s.via || '–', i: fmtDur(H.host.interval_sec) })) + '</div><div class="small text-body-tertiary">' + esc(s.key) + '</div></div></details>';
		var canAck = st !== 'ok' && s.since;
		html += '<div class="d-flex flex-wrap gap-2 mt-3"><button class="btn btn-primary btn-sm" type="button" data-sd="save">' + esc(L('save')) + '</button>' +
			(canAck && !s.ack ? '<button class="btn btn-outline-secondary btn-sm" type="button" data-sd="ack"><i class="bi bi-check2"></i> ' + esc(L('ov.ack')) + '</button>' : '') +
			(s.ack ? '<button class="btn btn-outline-secondary btn-sm" type="button" data-sd="unack"><i class="bi bi-arrow-counterclockwise"></i> ' + esc(L('ov.unack')) + '</button>' : '') +
			(s.vanished ? '<button class="btn btn-outline-danger btn-sm ms-auto" type="button" data-sd="remove"><i class="bi bi-trash"></i> ' + esc(L('sd.remove')) + '</button>' :
				s.kind !== 'access' ? '<button class="btn btn-outline-secondary btn-sm ms-auto" type="button" data-sd="ignore"><i class="bi bi-eye-slash"></i> ' + esc(L('sd.ignore')) + '</button>' : '') + '</div>';
		var body = $('#m64-sd-body');
		body.innerHTML = html;
		if (lv) { setMode(); $$('[name=m64-sd-mode]', body).forEach(function (r) { r.onchange = function () { setMode(true); }; }); }
		function curMode() { var r = $('[name=m64-sd-mode]:checked', body); return r ? r.value : 'used'; }
		function setMode(changed) {
			var e = lv.eff, meta = kindMeta(lv.kind) || {}, f = meta.factor || 1, free = curMode() === 'free', cur = lv.service || lv.host_kind || {};
			$$('.m64-sd-u', body).forEach(function (x) { x.textContent = free ? L('unit.gb_free') : (unit || '–'); });
			$('#m64-sd-lw').textContent = free ? L('sd.warn_below') : L('rl.warn');
			$('#m64-sd-lc').textContent = free ? L('sd.crit_below') : L('rl.crit');
			var iw = free ? lim(e.warn_free) : lim(e.warn), ic = free ? lim(e.crit_free) : lim(e.crit);
			if (!free && iw !== null) { iw /= f; }
			if (!free && ic !== null) { ic /= f; }
			var effFree = e.mode === 'free';
			$('#m64-sd-w').placeholder = effFree === free && iw !== null ? L('sd.inherits', { v: fmtNum(iw) }) : (free ? L('sd.example', { v: fmtNum(Math.round(capGB() * 0.1)) }) : '');
			$('#m64-sd-c').placeholder = effFree === free && ic !== null ? L('sd.inherits', { v: fmtNum(ic) }) : (free ? L('sd.example', { v: fmtNum(Math.round(capGB() * 0.05)) }) : '');
			var cw = free ? cur.warn_free : cur.warn, cc = free ? cur.crit_free : cur.crit;
			if (!changed) {
				$('#m64-sd-w').value = cw === undefined ? '' : lim(cw) === null ? '' : fmtNum(free ? cw : cw / f);
				$('#m64-sd-c').value = cc === undefined ? '' : lim(cc) === null ? '' : fmtNum(free ? cc : cc / f);
			} else { $('#m64-sd-w').value = ''; $('#m64-sd-c').value = ''; }
			var hint = '';
			if (store_ && mt) { hint = free ? L('sd.hint_free', { f: fmtNum(capGB() * (100 - mt.value) / 100), c: fmtNum(capGB()) }) : L('sd.hint_used', { v: fmtNum(mt.value) }); }
			$('#m64-sd-hint').textContent = hint;
		}
		function capGB() { return mt && mt.max ? mt.max / 1e9 : 0; }
		$$('[data-sd]', body).forEach(function (b) {
			b.onclick = function () {
				var a = b.dataset.sd;
				if (a === 'ack' || a === 'unack') {
					api('POST', '/api/monitor64/problems/action', { host: uid, key: s.key, action: a, comment: '' }).then(function () { toast(a === 'ack' ? L('ov.acked_toast') : L('ov.unacked_toast')); closeDetail(); reload(); }).catch(fail);
				} else if (a === 'ignore') {
					api('POST', '/api/monitor64/hosts/' + encodeURIComponent(uid) + '/services/adopt', { keys: [s.key], state: -1 }).then(function () { toast(L('sd.ignored_toast')); closeDetail(); reload(); }).catch(fail);
				} else if (a === 'remove') {
					confirmBox(L('sd.remove'), L('sd.remove_confirm', { n: s.name }), L('sd.remove'), function () {
						api('POST', '/api/monitor64/hosts/' + encodeURIComponent(uid) + '/services/remove', { keys: [s.key] }).then(function () { toast(L('sd.removed_toast')); closeDetail(); reload(); }).catch(fail);
					});
				} else if (a === 'reset') {
					api('PUT', '/api/monitor64/hosts/' + encodeURIComponent(uid) + '/service', { key: s.key, reset: true }).then(function () { toast(L('sd.reset_toast')); closeDetail(); reload(); }).catch(fail);
				} else if (a === 'save') { save(); }
			};
		});
		function save() {
			var req = { key: s.key };
			var nm = $('#m64-sd-name', body).value.trim();
			if (nm !== (s.custom_name || '')) { req.name = nm; }
			var so = $('[name=m64-sd-soll]:checked', body);
			if (so && so.value !== (s.soll || '')) { req.soll = so.value; }
			var rule = null;
			if (lv) {
				var meta = kindMeta(lv.kind) || {}, f = meta.factor || 1, free = curMode() === 'free';
				rule = {};
				var w = parseNum($('#m64-sd-w').value), c = parseNum($('#m64-sd-c').value);
				if ((w !== null && isNaN(w)) || (c !== null && isNaN(c))) { toast(L('err_number'), true); return; }
				if (store_) {
					var effMode = lv.eff.mode;
					if (free !== (effMode === 'free') || (lv.service || lv.host_kind || {}).mode) { rule.mode = free ? 'free' : 'used'; }
				}
				if (w !== null) { rule[free ? 'warn_free' : 'warn'] = free ? w : w * f; }
				if (c !== null) { rule[free ? 'crit_free' : 'crit'] = free ? c : c * f; }
				var fv = $('#m64-sd-f').value;
				if (fv !== '') { rule['for'] = parseInt(fv, 10); }
				var rv = $('#m64-sd-r').value;
				if (rv) { rule.report = rv; }
				var hy = $('#m64-sd-h', body);
				if (hy && hy.value.trim() !== '') { var hv = parseNum(hy.value); if (isNaN(hv) || hv < 0) { toast(L('err_number'), true); return; } rule.hyst = hv; }
			} else if (s.state_levels) {
				var sev = $('#m64-sd-sev', body).value;
				rule = sev ? { severity: sev } : {};
			}
			var scopeEl = $('[name=m64-sd-scope]:checked', body), scope = scopeEl ? scopeEl.value : 'service';
			var chain = Promise.resolve();
			if (rule !== null) {
				req.rule = rule;
				req.scope = scope;
				var hadSvc = lv ? !!lv.service : !!(s.state_levels && s.state_levels.service);
				if (scope === 'kind' && hadSvc) { // Einstellung "nur dieser Dienst" weicht der fuer alle dieser Art
					chain = api('PUT', '/api/monitor64/hosts/' + encodeURIComponent(uid) + '/service', { key: s.key, rule: {}, scope: 'service' });
				}
			}
			chain.then(function () { return api('PUT', '/api/monitor64/hosts/' + encodeURIComponent(uid) + '/service', req); })
				.then(function () { toast(L('sd.saved_toast')); closeDetail(); reload(); }).catch(fail);
		}
		var oc = window.bootstrap.Offcanvas.getOrCreateInstance(document.getElementById('m64-detail'));
		oc.show();
		if (sdChart) { sdChart.destroy(); sdChart = null; }
		if (chartMetric) {
			api('GET', '/api/monitor64/series?host=' + encodeURIComponent(uid) + '&s=' + encodeURIComponent(s.key + '|' + chartMetric.name) + '&range=24h').then(function (res) {
				var cv = document.getElementById('m64-sd-chart');
				if (!cv || detailFor !== key) { return; }
				var u = unitFmt(chartMetric.unit), w = null, c = null;
				if (lv && lv.eff.mode !== 'free' && chartMetric === mt) { w = lim(lv.eff.warn); c = lim(lv.eff.crit); }
				sdChart = lineChart(cv, { from: res.from, to: res.to, warn: w, crit: c, fmt: u.fmt, max: chartMetric.unit === '%' ? 100 : undefined, series: [{ label: s.name, data: toPoints(res.series[0] || {}, u.factor) }] });
			}).catch(function () {});
		}
	}
	function eval1(r) { // Standard einer Art als Anzeige-Werte
		var e = { warn: 'off', crit: 'off', warn_free: 'off', crit_free: 'off', dir: 'up', mode: 'used', kind: arguments[1] };
		if (r) { Object.keys(r).forEach(function (k) { e[k] = r[k]; }); }
		return e;
	}
	function closeDetail() { var oc = window.bootstrap.Offcanvas.getInstance(document.getElementById('m64-detail')); if (oc) { oc.hide(); } detailFor = null; }
	document.getElementById('m64-detail').addEventListener('hidden.bs.offcanvas', function () {
		detailFor = null;
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
		var types = ['agent', 'ssh', 'pve', 'pbs', 'docker'];
		return '<div class="row g-3"><div class="col-md-6"><label class="form-label" for="m64-af-type">' + esc(L('acc.type')) + '</label><select class="form-select" id="m64-af-type"' + (a ? ' disabled' : '') + '>' + types.map(function (x) { return '<option value="' + x + '"' + (x === t ? ' selected' : '') + '>' + esc(accLabel(x)) + '</option>'; }).join('') + '</select></div>' +
			'<div class="col-md-6 d-flex align-items-end"><div class="form-check form-switch"><input class="form-check-input" type="checkbox" id="m64-af-en"' + (!a || a.enabled ? ' checked' : '') + '><label class="form-check-label" for="m64-af-en">' + esc(L('acc.enabled')) + '</label></div></div>' +
			'<div class="col-md-4" data-af="agent ssh"><label class="form-label" for="m64-af-port">' + esc(L('acc.port')) + '</label><input class="form-control" id="m64-af-port" type="number" min="0" max="65535" value="' + (c.port || '') + '" placeholder="' + esc(t === 'ssh' ? '22' : String(D.port || 6465)) + '"></div>' +
			'<div class="col-md-8" data-af="ssh"><label class="form-label" for="m64-af-user">' + esc(L('acc.user')) + '</label><input class="form-control" id="m64-af-user" maxlength="32" value="' + esc(c.user || '') + '" placeholder="monitor64"></div>' +
			'<div class="col-12" data-af="ssh"><div class="form-check"><input class="form-check-input" type="checkbox" id="m64-af-smart"' + (c.smart ? ' checked' : '') + '><label class="form-check-label small" for="m64-af-smart">' + esc(L('new.smart')) + '</label></div></div>' +
			'<div class="col-12" data-af="pve pbs docker"><label class="form-label" for="m64-af-url">URL</label><input class="form-control" id="m64-af-url" maxlength="512" value="' + esc(c.url || '') + '" placeholder="https://10.0.0.10:8006"></div>' +
			'<div class="col-md-6" data-af="pve pbs"><label class="form-label" for="m64-af-tid">' + esc(L('new.token_id')) + '</label><input class="form-control" id="m64-af-tid" maxlength="128" value="' + esc(c.token_id || '') + '" placeholder="monitor@pve!node64"></div>' +
			'<div class="col-md-6" data-af="pve"><label class="form-label" for="m64-af-node">' + esc(L('new.node')) + '</label><input class="form-control" id="m64-af-node" maxlength="64" value="' + esc(c.node || '') + '"></div>' +
			'<div class="col-12" data-af="pve pbs docker"><label class="form-label" for="m64-af-pin">' + esc(L('new.pin')) + '</label><input class="form-control" id="m64-af-pin" maxlength="128" value="' + esc(c.pin || '') + '"></div>' +
			'<div class="col-12" data-af="ssh pve pbs docker"><label class="form-label" for="m64-af-secret">' + esc(L('acc.secret')) + '</label><input class="form-control" id="m64-af-secret" type="password" autocomplete="new-password" placeholder="' + esc(a && a.secret_set ? L('acc.secret_keep') : '') + '">' +
			'<div class="form-text">' + esc(L('acc.secret_hint')) + '</div>' + (a && a.secret_set ? '<div class="form-check mt-1"><input class="form-check-input" type="checkbox" id="m64-af-clear"><label class="form-check-label small" for="m64-af-clear">' + esc(L('acc.secret_clear')) + '</label></div>' : '') + '</div></div>';
	}
	function accessShow(body) {
		var t = $('#m64-af-type', body).value;
		$$('[data-af]', body).forEach(function (x) { x.classList.toggle('d-none', x.dataset.af.split(' ').indexOf(t) < 0); });
	}
	function accessFromForm(body) {
		var t = $('#m64-af-type', body).value, cfg = {};
		var port = parseInt($('#m64-af-port', body).value, 10);
		if ((t === 'agent' || t === 'ssh') && port) { cfg.port = port; }
		if (t === 'ssh') { cfg.user = $('#m64-af-user', body).value.trim(); cfg.smart = $('#m64-af-smart', body).checked; }
		if (t === 'pve' || t === 'pbs' || t === 'docker') { cfg.url = $('#m64-af-url', body).value.trim(); cfg.pin = $('#m64-af-pin', body).value.trim(); }
		if (t === 'pve' || t === 'pbs') { cfg.token_id = $('#m64-af-tid', body).value.trim(); }
		if (t === 'pve') { cfg.node = $('#m64-af-node', body).value.trim(); }
		var out = { type: t, config: cfg, secret: $('#m64-af-secret', body).value, enabled: $('#m64-af-en', body).checked };
		var cl = $('#m64-af-clear', body);
		if (cl && cl.checked) { out.clear_secret = true; }
		return out;
	}
	function testResult(r) {
		if (r.ok && !r.error) { return '<span class="text-success"><i class="bi bi-check-circle-fill"></i> ' + esc(L('new.test_ok', { n: r.services.length, ms: r.ms })) + '</span>' + (r.fingerprint ? '<div class="small mt-1">' + esc(L('new.fp')) + ' <code>' + esc(r.fingerprint) + '</code></div>' : ''); }
		if (r.ok) { return '<span class="text-warning-emphasis"><i class="bi bi-exclamation-triangle"></i> ' + esc(L('new.test_partial', { n: r.services.length, e: r.error })) + '</span>'; }
		return '<span class="text-danger"><i class="bi bi-x-circle-fill"></i> ' + esc(r.error || L('new.test_fail')) + '</span>';
	}
	root.addEventListener('click', function (ev) {
		var act = ev.target.closest('[data-act]');
		if (act) {
			ev.preventDefault();
			var h = H.host;
			switch (act.dataset.act) {
			case 'discover':
				act.disabled = true;
				api('POST', '/api/monitor64/hosts/' + encodeURIComponent(uid) + '/discover').then(function (r) {
					toast(L('host.discovered', { a: r.added, n: r['new'], v: r.vanished }));
					return reload();
				}).catch(fail).then(function () { act.disabled = false; });
				break;
			case 'edit':
				modal(L('host.edit'), hostForm(h), [{ label: L('cancel') }, { label: L('save'), cls: 'btn-primary', click: function (close) {
					hostPut(hostFromForm(h)).then(function () { close(); toast(L('host.saved_toast')); reload().then(buildCharts); }).catch(fail);
				} }], true);
				break;
			case 'pause':
				var b = { name: h.name, address: h.address, kind: h.kind, group: h.group, tags: h.tags || [], interval_sec: h.interval_sec, notes: h.notes || '', paused: !h.paused, agent_autoupdate: h.agent_autoupdate };
				hostPut(b).then(function () { toast(b.paused ? L('host.paused_toast') : L('host.resumed_toast')); reload(); }).catch(fail);
				break;
			case 'delete':
				modal(L('host.delete'), '<p>' + esc(L('host.delete_text', { n: h.name })) + '</p><div class="form-check"><input class="form-check-input" type="radio" name="m64-del-hist" id="m64-dh1" value="keep" checked><label class="form-check-label" for="m64-dh1">' + esc(L('host.delete_keep')) + '</label></div>' +
					'<div class="form-check"><input class="form-check-input" type="radio" name="m64-del-hist" id="m64-dh2" value="delete"><label class="form-check-label" for="m64-dh2">' + esc(L('host.delete_hist')) + '</label></div><div class="small text-body-secondary mt-2">' + esc(L('host.delete_hint')) + '</div>',
				[{ label: L('cancel') }, { label: L('host.delete'), cls: 'btn-danger', click: function (close) {
					var hist = $('[name=m64-del-hist]:checked').value;
					api('DELETE', '/api/monitor64/hosts/' + encodeURIComponent(uid) + '?history=' + hist).then(function () { close(); location.href = '/monitor64'; }).catch(fail);
				} }]);
				break;
			case 'maint':
				modal(L('host.maint'), '<div class="row g-3"><div class="col-md-6"><label class="form-label" for="m64-hm-d">' + esc(L('mt.duration')) + '</label><select class="form-select" id="m64-hm-d">' +
					[[30, L('mt.for', { d: fmtDur(1800) })], [60, L('mt.for', { d: fmtDur(3600) })], [120, L('mt.for', { d: fmtDur(7200) })], [240, L('mt.for', { d: fmtDur(14400) })], [0, L('mt.until_ended')]].map(function (o, i) { return '<option value="' + o[0] + '"' + (i === 1 ? ' selected' : '') + '>' + esc(o[1]) + '</option>'; }).join('') +
					'</select></div><div class="col-md-6"><label class="form-label" for="m64-hm-r">' + esc(L('mt.reason')) + '</label><input class="form-control" id="m64-hm-r" maxlength="200" placeholder="' + esc(L('mt.reason_ph')) + '"></div></div><div class="small text-body-secondary mt-2">' + esc(L('mt.intro')) + '</div>',
				[{ label: L('cancel') }, { label: L('mt.save'), cls: 'btn-primary', click: function (close) {
					api('POST', '/api/monitor64/maintenance', { title: $('#m64-hm-r').value, hosts: [uid], mode: 'now', minutes: parseInt($('#m64-hm-d').value, 10) }).then(function () { close(); toast(L('mt.saved_toast')); reload(); }).catch(fail);
				} }]);
				break;
			case 'access-add':
				var bodyA = modal(L('host.access_add'), accessForm(null), [{ label: L('cancel') }, { label: L('acc.test'), click: function (close, btn) {
					var a = accessFromForm(bodyA);
					btn.disabled = true;
					api('POST', '/api/monitor64/test', { address: h.address, access: a }).then(function (r) { $('#m64-af-res', bodyA).innerHTML = testResult(r); }).catch(fail).then(function () { btn.disabled = false; });
				} }, { label: L('save'), cls: 'btn-primary', click: function (close) {
					api('POST', '/api/monitor64/hosts/' + encodeURIComponent(uid) + '/access', accessFromForm(bodyA)).then(function () { close(); toast(L('acc.saved_toast')); reload(); }).catch(fail);
				} }], true);
				bodyA.insertAdjacentHTML('beforeend', '<div class="mt-3 small" id="m64-af-res"></div>');
				$('#m64-af-type', bodyA).onchange = function () { accessShow(bodyA); };
				accessShow(bodyA);
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
				aa.disabled = true;
				api('POST', au + '/test').then(function (r) { modal(L('acc.test') + ' · ' + accLabel(acc.type), '<div>' + testResult(r) + '</div>', [{ label: L('close') }]); }).catch(fail).then(function () { aa.disabled = false; });
				break;
			case 'edit':
				var bodyE = modal(L('acc.edit') + ' · ' + accLabel(acc.type), accessForm(acc), [{ label: L('cancel') }, { label: L('save'), cls: 'btn-primary', click: function (close) {
					var a = accessFromForm(bodyE);
					delete a.type;
					api('PUT', au, a).then(function () { close(); toast(L('acc.saved_toast')); reload(); }).catch(fail);
				} }], true);
				accessShow(bodyE);
				break;
			case 'hostkey':
				confirmBox(L('acc.hostkey_reset'), L('acc.hostkey_confirm'), L('acc.hostkey_reset'), function () { api('POST', au + '/hostkey-reset').then(function () { toast(L('acc.saved_toast')); reload(); }).catch(fail); });
				break;
			case 'delete':
				confirmBox(L('acc.delete'), L('acc.delete_confirm', { n: accLabel(acc.type) }), L('acc.delete'), function () { api('DELETE', au).then(function () { toast(L('acc.deleted_toast')); reload(); }).catch(fail); });
				break;
			}
			return;
		}
		var nb = ev.target.closest('[data-new]');
		if (nb) {
			var keys = $$('#m64-new input[type=checkbox]:checked').map(function (x) { return x.value; });
			if (!keys.length) { return; }
			api('POST', '/api/monitor64/hosts/' + encodeURIComponent(uid) + '/services/adopt', { keys: keys, state: parseInt(nb.dataset['new'], 10) }).then(function (r) {
				toast(nb.dataset['new'] === '1' ? L('host.adopted_toast', { n: r.changed }) : L('host.ignored_toast', { n: r.changed })); reload();
			}).catch(fail);
			return;
		}
		if (ev.target.closest('[data-remove-gone]')) {
			var gone = H.services.filter(function (s) { return s.vanished; }).map(function (s) { return s.key; });
			confirmBox(L('host.remove_all'), L('host.remove_all_confirm', { n: gone.length }), L('host.remove_all'), function () {
				api('POST', '/api/monitor64/hosts/' + encodeURIComponent(uid) + '/services/remove', { keys: gone }).then(function () { toast(L('sd.removed_toast')); reload(); }).catch(fail);
			});
			return;
		}
		var ig = ev.target.closest('[data-ign]');
		if (ig) {
			api('POST', '/api/monitor64/hosts/' + encodeURIComponent(uid) + '/services/adopt', { keys: [ig.dataset.ign], state: 1 }).then(function () { toast(L('host.adopted_toast', { n: 1 })); reload(); }).catch(fail);
			return;
		}
		var tr = ev.target.closest('tr[data-svc]');
		if (tr) { history.replaceState(null, '', '#svc=' + encodeURIComponent(tr.dataset.svc)); openDetail(tr.dataset.svc); }
	});
	renderAll();
	buildCharts();
	loadSparks();
	if (location.hash.indexOf('#svc=') === 0) { openDetail(decodeURIComponent(location.hash.slice(5))); }
	setInterval(function () { if (!document.hidden && !detailFor && !(modalEl && modalEl.classList.contains('show'))) { reload().catch(function () {}); } }, 15000);
	setInterval(function () { if (!document.hidden) { loadSparks(); } }, 300000);
}

// ---------- Probleme ----------
var TLI = { warn: ['bi-exclamation-triangle-fill', 'text-warning'], crit: ['bi-x-octagon-fill', 'text-danger'], unknown: ['bi-question-circle-fill', 'text-body-secondary'], unreachable: ['bi-plug-fill', 'text-danger'],
	ok: ['bi-check-circle-fill', 'text-success'], bell: ['bi-bell', 'text-body-secondary'], held: ['bi-moon-stars', 'text-body-secondary'], ack: ['bi-check2-square', 'text-primary'], unack: ['bi-arrow-counterclockwise', 'text-body-secondary'],
	comment: ['bi-chat-left-text', 'text-primary'], resolved: ['bi-person-check', 'text-primary'], maint: ['bi-cone-striped', 'text-body-secondary'], takeover: ['bi-diagram-3', 'text-body-secondary'] };
function evText(e, chans) {
	var t = e.text || '', w = whoTxt(e.actor);
	switch (e.kind) {
	case 'warn': case 'crit': case 'unknown': return stLabel(e.kind) + (t ? ': ' + t : '');
	case 'unreachable': return L('ev.unreachable') + (t ? ': ' + t : '');
	case 'ok': return L('ev.ok');
	case 'bell':
		var p = t.split(': '), ids = (p[1] || '').split(','), names = ids.map(function (id) { return id === 'default' ? L('nf.default') : (chans[id] || id); });
		var cs = { c: names.join(', ') };
		return p[0] === 'ok' || p[0] === 'better' ? L('ev.bell_ok', cs) : p[0] === 'reminder' ? L('ev.bell_reminder', cs) : L('ev.bell_problem', cs);
	case 'held': return L('ev.held');
	case 'ack': return L('ev.ack', { w: w }) + (t ? ': „' + t + '“' : '');
	case 'unack': return e.actor && e.actor.kind === 'system' ? L('ev.unack_auto') : L('ev.unack', { w: w });
	case 'comment': return L('ev.comment', { w: w }) + ': „' + t + '“';
	case 'resolved': return L('ev.resolved', { w: w }) + (t ? ': „' + t + '“' : '');
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
				(p.how === 'maint' ? '<i class="bi bi-cone-striped"></i> ' + esc(L('pb.maint')) : who(p.closed_by));
			var name = p.key ? p.name : L('ov.unreachable');
			html += '<tr data-row="' + esc(p.uid) + '" tabindex="0"><td>' + badge + '</td><td><span class="fw-semibold">' + esc(p.host) + '</span>' + (p.host_gone ? ' <span class="badge text-bg-light">' + esc(L('pb.host_gone')) + '</span>' : '') + ' · ' + esc(name) + maxSt + '</td><td class="d-none d-md-table-cell small">' + esc(fmtTime(p.opened)) + '</td><td class="d-none d-sm-table-cell small">' + esc(fmtDur(p.duration)) + '</td><td class="small">' + how + '</td><td class="d-none d-lg-table-cell small text-body-secondary">' + esc(p.channels.join(', ') || '–') + '</td></tr>';
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
			if (!box) { return; }
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
					api('POST', '/api/monitor64/problems/action', { host: p.host_uid, key: p.key, action: a, comment: c }).then(function () {
						toast({ ack: L('pb.done_ack'), unack: L('pb.done_unack'), comment: L('pb.done_comment'), resolve: L('pb.done_resolve') }[a]); load();
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
	var M = { items: [], hosts: [], targets: { groups: [], tags: [] }, form: null };
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
		var end = m.ended && (!m.end || m.ended < m.end) ? m.ended : m.end;
		return esc(fmtTime(m.start)) + ' – ' + esc(end ? fmtTime(end) : L('mt.until_ended'));
	}
	var MST = { running: L('mt.st_running'), planned: L('mt.st_planned'), recurring: L('mt.st_recurring'), ended: L('mt.st_ended') };
	var CLS = { running: 'text-bg-warning', planned: 'text-bg-primary', recurring: 'text-bg-info', ended: 'text-bg-secondary' };
	function render() {
		$('#m64-maint-list').innerHTML = M.items.length ? M.items.map(function (m) {
			var btns = '';
			if (m.status === 'running' || (m.status === 'recurring')) { btns += '<button class="btn btn-sm btn-outline-secondary" type="button" data-end="' + esc(m.uid) + '">' + esc(m.status === 'recurring' ? L('mt.stop') : L('mt.end')) + '</button> '; }
			if (m.status !== 'ended') { btns += '<button class="btn btn-sm btn-outline-secondary" type="button" data-edit="' + esc(m.uid) + '" title="' + esc(L('mt.edit')) + '" aria-label="' + esc(L('mt.edit')) + '"><i class="bi bi-pencil"></i></button> '; }
			btns += '<button class="btn btn-sm btn-outline-secondary" type="button" data-del="' + esc(m.uid) + '" title="' + esc(L('mt.delete')) + '" aria-label="' + esc(L('mt.delete')) + '"><i class="bi bi-trash"></i></button>';
			return '<tr' + (m.status === 'ended' ? ' class="text-body-secondary"' : '') + '><td class="fw-semibold">' + esc(m.title || L('mt.no_title')) + '<div class="small fw-normal text-body-secondary">' + esc(L('mt.by', { w: whoTxt(m.by) })) + '</div></td><td class="small">' + esc(targetsText(m)) + '</td>' +
				'<td class="d-none d-md-table-cell small">' + timeText(m) + '</td><td><span class="badge ' + CLS[m.status] + '">' + esc(MST[m.status] || m.status) + '</span>' + (m.status === 'recurring' && m.running ? ' <span class="badge text-bg-warning">' + esc(L('mt.st_running')) + '</span>' : '') + '</td><td class="text-end text-nowrap">' + btns + '</td></tr>';
		}).join('') : '<tr><td colspan="5" class="text-center text-body-secondary p-4">' + esc(L('mt.none')) + '</td></tr>';
	}
	function load() { api('GET', '/api/monitor64/maintenance').then(function (d) { M.items = d.items || []; M.hosts = d.hosts || []; M.targets = d.targets || M.targets; render(); }).catch(fail); }
	function isoLocal(d) { return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + 'T' + pad(d.getHours()) + ':' + pad(d.getMinutes()); }
	function form(m) {
		var f = M.form = { uid: m ? m.uid : '', mode: m ? (m.recur ? 'recur' : 'plan') : 'now' };
		var sel = { hosts: (m && m.hosts) || [], groups: (m && m.groups) || [], tags: (m && m.tags) || [] };
		var groups = [];
		M.hosts.forEach(function (h) { if (groups.indexOf(h.group) < 0) { groups.push(h.group); } });
		var now = new Date(), later = new Date(now.getTime() + 3600000);
		var html = '<div class="card mb-3 border-primary"><div class="card-body"><div class="row g-3"><div class="col-lg-6"><div class="form-label">' + esc(L('mt.systems')) + '</div><div class="maint-pick">' +
			groups.map(function (g) {
				return '<div class="small fw-semibold mt-1"><input class="form-check-input me-1" type="checkbox" data-mg="' + esc(g) + '"' + (sel.groups.indexOf(g) >= 0 ? ' checked' : '') + ' id="m64-mg-' + esc(g) + '" aria-label="' + esc(targetLabel('group', g)) + '"><label for="m64-mg-' + esc(g) + '">' + esc(g ? targetLabel('group', g) : L('ov.no_group')) + '</label></div>' +
					M.hosts.filter(function (h) { return h.group === g; }).map(function (h) { return '<div class="form-check ms-3"><input class="form-check-input" type="checkbox" data-mh="' + esc(h.uid) + '" id="m64-mh-' + esc(h.uid) + '"' + (sel.hosts.indexOf(h.uid) >= 0 ? ' checked' : '') + '><label class="form-check-label small" for="m64-mh-' + esc(h.uid) + '">' + esc(h.name) + '</label></div>'; }).join('');
			}).join('') + (M.hosts.length ? '' : '<div class="small text-body-secondary">' + esc(L('mt.no_hosts')) + '</div>') + '</div>' +
			(M.targets.tags.length ? '<div class="small text-body-secondary mt-1">' + esc(L('mt.by_tag')) + ' ' + M.targets.tags.map(function (t) { return '<span class="chip' + (sel.tags.indexOf(t) >= 0 ? ' active' : '') + '" data-mt="' + esc(t) + '" role="button" tabindex="0">' + esc(t) + '</span>'; }).join(' ') + '</div>' : '') +
			'<div class="small text-body-secondary mt-1">' + esc(L('mt.group_hint')) + '</div></div>' +
			'<div class="col-lg-6"><div class="form-label">' + esc(L('mt.when')) + '</div><div class="btn-group btn-group-sm w-100 mb-2">' + [['now', L('mt.m_now')], ['plan', L('mt.m_plan')], ['recur', L('mt.m_recur')]].map(function (x) { return '<button class="btn btn-outline-secondary' + (f.mode === x[0] ? ' active' : '') + '" type="button" data-mode="' + x[0] + '">' + esc(x[1]) + '</button>'; }).join('') + '</div>' +
			'<div data-mm="now"><select class="form-select form-select-sm" id="m64-mf-dur" aria-label="' + esc(L('mt.duration')) + '">' + [[30, L('mt.for', { d: fmtDur(1800) })], [60, L('mt.for', { d: fmtDur(3600) })], [120, L('mt.for', { d: fmtDur(7200) })], [240, L('mt.for', { d: fmtDur(14400) })], [0, L('mt.until_ended')]].map(function (o, i) { return '<option value="' + o[0] + '"' + (i === 1 ? ' selected' : '') + '>' + esc(o[1]) + '</option>'; }).join('') + '</select></div>' +
			'<div data-mm="plan" class="row g-2"><div class="col-6"><label class="small" for="m64-mf-from">' + esc(L('mt.from')) + '</label><input class="form-control form-control-sm" type="datetime-local" id="m64-mf-from" value="' + esc(m && m.start && !m.recur ? isoLocal(new Date(m.start)) : isoLocal(now)) + '"></div><div class="col-6"><label class="small" for="m64-mf-to">' + esc(L('mt.to')) + '</label><input class="form-control form-control-sm" type="datetime-local" id="m64-mf-to" value="' + esc(m && m.end && !m.recur ? isoLocal(new Date(m.end)) : isoLocal(later)) + '"></div></div>' +
			'<div data-mm="recur" class="row g-2"><div class="col-12 d-flex flex-wrap gap-2">' + DAYS.map(function (d) { var on = m && m.recur ? (!m.recur.days || !m.recur.days.length || m.recur.days.indexOf(d) >= 0) : d === 0; return '<div class="form-check form-check-inline me-1"><input class="form-check-input" type="checkbox" data-day="' + d + '" id="m64-md-' + d + '"' + (on ? ' checked' : '') + '><label class="form-check-label small" for="m64-md-' + d + '">' + esc(dayName(d)) + '</label></div>'; }).join('') + '</div>' +
			'<div class="col-6"><label class="small" for="m64-mf-rf">' + esc(L('mt.from')) + '</label><input class="form-control form-control-sm" type="time" id="m64-mf-rf" value="' + esc(m && m.recur ? m.recur.from : '02:00') + '"></div><div class="col-6"><label class="small" for="m64-mf-rt">' + esc(L('mt.to')) + '</label><input class="form-control form-control-sm" type="time" id="m64-mf-rt" value="' + esc(m && m.recur ? m.recur.to : '04:00') + '"></div></div>' +
			'<label class="form-label mt-2" for="m64-mf-title">' + esc(L('mt.reason')) + '</label><input class="form-control form-control-sm" id="m64-mf-title" maxlength="200" value="' + esc(m ? m.title : '') + '" placeholder="' + esc(L('mt.reason_ph')) + '"></div></div></div>' +
			'<div class="card-footer d-flex gap-2"><button class="btn btn-outline-secondary btn-sm" type="button" id="m64-mf-cancel">' + esc(L('cancel')) + '</button><button class="btn btn-primary btn-sm ms-auto" type="button" id="m64-mf-save">' + esc(m ? L('save') : L('mt.save')) + '</button></div></div>';
		var box = $('#m64-maint-form');
		box.innerHTML = html;
		function showMode() { $$('[data-mm]', box).forEach(function (x) { x.classList.toggle('d-none', x.dataset.mm !== f.mode); }); $$('[data-mode]', box).forEach(function (b) { b.classList.toggle('active', b.dataset.mode === f.mode); }); }
		showMode();
		$$('[data-mode]', box).forEach(function (b) { b.onclick = function () { f.mode = b.dataset.mode; showMode(); }; });
		$$('[data-mt]', box).forEach(function (c) { c.onclick = function () { c.classList.toggle('active'); }; });
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
			api(f.uid ? 'PUT' : 'POST', '/api/monitor64/maintenance' + (f.uid ? '/' + encodeURIComponent(f.uid) : ''), body).then(function () { box.innerHTML = ''; toast(L('mt.saved_toast')); load(); }).catch(fail);
		};
		box.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
	}
	$('#m64-maint-new').onclick = function () { form(null); };
	root.addEventListener('click', function (ev) {
		var e = ev.target.closest('[data-end]');
		if (e) { api('POST', '/api/monitor64/maintenance/' + encodeURIComponent(e.dataset.end) + '/end').then(function () { toast(L('mt.ended_toast')); load(); }).catch(fail); return; }
		var ed = ev.target.closest('[data-edit]');
		if (ed) { M.items.forEach(function (m) { if (m.uid === ed.dataset.edit) { form(m); } }); return; }
		var d = ev.target.closest('[data-del]');
		if (d) { confirmBox(L('mt.delete'), L('mt.delete_confirm'), L('mt.delete'), function () { api('DELETE', '/api/monitor64/maintenance/' + encodeURIComponent(d.dataset.del)).then(function () { toast(L('mt.deleted_toast')); load(); }).catch(fail); }); }
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
		api('PUT', '/api/monitor64/rules/std', { rules: rules }).then(function (r) { toast(L('rl.std_saved', { n: (r.changed || []).length })); loadOvr(); }).catch(fail);
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
				var kl = x.key ? x.name : L('rl.own_kind', { c: (D.cats || {})[catOf(x.kind)] || x.kind });
				return '<tr class="clickable" data-goto="/monitor64/host/' + encodeURIComponent(x.host_uid) + (x.key ? '#svc=' + encodeURIComponent(x.key) : '') + '"><td class="fw-semibold">' + esc(x.host) + '</td><td>' + esc(kl) + '</td><td class="text-end small">' + esc(ruleSummary(x.rule)) + '</td><td class="text-end"><i class="bi bi-chevron-right text-body-tertiary"></i></td></tr>';
			}).join('') + (own.length ? '' : '<tr><td class="small text-body-secondary">' + esc(L('rl.own_none')) + '</td></tr>') + '</tbody></table></div></div>';
	}
	function catOf(kind) { var m = { fs: 'fs', zfs: 'storage', store: 'storage', ds: 'storage', disk: 'disks', 'if': 'network', bond: 'network', vm: 'guests', ct: 'guests', ctr: 'docker' }; return m[kind] || 'system'; }
	function ruleSummary(r) {
		var p = [];
		if (r.mode === 'free') { p.push('< ' + fmtNum(lim(r.warn_free)) + ' / < ' + fmtNum(lim(r.crit_free)) + ' ' + L('unit.gb_free')); }
		else if (r.warn !== undefined || r.crit !== undefined) { p.push((r.warn === undefined ? '…' : fmtNum(lim(r.warn))) + ' / ' + (r.crit === undefined ? '…' : fmtNum(lim(r.crit)))); }
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
		var cur = o ? o.target_type + '|' + o.target : (tOpts.length ? tOpts[0][0] : '');
		if (o && !tOpts.some(function (x) { return x[0] === cur; })) { tOpts.push([cur, targetLabel(o.target_type, o.target)]); }
		var kinds = (D.kinds || []);
		var html = '<div class="card mb-3 border-primary"><div class="card-header fw-semibold">' + esc(o ? L('rl.edit') : L('rl.new')) + (o ? '' : ' <span class="small text-body-secondary fw-normal">– ' + esc(L('rl.new_sub')) + '</span>') + '</div><div class="card-body"><div class="row g-2">' +
			'<div class="col-md-4"><label class="form-label small mb-0" for="m64-nf-t">' + esc(L('rl.for_target')) + '</label><select class="form-select form-select-sm" id="m64-nf-t">' + tOpts.map(function (x) { return '<option value="' + esc(x[0]) + '"' + (x[0] === cur ? ' selected' : '') + '>' + esc(x[1]) + '</option>'; }).join('') + '</select>' +
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
				$('#m64-nf-w').value = w === undefined || lim(w) === null ? '' : fmtNum(free ? w : w / f);
				$('#m64-nf-c').value = c === undefined || lim(c) === null ? '' : fmtNum(free ? c : c / f);
			}
		}
		function cur() {
			var t = $('#m64-nf-t').value.split('|'), tn = $('#m64-nf-tn').value.trim();
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
				}).catch(function (err) { p.textContent = err.message; });
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
			api(o ? 'PUT' : 'POST', '/api/monitor64/rules/overrides' + (o ? '/' + encodeURIComponent(o.uid) : ''), c).then(function () { box.innerHTML = ''; toast(L('rl.saved_toast')); loadOvr(); }).catch(fail);
		};
		box.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
	}
	root.addEventListener('click', function (ev) {
		var mv = ev.target.closest('[data-mv]');
		if (mv) { api('POST', '/api/monitor64/rules/overrides/' + encodeURIComponent(mv.dataset.mv) + '/move', { dir: parseInt(mv.dataset.dir, 10) }).then(function () { toast(L('rl.moved_toast')); loadOvr(); }).catch(fail); return; }
		var ed = ev.target.closest('[data-ed]');
		if (ed) { R.overrides.forEach(function (o) { if (o.uid === ed.dataset.ed) { ovrForm(o); } }); return; }
		var rm = ev.target.closest('[data-rm]');
		if (rm) { confirmBox(L('rl.delete'), L('rl.delete_confirm'), L('rl.delete'), function () { api('DELETE', '/api/monitor64/rules/overrides/' + encodeURIComponent(rm.dataset.rm)).then(function () { toast(L('rl.deleted_toast')); loadOvr(); }).catch(fail); }); return; }
		var g = ev.target.closest('[data-goto]');
		if (g) { location.href = g.dataset.goto; }
	});
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
		var cur = o ? o.target_type + '|' + o.target : (tOpts.length ? tOpts[0][0] : '');
		if (o && !tOpts.some(function (x) { return x[0] === cur; })) { tOpts.push([cur, targetLabel(o.target_type, o.target)]); }
		var chans = [{ id: 'default', name: L('nf.default') }].concat(N.channels.map(function (c) { return { id: String(c.id), name: c.name }; }));
		function chv(id) { var r = ''; (n.channels || []).forEach(function (c) { if (c.id === id) { r = c.warn ? 'both' : 'crit'; } }); return r; }
		var html = '<div class="card-body border-top"><div class="row g-2">' +
			'<div class="col-md-6"><label class="form-label small mb-0" for="m64-no-t">' + esc(L('rl.for_target')) + '</label><select class="form-select form-select-sm" id="m64-no-t">' + tOpts.map(function (x) { return '<option value="' + esc(x[0]) + '"' + (x[0] === cur ? ' selected' : '') + '>' + esc(x[1]) + '</option>'; }).join('') + '</select></div>' +
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
			var t = $('#m64-no-t').value.split('|');
			if (!t[1]) { toast(L('rl.pick_target'), true); return; }
			var body = { target_type: t[0], target: t[1], replace: $('#m64-no-rep').value === '1', channels: [] };
			$$('[data-och]', box).forEach(function (s) { if (s.value) { body.channels.push({ id: s.dataset.och, warn: s.value === 'both', crit: true }); } });
			var oc = tri('m64-no-oc'), cq = tri('m64-no-cq'), rc = rem('m64-no-rc'), rw = rem('m64-no-rw');
			if (oc !== null) { body.only_crit = oc; }
			if (cq !== null) { body.crit_in_quiet = cq; }
			if (rc !== null) { body.remind_crit = rc; }
			if (rw !== null) { body.remind_warn = rw; }
			api(o ? 'PUT' : 'POST', '/api/monitor64/notify/overrides' + (o ? '/' + encodeURIComponent(o.uid) : ''), body).then(function () { box.innerHTML = ''; toast(L('rl.saved_toast')); load(); }).catch(fail);
		};
	}
	function load() { api('GET', '/api/monitor64/notify').then(function (d) { N.config = d.config || N.config; N.channels = d.channels || []; N.overrides = d.overrides || []; N.quiet = d.quiet; N.targets = d.targets || N.targets; render(); }).catch(fail); }
	$('#m64-nf-save').onclick = function () {
		var body = { channels: [], remind_warn: parseInt($('#m64-remind-warn').value, 10), remind_crit: parseInt($('#m64-remind-crit').value, 10), crit_in_quiet: $('#m64-crit-quiet').checked };
		$$('#m64-nf-channels tr[data-ch]').forEach(function (tr) {
			var w = $('[name=warn]', tr).checked, c = $('[name=crit]', tr).checked;
			if (w || c) { body.channels.push({ id: tr.dataset.ch, warn: w, crit: c }); }
		});
		api('PUT', '/api/monitor64/notify', body).then(function () { toast(L('nf.saved_toast')); load(); }).catch(fail);
	};
	$('#m64-nf-test').onclick = function () { api('POST', '/api/monitor64/notify/test').then(function (r) { toast(L('nf.test_toast', { n: r.channels })); }).catch(fail); };
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
		if (mv) { api('POST', '/api/monitor64/notify/overrides/' + encodeURIComponent(mv.dataset.mv) + '/move', { dir: parseInt(mv.dataset.dir, 10) }).then(function () { toast(L('rl.moved_toast')); load(); }).catch(fail); return; }
		var ed = ev.target.closest('[data-ed]');
		if (ed) { N.overrides.forEach(function (o) { if (o.uid === ed.dataset.ed) { ovrForm(o); } }); return; }
		var rm = ev.target.closest('[data-rm]');
		if (rm) { confirmBox(L('rl.delete'), L('rl.delete_confirm'), L('rl.delete'), function () { api('DELETE', '/api/monitor64/notify/overrides/' + encodeURIComponent(rm.dataset.rm)).then(function () { toast(L('rl.deleted_toast')); load(); }).catch(fail); }); }
	});
	load();
}

// ---------- Einstellungen ----------
function pageSettings() {
	$('#m64-settings-form').onsubmit = function (ev) {
		ev.preventDefault();
		api('PUT', '/api/monitor64/settings', { interval: parseInt($('#m64-interval').value, 10), workers: parseInt($('#m64-workers').value, 10) }).then(function () { toast(L('st.saved_toast')); }).catch(fail);
	};
}

// ---------- Assistent "Host hinzufuegen" ----------
function pageNew() {
	var WZ = { step: 1, kind: null, name: '', address: '', port: '', user: 'monitor64', smart: false, usePw: false, password: '', url: '', token_id: '', token_secret: '', node: '', pin: '',
		test: null, nodeAddr: '', group: '', tags: '', interval: D.interval || 60, adopt: {} };
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
		if (t === 'ssh') { cfg.user = WZ.user; cfg.smart = WZ.smart; if (WZ.port) { cfg.port = parseInt(WZ.port, 10) || 0; } if (WZ.usePw) { out.secret = WZ.password; } }
		if (t === 'pve' || t === 'pbs' || t === 'docker') { cfg.url = WZ.url; cfg.pin = WZ.pin; }
		if (t === 'pve' || t === 'pbs') { cfg.token_id = WZ.token_id; out.secret = WZ.token_secret; }
		if (t === 'pve') { cfg.node = WZ.node; }
		return out;
	}
	function collect() {
		$$('#m64-wizard [data-w]').forEach(function (el) { WZ[el.dataset.w] = el.type === 'checkbox' ? el.checked : el.value.trim(); });
	}
	function render() {
		steps();
		var html = '', k = kind();
		if (WZ.step === 1) {
			html = '<p class="text-body-secondary">' + esc(L('new.intro')) + '</p><div class="row g-3">' + (D.host_kinds || []).map(function (x) {
				var lb = (D.host_kind_labels || {})[x.kind] || [x.kind, ''];
				return '<div class="col-6 col-md-3"><div class="card kind-tile' + (WZ.kind === x.kind ? ' sel' : '') + (x.soon ? ' disabled' : '') + '" data-kind="' + esc(x.kind) + '" role="button" tabindex="0" aria-pressed="' + (WZ.kind === x.kind) + '"><div class="card-body"><i class="bi ' + esc(x.icon) + '"></i><div class="fw-semibold mt-1">' + esc(lb[0]) + '</div><div class="small">' + esc(lb[1]) + '</div>' + (x.soon ? '<span class="badge text-bg-light mt-1">' + esc(L('new.soon')) + '</span>' : '') + '</div></div></div>';
			}).join('') + '</div>';
		} else if (WZ.step === 2) {
			html = '<div class="row g-3"><div class="col-md-6">' + field('name', L('f.name'), WZ.name, ' data-w="name" maxlength="100" placeholder="nas02"') + '</div><div class="col-md-6">' + field('addr', L('f.address'), WZ.address, ' data-w="address" maxlength="253" placeholder="10.0.0.21"') + '</div>';
			if (k.access === 'agent') {
				var cmd = WZ.kind === 'windows' ? 'irm https://node64.de/agent/install.ps1 | iex; monitor64-agent install `\n  --key "' + key + '"' : 'curl -fsSL https://node64.de/agent/install.sh | sudo sh -s -- \\\n  --key "' + key + '"';
				html += '<div class="col-12"><div class="form-label d-flex align-items-center">' + esc(L('new.agent_step1')) + '<button class="btn btn-sm btn-link ms-auto p-0" type="button" data-copy-target="#m64-w-cmd"><i class="bi bi-clipboard"></i> ' + esc(L('copy')) + '</button></div><div class="cmd" id="m64-w-cmd">' + esc(cmd) + '</div>' +
					'<div class="small text-body-secondary mt-1"><i class="bi bi-shield-lock"></i> ' + esc(L('new.agent_safe', { p: D.port || 6465 })) + '</div>' +
					'<div class="small text-body-secondary"><i class="bi bi-wifi-off"></i> ' + esc(L('new.agent_offline')) + ' <code>' + esc(location.origin + '/monitor64/agent/') + '</code></div></div>' +
					'<div class="col-12"><div class="form-label">' + esc(L('new.agent_step2')) + '</div><div class="small">' + esc(L('new.agent_fp')) + '</div></div>' +
					'<div class="col-12"><details><summary class="small text-body-secondary">' + esc(L('advanced')) + '</summary><div class="pt-2" style="max-width:12rem">' + field('port', L('acc.port'), WZ.port, ' data-w="port" type="number" min="1" max="65535" placeholder="' + (D.port || 6465) + '"') + '</div></details></div>';
			} else if (k.access === 'ssh') {
				var line = 'restrict,from="' + (WZ.nodeAddr || L('new.node_ip')) + '" ' + key;
				html += '<div class="col-md-6">' + field('user', L('acc.user'), WZ.user, ' data-w="user" maxlength="32"') + '</div>' +
					'<div class="col-12"><div class="form-label d-flex align-items-center">' + esc(L('new.ssh_key')) + '<button class="btn btn-sm btn-link ms-auto p-0" type="button" data-copy-target="#m64-w-cmd"><i class="bi bi-clipboard"></i> ' + esc(L('copy')) + '</button></div><div class="cmd" id="m64-w-cmd">' + esc("echo '" + line + "' >> ~" + (WZ.user || 'monitor64') + '/.ssh/authorized_keys') + '</div>' +
					'<div class="small text-body-secondary mt-1"><i class="bi bi-shield-lock"></i> ' + esc(L('new.ssh_safe')) + '</div>' +
					'<div class="form-check mt-2"><input class="form-check-input" type="checkbox" id="m64-w-smart" data-w="smart"' + (WZ.smart ? ' checked' : '') + '><label class="form-check-label small" for="m64-w-smart">' + esc(L('new.smart')) + ' <code>' + esc((WZ.user || 'monitor64') + ' ALL=(root) NOPASSWD: /usr/sbin/smartctl') + '</code></label></div>' +
					'<details class="mt-2"' + (WZ.usePw ? ' open' : '') + '><summary class="small text-body-secondary">' + esc(L('advanced')) + '</summary><div class="pt-2 row g-2"><div class="col-md-4">' + field('port', L('acc.port'), WZ.port, ' data-w="port" type="number" min="1" max="65535" placeholder="22"') + '</div>' +
					'<div class="col-12"><div class="form-check"><input class="form-check-input" type="checkbox" id="m64-w-pw" data-w="usePw"' + (WZ.usePw ? ' checked' : '') + '><label class="form-check-label small" for="m64-w-pw">' + esc(L('new.pw_auth')) + '</label></div>' +
					'<input class="form-control form-control-sm mt-1' + (WZ.usePw ? '' : ' d-none') + '" type="password" id="m64-w-pass" data-w="password" autocomplete="new-password" aria-label="' + esc(L('acc.secret')) + '" value="' + esc(WZ.password) + '"></div></div></details></div>';
			} else if (k.access === 'pve' || k.access === 'pbs') {
				var port = k.access === 'pve' ? 8006 : 8007;
				html += '<div class="col-12">' + field('url', 'URL', WZ.url, ' data-w="url" maxlength="512" placeholder="https://' + esc(WZ.address || '10.0.0.10') + ':' + port + '"') + '</div>' +
					'<div class="col-md-6">' + field('tid', L('new.token_id'), WZ.token_id, ' data-w="token_id" maxlength="128" placeholder="' + (k.access === 'pve' ? 'monitor@pve!node64' : 'monitor@pbs!node64') + '"') + '</div>' +
					'<div class="col-md-6">' + field('tsec', L('new.token_secret'), WZ.token_secret, ' data-w="token_secret" type="password" autocomplete="new-password"') + '</div>' +
					'<div class="col-12"><div class="form-label d-flex align-items-center">' + esc(L('new.token_cmd')) + '<button class="btn btn-sm btn-link ms-auto p-0" type="button" data-copy-target="#m64-w-cmd"><i class="bi bi-clipboard"></i> ' + esc(L('copy')) + '</button></div><div class="cmd" id="m64-w-cmd">' + esc(k.access === 'pve' ?
						'pveum user add monitor@pve\npveum aclmod / -user monitor@pve -role PVEAuditor\npveum user token add monitor@pve node64 --privsep 0' :
						'proxmox-backup-manager user create monitor@pbs\nproxmox-backup-manager user generate-token monitor@pbs node64\nproxmox-backup-manager acl update / Audit --auth-id \'monitor@pbs!node64\'') + '</div>' +
					'<div class="small text-body-secondary mt-1"><i class="bi bi-info-circle"></i> ' + esc(L('new.api_hint')) + '</div></div>' +
					'<div class="col-12"><details><summary class="small text-body-secondary">' + esc(L('advanced')) + '</summary><div class="pt-2 row g-2">' + (k.access === 'pve' ? '<div class="col-md-6">' + field('node', L('new.node'), WZ.node, ' data-w="node" maxlength="64"') + '</div>' : '') + '<div class="col-md-6">' + field('pin', L('new.pin'), WZ.pin, ' data-w="pin" maxlength="128"') + '</div></div></details></div>';
			} else if (k.access === 'docker') {
				html += '<div class="col-12">' + field('url', 'URL', WZ.url, ' data-w="url" maxlength="512" placeholder="unix:///var/run/docker.sock"') + '<div class="form-text">' + esc(L('new.docker_hint')) + '</div></div>' +
					'<div class="col-12"><details><summary class="small text-body-secondary">' + esc(L('advanced')) + '</summary><div class="pt-2">' + field('pin', L('new.pin'), WZ.pin, ' data-w="pin" maxlength="128"') + '</div></details></div>';
			}
			html += '<div class="col-12"><button class="btn btn-outline-primary btn-sm" type="button" id="m64-w-test"><i class="bi bi-plug"></i> ' + esc(L('new.test')) + '</button> <span class="small ms-2" id="m64-w-res">' + (WZ.test ? testHTML(WZ.test) : '') + '</span></div></div>';
		} else if (WZ.step === 3) {
			var svcs = (WZ.test && WZ.test.services) || [];
			if (!svcs.length) {
				html = '<p class="text-body-secondary"><i class="bi bi-info-circle"></i> ' + esc(L('new.no_test')) + '</p>';
			} else {
				var cats = {};
				svcs.forEach(function (s) { var c = catOfKind(s.kind); (cats[c] = cats[c] || []).push(s); });
				html = '<p class="text-body-secondary">' + esc(L('new.found', { n: svcs.length })) + '</p><div class="mb-2"><button class="btn btn-sm btn-link p-0 me-3" type="button" data-all="1">' + esc(L('new.all')) + '</button><button class="btn btn-sm btn-link p-0" type="button" data-all="0">' + esc(L('new.none')) + '</button></div>';
				(D.cat_order || []).forEach(function (c) {
					if (!cats[c]) { return; }
					html += '<div class="fw-semibold small mt-2">' + esc((D.cats || {})[c] || c) + '</div><div class="row g-1">' + cats[c].map(function (s) {
						var id = 'm64-wa-' + btoa(unescape(encodeURIComponent(s.key))).replace(/[^a-z0-9]/gi, '');
						return '<div class="col-md-6 col-xl-4"><div class="form-check"><input class="form-check-input" type="checkbox" data-adopt="' + esc(s.key) + '" id="' + id + '"' + (WZ.adopt[s.key] ? ' checked' : '') + '><label class="form-check-label small" for="' + id + '">' + esc(s.name || s.key) + '</label></div></div>';
					}).join('') + '</div>';
				});
			}
		} else {
			var groups = (D.targets && D.targets.groups) || [];
			html = '<div class="row g-3"><div class="col-md-6"><label class="form-label" for="m64-w-group">' + esc(L('f.group')) + '</label><input class="form-control" id="m64-w-group" data-w="group" list="m64-w-groups" maxlength="64" value="' + esc(WZ.group) + '"><datalist id="m64-w-groups">' + groups.map(function (g) { return '<option value="' + esc(g) + '">'; }).join('') + '</datalist></div>' +
				'<div class="col-md-6"><label class="form-label" for="m64-w-tags">' + esc(L('f.tags')) + '</label><input class="form-control" id="m64-w-tags" data-w="tags" value="' + esc(WZ.tags) + '"><div class="form-text">' + esc(L('new.tags_hint')) + '</div></div>' +
				'<div class="col-md-6"><label class="form-label" for="m64-w-iv">' + esc(L('f.interval')) + '</label><select class="form-select" id="m64-w-iv" data-w="interval">' + [30, 60, 120, 300, 600, 900].map(function (s) { return '<option value="' + s + '"' + (String(s) === String(WZ.interval) ? ' selected' : '') + '>' + esc(s < 60 ? L('iv.sec', { n: s }) : fmtDur(s)) + '</option>'; }).join('') + '</select></div>' +
				'<div class="col-12 small text-body-secondary">' + esc(L('new.summary', { n: WZ.name, a: WZ.address, k: kl(WZ.kind), s: Object.keys(WZ.adopt).filter(function (x) { return WZ.adopt[x]; }).length })) + '</div></div>';
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
		var t = $('#m64-w-test');
		if (t) { t.onclick = testConn; }
	}
	function catOfKind(k) { var m = { cpu: 'system', load: 'system', mem: 'system', swap: 'system', temp: 'system', systemd: 'system', updates: 'system', reboot: 'system', cluster: 'system', ha: 'system', ceph: 'system', fs: 'fs', zfs: 'storage', raid: 'storage', store: 'storage', ds: 'storage', disk: 'disks', 'if': 'network', bond: 'network', vm: 'guests', ct: 'guests', backup: 'guests', job: 'guests', ctr: 'docker', winsvc: 'winsvc', local: 'local' }; return m[k] || 'other'; }
	function testHTML(r) {
		if (r.ok && !r.error) { return '<span class="text-success"><i class="bi bi-check-circle-fill"></i> ' + esc(L('new.test_ok', { n: r.services.length, ms: r.ms })) + '</span>' + (r.fingerprint ? '<div class="small mt-1">' + esc(L('new.fp')) + ' <code>' + esc(r.fingerprint) + '</code></div>' : ''); }
		if (r.ok) { return '<span class="text-warning-emphasis"><i class="bi bi-exclamation-triangle"></i> ' + esc(L('new.test_partial', { n: r.services.length, e: r.error })) + '</span>'; }
		return '<span class="text-danger"><i class="bi bi-x-circle-fill"></i> ' + esc(r.error || L('new.test_fail')) + '</span>';
	}
	function nodeAddr() {
		if (!WZ.address) { return; }
		api('GET', '/api/monitor64/nodeaddr?target=' + encodeURIComponent(WZ.address)).then(function (r) { if (r.addr && r.addr !== WZ.nodeAddr) { WZ.nodeAddr = r.addr; render(); } }).catch(function () {});
	}
	function testConn() {
		collect();
		if (!WZ.address) { toast(L('new.need_address'), true); return; }
		var res = $('#m64-w-res');
		res.innerHTML = '<span class="spinner-border spinner-border-sm"></span> ' + esc(L('new.testing'));
		api('POST', '/api/monitor64/test', { address: WZ.address, access: access() }).then(function (r) {
			WZ.test = r;
			WZ.adopt = {};
			(r.services || []).forEach(function (s) { WZ.adopt[s.key] = !!s['default']; });
			res.innerHTML = testHTML(r);
		}).catch(function (e) { res.innerHTML = '<span class="text-danger">' + esc(e.message) + '</span>'; });
	}
	$('#m64-wizard').addEventListener('click', function (ev) {
		var t = ev.target.closest('[data-kind]');
		if (t && !t.classList.contains('disabled')) { WZ.kind = t.dataset.kind; WZ.test = null; render(); return; }
		var a = ev.target.closest('[data-all]');
		if (a) { $$('[data-adopt]').forEach(function (c) { c.checked = a.dataset.all === '1'; WZ.adopt[c.dataset.adopt] = c.checked; }); }
	});
	$('#m64-wizard').addEventListener('change', function (ev) { if (ev.target.dataset.adopt !== undefined) { WZ.adopt[ev.target.dataset.adopt] = ev.target.checked; } });
	$('#m64-wizard').addEventListener('keydown', function (ev) { if ((ev.key === 'Enter' || ev.key === ' ') && ev.target.dataset.kind) { ev.preventDefault(); ev.target.click(); } });
	$('#m64-back').addEventListener('click', function (ev) { if (WZ.step > 1) { ev.preventDefault(); collect(); WZ.step--; render(); } });
	$('#m64-next').onclick = function () {
		collect();
		if (WZ.step === 2) {
			if (!WZ.name || !WZ.address) { toast(L('new.need_name'), true); return; }
		}
		if (WZ.step < 4) { WZ.step++; render(); if (WZ.step === 2 && kind() && kind().access === 'ssh') { nodeAddr(); } return; }
		var acc = access();
		if (WZ.test && WZ.test.fingerprint) { acc.hostkey = WZ.test.fingerprint; }
		var body = { name: WZ.name, address: WZ.address, kind: WZ.kind, group: WZ.group, tags: WZ.tags.split(/[,\s]+/).filter(Boolean), interval_sec: parseInt(WZ.interval, 10) || 0, notes: '', paused: false,
			agent_autoupdate: true, accesses: [acc], services: (WZ.test && WZ.test.services) || [], adopt: Object.keys(WZ.adopt).filter(function (x) { return WZ.adopt[x]; }) };
		$('#m64-next').disabled = true;
		api('POST', '/api/monitor64/hosts', body).then(function (r) { location.href = '/monitor64/host/' + encodeURIComponent(r.uid); }).catch(function (e) { $('#m64-next').disabled = false; fail(e); });
	};
	render();
}

var PAGES = { overview: pageOverview, host: pageHost, problems: pageProblems, maint: pageMaint, rules: pageRules, notify: pageNotify, settings: pageSettings, 'new': pageNew };
var fn = PAGES[root.dataset.m64Page];
if (fn) { fn(); }
})();
