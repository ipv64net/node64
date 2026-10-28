// Oeffentliche Statusseite: Zeiten lokal, Tooltips der Tagesbalken, Details per Klick, Neuladen.
// Ohne JS bleibt alles lesbar (Progressive Enhancement).
(function () {
var d = document, h = d.documentElement, L = JSON.parse(d.getElementById('L').textContent), lg = h.lang || 'de', open = 0;
var B = {up: 'i', partial: 's', down: 'b', maintenance: 'u'};
h.classList.add('js');
function nf(x, n) { return new Intl.NumberFormat(lg, {minimumFractionDigits: n, maximumFractionDigits: n}).format(x); }
function pct(x) { return x == null || x < 0 ? '–' : (x >= 100 ? nf(100, 0) : nf(Math.floor(x * 100) / 100, 2)) + (lg == 'de' ? ' %' : '%'); }
function fmt(s, o) { return String(s).replace(/\{(\w+)\}/g, function (m, k) { return k in o ? o[k] : m; }); }
function dur(ms) {
var m = Math.max(1, Math.round(ms / 6e4));
return m < 60 ? fmt(L.dm, {m: m}) : m < 1440 ? fmt(L.dh, {h: Math.floor(m / 60), m: m % 60}) : fmt(L.dd, {d: Math.floor(m / 1440), h: Math.floor(m % 1440 / 60)});
}
function set(t) { return t && t.slice(0, 4) != '0001'; }
var DT = new Intl.DateTimeFormat(lg, {dateStyle: 'medium', timeStyle: 'short'}), TM = new Intl.DateTimeFormat(lg, {timeStyle: 'short'}), DY = new Intl.DateTimeFormat(lg, {dateStyle: 'medium', timeZone: 'UTC'});
function ft(s, f) { var x = new Date(s); return isNaN(x) ? '' : (f ? TM : DT).format(x); }
d.querySelectorAll('time[datetime]').forEach(function (t) { var x = ft(t.getAttribute('datetime'), t.dataset.f); if (x) t.textContent = x; });
// Tooltip je Tag erst beim Darueberfahren (spart Bytes bei vielen Eintraegen)
d.addEventListener('mouseover', function (e) {
var i = e.target, p = i.parentNode;
if (i.title || !p.classList || !p.classList.contains('bars') || !p.dataset.s) return;
var t = new Date(p.dataset.s + 'T00:00:00Z');
t.setUTCDate(t.getUTCDate() + [].indexOf.call(p.children, i));
i.title = DY.format(t) + ': ' + (L.b[i.tagName.toLowerCase()] || '');
});
// Gruppen: eigene Auf-/Zuklapp-Wahl ueberlebt das Neuladen (Schluessel enthaelt den Problemzustand)
var K = 'st:' + location.pathname, S = {};
try { S = JSON.parse(sessionStorage.getItem(K)) || {}; } catch (e) {}
d.querySelectorAll('details[data-k]').forEach(function (g) {
var k = g.dataset.k;
if (k in S) g.open = S[k];
g.addEventListener('toggle', function () { S[k] = g.open; try { sessionStorage.setItem(K, JSON.stringify(S)); } catch (e) {} });
});
function el(t, c, x) { var e = d.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; }
function get(u) { return fetch(u, {cache: 'no-store', headers: {Accept: 'application/json'}}).then(function (r) { if (!r.ok) throw 0; return r.json(); }); }
function show(p, j) {
p.textContent = '';
if (j.show_uptime !== false) {
var g = el('div', 'dg');
[[pct(j.uptime_24h), L.h24], [pct(j.uptime_7d), L.d7], [pct(j.uptime_30d), L.d30], [j.latency_ms >= 0 ? nf(j.latency_ms, 0) + ' ms' : '–', L.lat]].forEach(function (a) {
var c = el('div'), v = el('b', 0, a[0]); if (a[0] == '–') v.title = L.nodata; c.appendChild(v); c.appendChild(el('span', 0, a[1])); g.appendChild(c);
});
p.appendChild(g);
}
if (set(j.since)) p.appendChild(el('p', 'mu', fmt(L.since, {t: ft(j.since)})));
if (j.hours && j.hours.length) {
p.appendChild(el('div', 'cap', L.hrs));
var b = el('div', 'bars hb');
b.setAttribute('role', 'img'); b.setAttribute('aria-label', L.hrs);
j.hours.forEach(function (x) { var g = B[x.state] || 'q', i = el(g); i.title = String(x.day).slice(11) + ':00 · ' + L.b[g] + (x.uptime >= 0 ? ' · ' + pct(x.uptime) : ''); b.appendChild(i); });
p.appendChild(b);
}
if (j.show_history === false) return;
var n = j.incidents || [];
p.appendChild(el('div', 'cap', n.length ? L.inc : L.noinc));
if (n.length) {
var u = el('ul', 'il');
n.forEach(function (x) {
var li = el('li'); li.appendChild(el('time', 0, ft(x.start)));
li.appendChild(d.createTextNode(' · ' + (set(x.end) ? dur(new Date(x.end) - new Date(x.start)) : L.run) + (x.reason ? ' · ' + x.reason : '')));
u.appendChild(li);
});
p.appendChild(u);
}
}
function tog(r) {
var it = r.parentNode, n = it.nextElementSibling;
if (n && n.classList.contains('det')) { n.remove(); r.setAttribute('aria-expanded', 'false'); open--; return; }
var p = el('li', 'det', L.load), u = L.base + '/item/' + it.dataset.id;
p.id = 'd' + it.dataset.id; p.setAttribute('aria-live', 'polite');
it.after(p); r.setAttribute('aria-expanded', 'true'); r.setAttribute('aria-controls', p.id); open++;
get(u).catch(function () { return get(u + '.json'); }).then(function (j) { show(p, j); }, function () { p.textContent = L.nodet; });
}
d.querySelectorAll('.it>.row').forEach(function (r) { r.tabIndex = 0; r.setAttribute('role', 'button'); r.setAttribute('aria-expanded', 'false'); });
d.addEventListener('click', function (e) {
var a = e.target.closest('a');
if (a) { var t = a.hash && d.getElementById(a.hash.slice(1)), g = t && t.closest('details'); if (g) g.open = true; return; }
var r = e.target.closest('.it>.row'); if (r) tog(r);
});
d.addEventListener('keydown', function (e) {
var r = e.target;
if ((e.key == 'Enter' || e.key == ' ') && r.matches && r.matches('.it>.row')) { e.preventDefault(); tog(r); }
});
// Neuladen: nur wenn nichts aufgeklappt ist und die Seite erreichbar ist (sonst Hinweis, alter Stand bleibt)
var st = d.getElementById('upd');
if (L.refresh > 0) setInterval(function () {
if (open || d.hidden) return;
fetch(location.href, {method: 'HEAD', cache: 'no-store'}).then(function (r) { if (!r.ok) throw 0; location.reload(); }).catch(function () {
if (st && st.firstChild) { st.classList.add('off'); st.firstChild.nodeValue = L.stale + ' '; }
});
}, L.refresh * 1000);
})();
