// Proxmox VE: Graphen der Detailseite (CPU, RAM/Disk, Netz, Disk-I/O) aus /api/healthchecks/proxmox/.../series.
// Vanilla-JS + Chart.js (lokal, wie die Healthchecks-Diagramme); Farben aus den Bootstrap-Variablen (hell/dunkel).
// Kanaele einer Node bzw. eines Gasts: ein geaenderter Haken heisst eigene Auswahl („erben“ -> „eigene Kanaele“).
document.addEventListener("change", function (ev) {
	"use strict";
	var t = ev.target;
	if (!t || t.name !== "channels" || !t.form) { return; }
	var mode = t.form.querySelector('select[name="ch_mode"]');
	if (mode && mode.value !== "own") { mode.value = "own"; }
});

(function () {
	"use strict";
	var box = document.getElementById("pve-charts");
	if (!box || !window.Chart) { return; }
	var css = getComputedStyle(document.documentElement);
	var color = function (name, fallback) { return (css.getPropertyValue(name) || fallback).trim(); };
	var cPrimary = color("--bs-primary", "#0d6efd"), cInfo = color("--bs-info", "#0dcaf0"), cSuccess = color("--bs-success", "#198754"),
		cWarn = color("--bs-warning", "#ffc107"), cDanger = color("--bs-danger", "#dc3545"), cMuted = color("--bs-secondary", "#6c757d");
	var spans = { "1h": 36e5, "24h": 24 * 36e5, "7d": 7 * 864e5, "30d": 30 * 864e5 };
	var L = function (k) { return box.getAttribute("data-l-" + k) || k; };
	var note = document.getElementById("pve-chart-note");
	var charts = {};

	function bytes(n) {
		var u = ["B/s", "KB/s", "MB/s", "GB/s", "TB/s"], i = 0;
		while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
		return (i || n < 10 ? Math.round(n * 10) / 10 : Math.round(n)) + " " + u[i];
	}

	function fmt(ms, range, long) {
		var t = new Date(ms);
		if (long || range === "1h" || range === "24h") {
			var time = t.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
			return long && range !== "1h" ? t.toLocaleDateString([], { day: "2-digit", month: "2-digit" }) + " " + time : time;
		}
		return t.toLocaleDateString([], { day: "2-digit", month: "2-digit" });
	}

	// Luecken (gestoppt, nicht erreichbar) nicht ueberbruecken: Abstand weit ueber der Schrittweite
	function withGaps(pts, step) {
		var out = [];
		for (var i = 0; i < pts.length; i++) {
			if (i > 0 && pts[i].x - pts[i - 1].x > 2.5 * step) { out.push({ x: pts[i - 1].x + 1, y: null }); }
			out.push(pts[i]);
		}
		return out;
	}

	function line(label, col, data, step, extra) {
		var ds = { label: label, borderColor: col, backgroundColor: col, borderWidth: 1.5, tension: 0.2, fill: false, spanGaps: false, pointRadius: 0, pointHoverRadius: 3,
			data: withGaps(data, step) };
		for (var k in extra || {}) { ds[k] = extra[k]; }
		return ds;
	}

	function draw(id, datasets, range, xmin, xmax, yfmt, ymax) {
		var canvas = document.getElementById(id);
		if (!canvas) { return; }
		if (charts[id]) { charts[id].destroy(); }
		var y = { beginAtZero: true, ticks: { callback: yfmt } };
		if (ymax) { y.suggestedMax = ymax; y.max = ymax; }
		charts[id] = new Chart(canvas.getContext("2d"), {
			type: "line", data: { datasets: datasets },
			options: {
				responsive: true, maintainAspectRatio: false, animation: false, interaction: { mode: "nearest", axis: "x", intersect: false },
				scales: { x: { type: "linear", min: xmin, max: xmax, ticks: { maxTicksLimit: 8, callback: function (v) { return fmt(v, range, false); } } }, y: y },
				plugins: { legend: { display: datasets.length > 1, position: "bottom", labels: { boxWidth: 12 } },
					tooltip: { callbacks: {
						title: function (items) { return items.length ? fmt(items[0].parsed.x, range, true) : ""; },
						label: function (it) { return it.dataset.label + ": " + (it.parsed.y === null ? "–" : yfmt(it.parsed.y)); }
					} } }
			}
		});
	}

	var pct = function (v) { return (Math.round(v * 10) / 10) + " %"; };

	function load(range) {
		fetch(box.getAttribute("data-url") + "&range=" + encodeURIComponent(range), { credentials: "same-origin" })
			.then(function (r) { return r.json(); })
			.then(function (d) {
				var pts = (d && d.points) || [], step = ((d && d.step_seconds) || 60) * 1000;
				var now = Date.now(), xmin = now - (spans[range] || spans["24h"]);
				var m = function (f) { return pts.map(function (p) { return { x: new Date(p.t).getTime(), y: f(p) }; }); };
				var disk = pts.some(function (p) { return p.disk !== null && p.disk !== undefined; });
				draw("pve-chart-cpu", [line(L("cpu"), cPrimary, m(function (p) { return p.cpu; }), step),
					line(L("cpumax"), cMuted, m(function (p) { return p.cpu_max; }), step, { borderDash: [4, 3], borderWidth: 1 })], range, xmin, now, pct, 100);
				var md = [line(L("mem"), cSuccess, m(function (p) { return p.mem; }), step)];
				if (disk) { md.push(line(L("disk"), cWarn, m(function (p) { return p.disk === null ? null : p.disk; }), step)); }
				draw("pve-chart-mem", md, range, xmin, now, pct, 100);
				draw("pve-chart-net", [line(L("in"), cInfo, m(function (p) { return p.net_in; }), step), line(L("out"), cPrimary, m(function (p) { return p.net_out; }), step)], range, xmin, now, bytes);
				draw("pve-chart-io", [line(L("read"), cSuccess, m(function (p) { return p.disk_read; }), step), line(L("write"), cDanger, m(function (p) { return p.disk_write; }), step)], range, xmin, now, bytes);
				if (note) {
					var n = Math.round(step / 60000);
					note.textContent = pts.length ? (box.getAttribute("data-note-" + n) || "") : (box.getAttribute("data-empty") || "");
				}
			}).catch(function () {});
	}

	document.querySelectorAll("#pve-ranges button").forEach(function (b) {
		b.addEventListener("click", function () {
			document.querySelectorAll("#pve-ranges button").forEach(function (x) { x.classList.remove("active"); });
			b.classList.add("active");
			load(b.getAttribute("data-range"));
		});
	});
	load("24h");
})();
