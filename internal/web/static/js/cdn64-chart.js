// CDN64-Verkehr als Diagramm, gemeinsam fuer das Dashboard und die Uebersicht der Proxy-Hosts (beide sehen gleich
// aus): Anfragen und Abgewiesene gestapelt, Datenmenge als Linie. Daten aus /api/cdn64/stats (je Stunde, UTC);
// Luecken werden aufgefuellt, ab 8 Tagen je Tag zusammengefasst. Vanilla-JS + Chart.js (lokal).
(function () {
	"use strict";
	var locale = document.documentElement.lang === "en" ? "en-GB" : "de-DE";
	var nf = new Intl.NumberFormat(locale);

	function css(name, def) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || def; }

	function bytes(n) {
		var u = ["B", "KB", "MB", "GB", "TB"], i = 0;
		while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
		return (i ? n.toFixed(1) : n) + " " + u[i];
	}

	// series: Punkte {t, ok, blocked, req, bytes, err} ueber den ganzen Zeitraum
	function series(timeline, hours) {
		var by = {};
		(timeline || []).forEach(function (p) { by[new Date(p.hour).getTime()] = p; });
		var now = Math.floor(Date.now() / 3600e3) * 3600e3;
		var out = [];
		for (var i = hours - 1; i >= 0; i--) {
			var t = now - i * 3600e3, p = by[t] || {};
			var blocked = p.blocked || 0, conn = p.conn_blocked || 0;
			// requests enthaelt die abgewiesenen Anfragen, nicht die abgewiesenen Verbindungen (conn_blocked)
			out.push({ t: t, ok: Math.max(0, (p.requests || 0) - (blocked - conn)), blocked: blocked, req: p.requests || 0, bytes: p.bytes || 0,
				err: (p["4xx"] || 0) + (p["5xx"] || 0) });
		}
		if (hours <= 168) { return { pts: out, daily: false, hours: hours }; }
		var days = [], cur = null;
		out.forEach(function (p) {
			var d = new Date(p.t); d.setHours(0, 0, 0, 0);
			if (!cur || cur.t !== d.getTime()) { cur = { t: d.getTime(), ok: 0, blocked: 0, req: 0, bytes: 0, err: 0 }; days.push(cur); }
			["ok", "blocked", "req", "bytes", "err"].forEach(function (k) { cur[k] += p[k]; });
		});
		return { pts: days, daily: true, hours: hours };
	}

	function label(t, s) {
		var o = s.daily ? { day: "2-digit", month: "2-digit" } : (s.hours > 24 ? { weekday: "short", hour: "2-digit", minute: "2-digit" } : { hour: "2-digit", minute: "2-digit" });
		return new Date(t).toLocaleString(locale, o);
	}

	// config: Chart.js-Einstellungen; L = Beschriftungen {requests, blocked, bytes}
	function config(s, L) {
		var pts = s.pts;
		return {
			type: "bar",
			data: { labels: pts.map(function (p) { return label(p.t, s); }), datasets: [
				{ type: "bar", label: L.requests, data: pts.map(function (p) { return p.ok; }), backgroundColor: css("--bs-primary", "#0d6efd"), borderRadius: 3, stack: "r", yAxisID: "y" },
				{ type: "bar", label: L.blocked, data: pts.map(function (p) { return p.blocked; }), backgroundColor: css("--bs-danger", "#dc3545"), borderRadius: 3, stack: "r", yAxisID: "y" },
				{ type: "line", label: L.bytes, data: pts.map(function (p) { return p.bytes; }), borderColor: css("--bs-info", "#0dcaf0"), backgroundColor: css("--bs-info", "#0dcaf0"),
					pointRadius: 0, tension: 0.3, yAxisID: "y1" }
			] },
			options: {
				responsive: true, maintainAspectRatio: false, animation: false, interaction: { mode: "index", intersect: false },
				scales: {
					x: { stacked: true, grid: { display: false }, ticks: { autoSkip: true, maxRotation: 0 } },
					y: { stacked: true, beginAtZero: true, ticks: { precision: 0, callback: function (v) { return nf.format(v); } } },
					y1: { beginAtZero: true, position: "right", grid: { drawOnChartArea: false }, ticks: { callback: function (v) { return bytes(v); } } }
				},
				plugins: { legend: { position: "bottom" }, tooltip: { callbacks: { label: function (ctx) {
					return ctx.dataset.label + ": " + (ctx.dataset.yAxisID === "y1" ? bytes(ctx.parsed.y) : nf.format(ctx.parsed.y));
				} } } }
			}
		};
	}

	window.Node64CDNChart = { series: series, config: config, bytes: bytes, nf: nf };
})();
