// CDN64-Verkehr als Diagramm, gemeinsam fuer das Dashboard und die Uebersicht der Proxy-Hosts (beide sehen gleich
// aus): beantwortete Anfragen, 4xx, Fehler (5xx), Abgewiesene und an den Honeypot Gegebene gestapelt, Datenmenge als
// Linie. Daten aus /api/cdn64/stats (je Stunde, UTC);
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

	// series: Punkte {t, ok, c4, err, blocked, decoy, req, bytes, up} ueber den ganzen Zeitraum (bytes = Download zum
	// Besucher, up = Upload vom Besucher) (ok = vom Ziel erfolgreich
	// beantwortet; aeltere Stunden zaehlten Abgewiesene noch bei 4xx, daher nie unter 0)
	function series(timeline, hours) {
		var by = {};
		(timeline || []).forEach(function (p) { by[new Date(p.hour).getTime()] = p; });
		var now = Math.floor(Date.now() / 3600e3) * 3600e3;
		var out = [];
		for (var i = hours - 1; i >= 0; i--) {
			var t = now - i * 3600e3, p = by[t] || {};
			var blocked = p.blocked || 0, conn = p.conn_blocked || 0, decoy = p.decoy || 0, c4 = p["4xx"] || 0, err = p["5xx"] || 0;
			// requests enthaelt die abgewiesenen und an den Koeder gegebenen Anfragen, nicht die abgewiesenen Verbindungen
			out.push({ t: t, ok: Math.max(0, (p.requests || 0) - (blocked - conn) - decoy - c4 - err), c4: c4, err: err, blocked: blocked, decoy: decoy,
				req: p.requests || 0, bytes: p.bytes || 0, up: p.bytes_in || 0 });
		}
		if (hours <= 168) { return { pts: out, daily: false, hours: hours }; }
		var days = [], cur = null;
		out.forEach(function (p) {
			var d = new Date(p.t); d.setHours(0, 0, 0, 0);
			if (!cur || cur.t !== d.getTime()) { cur = { t: d.getTime(), ok: 0, c4: 0, err: 0, blocked: 0, decoy: 0, req: 0, bytes: 0, up: 0 }; days.push(cur); }
			["ok", "c4", "err", "blocked", "decoy", "req", "bytes", "up"].forEach(function (k) { cur[k] += p[k]; });
		});
		return { pts: days, daily: true, hours: hours };
	}

	function label(t, s) {
		var o = s.daily ? { day: "2-digit", month: "2-digit" } : (s.hours > 24 ? { weekday: "short", hour: "2-digit", minute: "2-digit" } : { hour: "2-digit", minute: "2-digit" });
		return new Date(t).toLocaleString(locale, o);
	}

	// config: Chart.js-Einstellungen; L = Beschriftungen {requests, c4, errors, blocked, decoy, bytes, up}. 4xx und Fehler
	// erscheinen, wenn es welche gibt; "an den Honeypot" nur mit aktivem Koeder (showDecoy) oder Werten im Zeitraum.
	function config(s, L, showDecoy) {
		var pts = s.pts;
		var any = function (k) { return pts.some(function (p) { return p[k] > 0; }); };
		var bar = function (lbl, k, color) {
			return { type: "bar", label: lbl, data: pts.map(function (p) { return p[k]; }), backgroundColor: color, borderRadius: 3, stack: "r", yAxisID: "y" };
		};
		var sets = [bar(L.requests, "ok", css("--bs-primary", "#0d6efd"))];
		if (any("c4")) { sets.push(bar(L.c4 || "4xx", "c4", css("--bs-secondary-color", "#adb5bd"))); }
		if (any("err")) { sets.push(bar(L.errors || "5xx", "err", css("--bs-warning", "#ffc107"))); }
		sets.push(bar(L.blocked, "blocked", css("--bs-danger", "#dc3545")));
		if (showDecoy || any("decoy")) { sets.push(bar(L.decoy || "Honeypot", "decoy", css("--bs-purple", "#6f42c1"))); }
		sets.push({ type: "line", label: L.bytes, data: pts.map(function (p) { return p.bytes; }), borderColor: css("--bs-info", "#0dcaf0"), backgroundColor: css("--bs-info", "#0dcaf0"),
			pointRadius: 0, tension: 0.3, yAxisID: "y1" });
		if (any("up")) {
			sets.push({ type: "line", label: L.up || "Upload", data: pts.map(function (p) { return p.up; }), borderColor: css("--bs-success", "#198754"), backgroundColor: css("--bs-success", "#198754"),
				pointRadius: 0, tension: 0.3, yAxisID: "y1", borderDash: [4, 3] });
		}
		return {
			type: "bar",
			data: { labels: pts.map(function (p) { return label(p.t, s); }), datasets: sets },
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
