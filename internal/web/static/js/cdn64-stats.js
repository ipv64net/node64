// CDN64: Statistik in der Uebersicht (Anfragen nach Statusklasse, Datenmenge, Kennzahlen). Daten aus
// /api/cdn64/stats (cdn64.db, je Stunde); 30 Tage werden je Tag zusammengefasst. Vanilla-JS + Chart.js (lokal).
(function () {
	"use strict";
	var card = document.querySelector("[data-cdn64-stats]");
	if (!card || !window.Chart) { return; }
	var L = function (k) { return card.getAttribute("data-l-" + k) || k; };
	var locale = document.documentElement.lang === "en" ? "en-GB" : "de-DE";
	var nf = new Intl.NumberFormat(locale);
	var canvas = card.querySelector("[data-stats-chart]");
	var hostSel = card.querySelector("[data-stats-host]");
	var chart = null;
	var hours = 24;

	function css(name, def) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || def; }
	function bytes(n) {
		var u = ["B", "KB", "MB", "GB", "TB"], i = 0;
		while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
		return (i ? n.toFixed(1) : n) + " " + u[i];
	}
	function label(ts, daily) {
		var o = daily ? { day: "2-digit", month: "2-digit" } : (hours > 24 ? { weekday: "short", hour: "2-digit" } : { hour: "2-digit", minute: "2-digit" });
		return new Date(ts).toLocaleString(locale, o);
	}
	function set(k, v) { var el = card.querySelector('[data-kpi="' + k + '"]'); if (el) { el.textContent = v; } }

	// Luecken (Stunden ohne Anfragen) auffuellen, damit die Zeitachse stimmt; bei 30 Tagen je Tag zusammenfassen
	function series(pts) {
		var by = {};
		pts.forEach(function (p) { by[new Date(p.hour).getTime()] = p; });
		var now = Math.floor(Date.now() / 3600e3) * 3600e3; // volle Stunde (UTC, wie in cdn64.db)
		var out = [];
		for (var i = hours - 1; i >= 0; i--) {
			var t = now - i * 3600e3;
			var p = by[t] || {};
			out.push({ t: t, s2: p["2xx"] || 0, s3: p["3xx"] || 0, s4: p["4xx"] || 0, s5: p["5xx"] || 0, req: p.requests || 0, bytes: p.bytes || 0 });
		}
		if (hours <= 168) { return { pts: out, daily: false }; }
		var days = [], cur = null;
		out.forEach(function (p) {
			var d = new Date(p.t); d.setHours(0, 0, 0, 0);
			if (!cur || cur.t !== d.getTime()) { cur = { t: d.getTime(), s2: 0, s3: 0, s4: 0, s5: 0, req: 0, bytes: 0 }; days.push(cur); }
			["s2", "s3", "s4", "s5", "req", "bytes"].forEach(function (k) { cur[k] += p[k]; });
		});
		return { pts: days, daily: true };
	}

	function load() {
		var q = "/api/cdn64/stats?hours=" + hours + (hostSel && hostSel.value !== "0" ? "&host=" + hostSel.value : "");
		fetch(q, { cache: "no-store" }).then(function (r) { return r.json(); }).then(function (d) {
			var s = series(d.timeline || []), pts = s.pts;
			var sum = { req: 0, bytes: 0, err: 0 };
			pts.forEach(function (p) { sum.req += p.req; sum.bytes += p.bytes; sum.err += p.s4 + p.s5; });
			set("requests", nf.format(sum.req));
			set("bytes", bytes(sum.bytes));
			set("errors", nf.format(sum.err) + (sum.req ? " (" + (100 * sum.err / sum.req).toFixed(1) + " %)" : ""));
			card.querySelector("[data-stats-empty]").classList.toggle("d-none", sum.req > 0);
			var ds = [
				{ label: "2xx", key: "s2", color: css("--bs-success", "#198754") },
				{ label: "3xx", key: "s3", color: css("--bs-info", "#0dcaf0") },
				{ label: "4xx", key: "s4", color: css("--bs-warning", "#ffc107") },
				{ label: "5xx", key: "s5", color: css("--bs-danger", "#dc3545") }
			].map(function (x) {
				return { type: "bar", label: x.label, data: pts.map(function (p) { return p[x.key]; }), backgroundColor: x.color, stack: "r", yAxisID: "y", borderRadius: 2 };
			});
			ds.push({ type: "line", label: L("bytes"), data: pts.map(function (p) { return p.bytes; }), borderColor: css("--bs-primary", "#0d6efd"),
				backgroundColor: css("--bs-primary", "#0d6efd"), pointRadius: 0, tension: 0.3, yAxisID: "y1" });
			if (chart) { chart.destroy(); }
			chart = new window.Chart(canvas, {
				data: { labels: pts.map(function (p) { return label(p.t, s.daily); }), datasets: ds },
				options: {
					responsive: true, maintainAspectRatio: false, animation: false, interaction: { mode: "index", intersect: false },
					scales: {
						x: { stacked: true, grid: { display: false }, ticks: { autoSkip: true, maxRotation: 0 } },
						y: { stacked: true, beginAtZero: true, title: { display: true, text: L("requests") }, ticks: { precision: 0, callback: function (v) { return nf.format(v); } } },
						y1: { beginAtZero: true, position: "right", grid: { drawOnChartArea: false }, ticks: { callback: function (v) { return bytes(v); } } }
					},
					plugins: { legend: { position: "bottom" }, tooltip: { callbacks: { label: function (ctx) {
						return ctx.dataset.label + ": " + (ctx.dataset.yAxisID === "y1" ? bytes(ctx.parsed.y) : nf.format(ctx.parsed.y));
					} } } }
				}
			});
		}).catch(function () { card.querySelector("[data-stats-empty]").classList.remove("d-none"); });
	}

	card.querySelectorAll("[data-stats-range]").forEach(function (b) {
		b.addEventListener("click", function () {
			card.querySelectorAll("[data-stats-range]").forEach(function (x) { x.classList.toggle("active", x === b); });
			hours = parseInt(b.getAttribute("data-stats-range"), 10) || 24;
			load();
		});
	});
	if (hostSel) { hostSel.addEventListener("change", load); }
	load();
	setInterval(function () { if (!document.hidden) { load(); } }, 5 * 60 * 1000);
})();
