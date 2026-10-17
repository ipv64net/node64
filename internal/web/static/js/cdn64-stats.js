// CDN64: Verkehr in der Uebersicht der Proxy-Hosts, gleiches Diagramm wie auf dem Dashboard (cdn64-chart.js), dazu
// Kennzahlen und Auswahl je Host. Daten aus /api/cdn64/stats.
(function () {
	"use strict";
	var card = document.querySelector("[data-cdn64-stats]");
	var C = window.Node64CDNChart;
	if (!card || !window.Chart || !C) { return; }
	var L = function (k) { return card.getAttribute("data-l-" + k) || k; };
	var canvas = card.querySelector("[data-stats-chart]");
	var hostSel = card.querySelector("[data-stats-host]");
	var chart = null;
	var hours = 24;

	function set(k, v) { var el = card.querySelector('[data-kpi="' + k + '"]'); if (el) { el.textContent = v; } }

	function load() {
		var q = "/api/cdn64/stats?hours=" + hours + (hostSel && hostSel.value !== "0" ? "&host=" + hostSel.value : "");
		fetch(q, { cache: "no-store" }).then(function (r) { return r.json(); }).then(function (d) {
			var s = C.series(d.timeline, hours);
			var sum = { req: 0, bytes: 0, err: 0, blocked: 0 };
			s.pts.forEach(function (p) { sum.req += p.req; sum.bytes += p.bytes; sum.err += p.err; sum.blocked += p.blocked; });
			set("requests", C.nf.format(sum.req));
			set("bytes", C.bytes(sum.bytes));
			set("errors", C.nf.format(sum.err) + (sum.req ? " (" + (100 * sum.err / sum.req).toFixed(1) + " %)" : ""));
			set("blocked", C.nf.format(sum.blocked));
			card.querySelector("[data-stats-empty]").classList.toggle("d-none", sum.req + sum.blocked > 0);
			if (chart) { chart.destroy(); }
			chart = new window.Chart(canvas, C.config(s, { requests: L("requests"), blocked: L("blocked"), bytes: L("bytes") }));
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
