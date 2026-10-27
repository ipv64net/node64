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
			var sum = { req: 0, bytes: 0, up: 0, err: 0, c4: 0, blocked: 0, decoy: 0 };
			s.pts.forEach(function (p) { sum.req += p.req; sum.bytes += p.bytes; sum.up += p.up; sum.err += p.err; sum.c4 += p.c4; sum.blocked += p.blocked; sum.decoy += p.decoy; });
			set("requests", C.nf.format(sum.req));
			set("bytes", C.bytes(sum.bytes));
			set("up", C.bytes(sum.up));
			set("errors", C.nf.format(sum.err) + (sum.req ? " (" + (100 * sum.err / sum.req).toFixed(1) + " %)" : ""));
			set("c4", L("c4-sub").replace("{n}", C.nf.format(sum.c4)));
			set("blocked", C.nf.format(sum.blocked));
			set("decoy", C.nf.format(sum.decoy));
			// Kennzahl "an den Honeypot" nur, wenn der Koeder aktiv ist oder im Zeitraum etwas umgeleitet wurde
			var showDecoy = !!d.decoy_active || sum.decoy > 0;
			var dk = card.querySelector("[data-kpi-decoy]");
			if (dk) { dk.classList.toggle("d-none", !showDecoy); }
			card.querySelector("[data-stats-empty]").classList.toggle("d-none", sum.req + sum.blocked + sum.decoy > 0);
			rows(d.hosts || {});
			if (chart) { chart.destroy(); }
			chart = new window.Chart(canvas, C.config(s, { requests: L("requests"), blocked: L("blocked"), bytes: L("bytes"), up: L("up"), c4: L("c4"), errors: L("errors"), decoy: L("decoy") }, showDecoy));
		}).catch(function () { card.querySelector("[data-stats-empty]").classList.remove("d-none"); });
	}

	// Zeitraum an Kennzahlen und Spaltenkopf, Werte je Host in der Tabelle (gleicher Zeitraum wie die Kennzahlen)
	function rows(hosts) {
		var r = L("r" + hours);
		card.querySelectorAll("[data-stats-last]").forEach(function (el) { el.textContent = L("last").replace("{range}", r); });
		var col = document.querySelector("[data-stats-col]");
		if (col) { col.textContent = L("col").replace("{range}", r); }
		document.querySelectorAll("[data-stats-row]").forEach(function (td) {
			var h = hosts[td.getAttribute("data-stats-row")] || {};
			var err = h["5xx"] || 0, c4 = h["4xx"] || 0, dec = h.decoy || 0;
			var v = function (k, text, show) { var el = td.querySelector('[data-v="' + k + '"]'); if (el) { el.textContent = text; el.classList.toggle("d-none", !show); } };
			v("requests", C.nf.format(h.requests || 0), true);
			// geschuetzte Leerzeichen: umbrechen nur am Punkt zwischen den beiden Angaben (wie im Template)
			var nb = function (s) { return s.replace(/ /g, "\u00a0"); };
			v("bytes", nb("↓ " + C.bytes(h.bytes || 0)) + " · " + nb("↑ " + C.bytes(h.bytes_in || 0)), (h.bytes || 0) + (h.bytes_in || 0) > 0);
			v("errors", L("errors-n").replace("{n}", C.nf.format(err)), err > 0);
			v("c4", L("c4-n").replace("{n}", C.nf.format(c4)), c4 > 0);
			v("blocked", L("blocked-n").replace("{n}", C.nf.format(h.blocked || 0)), (h.blocked || 0) > 0);
			v("decoy", L("decoy-n").replace("{n}", C.nf.format(dec)), dec > 0);
		});
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
