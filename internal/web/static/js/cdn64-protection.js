// CDN64 Statistik (PROXY64, /cdn64/protection): Abgewehrtes je Tag, gestapelt nach Grund. Daten als JSON im Attribut
// data-chart ({labels: [YYYY-MM-DD], sets: [{label, color, data}]}, color = Bootstrap-Farbe). Vanilla-JS + Chart.js (lokal).
(function () {
	"use strict";
	var el = document.querySelector("[data-prot-chart]");
	if (!el || !window.Chart) { return; }
	var d;
	try { d = JSON.parse(el.getAttribute("data-chart") || "{}"); } catch (e) { return; }
	var locale = document.documentElement.lang === "en" ? "en-GB" : "de-DE";
	var nf = new Intl.NumberFormat(locale);
	var fallback = { danger: "#dc3545", secondary: "#6c757d", warning: "#ffc107", info: "#0dcaf0", purple: "#6f42c1" };

	function css(name) {
		return getComputedStyle(document.documentElement).getPropertyValue("--bs-" + name).trim() || fallback[name] || "#6c757d";
	}

	function label(day) {
		var p = String(day).split("-");
		if (p.length !== 3) { return day; }
		return new Date(+p[0], +p[1] - 1, +p[2]).toLocaleDateString(locale, { day: "2-digit", month: "2-digit" });
	}

	var sets = (d.sets || []).filter(function (s) {
		return (s.data || []).some(function (v) { return v > 0; });
	}).map(function (s) {
		return { label: s.label, data: s.data, backgroundColor: css(s.color), borderRadius: 3, stack: "b" };
	});
	new window.Chart(el, {
		type: "bar",
		data: { labels: (d.labels || []).map(label), datasets: sets },
		options: {
			responsive: true, maintainAspectRatio: false, animation: false, interaction: { mode: "index", intersect: false },
			scales: {
				x: { stacked: true, grid: { display: false }, ticks: { autoSkip: true, maxRotation: 0 } },
				y: { stacked: true, beginAtZero: true, ticks: { precision: 0, callback: function (v) { return nf.format(v); } } }
			},
			plugins: { legend: { position: "bottom" }, tooltip: { callbacks: { label: function (ctx) {
				return ctx.dataset.label + ": " + nf.format(ctx.parsed.y);
			} } } }
		}
	});
})();
