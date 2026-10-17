// Dashboard: Kacheln anpassen (Reihenfolge per Drag & Drop oder Pfeilen, Groesse, ein-/ausblenden; gespeichert je
// Benutzer ueber /api/dashboard/layout) und Diagramme fuer DNS64 und CDN64.
(function () {
	"use strict";
	var dataEl = document.getElementById("dash-data");
	var grid = document.getElementById("dash");
	if (!dataEl || !grid) { return; }
	var cfg = JSON.parse(dataEl.textContent || "{}");
	var T = cfg.t || {};
	var locale = cfg.lang === "en" ? "en-GB" : "de-DE";
	var SIZES = ["s", "m", "l", "xl"];
	var COLS = { s: "col-md-6 col-xl-3", m: "col-md-6 col-xl-4", l: "col-lg-6", xl: "col-12" };
	var ALLCOLS = "col-md-6 col-xl-3 col-xl-4 col-lg-6 col-12".split(" ");
	var root = document.body;

	function t(k) { return T[k] || k; }
	function items() { return Array.prototype.slice.call(grid.querySelectorAll(".dash-item")); }

	// ---------- Anpassen ----------

	function setEditing(on) {
		root.classList.toggle("dash-editing", on);
		items().forEach(function (el) { el.setAttribute("draggable", on ? "true" : "false"); });
	}

	function setSize(el, size) {
		ALLCOLS.forEach(function (c) { el.classList.remove(c); });
		COLS[size].split(" ").forEach(function (c) { el.classList.add(c); });
		el.setAttribute("data-size", size);
		var b = el.querySelector('[data-dash="size"]');
		if (b) { b.textContent = size; }
		resizeCharts();
	}

	function layout() {
		return items().map(function (el) {
			return { id: el.getAttribute("data-id"), size: el.getAttribute("data-size"), hidden: el.classList.contains("dash-hidden") };
		});
	}

	function send(method, body) {
		var init = { method: method, cache: "no-store", headers: { "X-CSRF-Token": cfg.csrf } };
		if (body) {
			init.headers["Content-Type"] = "application/json";
			init.body = JSON.stringify(body);
		}
		return fetch("/api/dashboard/layout", init).then(function (r) {
			if (!r.ok) { throw new Error(String(r.status)); }
		});
	}

	grid.addEventListener("click", function (e) {
		var b = e.target.closest("[data-dash]");
		if (!b || !root.classList.contains("dash-editing")) { return; }
		var el = b.closest(".dash-item");
		switch (b.getAttribute("data-dash")) {
		case "up":
			if (el.previousElementSibling) { grid.insertBefore(el, el.previousElementSibling); }
			break;
		case "down":
			if (el.nextElementSibling) { grid.insertBefore(el.nextElementSibling, el); }
			break;
		case "size":
			setSize(el, SIZES[(SIZES.indexOf(el.getAttribute("data-size")) + 1) % SIZES.length]);
			break;
		case "hide":
			el.classList.toggle("dash-hidden");
			b.title = el.classList.contains("dash-hidden") ? t("show") : t("hide");
			if (!el.classList.contains("dash-hidden")) { initCharts(el); }
			break;
		}
	});

	// Drag & Drop (Maus); auf Touch-Geraeten die Pfeile
	var dragging = null;
	grid.addEventListener("dragstart", function (e) {
		var el = e.target.closest(".dash-item");
		if (!el || !root.classList.contains("dash-editing")) { return; }
		dragging = el;
		el.classList.add("dash-dragging");
		e.dataTransfer.effectAllowed = "move";
		e.dataTransfer.setData("text/plain", el.getAttribute("data-id"));
	});
	grid.addEventListener("dragover", function (e) {
		if (!dragging) { return; }
		e.preventDefault();
		var over = e.target.closest(".dash-item");
		if (!over || over === dragging) { return; }
		var r = over.getBoundingClientRect();
		var after = (e.clientY - r.top) > r.height / 2 || ((e.clientX - r.left) > r.width / 2 && (e.clientY - r.top) > r.height / 4);
		grid.insertBefore(dragging, after ? over.nextElementSibling : over);
	});
	grid.addEventListener("drop", function (e) { if (dragging) { e.preventDefault(); } });
	grid.addEventListener("dragend", function () {
		if (dragging) { dragging.classList.remove("dash-dragging"); }
		dragging = null;
		resizeCharts();
	});

	var btnEdit = document.getElementById("dash-edit");
	var btnDone = document.getElementById("dash-done");
	var btnReset = document.getElementById("dash-reset");
	if (btnEdit) { btnEdit.addEventListener("click", function () { setEditing(true); }); }
	if (btnDone) {
		btnDone.addEventListener("click", function () {
			btnDone.disabled = true;
			send("PUT", { items: layout() }).then(function () {
				setEditing(false);
			}).catch(function () {
				window.alert(t("save_err"));
			}).then(function () { btnDone.disabled = false; });
		});
	}
	if (btnReset) {
		btnReset.addEventListener("click", function () {
			send("DELETE").then(function () { location.reload(); }).catch(function () { window.alert(t("save_err")); });
		});
	}

	// ---------- Diagramme ----------

	var charts = {};

	function resizeCharts() {
		Object.keys(charts).forEach(function (k) { if (charts[k]) { charts[k].resize(); } });
	}

	function colors() {
		var css = getComputedStyle(document.documentElement);
		return {
			ok: css.getPropertyValue("--bs-success").trim() || "#198754",
			bad: css.getPropertyValue("--bs-danger").trim() || "#dc3545",
			pri: css.getPropertyValue("--bs-primary").trim() || "#0d6efd",
			info: css.getPropertyValue("--bs-info").trim() || "#0dcaf0"
		};
	}

	function fmtTime(ts, long) {
		var opts = long ? { weekday: "short", hour: "2-digit", minute: "2-digit" } : { hour: "2-digit", minute: "2-digit" };
		return new Date(ts).toLocaleString(locale, opts);
	}

	function draw(canvas, kind, cfgChart) {
		var key = kind;
		if (charts[key]) { charts[key].destroy(); }
		charts[key] = new window.Chart(canvas, cfgChart);
	}

	function empty(card, isEmpty) {
		var e = card.querySelector("[data-chart-empty]");
		if (e) { e.classList.toggle("d-none", !isEmpty); }
	}

	function loadDNS64(card, canvas, range) {
		return fetch("/api/dns64/timeline?range=" + range, { cache: "no-store" }).then(function (r) { return r.json(); }).then(function (d) {
			var b = d.buckets || [];
			var long = d.stepMs >= 3600e3 * 4;
			var c = colors();
			empty(card, !b.length);
			draw(canvas, "dns64", {
				type: "bar",
				data: { labels: b.map(function (x) { return fmtTime(x.t, long); }), datasets: [
					{ label: t("allowed"), data: b.map(function (x) { return x.total - x.blocked; }), backgroundColor: c.ok, borderRadius: 3, stack: "q" },
					{ label: t("blocked"), data: b.map(function (x) { return x.blocked; }), backgroundColor: c.bad, borderRadius: 3, stack: "q" }
				] },
				options: {
					responsive: true, maintainAspectRatio: false, animation: false, interaction: { mode: "index", intersect: false },
					scales: { x: { stacked: true, grid: { display: false }, ticks: { autoSkip: true, maxRotation: 0 } }, y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } } },
					plugins: { legend: { position: "bottom" } }
				}
			});
		});
	}

	// gleiches Diagramm wie in der Uebersicht der Proxy-Hosts (cdn64-chart.js)
	function loadCDN64(card, canvas, range) {
		var hours = range === "7d" ? 168 : 24;
		return fetch("/api/cdn64/stats?hours=" + hours, { cache: "no-store" }).then(function (r) { return r.json(); }).then(function (d) {
			var C = window.Node64CDNChart;
			var s = C.series(d.timeline, hours);
			empty(card, !s.pts.some(function (p) { return p.req || p.blocked; }));
			draw(canvas, "cdn64", C.config(s, { requests: t("requests"), blocked: t("rejected"), bytes: t("bytes") }));
		});
	}

	function initCharts(scope) {
		if (!window.Chart) { return; }
		(scope || grid).querySelectorAll("canvas[data-chart]").forEach(function (canvas) {
			var item = canvas.closest(".dash-item");
			if (!item || item.classList.contains("dash-hidden")) { return; }
			var card = canvas.closest(".card");
			var kind = canvas.getAttribute("data-chart");
			var load = function (range) {
				var p = kind === "dns64" ? loadDNS64(card, canvas, range) : loadCDN64(card, canvas, range);
				p.catch(function () { empty(card, true); });
			};
			if (!card.hasAttribute("data-bound")) {
				card.setAttribute("data-bound", "1");
				card.querySelectorAll("[data-range]").forEach(function (b) {
					b.addEventListener("click", function () {
						card.querySelectorAll("[data-range]").forEach(function (x) { x.classList.toggle("active", x === b); });
						load(b.getAttribute("data-range"));
					});
				});
			}
			var active = card.querySelector("[data-range].active");
			load(active ? active.getAttribute("data-range") : "24h");
		});
	}

	initCharts();
	setInterval(function () { if (!document.hidden && !root.classList.contains("dash-editing")) { initCharts(); } }, 5 * 60 * 1000);
})();
