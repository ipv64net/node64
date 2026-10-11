// Healthchecks: Formular, Liste und Detail-Chart. Vanilla-JS, keine externen Quellen.
(function () {
	"use strict";

	// Formular: nur die Felder des gewaehlten Typs zeigen und absenden
	var typeSel = document.getElementById("hc-type");
	if (typeSel) {
		var update = function () {
			var t = typeSel.value;
			document.querySelectorAll("[data-types]").forEach(function (el) {
				var on = el.getAttribute("data-types").split(" ").indexOf(t) >= 0;
				el.classList.toggle("d-none", !on);
				el.querySelectorAll("input, select, textarea").forEach(function (i) { i.disabled = !on; });
			});
		};
		var exSel = document.getElementById("execution");
		var lockExec = function () {
			if (!exSel) { return; }
			var docker = typeSel.value === "docker";
			exSel.querySelectorAll("option").forEach(function (o) {
				if (o.value !== "local") {
					if (docker) { o.dataset.wasDisabled = o.dataset.wasDisabled || String(o.disabled); o.disabled = true; }
					else if (o.dataset.wasDisabled) { o.disabled = o.dataset.wasDisabled === "true"; delete o.dataset.wasDisabled; }
				}
			});
			if (docker) { exSel.value = "local"; }
		};
		typeSel.addEventListener("change", function () { update(); lockExec(); });
		update(); lockExec();
	}

	// Tooltips der Pillen: Inhalt aus data-Attributen, hier maskiert und als HTML gesetzt
	if (window.bootstrap && bootstrap.Tooltip) {
		var esc = function (s) { return String(s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); };
		document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(function (el) {
			var title = el.getAttribute("data-bs-title") || el.getAttribute("title") || "";
			if (el.hasAttribute("data-tip-label")) {
				var cls = (el.className.match(/beat-(up|down|maintenance|dependent)/) || [])[1] || "";
				title = '<strong class="hc-tip-' + cls + '">' + esc(el.getAttribute("data-tip-label")) + "</strong>";
				if (el.getAttribute("data-tip-ms")) { title += " · " + esc(el.getAttribute("data-tip-ms")); }
				title += "<br>" + esc(el.getAttribute("data-tip-when"));
				if (el.getAttribute("data-tip-msg")) { title += '<br><span class="hc-tip-msg">' + esc(el.getAttribute("data-tip-msg")) + "</span>"; }
			}
			new bootstrap.Tooltip(el, { title: title, html: true, customClass: "hc-tip", container: "body", delay: { show: 80, hide: 0 } });
		});
	}

	// Rueckfrage vor Loeschen und Massenaktionen
	document.querySelectorAll("[data-confirm]").forEach(function (b) {
		b.addEventListener("click", function (e) {
			var form = b.form || b.closest("form");
			if (form && form.id.indexOf("hc-bulk") === 0) {
				var sel = form.querySelector("select[name=action]");
				if (sel && sel.value !== "delete") { return; }
			}
			if (!window.confirm(b.getAttribute("data-confirm"))) { e.preventDefault(); }
		});
	});

	// Alle auswaehlen
	// Alle auswaehlen: je Tabelle (Haupttabelle, Docker), nur sichtbare Zeilen
	document.querySelectorAll("[data-select-all]").forEach(function (all) {
		all.addEventListener("change", function () {
			all.closest("form").querySelectorAll("input[name=tokens]").forEach(function (c) {
				if (!c.closest("tr") || !c.closest("tr").classList.contains("d-none")) { c.checked = all.checked; }
			});
		});
	});

	// Gruppen auf- und zuklappen (Zustand im Browser gemerkt)
	var closed = {};
	try { closed = JSON.parse(localStorage.getItem("node64_hc_closed") || "{}"); } catch (e) { closed = {}; }
	function setGroup(key, hide) {
		document.querySelectorAll('tr[data-group-row="' + key + '"]').forEach(function (tr) { tr.classList.toggle("d-none", hide); });
		var head = document.querySelector('tr.hc-group-row[data-group="' + key + '"]');
		if (head) { head.classList.toggle("collapsed", hide); }
	}
	document.querySelectorAll(".hc-group-toggle").forEach(function (btn) {
		var key = btn.getAttribute("data-group");
		var name = btn.textContent.trim();
		if (closed[name]) { setGroup(key, true); }
		btn.addEventListener("click", function () {
			var hide = !btn.closest("tr").classList.contains("collapsed");
			setGroup(key, hide);
			if (hide) { closed[name] = 1; } else { delete closed[name]; }
			try { localStorage.setItem("node64_hc_closed", JSON.stringify(closed)); } catch (e) {}
		});
	});

	// Push-URL in die Zwischenablage
	document.querySelectorAll("[data-copy]").forEach(function (el) {
		el.addEventListener("click", function () {
			el.select();
			if (navigator.clipboard) { navigator.clipboard.writeText(el.value).catch(function () {}); }
		});
	});

	// Latenz-Chart auf der Detailseite
	var canvas = document.getElementById("hc-chart");
	if (canvas && window.Chart) {
		var token = canvas.getAttribute("data-token");
		var chart = null;
		var css = getComputedStyle(document.documentElement);
		var color = function (name, fallback) { return (css.getPropertyValue(name) || fallback).trim(); };
		// Farben fuer Zustaende im Diagramm: gestoert rot, Uebergangsphasen gelb/orange, pausiert grau
		var bandColor = function (st) {
			switch (st) {
				case "down": return "rgba(220,53,69,.16)";
				case "stabilizing": case "degraded": case "dependent": return "rgba(255,193,7,.20)";
				case "flapping": case "unstable": return "rgba(253,126,20,.20)";
				case "paused": return "rgba(108,117,125,.12)";
				default: return null;
			}
		};
		var bandsPlugin = {
			id: "hcBands",
			beforeDatasetsDraw: function (ch) {
				var o = ch.options.plugins.hcBands || {};
				var bands = o.bands || [], x = ch.scales.x, area = ch.chartArea, n = (ch.data.labels || []).length;
				if (!bands.length || n < 2) { return; }
				var px = function (idx) {
					idx = Math.max(0, Math.min(n - 1, idx));
					var a = Math.floor(idx), b = Math.ceil(idx), pa = x.getPixelForValue(a), pb = x.getPixelForValue(b);
					return pa + (pb - pa) * (idx - a);
				};
				var c = ch.ctx;
				c.save();
				bands.forEach(function (bd) {
					var x0 = px(bd.from), x1 = px(bd.to);
					if (x1 - x0 < 2) { x1 = x0 + 2; }
					c.fillStyle = bd.color;
					c.fillRect(x0, area.top, x1 - x0, area.bottom - area.top);
				});
				c.restore();
			}
		};
		var legend = document.getElementById("hc-chart-legend");
		if (!legend) {
			legend = document.createElement("div");
			legend.id = "hc-chart-legend";
			legend.className = "small text-body-secondary mt-2 d-flex flex-wrap gap-3";
			legend.innerHTML = '<span><span class="hc-lg" style="background:rgba(220,53,69,.45)"></span> ' + (canvas.getAttribute("data-label-down") || "down") + '</span>' +
				'<span><span class="hc-lg" style="background:rgba(255,193,7,.6)"></span> ' + (canvas.getAttribute("data-label-warn") || "warning") + '</span>' +
				'<span><span class="hc-lg" style="background:rgba(253,126,20,.6)"></span> ' + (canvas.getAttribute("data-label-flap") || "unstable") + '</span>';
			canvas.parentNode.parentNode.appendChild(legend);
		}
		var load = function (range) {
			Promise.all([
				fetch("/api/checks/" + token + "/stats?range=" + range, { credentials: "same-origin" }).then(function (r) { return r.json(); }),
				fetch("/api/checks/" + token + "/events?limit=500", { credentials: "same-origin" }).then(function (r) { return r.json(); }).catch(function () { return []; })
			]).then(function (res) {
					var d = res[0], events = Array.isArray(res[1]) ? res[1] : [];
					var labels = d.series.map(function (b) {
						var t = new Date(b.time);
						return range === "24h" ? t.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : t.toLocaleDateString([], { day: "2-digit", month: "2-digit" }) + " " + t.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
					});
					var lat = d.series.map(function (b) { return b.count ? b.avg_ms : null; });
					var up = d.series.map(function (b) { return b.count ? b.up_percent : null; });
					var danger = color("--bs-danger", "#dc3545"), warn = color("--bs-warning", "#ffc107"), prim = color("--bs-primary", "#007bff");
					var colOf = function (b) { if (!b || !b.count) { return prim; } return b.up_percent <= 0 ? danger : (b.up_percent < 100 ? warn : prim); };
					var colors = d.series.map(colOf);
					// Zustandsphasen aus den Ereignissen als farbige Baender
					var t0 = d.series.length ? new Date(d.series[0].time).getTime() : 0, step = (d.bucket_seconds || 900) * 1000;
					var idxOf = function (ms) { return (ms - t0) / step; };
					var ev = events.slice().sort(function (a, b) { return new Date(a.time) - new Date(b.time); });
					var bands = [], cur = null, curFrom = null;
					ev.forEach(function (e) {
						var t = new Date(e.time).getTime();
						if (cur !== null && bandColor(cur)) { bands.push({ from: idxOf(curFrom), to: idxOf(t), color: bandColor(cur) }); }
						cur = e.to; curFrom = t;
					});
					if (cur !== null && bandColor(cur)) { bands.push({ from: idxOf(curFrom), to: idxOf(Date.now()), color: bandColor(cur) }); }
					bands = bands.filter(function (b) { return b.to > 0 && b.from < d.series.length; });
					var cfg = {
						type: "line",
						data: {
							labels: labels,
							datasets: [
								{ label: canvas.getAttribute("data-label-latency") + " (ms)", data: lat, borderColor: prim, backgroundColor: "rgba(0,123,255,.10)", pointBackgroundColor: colors, pointBorderColor: colors,
									pointRadius: function (c) { var b = d.series[c.dataIndex]; return b && b.count && b.up_percent < 100 ? 4 : 2; },
									segment: { borderColor: function (c) { return colOf(d.series[c.p1DataIndex]); } },
									tension: .25, fill: true, spanGaps: true, yAxisID: "y" },
								{ label: canvas.getAttribute("data-label-up") + " (%)", data: up, borderColor: color("--bs-success", "#28a745"), borderDash: [4, 3], pointRadius: 0, tension: 0, stepped: true, yAxisID: "y1",
									segment: { borderColor: function (c) { var b = d.series[c.p1DataIndex]; return b && b.count && b.up_percent < 100 ? danger : color("--bs-success", "#28a745"); } } }
							]
						},
						options: {
							responsive: true, maintainAspectRatio: false, animation: false,
							interaction: { mode: "index", intersect: false },
							scales: {
								y: { beginAtZero: true, title: { display: true, text: "ms" } },
								y1: { position: "right", min: 0, max: 100, grid: { drawOnChartArea: false }, title: { display: true, text: "%" } }
							},
							plugins: { legend: { display: true }, hcBands: { bands: bands } }
						},
						plugins: [bandsPlugin]
					};
					if (chart) { chart.destroy(); }
					chart = new Chart(canvas.getContext("2d"), cfg);
				})
				.catch(function () {});
		};
		document.querySelectorAll("#hc-ranges button").forEach(function (b) {
			b.addEventListener("click", function () {
				document.querySelectorAll("#hc-ranges button").forEach(function (x) { x.classList.remove("active"); });
				b.classList.add("active");
				load(b.getAttribute("data-range"));
			});
		});
		load("24h");
	}
})();
