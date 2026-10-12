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
		var nodesBox = document.getElementById("nodesbox");
		var syncNodes = function () {
			if (!nodesBox) { return; }
			nodesBox.classList.toggle("d-none", !!exSel && exSel.value === "online");
			var single = typeSel.value === "docker";
			nodesBox.querySelectorAll("input[name=nodes]").forEach(function (cb) {
				var own = cb.closest(".form-check").querySelector(".badge.text-bg-success");
				if (single) { cb.checked = !!own; cb.disabled = true; } else { cb.disabled = false; }
			});
		};
		if (exSel) { exSel.addEventListener("change", syncNodes); }
		typeSel.addEventListener("change", function () { update(); lockExec(); syncNodes(); });
		update(); lockExec(); syncNodes();
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

	// Latenz-Chart auf der Detailseite: eine Linie je Messstelle (wie im Portal), echte Zeitachse
	var canvas = document.getElementById("hc-chart");
	if (canvas && window.Chart) {
		var token = canvas.getAttribute("data-token");
		var chart = null;
		var note = document.getElementById("hc-chart-note");
		var css = getComputedStyle(document.documentElement);
		var color = function (name, fallback) { return (css.getPropertyValue(name) || fallback).trim(); };
		var palette = [color("--bs-primary", "#0d6efd"), "#198754", "#fd7e14", "#6f42c1", "#20c997", "#d63384"];
		var steps = { "1h": 6e5, "6h": 36e5, "24h": 3 * 36e5, "7d": 864e5, "30d": 5 * 864e5, "1y": 30 * 864e5 };
		var spans = { "1h": 36e5, "6h": 6 * 36e5, "24h": 24 * 36e5, "7d": 7 * 864e5, "30d": 30 * 864e5, "1y": 365 * 864e5 };
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
				var bands = (ch.options.plugins.hcBands || {}).bands || [], x = ch.scales.x, area = ch.chartArea;
				if (!bands.length) { return; }
				var c = ch.ctx;
				c.save();
				bands.forEach(function (bd) {
					var x0 = Math.max(area.left, x.getPixelForValue(bd.from)), x1 = Math.min(area.right, x.getPixelForValue(bd.to));
					if (x1 <= area.left || x0 >= area.right) { return; }
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
		// Achsenstriche auf volle Zeiten (lokal): 10 min, Stunden, Tage, Monatsanfaenge
		var alignedTicks = function (min, max, range) {
			var out = [], d = new Date(min), step = steps[range];
			if (range === "1y") {
				d = new Date(d.getFullYear(), d.getMonth() + 1, 1);
				while (d.getTime() <= max) { out.push({ value: d.getTime() }); d = new Date(d.getFullYear(), d.getMonth() + 1, 1); }
				return out;
			}
			if (step >= 864e5) { d.setHours(24, 0, 0, 0); } else {
				var mins = step / 6e4, cur = d.getHours() * 60 + d.getMinutes();
				d.setSeconds(0, 0); d.setMinutes(Math.ceil(cur / mins) * mins - d.getHours() * 60);
			}
			for (var t = d.getTime(); t <= max; t += step) { out.push({ value: t }); }
			return out;
		};
		var fmt = function (ms, range, long) {
			var t = new Date(ms);
			if (long) {
				var day = t.toLocaleDateString([], { day: "2-digit", month: "2-digit", year: "numeric" });
				return range === "1y" ? day : day + " " + t.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
			}
			if (range === "1h" || range === "6h" || range === "24h") { return t.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }); }
			if (range === "1y") { return t.toLocaleDateString([], { month: "short", year: "2-digit" }); }
			return t.toLocaleDateString([], { day: "2-digit", month: "2-digit" });
		};
		// Messpausen (Node aus, pausiert) nicht ueberbruecken: Luecke, wenn der Abstand weit ueber dem ueblichen liegt
		var withGaps = function (pts) {
			if (pts.length < 3) { return pts; }
			var d = [];
			for (var i = 1; i < pts.length; i++) { d.push(pts[i].x - pts[i - 1].x); }
			d.sort(function (a, b) { return a - b; });
			var limit = Math.max(3 * d[Math.floor(d.length / 2)], 120000), out = [pts[0]];
			for (var j = 1; j < pts.length; j++) {
				if (pts[j].x - pts[j - 1].x > limit) { out.push({ x: pts[j - 1].x + 1, y: null }); }
				out.push(pts[j]);
			}
			return out;
		};
		var load = function (range) {
			Promise.all([
				fetch("/api/checks/" + token + "/chart?range=" + range, { credentials: "same-origin" }).then(function (r) { return r.json(); }),
				fetch("/api/checks/" + token + "/events?limit=500", { credentials: "same-origin" }).then(function (r) { return r.json(); }).catch(function () { return []; })
			]).then(function (res) {
				var d = res[0] || {}, events = Array.isArray(res[1]) ? res[1] : [];
				var series = d.series || [], raw = d.bucket === "raw";
				var now = Date.now(), xmin = now - (spans[range] || spans["24h"]);
				var danger = color("--bs-danger", "#dc3545"), warn = color("--bs-warning", "#ffc107");
				var datasets = series.map(function (s, i) {
					var col = palette[i % palette.length];
					return {
						label: s.label, borderColor: col, backgroundColor: col, borderWidth: 1.5, tension: 0.2, fill: false, spanGaps: false,
						pointRadius: raw ? 1.2 : 0, pointHoverRadius: 4,
						data: withGaps(s.points.map(function (p) { return { x: new Date(p.t).getTime(), y: p.ms }; }))
					};
				});
				// Ausfaelle: rote Punkte auf der Nulllinie (Stunden/Tage mit Verlust gelb)
				var bad = [], badCol = [];
				series.forEach(function (s) {
					s.points.forEach(function (p) {
						var isBad = raw ? p.ms === null : (typeof p.up === "number" && p.up < 100);
						if (isBad) {
							bad.push({ x: new Date(p.t).getTime(), y: 0, up: p.up, src: s.label });
							badCol.push(raw || p.up <= 0 ? danger : warn);
						}
					});
				});
				if (bad.length) {
					datasets.push({ label: canvas.getAttribute("data-label-down") || "down", data: bad, showLine: false, pointRadius: 3, pointHoverRadius: 5,
						pointBackgroundColor: badCol, pointBorderColor: badCol, borderColor: danger, backgroundColor: danger });
				}
				// Zustandsphasen aus den Ereignissen als farbige Baender
				var ev = events.slice().sort(function (a, b) { return new Date(a.time) - new Date(b.time); });
				var bands = [], cur = null, curFrom = null;
				ev.forEach(function (e) {
					var t = new Date(e.time).getTime();
					if (cur !== null && bandColor(cur)) { bands.push({ from: curFrom, to: t, color: bandColor(cur) }); }
					cur = e.to; curFrom = t;
				});
				if (cur !== null && bandColor(cur)) { bands.push({ from: curFrom, to: now, color: bandColor(cur) }); }
				bands = bands.filter(function (b) { return b.to > xmin; });
				if (note) { note.textContent = series.length ? note.getAttribute("data-" + (raw ? "raw" : d.bucket)) : note.getAttribute("data-empty"); }
				var cfg = {
					type: "line",
					data: { datasets: datasets },
					options: {
						responsive: true, maintainAspectRatio: false, animation: false,
						interaction: { mode: "nearest", axis: "x", intersect: false },
						scales: {
							x: { type: "linear", min: xmin, max: now, afterBuildTicks: function (axis) { axis.ticks = alignedTicks(xmin, now, range); }, ticks: { autoSkip: false, callback: function (v) { return fmt(v, range, false); } } },
							y: { beginAtZero: true, title: { display: true, text: "ms" } }
						},
						plugins: {
							legend: { display: datasets.length > 1 },
							tooltip: { callbacks: {
								title: function (items) { return items.length ? fmt(items[0].parsed.x, range, true) : ""; },
								label: function (it) {
									var p = it.raw || {};
									if (it.dataset.showLine === false) { return it.dataset.label + " · " + (p.src || "") + (typeof p.up === "number" ? " (" + p.up + " %)" : ""); }
									return it.dataset.label + ": " + (it.parsed.y === null ? "–" : it.parsed.y + " ms");
								}
							} },
							hcBands: { bands: bands }
						}
					},
					plugins: [bandsPlugin]
				};
				if (chart) { chart.destroy(); }
				chart = new Chart(canvas.getContext("2d"), cfg);
			}).catch(function () {});
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
