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
			// Check aus einem ueberwachten System (sys:proxmox, sys:docker): Name optional, Gruppe, Messstellen und
			// Meldungen kommen vom System
			var sys = t.indexOf("sys:") === 0;
			document.querySelectorAll("[data-hide-types]").forEach(function (el) {
				el.classList.toggle("d-none", el.getAttribute("data-hide-types").split(" ").indexOf(t) >= 0);
			});
			var nm = document.getElementById("name");
			if (nm) { nm.required = !sys; nm.placeholder = sys ? (nm.getAttribute("data-auto") || "") : ""; }
		};
		// Auswahl System -> Maschine bzw. Container: nur die Eintraege des gewaehlten Systems, gefuehrte gesperrt
		document.querySelectorAll("[data-pick]").forEach(function (box) {
			var sysSel = box.querySelector("[data-pick-sys]"), resSel = box.querySelector("[data-pick-res]");
			if (!sysSel || !resSel) { return; }
			var filter = function () {
				var none = resSel.querySelector("[data-none]"), cur = resSel.selectedOptions[0], first = null, any = false;
				resSel.querySelectorAll("option[data-sys]").forEach(function (o) {
					var mine = o.getAttribute("data-sys") === sysSel.value;
					o.hidden = !mine;
					o.disabled = !mine || o.hasAttribute("data-taken");
					if (mine) { any = true; }
					if (!o.disabled && !first) { first = o; }
				});
				if (none) { none.hidden = any; }
				if (!cur || cur.disabled || cur.hidden) {
					if (first) { first.selected = true; } else if (none) { none.selected = true; }
				}
			};
			sysSel.addEventListener("change", filter);
			filter();
		});
		// Testlauf von ipv64 vor dem Umhaengen: die Standorte messen die Eingabe einmal (gespeichert wird nichts)
		var ot = document.getElementById("hc-otest");
		if (ot) {
			var otx = function (k) { return ot.getAttribute("data-t-" + k) || k; };
			var out = document.getElementById("hc-otest-out");
			var add = function (icon, text) {
				var li = document.createElement("li"), i = document.createElement("i");
				i.className = "bi " + icon + " me-1";
				li.appendChild(i);
				li.appendChild(document.createTextNode(text));
				out.appendChild(li);
			};
			ot.addEventListener("click", function () {
				var form = document.getElementById("hc-form");
				var body = new URLSearchParams(new FormData(form));
				body.set("token", ot.getAttribute("data-token") || "");
				ot.disabled = true;
				out.textContent = "";
				add("bi-hourglass-split text-body-secondary", otx("running"));
				fetch("/healthchecks/online-test", { method: "POST", body: body, headers: { "Content-Type": "application/x-www-form-urlencoded" } })
					.then(function (r) { return r.json(); })
					.then(function (d) {
						out.textContent = "";
						if (d.error) { add("bi-x-circle text-danger", d.error); return; }
						add(d.status === "ok" ? "bi-check-circle text-success" : "bi-exclamation-triangle text-warning", otx(d.status));
						(d.results || []).forEach(function (r) {
							add(r.ok ? "bi-check text-success" : "bi-x text-danger", (ot.getAttribute("data-t-loc-" + r.location) || r.location) + ": " + r.message);
						});
					})
					.catch(function () { out.textContent = ""; add("bi-x-circle text-danger", otx("error")); })
					.then(function () { ot.disabled = false; });
			});
		}
		// Tageskontingent: Verbrauch dieses Checks und des Accounts pro Tag live hochrechnen (wie der hub zaehlt)
		var proj = document.getElementById("hc-proj");
		if (proj) {
			var pnum = function (k) { return parseInt(proj.getAttribute("data-" + k), 10) || 0; };
			var ptx = function (k) { return proj.getAttribute("data-t-" + k) || ""; };
			var pfmt = function (n) { return n.toLocaleString(); };
			var calc = function () {
				var ex = document.getElementById("execution"), iv = document.getElementById("interval_seconds"), pa = document.querySelector("input[name=paused]");
				var sec = parseInt(iv && iv.value, 10) || 0;
				var locs = document.querySelectorAll("input[name=locations]:checked").length || 2;
				if (pnum("acclocs") === 1 && locs > 1) { locs = 1; }
				var cost = 0;
				if (ex && ex.value !== "local" && typeSel.value !== "push" && !(pa && pa.checked) && sec > 0) { cost = Math.floor(86400 / sec) * locs; }
				var total = pnum("other") + cost, limit = pnum("limit"), over = total > limit;
				var parts = [cost > 0 ? ptx("check").replace("{n}", pfmt(cost)).replace("{sec}", sec).replace("{locs}", locs) : ptx("local"),
					ptx("total").replace("{n}", pfmt(total)).replace("{limit}", pfmt(limit))];
				if (over) {
					var msg = ptx("over"), left = limit - pnum("today"), perMin = total / 1440;
					if (left > 0) {
						var at = new Date(Date.now() + left / perMin * 60000);
						if (at.toDateString() === new Date().toDateString()) { msg = ptx("runout").replace("{time}", at.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })); }
					}
					parts.push(msg);
				}
				proj.textContent = parts.join(" ");
				proj.className = "small mt-1 " + (over ? "text-warning-emphasis fw-semibold" : "text-body-secondary");
			};
			var pform = proj.closest("form");
			["change", "input"].forEach(function (ev) { (pform || document).addEventListener(ev, calc); });
			calc();
		}
		// TCP/Port/Zertifikat: host:port im Ziel gleich ins Port-Feld uebernehmen (der Port steht nur dort)
		var targetIn = document.getElementById("target");
		if (targetIn) {
			targetIn.addEventListener("change", function () {
				var pf = document.getElementById({ tcp: "tcp_port", port: "port_port", cert: "cert_port" }[typeSel.value]);
				var m = /^\[?([^\[\]\/]+?)\]?:(\d{1,5})$/.exec(targetIn.value.trim());
				if (!pf || !m || (m[1].indexOf(":") >= 0 && targetIn.value.trim().charAt(0) !== "[")) { return; }
				pf.value = m[2];
				targetIn.value = m[1];
			});
		}
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
			// Docker/Proxmox: diese Node und im Cluster die Nodes mit dem Bereich (data-cl); Docker nur ueber das Netz
			var item = typeSel.value === "docker" || typeSel.value === "proxmox" ? typeSel.value : "";
			var host = document.getElementById("docker_host");
			if (item === "docker" && !(host && /^(tcp|https?|ssh):\/\//i.test(host.value.trim()))) { item = "local"; }
			nodesBox.querySelectorAll("input[name=nodes]").forEach(function (cb) {
				var own = cb.closest(".form-check").querySelector(".badge.text-bg-success");
				var ok = !item || !!own || (" " + (cb.dataset.cl || "") + " ").indexOf(" " + item + " ") >= 0;
				if (!ok) { cb.checked = false; }
				cb.disabled = !ok;
			});
		};
		var hostIn = document.getElementById("docker_host");
		if (hostIn) { hostIn.addEventListener("input", function () { syncNodes(); }); }
		// Online-Standorte und Online-Test nur, wenn ipv64 mitmisst (online oder beides)
		var onlineBox = document.getElementById("onlinebox");
		var syncOnline = function () { if (onlineBox && exSel) { onlineBox.classList.toggle("d-none", exSel.value === "local"); } };
		var ivIn = document.getElementById("interval_seconds");
		var syncMin = function () { // lokal ab 5 s, online/hybrid ab 20 s; WHOIS hoechstens stuendlich
			if (!ivIn) { return; }
			var whois = typeSel.value === "whois";
			ivIn.min = whois ? 3600 : (!exSel || exSel.value === "local" ? 5 : 20);
			if (whois && (parseInt(ivIn.value, 10) || 0) < 3600) { ivIn.value = 3600; }
		};
		if (exSel) { exSel.addEventListener("change", syncNodes); exSel.addEventListener("change", syncMin); exSel.addEventListener("change", syncOnline); }
		typeSel.addEventListener("change", function () { update(); lockExec(); syncNodes(); syncMin(); syncOnline(); });
		update(); lockExec(); syncNodes(); syncMin(); syncOnline();
	}

	// Tooltips der Pillen: Inhalt aus data-Attributen, hier maskiert und als HTML gesetzt
	var esc = function (s) { return String(s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); };
	var initTips = function (root) {
		if (!window.bootstrap || !bootstrap.Tooltip) { return; }
		root.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(function (el) {
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
	};
	initTips(document);

	// Detailseite: so viele Pillen, wie in die Breite passen (neueste rechts), fehlende links als Platzhalter
	document.querySelectorAll(".beats-fill").forEach(function (bar) {
		var real = Array.prototype.slice.call(bar.querySelectorAll(".beat"));
		if (!real.length) { return; }
		var fit = function () {
			var w = real[real.length - 1].offsetWidth || 6, gap = parseFloat(getComputedStyle(bar).columnGap) || 2;
			var n = Math.max(1, Math.floor((bar.clientWidth + gap) / (w + gap)));
			bar.querySelectorAll(".beat-empty").forEach(function (e) { e.remove(); });
			real.forEach(function (el, i) { el.style.display = i < real.length - n ? "none" : ""; });
			for (var i = real.length; i < n; i++) {
				var e = document.createElement("span");
				e.className = "beat beat-lg beat-empty";
				bar.insertBefore(e, bar.firstChild);
			}
		};
		fit();
		var t;
		window.addEventListener("resize", function () { clearTimeout(t); t = setTimeout(fit, 100); });
	});

	// Filter der Liste: Auswahl sofort anwenden, Suche bei Enter, beim Verlassen des Feldes oder beim Leeren
	document.querySelectorAll("form[data-autosubmit]").forEach(function (f) {
		var go = function () {
			// leere Felder nicht in die Adresse schreiben
			f.querySelectorAll("input[name], select[name]").forEach(function (el) { if (!el.value) { el.disabled = true; } });
			f.submit();
		};
		f.querySelectorAll("select").forEach(function (s) { s.addEventListener("change", go); });
		var q = f.querySelector("input[type=search]");
		if (q) {
			q.addEventListener("change", go);
			q.addEventListener("search", function () { if (!q.value) { go(); } });
		}
	});

	// Rueckfrage vor Loeschen und Massenaktionen
	var initConfirm = function (root) { root.querySelectorAll("[data-confirm]").forEach(function (b) {
		b.addEventListener("click", function (e) {
			var form = b.form || b.closest("form");
			if (form && form.id.indexOf("hc-bulk") === 0) {
				var sel = form.querySelector("select[name=action]");
				if (sel && sel.value !== "delete") { return; }
			}
			if (!window.confirm(b.getAttribute("data-confirm"))) { e.preventDefault(); }
		});
	}); };
	initConfirm(document);

	// Alle auswaehlen: je Tabelle (Haupttabelle, Docker), nur sichtbare Zeilen
	var initSelectAll = function (root) { root.querySelectorAll("[data-select-all]").forEach(function (all) {
		all.addEventListener("change", function () {
			all.closest("form").querySelectorAll("input[name=tokens]").forEach(function (c) {
				if (!c.closest("tr") || !c.closest("tr").classList.contains("d-none")) { c.checked = all.checked; }
			});
		});
	}); };
	initSelectAll(document);

	// Gruppen auf- und zuklappen (Zustand im Browser gemerkt)
	var closed = {};
	try { closed = JSON.parse(localStorage.getItem("node64_hc_closed") || "{}"); } catch (e) { closed = {}; }
	// Untergruppen (Proxmox-System, Docker-Host): ihre Zeilen tragen data-sub-row; zugeklappt bleiben sie auch, wenn die
	// Gruppe wieder aufgeht
	function setGroup(key, hide, sub) {
		var head = document.querySelector('tr.hc-group-row[data-group="' + key + '"]');
		if (head) { head.classList.toggle("collapsed", hide); }
		document.querySelectorAll('tr[' + (sub ? "data-sub-row" : "data-group-row") + '="' + key + '"]').forEach(function (tr) {
			var s = !sub && tr.getAttribute("data-sub-row");
			var subHead = s && document.querySelector('tr.hc-group-row[data-group="' + s + '"]');
			var parent = sub && document.querySelector('tr.hc-group-row[data-group="' + tr.getAttribute("data-group-row") + '"]');
			tr.classList.toggle("d-none", hide || !!(subHead && subHead.classList.contains("collapsed")) || !!(parent && parent.classList.contains("collapsed")));
		});
	}
	var initGroups = function (root) { root.querySelectorAll(".hc-group-toggle").forEach(function (btn) {
		var key = btn.getAttribute("data-group"), sub = btn.hasAttribute("data-parent");
		var name = btn.getAttribute("data-name") || btn.textContent.trim();
		if (closed[name]) { setGroup(key, true, sub); }
		btn.addEventListener("click", function () {
			var hide = !btn.closest("tr").classList.contains("collapsed");
			setGroup(key, hide, sub);
			if (hide) { closed[name] = 1; } else { delete closed[name]; }
			try { localStorage.setItem("node64_hc_closed", JSON.stringify(closed)); } catch (e) {}
		});
	}); };
	initGroups(document);

	// Uebersicht: Countdown bis zur naechsten Messung (bei Push: Frist bis zum naechsten Push). Laeuft einer ab,
	// holt die Seite kurz darauf nur die Tabelle neu; Haekchen, Gruppen und Eingaben bleiben erhalten.
	var live = document.getElementById("hc-live");
	if (live) {
		var tx = function (k, d) { return live.getAttribute("data-t-" + k) || d; };
		var pad = function (n) { return (n < 10 ? "0" : "") + n; };
		var left = function (ms) {
			var s = Math.max(0, Math.ceil(ms / 1000));
			if (s >= 86400) { return Math.floor(s / 86400) + " d " + Math.floor(s % 86400 / 3600) + " h"; }
			if (s >= 3600) { return Math.floor(s / 3600) + ":" + pad(Math.floor(s % 3600 / 60)) + " h"; }
			return Math.floor(s / 60) + ":" + pad(s % 60);
		};
		var triggered = {}, refreshAt = 0, busy = false, lastRefresh = Date.now();
		var refresh = function () {
			var act = document.activeElement;
			if (busy || document.hidden || (act && live.contains(act) && /INPUT|SELECT|TEXTAREA/.test(act.tagName) && act.type !== "checkbox")) { return; }
			busy = true;
			fetch(location.href, { credentials: "same-origin" }).then(function (r) { return r.ok ? r.text() : Promise.reject(r.status); }).then(function (html) {
				var fresh = new DOMParser().parseFromString(html, "text/html").getElementById("hc-live");
				if (!fresh) { return; }
				var checked = {};
				live.querySelectorAll("input[name=tokens]:checked").forEach(function (c) { checked[c.value] = 1; });
				if (window.bootstrap && bootstrap.Tooltip) {
					live.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(function (el) { var t = bootstrap.Tooltip.getInstance(el); if (t) { t.dispose(); } });
				}
				live.innerHTML = fresh.innerHTML;
				live.querySelectorAll("input[name=tokens]").forEach(function (c) { if (checked[c.value]) { c.checked = true; } });
				initTips(live); initConfirm(live); initSelectAll(live); initGroups(live);
				tick();
			}).catch(function () {}).then(function () { busy = false; lastRefresh = Date.now(); });
		};
		var tick = function () {
			var now = Date.now(), due = false;
			live.querySelectorAll(".hc-next").forEach(function (el) {
				var at = el.getAttribute("data-next"), ms = Date.parse(at) - now, push = el.hasAttribute("data-push");
				if (ms > 0) {
					el.textContent = (push ? tx("push", "bis {t}") : tx("in", "in {t}")).replace("{t}", left(ms));
					el.classList.remove("text-danger");
				} else if (push) {
					el.textContent = tx("overdue", "überfällig"); el.classList.add("text-danger");
				} else {
					el.textContent = tx("now", "läuft …");
					if (ms > -60000 && !triggered[at]) { triggered[at] = 1; due = true; } // je Termin nur einmal neu laden
				}
			});
			if (due && !refreshAt) { refreshAt = now + 4000; } // kurz warten, bis das Ergebnis gespeichert ist
			if ((refreshAt && now >= refreshAt && now - lastRefresh > 8000) || now - lastRefresh > 60000) { refreshAt = 0; refresh(); }
		};
		setInterval(tick, 1000);
		tick();
	}

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
		// Legende filtert nach Messstelle: Klick = nur diese (nochmal = alle), Strg/Cmd/Umschalt-Klick = mehrere.
		// Die Auswahl bleibt beim Wechsel des Zeitraums; die Stoerungspunkte folgen ihr.
		var only = null; // Labels der sichtbaren Messstellen, null = alle
		var applyOnly = function (ch) {
			var names = ch.data.datasets.filter(function (d) { return !d.hcBad; }).map(function (d) { return d.label; });
			if (only && !names.some(function (n) { return only.indexOf(n) >= 0; })) { only = null; }
			ch.data.datasets.forEach(function (d, i) {
				if (d.hcBad) { d.data = d.hcAll.filter(function (p) { return !only || only.indexOf(p.src) >= 0; }); }
				else { ch.setDatasetVisibility(i, !only || only.indexOf(d.label) >= 0); }
			});
			ch.update();
		};
		var legendClick = function (e, item, legend) {
			var ch = legend.chart, ds = ch.data.datasets[item.datasetIndex];
			if (ds.hcBad) { ch.setDatasetVisibility(item.datasetIndex, !ch.isDatasetVisible(item.datasetIndex)); ch.update(); return; }
			var names = ch.data.datasets.filter(function (d) { return !d.hcBad; }).map(function (d) { return d.label; });
			var ev = e.native || {};
			if (ev.ctrlKey || ev.metaKey || ev.shiftKey) {
				var sel = (only || []).slice(), at = sel.indexOf(ds.label);
				if (at >= 0) { sel.splice(at, 1); } else { sel.push(ds.label); }
				only = sel.length && sel.length < names.length ? sel : null;
			} else {
				only = only && only.length === 1 && only[0] === ds.label ? null : [ds.label];
			}
			applyOnly(ch);
		};
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
				var bad = [];
				series.forEach(function (s) {
					s.points.forEach(function (p) {
						var isBad = raw ? p.ms === null : (typeof p.up === "number" && p.up < 100);
						if (isBad) {
							bad.push({ x: new Date(p.t).getTime(), y: 0, up: p.up, src: s.label, col: raw || p.up <= 0 ? danger : warn });
						}
					});
				});
				if (bad.length) {
					var badColor = function (c) { return (c.raw && c.raw.col) || danger; };
					datasets.push({ label: canvas.getAttribute("data-label-down") || "down", data: bad, hcBad: true, hcAll: bad.slice(), showLine: false, pointRadius: 3, pointHoverRadius: 5,
						pointBackgroundColor: badColor, pointBorderColor: badColor, borderColor: danger, backgroundColor: danger });
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
							legend: { display: datasets.length > 1, onClick: legendClick },
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
				if (only) { applyOnly(chart); }
				if (note && series.length > 1) { note.textContent += " " + (note.getAttribute("data-legend") || ""); }
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
