// Honeypot64: Live-Karte – auf der Laenderkarte der Uebersicht fliegen Boegen von der Quelle eines Angriffs zum eigenen
// Sensor (Daten: /api/honeypot/live, letzte 60 Minuten, jede Minute neu). Neue Angriffe zuerst, mehrere gleichzeitig;
// ist gerade nichts Neues da, werden aeltere aus dem Zeitraum wiederholt (nur auf der Karte, als Wiederholung markiert;
// die Listen zeigen nur echte Eintraege). Vollbild mit Seitenleiste: laufende Boegen, haeufigste Herkunft (anklickbar:
// feste Boegen und Arten aus diesem Land).
(function () {
	"use strict";
	var svg = document.querySelector("[data-hp-live-map]");
	if (!svg) { return; }
	var $ = function (s) { return document.querySelector(s); };
	var layer = svg.querySelector("[data-hp-live-layer]"), selLayer = svg.querySelector("[data-hp-live-sel]");
	var list = $("[data-hp-live-list]"), btn = $("[data-hp-live-toggle]"), stage = $("[data-hp-live-stage]"), fullBtn = $("[data-hp-live-full]");
	var nowBox = $("[data-hp-live-now]"), topBox = $("[data-hp-live-top]"), selBox = $("[data-hp-live-selbox]");
	var namesLayer = svg.querySelector("[data-hp-live-names]"), labelLayer = svg.querySelector("[data-hp-live-labels]"), strip = $("[data-hp-live-strip]");
	var NS = "http://www.w3.org/2000/svg";
	var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
	var MAX_LIVE = 12, PER_TICK = 3; // hoechstens so viele Boegen gleichzeitig / neue je Takt
	var target = null, events = [], fresh = [], seen = 0, running = true, replay = 0, recent = [], live = [], sel = null;
	var boxes = [], hits = 0; // belegte Flaechen der Beschriftungen, laufende Boegen (eigenes Land hervorgehoben)
	var nf = new Intl.NumberFormat(document.documentElement.lang || undefined);
	var L = function (k) { return (list && list.getAttribute("data-l-" + k)) || ""; };
	var timeFmt = new Intl.DateTimeFormat(document.documentElement.lang || undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });

	function el(name, attrs) {
		var e = document.createElementNS(NS, name);
		Object.keys(attrs || {}).forEach(function (k) { e.setAttribute(k, attrs[k]); });
		return e;
	}

	// Beschriftung (Flagge und Code) an einem Punkt; null, wenn sie eine andere ueberdecken wuerde
	function label(X, Y, text, dst) {
		if (!labelLayer) { return null; }
		var k = unit(), x = X + 4 * k, y = Y + (dst ? 14 : -6) * k, w = (text.length * 6 + 6) * k;
		for (var i = 0; i < boxes.length; i++) {
			if (Math.abs(boxes[i].x - x) < Math.max(boxes[i].w, w) + 2 * k && Math.abs(boxes[i].y - y) < 15 * k) { return null; }
		}
		// kleiner Kasten (dunkelgrau, halbtransparent) mit Flagge und Code, 10 px unabhaengig von der Kartengroesse
		var g = el("g", { "class": "hp-lbl" + (dst ? " hp-lbl-dst" : "") });
		var r = el("rect", { x: x - 3 * k, y: y - 10 * k, width: w, height: 13 * k, rx: 2 * k });
		var t = el("text", { x: x, y: y, "font-size": (10 * k).toFixed(2) });
		t.textContent = text;
		g.append(r, t);
		labelLayer.appendChild(g);
		try { var bb = t.getBBox(); if (bb.width) { w = bb.width + 6 * k; r.setAttribute("width", w); } } catch (e) { /* nicht sichtbar */ }
		var box = { x: x, y: y, w: w };
		boxes.push(box);
		return function () { g.remove(); boxes = boxes.filter(function (b) { return b !== box; }); };
	}

	// Kartenmass je Bildschirmpixel (Beschriftung bleibt bei jeder Kartengroesse gleich gross)
	function unit() {
		var m = svg.getScreenCTM && svg.getScreenCTM();
		return m && m.a > 0 ? 1 / m.a : 1;
	}

	// eigenes Land hell hervorheben, solange ein Bogen dorthin laeuft
	function hit(on) {
		hits = Math.max(0, hits + (on ? 1 : -1));
		var p = target && target.known ? svg.querySelector('path[data-cc="' + target.cc + '"]') : null;
		if (p) { p.classList.toggle("hp-hit", hits > 0); }
	}

	// schwache Laendernamen der Herkunftslaender und des eigenen Lands, ohne Ueberdeckung
	function drawNames() {
		if (!namesLayer) { return; }
		namesLayer.replaceChildren();
		var list = byCountry().slice(0, 12);
		if (target && target.known) { list.unshift({ name: target.name, x: target.x, y: target.y }); }
		var used = [], k = unit();
		list.forEach(function (c) {
			var tw = c.name.length * 5.5 * k;
			for (var i = 0; i < used.length; i++) { if (Math.abs(used[i][0] - c.x) < (used[i][2] + tw) / 2 + 2 * k && Math.abs(used[i][1] - c.y) < 13 * k) { return; } }
			used.push([c.x, c.y, tw]);
			var t = el("text", { x: c.x, y: c.y + 3 * k, "class": "hp-name", "font-size": (9.5 * k).toFixed(2) });
			t.style.strokeWidth = (2.5 * k).toFixed(2);
			t.textContent = c.name;
			namesLayer.appendChild(t);
		});
	}

	// kompakte Zahlen unter der Karte (auch ohne Vollbild)
	function renderStrip() {
		if (!strip) { return; }
		strip.replaceChildren();
		var add = function (key, text) {
			var sp = document.createElement("span"), b = document.createElement("span");
			b.className = "fw-semibold";
			b.textContent = strip.getAttribute("data-l-" + key) + ": ";
			sp.append(b, document.createTextNode(text));
			sp.setAttribute("data-k", key);
			strip.appendChild(sp);
		};
		var cs = byCountry();
		add("events", nf.format(events.length));
		add("countries", nf.format(cs.length));
		if (cs.length) { add("top", cs.slice(0, 3).map(function (c) { return c.flag + " " + c.cc + " " + nf.format(c.n); }).join(" · ")); }
		var k = {};
		events.forEach(function (e) { k[e.kind] = (k[e.kind] || 0) + 1; });
		var kk = Object.keys(k).sort(function (a, b) { return k[b] - k[a]; })[0];
		if (kk) { add("kind", kk + " (" + nf.format(k[kk]) + ")"); }
		add("now", String(live.length));
	}

	function liveCount() {
		var x = strip && strip.querySelector('[data-k="now"]');
		if (x) { x.lastChild.textContent = String(live.length); }
	}

	function svc(e) { return e.service.toUpperCase() + (e.port ? " " + e.port : ""); }

	function tip(e, rep) {
		return e.flag + " " + e.name + " · " + e.ip + " · " + e.kind + " · " + svc(e) + " · " + timeFmt.format(new Date(e.t)) + (rep ? " (" + L("replay") + ")" : "");
	}

	// Bogen von (x1, y1) zum Ziel (Angriff aus dem eigenen Land: kleiner Bogen daneben)
	function curve(x1, y1) {
		var x2 = target.x, y2 = target.y, dx = x2 - x1, dy = y2 - y1, dist = Math.sqrt(dx * dx + dy * dy);
		if (dist < 3) { x1 += 14; y1 -= 10; dist = 17; }
		var cx = (x1 + x2) / 2, cy = (y1 + y2) / 2 - Math.max(18, dist * 0.35);
		return "M" + x1 + " " + y1 + " Q" + cx + " " + cy + " " + x2 + " " + y2;
	}

	// Ziel: pulsierender Punkt am eigenen Standort
	function drawTarget() {
		var old = layer.querySelector(".hp-target");
		if (old) { old.remove(); }
		var label = $("[data-hp-live-target]");
		if (label) { label.textContent = target && target.known ? "→ " + target.flag + " " + target.name : ""; }
		if (!target) { return; }
		var g = el("g", { "class": "hp-target" });
		g.appendChild(el("circle", { cx: target.x, cy: target.y, r: 4, "class": "hp-target-ring" }));
		g.appendChild(el("circle", { cx: target.x, cy: target.y, r: 2.2, "class": "hp-target-dot" }));
		var t = el("title");
		t.textContent = target.known ? L("target").replace("{name}", target.flag + " " + target.name) : L("unknown");
		g.appendChild(t);
		layer.appendChild(g);
	}

	function arc(e, rep) {
		if (!target) { return; }
		var p = el("path", { d: curve(e.x, e.y), "class": "hp-arc hp-g-" + e.group + (rep ? " hp-arc-replay" : "") });
		var t = el("title");
		t.textContent = tip(e, rep);
		p.appendChild(t);
		var dot = el("circle", { cx: e.x, cy: e.y, r: 2, "class": "hp-src hp-g-" + e.group });
		layer.insertBefore(p, layer.firstChild);
		layer.insertBefore(dot, layer.firstChild);
		var item = { e: e, rep: rep, path: p };
		live.unshift(item);
		var la = label(e.x, e.y, e.flag + " " + e.cc, false), lb = target.known ? label(target.x, target.y, target.flag + " " + target.cc, true) : null;
		hit(true);
		renderNow(); liveCount();
		var gone = function () {
			p.remove(); dot.remove();
			if (la) { la(); }
			if (lb) { lb(); }
			hit(false);
			live = live.filter(function (x) { return x !== item; });
			renderNow(); liveCount();
		};
		if (!reduce && p.animate && p.getTotalLength) {
			var len = p.getTotalLength();
			p.style.strokeDasharray = len;
			p.animate([{ strokeDashoffset: len, opacity: 1 }, { strokeDashoffset: 0, opacity: 1, offset: 0.55 }, { strokeDashoffset: 0, opacity: 0 }],
				{ duration: 3200, easing: "ease-out" }).onfinish = gone;
		} else {
			setTimeout(gone, 3200);
		}
	}

	function row(group, text, opts) {
		var r = document.createElement("div");
		r.className = "hp-live-row" + (opts && opts.rep ? " hp-live-rep" : "") + (opts && opts.click ? " hp-live-click" : "");
		var dot = document.createElement("span");
		dot.className = "hp-live-sw hp-g-" + group;
		var txt = document.createElement("span");
		txt.textContent = text;
		r.append(dot, txt);
		if (opts && opts.title) { r.title = opts.title; }
		if (opts && opts.click) { r.addEventListener("click", opts.click); }
		if (opts && opts.hot) {
			r.addEventListener("mouseenter", function () { opts.hot(true); });
			r.addEventListener("mouseleave", function () { opts.hot(false); });
		}
		return r;
	}

	function isFull() { return stage && stage.classList.contains("hp-fs"); }

	// Liste unter der Karte: die letzten echten Angriffe (neueste oben)
	function renderList() {
		if (!list) { return; }
		list.replaceChildren();
		if (!recent.length) {
			list.textContent = L("empty");
			list.classList.add("text-body-secondary");
			return;
		}
		list.classList.remove("text-body-secondary");
		recent.slice(0, 8).forEach(function (e) {
			var r = row(e.group, timeFmt.format(new Date(e.t)) + " · " + e.flag + " " + e.cc + " · " + e.ip + " → " + svc(e) + " · " + e.kind, { title: e.name });
			r.lastChild.className = "font-monospace";
			list.appendChild(r);
		});
	}

	// Seitenleiste (Vollbild): Boegen, die gerade zu sehen sind
	function renderNow() {
		if (!nowBox || !isFull()) { return; }
		nowBox.replaceChildren();
		if (!live.length) { nowBox.textContent = nowBox.getAttribute("data-l-empty"); return; }
		live.slice(0, MAX_LIVE).forEach(function (it) {
			var e = it.e;
			nowBox.appendChild(row(e.group, timeFmt.format(new Date(e.t)) + " " + e.flag + " " + e.cc + " · " + e.ip + " · " + e.kind + " · " + svc(e) + (it.rep ? " (" + L("replay") + ")" : ""),
				{ rep: it.rep, title: tip(e, it.rep), hot: function (on) { it.path.classList.toggle("hp-hot", on); } }));
		});
	}

	// Herkunftslaender der letzten Stunde (Anzahl, staerkste Art-Gruppe)
	function byCountry() {
		var m = {};
		events.forEach(function (e) {
			var c = m[e.cc] || (m[e.cc] = { cc: e.cc, flag: e.flag, name: e.name, x: e.x, y: e.y, n: 0, groups: {}, kinds: {} });
			c.n++;
			c.groups[e.group] = (c.groups[e.group] || 0) + 1;
			var k = e.kind + " · " + svc(e);
			c.kinds[k] = c.kinds[k] || { n: 0, group: e.group };
			c.kinds[k].n++;
		});
		return Object.keys(m).map(function (k) {
			var c = m[k];
			c.group = Object.keys(c.groups).sort(function (a, b) { return c.groups[b] - c.groups[a]; })[0];
			return c;
		}).sort(function (a, b) { return b.n - a.n; });
	}

	function renderTop() {
		if (!topBox) { return; }
		topBox.replaceChildren();
		var cs = byCountry();
		if (!cs.length) { topBox.textContent = L("empty"); return; }
		cs.slice(0, 10).forEach(function (c) {
			topBox.appendChild(row(c.group, c.flag + " " + c.name + " · " + c.n, { click: function () { select(sel === c.cc ? null : c.cc); } }));
		});
	}

	// Auswahl eines Herkunftslands: fester Bogen und die Arten der Angriffe von dort
	function select(cc) {
		sel = cc;
		selLayer.replaceChildren();
		if (!selBox) { return; }
		var c = cc && byCountry().filter(function (x) { return x.cc === cc; })[0];
		if (!c || !target) { sel = null; selBox.hidden = true; return; }
		var p = el("path", { d: curve(c.x, c.y), "class": "hp-g-" + c.group, "stroke-width": "3" });
		var t = el("title"); t.textContent = c.flag + " " + c.name + " → " + target.flag + " " + target.name + " · " + c.n; p.appendChild(t);
		selLayer.appendChild(p);
		var title = $("[data-hp-live-seltitle]");
		title.textContent = title.getAttribute("data-l-title").replace("{name}", c.flag + " " + c.name);
		var box = $("[data-hp-live-sellist]");
		box.replaceChildren();
		Object.keys(c.kinds).sort(function (a, b) { return c.kinds[b].n - c.kinds[a].n; }).forEach(function (k) {
			box.appendChild(row(c.kinds[k].group, k + " · " + c.kinds[k].n));
		});
		selBox.hidden = false;
	}

	function load() {
		return fetch("/api/honeypot/live?minutes=60", { cache: "no-store", credentials: "same-origin" }).then(function (r) { return r.json(); }).then(function (d) {
			target = d.target || null;
			events = (d.events || []).slice().reverse(); // aelteste zuerst (Wiederholung in Zeitfolge)
			var max = seen;
			events.forEach(function (e) {
				if (seen && e.t > seen) { fresh.push(e); }
				if (e.t > max) { max = e.t; }
			});
			seen = max || Date.now();
			recent = (d.events || []).slice(0, 8);
			drawTarget();
			renderList();
			renderTop();
			drawNames();
			renderStrip();
			if (sel) { select(sel); }
		}).catch(function () {});
	}

	// Je Takt bis zu PER_TICK Boegen: zuerst neue Angriffe, sonst Wiederholung aus verschiedenen Laendern
	function tick() {
		if (!running || !target || document.hidden) { return; }
		var room = Math.min(PER_TICK, MAX_LIVE - live.length), batch = [], used = {}, tries = 0;
		while (room > 0 && fresh.length) { batch.push([fresh.shift(), false]); room--; }
		if (!batch.length) { room = Math.min(room, 1 + (Math.random() < 0.5 ? 1 : 0)); }
		while (room > 0 && events.length && tries < Math.min(events.length, 20)) {
			var e = events[replay++ % events.length]; tries++;
			if (used[e.cc]) { continue; }
			used[e.cc] = true;
			batch.push([e, true]); room--;
		}
		batch.forEach(function (b, i) { setTimeout(function () { arc(b[0], b[1]); }, i * 300); });
	}

	if (btn) {
		btn.addEventListener("click", function () {
			running = !running;
			btn.setAttribute("aria-pressed", running ? "true" : "false");
			btn.classList.toggle("btn-outline-danger", running);
			btn.classList.toggle("btn-outline-secondary", !running);
			if (!running) {
				layer.querySelectorAll(".hp-arc, .hp-src").forEach(function (x) { x.remove(); });
				if (labelLayer) { labelLayer.replaceChildren(); }
				boxes = []; live = []; hits = 1; hit(false);
				renderNow(); liveCount();
			}
		});
	}

	// Vollbild: Fullscreen API, sonst (z. B. iPhone) die Karte ueber die ganze Seite legen
	function setFull(on) {
		stage.classList.toggle("hp-fs", on);
		document.body.style.overflow = on && !document.fullscreenElement ? "hidden" : "";
		renderNow();
		drawNames();
	}
	function toggleFull() {
		if (isFull()) {
			if (document.fullscreenElement && document.exitFullscreen) { document.exitFullscreen(); } else { setFull(false); }
		} else if (stage.requestFullscreen) {
			stage.requestFullscreen().catch(function () { setFull(true); });
		} else {
			setFull(true);
		}
	}
	var rsz = 0;
	window.addEventListener("resize", function () { clearTimeout(rsz); rsz = setTimeout(drawNames, 300); });
	if (stage && fullBtn) {
		fullBtn.addEventListener("click", toggleFull);
		var exit = stage.querySelector("[data-hp-live-exit]");
		if (exit) { exit.addEventListener("click", toggleFull); }
		document.addEventListener("fullscreenchange", function () { setFull(document.fullscreenElement === stage); });
		document.addEventListener("keydown", function (ev) { if (ev.key === "Escape" && isFull() && !document.fullscreenElement) { setFull(false); } });
	}
	var clear = $("[data-hp-live-selclear]");
	if (clear) { clear.addEventListener("click", function () { select(null); }); }

	load();
	setInterval(tick, 1100);
	setInterval(function () { if (!document.hidden) { load(); } }, 60000);
})();
