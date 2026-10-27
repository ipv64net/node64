// Honeypot64 – Live-Karte auf ipv64.net (live.php): Weltkarte aus worldmap.json, Angriffe aus live.json (statisch, alle
// 2 Minuten neu). Neue Eintraege zuerst als Boegen (mehrere gleichzeitig); nur in einem Takt ohne neue werden aeltere
// aus der letzten Stunde wiederholt (blasser, als Wiederholung markiert); Tabelle und Listen zeigen nur echte Eintraege. Land anklicken: alle
// Verbindungen von und nach dort. Vollbild mit Seitenleiste (laufende Boegen, haeufigste Verbindungen, Zahlen).
(function () {
	"use strict";
	var T = window.HL_T || {}, lang = window.HL_LANG || "de";
	var NS = "http://www.w3.org/2000/svg";
	var $ = function (id) { return document.getElementById(id); };
	var land = $("hlLand"), arcs = $("hlArcs"), selLayer = $("hlSel"), table = $("hlTable"), stage = $("hlStage");
	var namesLayer = $("hlNames"), labelLayer = $("hlLabels"), strip = $("hlStrip"), mapEl = $("hlMap");
	var pauseBtn = $("hlPause"), fullBtn = $("hlFull");
	var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
	var names = window.Intl && Intl.DisplayNames ? new Intl.DisplayNames([lang], { type: "region" }) : null;
	var tf = new Intl.DateTimeFormat(lang, { hour: "2-digit", minute: "2-digit" });
	var nf = new Intl.NumberFormat(lang);
	var MAX_LIVE = 12, PER_TICK = 3; // hoechstens so viele Boegen gleichzeitig / neue je Takt
	var map = null, entries = [], fresh = [], seen = 0, running = true, replay = 0, shownIds = {}, live = [], sel = null;
	var labels = {}, hits = {}, lastBy = {}, gen = 0; // Beschriftungen je Text (Zaehler), Boegen je Ziel-Land, Laender (Namen), Takt-Generation

	function name(cc) { try { return names ? names.of(cc) : cc; } catch (e) { return cc; } }
	function flag(cc) { return /^[A-Z]{2}$/.test(cc) ? String.fromCodePoint(0x1F1E6 + cc.charCodeAt(0) - 65, 0x1F1E6 + cc.charCodeAt(1) - 65) : ""; }
	function cn(cc) { return flag(cc) + " " + name(cc); }
	function el(n, a) { var e = document.createElementNS(NS, n); Object.keys(a || {}).forEach(function (k) { e.setAttribute(k, a[k]); }); return e; }
	// Mittelpunkt eines Landes; Kleinstaaten ohne Flaeche (Singapur, Hongkong, …) als fester Punkt (points)
	function pt(cc) { var c = map && (map.countries[cc] || (map.points || {})[cc]); return c ? [c.x, c.y] : null; }
	function svc(e) { return e.svc.toUpperCase() + (e.port ? " " + e.port : ""); }

	// Bogen von Land a nach Land b (gleiches Land: kleiner Bogen daneben)
	function curve(a, b) {
		var x1 = a[0], y1 = a[1], x2 = b[0], y2 = b[1], dx = x2 - x1, dy = y2 - y1, dist = Math.sqrt(dx * dx + dy * dy);
		if (dist < 3) { x1 += 14; y1 -= 10; dist = 17; }
		var cx = (x1 + x2) / 2, cy = (y1 + y2) / 2 - Math.max(18, dist * 0.35);
		return "M" + x1 + " " + y1 + " Q" + cx + " " + cy + " " + x2 + " " + y2;
	}

	function drawLand(byCountry) {
		land.replaceChildren();
		var max = 0;
		Object.keys(byCountry || {}).forEach(function (k) { max = Math.max(max, byCountry[k]); });
		Object.keys(map.countries).forEach(function (cc) {
			var n = (byCountry || {})[cc] || 0;
			// Stufen 1-5 logarithmisch wie in Node64 (staerkstes Land = 5)
			var lvl = n <= 0 ? 0 : (max <= 1 ? 5 : Math.min(5, 1 + Math.floor(4.999 * Math.log(n) / Math.log(max))));
			var cls = (lvl ? "hl-m" + lvl : "") + (sel && sel.cc === cc ? " hl-on" : "") + (hits[cc] > 0 ? " hl-hit" : "");
			var p = el("path", { d: map.countries[cc].d, "class": cls, "data-cc": cc });
			var t = el("title");
			t.textContent = cn(cc) + (n ? ": " + nf.format(n) + " " + T.attacks : "");
			p.appendChild(t);
			land.appendChild(p);
		});
		// Kleinstaaten mit Angriffen (Farbe der Stufe) oder als Ziel (Land des Sensors) als Punkt
		var dsts = {};
		entries.forEach(function (e) { dsts[e.dst] = true; });
		Object.keys(map.points || {}).forEach(function (cc) {
			var n = (byCountry || {})[cc] || 0;
			if (!n && !dsts[cc]) { return; }
			var lvl = n <= 0 ? 0 : (max <= 1 ? 5 : Math.min(5, 1 + Math.floor(4.999 * Math.log(n) / Math.log(max))));
			var c = el("circle", { cx: map.points[cc].x, cy: map.points[cc].y, r: 2.6, "data-cc": cc,
				"class": "hl-pt" + (lvl ? " hl-m" + lvl : "") + (sel && sel.cc === cc ? " hl-on" : "") + (hits[cc] > 0 ? " hl-hit" : "") });
			var t = el("title");
			t.textContent = cn(cc) + (n ? ": " + nf.format(n) + " " + T.attacks : "");
			c.appendChild(t);
			land.appendChild(c);
		});
	}

	// Beschriftung (Flagge und Code) an einem Punkt; gleiche Beschriftung mehrerer Boegen wird geteilt (Zaehler) und erst
	// mit dem letzten Bogen entfernt. null, wenn sie eine andere ueberdecken wuerde. Rueckgabe: Freigabe-Funktion
	function label(p, text, dst) {
		var X = p[0], Y = p[1], key = (dst ? "d|" : "s|") + text;
		if (labels[key]) { labels[key].n++; return release(key); }
		var k = unit(), x = X + 4 * k, y = Y + (dst ? 14 : -6) * k, w = (text.length * 6 + 6) * k;
		var keys = Object.keys(labels);
		for (var i = 0; i < keys.length; i++) {
			var o = labels[keys[i]].box;
			if (Math.abs(o.x - x) < Math.max(o.w, w) + 2 * k && Math.abs(o.y - y) < 15 * k) { return null; }
		}
		// kleiner Kasten (dunkelgrau, halbtransparent) mit Flagge und Code, 10 px unabhaengig von der Kartengroesse
		var g = el("g", { "class": "hl-lbl" + (dst ? " hl-lbl-dst" : "") });
		var r = el("rect", { x: x - 3 * k, y: y - 10 * k, width: w, height: 13 * k, rx: 2 * k });
		var t = el("text", { x: x, y: y, "font-size": (10 * k).toFixed(2) });
		t.textContent = text;
		g.append(r, t);
		labelLayer.appendChild(g);
		try { var bb = t.getBBox(); if (bb.width) { w = bb.width + 6 * k; r.setAttribute("width", w); } } catch (e) { /* nicht sichtbar */ }
		labels[key] = { g: g, box: { x: x, y: y, w: w }, n: 1 };
		return release(key);
	}

	function release(key) {
		var l = labels[key], done = false;
		return function () {
			if (done || labels[key] !== l) { return; } // schon frei oder nach einer Pause neu angelegt
			done = true;
			if (--l.n <= 0) { l.g.remove(); delete labels[key]; }
		};
	}

	// Kartenmass je Bildschirmpixel (Beschriftung bleibt bei jeder Kartengroesse gleich gross)
	function unit() {
		var m = mapEl.getScreenCTM && mapEl.getScreenCTM();
		return m && m.a > 0 ? 1 / m.a : 1;
	}

	// schwache Laendernamen der aktiven Laender (Quelle oder Ziel) auf der Flaeche, ohne Ueberdeckung
	function drawNames(byCountry) {
		lastBy = byCountry;
		namesLayer.replaceChildren();
		var w = {};
		Object.keys(byCountry || {}).forEach(function (cc) { w[cc] = byCountry[cc]; });
		entries.forEach(function (e) { w[e.dst] = (w[e.dst] || 0) + e.n; });
		var used = [], k = unit();
		Object.keys(w).sort(function (a, b) { return w[b] - w[a]; }).slice(0, 14).forEach(function (cc) {
			var c = map.countries[cc], pt0 = !c && (map.points || {})[cc]; // Kleinstaat: Name links neben dem Punkt
			c = c || pt0;
			if (!c) { return; }
			var n = name(cc), tw = n.length * 5.5 * k, cx = pt0 ? c.x - 5 * k - tw / 2 : c.x;
			for (var i = 0; i < used.length; i++) { if (Math.abs(used[i][0] - cx) < (used[i][2] + tw) / 2 + 2 * k && Math.abs(used[i][1] - c.y) < 13 * k) { return; } }
			used.push([cx, c.y, tw]);
			var t = el("text", { x: pt0 ? c.x - 5 * k : c.x, y: c.y + 3 * k, "class": "hl-name", "font-size": (9.5 * k).toFixed(2) });
			if (pt0) { t.style.textAnchor = "end"; }
			t.style.strokeWidth = (2.5 * k).toFixed(2);
			t.textContent = n;
			namesLayer.appendChild(t);
		});
	}

	// angegriffenes Land hell hervorheben, solange ein Bogen dorthin laeuft (Flaeche oder Punkt eines Kleinstaats)
	function hit(cc, on) {
		hits[cc] = Math.max(0, (hits[cc] || 0) + (on ? 1 : -1));
		var p = land.querySelector('[data-cc="' + cc + '"]');
		if (p) { p.classList.toggle("hl-hit", hits[cc] > 0); }
	}

	// kompakte Zahlen unter der Karte (auch ohne Vollbild)
	function renderStrip(s) {
		if (!strip) { return; }
		strip.replaceChildren();
		var add = function (title, text) {
			var sp = document.createElement("span"), b = document.createElement("b");
			b.textContent = title + ": ";
			sp.append(b, document.createTextNode(text));
			strip.appendChild(sp);
			return sp;
		};
		var top = (s.countries || []).slice(0, 3).map(function (c) { return flag(c[0]) + " " + c[0] + " " + nf.format(c[1]); });
		if (top.length) { add(T.strip_top, top.join(" · ")); }
		var p = pairs(null)[0];
		if (p) { add(T.strip_pair, flag(p.cc) + " " + p.cc + " → " + flag(p.dst) + " " + p.dst + " (" + nf.format(p.n) + ")"); }
		var k = {};
		entries.forEach(function (e) { k[e.kind] = (k[e.kind] || 0) + e.n; });
		var kk = Object.keys(k).sort(function (a, b) { return k[b] - k[a]; })[0];
		if (kk) { add(T.strip_kind, kk + " (" + nf.format(k[kk]) + ")"); }
		var lv = add(T.strip_live, String(live.length));
		lv.id = "hlStripLive";
	}

	function liveCount() {
		var x = $("hlStripLive");
		if (x) { x.lastChild.textContent = String(live.length); }
	}

	function tip(e, rep) {
		return cn(e.cc) + " (" + e.src + ") → " + cn(e.dst) + " · " + e.kind + " · " + svc(e) + " · " + tf.format(new Date(e.t)) + (rep ? " (" + T.replay + ")" : "");
	}

	function arc(e, rep) {
		var a = pt(e.cc), b = pt(e.dst);
		if (!a || !b) { return; }
		var p = el("path", { d: curve(a, b), "class": "hl-arc hl-g-" + e.group + (rep ? " hl-replay" : "") });
		var t = el("title"); t.textContent = tip(e, rep); p.appendChild(t);
		var dot = el("circle", { cx: a[0], cy: a[1], r: 2.2, "class": "hl-src hl-g-" + e.group });
		var ring = el("circle", { cx: b[0], cy: b[1], r: 4, "class": "hl-dst" });
		arcs.append(p, dot, ring);
		var item = { e: e, rep: rep, path: p, hit: true };
		live.unshift(item);
		var la = label(a, flag(e.cc) + " " + e.cc, false), lb = label(b, flag(e.dst) + " " + e.dst, true);
		hit(e.dst, true);
		renderNow(); liveCount();
		var gone = function () {
			p.remove(); dot.remove(); ring.remove();
			if (la) { la(); }
			if (lb) { lb(); }
			if (item.hit) { item.hit = false; hit(e.dst, false); }
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

	function row(sw, text, opts) {
		var r = document.createElement("div");
		r.className = "hl-row" + (opts && opts.rep ? " hl-rep" : "") + (opts && opts.click ? " hl-click" : "");
		var s = document.createElement("span"); s.className = "hl-sw hl-g-" + sw;
		var x = document.createElement("span"); x.textContent = text;
		r.append(s, x);
		if (opts && opts.title) { r.title = opts.title; }
		if (opts && opts.click) { r.addEventListener("click", opts.click); }
		if (opts && opts.hot) {
			r.addEventListener("mouseenter", function () { opts.hot(true); });
			r.addEventListener("mouseleave", function () { opts.hot(false); });
		}
		return r;
	}

	function isFull() { return stage.classList.contains("hl-fs"); }

	// Seitenleiste: Boegen, die gerade zu sehen sind
	function renderNow() {
		var box = $("hlNow");
		if (!box || !isFull()) { return; }
		box.replaceChildren();
		if (!live.length) { box.textContent = T.now_empty; return; }
		live.slice(0, MAX_LIVE).forEach(function (it) {
			var e = it.e;
			box.appendChild(row(e.group, tf.format(new Date(e.t)) + " " + flag(e.cc) + " " + e.cc + " → " + flag(e.dst) + " " + e.dst + " · " + e.kind + " · " + svc(e) + (it.rep ? " (" + T.replay + ")" : ""),
				{ rep: it.rep, title: tip(e, it.rep), hot: function (on) { it.path.classList.toggle("hl-hot", on); } }));
		});
	}

	// Verbindungen Land -> Land aus den echten Eintraegen (Summe, staerkste Art-Gruppe)
	function pairs(filter) {
		var m = {};
		entries.forEach(function (e) {
			if (filter && !filter(e)) { return; }
			var k = e.cc + ">" + e.dst;
			var p = m[k] || (m[k] = { cc: e.cc, dst: e.dst, n: 0, groups: {}, kinds: {}, t: 0 });
			p.n += e.n; p.t = Math.max(p.t, e.t);
			p.groups[e.group] = (p.groups[e.group] || 0) + e.n;
			p.kinds[e.kind] = (p.kinds[e.kind] || 0) + e.n;
		});
		return Object.keys(m).map(function (k) {
			var p = m[k];
			p.group = Object.keys(p.groups).sort(function (a, b) { return p.groups[b] - p.groups[a]; })[0];
			p.kindList = Object.keys(p.kinds).sort(function (a, b) { return p.kinds[b] - p.kinds[a]; });
			return p;
		}).sort(function (a, b) { return b.n - a.n; });
	}

	function pairText(p) { return flag(p.cc) + " " + name(p.cc) + " → " + flag(p.dst) + " " + name(p.dst) + " · " + nf.format(p.n) + " · " + p.kindList.slice(0, 2).join(", "); }

	function renderPairs() {
		var box = $("hlPairs");
		if (!box) { return; }
		box.replaceChildren();
		var list = pairs(null);
		if (!list.length) { box.textContent = T.empty; return; }
		list.slice(0, 10).forEach(function (p) {
			box.appendChild(row(p.group, pairText(p), { click: function () { select({ cc: null, from: p.cc, to: p.dst }); } }));
		});
	}

	// Auswahl: Land (alle Verbindungen von und nach dort) oder eine Verbindung; als feste Boegen auf der Karte
	function select(s) {
		sel = s;
		renderSel();
		land.querySelectorAll(".hl-on").forEach(function (x) { x.classList.remove("hl-on"); });
		if (sel && sel.cc) { var lp = land.querySelector('[data-cc="' + sel.cc + '"]'); if (lp) { lp.classList.add("hl-on"); } }
	}

	function renderSel() {
		selLayer.replaceChildren();
		var box = $("hlSelBox"), list = $("hlSelList");
		if (!sel) { box.hidden = true; return; }
		var ps = pairs(sel.cc ? function (e) { return e.cc === sel.cc || e.dst === sel.cc; } : function (e) { return e.cc === sel.from && e.dst === sel.to; });
		$("hlSelTitle").textContent = sel.cc ? (T.sel_country || "").replace("{name}", cn(sel.cc)) :
			(T.sel_pair || "").replace("{from}", cn(sel.from)).replace("{to}", cn(sel.to));
		list.replaceChildren();
		box.hidden = false;
		if (!ps.length) { list.textContent = T.sel_empty; return; }
		var max = ps[0].n;
		ps.forEach(function (p) {
			var a = pt(p.cc), b = pt(p.dst);
			if (!a || !b) { return; }
			var w = 1.2 + 3 * (max > 1 ? Math.log(p.n) / Math.log(max) : 1);
			var path = el("path", { d: curve(a, b), "class": "hl-g-" + p.group, "stroke-width": w.toFixed(1) });
			path.style.fill = "none";
			var t = el("title"); t.textContent = pairText(p); path.appendChild(t);
			selLayer.appendChild(path);
			list.appendChild(row(p.group, pairText(p), { title: p.kindList.join(", "), hot: function (on) { path.classList.toggle("hl-hot", on); } }));
		});
	}

	function renderTable(list) {
		table.replaceChildren();
		if (!list.length) {
			var tr0 = document.createElement("tr"), td0 = document.createElement("td");
			td0.colSpan = 6; td0.className = "text-muted"; td0.textContent = T.empty;
			tr0.appendChild(td0); table.appendChild(tr0);
			return;
		}
		list.slice(0, 40).forEach(function (e) {
			var id = e.t + "|" + e.src + "|" + e.kind + "|" + e.port + "|" + e.dst;
			var tr = document.createElement("tr");
			if (seen && !shownIds[id]) { tr.className = "hl-new"; }
			shownIds[id] = true;
			var sw = '<span class="hl-sw hl-g-' + e.group + '"></span> ';
			[tf.format(new Date(e.t)), flag(e.cc) + " " + e.src, sw + e.kind, svc(e), cn(e.dst), nf.format(e.n)].forEach(function (v, i) {
				var td = document.createElement("td");
				if (i === 2) { td.innerHTML = sw; td.appendChild(document.createTextNode(e.kind)); } else { td.textContent = v; }
				if (i === 1) { td.className = "hp-mono"; }
				if (i === 5) { td.className = "text-right"; }
				tr.appendChild(td);
			});
			table.appendChild(tr);
		});
	}

	function stats(s) {
		var set = function (k, v) { document.querySelectorAll('[data-hl-stat="' + k + '"]').forEach(function (x) { x.textContent = v; }); };
		set("events", nf.format(s.events || 0));
		set("sources", nf.format(s.sources || 0));
		set("targets", nf.format(s.targets || 0));
		var top = (s.countries || [])[0];
		set("top", top ? cn(top[0]) : "–");
	}

	function load() {
		return fetch("live.json?t=" + Math.floor(Date.now() / 60000), { cache: "no-store" }).then(function (r) { if (!r.ok) { throw new Error(r.status); } return r.json(); }).then(function (d) {
			var list = d.entries || [];
			var max = seen;
			list.forEach(function (e) { if (seen && e.t > seen) { fresh.push(e); } if (e.t > max) { max = e.t; } });
			entries = list.slice().reverse();
			drawLand((d.stats || {}).by_country);
			drawNames((d.stats || {}).by_country);
			stats(d.stats || {});
			renderStrip(d.stats || {});
			renderTable(list);
			renderPairs();
			if (sel) { select(sel); }
			seen = max || 1;
			$("hlUpdated").textContent = (T.updated || "").replace("{time}", new Date(d.generated).toLocaleString(lang));
		}).catch(function () { $("hlUpdated").textContent = T.unavailable; });
	}

	// Je Takt bis zu PER_TICK Boegen: neue Eintraege; nur in einem Takt ohne neue 1-2 Wiederholungen (verschiedene
	// Verbindungen). Die Boegen eines Takts starten versetzt; nach einer Pause (gen) faellt der Rest weg.
	function tick() {
		if (!running || document.hidden || !map) { return; }
		var room = Math.min(PER_TICK, MAX_LIVE - live.length), batch = [], used = {}, tries = 0, g = gen;
		while (room > 0 && fresh.length) { batch.push([fresh.shift(), false]); room--; }
		if (!batch.length) {
			room = Math.min(room, Math.random() < 0.5 ? 1 : 2);
			while (room > 0 && entries.length && tries < Math.min(entries.length, 20)) {
				var e = entries[replay++ % entries.length]; tries++;
				var k = e.cc + ">" + e.dst;
				if (used[k]) { continue; }
				used[k] = true;
				batch.push([e, true]); room--;
			}
		}
		batch.forEach(function (b, i) { setTimeout(function () { if (running && g === gen) { arc(b[0], b[1]); } }, i * 300); });
	}

	function setBadges() {
		var cls = running ? "badge-danger" : "badge-secondary";
		$("hlLiveBadge").className = "badge align-middle small " + cls;
		document.querySelectorAll("[data-hl-badge]").forEach(function (b) { b.className = "badge " + cls; });
	}

	pauseBtn.addEventListener("click", function () {
		running = !running;
		pauseBtn.innerHTML = running ? '<i class="fa-solid fa-pause"></i> ' + T.pause : '<i class="fa-solid fa-play"></i> ' + T.play;
		setBadges();
		if (!running) {
			gen++;
			live.forEach(function (it) { it.hit = false; });
			arcs.replaceChildren(); labelLayer.replaceChildren(); labels = {}; live = []; hits = {};
			land.querySelectorAll(".hl-hit").forEach(function (x) { x.classList.remove("hl-hit"); });
			renderNow(); liveCount();
		}
	});

	// Vollbild: Fullscreen API, sonst (z. B. iPhone) die Karte ueber die ganze Seite legen
	function setFull(on) {
		stage.classList.toggle("hl-fs", on);
		fullBtn.innerHTML = on ? '<i class="fa-solid fa-compress"></i> ' + T.full_exit : '<i class="fa-solid fa-expand"></i> ' + T.full;
		document.body.style.overflow = on && !document.fullscreenElement ? "hidden" : "";
		renderNow();
		renderPairs();
		if (map) { drawNames(lastBy); }
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
	fullBtn.addEventListener("click", toggleFull);
	var rsz = 0;
	window.addEventListener("resize", function () { clearTimeout(rsz); rsz = setTimeout(function () { if (map) { drawNames(lastBy); } }, 300); });
	stage.querySelector("[data-hl-exit]").addEventListener("click", toggleFull);
	document.addEventListener("fullscreenchange", function () { setFull(document.fullscreenElement === stage); });
	document.addEventListener("keydown", function (ev) {
		if (ev.key !== "Escape") { return; }
		if (isFull() && !document.fullscreenElement) { setFull(false); } else if (!isFull() && sel) { select(null); }
	});

	land.addEventListener("click", function (ev) {
		var cc = ev.target && ev.target.getAttribute && ev.target.getAttribute("data-cc");
		if (cc) { select(sel && sel.cc === cc ? null : { cc: cc }); }
	});
	$("hlMap").addEventListener("click", function (ev) { if (ev.target === ev.currentTarget && sel) { select(null); } });
	$("hlSelClear").addEventListener("click", function () { select(null); });

	fetch("worldmap.json?v=3", { cache: "force-cache" }).then(function (r) { return r.json(); }).then(function (m) {
		map = m;
		$("hlMap").setAttribute("viewBox", m.viewBox);
		drawLand({});
		load();
		setInterval(tick, 1100);
		setInterval(function () { if (!document.hidden) { load(); } }, 60000);
	});
})();
