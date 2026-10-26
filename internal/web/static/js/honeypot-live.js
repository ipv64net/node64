// Honeypot64: Live-Karte – auf der Laenderkarte der Uebersicht fliegen Boegen von der Quelle eines Angriffs zum eigenen
// Sensor (Daten: /api/honeypot/live, letzte 60 Minuten, jede Minute neu). Neue Angriffe zuerst; ist gerade nichts
// Neues da, werden aeltere aus dem Zeitraum wiederholt (nur auf der Karte, die Liste zeigt nur echte Eintraege).
(function () {
	"use strict";
	var svg = document.querySelector("[data-hp-live-map]");
	if (!svg) { return; }
	var layer = svg.querySelector("[data-hp-live-layer]");
	var list = document.querySelector("[data-hp-live-list]");
	var btn = document.querySelector("[data-hp-live-toggle]");
	var NS = "http://www.w3.org/2000/svg";
	var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
	var target = null, events = [], fresh = [], seen = 0, running = true, replay = 0, recent = [];
	var L = function (k) { return (list && list.getAttribute("data-l-" + k)) || ""; };
	var timeFmt = new Intl.DateTimeFormat(document.documentElement.lang || undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });

	function el(name, attrs) {
		var e = document.createElementNS(NS, name);
		Object.keys(attrs || {}).forEach(function (k) { e.setAttribute(k, attrs[k]); });
		return e;
	}

	function tip(e, rep) {
		return e.flag + " " + e.name + " · " + e.ip + " · " + e.kind + " · " + e.service.toUpperCase() + (e.port ? " " + e.port : "") +
			" · " + timeFmt.format(new Date(e.t)) + (rep ? " (" + L("replay") + ")" : "");
	}

	// Ziel: pulsierender Punkt am eigenen Standort
	function drawTarget() {
		var old = layer.querySelector(".hp-target");
		if (old) { old.remove(); }
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
		var x1 = e.x, y1 = e.y, x2 = target.x, y2 = target.y;
		var dx = x2 - x1, dy = y2 - y1, dist = Math.sqrt(dx * dx + dy * dy);
		if (dist < 3) { // Angriff aus dem eigenen Land: kleiner Kreis statt Bogen
			x1 += 14; y1 -= 10; dist = 17;
		}
		var cx = (x1 + x2) / 2, cy = (y1 + y2) / 2 - Math.max(18, dist * 0.35);
		var p = el("path", { d: "M" + x1 + " " + y1 + " Q" + cx + " " + cy + " " + x2 + " " + y2, "class": "hp-arc hp-g-" + e.group + (rep ? " hp-arc-replay" : "") });
		var t = el("title");
		t.textContent = tip(e, rep);
		p.appendChild(t);
		var dot = el("circle", { cx: e.x, cy: e.y, r: 2, "class": "hp-src hp-g-" + e.group });
		layer.insertBefore(p, layer.firstChild);
		layer.insertBefore(dot, layer.firstChild);
		var gone = function () { p.remove(); dot.remove(); };
		if (!reduce && p.animate && p.getTotalLength) {
			var len = p.getTotalLength();
			p.style.strokeDasharray = len;
			p.animate([{ strokeDashoffset: len, opacity: 1 }, { strokeDashoffset: 0, opacity: 1, offset: 0.55 }, { strokeDashoffset: 0, opacity: 0 }],
				{ duration: 2800, easing: "ease-out" }).onfinish = gone;
		} else {
			setTimeout(gone, 2800);
		}
	}

	// Liste: die letzten echten Angriffe (neueste oben)
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
			var row = document.createElement("div");
			row.className = "hp-live-row";
			var dot = document.createElement("span");
			dot.className = "hp-live-sw hp-g-" + e.group;
			var txt = document.createElement("span");
			txt.textContent = timeFmt.format(new Date(e.t)) + " · " + e.flag + " " + e.cc + " · " + e.ip + " → " + e.service.toUpperCase() + (e.port ? " " + e.port : "") + " · " + e.kind;
			txt.className = "font-monospace";
			row.append(dot, txt);
			row.title = e.name;
			list.appendChild(row);
		});
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
		}).catch(function () {});
	}

	function tick() {
		if (!running || !target || document.hidden) { return; }
		if (fresh.length) { arc(fresh.shift(), false); return; }
		if (events.length) { arc(events[replay++ % events.length], true); }
	}

	if (btn) {
		btn.addEventListener("click", function () {
			running = !running;
			btn.setAttribute("aria-pressed", running ? "true" : "false");
			btn.classList.toggle("btn-outline-danger", running);
			btn.classList.toggle("btn-outline-secondary", !running);
			if (!running) { layer.querySelectorAll(".hp-arc, .hp-src").forEach(function (x) { x.remove(); }); }
		});
	}
	load();
	setInterval(tick, 1200);
	setInterval(function () { if (!document.hidden) { load(); } }, 60000);
})();
