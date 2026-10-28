// Sonar64: Live-Tabellen der Seite /sonar64 – „Pings von mir“ und live auf UDP 6464 beantwortete Proben alle 5 s
// (/api/sonar64/recent), „Pings gegen mich“ aus den Ergebnissen bei ipv64 jede Minute (/api/sonar64/inbound).
// Nur textContent (keine HTML-Einfuegung); bei verdeckter Seite ruht die Abfrage.
(function () {
	"use strict";
	var out = document.querySelector("[data-s64-out]");
	if (!out) { return; }
	var live = document.querySelector("[data-s64-in-live]");
	var inb = document.querySelector("[data-s64-in]");
	var state = document.querySelector("[data-s64-live-state]");
	var labels = document.querySelector("[data-s64-labels]");
	var lang = document.documentElement.lang || undefined;
	var timeFmt = new Intl.DateTimeFormat(lang, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
	var numFmt = new Intl.NumberFormat(lang, { minimumFractionDigits: 1, maximumFractionDigits: 1 });
	var L = function (k) { return (labels && labels.getAttribute("data-l-" + k)) || k; };
	var timer = null, inTimer = null;

	function cell(tr, text, cls, title) {
		var td = document.createElement("td");
		td.textContent = text;
		if (cls) { td.className = cls; }
		if (title) { td.title = title; }
		tr.appendChild(td);
		return td;
	}

	function when(s) {
		var d = new Date(s);
		return isNaN(d.getTime()) ? "–" : timeFmt.format(d);
	}

	function fill(tbody, rows, cols, row) {
		var frag = document.createDocumentFragment();
		if (!rows || rows.length === 0) {
			var tr = document.createElement("tr");
			var td = cell(tr, tbody.getAttribute("data-l-empty") || "", "text-body-secondary small");
			td.colSpan = cols;
			frag.appendChild(tr);
		} else {
			rows.forEach(function (r) { var tr = document.createElement("tr"); row(tr, r); frag.appendChild(tr); });
		}
		tbody.replaceChildren(frag);
	}

	function method(m, fam) { return L(m) + " · IPv" + fam; }

	function renderRecent(d) {
		fill(out, d.results, 6, function (tr, r) {
			cell(tr, when(r.at), "text-nowrap");
			cell(tr, r.target, "font-monospace");
			cell(tr, method(r.method, r.fam));
			cell(tr, r.recv ? numFmt.format(r.avg) : "–", "text-end", "min " + numFmt.format(r.min || 0) + " · max " + numFmt.format(r.max || 0));
			cell(tr, numFmt.format(r.loss || 0) + " %", "text-end");
			cell(tr, r.err || "", "small text-body-secondary");
		});
		if (live) {
			fill(live, d.inbound, 4, function (tr, r) {
				cell(tr, when(r.at), "text-nowrap");
				var td = cell(tr, r.name ? r.name + " " : "");
				var sp = document.createElement("span");
				sp.className = "font-monospace small text-body-secondary";
				sp.textContent = r.from;
				td.appendChild(sp);
				cell(tr, "IPv" + r.fam);
				cell(tr, String(r.count), "text-end");
			});
		}
	}

	function renderInbound(d) {
		if (!inb) { return; }
		if (!d.ready) {
			fill(inb, [], 7, null);
			inb.querySelector("td").textContent = inb.getAttribute("data-l-wait") || "";
			return;
		}
		fill(inb, d.rows, 7, function (tr, r) {
			cell(tr, when(r.at), "text-nowrap");
			var td = cell(tr, r.name || r.from);
			if (r.trust && /^[a-z]{1,12}$/.test(r.trust)) {
				var b = document.createElement("span");
				b.className = "badge ms-1 " + trustClass(r.trust);
				b.textContent = L("trust-" + r.trust);
				td.appendChild(b);
			}
			cell(tr, r.asname || "");
			cell(tr, r.place || "");
			cell(tr, method(r.method, r.fam));
			cell(tr, numFmt.format(r.avg || 0), "text-end");
			cell(tr, numFmt.format((r.loss || 0) * 100) + " %", "text-end");
		});
	}

	function trustClass(t) {
		var c = { stable: "text-bg-primary", trusted: "text-bg-success", pillar: "s64-gold", anchor: "s64-violet", quarantine: "text-bg-danger" };
		return Object.prototype.hasOwnProperty.call(c, t) ? c[t] : "text-bg-secondary";
	}

	function get(url, done, fail) {
		fetch(url, { headers: { "Accept": "application/json" }, cache: "no-store" })
			.then(function (r) { if (!r.ok) { throw new Error(String(r.status)); } return r.json(); })
			.then(done)
			.catch(function () { if (fail) { fail(); } });
	}

	function tick() {
		get("/api/sonar64/recent?n=50", renderRecent);
	}

	function tickIn() {
		get("/api/sonar64/inbound", renderInbound, function () {
			if (inb) { fill(inb, [], 7, null); inb.querySelector("td").textContent = inb.getAttribute("data-l-error") || ""; }
		});
	}

	function start() {
		if (timer) { return; }
		tick();
		tickIn();
		timer = setInterval(tick, 5000);
		inTimer = setInterval(tickIn, 60000);
		if (state) { state.textContent = L("live"); }
	}

	function stop() {
		clearInterval(timer);
		clearInterval(inTimer);
		timer = inTimer = null;
		if (state) { state.textContent = L("paused"); }
	}

	document.addEventListener("visibilitychange", function () { if (document.hidden) { stop(); } else { start(); } });
	start();
})();
