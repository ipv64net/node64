// Tabellen sortieren: Klick auf eine Spaltenueberschrift sortiert die Zeilen (nochmal Klick: absteigend), Pfeil zeigt die
// Richtung. Gilt fuer alle Tabellen mit thead; aus mit data-nosort an der Tabelle oder Spalte. Spalten, die schon auf
// dem Server sortieren (Link in der Ueberschrift), bleiben wie sie sind. Gruppenzeilen (eine Zelle ueber die ganze
// Breite, table-light, hc-group-row, dyn-domain-row, th im tbody) trennen Abschnitte, sortiert wird je Abschnitt;
// Zeilen mit data-sort-child bzw. class collapse bleiben an ihrer Zeile davor. Wert einer Zelle: data-sort, sonst
// datetime/title mit Datum, sonst der Text (Zahlen und Datumsangaben nach Sprache der Seite). Schreibt die Seite die
// Zeilen neu (Live-Daten), bleibt die gewaehlte Sortierung.
(function () {
	"use strict";
	var de = (document.documentElement.lang || "de").indexOf("de") === 0;
	var coll = new Intl.Collator(de ? "de" : "en", { numeric: true, sensitivity: "base" });
	var DATE_DE = /^(\d{2})\.(\d{2})\.(\d{4})(?:,?\s+(\d{2}):(\d{2})(?::(\d{2}))?)?$/;
	var DATE_ISO = /^(\d{4})-(\d{2})-(\d{2})(?:[ T](\d{2}):(\d{2})(?::(\d{2}))?)?/;
	var NUM = /^[-+−]?[\d.,'\s  ]*\d[\d.,'\s  ]*\s*(%|[a-zA-Zµ/]{1,6})?$/;

	function dateKey(s) {
		var m = DATE_DE.exec(s);
		if (m) { return Date.UTC(+m[3], +m[2] - 1, +m[1], +(m[4] || 0), +(m[5] || 0), +(m[6] || 0)); }
		m = DATE_ISO.exec(s);
		if (m) { return Date.UTC(+m[1], +m[2] - 1, +m[3], +(m[4] || 0), +(m[5] || 0), +(m[6] || 0)); }
		return null;
	}

	function numKey(s) {
		if (!NUM.test(s)) { return null; }
		var u = { "kb": 1e3, "kib": 1024, "mb": 1e6, "mib": 1048576, "gb": 1e9, "gib": 1073741824, "tb": 1e12, "tib": 1099511627776 };
		var unit = (/([a-zA-Zµ]+)\s*$/.exec(s) || [])[1] || "";
		var n = s.replace(/[^\d.,\-−]/g, "").replace("−", "-");
		n = de ? n.replace(/\./g, "").replace(",", ".") : n.replace(/,/g, "");
		var v = parseFloat(n);
		if (isNaN(v)) { return null; }
		return v * (u[unit.toLowerCase()] || 1);
	}

	// cellKey liefert {n: Zahl} oder {s: Text} fuer den Vergleich
	function cellKey(td) {
		if (!td) { return { s: "" }; }
		var raw = td.getAttribute("data-sort");
		if (raw === null) {
			var t = td.querySelector("time[datetime]");
			if (t) { var dt = Date.parse(t.getAttribute("datetime")); if (!isNaN(dt)) { return { n: dt }; } }
		}
		var s = (raw !== null ? raw : td.textContent).replace(/\s+/g, " ").trim();
		if (raw === null) {
			var ti = td.querySelector("[title]");
			var tk = ti ? dateKey(ti.getAttribute("title").trim()) : null;
			if (tk !== null && dateKey(s) === null && numKey(s) === null) { return { n: tk }; } // "vor 5 min" mit Datum im Titel
		}
		var d = dateKey(s);
		if (d !== null) { return { n: d }; }
		var n = numKey(s);
		if (n !== null) { return { n: n }; }
		return { s: s };
	}

	function compare(a, b) {
		if (a.n !== undefined && b.n !== undefined) { return a.n - b.n; }
		if (a.n !== undefined) { return -1; } // Zahlen vor Text ("–", leer)
		if (b.n !== undefined) { return 1; }
		if (a.s === "" || a.s === "–") { return b.s === "" || b.s === "–" ? 0 : 1; }
		if (b.s === "" || b.s === "–") { return -1; }
		return coll.compare(a.s, b.s);
	}

	// Spaltenindex einer Ueberschrift (colspan beachten)
	function colIndex(th) {
		var i = 0;
		for (var c = th.parentNode.firstElementChild; c && c !== th; c = c.nextElementSibling) { i += c.colSpan || 1; }
		return i;
	}
	function cellAt(tr, idx) {
		var i = 0;
		for (var c = tr.firstElementChild; c; c = c.nextElementSibling) {
			if (idx < i + (c.colSpan || 1)) { return idx === i ? c : null; }
			i += c.colSpan || 1;
		}
		return null;
	}

	function isSeparator(tr, cols) {
		if (tr.hasAttribute("data-sort-sep") || tr.classList.contains("table-light") || tr.classList.contains("hc-group-row") || tr.classList.contains("dyn-domain-row")) { return true; }
		if (tr.querySelector(":scope > th")) { return true; }
		return tr.children.length === 1 && (tr.firstElementChild.colSpan || 1) >= Math.max(2, cols - 1);
	}
	function isChild(tr) { return tr.hasAttribute("data-sort-child") || tr.classList.contains("collapse"); }

	function sortTable(table) {
		var st = table._sort;
		if (!st) { return; }
		var cols = table.tHead.rows[0] ? Array.prototype.reduce.call(table.tHead.rows[0].cells, function (n, c) { return n + (c.colSpan || 1); }, 0) : 0;
		if (table._obs) { table._obs.disconnect(); }
		Array.prototype.forEach.call(table.tBodies, function (tb) {
			var seg = [], frag = document.createDocumentFragment(), out = [];
			var flush = function () {
				seg.sort(function (a, b) { var c = compare(a.k, b.k); return (st.dir === "desc" ? -c : c) || a.i - b.i; });
				seg.forEach(function (g) { g.rows.forEach(function (r) { out.push(r); }); });
				seg = [];
			};
			Array.prototype.slice.call(tb.rows).forEach(function (tr, i) {
				if (isSeparator(tr, cols)) { flush(); out.push(tr); return; }
				if (isChild(tr) && seg.length) { seg[seg.length - 1].rows.push(tr); return; }
				seg.push({ rows: [tr], k: cellKey(cellAt(tr, st.col)), i: i });
			});
			flush();
			out.forEach(function (r) { frag.appendChild(r); });
			tb.appendChild(frag);
		});
		if (table._obs) { Array.prototype.forEach.call(table.tBodies, function (tb) { table._obs.observe(tb, { childList: true }); }); }
	}

	function mark(table) {
		Array.prototype.forEach.call(table.tHead.querySelectorAll("th[data-sortable]"), function (th) {
			var on = table._sort && table._sort.th === th;
			th.setAttribute("aria-sort", on ? (table._sort.dir === "desc" ? "descending" : "ascending") : "none");
			var ic = th.querySelector(".th-sort-icon");
			if (ic) { ic.className = "bi th-sort-icon " + (on ? (table._sort.dir === "desc" ? "bi-caret-down-fill" : "bi-caret-up-fill") : "bi-chevron-expand"); }
		});
	}

	function setup(table) {
		if (table._sortReady || table.hasAttribute("data-nosort") || !table.tHead || !table.tHead.rows.length) { return; }
		var ths = table.tHead.rows[table.tHead.rows.length - 1].cells;
		if (ths.length < 2) { return; }
		table._sortReady = true;
		Array.prototype.forEach.call(ths, function (th) {
			if (th.hasAttribute("data-nosort") || th.querySelector("a, button, input, select") || !th.textContent.trim()) { return; }
			th.setAttribute("data-sortable", "");
			th.setAttribute("tabindex", "0");
			th.classList.add("th-sort");
			th.appendChild(Object.assign(document.createElement("i"), { className: "bi bi-chevron-expand th-sort-icon" }));
			var go = function () {
				var st = table._sort;
				var dir = st && st.th === th && st.dir === "asc" ? "desc" : "asc";
				table._sort = { th: th, col: colIndex(th), dir: dir };
				sortTable(table);
				mark(table);
			};
			th.addEventListener("click", go);
			th.addEventListener("keydown", function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); go(); } });
		});
		// Zeilen neu geschrieben (Live-Daten): Sortierung erneut anwenden
		table._obs = new MutationObserver(function () { if (table._sort) { sortTable(table); } });
		Array.prototype.forEach.call(table.tBodies, function (tb) { table._obs.observe(tb, { childList: true }); });
		mark(table);
	}

	function scan(root) { Array.prototype.forEach.call((root || document).querySelectorAll("table.table"), setup); }
	if (document.readyState === "loading") { document.addEventListener("DOMContentLoaded", function () { scan(); }); } else { scan(); }
	// spaeter eingefuegte Tabellen (Modale, nachgeladene Bereiche)
	new MutationObserver(function (ms) {
		ms.forEach(function (m) {
			Array.prototype.forEach.call(m.addedNodes, function (n) {
				if (n.nodeType !== 1) { return; }
				if (n.matches && n.matches("table.table")) { setup(n); } else if (n.querySelectorAll) { scan(n); }
			});
		});
	}).observe(document.body || document.documentElement, { childList: true, subtree: true });
})();
