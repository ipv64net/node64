// IPAM64, Seite eines Praefixes: Raster und Liste gehoeren zusammen. Klick auf ein belegtes Feld markiert die Zeile
// in der Liste (freie Felder und Felder ohne Zeile auf dieser Seite oeffnen wie bisher das Formular), Zeigen auf eine
// Zeile hebt ihr Feld hervor, die Suche filtert die Zeilen dieser Seite schon beim Tippen und hebt die passenden
// Felder hervor (Enter sucht im ganzen Praefix, wie ohne JS).
(function () {
	"use strict";
	var grid = document.querySelector("#ipam-grid .ipam-grid");
	var list = document.getElementById("ipam-list");
	if (!list) { return; }
	var rows = Array.prototype.slice.call(list.querySelectorAll("tr[data-ip]"));
	var cells = {};
	if (grid) {
		grid.querySelectorAll("a.ipam-cell[data-ip]").forEach(function (c) { cells[c.getAttribute("data-ip")] = c; });
	}
	var rowOf = function (ip) { return document.getElementById("ip-" + ip); };

	var select = function (ip) {
		list.querySelectorAll("tr.ipam-hit").forEach(function (r) { r.classList.remove("ipam-hit"); });
		if (grid) { grid.querySelectorAll(".ipam-selected").forEach(function (c) { c.classList.remove("ipam-selected"); }); }
		var r = rowOf(ip);
		if (r) {
			r.classList.add("ipam-hit");
			r.scrollIntoView({ block: "center", behavior: "smooth" });
		}
		if (cells[ip]) { cells[ip].classList.add("ipam-selected"); }
	};

	if (grid) {
		grid.addEventListener("click", function (e) {
			var c = e.target.closest("a.ipam-cell[data-ip]");
			if (!c || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey || e.button !== 0) { return; }
			var ip = c.getAttribute("data-ip");
			var r = rowOf(ip);
			if (!r || r.classList.contains("d-none")) { return; } // keine Zeile: Formular der Adresse
			e.preventDefault();
			select(ip);
			history.replaceState(null, "", "#ip-" + ip);
		});
		var hover = function (on) {
			return function (e) {
				var r = e.target.closest("tr[data-ip]");
				var c = r && cells[r.getAttribute("data-ip")];
				if (c) { c.classList.toggle("ipam-hover", on); }
			};
		};
		list.addEventListener("mouseover", hover(true));
		list.addEventListener("mouseout", hover(false));
	}

	// Sprung von aussen (#ip-...): Zeile und Feld markieren
	if (location.hash.indexOf("#ip-") === 0) { select(decodeURIComponent(location.hash.slice(4))); }

	// Suche beim Tippen: nur die Zeilen dieser Seite (Luecken ausblenden), Treffer im Raster hervorheben
	var q = document.getElementById("ipam-q");
	var none = document.getElementById("ipam-live-none");
	if (!q) { return; }
	var initial = q.value.trim().toLowerCase();
	var marking = grid && grid.classList.contains("ipam-marking");
	var server = {};
	Object.keys(cells).forEach(function (ip) { server[ip] = cells[ip].classList.contains("ipam-match"); });
	q.addEventListener("input", function () {
		var v = q.value.trim().toLowerCase();
		var live = v !== "" && v !== initial;
		var shown = 0;
		rows.forEach(function (r) {
			var ok = !live || r.textContent.toLowerCase().indexOf(v) >= 0;
			r.classList.toggle("d-none", !ok);
			if (ok) { shown++; }
		});
		list.querySelectorAll("tr.ipam-free-row").forEach(function (r) { r.classList.toggle("d-none", live); });
		if (none) { none.classList.toggle("d-none", !live || shown > 0); }
		if (grid) {
			Object.keys(cells).forEach(function (ip) {
				var r = rowOf(ip);
				cells[ip].classList.toggle("ipam-match", live ? !!r && !r.classList.contains("d-none") : server[ip]);
			});
			grid.classList.toggle("ipam-marking", live || marking);
		}
	});
})();
