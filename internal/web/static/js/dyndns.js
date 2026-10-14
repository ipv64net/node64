// DynDNS: Rueckfragen, Felder je Modus, Auswahl. Vanilla-JS, keine externen Quellen.
(function () {
	"use strict";

	// Rueckfrage vor Loeschen
	document.querySelectorAll("[data-confirm]").forEach(function (b) {
		b.addEventListener("click", function (e) {
			if (!window.confirm(b.getAttribute("data-confirm"))) { e.preventDefault(); }
		});
	});

	// Felder nur fuer den gewaehlten Modus zeigen (data-mode-of="mode6" data-modes="suffix fixed")
	var sync = function (sel) {
		document.querySelectorAll('[data-mode-of="' + sel.name + '"]').forEach(function (el) {
			var on = el.getAttribute("data-modes").split(" ").indexOf(sel.value) >= 0;
			el.classList.toggle("d-none", !on);
			el.querySelectorAll("input, select").forEach(function (i) { i.disabled = !on; });
		});
	};
	document.querySelectorAll("select[data-mode-select]").forEach(function (sel) {
		sel.addEventListener("change", function () { sync(sel); });
		sync(sel);
	});

	// Modus in einer Zeile geaendert: Zeile gleich mit auswaehlen
	document.querySelectorAll("[data-pick-row] select").forEach(function (sel) {
		sel.addEventListener("change", function () {
			var c = sel.closest("tr").querySelector('input[name="pick"]');
			if (c && !c.disabled) { c.checked = true; }
		});
	});

	// Alle waehlbaren Namen an-/abhaken
	var all = document.querySelector("[data-pick-all]");
	if (all) {
		all.addEventListener("change", function () {
			document.querySelectorAll('input[name="pick"]:not(:disabled)').forEach(function (c) { c.checked = all.checked; });
		});
	}
})();
