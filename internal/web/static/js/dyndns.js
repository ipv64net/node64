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

	// Mehr als ein Name: Rueckfrage im Fenster, denn der Updater setzt bei allen sofort die Adresse dieses Anschlusses.
	// Der Server verlangt die Bestaetigung (confirm_many) ebenfalls. Namen mit IPv4 und IPv6 "aus" legt er nicht an.
	var form = document.querySelector("[data-pick-form]");
	var modalEl = document.querySelector("[data-pick-modal]");
	if (form && modalEl && window.bootstrap) {
		var maxList = 20;
		var modal = new window.bootstrap.Modal(modalEl);
		var ok = modalEl.querySelector("[data-pick-confirm]");
		var flag = form.querySelector('input[name="confirm_many"]');
		var effective = function () {
			return Array.prototype.filter.call(form.querySelectorAll('input[name="pick"]:checked'), function (c) {
				var m4 = form.querySelector('select[name="m4:' + c.value + '"]');
				var m6 = form.querySelector('select[name="m6:' + c.value + '"]');
				return !(m4 && m6 && m4.value === "off" && m6.value === "off");
			});
		};
		form.addEventListener("submit", function (e) {
			var picked = effective();
			if (picked.length < 2) { return; }
			e.preventDefault();
			var count = modalEl.querySelector("[data-pick-count]");
			count.textContent = count.getAttribute("data-text").replace("{n}", picked.length);
			var list = modalEl.querySelector("[data-pick-list]");
			list.textContent = "";
			picked.slice(0, maxList).forEach(function (c) {
				var li = document.createElement("li");
				li.textContent = c.getAttribute("aria-label");
				list.appendChild(li);
			});
			if (picked.length > maxList) {
				var more = document.createElement("li");
				more.className = "list-unstyled text-body-secondary";
				more.textContent = list.getAttribute("data-more").replace("{n}", picked.length - maxList);
				list.appendChild(more);
			}
			modal.show();
		});
		ok.addEventListener("click", function () {
			ok.disabled = true; // kein zweites Absenden bei Doppelklick
			if (flag) { flag.value = "1"; }
			form.submit(); // loest kein submit-Ereignis aus
		});
		window.addEventListener("pageshow", function () { // Zurueckblaettern (bfcache): wieder bedienbar, neu bestaetigen
			ok.disabled = false;
			if (flag) { flag.value = ""; }
		});
	}
})();

// Filter im Verlauf: bei Aenderung sofort anwenden
(function () {
	"use strict";
	document.querySelectorAll("form[data-autosubmit] select").forEach(function (sel) {
		sel.addEventListener("change", function () { sel.form.submit(); });
	});
})();
