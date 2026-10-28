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

	// Mehr als ein Name: Rueckfrage im Fenster, denn der Updater setzt bei allen sofort die Adresse dieses Anschlusses
	var form = document.querySelector("[data-pick-form]");
	var modalEl = document.querySelector("[data-pick-modal]");
	if (form && modalEl && window.bootstrap) {
		var confirmed = false;
		var modal = new window.bootstrap.Modal(modalEl);
		form.addEventListener("submit", function (e) {
			var picked = form.querySelectorAll('input[name="pick"]:checked');
			if (confirmed || picked.length < 2) { return; }
			e.preventDefault();
			var count = modalEl.querySelector("[data-pick-count]");
			count.textContent = count.getAttribute("data-text").replace("{n}", picked.length);
			var list = modalEl.querySelector("[data-pick-list]");
			list.textContent = "";
			picked.forEach(function (c, i) {
				if (i >= 20) { return; }
				var li = document.createElement("li");
				li.textContent = c.getAttribute("aria-label");
				list.appendChild(li);
			});
			if (picked.length > 20) {
				var more = document.createElement("li");
				more.className = "list-unstyled text-body-secondary";
				more.textContent = list.getAttribute("data-more").replace("{n}", picked.length - 20);
				list.appendChild(more);
			}
			modal.show();
		});
		modalEl.querySelector("[data-pick-confirm]").addEventListener("click", function () {
			confirmed = true;
			modal.hide();
			form.submit();
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
