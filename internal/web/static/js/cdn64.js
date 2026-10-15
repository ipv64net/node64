// CDN64: Rueckfragen und SSL-Optionen im Host-Formular. Vanilla-JS, keine externen Quellen.
(function () {
	"use strict";

	// Rueckfrage vor Loeschen
	document.querySelectorAll("[data-confirm]").forEach(function (b) {
		b.addEventListener("click", function (e) {
			if (!window.confirm(b.getAttribute("data-confirm"))) { e.preventDefault(); }
		});
	});

	// "Nur HTTP" gewaehlt: HTTPS-Optionen ausgrauen; HSTS-Subdomains nur mit HSTS
	var sel = document.querySelector("[data-cert-select]");
	var opts = document.querySelector("[data-ssl-options]");
	var hsts = document.getElementById("hsts");
	var sub = document.getElementById("hsts_subdomains");
	var sync = function () {
		if (sel && opts) { opts.disabled = sel.value === "-1"; }
		if (hsts && sub && !(opts && opts.disabled)) { sub.disabled = !hsts.checked; }
	};
	if (sel) { sel.addEventListener("change", sync); }
	if (hsts) { hsts.addEventListener("change", sync); }
	sync();
})();
