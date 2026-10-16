// Zertifikate (Kern): Rueckfragen, Alias-Vorschau, Felder des DNS-Anbieters, Neuladen waehrend eines Abrufs.
// Vanilla-JS, keine externen Quellen.
(function () {
	"use strict";

	// Rueckfrage vor Loeschen
	document.querySelectorAll("[data-confirm]").forEach(function (b) {
		b.addEventListener("click", function (e) {
			if (!window.confirm(b.getAttribute("data-confirm"))) { e.preventDefault(); }
		});
	});

	// Neues Zertifikat: Alias-Felder nur beim Alias-Weg, dazu die noetigen CNAMEs als Vorschau
	var names = document.querySelector("[data-cert-names]");
	var aliasBox = document.querySelector("[data-alias-box]");
	var zone = document.querySelector("[data-alias-zone]");
	var prefix = document.querySelector("[data-alias-prefix]");
	var preview = document.querySelector("[data-alias-preview]");
	var srcs = document.querySelectorAll("[data-cert-source]");
	var dnsBox = document.querySelector("[data-dns-box]");
	var aliasSync = function () {
		var src = "";
		srcs.forEach(function (r) { if (r.checked) { src = r.value; } });
		if (aliasBox) { aliasBox.classList.toggle("d-none", src !== "alias"); }
		if (dnsBox) { dnsBox.classList.toggle("d-none", src !== "dns"); }
		if (!preview || !names || !zone) { return; }
		var z = (zone.value || "").trim().toLowerCase().replace(/\.$/, "");
		var p = prefix ? (prefix.value || "").trim().toLowerCase().replace(/^\.+|\.+$/g, "") : "";
		var to = "_acme-challenge." + (p ? p + "." : "") + z;
		var out = [];
		names.value.split(/[\s,;]+/).forEach(function (n) {
			n = n.trim().toLowerCase().replace(/\.$/, "").replace(/^\*\./, "");
			if (n && z) { out.push("_acme-challenge." + n + "  CNAME  " + to); }
		});
		preview.textContent = out.join("\n");
		preview.style.whiteSpace = "pre-wrap";
	};
	srcs.forEach(function (r) { r.addEventListener("change", aliasSync); });
	[names, zone, prefix].forEach(function (el) { if (el) { el.addEventListener("input", aliasSync); el.addEventListener("change", aliasSync); } });
	aliasSync();

	// DNS-Zugang: nur die Felder des gewaehlten Anbieters
	var prov = document.querySelector("[data-provider-select]");
	if (prov) {
		var provSync = function () {
			document.querySelectorAll("[data-provider-fields]").forEach(function (el) {
				var on = el.getAttribute("data-provider-fields") === prov.value;
				el.classList.toggle("d-none", !on);
				el.querySelectorAll("input").forEach(function (i) { i.disabled = !on; });
			});
		};
		prov.addEventListener("change", provSync);
		provSync();
	}

	// Waehrend ein Zertifikat geholt wird: Seite alle paar Sekunden neu laden
	var reload = document.querySelector("[data-reload]");
	if (reload) {
		setTimeout(function () { window.location.reload(); }, 1000 * (parseInt(reload.getAttribute("data-reload"), 10) || 5));
	}
})();
