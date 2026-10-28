// CDN64: Rueckfragen, SSL-Optionen im Host-Formular, Alias-Vorschau, Neuladen waehrend eines Abrufs.
// Vanilla-JS, keine externen Quellen.
(function () {
	"use strict";

	// Zugriffsliste: Anmeldedienst (Adresse, Beispiel als Platzhalter), Login-Seite nur ohne Dienst
	var auth = document.querySelector("[data-acl-auth]");
	if (auth) {
		var fwdBox = document.querySelector("[data-fwd-box]");
		var loginBox = document.querySelector("[data-login-box]");
		var addr = document.querySelector("[data-fwd-address]");
		var authSync = function () {
			var o = auth.options[auth.selectedIndex];
			if (fwdBox) { fwdBox.classList.toggle("d-none", auth.value === ""); }
			if (loginBox) { loginBox.classList.toggle("d-none", auth.value !== ""); }
			if (addr) { addr.placeholder = (o && o.getAttribute("data-example")) || "http://…"; }
		};
		auth.addEventListener("change", authSync);
		authSync();
	}

	// Rueckfrage vor Loeschen
	document.querySelectorAll("[data-confirm]").forEach(function (b) {
		b.addEventListener("click", function (e) {
			if (!window.confirm(b.getAttribute("data-confirm"))) { e.preventDefault(); }
		});
	});

	// Host-Formular: "Nur HTTP" graut die HTTPS-Optionen aus, "neu anfordern" zeigt den Weg; HSTS-Subdomains nur mit HSTS
	var sel = document.querySelector("[data-cert-select]");
	var opts = document.querySelector("[data-ssl-options]");
	var newBox = document.querySelector("[data-new-cert]");
	var hsts = document.getElementById("hsts");
	var sub = document.getElementById("hsts_subdomains");
	var sync = function () {
		if (sel && opts) { opts.disabled = sel.value === "-1"; }
		if (sel && newBox) { newBox.classList.toggle("d-none", sel.value !== "new"); }
		if (hsts && sub && !(opts && opts.disabled)) { sub.disabled = !hsts.checked; }
	};
	if (sel) { sel.addEventListener("change", sync); }
	if (hsts) { hsts.addEventListener("change", sync); }
	sync();
	// Nutzungsbedingungen von Let's Encrypt nur fuer ACME-Wege (nicht eigene CA, nicht selbst signiert)
	var way = document.querySelector("[data-cert-way]");
	var tos = document.querySelector("[data-cert-tos]");
	var tosSync = function () {
		if (!way || !tos) { return; }
		var acme = way.value !== "self" && way.value.indexOf("ca:") !== 0;
		tos.classList.toggle("d-none", !acme);
	};
	if (way) { way.addEventListener("change", tosSync); }
	tosSync();

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

	// Standardseite: Felder nur fuer den gewaehlten Modus
	var modes = document.querySelectorAll("[data-default-mode]");
	var modeSync = function () {
		var cur = "";
		modes.forEach(function (r) { if (r.checked) { cur = r.value; } });
		document.querySelectorAll("[data-default-of]").forEach(function (el) {
			el.classList.toggle("d-none", el.getAttribute("data-default-of") !== cur);
		});
	};
	modes.forEach(function (r) { r.addEventListener("change", modeSync); });
	if (modes.length) { modeSync(); }

	// Erweitert: Cloudflare-Netze als vertrauenswuerdige Proxys einfuegen
	document.querySelectorAll("[data-cf-nets]").forEach(function (btn) {
		btn.addEventListener("click", function () {
			var ta = document.querySelector("[data-trusted]");
			if (!ta) { return; }
			var have = ta.value.split(/\s+/).filter(Boolean);
			btn.getAttribute("data-cf-nets").split("\n").forEach(function (n) { if (have.indexOf(n) < 0) { have.push(n); } });
			ta.value = have.join("\n");
		});
	});

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

	// Host-Liste: "lokal in DNS64 eintragen" fuellt Ziel und Namen des Fensters aus dem Knopf
	var ldns = document.getElementById("cdn64-localdns");
	if (ldns) {
		ldns.addEventListener("show.bs.modal", function (e) {
			var b = e.relatedTarget;
			if (!b) { return; }
			ldns.querySelector("[data-ldns-form]").setAttribute("action", "/cdn64/hosts/" + b.getAttribute("data-ldns-id") + "/localdns");
			ldns.querySelector("[data-ldns-names]").textContent = b.getAttribute("data-ldns-names");
		});
	}

	// Waehrend ein Zertifikat geholt wird: Seite alle paar Sekunden neu laden
	var reload = document.querySelector("[data-reload]");
	if (reload) {
		setTimeout(function () { window.location.reload(); }, 1000 * (parseInt(reload.getAttribute("data-reload"), 10) || 5));
	}
})();
