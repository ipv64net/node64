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

	// Bandbreite je Proxy-Host: neben Mbit/s die MB/s zeigen
	document.querySelectorAll("[data-bw-mbit]").forEach(function (inp) {
		var out = inp.closest("div[class^=col]").querySelector("[data-bw-mb]");
		var show = function () {
			var v = parseFloat(inp.value);
			out.textContent = v > 0 ? "≈ " + (v / 8).toLocaleString(undefined, { maximumFractionDigits: 2 }) + " MB/s" : "";
		};
		inp.addEventListener("input", show);
		show();
	});

	// Stream: PROXY-Kopf zum Ziel nur bei TCP (ohne TCP ausgeblendet und nicht gesendet = aus)
	var tcpBox = document.getElementById("tcp");
	var tcpOnly = document.querySelectorAll("[data-tcp-only]");
	if (tcpBox && tcpOnly.length) {
		var tcpSync = function () {
			tcpOnly.forEach(function (el) {
				el.classList.toggle("d-none", !tcpBox.checked);
				el.querySelectorAll("select, input").forEach(function (i) { i.disabled = !tcpBox.checked; });
			});
		};
		tcpBox.addEventListener("change", tcpSync);
		tcpSync();
	}

	// Waehrend ein Zertifikat geholt wird: Seite alle paar Sekunden neu laden
	var reload = document.querySelector("[data-reload]");
	if (reload) {
		setTimeout(function () { window.location.reload(); }, 1000 * (parseInt(reload.getAttribute("data-reload"), 10) || 5));
	}

	// Laendersperre (#54): eigene Vorschlagsliste unter dem Feld - sucht nach Kuerzel und Laendername (deutsch und
	// englisch) im Teil nach dem letzten Komma, Auswahl per Klick, Pfeiltasten und Enter; darunter die gewaehlten Laender
	// mit Flagge und Namen (x entfernt eins). Das Feld bleibt Text mit Kommas (Formular und API unveraendert).
	var geo = document.getElementById("geo_countries"), geoList = document.getElementById("geo-cc");
	if (geo && geoList) {
		var cc = Array.prototype.map.call(geoList.options, function (o) {
			return { c: o.value, n: o.textContent, f: o.getAttribute("data-flag") || "", a: (o.getAttribute("data-alt") || "").toLowerCase() };
		});
		var byCode = {};
		cc.forEach(function (x) { byCode[x.c] = x; });
		var box = document.createElement("div");
		box.className = "dropdown-menu shadow-sm";
		box.style.maxHeight = "16rem";
		box.style.overflowY = "auto";
		var wrap = geo.parentNode;
		wrap.style.position = "relative";
		wrap.appendChild(box);
		var chips = document.createElement("div");
		chips.className = "d-flex flex-wrap gap-1 mt-1 small";
		wrap.appendChild(chips);
		var active = -1;
		var codes = function () {
			return geo.value.split(/[\s,;]+/).map(function (s) { return s.trim().toUpperCase(); }).filter(function (s) { return s !== ""; });
		};
		var showChips = function () {
			chips.replaceChildren();
			var seen = {}, typing = document.activeElement === geo ? cut()[1].toUpperCase() : ""; // angefangenes Wort noch nicht
			codes().forEach(function (c) {
				if (seen[c] || (c === typing && !byCode[c])) { return; }
				seen[c] = true;
				var x = byCode[c], s = document.createElement("span");
				s.className = "badge rounded-pill border fw-normal " + (x || !cc.length ? "text-body-emphasis" : "text-danger border-danger");
				s.textContent = (x && x.f ? x.f + " " : "") + (x ? x.n + " (" + c + ")" : c) + " ";
				var del = document.createElement("button");
				del.type = "button";
				del.className = "btn-close btn-close-sm ms-1 align-middle";
				del.style.fontSize = ".55rem";
				del.setAttribute("aria-label", "×");
				del.addEventListener("click", function () {
					geo.value = codes().filter(function (k) { return k !== c; }).join(", ");
					showChips();
					geo.focus();
				});
				s.appendChild(del);
				chips.appendChild(s);
			});
		};
		var cut = function () { // bisheriger Text bis einschliesslich des letzten Trenners, und das angefangene Wort
			var v = geo.value, i = Math.max(v.lastIndexOf(","), v.lastIndexOf(" "), v.lastIndexOf(";"));
			return [v.slice(0, i + 1), v.slice(i + 1).trim()];
		};
		var hide = function () { box.classList.remove("show"); active = -1; };
		var pick = function (code) {
			var pre = cut()[0].replace(/[\s,;]+$/, "");
			geo.value = (pre ? pre + ", " : "") + code + ", ";
			hide();
			showChips();
			geo.focus();
		};
		var fill = function () {
			var q = cut()[1].toLowerCase(), have = {};
			codes().forEach(function (c) { have[c] = true; });
			box.replaceChildren();
			active = -1;
			var hits = cc.filter(function (x) {
				if (have[x.c] && x.c.toLowerCase() !== q) { return false; }
				return q === "" || x.c.toLowerCase().indexOf(q) === 0 || x.n.toLowerCase().indexOf(q) >= 0 || x.a.indexOf(q) >= 0;
			}).sort(function (a, b) { // Kuerzel-Treffer zuerst
				return (b.c.toLowerCase().indexOf(q) === 0) - (a.c.toLowerCase().indexOf(q) === 0);
			}).slice(0, 12);
			hits.forEach(function (x) {
				var b = document.createElement("button");
				b.type = "button";
				b.className = "dropdown-item small";
				b.textContent = (x.f ? x.f + " " : "") + x.n + " (" + x.c + ")";
				b.addEventListener("mousedown", function (e) { e.preventDefault(); pick(x.c); });
				box.appendChild(b);
			});
			box.classList.toggle("show", hits.length > 0 && document.activeElement === geo);
		};
		var mark = function (n) {
			var items = box.querySelectorAll(".dropdown-item");
			if (!items.length) { return; }
			active = (n + items.length) % items.length;
			items.forEach(function (it, i) { it.classList.toggle("active", i === active); });
			items[active].scrollIntoView({ block: "nearest" });
		};
		geo.removeAttribute("list");
		geo.addEventListener("input", function () { fill(); showChips(); });
		geo.addEventListener("focus", fill);
		geo.addEventListener("blur", function () { setTimeout(function () { hide(); showChips(); }, 150); });
		geo.addEventListener("keydown", function (e) {
			if (!box.classList.contains("show")) { return; }
			if (e.key === "ArrowDown" || e.key === "ArrowUp") {
				e.preventDefault();
				mark(active + (e.key === "ArrowDown" ? 1 : -1));
			} else if (e.key === "Enter" && active >= 0) {
				e.preventDefault();
				box.querySelectorAll(".dropdown-item")[active].dispatchEvent(new MouseEvent("mousedown"));
			} else if (e.key === "Escape") {
				hide();
			}
		});
		showChips();
	}

	// Locations (#78): eingeklappt, "+ Location hinzufuegen" zeigt die leere Zeile bzw. legt eine weitere an (Nummer =
	// loc_count, hoechstens 50); "entfernen" leert den Pfad (leere Zeilen speichert der Server nicht)
	var locAdd = document.querySelector("[data-loc-add]"), locCount = document.querySelector("input[name=loc_count]");
	if (locAdd && locCount) {
		var tplLoc = document.querySelector("[data-loc-new]");
		tplLoc = tplLoc ? tplLoc.cloneNode(true) : null;
		var locWire = function (d) {
			var p = d.querySelector("input[id$=_path]"), t = d.querySelector("[data-loc-title]");
			if (p && t && d.hasAttribute("data-loc-new")) {
				p.addEventListener("input", function () { if (p.value.trim()) { t.textContent = p.value.trim(); } });
			}
			var del = d.querySelector("[data-loc-del]");
			if (del && p) {
				del.addEventListener("click", function () { p.value = ""; d.hidden = true; });
			}
		};
		document.querySelectorAll("[data-loc]").forEach(locWire);
		locAdd.addEventListener("click", function () {
			var d = document.querySelector("[data-loc-new][hidden]");
			if (!d && tplLoc) {
				var n = parseInt(locCount.value, 10) || 0;
				if (n >= 50) { return; }
				d = tplLoc.cloneNode(true);
				d.querySelectorAll("[id],[name],[for]").forEach(function (el) {
					["id", "name", "for"].forEach(function (a) {
						var v = el.getAttribute(a);
						if (v) { el.setAttribute(a, v.replace(/^loc_\d+_/, "loc_" + n + "_")); }
					});
				});
				locCount.value = String(n + 1);
				locAdd.parentNode.insertBefore(d, locAdd);
				locWire(d);
			}
			if (!d) { return; }
			d.hidden = false;
			d.open = true;
			var p = d.querySelector("input[id$=_path]");
			if (p) { p.focus(); }
		});
	}
})();
