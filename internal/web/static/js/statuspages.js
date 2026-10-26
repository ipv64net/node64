// Statusseiten (Healthchecks): Slug-Vorschlag aus dem Titel und Filter der Check-Auswahl.
// Vanilla-JS, keine externen Quellen; das Formular funktioniert auch ohne. Rueckfragen (data-confirm) macht app.js.
(function () {
	"use strict";

	// Nach einem Knopf bei den Eintraegen (formaction mit #sp-groups) sofort dorthin springen; der sanfte
	// Bildlauf des Layouts bleibt nach dem Absenden sonst oben haengen
	if (location.hash === "#sp-groups") {
		window.addEventListener("load", function () {
			setTimeout(function () {
				var grp = document.getElementById("sp-groups");
				if (grp) { grp.scrollIntoView({ block: "start", behavior: "instant" }); }
			}, 0);
		});
	}

	// Slug aus dem Titel vorschlagen, solange er nicht von Hand geaendert wurde
	var title = document.getElementById("sp-title");
	var slug = document.getElementById("sp-slug");
	if (title && slug && slug.getAttribute("data-auto") === "1") {
		var slugify = function (s) {
			s = s.toLowerCase().replace(/ä/g, "ae").replace(/ö/g, "oe").replace(/ü/g, "ue").replace(/ß/g, "ss");
			return s.replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 50).replace(/-+$/, "");
		};
		title.addEventListener("input", function () {
			if (slug.getAttribute("data-auto") === "1") { slug.value = slugify(title.value); }
		});
		slug.addEventListener("input", function () { slug.setAttribute("data-auto", "0"); });
	}

	// Auswahl der Checks: nach Name, Tag und Healthchecks-Gruppe filtern
	var list = document.querySelector("[data-sp-list]");
	if (!list) { return; }
	var q = document.querySelector("[data-sp-q]");
	var tag = document.querySelector("[data-sp-tag]");
	var hcg = document.querySelector("[data-sp-hcg]");
	var all = document.querySelector("[data-sp-selall]");
	var count = document.querySelector("[data-sp-count]");
	var rows = list.querySelectorAll("[data-sp-check]");
	var visible = function () {
		var out = [];
		rows.forEach(function (r) { if (!r.classList.contains("d-none")) { out.push(r); } });
		return out;
	};
	var apply = function () {
		var s = q ? q.value.trim().toLowerCase() : "";
		var t = tag ? tag.value : "";
		var g = hcg ? hcg.value : "";
		var n = 0;
		rows.forEach(function (r) {
			var tags = (r.getAttribute("data-tags") || "").split(",");
			var on = (!s || (r.getAttribute("data-name") || "").toLowerCase().indexOf(s) >= 0) &&
				(!t || tags.indexOf(t) >= 0) && (!g || r.getAttribute("data-group") === g);
			r.classList.toggle("d-none", !on);
			if (on) { n++; }
		});
		if (count) { count.textContent = n + " / " + rows.length; }
	};
	[q, tag, hcg].forEach(function (el) {
		if (!el) { return; }
		el.addEventListener("input", apply);
		el.addEventListener("change", apply);
		// Enter im Suchfeld soll nicht das Formular abschicken
		el.addEventListener("keydown", function (e) { if (e.key === "Enter") { e.preventDefault(); } });
	});
	if (all) {
		all.classList.remove("d-none");
		all.addEventListener("click", function () {
			var v = visible();
			var on = v.some(function (r) { var c = r.querySelector("input"); return c && !c.disabled && !c.checked; });
			v.forEach(function (r) { var c = r.querySelector("input"); if (c && !c.disabled) { c.checked = on; } });
		});
	}
	apply();
})();
