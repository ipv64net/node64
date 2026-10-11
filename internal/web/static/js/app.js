// Node64: wenig Vanilla-JS. Farbschema, Hinweise ausblenden.
(function () {
	"use strict";
	var root = document.documentElement;

	function cookie(name) {
		var m = document.cookie.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
		return m ? decodeURIComponent(m[1]) : "";
	}
	function apply(theme) {
		if (theme === "light" || theme === "dark") {
			root.setAttribute("data-bs-theme", theme);
		} else {
			root.setAttribute("data-bs-theme", window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
		}
	}
	// Ohne Cookie folgt das Schema dem System
	if (!root.getAttribute("data-bs-theme")) {
		apply(cookie("node64_theme"));
		window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", function () {
			if (!cookie("node64_theme")) { apply(""); }
		});
	}
	document.querySelectorAll("#themeToggle, .theme-toggle").forEach(function (btn) {
		btn.addEventListener("click", function () {
			var next = root.getAttribute("data-bs-theme") === "dark" ? "light" : "dark";
			apply(next);
			document.cookie = "node64_theme=" + next + "; path=/; max-age=31536000; samesite=lax";
		});
	});

	// In die Zwischenablage: <button data-copy-target="#id"> oder <button data-copy-text="...">
	function copyText(text, btn) {
		var done = function () {
			if (!btn) { return; }
			btn.classList.add("copied");
			var i = btn.querySelector(".bi");
			if (i) { i.className = "bi bi-check2"; }
			setTimeout(function () { btn.classList.remove("copied"); if (i) { i.className = "bi bi-clipboard"; } }, 1500);
		};
		if (navigator.clipboard && window.isSecureContext) {
			navigator.clipboard.writeText(text).then(done, function () { fallback(text); done(); });
		} else {
			fallback(text); done();
		}
	}
	function fallback(text) {
		var ta = document.createElement("textarea");
		ta.value = text; ta.setAttribute("readonly", ""); ta.style.position = "fixed"; ta.style.opacity = "0";
		document.body.appendChild(ta); ta.select();
		try { document.execCommand("copy"); } catch (e) {}
		document.body.removeChild(ta);
	}
	document.addEventListener("click", function (ev) {
		var btn = ev.target.closest("[data-copy-target],[data-copy-text]");
		if (!btn) { return; }
		ev.preventDefault();
		var text = btn.getAttribute("data-copy-text");
		if (text === null) {
			var el = document.querySelector(btn.getAttribute("data-copy-target"));
			text = el ? (el.value !== undefined && el.tagName !== "DIV" && el.tagName !== "CODE" ? el.value : el.textContent) : "";
		}
		copyText(text.trim(), btn);
	});

	// Erfolgsmeldungen nach einigen Sekunden ausblenden
	document.querySelectorAll(".alert-success.alert-dismissible").forEach(function (el) {
		setTimeout(function () {
			if (window.bootstrap && bootstrap.Alert.getOrCreateInstance) { bootstrap.Alert.getOrCreateInstance(el).close(); }
		}, 6000);
	});
})();
