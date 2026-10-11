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

	// Erfolgsmeldungen nach einigen Sekunden ausblenden
	document.querySelectorAll(".alert-success.alert-dismissible").forEach(function (el) {
		setTimeout(function () {
			if (window.bootstrap && bootstrap.Alert.getOrCreateInstance) { bootstrap.Alert.getOrCreateInstance(el).close(); }
		}, 6000);
	});
})();
