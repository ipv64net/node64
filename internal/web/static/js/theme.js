// Farbschema "System": vor dem ersten Zeichnen im head setzen, sonst blitzt bei dunklem System erst das helle auf
// (#124). Mit Cookie setzt der Server data-bs-theme schon im html-Tag und laedt diese Datei nicht.
(function () {
	"use strict";
	if (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) {
		document.documentElement.setAttribute("data-bs-theme", "dark");
	}
})();
