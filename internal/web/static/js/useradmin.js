// Benutzerverwaltung: Reiter ueber die Sprungmarke (#users, #groups, #login) waehlen und beim Wechsel merken.
(function () {
	"use strict";
	var tabs = document.getElementById("ua-tabs");
	if (!tabs || !window.bootstrap) { return; }
	var show = function () {
		var id = location.hash.replace(/[^a-z]/gi, "");
		var b = id && tabs.querySelector('[data-bs-target="#' + id + '"]');
		if (b) { bootstrap.Tab.getOrCreateInstance(b).show(); }
	};
	show();
	window.addEventListener("hashchange", show);
	tabs.addEventListener("shown.bs.tab", function (e) {
		var t = e.target.getAttribute("data-bs-target");
		if (t && history.replaceState) { history.replaceState(null, "", location.pathname + t); }
	});
})();
