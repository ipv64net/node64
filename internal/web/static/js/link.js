// Verknuepfungsseite: Status abfragen, bis der Code eingeloest ist (die Node fragt zusaetzlich selbst im Hintergrund).
(function () {
	"use strict";
	var me = document.getElementById("link-poll");
	var tries = 0, hadCode = !!(me && me.getAttribute("data-had-code"));
	function poll() {
		fetch("/link/status", { credentials: "same-origin" }).then(function (r) { return r.json(); }).then(function (d) {
			if (d.linked) { location.reload(); return; }
			if (d.error) { var e = document.getElementById("link-error"); if (e) { e.textContent = d.error; e.classList.remove("d-none"); } }
			if (hadCode && !d.code) { location.reload(); return; }
			if (!hadCode && (d.code || !d.requesting)) { location.reload(); return; }
			if (++tries < 150) { setTimeout(poll, hadCode ? 5000 : 2000); }
		}).catch(function () { setTimeout(poll, 10000); });
	}
	setTimeout(poll, hadCode ? 3000 : 2000);
})();
