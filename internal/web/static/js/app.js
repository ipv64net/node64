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
	// Einstellungen > Darstellung: Farbschema und Schriftgroesse (Cookie, sofort wirksam)
	var setCookie = function (name, val) {
		document.cookie = name + "=" + (val || "") + "; path=/; max-age=" + (val ? 31536000 : 0) + "; samesite=lax";
	};
	document.querySelectorAll("input[name=ui_theme]").forEach(function (r) {
		r.addEventListener("change", function () { setCookie("node64_theme", r.value); apply(r.value); });
	});
	document.querySelectorAll("input[name=ui_fs]").forEach(function (r) {
		r.addEventListener("change", function () {
			setCookie("node64_fs", r.value);
			if (r.value) { root.setAttribute("data-fs", r.value); } else { root.removeAttribute("data-fs"); }
		});
	});
	document.querySelectorAll("#themeToggle, .theme-toggle").forEach(function (btn) {
		btn.addEventListener("click", function () {
			var next = root.getAttribute("data-bs-theme") === "dark" ? "light" : "dark";
			apply(next);
			document.cookie = "node64_theme=" + next + "; path=/; max-age=31536000; samesite=lax";
		});
	});

	// Menue-Knopf: ab lg Seitenleiste ein-/ausklappen (Cookie node64_nav), darunter das ausfahrende Menue
	var navToggle = document.getElementById("navToggle");
	if (navToggle) {
		navToggle.addEventListener("click", function () {
			if (window.matchMedia("(min-width: 992px)").matches) {
				var mini = root.classList.toggle("nav-mini");
				setCookie("node64_nav", mini ? "mini" : "");
			} else if (window.bootstrap) {
				window.bootstrap.Offcanvas.getOrCreateInstance(document.getElementById("sidenav")).toggle();
			}
		});
	}

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
	// Einstellungen: alte Sprungmarken (/settings#ports, #backup …) auf die neuen Unterseiten weiterleiten
	var moved = document.getElementById("settings-moved");
	var followMoved = function () {
		if (!moved || location.hash.length < 2) { return; }
		var to = moved.querySelector('[data-from="' + location.hash.slice(1).replace(/[^a-z0-9_-]/gi, "") + '"]');
		if (to) { location.replace(to.getAttribute("data-to")); }
	};
	followMoved();
	window.addEventListener("hashchange", followMoved); // Link auf derselben Seite (nur die Sprungmarke aendert sich)
	// Formular beim Aendern absenden (statt onchange-Attribut, das die CSP blockiert)
	document.addEventListener("change", function (ev) {
		var el = ev.target.closest ? ev.target.closest("[data-autosubmit]") : null;
		if (el && el.form) { el.form.submit(); }
	});
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

	// Browser-Benachrichtigungen (Kanal "Browser"): Server-Sent Events von /notifications/stream
	var BN_KEY = "node64_browser_notify";
	var bnOn = function () { try { return localStorage.getItem(BN_KEY) === "1"; } catch (e) { return false; } };
	var bnSet = function (v) { try { localStorage.setItem(BN_KEY, v ? "1" : "0"); } catch (e) {} };
	var canNotify = function () { return "Notification" in window && window.isSecureContext; };
	function toast(ev) {
		var box = document.getElementById("bn-toasts");
		if (!box) {
			box = document.createElement("div");
			box.id = "bn-toasts";
			box.className = "toast-container position-fixed bottom-0 end-0 p-3";
			box.style.zIndex = 1090;
			document.body.appendChild(box);
		}
		var down = /down|reminder|flapping_start|degraded$|summary/.test(ev.kind || "");
		var t = document.createElement("div");
		t.className = "toast show border-" + (down ? "danger" : "success");
		t.setAttribute("role", "alert");
		var head = document.createElement("div");
		head.className = "toast-header";
		head.innerHTML = '<i class="bi ' + (down ? "bi-exclamation-octagon-fill text-danger" : "bi-check-circle-fill text-success") + ' me-2"></i><strong class="me-auto"></strong><button type="button" class="btn-close" aria-label="Close"></button>';
		head.querySelector("strong").textContent = ev.title || "Node64";
		var body = document.createElement("div");
		body.className = "toast-body small";
		body.style.whiteSpace = "pre-line";
		body.textContent = ev.text || "";
		if (ev.token) { body.style.cursor = "pointer"; body.addEventListener("click", function () { location.href = "/healthchecks/" + ev.token; }); }
		t.appendChild(head); t.appendChild(body); box.appendChild(t);
		head.querySelector(".btn-close").addEventListener("click", function () { t.remove(); });
		setTimeout(function () { t.remove(); }, down ? 30000 : 10000);
	}
	// Hinweiston (Web Audio, keine Datei): Stoerung zwei fallende Toene, Entwarnung zwei steigende.
	// Browser erlauben Ton erst nach einer Bedienung der Seite; der Kontext wird beim ersten Klick freigeschaltet.
	var SOUND_KEY = "node64_browser_sound";
	var soundOn = function () { try { return localStorage.getItem(SOUND_KEY) !== "0"; } catch (e) { return true; } };
	var audio = null;
	var unlockAudio = function () {
		try {
			if (!audio) { audio = new (window.AudioContext || window.webkitAudioContext)(); }
			if (audio.state === "suspended") { audio.resume(); }
		} catch (e) {}
	};
	if (bnOn()) { ["click", "keydown", "touchstart"].forEach(function (t) { document.addEventListener(t, unlockAudio, { once: true, passive: true }); }); }
	function beep(down) {
		if (!soundOn()) { return; }
		unlockAudio();
		if (!audio) { return; }
		var t0 = audio.currentTime + 0.02;
		(down ? [880, 587] : [660, 988]).forEach(function (f, i) {
			var o = audio.createOscillator(), g = audio.createGain();
			o.type = "sine"; o.frequency.value = f;
			g.gain.setValueAtTime(0.0001, t0 + i * 0.22);
			g.gain.exponentialRampToValueAtTime(0.25, t0 + i * 0.22 + 0.02);
			g.gain.exponentialRampToValueAtTime(0.0001, t0 + i * 0.22 + 0.2);
			o.connect(g); g.connect(audio.destination);
			o.start(t0 + i * 0.22); o.stop(t0 + i * 0.22 + 0.21);
		});
	}
	function show(ev) {
		var down = /down|reminder|flapping_start|degraded$|summary/.test(ev.kind || "");
		if (canNotify() && Notification.permission === "granted") {
			try {
				// renotify: auch eine erneute Meldung zum selben Check bekommt den Ton des Betriebssystems
				var tag = ev.token ? "node64-" + ev.token : undefined;
				var n = new Notification(ev.title || "Node64", { body: ev.text || "", tag: tag, renotify: !!tag, silent: false, requireInteraction: down, icon: "/static/img/favicon.png" });
				n.onclick = function () { window.focus(); if (ev.token) { location.href = "/healthchecks/" + ev.token; } n.close(); };
			} catch (e) {}
		}
		beep(down);
		if (!document.hidden || !(canNotify() && Notification.permission === "granted")) { toast(ev); }
	}
	window.node64ShowNotification = show;
	if (bnOn() && window.EventSource && document.querySelector(".topbar")) {
		var es = new EventSource("/notifications/stream");
		es.addEventListener("notify", function (m) { try { show(JSON.parse(m.data)); } catch (e) {} });
	}
	// Bedienung auf der Seite "Benachrichtigungen"
	var card = document.getElementById("browser-notify-card");
	if (card) {
		var st = document.getElementById("bn-state"), hint = document.getElementById("bn-hint");
		var en = document.getElementById("bn-enable"), dis = document.getElementById("bn-disable"), tr = document.getElementById("bn-test");
		var refresh = function () {
			var on = bnOn();
			en.classList.toggle("d-none", on); dis.classList.toggle("d-none", !on); tr.classList.toggle("d-none", !on);
			st.className = "badge " + (on ? "text-bg-success" : "text-bg-secondary");
			st.textContent = on ? hint.getAttribute("data-on") : hint.getAttribute("data-off");
			if (!("Notification" in window)) { hint.textContent = hint.getAttribute("data-unsupported") + " " + hint.getAttribute("data-inpage"); }
			else if (!window.isSecureContext) { hint.textContent = hint.getAttribute("data-insecure") + " " + hint.getAttribute("data-inpage"); }
			else if (Notification.permission === "denied") { hint.textContent = hint.getAttribute("data-denied") + " " + hint.getAttribute("data-inpage"); }
			else { hint.textContent = ""; }
		};
		en.addEventListener("click", function () {
			bnSet(true);
			if (canNotify() && Notification.permission === "default") {
				Notification.requestPermission().then(function () { refresh(); location.reload(); });
			} else { refresh(); location.reload(); }
		});
		dis.addEventListener("click", function () { bnSet(false); refresh(); location.reload(); });
		tr.addEventListener("click", function () { unlockAudio(); show({ kind: "test", title: "Node64", text: tr.textContent.trim() + " ✓" }); });
		var snd = document.getElementById("bn-sound");
		if (snd) {
			snd.checked = soundOn();
			snd.addEventListener("change", function () { try { localStorage.setItem(SOUND_KEY, snd.checked ? "1" : "0"); } catch (e) {} if (snd.checked) { unlockAudio(); beep(false); } });
		}
		refresh();
	}

	// Tabellen .table-stack (Handy: Karten, node64.css): Beschriftung je Zelle aus dem Tabellenkopf, auch fuer Zeilen,
	// die ein Modulskript spaeter einfuegt. Kopfzellen mit data-nolabel bzw. ohne Text bekommen keine.
	function stackLabels(table) {
		var heads = [];
		table.querySelectorAll("thead th").forEach(function (th) {
			for (var i = 0; i < (th.colSpan || 1); i++) { heads.push(th.hasAttribute("data-nolabel") ? "" : th.textContent.trim()); }
		});
		table.querySelectorAll("tbody tr").forEach(function (tr) {
			var col = 0;
			Array.prototype.forEach.call(tr.cells, function (td) {
				if (!td.hasAttribute("data-label") && heads[col]) { td.setAttribute("data-label", heads[col]); }
				col += td.colSpan || 1;
			});
		});
	}
	document.querySelectorAll("table.table-stack").forEach(function (table) {
		stackLabels(table);
		if (window.MutationObserver && table.tBodies[0]) {
			new MutationObserver(function () { stackLabels(table); }).observe(table.tBodies[0], { childList: true });
		}
	});

	// Erfolgsmeldungen nach einigen Sekunden ausblenden
	document.querySelectorAll(".alert-success.alert-dismissible").forEach(function (el) {
		setTimeout(function () {
			if (window.bootstrap && bootstrap.Alert.getOrCreateInstance) { bootstrap.Alert.getOrCreateInstance(el).close(); }
		}, 6000);
	});

	// Rueckfrage vor Loeschen (data-confirm) auf den Kernseiten; Modulseiten mit eigenem Skript fragen selbst
	// (geprueft beim Klick: die Modulskripte stehen erst nach app.js im Dokument)
	document.addEventListener("click", function (e) {
		var b = e.target.closest("[data-confirm]");
		if (!b || document.querySelector('script[src*="/static/js/dns64.js"], script[src*="/static/js/cdn64.js"], script[src*="/static/js/certs.js"]')) { return; }
		if (!window.confirm(b.getAttribute("data-confirm"))) { e.preventDefault(); }
	});
})();
