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
	function show(ev) {
		if (canNotify() && Notification.permission === "granted") {
			try {
				var n = new Notification(ev.title || "Node64", { body: ev.text || "", tag: ev.token ? "node64-" + ev.token : undefined, icon: "/static/img/favicon.png" });
				n.onclick = function () { window.focus(); if (ev.token) { location.href = "/healthchecks/" + ev.token; } n.close(); };
			} catch (e) {}
		}
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
		tr.addEventListener("click", function () { show({ kind: "test", title: "Node64", text: tr.textContent.trim() + " ✓" }); });
		refresh();
	}

	// Erfolgsmeldungen nach einigen Sekunden ausblenden
	document.querySelectorAll(".alert-success.alert-dismissible").forEach(function (el) {
		setTimeout(function () {
			if (window.bootstrap && bootstrap.Alert.getOrCreateInstance) { bootstrap.Alert.getOrCreateInstance(el).close(); }
		}, 6000);
	});
})();
