// Passkeys: anlegen (Einstellungen -> Anmeldung) und anmelden (Login-Seite) ueber WebAuthn.
(function () {
	"use strict";
	var supported = window.PublicKeyCredential && window.isSecureContext;
	document.querySelectorAll("[data-pk-needs]").forEach(function (el) { el.classList.toggle("d-none", !supported); });
	document.querySelectorAll("[data-pk-unsupported]").forEach(function (el) { el.classList.toggle("d-none", !!supported); });
	if (!supported) { return; }

	function b64(buf) {
		var s = "", b = new Uint8Array(buf);
		for (var i = 0; i < b.length; i++) { s += String.fromCharCode(b[i]); }
		return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
	}
	function unb64(s) {
		s = s.replace(/-/g, "+").replace(/_/g, "/");
		while (s.length % 4) { s += "="; }
		var bin = atob(s), out = new Uint8Array(bin.length);
		for (var i = 0; i < bin.length; i++) { out[i] = bin.charCodeAt(i); }
		return out.buffer;
	}
	function post(url, csrf, body) {
		return fetch(url, { method: "POST", cache: "no-store", headers: { "X-CSRF-Token": csrf, "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : "{}" })
			.then(function (r) {
				return r.json().catch(function () { return {}; }).then(function (j) {
					if (!r.ok) { throw new Error(j.error || String(r.status)); }
					return j;
				});
			});
	}
	function fail(el, msg) {
		var e = el.querySelector("[data-pk-error]");
		if (e) { e.textContent = msg; e.classList.remove("d-none"); }
	}

	// Anlegen
	var add = document.getElementById("passkey-add");
	if (add) {
		add.addEventListener("submit", function (ev) {
			ev.preventDefault();
			var csrf = add.getAttribute("data-csrf");
			var name = add.querySelector("[name=name]").value;
			post("/settings/login/passkeys/begin", csrf).then(function (o) {
				var pk = o.publicKey;
				pk.challenge = unb64(pk.challenge);
				pk.user.id = unb64(pk.user.id);
				(pk.excludeCredentials || []).forEach(function (c) { c.id = unb64(c.id); });
				return navigator.credentials.create({ publicKey: pk });
			}).then(function (c) {
				return post("/settings/login/passkeys/finish?name=" + encodeURIComponent(name), csrf, {
					id: c.id, rawId: b64(c.rawId), type: c.type, clientExtensionResults: c.getClientExtensionResults(),
					response: { attestationObject: b64(c.response.attestationObject), clientDataJSON: b64(c.response.clientDataJSON),
						transports: c.response.getTransports ? c.response.getTransports() : [] }
				});
			}).then(function () { location.reload(); }).catch(function (e) { fail(add, add.getAttribute("data-err") + " (" + e.message + ")"); });
		});
	}

	// Anmelden
	var login = document.getElementById("passkey-login");
	if (login) {
		login.addEventListener("click", function () {
			var csrf = login.getAttribute("data-csrf");
			var box = login.parentNode;
			post("/login/passkey/begin?next=" + encodeURIComponent(login.getAttribute("data-next") || "/"), csrf).then(function (o) {
				var pk = o.publicKey;
				pk.challenge = unb64(pk.challenge);
				(pk.allowCredentials || []).forEach(function (c) { c.id = unb64(c.id); });
				return navigator.credentials.get({ publicKey: pk });
			}).then(function (c) {
				return post("/login/passkey/finish", csrf, {
					id: c.id, rawId: b64(c.rawId), type: c.type, clientExtensionResults: c.getClientExtensionResults(),
					response: { authenticatorData: b64(c.response.authenticatorData), clientDataJSON: b64(c.response.clientDataJSON),
						signature: b64(c.response.signature), userHandle: c.response.userHandle ? b64(c.response.userHandle) : "" }
				});
			}).then(function (j) { location.href = j.redirect || "/"; }).catch(function () { fail(box, login.getAttribute("data-err")); });
		});
	}
})();
