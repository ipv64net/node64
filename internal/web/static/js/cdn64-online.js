// CDN64 online: Ein Klick in der Host-Liste (Account pruefen, Tunnel anmelden, Namen einschalten, Selbsttest ueber
// srv07/srv08) und Ausschalten. Texte aus data-l (JSON) des Fensters, API unter /api/cdn64 (Sitzung + X-CSRF-Token).
// Vanilla-JS, keine externen Quellen.
(function () {
	"use strict";
	var modalEl = document.querySelector("[data-online-modal]");
	if (!modalEl || !window.bootstrap) { return; }
	var L = {};
	try { L = JSON.parse(modalEl.getAttribute("data-l") || "{}"); } catch (e) { L = {}; }
	var csrf = modalEl.getAttribute("data-csrf") || "";
	var modal = new window.bootstrap.Modal(modalEl);
	var stepsEl = modalEl.querySelector("[data-online-steps]");
	var setup = modalEl.querySelector("[data-online-setup]");
	var startBtn = modalEl.querySelector("[data-online-start]");
	var modeSel = modalEl.querySelector("[data-online-mode]");
	var hc = modalEl.querySelector("[data-online-hc]");
	var hostID = "", onlyTest = false, busy = false, changed = false;

	function t(k, args) {
		var s = L[k] || k;
		Object.keys(args || {}).forEach(function (a) { s = s.split("{" + a + "}").join(String(args[a])); });
		return s;
	}

	function api(method, path, body) {
		var init = { method: method, cache: "no-store", headers: { "X-CSRF-Token": csrf, "Accept": "application/json" } };
		if (body) {
			init.headers["Content-Type"] = "application/json";
			init.body = JSON.stringify(body);
		}
		return fetch(path, init).then(function (r) {
			if (r.status === 204) { return null; }
			return r.json().catch(function () { return {}; }).then(function (j) {
				if (!r.ok) {
					var e = new Error((j && (j.text || j.error)) || ("HTTP " + r.status));
					e.code = j && j.code;
					throw e;
				}
				return j;
			});
		});
	}

	function el(tag, cls, text) {
		var x = document.createElement(tag);
		if (cls) { x.className = cls; }
		if (text !== undefined) { x.textContent = text; }
		return x;
	}

	// Schritt: Symbol (laeuft, ok, Hinweis, Fehler), Titel, Details darunter
	function step(title) {
		var li = el("li", "mb-3");
		var head = el("div", "d-flex align-items-center gap-2");
		var icon = el("span", "spinner-border spinner-border-sm text-primary");
		icon.setAttribute("role", "status");
		head.appendChild(icon);
		head.appendChild(el("strong", "", title));
		var body = el("div", "ms-4 mt-1");
		li.appendChild(head);
		li.appendChild(body);
		stepsEl.appendChild(li);
		var s = {
			body: body,
			ok: function () { icon.className = "bi bi-check-circle-fill text-success"; },
			warn: function () { icon.className = "bi bi-exclamation-triangle-fill text-warning"; },
			fail: function (msg) {
				icon.className = "bi bi-x-circle-fill text-danger";
				if (msg) { body.appendChild(el("div", "text-danger", msg)); }
			},
			line: function (text, cls) {
				var d = el("div", cls || "text-body-secondary", text);
				body.appendChild(d);
				return d;
			}
		};
		s.failed = function (e) { s.fail(e && e.message); throw e; };
		return s;
	}

	function quota(s, q) {
		if (!q) { return; }
		s.line(t("quota", { used: q.domains.used, limit: q.domains.limit, traffic: (q.traffic_mb.used / 1024).toFixed(1), tlimit: Math.round(q.traffic_mb.limit / 1024) }));
	}

	function account() {
		var s = step(t("s_account"));
		return api("GET", "/api/cdn64/online").then(function (v) {
			if (!v.api_ready) {
				s.fail(t("e.no_api_key"));
				var a = el("a", "btn btn-sm btn-outline-primary mt-1", t("connect"));
				a.href = "/settings#ipv64";
				s.body.appendChild(a);
				throw new Error("no_api_key");
			}
			if (v.quota && v.quota.domains.limit <= 0) {
				s.fail(t("e.plan_not_allowed"));
				throw new Error("plan_not_allowed");
			}
			s.ok();
			quota(s, v.quota);
			return v;
		}, s.failed);
	}

	function tunnel() {
		var s = step(t("s_tunnel"));
		return api("POST", "/api/cdn64/online/tunnel").then(function (v) {
			var up = v.edges.filter(function (e) { return e.connected; });
			var tcp = up.some(function (e) { return e.transport === "tcp"; });
			v.edges.forEach(function (e) {
				if (e.connected) {
					s.line(t("direct", { edge: e.name, transport: t("via_" + (e.via || (e.transport === "tcp" ? "tls" : "quic"))) }), "text-success");
				} else {
					s.line(up.length ? t("peer", { edge: e.name }) : t("down", { edge: e.name }));
				}
			});
			if (!up.length) {
				s.fail(t("e.tunnel_down"));
				throw new Error("tunnel_down");
			}
			if (tcp) {
				s.warn();
				s.line(t("tcp"), "text-warning-emphasis");
			} else {
				s.ok();
				if (v.udp_buffer_low) { s.line(t("udp_buf", { n: v.udp_buffer }), "text-body-secondary font-monospace small"); }
			}
			return v;
		}, s.failed);
	}

	function names() {
		var s = step(t("s_names"));
		var body = { mode: parseInt(modeSel.value, 10) || 1, healthcheck: !!(hc && hc.checked) };
		return api("POST", "/api/cdn64/hosts/" + hostID + "/online", body).then(function (res) {
			var on = 0, want = 0;
			res.results.forEach(function (r) {
				if (r.result !== "skipped") { want++; }
				if (r.result === "on") {
					on++;
					s.line("✓ " + r.name, "text-success font-monospace");
				} else {
					s.line((r.result === "skipped" ? "– " : "✗ ") + r.name + ": " + (r.text || r.error || r.code), r.result === "skipped" ? "text-body-secondary" : "text-danger");
				}
			});
			if (on) { changed = true; }
			if (res.check) {
				s.line(t("check_created"));
			} else if (res.check_error) {
				s.line(t("check_failed", { error: res.check_error }), "text-warning-emphasis");
			}
			if (!on) {
				s.fail();
				throw new Error("none");
			}
			if (on < want) { s.warn(); } else { s.ok(); }
			if (body.mode === 2) { s.line(t("mode2_hint")); }
			s.line(t("hint_lan"));
		}, s.failed);
	}

	// Selbsttest; direkt nach dem Einschalten holen die Server die Einstellung erst (bis 10 s): dann bis zu
	// dreimal im Abstand von 6 s wiederholen, bevor ein Fehler angezeigt wird
	function selftest(retries) {
		var s = step(t("s_test"));
		var wait = null;
		var attempt = function (left) {
			return api("POST", "/api/cdn64/hosts/" + hostID + "/online/test").then(function (list) {
				var bad = (list || []).some(function (n) { return n.probes.some(function (p) { return !p.ok && !p.skipped; }); });
				if (bad && left > 0) {
					if (!wait) { wait = s.line(t("wait_edges")); }
					return new Promise(function (r) { setTimeout(r, 6000); }).then(function () { return attempt(left - 1); });
				}
				if (wait) { wait.remove(); }
				return list;
			});
		};
		return attempt(retries || 0).then(function (list) {
			var okAny = false, okAll = true, url = "";
			(list || []).forEach(function (n) {
				var row = s.line("", "mt-1");
				row.appendChild(el("span", "font-monospace me-2", n.name));
				n.probes.forEach(function (p) {
					var fam = p.family === "ipv6" ? "IPv6" : "IPv4";
					var b = el("span", "badge me-1 " + (p.ok ? "text-bg-success" : (p.skipped ? "text-bg-light" : "text-bg-danger")),
						p.edge + " " + fam + (p.ok ? " · " + p.ms + " ms" : ""));
					b.title = p.ok ? p.addr : (p.skipped ? t("skipped", { family: fam }) : p.addr + ": " + p.error);
					row.appendChild(b);
					if (p.ok) { okAny = true; } else if (!p.skipped) { okAll = false; }
				});
				if (n.route_error) {
					okAll = false;
					s.line(t("route_error", { error: n.route_error }), "text-danger");
				}
				if (n.probes.some(function (p) { return p.other_node; })) { s.line(t("other_node"), "text-danger"); }
				if (n.probes.some(function (p) { return p.trusted === false; })) { s.line(t("untrusted"), "text-warning-emphasis"); }
				s.line(n.dns_ok ? t("dns_ok") : t("dns_wait"));
				if (!url) { url = n.stream_only ? n.name : (n.tls ? "https://" : "http://") + n.name; } // nur Streams: kein HTTP
			});
			if (okAny && okAll) {
				s.ok();
				s.line(t("done", { url: url }), "text-success fw-semibold");
			} else if (okAny) {
				s.warn();
				s.line(t("partial"), "text-warning-emphasis");
			} else {
				s.fail(t("failed"));
			}
		}, s.failed);
	}

	function run() {
		busy = true;
		startBtn.disabled = true;
		setup.classList.add("d-none");
		stepsEl.textContent = "";
		var chain = onlyTest ? Promise.resolve() : account().then(tunnel).then(names);
		chain.then(function () { return selftest(onlyTest ? 0 : 3); }).catch(function () { return null; }).then(function () {
			busy = false;
			onlyTest = true; // danach: erneut testen
			startBtn.disabled = false;
			startBtn.textContent = t("retest");
		});
	}

	// Erklaerung der Modi: Kasten anklicken waehlt den Modus, die Auswahl markiert den Kasten
	var picks = modalEl.querySelectorAll("[data-online-pick]");
	function markPick() {
		picks.forEach(function (p) { p.classList.toggle("active", p.getAttribute("data-online-pick") === modeSel.value); });
	}
	picks.forEach(function (p) {
		var pick = function () { modeSel.value = p.getAttribute("data-online-pick"); markPick(); };
		p.addEventListener("click", function (e) { if (!e.target.closest("a")) { pick(); } });
		p.addEventListener("keydown", function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(); } });
	});
	modeSel.addEventListener("change", markPick);

	function open(id, test, mode) {
		hostID = id;
		modeSel.value = mode === "2" ? "2" : "1"; // Modus 3 gibt es nur auf ipv64.net/cdn64
		markPick();
		onlyTest = test;
		stepsEl.textContent = "";
		setup.classList.toggle("d-none", test);
		startBtn.textContent = test ? t("retest") : t("start");
		modal.show();
		if (test) { run(); }
	}

	document.querySelectorAll("[data-c64o-on]").forEach(function (b) {
		b.addEventListener("click", function () { open(b.getAttribute("data-c64o-on"), false, b.getAttribute("data-c64o-mode")); });
	});
	document.querySelectorAll("[data-c64o-test]").forEach(function (b) {
		b.addEventListener("click", function () { open(b.getAttribute("data-c64o-test"), true); });
	});
	document.querySelectorAll("[data-c64o-off]").forEach(function (b) {
		b.addEventListener("click", function () {
			if (!window.confirm(t("off_confirm", { name: b.getAttribute("data-name") || "" }))) { return; }
			b.disabled = true;
			api("DELETE", "/api/cdn64/hosts/" + b.getAttribute("data-c64o-off") + "/online").then(function () {
				window.location.reload();
			}, function (e) {
				b.disabled = false;
				window.alert(e.message);
			});
		});
	});
	// Pause: Host der Node (data-c64o-pause = Host-ID) bzw. Name, den die Node nicht verwaltet (data-c64o-rpause = ID bei ipv64)
	document.querySelectorAll("[data-c64o-pause],[data-c64o-rpause]").forEach(function (b) {
		b.addEventListener("click", function () {
			var pause = b.getAttribute("data-paused") !== "1";
			if (pause && !window.confirm(t("pause_confirm", { name: b.getAttribute("data-name") || "" }))) { return; }
			var path = b.hasAttribute("data-c64o-pause") ? "/api/cdn64/hosts/" + b.getAttribute("data-c64o-pause") + "/online/pause"
				: "/api/cdn64/online/names/" + b.getAttribute("data-c64o-rpause") + "/pause";
			b.disabled = true;
			api("POST", path, { paused: pause }).then(function () {
				window.location.reload();
			}, function (e) {
				b.disabled = false;
				window.alert(e.message);
			});
		});
	});
	startBtn.addEventListener("click", function () { if (!busy) { run(); } });
	modalEl.addEventListener("hidden.bs.modal", function () { if (changed) { window.location.reload(); } });
})();
