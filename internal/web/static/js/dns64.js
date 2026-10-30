// DNS64: Seiten Uebersicht, Abfrage-Log, Freigaben & Blocklisten. Daten ueber /api/dns64/*.
(function () {
	"use strict";
	// Rueckfrage vor Loeschen/Entfernen (Buttons mit data-confirm, auch in Formularen mit formaction)
	document.querySelectorAll("[data-confirm]").forEach(function (b) {
		b.addEventListener("click", function (e) {
			if (!window.confirm(b.getAttribute("data-confirm"))) { e.preventDefault(); }
		});
	});
	// laufender Zertifikatsabruf: Seite alle paar Sekunden neu laden, bis er fertig ist
	var reload = document.querySelector("[data-dns64-reload]");
	if (reload) { setTimeout(function () { location.reload(); }, 1000 * Number(reload.getAttribute("data-dns64-reload") || 3)); }
	var dataEl = document.getElementById("dns64-data");
	var page = document.querySelector("[data-dns64-page]");
	if (!dataEl || !page) { return; }
	var cfg = JSON.parse(dataEl.textContent || "{}");
	var T = cfg.t || {};
	var locale = cfg.lang === "en" ? "en-GB" : "de-DE";
	var nf = new Intl.NumberFormat(locale);
	var pf = new Intl.NumberFormat(locale, { maximumFractionDigits: 1 });
	var PAGE_SIZE = 50;
	var state = { range: "24h", chartRange: "24h", status: "", search: "", group: "*", live: true, page: 0, total: 0 };
	var allowed = new Set();
	var denied = new Set(); // eigene Sperrliste
	var $ = function (id) { return document.getElementById(id); };

	// t liefert einen Text, {name}-Platzhalter werden ersetzt
	function t(key, vars) {
		var s = T[key] || key;
		if (vars) { Object.keys(vars).forEach(function (k) { s = s.split("{" + k + "}").join(vars[k]); }); }
		return s;
	}

	function api(path, opts) {
		opts = opts || {};
		var init = { method: opts.method || "GET", cache: "no-store", headers: {} };
		if (init.method !== "GET") {
			init.headers["X-CSRF-Token"] = cfg.csrf;
			init.headers["Content-Type"] = "application/json";
			init.body = JSON.stringify(opts.body || {});
		}
		return fetch("/api/dns64/" + path, init).then(function (r) {
			if (r.status === 204) { return null; }
			return r.json().catch(function () { return {}; }).then(function (j) {
				if (!r.ok) { throw new Error((j && j.error) || ("HTTP " + r.status)); }
				return j;
			});
		});
	}

	function el(tag, attrs, text) {
		var e = document.createElement(tag);
		Object.keys(attrs || {}).forEach(function (k) { e.setAttribute(k, attrs[k]); });
		if (text !== undefined) { e.textContent = text; }
		return e;
	}

	function toast(msg) {
		var box = $("dns64-toast");
		if (!box || !window.bootstrap) { return; }
		box.querySelector(".toast-body").textContent = msg;
		window.bootstrap.Toast.getOrCreateInstance(box, { delay: 3500 }).show();
	}

	function ago(date) {
		var s = Math.max(0, (Date.now() - date.getTime()) / 1000);
		if (s < 90) { return t("just_now"); }
		if (s < 5400) { return t("min_ago", { n: Math.round(s / 60) }); }
		if (s < 129600) { return t("hours_ago", { n: Math.round(s / 3600) }); }
		return t("days_ago", { n: Math.round(s / 86400) });
	}

	function fmtDuration(ms) {
		var s = ms / 1000;
		if (s < 60) { return pf.format(s) + " " + t("sec"); }
		if (s < 3600) { return pf.format(s / 60) + " " + t("min"); }
		return pf.format(s / 3600) + " " + t("hours");
	}

	function badge(status) {
		var cls = { allowed: "text-bg-success", blocked: "text-bg-danger", cached: "text-bg-info", local: "text-bg-secondary", error: "text-bg-warning", custom: "text-bg-primary" }[status] || "text-bg-light";
		return el("span", { "class": "badge " + cls }, t("status." + status));
	}

	// ---------- Freigaben ----------

	function isReleased(domain) {
		for (var d = domain; d;) {
			if (allowed.has(d)) { return true; }
			var i = d.indexOf(".");
			if (i < 0) { return false; }
			d = d.slice(i + 1);
		}
		return false;
	}

	function releaseButton(domain) {
		if (isReleased(domain)) { return el("span", { "class": "badge text-bg-light" }, "✓ " + t("released")); }
		var b = el("button", { type: "button", "class": "btn btn-sm btn-outline-success py-0", title: t("release_title", { domain: domain }) }, t("release"));
		b.addEventListener("click", function (e) { e.stopPropagation(); release(domain); });
		return b;
	}

	// Eigene Sperrliste: Domain samt Subdomains sperren (Knopf im Abfrage-Log und Karte unter den Freigaben)
	function isDenied(domain) {
		for (var d = domain; d;) {
			if (denied.has(d)) { return true; }
			var i = d.indexOf(".");
			if (i < 0) { return false; }
			d = d.slice(i + 1);
		}
		return false;
	}

	function blockButton(domain) {
		if (isDenied(domain)) { return el("span", { "class": "badge text-bg-light" }, "⛔ " + t("own_blocked")); }
		var b = el("button", { type: "button", "class": "btn btn-sm btn-outline-danger py-0", title: t("block_title", { domain: domain }) }, t("block"));
		b.addEventListener("click", function (e) { e.stopPropagation(); block(domain); });
		return b;
	}

	function block(domain) {
		if (!window.confirm(t("block_confirm", { domain: domain }))) { return; }
		api("denylist", { method: "POST", body: { domain: domain } }).then(function (r) {
			toast(t("blocked_toast", { domain: (r && r.domain) || domain }));
			return afterAllowChange();
		}).catch(function (e) { toast(t("error") + ": " + e.message); });
	}

	function unblock(domain) {
		if (!window.confirm(t("unblock_confirm", { domain: domain }))) { return; }
		api("denylist?domain=" + encodeURIComponent(domain), { method: "DELETE" }).then(function () {
			toast(t("unblocked_toast", { domain: domain }));
			return afterAllowChange();
		}).catch(function (e) { toast(t("error") + ": " + e.message); });
	}

	function loadDeny() {
		return api("denylist").then(function (list) {
			denied = new Set(list.map(function (e) { return e.domain; }));
			var ul = $("deny-list");
			if (!ul) { return; }
			ul.replaceChildren();
			if (!list.length) { ul.append(el("li", { "class": "list-group-item px-0 text-body-secondary" }, t("no_own_blocks"))); return; }
			list.forEach(function (e) {
				var li = el("li", { "class": "list-group-item px-0 d-flex align-items-center gap-2" });
				var b = el("button", { type: "button", "class": "btn btn-sm btn-outline-secondary py-0 ms-auto" }, t("remove"));
				b.addEventListener("click", function () { unblock(e.domain); });
				var when = e.addedAt && e.addedAt.indexOf("0001") !== 0 ? ago(new Date(e.addedAt)) : "";
				li.append(el("span", { "class": "font-monospace text-truncate", title: e.domain }, e.domain), el("span", { "class": "text-body-secondary text-nowrap" }, when), b);
				ul.append(li);
			});
		});
	}

	function afterAllowChange() {
		return Promise.allSettled([loadAllow(), loadDeny()]).then(function () {
			if ($("top-blocked")) { loadTop("blocked", "top-blocked"); }
			if ($("log-body")) { loadLog(); }
		});
	}

	function release(domain) {
		if (!window.confirm(t("release_confirm", { domain: domain }))) { return; }
		api("allowlist", { method: "POST", body: { domain: domain } }).then(function () {
			toast(t("released_toast", { domain: domain }));
			return afterAllowChange();
		}).catch(function (e) { toast(t("error") + ": " + e.message); });
	}

	function unrelease(domain) {
		if (!window.confirm(t("unrelease_confirm", { domain: domain }))) { return; }
		api("allowlist?domain=" + encodeURIComponent(domain), { method: "DELETE" }).then(function () {
			toast(t("unreleased_toast", { domain: domain }));
			return afterAllowChange();
		}).catch(function (e) { toast(t("error") + ": " + e.message); });
	}

	function loadAllow() {
		return api("allowlist").then(function (list) {
			allowed = new Set(list.map(function (e) { return e.domain; }));
			var ul = $("allow-list");
			if (!ul) { return; }
			ul.replaceChildren();
			if (!list.length) { ul.append(el("li", { "class": "list-group-item px-0 text-body-secondary" }, t("no_releases"))); return; }
			list.forEach(function (e) {
				var li = el("li", { "class": "list-group-item px-0 d-flex align-items-center gap-2" });
				var b = el("button", { type: "button", "class": "btn btn-sm btn-outline-danger py-0 ms-auto" }, t("remove"));
				b.addEventListener("click", function () { unrelease(e.domain); });
				var when = e.addedAt && e.addedAt.indexOf("0001") !== 0 ? ago(new Date(e.addedAt)) : "";
				li.append(el("span", { "class": "font-monospace text-truncate", title: e.domain }, e.domain), el("span", { "class": "text-body-secondary text-nowrap" }, when), b);
				ul.append(li);
			});
		});
	}

	// ---------- Upstreams und Cache ----------

	var upstreamAvgMs = 0; // Schnitt des schnellsten Upstreams, fuer die eingesparte Wartezeit

	function loadUpstreams() {
		return api("upstreams").then(function (d) {
			var box = $("upstreams");
			box.replaceChildren();
			$("up-mode").textContent = t("mode_" + d.mode) + (d.mode === "fastest" ? " · " + d.count : "");
			var wins = d.servers.reduce(function (a, s) { return a + s.wins; }, 0);
			var avgs = d.servers.map(function (s) { return s.avgMs; }).filter(Boolean);
			upstreamAvgMs = avgs.length ? Math.min.apply(null, avgs) : 0;
			d.servers.forEach(function (s) {
				var ok = s.requests === 0 || s.healthy;
				var share = wins ? 100 * s.wins / wins : 0;
				var card = el("div", { "class": "border rounded p-2" });
				var title = el("div", { "class": "d-flex flex-wrap align-items-center gap-2" }); // Handy: IPs in eine eigene Zeile
				title.append(el("b", {}, s.name), el("span", { "class": "badge text-bg-info" }, { doh: "DoH", dot: "DoT", doq: "DoQ" }[s.proto] || s.proto),
					el("span", { "class": "badge " + (ok ? "text-bg-success" : "text-bg-danger") }, s.requests === 0 ? t("ready") : ok ? t("online") : t("disturbed")),
					s.active ? el("span", { "class": "badge text-bg-primary" }, t("in_use")) : "",
					el("span", { "class": "text-body-secondary ms-auto font-monospace text-break" }, s.ips.join(", ")));
				var stats = el("div", { "class": "d-flex flex-wrap gap-3 mt-1" });
				[[t("avg"), s.avgMs ? pf.format(s.avgMs) + " ms" : "–"], [t("fastest"), pf.format(share) + " %"], [t("requests"), nf.format(s.requests)], [t("errors"), nf.format(s.errors)]].forEach(function (p) {
					var sp = el("span", { "class": "text-body-secondary" }, p[0] + " ");
					sp.append(el("b", { "class": "text-body" }, p[1]));
					stats.append(sp);
				});
				var bar = el("div", { "class": "progress mt-1", style: "height:.3rem" });
				var fill = el("div", { "class": "progress-bar bg-info" });
				fill.style.width = share + "%";
				bar.append(fill);
				card.append(title, el("div", { "class": "text-body-secondary text-break", title: s.url }, s.url), stats, bar);
				if (s.lastError && !s.healthy) { card.append(el("div", { "class": "text-danger text-truncate", title: s.lastError }, t("last_error") + ": " + s.lastError)); }
				box.append(card);
			});
			var addr = (d.localDNS || "").replace(/:53$/, "").replace(/^\[(.*)\]$/, "$1");
			$("local-dns").textContent = d.localDNS ? t(d.localSource === "auto" ? "router_auto" : "router_config", { addr: addr }) : t("router_none");
		});
	}

	function loadCache() {
		return api("cache").then(function (c) {
			var lookups = c.hits + c.misses;
			var rate = lookups ? 100 * c.hits / lookups : 0;
			$("c-rate").textContent = lookups ? pf.format(rate) + " %" : "–";
			$("c-rate-bar").style.width = rate + "%";
			var entries = $("c-entries");
			entries.textContent = nf.format(c.entries) + " ";
			entries.append(el("small", { "class": "text-body-secondary" }, t("of") + " " + nf.format(c.max)));
			$("c-saved").textContent = upstreamAvgMs && c.hits ? "≈ " + fmtDuration(c.hits * upstreamAvgMs) : "–";
			$("c-stale").textContent = nf.format(c.staleServed);
			var ref = $("c-refreshed");
			ref.textContent = nf.format(c.refreshed) + " ";
			if (c.refreshFailures) { ref.append(el("small", { "class": "text-danger" }, nf.format(c.refreshFailures) + " " + t("failed"))); }
		});
	}

	// ---------- Kennzahlen und Zeitverlauf ----------

	function loadSummary() {
		return api("summary?range=" + state.range).then(function (d) {
			var s = d.summary;
			var hours = { "1h": 1, "24h": 24, "7d": 168 }[state.range];
			$("k-total").textContent = nf.format(s.total);
			$("k-rate").textContent = t("per_hour", { n: nf.format(Math.round(s.total / hours)) });
			$("k-blocked").textContent = nf.format(s.blocked);
			$("k-pct").textContent = s.total ? t("pct_all", { n: pf.format(100 * s.blocked / s.total) }) : "";
			$("k-cached").textContent = nf.format(s.cached);
			$("k-cache-pct").textContent = s.total ? t("pct_cache", { n: pf.format(100 * s.cached / s.total) }) : "";
			$("k-clients").textContent = nf.format(s.clients);
			$("k-latency").textContent = s.avgUpstreamMs ? pf.format(s.avgUpstreamMs) + " ms" : "–";
			$("k-lists").textContent = nf.format(d.blocklistSize);
			$("k-lists-age").textContent = t("loaded", { ago: ago(new Date(d.listsLoadedAt)) });
		});
	}

	var chart = null;

	function fmtBucket(ts, stepMs) {
		var opts = stepMs >= 3600e3 * 4 ? { weekday: "short", hour: "2-digit", minute: "2-digit" } : { hour: "2-digit", minute: "2-digit" };
		return new Date(ts).toLocaleString(locale, opts);
	}

	function loadTimeline() {
		return api("timeline?range=" + state.chartRange).then(function (d) {
			var b = d.buckets || [];
			var labels = b.map(function (x) { return fmtBucket(x.t, d.stepMs); });
			var blocked = b.map(function (x) { return x.blocked; });
			var allowedV = b.map(function (x) { return x.total - x.blocked; });
			if (!window.Chart) { return; }
			if (chart) {
				chart.data.labels = labels;
				chart.data.datasets[0].data = allowedV;
				chart.data.datasets[1].data = blocked;
				chart.update("none");
				return;
			}
			var css = getComputedStyle(document.documentElement);
			var ok = css.getPropertyValue("--bs-success").trim() || "#198754";
			var bad = css.getPropertyValue("--bs-danger").trim() || "#dc3545";
			chart = new window.Chart($("dns64-chart"), {
				type: "bar",
				data: { labels: labels, datasets: [
					{ label: t("allowed"), data: allowedV, backgroundColor: ok, borderRadius: 3, stack: "q" },
					{ label: t("blocked"), data: blocked, backgroundColor: bad, borderRadius: 3, stack: "q" }
				] },
				options: {
					responsive: true, maintainAspectRatio: false, animation: false,
					interaction: { mode: "index", intersect: false },
					scales: { x: { stacked: true, grid: { display: false }, ticks: { autoSkip: true, maxRotation: 0 } }, y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } } },
					plugins: { legend: { position: "bottom" } }
				}
			});
		});
	}

	// ---------- Top-Listen ----------

	function loadTop(kind, target) {
		return api("top?kind=" + kind + "&range=" + state.range + "&limit=10").then(function (items) {
			var ul = $(target);
			ul.replaceChildren();
			if (!items.length) { ul.append(el("li", { "class": "list-group-item text-body-secondary" }, t("no_data"))); return; }
			var maxC = items[0].count;
			items.forEach(function (it) {
				var li = el("li", { "class": "list-group-item" });
				var row = el("div", { "class": "d-flex align-items-center gap-2" });
				var name = el("a", { href: "/dns64/log?q=" + encodeURIComponent(it.name), "class": "text-truncate text-decoration-none", title: it.name });
				if (kind === "clients" && it.hostname) {
					name.textContent = it.hostname + " ";
					name.append(el("small", { "class": "text-body-secondary" }, it.name));
				} else {
					name.textContent = it.name;
				}
				var cnt = kind === "clients" ? nf.format(it.count) + " · " + t("blocked_n", { n: nf.format(it.blocked) }) : nf.format(it.count);
				row.append(name, el("span", { "class": "ms-auto text-nowrap text-body-secondary" }, cnt));
				if (kind === "blocked") { row.append(releaseButton(it.name)); }
				var bar = el("div", { "class": "progress mt-1", style: "height:.25rem" });
				if (kind === "clients") {
					var fb = el("div", { "class": "progress-bar bg-danger" }), fa = el("div", { "class": "progress-bar bg-success" });
					fb.style.width = (100 * it.blocked / maxC) + "%";
					fa.style.width = (100 * (it.count - it.blocked) / maxC) + "%";
					bar.append(fb, fa);
				} else {
					var f = el("div", { "class": "progress-bar " + (kind === "blocked" ? "bg-danger" : "bg-success") });
					f.style.width = (100 * it.count / maxC) + "%";
					bar.append(f);
				}
				li.append(row, bar);
				ul.append(li);
			});
		});
	}

	// ---------- Abfrage-Log ----------

	function searchFor(q) {
		$("log-search").value = q;
		state.search = q;
		state.page = 0;
		loadLog();
	}

	function loadLog() {
		var p = new URLSearchParams({ limit: PAGE_SIZE, offset: state.page * PAGE_SIZE });
		if (state.status) { p.set("status", state.status); }
		if (state.search) { p.set("q", state.search); }
		if (state.group !== "*") { p.set("group", state.group); }
		return api("log?" + p).then(function (d) {
			state.total = d.total;
			state.capped = !!d.capped;
			var pages = Math.max(1, Math.ceil(d.total / PAGE_SIZE));
			if (state.page >= pages) { state.page = pages - 1; if (d.total) { return loadLog(); } }
			renderPager(pages);
			var tb = $("log-body");
			tb.replaceChildren();
			if (!d.rows.length) {
				var tr0 = el("tr");
				tr0.append(el("td", { colspan: "8", "class": "text-body-secondary" }, t("no_entries")));
				tb.append(tr0);
				return;
			}
			var today = new Date().toDateString();
			d.rows.forEach(function (r) {
				var dt = new Date(r.t);
				var time = dt.toDateString() === today ? dt.toLocaleTimeString(locale)
					: dt.toLocaleString(locale, { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
				var tr = el("tr");
				var client = el("td", { "class": "text-nowrap", role: "button", title: r.client });
				client.textContent = r.clientName ? r.clientName + " " : r.client;
				if (r.clientName) { client.append(el("small", { "class": "text-body-secondary" }, r.client)); }
				if (r.group) { client.append(" ", el("span", { "class": "badge text-bg-light fw-normal" }, r.group)); }
				client.addEventListener("click", function () { searchFor(r.client); });
				var domain = el("td", { "class": "font-monospace text-break", role: "button", title: r.domain }, r.domain);
				domain.addEventListener("click", function () { searchFor(r.domain); });
				var details = r.reason || "";
				if (details === "stale") { details = t("reason_stale"); }
				else if (details.indexOf("released:") === 0) { details = t("reason_released", { list: details.slice(9) }); }
				else if (details.indexOf("own:") === 0) { details = t("reason_own", { domain: details.slice(4) }); }
				else if (details.indexOf("search:") === 0) { details = t("reason_search", { domain: details.slice(7) }); }
				else if (details.indexOf("paused:") === 0) { details = t("reason_paused", { list: details.slice(7) }); }
				else if (details.indexOf("group:") === 0) { details = t("reason_group", { domain: details.slice(6), group: r.group || "" }); }
				else if (details === "off:hold") { details = t("reason_off_hold", { group: r.group || "" }); }
				else if (details.indexOf("off:schedule:") === 0) { details = t("reason_off_schedule", { name: details.slice(13), group: r.group || "" }); }
				else if (details.indexOf("safesearch:") === 0) { details = t("reason_safesearch", { target: details.slice(11), group: r.group || "" }); }
				else if (details.indexOf("forward:") === 0) { details = t("reason_forward", { domain: details.slice(8), server: r.upstream || "" }); }
				else if (details.indexOf("rewrite:") === 0) { details = t("reason_rewrite", { target: details.slice(8) }); }
				else if (details === "canary") { details = t("reason_canary"); }
				else if (details === "bypass:icloud") { details = t("reason_bypass_icloud", { group: r.group || "" }); }
				else if (details.indexOf("cat:") === 0) { details = t("reason_cat", { cat: t("cat." + details.slice(4)), group: r.group || "" }); }
				if (!details && r.upstream) { details = t("via", { name: r.upstream }); }
				if (r.rcode && r.rcode !== "NOERROR") { details = (details ? details + " · " : "") + r.rcode; }
				var st = el("td");
				st.append(badge(r.status));
				var action = el("td", { "class": "text-end" });
				if (r.status === "blocked") { action.append(releaseButton(r.domain)); }
				else if (r.status === "allowed" || r.status === "cached") { action.append(blockButton(r.domain)); }
				tr.append(el("td", { "class": "text-nowrap" }, time), client, domain, el("td", { "class": "text-nowrap" }, r.qtype + (r.proto && r.proto !== "udp" ? " · " + t("proto." + r.proto) : "")), st,
					el("td", { "class": "text-body-secondary text-truncate", style: "max-width:22rem", title: details }, details),
					el("td", { "class": "text-end text-nowrap" }, r.ms < 1 ? "<1 ms" : pf.format(r.ms) + " ms"), action);
				tb.append(tr);
			});
		});
	}

	function renderPager(pages) {
		var from = state.total ? state.page * PAGE_SIZE + 1 : 0;
		var to = Math.min(state.total, (state.page + 1) * PAGE_SIZE);
		$("page-info").textContent = t("entries", { from: nf.format(from), to: nf.format(to), total: nf.format(state.total) + (state.capped ? "+" : "") })
			+ (state.page > 0 && state.live ? " · " + t("live_paused") : "");
		$("page-num").textContent = t("page", { n: nf.format(state.page + 1), of: nf.format(pages) });
		$("page-first").disabled = $("page-prev").disabled = state.page === 0;
		$("page-next").disabled = state.page >= pages - 1;
	}

	// ---------- Blocklisten ----------

	// loadLists traegt Domains, Stand und Status in die Zeilen der Listen-Tabelle ein (Zeile per data-url)
	function loadLists() {
		return api("lists").then(function (lists) {
			lists.forEach(function (l) {
				var tr = Array.prototype.find.call(document.querySelectorAll("tr[data-url]"), function (x) { return x.getAttribute("data-url") === l.url; });
				if (!tr) { return; }
				var loaded = l.updatedAt && l.updatedAt.indexOf("0001") !== 0;
				tr.querySelector(".l-rules").textContent = nf.format(l.rules);
				tr.querySelector(".l-updated").textContent = loaded ? ago(new Date(l.updatedAt)) : "–";
				var status = tr.querySelector(".l-status");
				status.replaceChildren();
				if (l.error) { status.append(el("span", { "class": "badge text-bg-danger text-wrap", title: l.error }, t("error") + ": " + l.error)); }
				else if (loaded) { status.append(el("span", { "class": "badge text-bg-success" }, t("active"))); }
				else { status.append(el("span", { "class": "badge text-bg-secondary" }, t("loading"))); }
			});
		});
	}

	// ---------- Verdrahtung je Seite ----------

	function every(ms, fn) { setInterval(function () { if (!document.hidden) { fn().catch(function () {}); } }, ms); }
	var kind = page.getAttribute("data-dns64-page");

	if (kind === "overview") {
		var refreshStats = function () {
			return Promise.allSettled([loadSummary(), loadTimeline(), loadTop("blocked", "top-blocked"), loadTop("allowed", "top-allowed"), loadTop("clients", "top-clients")]);
		};
		document.querySelectorAll("[data-range]").forEach(function (btn) {
			btn.addEventListener("click", function () {
				document.querySelectorAll("[data-range]").forEach(function (b) { b.classList.toggle("active", b === btn); });
				state.range = btn.getAttribute("data-range");
				refreshStats();
			});
		});
		// Zeitraum nur fuer das Diagramm "Anfragen im Zeitverlauf"
		document.querySelectorAll("[data-chart-range]").forEach(function (btn) {
			btn.addEventListener("click", function () {
				document.querySelectorAll("[data-chart-range]").forEach(function (b) { b.classList.toggle("active", b === btn); });
				state.chartRange = btn.getAttribute("data-chart-range");
				loadTimeline().catch(function () {});
			});
		});
		$("cache-flush").addEventListener("click", function () {
			if (!window.confirm(t("flush_confirm"))) { return; }
			api("cache/flush", { method: "POST" }).then(function (r) {
				toast(t("flushed", { n: nf.format(r.flushed) }));
				loadCache();
			}).catch(function (e) { toast(t("error") + ": " + e.message); });
		});
		loadAllow().catch(function () {}).then(refreshStats);
		loadUpstreams().catch(function () {}).then(function () { return loadCache(); }).catch(function () {});
		every(15000, refreshStats);
		every(10000, function () { return loadUpstreams().then(loadCache); });
	}

	if (kind === "log") {
		var q = new URLSearchParams(location.search).get("q");
		if (q) { $("log-search").value = q; state.search = q; }
		document.querySelectorAll("#log-filter button").forEach(function (btn) {
			btn.addEventListener("click", function () {
				document.querySelectorAll("#log-filter button").forEach(function (b) { b.classList.toggle("active", b === btn); });
				state.status = btn.getAttribute("data-status");
				state.page = 0;
				loadLog();
			});
		});
		if ($("log-group")) {
			$("log-group").addEventListener("change", function (e) { state.group = e.target.value; state.page = 0; loadLog(); });
		}
		var searchTimer;
		$("log-search").addEventListener("input", function (e) {
			clearTimeout(searchTimer);
			searchTimer = setTimeout(function () { state.search = e.target.value.trim(); state.page = 0; loadLog(); }, 250);
		});
		$("log-live").addEventListener("change", function (e) {
			state.live = e.target.checked;
			renderPager(Math.max(1, Math.ceil(state.total / PAGE_SIZE)));
		});
		$("page-first").addEventListener("click", function () { state.page = 0; loadLog(); });
		$("page-prev").addEventListener("click", function () { state.page = Math.max(0, state.page - 1); loadLog(); });
		$("page-next").addEventListener("click", function () { state.page += 1; loadLog(); });
		Promise.allSettled([loadAllow(), loadDeny()]).then(loadLog);
		every(3000, function () { return state.live && state.page === 0 ? loadLog() : Promise.resolve(); });
	}

	if (kind === "lists" && $("allow-form")) {
		$("allow-form").addEventListener("submit", function (e) {
			e.preventDefault();
			var v = $("allow-input").value.trim().toLowerCase();
			if (!v) { return; }
			api("allowlist", { method: "POST", body: { domain: v } }).then(function (r) {
				$("allow-input").value = "";
				toast(t("released_toast", { domain: r.domain }));
				return loadAllow();
			}).catch(function (err) { toast(t("error") + ": " + err.message); });
		});
		if ($("deny-form")) {
			$("deny-form").addEventListener("submit", function (e) {
				e.preventDefault();
				var v = $("deny-input").value.trim().toLowerCase();
				if (!v) { return; }
				api("denylist", { method: "POST", body: { domain: v } }).then(function (r) {
					$("deny-input").value = "";
					toast(t("blocked_toast", { domain: r.domain }));
					return afterAllowChange();
				}).catch(function (err) { toast(t("error") + ": " + err.message); });
			});
		}
		loadAllow().catch(function () {});
		loadDeny().catch(function () {});
		loadLists().catch(function () {});
		every(60000, loadLists);
	}

	// Eigene Eintraege: Beispiel und Hinweis je Typ, Bearbeiten im selben Formular, Suche in der Tabelle
	if (kind === "records" && $("rec-form")) {
		var examples = { A: "192.168.1.10", AAAA: "fd00::10", CNAME: "nas.home.lan", TXT: "v=spf1 -all", MX: "10 mail.home.lan",
			SRV: "0 5 5060 sip.home.lan", PTR: "nas.home.lan", CAA: "0 issue letsencrypt.org" };
		var form = $("rec-form"), typeSel = $("r-type");
		var onType = function () {
			var ty = typeSel.value;
			$("r-value").placeholder = examples[ty] || "";
			var zn = form.getAttribute("data-zone") || ""; // in einer Zone: Name relativ
			$("r-name").placeholder = ty === "PTR" && !zn ? "192.168.1.10" : ty === "SRV" ? (zn ? "_sip._tcp" : "_sip._tcp.home.lan") : (zn ? "nas" : "nas.home.lan");
			$("r-type-hint").textContent = t("rec_hint_" + ty);
			$("r-noptr-wrap").classList.toggle("d-none", ty !== "A" && ty !== "AAAA");
		};
		typeSel.addEventListener("change", onType);
		onType();
		var addTitle = $("rec-title").textContent, submit = $("rec-submit"), addLabel = submit.querySelector("span").textContent;
		var reset = function () {
			form.reset();
			form.action = "/dns64/records";
			$("rec-title").textContent = addTitle;
			submit.querySelector("span").textContent = addLabel;
			$("rec-cancel").classList.add("d-none");
			onType();
		};
		document.querySelectorAll("[data-rec-edit]").forEach(function (b) {
			b.addEventListener("click", function () {
				form.action = "/dns64/records/" + b.getAttribute("data-rec-edit") + "/edit";
				var nm = b.getAttribute("data-name"), zn = form.getAttribute("data-zone") || "";
				if (zn) { nm = nm === zn ? "@" : nm.slice(-(zn.length + 1)) === "." + zn ? nm.slice(0, -(zn.length + 1)) : nm + "."; }
				$("r-name").value = nm;
				typeSel.value = b.getAttribute("data-type");
				$("r-value").value = b.getAttribute("data-value");
				$("r-ttl").value = b.getAttribute("data-ttl");
				$("r-comment").value = b.getAttribute("data-comment");
				$("r-noptr").checked = b.getAttribute("data-noptr") === "1";
				$("r-local").checked = b.getAttribute("data-local") === "1";
				$("rec-title").textContent = $("rec-title").getAttribute("data-edit");
				submit.querySelector("span").textContent = submit.getAttribute("data-edit");
				$("rec-cancel").classList.remove("d-none");
				onType();
				form.scrollIntoView({ behavior: "smooth", block: "start" });
				$("r-name").focus();
			});
		});
		$("rec-cancel").addEventListener("click", reset);
		document.querySelectorAll("[data-reveal]").forEach(function (b) {
			b.addEventListener("click", function () { var f = $(b.getAttribute("data-reveal")); f.type = f.type === "password" ? "text" : "password"; });
		});
		if ($("rec-search")) {
			$("rec-search").addEventListener("input", function (e) {
				var q = e.target.value.trim().toLowerCase(), n = 0;
				document.querySelectorAll("tr[data-rec]").forEach(function (tr) {
					var hit = !q || tr.getAttribute("data-rec").toLowerCase().indexOf(q) >= 0;
					tr.classList.toggle("d-none", !hit);
					if (hit) { n++; }
				});
				$("rec-count").textContent = nf.format(n);
			});
		}
	}

	// Weiterleitungen, Umschreiben und lokale Zonen: Bearbeiten im Formular der Karte, Testabfrage je Weiterleitung
	if (kind === "forwards" || kind === "records") {
		var reset = function (form) {
			var title = form.closest(".card").querySelector(".card-header [data-edit]"), btn = form.querySelector("button[type=submit] span");
			form.reset();
			form.action = form.getAttribute("data-base");
			if (form.dataset.addTitle) { title.textContent = form.dataset.addTitle; btn.textContent = form.dataset.addLabel; }
			form.querySelector("[data-cancel]").classList.add("d-none");
		};
		document.querySelectorAll("[data-edit-form]").forEach(function (b) {
			b.addEventListener("click", function () {
				var form = $(b.getAttribute("data-edit-form"));
				var title = form.closest(".card").querySelector(".card-header [data-edit]"), btn = form.querySelector("button[type=submit]");
				if (!form.dataset.addTitle) { form.dataset.addTitle = title.textContent; form.dataset.addLabel = btn.querySelector("span").textContent; }
				form.action = form.getAttribute("data-base") + "/" + b.getAttribute("data-id") + "/edit";
				form.querySelectorAll("[data-field]").forEach(function (f) {
					var v = b.getAttribute("data-" + f.getAttribute("data-field")) || "";
					if (f.type === "checkbox") { f.checked = v === "1"; } else { f.value = v; }
				});
				title.textContent = title.getAttribute("data-edit");
				btn.querySelector("span").textContent = btn.getAttribute("data-edit");
				form.querySelector("[data-cancel]").classList.remove("d-none");
				form.scrollIntoView({ behavior: "smooth", block: "start" });
			});
		});
		document.querySelectorAll("form [data-cancel]").forEach(function (c) {
			c.addEventListener("click", function () { reset(c.form); });
		});
		document.querySelectorAll("[data-fwd-test]").forEach(function (b) {
			b.addEventListener("click", function () {
				var id = b.getAttribute("data-fwd-test"), out = document.querySelector('[data-fwd-result="' + id + '"]');
				out.className = "small text-body-secondary";
				out.textContent = t("loading");
				api("forwards/" + id + "/test", { method: "POST" }).then(function (r) {
					out.className = "small " + (r.ok ? "text-success" : "text-danger");
					out.textContent = r.ok ? t("fwd_ok", { rcode: r.rcode, server: r.server, ms: pf.format(r.ms) })
						: t("fwd_fail", { err: r.error || r.rcode || "" });
				}).catch(function (e) { out.className = "small text-danger"; out.textContent = t("error") + ": " + e.message; });
			});
		});
	}
})();
