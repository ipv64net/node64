package sonar

// Ablauf eines Knotens: anmelden, Plan holen, Runden messen, melden, Antworter (Vertrag Abschnitt 8).

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
)

// responderIface ist der Antworter auf UDP 6464 (Tests ersetzen ihn).
type responderIface interface {
	Run(ctx context.Context) error
	Drain() []Inbound
}

// openResponder oeffnet den echten Antworter (Teil Messung).
var openResponder = func(addr, nodeID string) (responderIface, error) {
	r, err := NewResponder(addr, nodeID)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, errors.New("responder unavailable")
	}
	return r, nil
}

var errCodeRe = regexp.MustCompile(`^[a-z0-9_]{1,24}$`)

// limits liefert die wirksamen Grenzen.
func (r *Runner) limits() limits {
	r.mu.Lock()
	b := r.budget
	r.mu.Unlock()
	return limitsFor(r.anchor, b)
}

// safe fuehrt f aus und faengt Panics ab (boesartige Daten duerfen den Knoten nicht beenden).
func (r *Runner) safe(what string, f func()) {
	defer func() {
		if p := recover(); p != nil {
			r.log.Error("sonar64: internal error", "in", what, "panic", fmt.Sprint(p))
			r.setErr(fmt.Errorf("internal error in %s", what))
		}
	}()
	f()
}

func (r *Runner) setErr(err error) {
	r.mu.Lock()
	if err == nil {
		r.lastErr = ""
	} else {
		r.lastErr = errText(err)
	}
	r.mu.Unlock()
}

// setPlanErr merkt einen Fehler beim Plan (nil = behoben).
func (r *Runner) setPlanErr(err error) {
	r.mu.Lock()
	if err == nil {
		r.planErr = ""
	} else {
		r.planErr = errText(err)
	}
	r.mu.Unlock()
}

func (r *Runner) signalWake() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// jitter verteilt d um +-20 % (Abrufe vieler Knoten verteilen sich, Vertrag 10.1).
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	return d + time.Duration(rand.Int64N(int64(d)*2/5+1)) - d/5
}

// ---- Abmeldung durch ipv64 (Vertrag 10.2) ----

// revokedErr: ipv64 kennt das Token nicht mehr (401 invalid_token) oder hat den Knoten gesperrt (403
// node_disabled). Anderes 401/403 (ohne diesen Code, z. B. von einem Proxy) und 429 zaehlen nicht.
func revokedErr(err error) bool {
	var e *APIError
	if !errors.As(err, &e) {
		return false
	}
	return e.Status == http.StatusUnauthorized && e.Code == "invalid_token" || e.Status == http.StatusForbidden && e.Code == "node_disabled"
}

func (r *Runner) isRevoked() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.revoked
}

// noteRevoked schaltet bei einer Abmeldung durch ipv64 in den Zustand abgemeldet: nichts mehr messen, Antworter zu,
// Puffer verwerfen, nur noch stuendlich GET /sonar/me (checkBack). true = abgemeldet.
func (r *Runner) noteRevoked(err error) bool {
	if !revokedErr(err) {
		return false
	}
	r.mu.Lock()
	first := !r.revoked
	r.revoked, r.paused, r.lastErr = true, "revoked", errText(err)
	r.bufOff, r.buf = r.bufOff+uint64(len(r.buf)), nil
	r.inOff, r.inbuf = r.inOff+uint64(len(r.inbuf)), nil
	r.mu.Unlock()
	if first {
		r.signalWake() // Antworter schliessen
		r.log.Warn("sonar64: node signed off by ipv64 - not measuring, checking again every hour", "err", errText(err))
	}
	return true
}

// checkBack fragt im Zustand abgemeldet, ob ipv64 den Knoten wieder annimmt (GET /sonar/me, z. B. nach einem
// voruebergehend gesperrten Account): 200 bzw. 409 not_registered (Token gilt, noch ohne Knoten) = wieder normal.
func (r *Runner) checkBack(ctx context.Context) {
	resp, err := r.api.send(ctx, http.MethodGet, "/sonar/me", r.cfg.Token, nil, nil, smallLimit)
	if err != nil {
		r.log.Debug("sonar64: revocation check failed", "err", errText(err))
		return
	}
	if resp.status != http.StatusOK && (resp.status != http.StatusConflict || apiError(resp).Code != "not_registered") {
		r.setErr(apiError(resp))
		return
	}
	r.mu.Lock()
	r.revoked, r.paused, r.lastErr = false, "", ""
	r.mu.Unlock()
	r.signalWake() // Antworter wieder oeffnen (falls gemessen)
	r.log.Info("sonar64: ipv64 accepts the node again")
}

// waitRevoked wartet im Zustand abgemeldet bis zur naechsten Pruefung und fuehrt sie aus. false = ctx beendet.
func (r *Runner) waitRevoked(ctx context.Context) bool {
	if sleepCtx(ctx, jitter(r.revokedEvery)) != nil {
		return false
	}
	r.safe("revoked check", func() { r.checkBack(ctx) })
	return true
}

// ---- Anmeldung ----

// ensureRegistered meldet den Knoten einmal an (POST /sonar/register) und wiederholt mit wachsendem Abstand
// (abgemeldet: stuendlich pruefen). Fehler nur, wenn ctx endet.
func (r *Runner) ensureRegistered(ctx context.Context) error {
	wait := r.retryMin
	for {
		if r.isRevoked() {
			if !r.waitRevoked(ctx) {
				return ctx.Err()
			}
			continue
		}
		r.mu.Lock()
		done := r.registered
		r.mu.Unlock()
		if done {
			r.safe("sync me", func() { r.syncMe(ctx) })
			return nil
		}
		var err error
		r.safe("register", func() { err = r.register(ctx) })
		if err == nil {
			r.safe("sync me", func() { r.syncMe(ctx) })
			return nil
		}
		r.setErr(err)
		if r.noteRevoked(err) {
			continue
		}
		r.log.Warn("sonar64: register failed", "err", errText(err), "retry_in", wait)
		if e := sleepCtx(ctx, jitter(wait)); e != nil {
			return e
		}
		wait = min(wait*2, time.Hour)
	}
}

func (r *Runner) register(ctx context.Context) error {
	// Wiederholung mit demselben Schluessel liefert denselben Knoten; 409 = Token gehoert zu einem anderen Schluessel
	// (dann hilft nur ein neues Token).
	var me Me
	err := r.api.call(ctx, http.MethodPost, "/sonar/register", r.cfg.Token,
		Register{PubKey: r.pubB64, Version: r.cfg.Version, Mode: r.cfg.Mode}, smallLimit, &me)
	if err != nil {
		return err
	}
	if !validNodeID(me.NodeID) {
		return errors.New("ipv64: invalid node id in answer")
	}
	r.mu.Lock()
	r.st.NodeID, r.st.TokenID = me.NodeID, r.tokenID
	r.registered = true
	r.lastErr = ""
	r.mu.Unlock()
	r.saveState()
	r.log.Info("sonar64: registered", "node_id", me.NodeID)
	return nil
}

// syncMe gleicht Measured und Budget bei ipv64 mit der lokalen Einstellung ab (lokal ist massgeblich).
func (r *Runner) syncMe(ctx context.Context) {
	if r.anchor {
		return
	}
	m, err := r.Me(ctx)
	if err != nil {
		r.log.Debug("sonar64: me not readable", "err", errText(err))
		return
	}
	r.mu.Lock()
	measured, budget := r.measured, r.budget
	r.mu.Unlock()
	if m.Measured == measured && m.Budget == budget {
		return
	}
	w := meWrite{Measured: measured, Budget: budget}
	if err := r.api.call(ctx, http.MethodPut, "/sonar/me", r.cfg.Token, w, smallLimit, nil); err != nil && !r.noteRevoked(err) {
		r.log.Warn("sonar64: cannot update settings at ipv64", "err", errText(err))
	}
}

func (r *Runner) initProber() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.prober != nil {
		return
	}
	if r.cfg.Prober != nil {
		r.prober = r.cfg.Prober
		return
	}
	r.prober = NewProber(ProbeConfig{NodeID: r.st.NodeID})
	if r.prober == nil {
		r.lastErr = "no prober available"
	}
}

// ---- Plan ----

// restorePlan uebernimmt den gespeicherten Plan, wenn er noch passt (Signatur erneut pruefen).
func (r *Runner) restorePlan() {
	st := r.st
	if len(st.PlanRaw) == 0 {
		return
	}
	now := r.now()
	got := st.PlanGot
	if got.IsZero() || got.After(now) {
		got = now
	}
	p, err := verifyPlan(st.PlanRaw, st.PlanSig, r.keys, st.NodeID, now)
	if err != nil {
		r.st.PlanRaw, r.st.ETag = nil, ""
		return
	}
	ap := &activePlan{plan: *p, raw: st.PlanRaw, kid: st.PlanKID, sig: st.PlanSig, etag: st.ETag, got: got}
	ap.validUntil, ap.anchorsUntil = window(p, got)
	if now.Before(ap.anchorsUntil) {
		r.plan = ap
	}
}

func (r *Runner) planLoop(ctx context.Context) {
	for {
		if r.isRevoked() { // abgemeldet: nur die stuendliche Pruefung, kein Plan
			if !r.waitRevoked(ctx) {
				return
			}
			continue
		}
		var next time.Duration
		r.safe("plan", func() { next = r.fetchPlan(ctx) })
		if next <= 0 {
			next = r.retryMin
		}
		if sleepCtx(ctx, next) != nil {
			return
		}
	}
}

var etagRe = regexp.MustCompile(`^(W/)?"?[A-Za-z0-9_.-]{1,64}"?$`)

// fetchPlan holt den Plan (ETag) und liefert die Wartezeit bis zum naechsten Abruf.
func (r *Runner) fetchPlan(ctx context.Context) time.Duration {
	r.mu.Lock()
	nodeID := r.st.NodeID
	var etag string
	if r.plan != nil {
		etag = r.plan.etag
	}
	r.mu.Unlock()
	hdr := http.Header{}
	if etag != "" {
		hdr.Set("If-None-Match", etag)
	}
	limit := int64(planLimitNode)
	if r.anchor {
		limit = planLimitAnchor
	}
	resp, err := r.api.send(ctx, http.MethodGet, "/sonar/plan", r.cfg.Token, hdr, nil, limit)
	if err != nil {
		r.setPlanErr(err)
		return r.retryMin
	}
	switch {
	case resp.status == http.StatusNotModified:
		r.setPlanErr(nil)
		return jitter(r.planEvery)
	case resp.status == http.StatusNoContent:
		r.mu.Lock()
		r.plan = nil
		r.st.PlanRaw, r.st.PlanSig, r.st.PlanKID, r.st.ETag = nil, "", "", ""
		r.planErr = ""
		r.mu.Unlock()
		r.saveState()
		return jitter(r.planEvery)
	case resp.status < 200 || resp.status > 299:
		e := apiError(resp)
		r.setPlanErr(e)
		if r.noteRevoked(e) {
			return jitter(r.planEvery)
		}
		if e.RetryAfter > 0 {
			return min(max(e.RetryAfter, r.retryMin), time.Hour)
		}
		if resp.status == http.StatusUnauthorized || resp.status == http.StatusForbidden {
			return jitter(r.planEvery)
		}
		return r.retryMin
	}
	var sp SignedPlan
	if err := unwrap(resp.body, &sp); err != nil {
		r.setPlanErr(err)
		return r.retryMin
	}
	now := r.now()
	p, err := verifyPlan(sp.Plan, sp.Sig, r.keys, nodeID, now)
	if err != nil {
		r.setPlanErr(fmt.Errorf("plan rejected: %w", err))
		r.log.Warn("sonar64: plan rejected", "err", err)
		return jitter(r.planEvery) // nicht jede Minute neu laden (Anker-Plaene sind gross)
	}
	newTag := resp.header.Get("ETag")
	if !etagRe.MatchString(newTag) {
		newTag = ""
	}
	ap := &activePlan{plan: *p, raw: append([]byte(nil), sp.Plan...), kid: cleanText(sp.KeyID, 16), sig: sp.Sig, etag: newTag, got: now}
	ap.validUntil, ap.anchorsUntil = window(p, now)
	r.mu.Lock()
	if r.plan != nil && p.Issued.Before(r.plan.plan.Issued) {
		r.mu.Unlock() // aelter als der vorhandene: nicht zurueckspringen (Wiederholung)
		return jitter(r.planEvery)
	}
	r.plan = ap
	r.planErr = ""
	if len(ap.raw) <= maxStoredPlan {
		r.st.PlanRaw, r.st.PlanSig, r.st.PlanKID, r.st.ETag, r.st.PlanGot = ap.raw, ap.sig, ap.kid, ap.etag, now
	} else {
		r.st.PlanRaw, r.st.PlanSig, r.st.PlanKID, r.st.ETag = nil, "", "", ""
	}
	r.mu.Unlock()
	r.saveState()
	r.log.Debug("sonar64: new plan", "rounds", len(p.Rounds), "valid_until", ap.validUntil.UTC())
	return jitter(r.planEvery)
}

// ---- Runden ----

func (r *Runner) measureLoop(ctx context.Context) {
	for {
		r.safe("round", func() { r.measureTick(ctx) })
		if sleepCtx(ctx, r.tick) != nil {
			return
		}
	}
}

// dueRound sucht die faellige Runde (Plan oder Anker-Rueckfall) und merkt sie als erledigt. Runden folgen mit
// mindestens einer Rundenlaenge Abstand aufeinander (auch ein Plan mit ueberlappenden Runden misst nicht oefter),
// die zuletzt gemessene steht im Zustand (nach Neustart nicht doppelt). r.mu gehalten.
func (r *Runner) dueRound(now time.Time) (start time.Time, targets []Target, anchorsOnly bool, ok bool) {
	p := r.plan
	if p == nil || !now.Before(p.anchorsUntil) {
		r.paused = "no_plan"
		return
	}
	last := r.st.LastRound
	if last > now.Add(r.roundLen).UnixMilli() {
		last = 0 // Uhr wurde zurueckgestellt
	}
	due := func(s time.Time) bool {
		return !now.Before(s) && now.Before(s.Add(r.roundLen)) && (last == 0 || s.UnixMilli() >= last+r.roundLen.Milliseconds())
	}
	if now.Before(p.validUntil) {
		for _, rd := range p.plan.Rounds {
			if due(rd.Start) {
				start, targets, ok = rd.Start, rd.Targets, true
				break
			}
		}
		if !ok && r.paused == "no_plan" {
			r.paused = ""
		}
	} else if s := now.UTC().Truncate(r.roundLen); due(s) {
		start, targets, anchorsOnly, ok = s, p.plan.Anchors, true, true
	}
	if ok {
		r.st.LastRound = start.UnixMilli()
	}
	return
}

// measureTick fuehrt eine faellige Runde aus (blockiert bis zu deren Ende).
func (r *Runner) measureTick(ctx context.Context) {
	now := r.now()
	lim := r.limits()
	r.mu.Lock()
	start, targets, anchorsOnly, ok := r.dueRound(now)
	prober := r.prober
	switch {
	case r.revoked:
		r.paused, ok = "revoked", false
	case !ok:
	case prober == nil:
		ok = false
	case inQuiet(r.cfg.Quiet, now.Local().Hour()):
		r.paused, ok = "quiet", false
	case r.pauseNext:
		r.pauseNext, r.paused, ok = false, "uplink", false
	case r.sentTodayLocked(now) >= lim.day:
		r.paused, ok = "budget", false
	default:
		r.paused = ""
	}
	self := r.st.NodeID
	r.mu.Unlock()
	if !ok {
		return
	}
	// Runde vermerken (Neustart misst sie nicht noch einmal); im Hintergrund, die Runde wartet nicht auf die Platte
	r.saves.Add(1)
	go func() {
		defer r.saves.Done()
		r.saveState()
	}()
	ts := roundTargets(targets, lim.targets, self, anchorsOnly)
	if len(ts) == 0 {
		return
	}
	results := r.runRound(ctx, prober, start, ts)
	// Selbstbremse: zu allen Ankern >= 80 % Verlust -> naechste Runde Pause.
	sent, recv := 0, 0
	for _, x := range results {
		if strings.HasPrefix(x.Target, "a_") && x.Method != MethodTrace && x.Sent > 0 {
			sent += x.Sent
			recv += x.Recv
		}
	}
	if sent > 0 {
		r.mu.Lock()
		r.uplink = float64(recv) > 0.2*float64(sent)
		r.pauseNext = !r.uplink
		r.mu.Unlock()
		if !r.uplink {
			r.log.Warn("sonar64: high loss to all anchors, pausing next round")
		}
	}
}

type job struct {
	at time.Time
	t  Target
}

// runRound verteilt die Messungen zufaellig in der Runde und fuehrt sie aus.
func (r *Runner) runRound(ctx context.Context, prober Prober, start time.Time, ts []Target) []Result {
	now := r.now()
	deadline := start.Add(r.roundLen)
	margin := min(30*time.Second, r.roundLen/10)
	win := deadline.Sub(now) - margin
	jobs := make([]job, len(ts))
	for i, t := range ts {
		var off time.Duration
		if win > 0 {
			off = time.Duration(rand.Int64N(int64(win)))
		}
		jobs[i] = job{at: now.Add(off), t: t}
	}
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].at.Before(jobs[j].at) })
	icmpOK := prober.ICMPAllowed()
	r.mu.Lock()
	r.icmpDenied = !icmpOK
	r.mu.Unlock()

	workers := 1
	if r.anchor {
		workers = maxWorkersAnchor
	}
	ch := make(chan job)
	out := make(chan Result, len(jobs))
	done := make(chan struct{})
	for range workers {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := range ch {
				r.safe("measure", func() {
					if res, ok := r.measureOne(ctx, prober, start, deadline, j.t, icmpOK); ok {
						out <- res
					}
				})
			}
		}()
	}
	for _, j := range jobs {
		if sleepCtx(ctx, j.at.Sub(r.now())) != nil {
			break
		}
		select {
		case ch <- j:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
	}
	close(ch)
	for range workers {
		<-done
	}
	close(out)
	var results []Result
	for x := range out {
		results = append(results, x)
	}
	return results
}

// measureOne prueft die Grenzen, misst ein Ziel und legt das Ergebnis ab.
func (r *Runner) measureOne(ctx context.Context, prober Prober, round, deadline time.Time, t Target, icmpOK bool) (Result, bool) {
	now := r.now()
	if !now.Before(deadline) || r.isRevoked() {
		return Result{}, false // zu spaet, Runde vorbei bzw. abgemeldet
	}
	// doppelt pruefen (auch wenn Plan und Prober pruefen)
	if _, ok := targetAddr(t); !ok || t.Count < 1 || t.Count > MaxCount || (t.Method == MethodTrace && (t.MaxTTL < 1 || t.MaxTTL > MaxTTL || t.Count > MaxTraceCount)) {
		return Result{}, false
	}
	base := Result{Round: round.UTC(), Target: t.ID, Family: t.Family, Method: t.Method, At: now.UTC()}
	if t.Method == MethodICMP && !icmpOK {
		base.Error = "denied"
		r.store(base)
		return base, true
	}
	n := packetsOf(t)
	lim := r.limits()
	r.mu.Lock()
	if t.Method == MethodTrace {
		keep := r.traces[:0]
		for _, x := range r.traces {
			if now.Sub(x) < time.Hour {
				keep = append(keep, x)
			}
		}
		r.traces = keep
		if len(r.traces) >= MaxTracesPerHour {
			r.mu.Unlock()
			base.Error = "budget"
			r.store(base)
			return base, true
		}
		r.traces = append(r.traces, now)
	}
	if r.sentTodayLocked(now)+n > lim.day {
		r.paused = "budget"
		r.mu.Unlock()
		base.Error = "budget"
		r.store(base)
		return base, true
	}
	r.st.SentToday += n
	r.mu.Unlock()

	if err := r.bucket.wait(ctx, n); err != nil {
		return Result{}, false
	}
	if !r.now().Before(deadline) {
		return Result{}, false
	}
	limit := 2 * time.Minute
	if t.Method == MethodTrace {
		limit = 3 * time.Minute
	}
	mctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	started := r.now()
	var res Result
	if t.Method == MethodTrace {
		res = prober.Trace(mctx, t, round)
	} else {
		res = prober.Ping(mctx, t, round)
	}
	res = cleanResult(res, base, n, started, r.now())
	r.store(res)
	return res, true
}

// cleanResult setzt die Felder, die der Kern kennt, und bringt Werte des Probers in sichere Grenzen.
func cleanResult(res, base Result, packets int, started, now time.Time) Result {
	res.Round, res.Target, res.Family, res.Method = base.Round, base.Target, base.Family, base.Method
	if res.At.IsZero() || res.At.Before(started.Add(-time.Second)) || res.At.After(now.Add(time.Second)) {
		res.At = started
	}
	res.At = res.At.UTC()
	res.Sent = min(max(res.Sent, 0), packets)
	res.Recv = min(max(res.Recv, 0), res.Sent)
	ms := func(v float64) float64 {
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > 60000 {
			return 0
		}
		return math.Round(v*1000) / 1000
	}
	res.MinMs, res.AvgMs, res.MaxMs, res.JitterMs = ms(res.MinMs), ms(res.AvgMs), ms(res.MaxMs), ms(res.JitterMs)
	if res.Recv > 0 && res.Method != MethodTrace && (res.MinMs <= 0 || res.AvgMs <= 0 || res.MaxMs <= 0) {
		// unbrauchbare Werte des Probers: als nicht gemessen melden (ipv64 wertete sie sonst als unplausibel)
		res.Sent, res.Recv = 0, 0
		if res.Error == "" {
			res.Error = "invalid"
		}
	}
	if res.Recv == 0 || res.Method == MethodTrace {
		res.MinMs, res.AvgMs, res.MaxMs, res.JitterMs = 0, 0, 0, 0
	} else {
		res.MinMs = min(res.MinMs, res.AvgMs)
		res.MaxMs = max(res.MaxMs, res.AvgMs)
		res.JitterMs = min(res.JitterMs, res.MaxMs-res.MinMs)
	}
	if res.Error != "" && !errCodeRe.MatchString(res.Error) {
		res.Error = "error"
	}
	if res.Method != MethodTrace {
		res.Hops = nil
	} else {
		in := append([]Hop(nil), res.Hops...)
		sort.SliceStable(in, func(i, j int) bool { return in[i].TTL < in[j].TTL })
		hops := make([]Hop, 0, min(len(in), MaxTTL))
		for _, h := range in {
			if len(hops) >= MaxTTL {
				break
			}
			if h.TTL < 1 || h.TTL > MaxTTL || (len(hops) > 0 && hops[len(hops)-1].TTL == h.TTL) {
				continue // ipv64 verlangt streng steigende TTL
			}
			h.RTTMs = ms(h.RTTMs)
			if a, err := netip.ParseAddr(h.Addr); err != nil || !isPublicAddr(a) {
				h.Addr = "" // private Hops (eigenes Heimnetz) nie melden
			} else {
				h.Addr = a.String()
			}
			hops = append(hops, h)
		}
		res.Hops = hops
	}
	return res
}

// store legt ein Ergebnis in Puffer und Recent ab (abgemeldet bzw. nach Leave: verwerfen).
func (r *Runner) store(res Result) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.revoked || r.left {
		return
	}
	if len(r.buf) >= maxBuffered {
		r.buf = r.buf[1:]
		r.bufOff++
	}
	r.buf = append(r.buf, res)
	r.recent = append(r.recent, res)
	if len(r.recent) > 2*recentMax {
		r.recent = append(r.recent[:0:0], r.recent[len(r.recent)-recentMax:]...)
	}
}

// ---- Meldung ----

func (r *Runner) reportLoop(ctx context.Context) {
	// erste Meldung bald, verteilt
	if sleepCtx(ctx, time.Duration(rand.Int64N(int64(r.reportEvery)/10+1))) != nil {
		return
	}
	for {
		next := jitter(r.reportEvery)
		r.safe("report", func() {
			more, retry := r.report(ctx)
			switch {
			case retry > 0:
				next = retry
			case more:
				next = r.reportGap
			}
		})
		if sleepCtx(ctx, max(next, r.reportGap)) != nil {
			return
		}
	}
}

// reportAnswer ist die Antwort auf POST /sonar/results.
type reportAnswer struct {
	Accepted int            `json:"accepted"`
	Rejected int            `json:"rejected"`
	Reasons  map[string]int `json:"reasons"`
}

// report schickt eine Meldung. more = noch Ergebnisse im Puffer, retry = Wartezeit vom Server (429).
func (r *Runner) report(ctx context.Context) (more bool, retry time.Duration) {
	r.drainResponder()
	now := r.now()
	r.mu.Lock()
	if !r.registered || r.revoked || r.left {
		r.mu.Unlock()
		return false, 0
	}
	cut := now.Add(-BufferFor)
	i := 0
	for i < len(r.buf) && r.buf[i].At.Before(cut) {
		i++
	}
	r.buf, r.bufOff = r.buf[i:], r.bufOff+uint64(i)
	j := 0
	for j < len(r.inbuf) && r.inbuf[j].At.Before(cut) {
		j++
	}
	r.inbuf, r.inOff = r.inbuf[j:], r.inOff+uint64(j)
	if r.anchor && len(r.buf) == 0 && len(r.inbuf) == 0 && now.Sub(r.lastReport) < r.heartbeat {
		r.mu.Unlock() // Anker melden jede Minute nur, wenn etwas zu melden ist (Health spaetestens nach heartbeat)
		return false, 0
	}
	nRes := min(len(r.buf), 1000)
	nIn := min(len(r.inbuf), maxInboundRows)
	resAt, inAt := r.bufOff, r.inOff
	results := append([]Result{}, r.buf[:nRes]...)
	inbound := append([]Inbound(nil), r.inbuf[:nIn]...)
	r.inSending = inAt + uint64(nIn)
	seq := max(r.st.Seq+1, uint64(max(now.UnixMilli(), 0)))
	r.st.Seq = seq
	paused := r.paused
	if paused == "" && r.plan == nil {
		paused = "no_plan"
	}
	h := Health{Version: r.cfg.Version, Mode: r.cfg.Mode, Uplink: r.uplink, Paused: paused,
		SentToday: r.sentTodayLocked(now), Budget: r.budget, Responder: r.responderOn, ICMPDenied: r.icmpDenied}
	rep := Report{V: ProtoVersion, NodeID: r.st.NodeID, Seq: seq, Sent: now.UTC(), Health: h}
	r.mu.Unlock()
	r.saveState() // Seq vor dem Senden sichern

	var raw []byte
	for {
		rep.Results, rep.Inbound = results, inbound
		b, err := json.Marshal(rep)
		if err != nil {
			r.mu.Lock()
			r.inSending = 0
			r.mu.Unlock()
			r.setErr(err)
			return false, 0
		}
		if len(b) <= maxBody-256 || (len(results) == 0 && len(inbound) == 0) {
			raw = b
			break
		}
		results, inbound = results[:len(results)/2], inbound[:len(inbound)/2]
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(r.key, raw))
	body := make([]byte, 0, len(raw)+120)
	body = append(body, `{"report":`...)
	body = append(body, raw...)
	body = append(body, `,"sig":"`...)
	body = append(body, sig...)
	body = append(body, `"}`...)
	// Eine laufende Meldung nicht beim Beenden abbrechen (sonst kaeme sie doppelt), aber kurz halten.
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	resp, err := r.api.send(sctx, http.MethodPost, "/sonar/results", r.cfg.Token, nil, body, smallLimit)
	if err != nil {
		r.mu.Lock()
		r.inSending = 0
		r.mu.Unlock()
		r.setErr(err)
		return false, 0
	}
	drop := false
	switch {
	case resp.status >= 200 && resp.status <= 299:
		var a reportAnswer
		if unwrap(resp.body, &a) == nil && a.Rejected > 0 {
			r.log.Info("sonar64: results rejected by ipv64", "accepted", a.Accepted, "rejected", a.Rejected, "reasons", reasonsText(a.Reasons))
		}
		drop = true
		r.mu.Lock()
		r.lastReport, r.lastErr = now, ""
		r.mu.Unlock()
	case resp.status == http.StatusBadRequest || resp.status == http.StatusRequestEntityTooLarge || resp.status == http.StatusUnprocessableEntity:
		e := apiError(resp)
		r.setErr(e)
		r.log.Warn("sonar64: report refused, dropping it", "err", e.Error())
		drop = true
	default:
		e := apiError(resp)
		r.setErr(e)
		r.noteRevoked(e) // verwirft auch den Puffer
		if e.RetryAfter > 0 {
			retry = min(max(e.RetryAfter, r.reportGap), time.Hour)
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inSending = 0
	if drop {
		k := dropCount(r.bufOff, resAt, len(rep.Results), len(r.buf))
		r.buf, r.bufOff = r.buf[k:], r.bufOff+uint64(k)
		k = dropCount(r.inOff, inAt, len(rep.Inbound), len(r.inbuf))
		r.inbuf, r.inOff = r.inbuf[k:], r.inOff+uint64(k)
	}
	return drop && (len(r.buf) > 0 || len(r.inbuf) > 0), retry
}

// dropCount: wie viele Eintraege vorne im Puffer (Beginn off) zur Meldung ab Position at mit n Eintraegen gehoeren
// (vorne kann inzwischen schon verworfen worden sein).
func dropCount(off, at uint64, n, have int) int {
	end := at + uint64(n)
	if end <= off {
		return 0
	}
	return int(min(end-off, uint64(have)))
}

func reasonsText(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		if len(keys) >= 10 {
			break
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%d ", cleanText(k, 20), m[k])
	}
	return strings.TrimSpace(b.String())
}

// ---- Antworter UDP 6464 ----

var shortRe = regexp.MustCompile(`^[0-9a-f]{8}$`)

func (r *Runner) wantResponder() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return !r.revoked && !r.left && (r.anchor || r.measured)
}

// respRun ist ein laufender Antworter.
type respRun struct {
	cancel context.CancelFunc
	done   chan struct{}
}

func (r *Runner) responderLoop(ctx context.Context) {
	var cur *respRun
	stop := func() {
		if cur == nil {
			return
		}
		cur.cancel()
		<-cur.done
		cur = nil
		r.drainResponder()
		r.mu.Lock()
		r.responder, r.responderOn = nil, false
		r.mu.Unlock()
	}
	defer stop()
	for {
		want := r.wantResponder()
		if !want {
			stop()
		}
		if want && cur == nil {
			r.mu.Lock()
			id := r.st.NodeID
			r.mu.Unlock()
			resp, err := openResponder("", id)
			if err != nil {
				r.setErr(fmt.Errorf("UDP %d: %w", Port, err))
				r.log.Warn("sonar64: responder not started", "err", errText(err))
			} else {
				cur = &respRun{done: make(chan struct{})}
				var rctx context.Context
				rctx, cur.cancel = context.WithCancel(ctx)
				r.mu.Lock()
				r.responder, r.responderOn = resp, true
				r.mu.Unlock()
				go func(ch chan struct{}) {
					defer close(ch)
					r.safe("responder", func() {
						if err := resp.Run(rctx); err != nil && rctx.Err() == nil {
							r.setErr(fmt.Errorf("UDP %d: %w", Port, err))
						}
					})
				}(cur.done)
			}
		}
		var ended chan struct{} // nil = blockiert nie
		if cur != nil {
			ended = cur.done
		}
		t := time.NewTimer(5 * time.Minute)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-r.wake:
		case <-ended: // von selbst beendet: aufraeumen, spaeter neu versuchen
			stop()
			if sleepCtx(ctx, r.retryMin) != nil {
				t.Stop()
				return
			}
		case <-t.C:
		}
		t.Stop()
	}
}

// drainResponder holt die beantworteten Proben in Puffer und Recent.
func (r *Runner) drainResponder() {
	r.mu.Lock()
	resp := r.responder
	r.mu.Unlock()
	if resp == nil {
		return
	}
	var got []Inbound
	r.safe("drain", func() { got = resp.Drain() })
	if len(got) == 0 {
		return
	}
	now := r.now().UTC()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, x := range got {
		if !shortRe.MatchString(x.From) || (x.Family != 4 && x.Family != 6) || x.Count < 1 {
			continue
		}
		x.Count = min(x.Count, 1000000)
		if x.At.IsZero() || x.At.After(now.Add(time.Minute)) {
			x.At = now
		}
		x.At = x.At.UTC()
		r.recentIn = append(r.recentIn, x)
		if r.revoked || r.left || r.mergeInbound(x) { // abgemeldet: nichts mehr melden
			continue
		}
		if len(r.inbuf) >= maxInboundBuf {
			r.inbuf = r.inbuf[1:]
			r.inOff++
		}
		r.inbuf = append(r.inbuf, x)
	}
	if len(r.recentIn) > 2*recentMax {
		r.recentIn = append(r.recentIn[:0:0], r.recentIn[len(r.recentIn)-recentMax:]...)
	}
}

// mergeInbound fasst x mit einem noch nicht gemeldeten Eintrag derselben Quelle, Familie und 5-Minuten-Spanne
// zusammen (Recent fragt den Antworter alle paar Sekunden ab; die Meldung bleibt trotzdem klein). r.mu gehalten.
func (r *Runner) mergeInbound(x Inbound) bool {
	slot := x.At.Truncate(RoundInterval)
	for i := len(r.inbuf) - 1; i >= 0 && i >= len(r.inbuf)-64; i-- {
		if r.inOff+uint64(i) < r.inSending {
			return false // gehoert zu einer laufenden Meldung
		}
		e := &r.inbuf[i]
		if e.From == x.From && e.Family == x.Family && e.At.Truncate(RoundInterval).Equal(slot) {
			e.Count = min(e.Count+x.Count, 1000000)
			if x.At.After(e.At) {
				e.At = x.At
			}
			return true
		}
	}
	return false
}
