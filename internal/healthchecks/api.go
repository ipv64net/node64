package healthchecks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/scheduler"
)

var locationRe = regexp.MustCompile(`^[a-z0-9]{2,16}$`)

var tokenRe = regexp.MustCompile(`^[A-Za-z0-9]{32}$`)

// ---------------------------------------------------------------- JSON-Darstellung

// checkJSON ist die API-Darstellung eines Checks (Ein- und Ausgabe).
type checkJSON struct {
	Token                 string          `json:"token,omitempty"`
	Name                  string          `json:"name"`
	Type                  string          `json:"type"`
	Target                string          `json:"target"`
	Params                json.RawMessage `json:"params,omitempty"`
	IntervalSeconds       *int            `json:"interval_seconds,omitempty"`
	RetryIntervalSeconds  *int            `json:"retry_interval_seconds,omitempty"`
	Retries               *int            `json:"retries,omitempty"`
	ConnectTimeoutSeconds *float64        `json:"connect_timeout_seconds,omitempty"`
	TimeoutSeconds        *float64        `json:"timeout_seconds,omitempty"`
	Invert                *bool           `json:"invert,omitempty"`
	Stabilize             *int            `json:"stabilize,omitempty"`
	IPMode                string          `json:"ip_mode,omitempty"`
	Tags                  []string        `json:"tags"`
	Group                 *string         `json:"group,omitempty"`
	Description           string          `json:"description"`
	Paused                *bool           `json:"paused,omitempty"`
	Parent                *string         `json:"parent,omitempty"`
	Critical              *bool           `json:"critical,omitempty"`
	Execution             string          `json:"execution,omitempty"`
	Owner                 string          `json:"owner,omitempty"` // self, online, other (nur Ausgabe)
	Policy                string          `json:"policy,omitempty"`
	Locations             []string        `json:"locations"`
	Nodes                 []string        `json:"nodes,omitempty"` // messende Nodes (verknuepft, local/both)
	NotifyDegraded        *bool           `json:"notify_degraded,omitempty"`
	NotifyDown            *bool           `json:"notify_down,omitempty"`
	NotifyUp              *bool           `json:"notify_up,omitempty"`
	Channels              []int64         `json:"channels"`
	RepeatMinutes         *int            `json:"repeat_minutes,omitempty"`
	Revision              int64           `json:"revision,omitempty"`
	CreatedAt             *time.Time      `json:"created_at,omitempty"`
	UpdatedAt             *time.Time      `json:"updated_at,omitempty"`
	PushURL               string          `json:"push_url,omitempty"`
	State                 *stateJSON      `json:"state,omitempty"`
}

type stateJSON struct {
	State           string    `json:"state"`
	Since           time.Time `json:"since"`
	LastCheckAt     time.Time `json:"last_check_at"`
	NextCheckAt     time.Time `json:"next_check_at"`
	LastStatus      string    `json:"last_status"`
	LastLatencyMS   float64   `json:"last_latency_ms"`
	LastReason      string    `json:"last_reason"`
	LastMessage     string    `json:"last_message"`
	ConsecutiveFail int       `json:"consecutive_fail"`
	ConsecutiveOK   int       `json:"consecutive_ok"`
	LastPushAt      time.Time `json:"last_push_at"`
	DownSince       time.Time `json:"down_since"`
	IncidentID      int64     `json:"incident_id,omitempty"`
	Maintenance     bool      `json:"maintenance"`
	// Unchecked: seit 3 Intervallen (mind. 5 min) nicht gemessen; state ist dann der Zustand der letzten Messung
	Unchecked bool `json:"unchecked,omitempty"`
}

func (m *Module) toJSON(c *Check, r *http.Request) checkJSON {
	iv, riv, re, st, rp := int(c.Interval.Seconds()), int(c.RetryInterval.Seconds()), c.Retries, c.Stabilize, c.RepeatMinutes
	ct, tt := c.ConnectTimeout.Seconds(), c.TotalTimeout.Seconds()
	inv, pa, cr, nd, nu, ndeg := c.Invert, c.Paused, c.Critical, c.NotifyDown, c.NotifyUp, c.NotifyDegraded
	parent := c.Parent
	created, updated := c.CreatedAt, c.UpdatedAt
	rt := c.Runtime
	if s := m.scheduler(); s != nil {
		if live, ok := s.Runtime(c.Token); ok {
			rt = live
		}
	}
	out := checkJSON{Token: c.Token, Name: c.Name, Type: string(c.Type), Target: c.Target, Params: c.Params,
		IntervalSeconds: &iv, RetryIntervalSeconds: &riv, Retries: &re, ConnectTimeoutSeconds: &ct, TimeoutSeconds: &tt,
		Invert: &inv, Stabilize: &st, IPMode: string(c.IPMode), Tags: c.Tags, Group: &c.Group, Description: c.Description, Paused: &pa, Parent: &parent,
		Critical: &cr, Execution: c.Execution, Owner: c.Owner, Policy: c.Policy, Locations: c.Locations, Nodes: c.Nodes, NotifyDegraded: &ndeg,
		NotifyDown: &nd, NotifyUp: &nu, Channels: c.Channels, RepeatMinutes: &rp,
		Revision: c.Revision, CreatedAt: &created, UpdatedAt: &updated,
		State: &stateJSON{State: string(rt.State), Since: rt.Since, LastCheckAt: rt.LastCheck, NextCheckAt: rt.NextCheck, LastStatus: string(rt.LastStatus),
			LastLatencyMS: msf(rt.LastLatency), LastReason: string(rt.LastReason), LastMessage: rt.LastMessage, ConsecutiveFail: rt.ConsecutiveFail,
			ConsecutiveOK: rt.ConsecutiveOK, LastPushAt: rt.LastPush, DownSince: rt.DownSince, IncidentID: rt.Incident,
			Maintenance: m.st.InMaintenance(r.Context(), c.Token, time.Now())}}
	out.State.Unchecked = stale(c, rt.LastCheck, string(rt.State))
	if out.Tags == nil {
		out.Tags = []string{}
	}
	if out.Channels == nil {
		out.Channels = []int64{}
	}
	if out.Locations == nil {
		out.Locations = []string{}
	}
	if c.Type == checks.TypePush {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		out.PushURL = scheme + "://" + r.Host + "/api/push/" + c.Token
	}
	return out
}

// splitPort: Port aus dem Ziel (host:port) ins Port-Feld, nur fuer Eingaben aus Formular und API.
func splitPort(c *Check, in *checkJSON) error {
	params := in.Params
	if len(params) == 0 {
		params = c.Params
	}
	t, p, err := checks.SplitTargetPort(checks.Type(strings.ToLower(strings.TrimSpace(in.Type))), in.Target, params)
	if err != nil {
		return err
	}
	if t != in.Target {
		in.Target, in.Params = t, p
	}
	return nil
}

// apply uebertraegt Eingaben auf einen Check und prueft sie.
func (m *Module) apply(c *Check, in checkJSON, create bool) error {
	if create {
		c.Interval, c.RetryInterval, c.Retries, c.Stabilize = checks.DefaultInterval, 20*time.Second, 1, 3
		c.ConnectTimeout, c.TotalTimeout = checks.DefaultConnectTimeout, checks.DefaultTotalTimeout
		c.IPMode, c.Execution, c.NotifyDown, c.NotifyUp = checks.IPAuto, "local", true, true
		c.Policy = PolicyAll
	}
	c.Name = strings.TrimSpace(in.Name)
	if c.Name == "" || len(c.Name) > 200 {
		return errors.New("name is required (max 200 characters)")
	}
	c.Type = checks.Type(strings.ToLower(strings.TrimSpace(in.Type)))
	c.Target = strings.TrimSpace(in.Target)
	if len(in.Params) > 0 {
		var tmp any
		if err := json.Unmarshal(in.Params, &tmp); err != nil {
			return fmt.Errorf("params: %w", err)
		}
		c.Params = in.Params
	} else if create {
		c.Params = json.RawMessage("{}")
	}
	if in.IntervalSeconds != nil {
		c.Interval = time.Duration(*in.IntervalSeconds) * time.Second
	}
	if in.RetryIntervalSeconds != nil {
		c.RetryInterval = time.Duration(*in.RetryIntervalSeconds) * time.Second
	}
	if in.Retries != nil {
		c.Retries = *in.Retries
	}
	if in.ConnectTimeoutSeconds != nil {
		c.ConnectTimeout = time.Duration(*in.ConnectTimeoutSeconds * float64(time.Second))
	}
	if in.TimeoutSeconds != nil {
		c.TotalTimeout = time.Duration(*in.TimeoutSeconds * float64(time.Second))
	}
	if in.Invert != nil {
		c.Invert = *in.Invert
	}
	if in.Stabilize != nil {
		c.Stabilize = *in.Stabilize
	}
	if in.IPMode != "" {
		c.IPMode = checks.IPMode(in.IPMode)
	}
	if in.Tags != nil {
		c.Tags = nil
		for _, t := range in.Tags {
			if t = strings.TrimSpace(t); t != "" && !strings.Contains(t, ",") {
				c.Tags = append(c.Tags, t)
			}
		}
	}
	if in.Group != nil {
		g := strings.TrimSpace(*in.Group)
		if len([]rune(g)) > 100 {
			g = string([]rune(g)[:100])
		}
		c.Group = g
	}
	c.Description = strings.TrimSpace(in.Description)
	if in.Paused != nil {
		c.Paused = *in.Paused
	}
	if in.Parent != nil {
		c.Parent = strings.TrimSpace(*in.Parent)
	}
	if in.Critical != nil {
		c.Critical = *in.Critical
	}
	if in.NotifyDown != nil {
		c.NotifyDown = *in.NotifyDown
	}
	if in.NotifyUp != nil {
		c.NotifyUp = *in.NotifyUp
	}
	if in.Channels != nil {
		c.Channels = in.Channels
	}
	if in.RepeatMinutes != nil {
		c.RepeatMinutes = *in.RepeatMinutes
	}
	if in.Execution != "" {
		switch in.Execution {
		case "local":
		case "online", "both":
			if singleNode(c.Type) {
				return errors.New("execution: " + string(c.Type) + " checks run only locally on this node")
			}
			if !m.onlineOK() {
				return errors.New("execution: online and hybrid need the ipv64 link")
			}
			if c.Type != checks.TypePush && checks.IsPrivateTarget(string(c.Type), c.Target) {
				return errors.New("execution: ipv64 cannot check private targets (home network, localhost, .local) from outside – keep this check local")
			}
			if c.Type == checks.TypeDNS && checks.DNSNeedsNode(c.Params) {
				return errors.New("execution: a DNS check against a private DNS server or the node's public address runs only locally")
			}
			if err := m.checkOnlineLimit(c, in.Locations); err != nil {
				return err
			}
		default:
			return errors.New("execution must be local, online or both")
		}
		c.Execution = in.Execution
	}
	if in.Policy != "" {
		c.Policy = strings.ToLower(strings.TrimSpace(in.Policy))
	}
	if !ValidPolicy(c.Policy) {
		return errors.New("policy must be all, any or majority")
	}
	if in.Locations != nil {
		c.Locations = nil
		for _, l := range in.Locations {
			if l = strings.ToLower(strings.TrimSpace(l)); l != "" {
				if !locationRe.MatchString(l) {
					return errors.New("locations: use short codes like nbg")
				}
				c.Locations = append(c.Locations, l)
			}
		}
	}
	prevNodes := c.Nodes
	if in.Nodes != nil {
		list, ok := cleanNodes(in.Nodes)
		if !ok {
			return errors.New("nodes: invalid node id")
		}
		c.Nodes = list
	}
	switch {
	case c.Execution == "online":
		c.Nodes = nil // online: keine Nodes
	case singleNode(c.Type):
		c.Nodes = m.clusterNodesOf(c, prevNodes) // Docker/Proxmox: nur die Besitzer-Node, im Cluster auch Nodes mit dem Bereich
	}
	if in.NotifyDegraded != nil {
		c.NotifyDegraded = *in.NotifyDegraded
	}
	// Grenzen
	if c.Type != checks.TypePush {
		minIv := checks.MinInterval
		if c.Execution == "local" || c.Execution == "" {
			minIv = checks.MinIntervalLocal
		}
		if c.Interval < minIv || c.Interval > 24*time.Hour {
			return fmt.Errorf("interval_seconds must be between %d and 86400 (5 only local, 20 online/hybrid)", int(minIv.Seconds()))
		}
		if c.Type == checks.TypeWhois && c.Interval < checks.MinIntervalWhois {
			return fmt.Errorf("interval_seconds must be at least %d for whois checks (WHOIS/RDAP servers limit queries)", int(checks.MinIntervalWhois.Seconds()))
		}
		if c.Type == checks.TypeWhois && c.RetryInterval < checks.MinRetryWhois {
			c.RetryInterval = checks.MinRetryWhois // auch im gestoerten Zustand nicht oefter fragen
		}
		if c.RetryInterval > c.Interval {
			c.RetryInterval = c.Interval // z. B. Standard 20 s bei einem lokalen 5-s-Check
		}
		if c.RetryInterval < 5*time.Second {
			return errors.New("retry_interval_seconds must be between 5 and interval_seconds")
		}
	}
	if c.Retries < 0 || c.Retries > 10 {
		return errors.New("retries must be between 0 and 10")
	}
	if c.Stabilize < 1 || c.Stabilize > 20 {
		return errors.New("stabilize must be between 1 and 20")
	}
	if c.ConnectTimeout < 500*time.Millisecond || c.ConnectTimeout > 60*time.Second {
		return errors.New("connect_timeout_seconds must be between 0.5 and 60")
	}
	if c.TotalTimeout < c.ConnectTimeout || c.TotalTimeout > 120*time.Second {
		return errors.New("timeout_seconds must be between connect_timeout_seconds and 120")
	}
	if c.RepeatMinutes < 0 || c.RepeatMinutes > 10080 { // wie im Portal: hoechstens eine Woche
		return errors.New("repeat_minutes must be between 0 and 10080")
	}
	if len(c.Description) > 2000 {
		return errors.New("description too long")
	}
	if c.Parent != "" && (!tokenRe.MatchString(c.Parent) || c.Parent == c.Token) {
		return errors.New("parent must be the token of another check")
	}
	return checks.Validate(c.Definition())
}

// parentCycle prueft, ob parent (transitiv) auf token zurueckfuehrt.
func (m *Module) parentCycle(r *http.Request, token, parent string) (bool, error) {
	seen := map[string]bool{token: true}
	for parent != "" {
		if seen[parent] {
			return true, nil
		}
		seen[parent] = true
		p, err := m.st.Check(r.Context(), parent)
		if err != nil {
			return false, err
		}
		if p == nil {
			return false, errors.New("parent check not found")
		}
		parent = p.Parent
	}
	return false, nil
}

// ---------------------------------------------------------------- Handler

type apiError struct {
	Error string `json:"error"`
	Field string `json:"field,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, apiError{Error: msg})
}

func readJSON(r *http.Request, v any) error {
	b, err := io.ReadAll(io.LimitReader(r.Body, 256<<10))
	if err != nil {
		return err
	}
	if len(b) == 0 {
		return errors.New("empty body")
	}
	return json.Unmarshal(b, v)
}

// actor: angemeldeter Benutzer (Sitzung oder API-Key) fuer Audit und "geaendert von".
func (m *Module) actor(r *http.Request) string {
	if m.g.Actor != nil {
		if a := m.g.Actor(r); a != "" && a != "-" {
			return a
		}
	}
	return "api"
}

func (m *Module) load(w http.ResponseWriter, r *http.Request) *Check {
	token := r.PathValue("token")
	if !tokenRe.MatchString(token) {
		writeErr(w, http.StatusNotFound, "check not found")
		return nil
	}
	c, err := m.st.Check(r.Context(), token)
	if err != nil {
		m.log.Error("load check", "err", err)
		writeErr(w, http.StatusInternalServerError, "database error")
		return nil
	}
	if c == nil {
		writeErr(w, http.StatusNotFound, "check not found")
		return nil
	}
	return c
}

func (m *Module) apiList(w http.ResponseWriter, r *http.Request) {
	list, err := m.st.Checks(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	q := r.URL.Query()
	out := make([]checkJSON, 0, len(list))
	for _, c := range list {
		j := m.toJSON(c, r)
		if t := q.Get("type"); t != "" && j.Type != t {
			continue
		}
		if s := q.Get("state"); s != "" && j.State.State != s {
			continue
		}
		if tag := q.Get("tag"); tag != "" && !contains(j.Tags, tag) {
			continue
		}
		if s := strings.ToLower(q.Get("q")); s != "" && !strings.Contains(strings.ToLower(j.Name+" "+j.Target+" "+strings.Join(j.Tags, " ")), s) {
			continue
		}
		out = append(out, j)
	}
	writeJSON(w, http.StatusOK, out)
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func (m *Module) apiGet(w http.ResponseWriter, r *http.Request) {
	if c := m.load(w, r); c != nil {
		writeJSON(w, http.StatusOK, m.toJSON(c, r))
	}
}

func (m *Module) apiCreate(w http.ResponseWriter, r *http.Request) {
	var in checkJSON
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	c := &Check{Token: NewToken(), UpdatedBy: m.actor(r)}
	if err := splitPort(c, &in); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err := m.apply(c, in, true); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if c.Parent != "" {
		if cyc, err := m.parentCycle(r, c.Token, c.Parent); err != nil || cyc {
			writeErr(w, http.StatusUnprocessableEntity, "parent: "+errText(err, "would create a cycle"))
			return
		}
	}
	if err := m.st.Insert(r.Context(), c); err != nil {
		m.log.Error("insert check", "err", err)
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	c, _ = m.st.Check(r.Context(), c.Token)
	if s := m.scheduler(); s != nil {
		upsertSched(s, c, nil)
	}
	m.audit(r, "check.create", c)
	writeJSON(w, http.StatusCreated, m.toJSON(c, r))
}

func errText(err error, def string) string {
	if err != nil {
		return err.Error()
	}
	return def
}

func (m *Module) apiUpdate(w http.ResponseWriter, r *http.Request) {
	c := m.load(w, r)
	if c == nil {
		return
	}
	var in checkJSON
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	oldType := c.Type
	c.UpdatedBy = m.actor(r)
	if err := splitPort(c, &in); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err := m.apply(c, in, false); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if c.Parent != "" {
		if cyc, err := m.parentCycle(r, c.Token, c.Parent); err != nil || cyc {
			writeErr(w, http.StatusUnprocessableEntity, "parent: "+errText(err, "would create a cycle"))
			return
		}
	}
	if err := m.st.Update(r.Context(), c); err != nil {
		m.log.Error("update check", "err", err)
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	if s := m.scheduler(); s != nil {
		var rt *scheduler.Runtime
		if oldType == c.Type {
			if live, ok := s.Runtime(c.Token); ok {
				rt = &live
			}
		}
		upsertSched(s, c, rt)
	}
	m.audit(r, "check.update", c)
	c, _ = m.st.Check(r.Context(), c.Token)
	writeJSON(w, http.StatusOK, m.toJSON(c, r))
}

func (m *Module) apiDelete(w http.ResponseWriter, r *http.Request) {
	c := m.load(w, r)
	if c == nil {
		return
	}
	if s := m.scheduler(); s != nil {
		s.Remove(c.Token)
	}
	if err := m.st.Delete(r.Context(), c.Token); err != nil {
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	m.audit(r, "check.delete", c)
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) setPaused(w http.ResponseWriter, r *http.Request, paused bool) {
	c := m.load(w, r)
	if c == nil {
		return
	}
	if err := m.st.SetPaused(r.Context(), c.Token, paused, m.actor(r)); err != nil {
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	c, _ = m.st.Check(r.Context(), c.Token)
	if s := m.scheduler(); s != nil {
		upsertSched(s, c, nil)
	}
	m.PushState(c.Token)
	m.audit(r, map[bool]string{true: "check.pause", false: "check.resume"}[paused], c)
	writeJSON(w, http.StatusOK, m.toJSON(c, r))
}

func (m *Module) apiPause(w http.ResponseWriter, r *http.Request)  { m.setPaused(w, r, true) }
func (m *Module) apiResume(w http.ResponseWriter, r *http.Request) { m.setPaused(w, r, false) }

func (m *Module) apiRun(w http.ResponseWriter, r *http.Request) {
	c := m.load(w, r)
	if c == nil {
		return
	}
	if c.Type == checks.TypePush {
		writeErr(w, http.StatusConflict, "push checks cannot be run manually")
		return
	}
	if !c.Runnable() {
		writeErr(w, http.StatusConflict, "measured by ipv64 only; online checks run on their interval")
		return
	}
	if err := m.runNow(c); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	m.audit(r, "check.run", c)
	w.WriteHeader(http.StatusAccepted)
}

func (m *Module) apiClone(w http.ResponseWriter, r *http.Request) {
	c := m.load(w, r)
	if c == nil {
		return
	}
	n := *c
	n.Token = NewToken()
	n.Name = c.Name + " (copy)"
	n.Paused = true
	n.Revision = 0
	n.UpdatedBy = m.actor(r)
	n.Runtime = scheduler.Runtime{}
	if c.Owner == "other" {
		n.Execution = "local" // wie in der Oberflaeche: die Kopie gehoert dieser Node
	}
	n.Owner = "self"
	if err := m.st.Insert(r.Context(), &n); err != nil {
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	nc, _ := m.st.Check(r.Context(), n.Token)
	if s := m.scheduler(); s != nil {
		upsertSched(s, nc, nil)
	}
	m.audit(r, "check.clone", nc)
	writeJSON(w, http.StatusCreated, m.toJSON(nc, r))
}

func (m *Module) apiMeasurements(w http.ResponseWriter, r *http.Request) {
	c := m.load(w, r)
	if c == nil {
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	from, to := parseTime(q.Get("from")), parseTime(q.Get("to"))
	list, err := m.st.Measurements(r.Context(), c.Token, from, to, limit, before)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	if list == nil {
		list = []Measurement{}
	}
	writeJSON(w, http.StatusOK, list)
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func (m *Module) apiEvents(w http.ResponseWriter, r *http.Request) {
	c := m.load(w, r)
	if c == nil {
		return
	}
	m.events(w, r, c.Token)
}

func (m *Module) apiAllEvents(w http.ResponseWriter, r *http.Request) { m.events(w, r, "") }

func (m *Module) events(w http.ResponseWriter, r *http.Request, token string) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	list, err := m.st.Events(r.Context(), token, limit, before)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	if list == nil {
		list = []Event{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (m *Module) apiIncidents(w http.ResponseWriter, r *http.Request) {
	c := m.load(w, r)
	if c == nil {
		return
	}
	m.incidents(w, r, c.Token)
}

func (m *Module) apiAllIncidents(w http.ResponseWriter, r *http.Request) { m.incidents(w, r, "") }

func (m *Module) incidents(w http.ResponseWriter, r *http.Request, token string) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	list, err := m.st.Incidents(r.Context(), token, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	if list == nil {
		list = []Incident{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (m *Module) apiStats(w http.ResponseWriter, r *http.Request) {
	c := m.load(w, r)
	if c == nil {
		return
	}
	rng := r.URL.Query().Get("range")
	if rng == "" {
		rng = "24h"
	}
	st, err := m.st.Stats(r.Context(), c.Token, rng, time.Now().UTC())
	if err != nil {
		if _, ok := ranges[rng]; !ok {
			writeErr(w, http.StatusBadRequest, "range must be one of 1h, 24h, 7d, 30d, 1y")
			return
		}
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (m *Module) apiTypes(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, checks.Types)
}

// ---------------------------------------------------------------- Wartungsfenster

type maintenanceIn struct {
	Name        string   `json:"name"`
	StartAt     string   `json:"start_at"`
	EndAt       string   `json:"end_at"`
	Repeat      string   `json:"repeat"`
	RepeatUntil string   `json:"repeat_until"`
	Tokens      []string `json:"tokens"`
	Active      *bool    `json:"active"`
}

func (m *Module) maintenanceFrom(in maintenanceIn, mw *Maintenance) error {
	mw.Name = strings.TrimSpace(in.Name)
	if mw.Name == "" || len(mw.Name) > 200 {
		return errors.New("name is required")
	}
	st, err := time.Parse(time.RFC3339, in.StartAt)
	if err != nil {
		return errors.New("start_at must be RFC 3339")
	}
	en, err := time.Parse(time.RFC3339, in.EndAt)
	if err != nil {
		return errors.New("end_at must be RFC 3339")
	}
	if !en.After(st) {
		return errors.New("end_at must be after start_at")
	}
	if en.Sub(st) > 30*24*time.Hour {
		return errors.New("a window may last at most 30 days")
	}
	mw.StartAt, mw.EndAt = st.UTC(), en.UTC()
	switch in.Repeat {
	case "", "none":
		mw.Repeat = "none"
	case "daily", "weekly", "monthly":
		mw.Repeat = in.Repeat
	default:
		return errors.New("repeat must be none, daily, weekly or monthly")
	}
	mw.RepeatUntil = time.Time{}
	if in.RepeatUntil != "" {
		u, err := time.Parse(time.RFC3339, in.RepeatUntil)
		if err != nil {
			return errors.New("repeat_until must be RFC 3339")
		}
		mw.RepeatUntil = u.UTC()
	}
	mw.Tokens = nil
	for _, t := range in.Tokens {
		if !tokenRe.MatchString(t) {
			return errors.New("tokens must be check tokens")
		}
		mw.Tokens = append(mw.Tokens, t)
	}
	mw.Active = in.Active == nil || *in.Active
	return nil
}

func (m *Module) apiMaintenanceList(w http.ResponseWriter, r *http.Request) {
	list, err := m.st.MaintenanceList(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	if list == nil {
		list = []Maintenance{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (m *Module) apiMaintenanceCreate(w http.ResponseWriter, r *http.Request) {
	var in maintenanceIn
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	var mw Maintenance
	if err := m.maintenanceFrom(in, &mw); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err := m.st.MaintenanceInsert(r.Context(), &mw); err != nil {
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	m.auditText(r, "maintenance.create", mw.Name)
	writeJSON(w, http.StatusCreated, mw)
}

func (m *Module) apiMaintenanceUpdate(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	list, _ := m.st.MaintenanceList(r.Context())
	var mw *Maintenance
	for i := range list {
		if list[i].ID == id {
			mw = &list[i]
		}
	}
	if mw == nil {
		writeErr(w, http.StatusNotFound, "maintenance window not found")
		return
	}
	var in maintenanceIn
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if err := m.maintenanceFrom(in, mw); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err := m.st.MaintenanceUpdate(r.Context(), mw); err != nil {
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	m.auditText(r, "maintenance.update", mw.Name)
	writeJSON(w, http.StatusOK, mw)
}

func (m *Module) apiMaintenanceDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := m.st.MaintenanceDelete(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	m.auditText(r, "maintenance.delete", strconv.FormatInt(id, 10))
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------- Push

// pushLimiter: je Token hoechstens 60 Meldungen pro Minute, Mindestabstand 1 s.
type pushLimiter struct {
	mu   sync.Mutex
	last map[string]time.Time
	cnt  map[string]int
	win  time.Time
}

func newPushLimiter() *pushLimiter {
	return &pushLimiter{last: map[string]time.Time{}, cnt: map[string]int{}, win: time.Now()}
}

func (l *pushLimiter) allow(token string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.Sub(l.win) > time.Minute {
		l.cnt = map[string]int{}
		l.win = now
		if len(l.last) > 10000 {
			l.last = map[string]time.Time{}
		}
	}
	if now.Sub(l.last[token]) < time.Second || l.cnt[token] >= 60 {
		return false
	}
	l.last[token] = now
	l.cnt[token]++
	return true
}

// apiPush nimmt einen Heartbeat an. Die Antwort ist fuer bekannte und
// unbekannte Tokens gleich, damit Tokens nicht erraten werden koennen.
func (m *Module) apiPush(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	w.Header().Set("Cache-Control", "no-store")
	if !tokenRe.MatchString(token) || !m.push.allow(token) {
		if tokenRe.MatchString(token) {
			m.log.Debug("push rate limited", "token", checks.TokenHint(token))
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	q := r.URL.Query()
	status := checks.Status(strings.ToLower(q.Get("status")))
	if status != checks.Down {
		status = checks.Up
	}
	msg := strings.TrimSpace(q.Get("msg"))
	if len(msg) > 200 {
		msg = msg[:200]
	}
	details := map[string]any{}
	if r.Method == http.MethodPost && r.Body != nil {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
		if len(b) > 0 {
			var v any
			if json.Unmarshal(b, &v) == nil {
				details["payload"] = v
			} else {
				details["payload"] = string(b)
			}
		}
	}
	if ip := r.RemoteAddr; ip != "" {
		if h, _, err := splitHostPort(ip); err == nil {
			ip = h
		}
		details["from"] = ip
	}
	measured := false
	if s := m.scheduler(); s != nil {
		measured = s.Push(r.Context(), token, status, msg, details)
	}
	// Push-Checks sind von ueberall ausloesbar: weitere Messstellen (andere Nodes, ipv64) ueber den hub informieren
	if m.pushFwd != nil && m.linked != nil && m.linked() {
		if c, _ := m.st.Check(r.Context(), token); c != nil && c.Type == checks.TypePush && (c.Execution != "local" || len(c.Nodes) > 1 || !c.MeasuredHere()) {
			from, _ := details["from"].(string)
			if !m.pushFwd(token, status == checks.Down, msg, from) && !measured {
				// weder hier gemessen noch weitergegeben: dem Aufrufer nicht "ok" melden
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "error", "error": "not connected to ipv64, push not delivered"})
				return
			}
		}
	}
	if !measured {
		m.log.Debug("push not measured here", "token", checks.TokenHint(token))
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ---------------------------------------------------------------- Audit

func (m *Module) audit(r *http.Request, action string, c *Check) {
	m.auditText(r, action, c.Name+" ("+checks.TokenHint(c.Token)+")")
}

func (m *Module) auditText(r *http.Request, action, target string) {
	if m.g.Audit != nil {
		m.g.Audit(r, action, target, "") // Benutzer, IP und Herkunft (Oberflaeche oder welcher API-Key) wie im Kern
		return
	}
	ip := r.RemoteAddr
	if m.g.ClientIP != nil {
		ip = m.g.ClientIP(r)
	} else if h, _, err := splitHostPort(ip); err == nil {
		ip = h
	}
	if err := m.core.Audit(r.Context(), auditEntry(m.actor(r), action, target, ip)); err != nil {
		m.log.Error("audit", "err", err)
	}
}

// apiBulk fuehrt eine Aktion fuer mehrere Checks aus, wie die Sammelaktionen der Oberflaeche:
// pause, resume, run, delete, tag, untag (mit "tag"). Ergebnis je Check, ein Sammeleintrag im Audit.
func (m *Module) apiBulk(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Action string   `json:"action"`
		Tokens []string `json:"tokens"`
		Tag    string   `json:"tag"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	switch in.Action {
	case "pause", "resume", "run", "delete", "tag", "untag":
	default:
		writeErr(w, http.StatusUnprocessableEntity, "action must be pause, resume, run, delete, tag or untag")
		return
	}
	if len(in.Tokens) == 0 || len(in.Tokens) > 1000 {
		writeErr(w, http.StatusUnprocessableEntity, "tokens: 1 to 1000 check tokens")
		return
	}
	type failure struct {
		Token string `json:"token"`
		Error string `json:"error"`
	}
	done, failed := 0, []failure{}
	for _, t := range in.Tokens {
		if !tokenRe.MatchString(t) {
			failed = append(failed, failure{t, "invalid token"})
			continue
		}
		c, err := m.st.Check(r.Context(), t)
		if err != nil || c == nil {
			failed = append(failed, failure{t, "not found"})
			continue
		}
		if in.Action == "tag" || in.Action == "untag" {
			if m.bulkTag(r, c, in.Action == "tag", in.Tag) {
				done++
			} else {
				failed = append(failed, failure{t, "tag invalid or nothing to change"})
			}
			continue
		}
		if err := m.doAction(r, c, in.Action); err != nil {
			failed = append(failed, failure{t, err.Error()})
			continue
		}
		done++
	}
	m.auditBulk(r, in.Action, in.Tag, done, len(in.Tokens))
	writeJSON(w, http.StatusOK, map[string]any{"done": done, "failed": failed})
}

// auditBulk schreibt einen Sammeleintrag fuer eine Sammelaktion (die einzelnen Checks haben eigene Eintraege).
func (m *Module) auditBulk(r *http.Request, action, tag string, done, total int) {
	target := fmt.Sprintf("%d/%d checks", done, total)
	if tag != "" && (action == "tag" || action == "untag") {
		target = "tag " + tag + ": " + target
	}
	m.auditText(r, "check.bulk_"+action, target)
}

// checkOnlineLimit prueft Online-/Hybrid-Checks gegen die Account-Klasse wie das Portal: hoechstens so viele
// Standorte je Check wie erlaubt und genug freie Online-Messstellen. Ohne Kontodaten (standalone, API-Modus) nichts.
func (m *Module) checkOnlineLimit(c *Check, locations []string) error {
	if m.quota == nil || m.account == nil {
		return nil
	}
	_, _, accLocs := m.quota()
	_, limit := m.account()
	n := len(locations)
	if n == 0 {
		n = len(c.Locations)
	}
	if accLocs > 0 && n > accLocs {
		return fmt.Errorf("locations: your account class allows %d location(s) per check", accLocs)
	}
	if limit <= 0 {
		return nil
	}
	tmp := *c
	if locations != nil {
		tmp.Locations = locations
	}
	used := m.OnlinePoints(context.Background(), c.Token, accLocs)
	if need := onlineLocs(&tmp, accLocs); used+need > limit {
		return fmt.Errorf("online limit reached: %d of %d measuring points used, this check needs %d more – reduce locations or measure locally on a node", used, limit, need)
	}
	return nil
}
