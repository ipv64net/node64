package monitor64

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/m64proto"
	"github.com/ipv64net/node64/internal/monitor64/eval"
	"github.com/ipv64net/node64/internal/monitor64/transport"
	"github.com/ipv64net/node64/internal/monitor64/tsdb"
)

// API fuer Schwellen (Standard, Abweichungen mit Vorschau), Benachrichtigung, Wartung und Einstellungen.
// Nach jeder Aenderung: reloadConfig (Neubewertung in der naechsten Runde) und Akteur in Tabelle und Audit-Log.

const setInterval = "monitor64.interval" // Standard-Intervall fuer neue Hosts (Sekunden)

// ---------------------------------------------------------------------------------------------------------
// Schwellen

type targetsOut struct {
	Groups []string `json:"groups"`
	Tags   []string `json:"tags"`
}

func (m *Module) targets(ctx context.Context) targetsOut {
	t := targetsOut{Groups: []string{}, Tags: []string{}}
	hosts, _ := m.store.Hosts(ctx)
	for _, h := range hosts {
		if h.Group != "" && !slices.Contains(t.Groups, h.Group) {
			t.Groups = append(t.Groups, h.Group)
		}
		for _, tg := range h.Tags {
			if !slices.Contains(t.Tags, tg) {
				t.Tags = append(t.Tags, tg)
			}
		}
	}
	sort.Strings(t.Groups)
	sort.Strings(t.Tags)
	return t
}

// effect ist die Wirkung einer Abweichung (Vorschau "betrifft N Dienste auf M Hosts, danach X Warnungen").
type effect struct {
	Services int              `json:"services"`
	Hosts    []string         `json:"hosts"`
	Own      []string         `json:"own"`    // Hosts, an denen die Schwelle direkt eingestellt ist
	Shadow   map[int][]string `json:"shadow"` // Index einer Abweichung weiter oben -> Hosts, auf denen sie gewinnt
	Before   counts           `json:"before"`
	After    counts           `json:"after"`
}

type counts struct {
	Warn int `json:"warn"`
	Crit int `json:"crit"`
}

func (c *counts) add(s eval.State) {
	switch s {
	case eval.Warn:
		c.Warn++
	case eval.Crit:
		c.Crit++
	}
}

// levelOf bewertet den letzten Wert einer Messgroesse mit einer Regel (ohne Dauer und Hysterese; Vorschau).
func levelOf(e eval.Effective, mt MetricView) eval.State {
	w, c, dir, _ := e.Levels()
	v := mt.Value
	if e.Mode == eval.ModeFree {
		if mt.Max <= 0 || mt.Unit != "%" {
			return mt.Status.Level
		}
		v = mt.Max * (100 - mt.Value) / 100 / eval.GB
	}
	over := func(l eval.Limit) bool {
		if l.Off {
			return false
		}
		if dir == eval.Down {
			return v < l.V
		}
		return v >= l.V
	}
	switch {
	case over(c):
		return eval.Crit
	case over(w):
		return eval.Warn
	}
	return eval.OK
}

// ownRule: am Host ist fuer diesen Dienst eine Schwelle eingestellt (gilt vor allen Abweichungen).
func ownRule(hl eval.HostLevel) bool {
	set := func(r *eval.Rule) bool {
		return r != nil && (r.Warn != nil || r.Crit != nil || r.WarnFree != nil || r.CritFree != nil || r.Mode != nil || r.Severity != nil)
	}
	return set(hl.Service) || set(hl.Kind)
}

// effectOf rechnet die Wirkung der Abweichung list[idx] auf den aktuellen Stand aller Hosts.
func (m *Module) effectOf(ctx context.Context, std eval.Table, list []eval.Override, idx int) effect {
	ef := effect{Hosts: []string{}, Own: []string{}, Shadow: map[int][]string{}}
	o := list[idx]
	rows, _ := m.store.Services(ctx, "")
	byKey := map[string]*ServiceRow{}
	for _, r := range rows {
		byKey[r.HostUID+"|"+r.Key] = r
	}
	addHost := func(l []string, n string) []string {
		if !slices.Contains(l, n) {
			return append(l, n)
		}
		return l
	}
	for _, v := range m.sortedViews() {
		ref := hostRef(v.Host)
		if !o.Matches(ref, o.Kind) {
			continue
		}
		for _, s := range v.Services {
			row := byKey[v.Host.UID+"|"+s.Key]
			if row == nil {
				row = &ServiceRow{HostUID: v.Host.UID, Key: s.Key, Kind: s.Kind}
			}
			hl := m.hostLevel(row)
			check := func(mt *MetricView) {
				if ownRule(hl) {
					ef.Own = addHost(ef.Own, v.Host.Name)
					return
				}
				e := eval.Resolve(std, list, ref, hl, o.Kind)
				if e.Override != idx {
					if e.Override >= 0 && e.Override < idx {
						ef.Shadow[e.Override] = addHost(ef.Shadow[e.Override], v.Host.Name)
					}
					return
				}
				ef.Services++
				ef.Hosts = addHost(ef.Hosts, v.Host.Name)
				if mt != nil {
					ef.Before.add(mt.Status.Level)
					ef.After.add(levelOf(e, *mt))
				}
			}
			if rk, _ := ruleKindOf(o.Kind); rk.State {
				if slices.Contains(factKinds[s.Kind], o.Kind) || (o.Kind == eval.KindGuestDown && guestKind(s.Kind)) {
					check(nil)
				}
				continue
			}
			for i := range s.Metrics {
				if s.Metrics[i].Metric.Rule == o.Kind {
					check(&s.Metrics[i])
					break
				}
			}
		}
	}
	return ef
}

// ruleOverrideOut ist eine Abweichung der Schwellen mit ihrer Wirkung.
type ruleOverrideOut struct {
	overrideRow
	Rule   eval.Rule `json:"rule"`
	Effect effect    `json:"effect"`
}

// ownOut ist eine Schwelle, die direkt am Host eingestellt ist.
type ownOut struct {
	HostUID string    `json:"host_uid"`
	Host    string    `json:"host"`
	Key     string    `json:"key,omitempty"` // leer = alle Dienste der Art
	Name    string    `json:"name"`
	Kind    string    `json:"kind"`
	Rule    eval.Rule `json:"rule"`
}

// apiRules: GET Standard-Tabelle, Abweichungen (mit Wirkung) und "Am Host eingestellt".
func (m *Module) apiRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cfg := m.config()
	rows, err := m.store.Overrides(ctx, "rule")
	if err != nil {
		m.fail(w, r, err)
		return
	}
	ovs := []ruleOverrideOut{}
	for i, o := range rows {
		var rule eval.Rule
		_ = json.Unmarshal(o.Data, &rule)
		out := ruleOverrideOut{overrideRow: o, Rule: rule}
		if i < len(cfg.overrides) && cfg.overrides[i].ID == o.UID {
			out.Effect = m.effectOf(ctx, cfg.std, cfg.overrides, i)
		}
		ovs = append(ovs, out)
	}
	hosts := map[string]string{}
	if hl, err := m.store.Hosts(ctx); err == nil {
		for _, h := range hl {
			hosts[h.UID] = h.Name
		}
	}
	own := []ownOut{}
	if svcs, err := m.store.Services(ctx, ""); err == nil {
		for _, s := range svcs {
			if s.HostRule == "" || s.Adopted != 1 || hosts[s.HostUID] == "" {
				continue
			}
			var rule eval.Rule
			if json.Unmarshal([]byte(s.HostRule), &rule) != nil || rule.Empty() {
				continue
			}
			own = append(own, ownOut{HostUID: s.HostUID, Host: hosts[s.HostUID], Key: s.Key, Name: firstNonEmpty(s.Name, s.Key), Kind: s.Kind, Rule: rule})
		}
	}
	if hr, err := m.store.HostRules(ctx, ""); err == nil {
		for _, x := range hr {
			if hosts[x.HostUID] == "" {
				continue
			}
			own = append(own, ownOut{HostUID: x.HostUID, Host: hosts[x.HostUID], Kind: x.Kind, Rule: x.Rule})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"kinds": ruleKinds, "defaults": eval.Defaults(), "std": cfg.std, "overrides": ovs, "own": own,
		"targets": m.targets(ctx)})
}

type stdIn struct {
	Rules map[string]eval.Rule `json:"rules"`
}

// apiRulesStd: PUT Standard-Tabelle speichern (gespeichert werden nur Arten, die vom eingebauten Standard abweichen).
func (m *Module) apiRulesStd(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in stdIn
	if err := decode(r, &in); err != nil {
		m.fail(w, r, err)
		return
	}
	def := eval.Defaults()
	saved := map[string]eval.Rule{}
	var changed []string
	for kind, rule := range in.Rules {
		base, ok := def[kind]
		if !ok {
			m.fail(w, r, errBad("kind"))
			return
		}
		if err := rule.Validate(); err != nil {
			m.fail(w, r, errBad("rule", "error", err.Error()))
			return
		}
		merged := eval.Table{kind: base}
		e := eval.Resolve(merged, nil, eval.HostRef{}, eval.HostLevel{Service: &rule}, kind)
		if err := e.Validate(); err != nil {
			m.fail(w, r, errBad("rule_kind", "kind", kind, "error", err.Error()))
			return
		}
		// Herkunft unterscheidet sich immer; verglichen werden nur die Werte
		eB := eval.Resolve(merged, nil, eval.HostRef{}, eval.HostLevel{}, kind)
		e.Origin, eB.Origin = nil, nil
		b1, _ := json.Marshal(eB)
		b2, _ := json.Marshal(e)
		if string(b1) != string(b2) {
			saved[kind] = rule
			changed = append(changed, kind)
		}
	}
	b, _ := json.Marshal(saved)
	if err := m.st.SetSetting(ctx, setStd, string(b)); err != nil {
		m.fail(w, r, err)
		return
	}
	sort.Strings(changed)
	m.reloadConfig(ctx)
	m.audit(r, "rules.std", "", "changed="+strings.Join(changed, ","))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "changed": changed})
}

type ruleOverrideIn struct {
	TargetType string    `json:"target_type"`
	Target     string    `json:"target"`
	Kind       string    `json:"kind"`
	Rule       eval.Rule `json:"rule"`
}

func (in *ruleOverrideIn) check(std eval.Table) error {
	if in.TargetType != "group" && in.TargetType != "tag" {
		return errBad("target")
	}
	in.Target = cleanText(in.Target, 64)
	if in.TargetType == "tag" {
		in.Target = strings.ToLower(in.Target)
	}
	if in.Target == "" {
		return errBad("target")
	}
	if _, ok := std[in.Kind]; !ok {
		return errBad("kind")
	}
	if err := in.Rule.Validate(); err != nil {
		return errBad("rule", "error", err.Error())
	}
	if in.Rule.Empty() {
		return errBad("rule_empty")
	}
	e := eval.Resolve(std, []eval.Override{in.override("")}, eval.HostRef{Group: in.Target, Tags: []string{in.Target}}, eval.HostLevel{}, in.Kind)
	if err := e.Validate(); err != nil {
		return errBad("rule", "error", err.Error())
	}
	return nil
}

func (in ruleOverrideIn) override(id string) eval.Override {
	o := eval.Override{ID: id, Kind: in.Kind, Rule: in.Rule}
	if in.TargetType == "group" {
		o.Group = in.Target
	} else {
		o.Tag = in.Target
	}
	return o
}

// apiRulePreview: POST Vorschau einer neuen bzw. geaenderten Abweichung (uid gesetzt = ersetzt diese).
func (m *Module) apiRulePreview(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ruleOverrideIn
		UID string `json:"uid"`
	}
	if err := decode(r, &in); err != nil {
		m.fail(w, r, err)
		return
	}
	cfg := m.config()
	if err := in.check(cfg.std); err != nil {
		m.fail(w, r, err)
		return
	}
	list := slices.Clone(cfg.overrides)
	idx := slices.IndexFunc(list, func(o eval.Override) bool { return in.UID != "" && o.ID == in.UID })
	if idx >= 0 {
		list[idx] = in.override(in.UID)
	} else {
		list = append(list, in.override("new"))
		idx = len(list) - 1
	}
	writeJSON(w, http.StatusOK, m.effectOf(r.Context(), cfg.std, list, idx))
}

// apiRuleOverrideSave: POST (neu, unten angefuegt) bzw. PUT (aendern) einer Abweichung der Schwellen.
func (m *Module) apiRuleOverrideSave(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in ruleOverrideIn
	if err := decode(r, &in); err != nil {
		m.fail(w, r, err)
		return
	}
	if err := in.check(m.config().std); err != nil {
		m.fail(w, r, err)
		return
	}
	data, _ := json.Marshal(in.Rule)
	o := &overrideRow{UID: r.PathValue("uid"), Scope: "rule", TargetType: in.TargetType, Target: in.Target, Kind: in.Kind, Data: data}
	action := "rules.override.update"
	if o.UID == "" {
		action = "rules.override.create"
	}
	if err := m.store.SaveOverride(ctx, o, m.actor(r)); err != nil {
		m.fail(w, r, err)
		return
	}
	m.reloadConfig(ctx)
	m.audit(r, action, in.TargetType+":"+in.Target, in.Kind+" "+string(data))
	writeJSON(w, http.StatusOK, map[string]any{"uid": o.UID})
}

// apiOverrideDelete: DELETE Abweichung (Schwellen bzw. Benachrichtigung) entfernen.
func (m *Module) apiOverrideDelete(scope string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		uid := r.PathValue("uid")
		if err := m.store.DeleteOverride(ctx, scope, uid, m.actor(r)); err != nil {
			m.fail(w, r, err)
			return
		}
		m.reloadConfig(ctx)
		m.audit(r, scopeAction(scope)+".override.delete", uid, "")
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}
}

// apiOverrideMove: POST Abweichung eine Stelle nach oben (dir -1) oder unten (1) schieben (oben gewinnt).
func (m *Module) apiOverrideMove(scope string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		var in struct {
			Dir int `json:"dir"`
		}
		if err := decode(r, &in); err != nil {
			m.fail(w, r, err)
			return
		}
		if in.Dir != -1 && in.Dir != 1 {
			m.fail(w, r, errBad("dir"))
			return
		}
		uid := r.PathValue("uid")
		if err := m.store.MoveOverride(ctx, scope, uid, in.Dir, m.actor(r)); err != nil {
			m.fail(w, r, err)
			return
		}
		m.reloadConfig(ctx)
		m.audit(r, scopeAction(scope)+".override.move", uid, strconv.Itoa(in.Dir))
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}
}

func scopeAction(scope string) string {
	if scope == "notify" {
		return "notify"
	}
	return "rules"
}

// ---------------------------------------------------------------------------------------------------------
// Benachrichtigung

type quietOut struct {
	Enabled bool   `json:"enabled"`
	From    string `json:"from"`
	To      string `json:"to"`
	Days    string `json:"days"`
}

// apiNotify: GET Benachrichtigung (Kanaele x Schwere, Erinnerung, Abweichungen) mit den Kanaelen der Node.
func (m *Module) apiNotify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cfg := m.config()
	chs, err := m.store.Channels(ctx)
	if err != nil {
		m.fail(w, r, err)
		return
	}
	if chs == nil {
		chs = []channelInfo{}
	}
	rows, err := m.store.Overrides(ctx, "notify")
	if err != nil {
		m.fail(w, r, err)
		return
	}
	type ovOut struct {
		overrideRow
		Notify eval.NotifyOverride `json:"notify"`
	}
	ovs := []ovOut{}
	for _, o := range rows {
		var n eval.NotifyOverride
		_ = json.Unmarshal(o.Data, &n)
		ovs = append(ovs, ovOut{overrideRow: o, Notify: n})
	}
	q := quietOut{Enabled: m.st.SettingOr(ctx, "notify.quiet_enabled", "") == "1" || m.st.SettingOr(ctx, "notify.quiet_enabled", "") == "true",
		From: m.st.SettingOr(ctx, "notify.quiet_from", ""), To: m.st.SettingOr(ctx, "notify.quiet_to", ""), Days: m.st.SettingOr(ctx, "notify.quiet_days", "")}
	writeJSON(w, http.StatusOK, map[string]any{"config": cfg.notify, "channels": chs, "overrides": ovs, "quiet": q, "targets": m.targets(ctx)})
}

// checkRoutes prueft Kanaele (Standardkanaele oder Kanaele der Node).
func (m *Module) checkRoutes(ctx context.Context, list []eval.ChannelRoute) ([]eval.ChannelRoute, error) {
	chs, _ := m.store.Channels(ctx)
	out := []eval.ChannelRoute{}
	for _, c := range list {
		if !c.Warn && !c.Crit {
			continue
		}
		if c.ID != defaultChannels && !slices.ContainsFunc(chs, func(x channelInfo) bool { return strconv.FormatInt(x.ID, 10) == c.ID }) {
			return nil, errBad("channel")
		}
		if slices.ContainsFunc(out, func(x eval.ChannelRoute) bool { return x.ID == c.ID }) {
			continue
		}
		out = append(out, c)
	}
	return out, nil
}

func validRemind(d eval.Dur) bool {
	return d == 0 || time.Duration(d) >= time.Hour
}

// apiNotifySave: PUT Grundeinstellung der Benachrichtigung.
func (m *Module) apiNotifySave(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in eval.NotifyConfig
	if err := decode(r, &in); err != nil {
		m.fail(w, r, err)
		return
	}
	chs, err := m.checkRoutes(ctx, in.Channels)
	if err != nil {
		m.fail(w, r, err)
		return
	}
	if !validRemind(in.RemindWarn) || !validRemind(in.RemindCrit) {
		m.fail(w, r, errBad("remind"))
		return
	}
	in.Channels = chs
	b, _ := json.Marshal(in)
	if err := m.st.SetSetting(ctx, setNotify, string(b)); err != nil {
		m.fail(w, r, err)
		return
	}
	m.reloadConfig(ctx)
	m.audit(r, "notify.save", "", string(b))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

type notifyOverrideIn struct {
	TargetType  string              `json:"target_type"`
	Target      string              `json:"target"`
	Channels    []eval.ChannelRoute `json:"channels"`
	Replace     bool                `json:"replace"`
	OnlyCrit    *bool               `json:"only_crit"`
	CritInQuiet *bool               `json:"crit_in_quiet"`
	RemindWarn  *eval.Dur           `json:"remind_warn"`
	RemindCrit  *eval.Dur           `json:"remind_crit"`
}

// apiNotifyOverrideSave: POST (neu, unten) bzw. PUT (aendern) einer Abweichung der Benachrichtigung.
func (m *Module) apiNotifyOverrideSave(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in notifyOverrideIn
	if err := decode(r, &in); err != nil {
		m.fail(w, r, err)
		return
	}
	if in.TargetType != "group" && in.TargetType != "tag" {
		m.fail(w, r, errBad("target"))
		return
	}
	in.Target = cleanText(in.Target, 64)
	if in.TargetType == "tag" {
		in.Target = strings.ToLower(in.Target)
	}
	if in.Target == "" {
		m.fail(w, r, errBad("target"))
		return
	}
	chs, err := m.checkRoutes(ctx, in.Channels)
	if err != nil {
		m.fail(w, r, err)
		return
	}
	if (in.RemindWarn != nil && !validRemind(*in.RemindWarn)) || (in.RemindCrit != nil && !validRemind(*in.RemindCrit)) {
		m.fail(w, r, errBad("remind"))
		return
	}
	n := eval.NotifyOverride{Channels: chs, Replace: in.Replace, OnlyCrit: in.OnlyCrit, CritInQuiet: in.CritInQuiet, RemindWarn: in.RemindWarn, RemindCrit: in.RemindCrit}
	data, _ := json.Marshal(n)
	o := &overrideRow{UID: r.PathValue("uid"), Scope: "notify", TargetType: in.TargetType, Target: in.Target, Data: data}
	action := "notify.override.update"
	if o.UID == "" {
		action = "notify.override.create"
	}
	if err := m.store.SaveOverride(ctx, o, m.actor(r)); err != nil {
		m.fail(w, r, err)
		return
	}
	m.reloadConfig(ctx)
	m.audit(r, action, in.TargetType+":"+in.Target, string(data))
	writeJSON(w, http.StatusOK, map[string]any{"uid": o.UID})
}

// apiNotifyTest: POST Testmeldung (Beispiel-Problem) an alle Kanaele der Grundeinstellung.
func (m *Module) apiNotifyTest(w http.ResponseWriter, r *http.Request) {
	if m.dispatchFn == nil {
		m.fail(w, r, errNotRunning)
		return
	}
	cfg := m.config()
	rt := eval.ResolveRouting(cfg.notify, nil, eval.HostRef{})
	chans := rt.Route(eval.Crit)
	for _, c := range rt.Route(eval.Warn) {
		if !slices.Contains(chans, c) {
			chans = append(chans, c)
		}
	}
	if len(chans) == 0 {
		m.fail(w, r, errBad("no_channels"))
		return
	}
	t := func(k string) string {
		if m.g.T != nil {
			return m.g.T(r, "monitor64.notify.test_"+k)
		}
		return k
	}
	now := time.Now()
	h := &Host{UID: "test", Name: t("host")}
	msg := eval.Message{At: now, Host: eval.HostRef{ID: "test", Name: h.Name}, Event: eval.EvProblem, Severity: eval.Warn, Counts: eval.Counts{Warn: 1},
		Lines:    []eval.Line{{Kind: eval.LineProblem, Key: "test", Name: t("service"), State: eval.Warn, Since: now, Detail: t("detail")}},
		Channels: chans}
	m.dispatch(h, msg, "")
	m.audit(r, "notify.test", "", strings.Join(chans, ","))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "channels": len(chans)})
}

// ---------------------------------------------------------------------------------------------------------
// Wartung

type maintOut struct {
	maintRow
	Status  string `json:"status"` // running, planned, recurring, ended
	Running bool   `json:"running"`
}

// maintStatus ermittelt den Stand eines Fensters zum Zeitpunkt now.
func maintStatus(mr maintRow, now time.Time, loc *time.Location) (string, bool) {
	w := eval.Window{Hosts: []string{"x"}, Start: mr.Start, End: mr.End, Recurring: mr.Recur}
	if !mr.Ended.IsZero() && (w.End.IsZero() || mr.Ended.Before(w.End)) {
		w.End = mr.Ended
	}
	active := w.Active(now, eval.HostRef{ID: "x"}, loc)
	switch {
	case !w.End.IsZero() && !now.Before(w.End):
		return "ended", false
	case mr.Recur != nil:
		return "recurring", active
	case active:
		return "running", true
	}
	return "planned", false
}

// apiMaint: GET Wartungsfenster mit Stand, dazu Hosts, Gruppen und Tags fuer die Auswahl.
func (m *Module) apiMaint(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	list, err := m.store.Maintenances(ctx)
	if err != nil {
		m.fail(w, r, err)
		return
	}
	now, loc := time.Now(), m.location()
	items := []maintOut{}
	for _, mr := range list {
		st, run := maintStatus(mr, now, loc)
		items = append(items, maintOut{maintRow: mr, Status: st, Running: run})
	}
	order := map[string]int{"running": 0, "planned": 1, "recurring": 2, "ended": 3}
	sort.SliceStable(items, func(i, j int) bool { return order[items[i].Status] < order[items[j].Status] })
	type hostBrief struct {
		UID   string `json:"uid"`
		Name  string `json:"name"`
		Group string `json:"group"`
		Kind  string `json:"kind"`
	}
	hosts := []hostBrief{}
	if hl, err := m.store.Hosts(ctx); err == nil {
		for _, h := range hl {
			hosts = append(hosts, hostBrief{UID: h.UID, Name: h.Name, Group: h.Group, Kind: h.Kind})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "hosts": hosts, "targets": m.targets(ctx), "tz": loc.String()})
}

type maintIn struct {
	Title   string         `json:"title"`
	Hosts   []string       `json:"hosts"`
	Groups  []string       `json:"groups"`
	Tags    []string       `json:"tags"`
	Mode    string         `json:"mode"`    // now, plan, recur
	Minutes int            `json:"minutes"` // now: Dauer (0 = bis beendet)
	Start   string         `json:"start"`   // plan: "2006-01-02T15:04" in Ortszeit der Node
	End     string         `json:"end"`
	Days    []time.Weekday `json:"days"` // recur: leer = jeden Tag
	From    string         `json:"from"` // recur: "HH:MM"
	To      string         `json:"to"`
}

func (m *Module) buildMaint(ctx context.Context, in maintIn, mr *maintRow, now time.Time) error {
	mr.Title = cleanText(in.Title, 200)
	mr.Hosts, mr.Groups, mr.Tags = nil, nil, nil
	for _, uid := range in.Hosts {
		if _, err := m.store.Host(ctx, uid); err != nil {
			return errBad("maint_host")
		}
		mr.Hosts = append(mr.Hosts, uid)
	}
	for _, g := range in.Groups {
		if g = cleanText(g, 64); g != "" {
			mr.Groups = append(mr.Groups, g)
		}
	}
	mr.Tags = normTags(in.Tags)
	if len(mr.Hosts)+len(mr.Groups)+len(mr.Tags) == 0 {
		return errBad("maint_targets")
	}
	loc := m.location()
	mr.Recur = nil
	switch in.Mode {
	case "now":
		if in.Minutes < 0 || in.Minutes > 30*24*60 {
			return errBad("maint_time")
		}
		mr.Start, mr.End = now, time.Time{}
		if in.Minutes > 0 {
			mr.End = now.Add(time.Duration(in.Minutes) * time.Minute)
		}
	case "plan":
		s, err1 := time.ParseInLocation("2006-01-02T15:04", in.Start, loc)
		e, err2 := time.ParseInLocation("2006-01-02T15:04", in.End, loc)
		if err1 != nil || err2 != nil || !e.After(s) {
			return errBad("maint_time")
		}
		mr.Start, mr.End = s, e
	case "recur":
		var rc eval.Recurrence
		if rc.From.UnmarshalText([]byte(in.From)) != nil || rc.To.UnmarshalText([]byte(in.To)) != nil {
			return errBad("maint_time")
		}
		for _, d := range in.Days {
			if d < 0 || d > 6 {
				return errBad("maint_time")
			}
			if !slices.Contains(rc.Days, d) {
				rc.Days = append(rc.Days, d)
			}
		}
		mr.Recur, mr.Start, mr.End = &rc, time.Time{}, time.Time{}
	default:
		return errBad("maint_mode")
	}
	return nil
}

// apiMaintSave: POST (neu) bzw. PUT (aendern) eines Wartungsfensters.
func (m *Module) apiMaintSave(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in maintIn
	if err := decode(r, &in); err != nil {
		m.fail(w, r, err)
		return
	}
	mr := &maintRow{UID: r.PathValue("uid")}
	now := time.Now()
	if err := m.buildMaint(ctx, in, mr, now); err != nil {
		m.fail(w, r, err)
		return
	}
	by := m.actor(r)
	isNew := mr.UID == ""
	if err := m.store.SaveMaint(ctx, mr, by); err != nil {
		m.fail(w, r, err)
		return
	}
	m.reloadConfig(ctx)
	if isNew {
		m.event(ctx, "", "", "", "maint", mr.Title, by, now)
	}
	tb, _ := json.Marshal(maintTargets{Hosts: mr.Hosts, Groups: mr.Groups, Tags: mr.Tags})
	action := "maint.update"
	if isNew {
		action = "maint.create"
	}
	m.audit(r, action, mr.Title, fmt.Sprintf("uid=%s mode=%s targets=%s", mr.UID, in.Mode, tb))
	writeJSON(w, http.StatusOK, map[string]any{"uid": mr.UID})
}

func (m *Module) maintByUID(ctx context.Context, uid string) (*maintRow, error) {
	list, err := m.store.Maintenances(ctx)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].UID == uid {
			return &list[i], nil
		}
	}
	return nil, ErrNotFound
}

// apiMaintEnd: POST Wartung jetzt beenden.
func (m *Module) apiMaintEnd(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	mr, err := m.maintByUID(ctx, r.PathValue("uid"))
	if err != nil {
		m.fail(w, r, err)
		return
	}
	by := m.actor(r)
	now := time.Now()
	if err := m.store.EndMaint(ctx, mr.UID, now, by); err != nil {
		m.fail(w, r, err)
		return
	}
	m.reloadConfig(ctx)
	m.event(ctx, "", "", "", "maint_end", mr.Title, by, now)
	m.audit(r, "maint.end", mr.Title, "uid="+mr.UID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// apiMaintDelete: DELETE Wartungsfenster entfernen.
func (m *Module) apiMaintDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	mr, err := m.maintByUID(ctx, r.PathValue("uid"))
	if err != nil {
		m.fail(w, r, err)
		return
	}
	if err := m.store.DeleteMaint(ctx, mr.UID, m.actor(r)); err != nil {
		m.fail(w, r, err)
		return
	}
	m.reloadConfig(ctx)
	m.audit(r, "maint.delete", mr.Title, "uid="+mr.UID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---------------------------------------------------------------------------------------------------------
// Einstellungen

type settingsOut struct {
	Interval    int        `json:"interval"`
	Workers     int        `json:"workers"`
	RetRawH     int        `json:"retention_raw_hours"`
	Ret5mD      int        `json:"retention_5m_days"`
	Ret1hD      int        `json:"retention_1h_days"`
	Hosts       int        `json:"hosts"`
	Services    int        `json:"services"`
	Status      statusView `json:"status"`
	Port        int        `json:"port"`
	PublicKey   string     `json:"public_key,omitempty"`
	Fingerprint string     `json:"fingerprint,omitempty"`
}

func (m *Module) settings(ctx context.Context) settingsOut {
	o := tsdb.DefaultOptions()
	s := settingsOut{Interval: m.defaultInterval(ctx), Workers: m.workers(ctx), RetRawH: int(o.RetentionRaw.Hours()), Ret5mD: int(o.Retention5m.Hours() / 24),
		Ret1hD: int(o.Retention1h.Hours() / 24), Status: m.status(), Port: m64proto.DefaultPort, Services: m.store.ServiceCount(ctx)}
	if hl, err := m.store.Hosts(ctx); err == nil {
		s.Hosts = len(hl)
	}
	if m.scheduler() != nil { // Schluessel nur bei laufendem Modul (wird sonst nicht erzeugt)
		if signer, err := m.nodeSigner(ctx); err == nil {
			s.Fingerprint = transport.Fingerprint(signer.PublicKey())
			s.PublicKey, _ = m.PublicKeyLine(ctx)
		}
	}
	return s
}

// apiSettings: GET Einstellungen und technischer Stand.
func (m *Module) apiSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, m.settings(r.Context()))
}

// apiSettingsSave: PUT Standard-Intervall und gleichzeitige Abfragen (gilt nach dem naechsten Start des Moduls).
func (m *Module) apiSettingsSave(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in struct {
		Interval int `json:"interval"`
		Workers  int `json:"workers"`
	}
	if err := decode(r, &in); err != nil {
		m.fail(w, r, err)
		return
	}
	if in.Interval < 30 || in.Interval > 900 {
		m.fail(w, r, errBad("interval"))
		return
	}
	if in.Workers < 1 || in.Workers > 512 {
		m.fail(w, r, errBad("workers"))
		return
	}
	err := errors.Join(m.st.SetSetting(ctx, setInterval, strconv.Itoa(in.Interval)), m.st.SetSetting(ctx, setWorkers, strconv.Itoa(in.Workers)))
	if err != nil {
		m.fail(w, r, err)
		return
	}
	m.audit(r, "settings", "", fmt.Sprintf("interval=%d workers=%d", in.Interval, in.Workers))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
