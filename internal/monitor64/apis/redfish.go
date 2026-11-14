package apis

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/model"
)

// Redfish (BMCs: iDRAC, iLO, Supermicro, OpenBMC …). Basic-Auth oder Sitzung (X-Auth-Token), Zertifikat meist
// selbstsigniert (Pinning). Je Runde:
//
//	/redfish/v1/                       Dienst-Wurzel (Links)
//	Systems/{id}                       Einschaltzustand, CPU-/RAM-Zustand (system bzw. system:<id>)
//	Chassis/{id}/Thermal               Temperaturen mit den Schwellen des Geraets (temp:<name>), Luefter (fan:<name>)
//	Chassis/{id}/Power                 Netzteile (psu:<name>), Leistungsaufnahme und Redundanz (power)
//	  (ohne Thermal/Power: Chassis/{id}/Sensors bzw. PowerSubsystem/PowerSupplies)
//
// Seltener (StorageEvery, Standard 5 min): Systems/{id}/Storage – Controller (ctrl:<storage>), Laufwerke
// (disk:<seriennummer>) und Volumes (raid:<storage>/<volume>); aeltere BMCs: SimpleStorage (Controller und Geraete). Ereignis-Logs werden nicht gelesen (Formate je
// Hersteller; der Zustand der Bauteile deckt Fehler ab). IPMI (RMCP+) gibt es bewusst nicht.
//
// Hersteller unterscheiden sich: fehlende Felder und Links bedeuten "nicht vorhanden", kein Fehler. Zustand: Health
// Warning -> device_warn, Critical -> device_crit (Laufwerke smart_failed/disk_errors, Volumes raid_degraded).

// RedfishConfig sind die Verbindungsdaten eines BMC.
type RedfishConfig struct {
	Address      string        // https://bmc[:443]
	User         string        // Benutzer (Rolle ReadOnly genuegt)
	Password     string        // Geheimnis (nie ausgeben)
	Pin          string        // SHA-256 des Zertifikats (hex); leer = System-CA
	Session      bool          // Sitzung (X-Auth-Token) statt Basic-Auth bei jeder Anfrage
	Timeout      time.Duration // ganze Runde (0 = DefaultTimeout)
	StorageEvery time.Duration // Controller, Laufwerke, Volumes (0 = 5 min)
}

const (
	rfStorageEvery = 5 * time.Minute
	rfMaxMembers   = 64 // Eintraege je Sammlung hoechstens
	rfMaxSensors   = 64 // Sensors-Sammlung (ein Abruf je Sensor) hoechstens
	rfMaxPath      = 512
)

// Redfish ist der Sammler eines BMC.
type Redfish struct {
	cfg RedfishConfig
	wc  *webClient
	now func() time.Time

	// slash: der BMC fuehrt seine Ressourcen unter dem Pfad mit Schraegstrich am Ende und leitet die Form ohne um
	// (HPE iLO 4, #141) – nach der ersten Weiterleitung haengt der Sammler ihn selbst an.
	slash atomic.Bool

	mu       sync.Mutex
	storAt   time.Time
	stor     []model.Service
	loginMu  sync.Mutex // eine Anmeldung zur Zeit (sonst mehrere Sitzungen auf dem BMC)
	loginErr error      // letzte gescheiterte Anmeldung (unter loginMu)
	tokMu    sync.Mutex
	token    string // Sitzung: X-Auth-Token
	session  string // Sitzung: Pfad zum Abmelden
}

// NewRedfish baut den Sammler (prueft Adresse, Zugangsdaten und Pin; fragt noch nichts ab).
func NewRedfish(cfg RedfishConfig) (*Redfish, error) { return newRedfish(cfg, nil) }

func newRedfish(cfg RedfishConfig, roots *x509.CertPool) (*Redfish, error) {
	t, err := parseWebAddr(rfBaseAddr(cfg.Address), "https", "443", false)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.User) == "" || cfg.Password == "" {
		return nil, errors.New(model.T("monitor64.txt.cred_required"))
	}
	if strings.ContainsAny(cfg.User, "\r\n:") || strings.ContainsAny(cfg.Password, "\r\n") {
		return nil, errors.New(model.T("monitor64.txt.cred_invalid"))
	}
	wc, err := newWebClient(t, cfg.Pin, roots)
	if err != nil {
		return nil, err
	}
	r := &Redfish{cfg: cfg, wc: wc, now: time.Now}
	wc.header = func(h http.Header) {
		h.Set("OData-Version", "4.0")
		if tok := r.tok(); tok != "" {
			h.Set("X-Auth-Token", tok)
			return
		}
		if !cfg.Session {
			req := http.Request{Header: h}
			req.SetBasicAuth(strings.TrimSpace(cfg.User), cfg.Password)
		}
	}
	return r, nil
}

func (r *Redfish) tok() string {
	r.tokMu.Lock()
	defer r.tokMu.Unlock()
	return r.token
}

func (r *Redfish) timeout() time.Duration {
	if r.cfg.Timeout > 0 {
		return r.cfg.Timeout
	}
	return DefaultTimeout
}

func (r *Redfish) secrets() []string { return []string{r.cfg.Password, r.tok()} }

// Queries nennt die Pfade ("Was wird abgefragt?").
func (r *Redfish) Queries() []string {
	q := []string{"GET /redfish/v1/", "GET Systems, Systems/{id}", "GET Chassis/{id}, Chassis/{id}/Thermal, Chassis/{id}/Power",
		"GET Chassis/{id}/Sensors, PowerSubsystem/PowerSupplies (ohne Thermal/Power)",
		"GET Systems/{id}/Storage/{id}, Drives/{id}, Volumes/{id} (alle 5 min)"}
	if r.cfg.Session {
		q = append([]string{"POST/DELETE SessionService/Sessions (Sitzung)"}, q...)
	}
	return q
}

// rfLink ist ein Verweis ({"@odata.id": "/redfish/v1/…"}).
type rfLink struct {
	ID string `json:"@odata.id"`
}

// rfStatus ist der Zustand eines Bauteils.
type rfStatus struct {
	State        string `json:"State"`
	Health       string `json:"Health"`
	HealthRollup string `json:"HealthRollup"`
}

func (s rfStatus) absent() bool { return strings.EqualFold(s.State, "Absent") }

// rfSev: 0 ok/unbekannt, 1 Warning, 2 Critical.
func rfSev(h string) int {
	switch strings.ToLower(strings.TrimSpace(h)) {
	case "warning":
		return 1
	case "critical":
		return 2
	}
	return 0
}

// rfPath prueft einen Pfad vom Geraet: nur unterhalb von /redfish/v1/ auf demselben Host.
func rfPath(p string) (string, bool) {
	p = strings.TrimSpace(p)
	if u, err := url.Parse(p); err == nil && u.IsAbs() {
		p = u.EscapedPath() // manche BMCs liefern absolute URLs; der Host zaehlt nicht
	}
	if p == "" || len(p) > rfMaxPath || !strings.HasPrefix(p, "/redfish/v1") || strings.Contains(p, "..") ||
		strings.Contains(strings.ToLower(p), "%2e") ||
		strings.ContainsAny(p, "?#\\ \r\n") {
		return "", false
	}
	return strings.TrimRight(p, "/"), true
}

// rfBaseAddr: eine Adresse mit Pfad unter /redfish (wie sie im Browser steht, z. B.
// https://10.1.15.17/redfish/v1/Systems/) gilt als Adresse des BMC – die Pfade kennt der Sammler (#141).
func rfBaseAddr(raw string) string {
	s := strings.TrimSpace(raw)
	start := 0
	if i := strings.Index(s, "://"); i >= 0 {
		start = i + 3
	}
	if j := strings.Index(s[start:], "/"); j >= 0 && strings.HasPrefix(strings.ToLower(s[start+j:]), "/redfish") {
		return s[:start+j]
	}
	return s
}

// rfFull: Pfad fuer die Anfrage (mit Schraegstrich, wenn der BMC ihn verlangt).
func (r *Redfish) rfFull(p string) string {
	if p == "/redfish/v1" || (r.slash.Load() && !strings.HasSuffix(p, "/")) {
		return p + "/"
	}
	return p
}

// rfRedirect: Ziel einer Weiterleitung, wenn es auf denselben BMC unter /redfish/v1 zeigt ("" = nicht folgen; die
// Zugangsdaten gehoeren nur der eingerichteten Adresse).
func (r *Redfish) rfRedirect(err error, h http.Header) string {
	var we *webError
	if !errors.As(err, &we) || h == nil {
		return ""
	}
	switch we.Status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
	default:
		return ""
	}
	base, err1 := url.Parse(r.wc.t.base)
	loc, err2 := url.Parse(strings.TrimSpace(h.Get("Location")))
	if err1 != nil || err2 != nil {
		return ""
	}
	to := base.ResolveReference(loc)
	port := func(u *url.URL) string {
		if p := u.Port(); p != "" {
			return p
		}
		if u.Scheme == "http" {
			return "80"
		}
		return "443"
	}
	if !strings.EqualFold(to.Scheme, base.Scheme) || !strings.EqualFold(to.Hostname(), base.Hostname()) || port(to) != port(base) ||
		to.RawQuery != "" || to.User != nil {
		return ""
	}
	p, ok := rfPath(to.EscapedPath())
	if !ok {
		return ""
	}
	if strings.HasSuffix(to.EscapedPath(), "/") {
		p += "/"
	}
	return p
}

// send stellt eine Anfrage und folgt einer Weiterleitung auf denselben BMC einmal (GET immer, sonst nur 307/308,
// die Methode und Inhalt behalten). Zeigt sie nur auf den Pfad mit Schraegstrich, gilt das fuer alle weiteren.
func (r *Redfish) send(ctx context.Context, method, p string, hdr http.Header, body, out any) (http.Header, error) {
	h, err := r.wc.do(ctx, method, p, hdr, body, out)
	to := r.rfRedirect(err, h)
	var we *webError
	if to == "" || to == p || (method != http.MethodGet && errors.As(err, &we) && we.Status != http.StatusTemporaryRedirect && we.Status != http.StatusPermanentRedirect) {
		return h, err
	}
	if to == p+"/" {
		r.slash.Store(true)
	}
	return r.wc.do(ctx, method, to, hdr, body, out)
}

// get liest einen Pfad (vom Geraet geliefert oder fest); bei abgelaufener Sitzung einmal neu anmelden.
func (r *Redfish) get(ctx context.Context, path string, out any) error {
	p, ok := rfPath(path)
	if !ok {
		return &webError{Kind: errWebResp, Detail: model.T("monitor64.txt.bad_link") + " " + devText(path), Where: "GET"}
	}
	stale := r.tok()
	_, err := r.send(ctx, http.MethodGet, r.rfFull(p), nil, nil, out)
	if r.cfg.Session && stale != "" && errors.Is(err, errWebAuth) {
		if lerr := r.login(ctx, stale); lerr != nil {
			return lerr
		}
		_, err = r.send(ctx, http.MethodGet, r.rfFull(p), nil, nil, out)
	}
	return err
}

// login meldet eine Sitzung an, wenn noch keine besteht bzw. die bisherige (stale) abgelaufen ist; meldet sich
// inzwischen eine andere Anfrage neu an, gilt deren Sitzung. Das alte Token bleibt bis zur erfolgreichen Anmeldung
// stehen: gleichzeitige Anfragen gehen nie ohne Anmeldung hinaus, sondern warten nach ihrem 401 hier. Scheitert die
// Neuanmeldung, bekommen die wartenden Anfragen denselben Fehler, statt sich jede fuer sich erneut anzumelden.
func (r *Redfish) login(ctx context.Context, stale string) error {
	r.loginMu.Lock()
	defer r.loginMu.Unlock()
	cur := r.tok()
	switch {
	case cur != "" && cur != stale:
		return nil
	case cur == "" && stale != "": // Neuanmeldung einer anderen Anfrage gescheitert bzw. abgemeldet
		if r.loginErr != nil {
			return r.loginErr
		}
		return &webError{Kind: errWebAuth, Detail: model.T("monitor64.txt.session_ended"), Where: "POST SessionService/Sessions"}
	}
	body := map[string]string{"UserName": strings.TrimSpace(r.cfg.User), "Password": r.cfg.Password}
	// ohne das abgelaufene Token (manche BMCs lehnen eine Anmeldung mit ungueltigem X-Auth-Token ab)
	h, err := r.send(ctx, http.MethodPost, r.rfFull("/redfish/v1/SessionService/Sessions"), http.Header{"X-Auth-Token": nil}, body, nil)
	if err == nil {
		tok := strings.TrimSpace(h.Get("X-Auth-Token"))
		if tok != "" && len(tok) <= 4096 && !strings.ContainsAny(tok, "\r\n") {
			sess, _ := rfPath(h.Get("Location"))
			r.loginErr = nil
			r.setTok(tok, sess)
			return nil
		}
		err = &webError{Kind: errWebResp, Detail: model.T("monitor64.txt.login_no_token"), Where: "POST SessionService/Sessions"}
	}
	r.loginErr = err
	r.setTok("", "")
	return err
}

func (r *Redfish) setTok(tok, sess string) {
	r.tokMu.Lock()
	r.token, r.session = tok, sess
	r.tokMu.Unlock()
}

// Close meldet eine offene Sitzung ab und gibt Verbindungen frei.
func (r *Redfish) Close() {
	r.tokMu.Lock()
	sess := r.session
	has := r.token != ""
	r.tokMu.Unlock()
	if has && sess != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, _ = r.send(ctx, http.MethodDelete, r.rfFull(sess), nil, nil, nil)
		cancel()
	}
	r.tokMu.Lock()
	r.token, r.session = "", ""
	r.tokMu.Unlock()
	r.wc.close()
}

// hint ergaenzt Anmelde- und Rechtefehler.
func (r *Redfish) hint(err error) error {
	switch {
	case errors.Is(err, errWebAuth):
		return fmt.Errorf("%w – %s", err, model.T("monitor64.txt.rf_hint_auth"))
	case errors.Is(err, errWebPerm):
		return fmt.Errorf("%w – %s", err, model.T("monitor64.txt.rf_hint_perm"))
	}
	return err
}

// rfRoot ist die Dienst-Wurzel.
type rfRoot struct {
	RedfishVersion string `json:"RedfishVersion"`
	Vendor         string `json:"Vendor"`
	Product        string `json:"Product"`
	Systems        rfLink `json:"Systems"`
	Chassis        rfLink `json:"Chassis"`
}

type rfCollection struct {
	Members []rfLink `json:"Members"`
}

// members liest eine Sammlung (hoechstens max Eintraege, nur gueltige Verweise).
func (r *Redfish) members(ctx context.Context, path string, max int) ([]string, error) {
	var c rfCollection
	if err := r.get(ctx, path, &c); err != nil {
		return nil, err
	}
	var out []string
	for _, m := range c.Members {
		if p, ok := rfPath(m.ID); ok && len(out) < max {
			out = append(out, p)
		}
	}
	return out, nil
}

// rfSystem ist der benutzte Teil eines Systems.
type rfSystem struct {
	ID           string   `json:"Id"`
	Name         string   `json:"Name"`
	HostName     string   `json:"HostName"`
	Manufacturer string   `json:"Manufacturer"`
	Model        string   `json:"Model"`
	Serial       string   `json:"SerialNumber"`
	BIOS         string   `json:"BiosVersion"`
	PowerState   string   `json:"PowerState"`
	Status       rfStatus `json:"Status"`
	Proc         struct {
		Count  optF      `json:"Count"`
		Model  string    `json:"Model"`
		Status *rfStatus `json:"Status"`
	} `json:"ProcessorSummary"`
	Mem struct {
		GiB    optF      `json:"TotalSystemMemoryGiB"`
		Status *rfStatus `json:"Status"`
	} `json:"MemorySummary"`
	Storage rfLink `json:"Storage"`
	Simple  rfLink `json:"SimpleStorage"` // aeltere BMCs ohne Storage
}

// Test prueft die Verbindung im Assistenten (Zertifikat, Anmeldung, Systeme).
func (r *Redfish) Test(ctx context.Context) TestResult {
	ctx, cancel := context.WithTimeout(ctx, r.timeout())
	defer cancel()
	res, proceed := probeCert(ctx, r.wc.t, r.wc.pin, r.wc.roots)
	if !proceed {
		return res
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	fail := func(err error) TestResult {
		res.Error = scrub(r.hint(err).Error(), r.secrets()...)
		return res
	}
	var root rfRoot
	if err := r.get(ctx, "/redfish/v1/", &root); err != nil {
		return fail(err)
	}
	res.Version = shortText(strings.TrimSpace(strings.Join([]string{root.Vendor, root.Product, "Redfish " + root.RedfishVersion}, " ")))
	if r.cfg.Session {
		if err := r.login(ctx, ""); err != nil {
			return fail(err)
		}
	}
	sys, err := r.members(ctx, firstNonEmpty(root.Systems.ID, "/redfish/v1/Systems"), rfMaxMembers)
	if err != nil {
		return fail(err)
	}
	res.OK = true
	if len(sys) == 0 {
		res.Warning = model.T("monitor64.txt.rf_no_system")
		return res
	}
	var s rfSystem
	if err := r.get(ctx, sys[0], &s); err != nil {
		res.Warning = scrub(r.hint(err).Error(), r.secrets()...)
		return res
	}
	res.Node = shortText(s.HostName)
	res.Summary = devText(strings.TrimSpace(s.Manufacturer+" "+s.Model)) + " (" + rfPower(s.PowerState) + ")"
	if len(sys) > 1 {
		res.Summary += ", " + model.T("monitor64.txt.systems_n", "n", len(sys))
	}
	return res
}

func rfPower(s string) string {
	return stateText(map[string]string{"On": "monitor64.txt.on", "Off": "monitor64.txt.off", "PoweringOn": "monitor64.txt.powering_on",
		"PoweringOff": "monitor64.txt.shutting_down", "Paused": "monitor64.txt.paused"}, s)
}

// Collect ist eine Abfragerunde (nicht gleichzeitig mit sich selbst aufrufen).
func (r *Redfish) Collect(ctx context.Context) ([]model.Service, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, r.timeout())
	defer cancel()
	now := r.now()
	var root rfRoot
	if err := r.get(ctx, "/redfish/v1/", &root); err != nil {
		return nil, scrubErr(r.hint(err), r.secrets()...)
	}
	if r.cfg.Session {
		if err := r.login(ctx, ""); err != nil {
			return nil, scrubErr(r.hint(err), r.secrets()...)
		}
	}
	sysPaths, err := r.members(ctx, firstNonEmpty(root.Systems.ID, "/redfish/v1/Systems"), rfMaxMembers)
	if err != nil {
		return nil, scrubErr(r.hint(err), r.secrets()...)
	}
	part := &partial{secrets: r.secrets()}
	add := func(what string, err error, prefixes ...string) { part.add(what, r.hint(err), prefixes...) }
	var out []model.Service
	var systems []rfSystem
	for _, p := range sysPaths {
		var s rfSystem
		if err := r.get(ctx, p, &s); err != nil {
			// ohne das System fehlen auch seine Controller, Laufwerke und Volumes (storage liest es nicht)
			add(p, err, "system", "ctrl:", "disk:", "raid:")
			continue
		}
		systems = append(systems, s)
	}
	for _, s := range systems {
		key := "system"
		if len(sysPaths) > 1 {
			key += ":" + firstNonEmpty(s.ID, s.Name)
		}
		out = append(out, rfSystemService(key, s))
	}
	out = append(out, r.chassis(ctx, firstNonEmpty(root.Chassis.ID, "/redfish/v1/Chassis"), add)...)
	out = append(out, r.storage(ctx, now, systems, len(systems) == len(sysPaths), add)...)
	return out, part.result()
}

// rfSystemService: Einschaltzustand und Zustand von CPU und RAM (der Gesamtzustand des Systems steht nur im Text,
// er fasst die einzelnen Bauteile zusammen, die eigene Dienste haben).
func rfSystemService(key string, s rfSystem) model.Service {
	name := "System"
	if m := strings.TrimSpace(s.Manufacturer + " " + s.Model); m != "" {
		name += " " + shortText(m)
	}
	if strings.HasPrefix(key, "system:") {
		name += " (" + shortText(firstNonEmpty(s.ID, s.Name)) + ")"
	}
	sv := model.Service{Key: key, Name: model.Raw(name), Kind: "system", Default: true}
	on := 0.0
	if s.PowerState == "On" {
		on = 1
	}
	sv.Metrics = []model.Metric{{Name: "power_on", Value: on}}
	parts := []string{rfPower(s.PowerState)}
	if h := firstNonEmpty(s.Status.HealthRollup, s.Status.Health); h != "" {
		parts = append(parts, model.T("monitor64.txt.health_v", "v", shortText(h)))
	}
	if s.Proc.Count.Set && s.Proc.Count.V > 0 {
		parts = append(parts, fmt.Sprintf("%.0f CPU", s.Proc.Count.V))
	}
	if s.Mem.GiB.Set && s.Mem.GiB.V > 0 {
		parts = append(parts, fmt.Sprintf("%.0f GiB RAM", s.Mem.GiB.V))
	}
	if s.BIOS != "" {
		parts = append(parts, "BIOS "+devText(s.BIOS))
	}
	var warn, crit []string
	note := func(what string, st *rfStatus) {
		if st == nil {
			return
		}
		h := firstNonEmpty(st.HealthRollup, st.Health)
		switch rfSev(h) {
		case 1:
			warn = append(warn, what+" "+model.Raw(h))
		case 2:
			crit = append(crit, what+" "+model.Raw(h))
		}
	}
	note("CPU", s.Proc.Status)
	note("RAM", s.Mem.Status)
	if s.Proc.Status == nil && s.Mem.Status == nil {
		st := s.Status
		note("System", &st) // ohne Teilzustaende: Gesamtzustand
	}
	if len(crit) > 0 {
		sv.Facts = append(sv.Facts, model.Fact{Code: "device_crit", Text: strings.Join(crit, ", ")})
	}
	if len(warn) > 0 {
		sv.Facts = append(sv.Facts, model.Fact{Code: "device_warn", Text: strings.Join(warn, ", ")})
	}
	sv.Text = strings.Join(parts, " · ")
	return sv
}

// rfChassis ist der benutzte Teil eines Chassis.
type rfChassis struct {
	ID       string `json:"Id"`
	Thermal  rfLink `json:"Thermal"`
	Power    rfLink `json:"Power"`
	Sensors  rfLink `json:"Sensors"`
	PowerSub rfLink `json:"PowerSubsystem"`
}

type rfTemp struct {
	Name     string   `json:"Name"`
	MemberID string   `json:"MemberId"`
	Reading  optF     `json:"ReadingCelsius"`
	Warn     optF     `json:"UpperThresholdNonCritical"`
	Crit     optF     `json:"UpperThresholdCritical"`
	Fatal    optF     `json:"UpperThresholdFatal"`
	Status   rfStatus `json:"Status"`
}

type rfFan struct {
	Name     string   `json:"Name"`
	FanName  string   `json:"FanName"`
	MemberID string   `json:"MemberId"`
	Reading  optF     `json:"Reading"`
	Units    string   `json:"ReadingUnits"`
	LowWarn  optF     `json:"LowerThresholdNonCritical"`
	LowCrit  optF     `json:"LowerThresholdCritical"`
	LowFatal optF     `json:"LowerThresholdFatal"`
	Status   rfStatus `json:"Status"`
}

type rfRedundancy struct {
	Name   string   `json:"Name"`
	Mode   string   `json:"Mode"`
	Status rfStatus `json:"Status"`
}

type rfPSU struct {
	Name      string   `json:"Name"`
	MemberID  string   `json:"MemberId"`
	ID        string   `json:"Id"`
	Model     string   `json:"Model"`
	InWatts   optF     `json:"PowerInputWatts"`
	OutWatts  optF     `json:"LastPowerOutputWatts"`
	Capacity  optF     `json:"PowerCapacityWatts"`
	LineVolts optF     `json:"LineInputVoltage"`
	Status    rfStatus `json:"Status"`
}

// rfSensor ist ein Eintrag aus Chassis/{id}/Sensors (neueres Schema).
type rfSensor struct {
	ID         string   `json:"Id"`
	Name       string   `json:"Name"`
	Type       string   `json:"ReadingType"`
	Reading    optF     `json:"Reading"`
	Units      string   `json:"ReadingUnits"`
	Status     rfStatus `json:"Status"`
	Thresholds struct {
		UpperCaution  struct{ Reading optF } `json:"UpperCaution"`
		UpperCritical struct{ Reading optF } `json:"UpperCritical"`
		UpperFatal    struct{ Reading optF } `json:"UpperFatal"`
		LowerCritical struct{ Reading optF } `json:"LowerCritical"`
	} `json:"Thresholds"`
}

// rfItem ist ein gesammelter Sensor bzw. Bauteil vor der Vergabe der Schluessel.
type rfItem struct {
	chassis string
	name    string
	svc     model.Service
}

// chassis: Temperaturen, Luefter, Netzteile und Leistung aller Chassis.
func (r *Redfish) chassis(ctx context.Context, path string, add func(string, error, ...string)) []model.Service {
	paths, err := r.members(ctx, path, rfMaxMembers)
	if err != nil {
		add("Chassis", err, "temp:", "fan:", "psu:", "power")
		return nil
	}
	var temps, fans, psus, powers []rfItem
	for _, cp := range paths {
		var ch rfChassis
		if err := r.get(ctx, cp, &ch); err != nil {
			add(cp, err, "temp:", "fan:", "psu:", "power")
			continue
		}
		cid := firstNonEmpty(ch.ID, cp[strings.LastIndex(cp, "/")+1:])
		switch {
		case ch.Thermal.ID != "":
			var th struct {
				Temperatures []rfTemp       `json:"Temperatures"`
				Fans         []rfFan        `json:"Fans"`
				Redundancy   []rfRedundancy `json:"Redundancy"`
			}
			if err := r.get(ctx, ch.Thermal.ID, &th); err != nil {
				add(ch.Thermal.ID, err, "temp:", "fan:")
				break
			}
			for _, t := range th.Temperatures {
				if it, ok := rfTempItem(cid, t.Name, t.MemberID, t.Reading, t.Warn, t.Crit, t.Fatal, t.Status); ok {
					temps = append(temps, it)
				}
			}
			for _, f := range th.Fans {
				if it, ok := rfFanItem(cid, firstNonEmpty(f.Name, f.FanName, f.MemberID), f.Reading, f.Units, f.LowWarn, f.LowCrit, f.LowFatal, f.Status); ok {
					fans = append(fans, it)
				}
			}
		case ch.Sensors.ID != "":
			t, f := r.sensors(ctx, cid, ch.Sensors.ID, add)
			temps, fans = append(temps, t...), append(fans, f...)
		}
		switch {
		case ch.Power.ID != "":
			var pw struct {
				Control []struct {
					Consumed optF `json:"PowerConsumedWatts"`
				} `json:"PowerControl"`
				Supplies   []rfPSU        `json:"PowerSupplies"`
				Redundancy []rfRedundancy `json:"Redundancy"`
			}
			if err := r.get(ctx, ch.Power.ID, &pw); err != nil {
				add(ch.Power.ID, err, "psu:", "power")
				break
			}
			for _, p := range pw.Supplies {
				if it, ok := rfPSUItem(cid, p); ok {
					psus = append(psus, it)
				}
			}
			var watts optF
			if len(pw.Control) > 0 {
				watts = pw.Control[0].Consumed
			}
			if it, ok := rfPowerItem(cid, watts, pw.Redundancy); ok {
				powers = append(powers, it)
			}
		case ch.PowerSub.ID != "":
			psus = append(psus, r.powerSubsystem(ctx, cid, ch.PowerSub.ID, add)...)
		}
	}
	// Schluessel mit Chassis, sobald der BMC mehrere Chassis nennt: das haengt nur an der Liste, nicht daran, welche
	// Chassis in dieser Runde Werte geliefert haben (sonst wechselte der Schluessel bei einem Teilfehler)
	multi := len(paths) > 1
	var out []model.Service
	out = append(out, rfKeys("temp:", temps, multi)...)
	out = append(out, rfKeys("fan:", fans, multi)...)
	out = append(out, rfKeys("psu:", psus, multi)...)
	for _, p := range powers {
		p.svc.Key = "power"
		if multi {
			p.svc.Key += ":" + p.chassis
			p.svc.Name += " (" + model.Raw(p.chassis) + ")"
		}
		out = append(out, p.svc)
	}
	return out
}

// rfKeys vergibt die Schluessel: Name des Sensors; nennt der BMC mehrere Chassis (multi), mit Chassis davor.
func rfKeys(prefix string, items []rfItem, multi bool) []model.Service {
	var out []model.Service
	seen := map[string]bool{}
	for _, it := range items {
		k := prefix + it.name
		if multi {
			k = prefix + it.chassis + "/" + it.name
			it.svc.Name += " (" + model.Raw(it.chassis) + ")"
		}
		if seen[k] {
			continue // gleicher Name im selben Chassis: einmal
		}
		seen[k] = true
		it.svc.Key = k
		out = append(out, it.svc)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// rfHealthFacts haengt die Zustaende aus Health an (Warning -> device_warn, Critical -> device_crit); what ist
// fertiger Text (Dienstname).
func rfHealthFacts(s *model.Service, what string, h string) {
	switch rfSev(h) {
	case 1:
		s.Facts = append(s.Facts, model.Fact{Code: "device_warn", Text: what + ": " + model.T("monitor64.txt.health_v", "v", shortText(h))})
	case 2:
		s.Facts = append(s.Facts, model.Fact{Code: "device_crit", Text: what + ": " + model.T("monitor64.txt.health_v", "v", shortText(h))})
	}
}

// rfTempItem: Temperatur mit den Schwellen des Geraets. Hat das Geraet Schwellen, bewertet Monitor64 nur diese
// (keine Standard-Regel temp.system, die z. B. fuer CPUs zu niedrig waere); sonst gilt temp.system. Ein Sensor ohne
// Wert (z. B. Server ausgeschaltet) bleibt ein Dienst ohne Messgroesse, sonst hiesse er nachts "verschwunden".
func rfTempItem(cid, name, member string, rd, warn, crit, fatal optF, st rfStatus) (rfItem, bool) {
	name = shortText(firstNonEmpty(name, member))
	if name == "" || st.absent() {
		return rfItem{}, false
	}
	s := model.Service{Name: model.T("monitor64.svc.temp", "name", name), Kind: "temp", Default: true}
	var parts []string
	if rd.Set && rd.V > -60 && rd.V < 300 {
		m := model.Metric{Name: "temp", Value: round2(rd.V), Unit: "°C"}
		if !warn.Set && !crit.Set && !fatal.Set {
			m.Rule = model.RuleTemp
		}
		s.Metrics = append(s.Metrics, m)
		parts = append(parts, fmt.Sprintf("%.0f °C", rd.V))
		limit := crit
		if !limit.Set || (fatal.Set && fatal.V < limit.V) {
			limit = fatal
		}
		switch {
		case limit.Set && limit.V > 0 && rd.V >= limit.V:
			s.Facts = append(s.Facts, model.Fact{Code: "device_crit", Text: model.T("monitor64.txt.temp_crit", "name", name, "v", fmt.Sprintf("%.0f", rd.V), "limit", fmt.Sprintf("%.0f", limit.V))})
		case warn.Set && warn.V > 0 && rd.V >= warn.V:
			s.Facts = append(s.Facts, model.Fact{Code: "device_warn", Text: model.T("monitor64.txt.temp_warn", "name", name, "v", fmt.Sprintf("%.0f", rd.V), "limit", fmt.Sprintf("%.0f", warn.V))})
		}
	}
	if len(s.Metrics) == 0 {
		parts = append(parts, model.T("monitor64.txt.no_reading"))
	}
	var th []string
	if warn.Set && warn.V > 0 {
		th = append(th, model.T("monitor64.txt.warn_from", "v", fmt.Sprintf("%.0f", warn.V)))
	}
	if crit.Set && crit.V > 0 {
		th = append(th, model.T("monitor64.txt.crit_from", "v", fmt.Sprintf("%.0f", crit.V)))
	} else if fatal.Set && fatal.V > 0 {
		th = append(th, model.T("monitor64.txt.crit_from", "v", fmt.Sprintf("%.0f", fatal.V)))
	}
	if len(th) > 0 {
		parts = append(parts, model.T("monitor64.txt.device")+": "+strings.Join(th, ", "))
	}
	if len(s.Facts) == 0 {
		rfHealthFacts(&s, model.Raw(name), st.Health)
	}
	s.Text = strings.Join(parts, " · ")
	return rfItem{chassis: cid, name: name, svc: s}, true
}

// rfFanItem: Luefter mit Drehzahl bzw. Prozent und unteren Schwellen des Geraets.
func rfFanItem(cid, name string, rd optF, units string, lowWarn, lowCrit, lowFatal optF, st rfStatus) (rfItem, bool) {
	name = shortText(name)
	if name == "" || st.absent() {
		return rfItem{}, false
	}
	s := model.Service{Name: model.T("monitor64.svc.fan", "name", name), Kind: "fan", Default: true}
	var parts []string
	if rd.Set && rd.V >= 0 {
		if strings.EqualFold(units, "Percent") || units == "%" {
			s.Metrics = append(s.Metrics, model.Metric{Name: "speed", Value: round2(rd.V), Unit: "%"})
			parts = append(parts, fmt.Sprintf("%.0f %%", rd.V))
		} else {
			s.Metrics = append(s.Metrics, model.Metric{Name: "rpm", Value: round2(rd.V), Unit: "rpm"})
			parts = append(parts, model.T("monitor64.txt.rpm", "v", fmt.Sprintf("%.0f", rd.V)))
		}
		limit := lowCrit
		if !limit.Set || (lowFatal.Set && lowFatal.V > limit.V) {
			limit = lowFatal
		}
		switch {
		case limit.Set && limit.V > 0 && rd.V < limit.V:
			s.Facts = append(s.Facts, model.Fact{Code: "device_crit", Text: model.T("monitor64.txt.fan_crit", "name", name, "v", fmt.Sprintf("%.0f", rd.V), "limit", fmt.Sprintf("%.0f", limit.V))})
		case lowWarn.Set && lowWarn.V > 0 && rd.V < lowWarn.V:
			s.Facts = append(s.Facts, model.Fact{Code: "device_warn", Text: model.T("monitor64.txt.fan_warn", "name", name, "v", fmt.Sprintf("%.0f", rd.V), "limit", fmt.Sprintf("%.0f", lowWarn.V))})
		}
	}
	if h := st.Health; h != "" {
		parts = append(parts, model.T("monitor64.txt.health_v", "v", shortText(h)))
	}
	if len(s.Facts) == 0 {
		rfHealthFacts(&s, s.Name, st.Health)
	}
	s.Text = strings.Join(parts, " · ")
	return rfItem{chassis: cid, name: name, svc: s}, true
}

// rfPSUItem: Netzteil mit Zustand, Eingangsleistung und -spannung.
func rfPSUItem(cid string, p rfPSU) (rfItem, bool) {
	name := shortText(firstNonEmpty(p.Name, p.MemberID, p.ID))
	if name == "" || p.Status.absent() {
		return rfItem{}, false
	}
	s := model.Service{Name: model.T("monitor64.svc.psu", "name", name), Kind: "psu", Default: true}
	var parts []string
	if h := p.Status.Health; h != "" {
		parts = append(parts, model.T("monitor64.txt.health_v", "v", shortText(h)))
	}
	if st := p.Status.State; st != "" && st != "Enabled" {
		parts = append(parts, devText(st))
	}
	if w := p.InWatts; w.Set && w.V >= 0 {
		s.Metrics = append(s.Metrics, model.Metric{Name: "watts", Value: round2(w.V), Unit: "W", Max: max(p.Capacity.V, 0)})
		parts = append(parts, fmt.Sprintf("%.0f W", w.V))
	} else if w := p.OutWatts; w.Set && w.V >= 0 {
		s.Metrics = append(s.Metrics, model.Metric{Name: "watts", Value: round2(w.V), Unit: "W", Max: max(p.Capacity.V, 0)})
		parts = append(parts, fmt.Sprintf("%.0f W", w.V))
	}
	if v := p.LineVolts; v.Set && v.V >= 0 {
		s.Metrics = append(s.Metrics, model.Metric{Name: "input_voltage", Value: round2(v.V), Unit: "V"})
		parts = append(parts, model.T("monitor64.txt.input_v", "v", fmt.Sprintf("%.0f", v.V)))
	}
	if p.Model != "" {
		parts = append(parts, devText(p.Model))
	}
	rfHealthFacts(&s, s.Name, p.Status.Health)
	s.Text = strings.Join(parts, " · ")
	return rfItem{chassis: cid, name: name, svc: s}, true
}

// rfPowerItem: Leistungsaufnahme und Redundanz der Netzteile.
func rfPowerItem(cid string, watts optF, red []rfRedundancy) (rfItem, bool) {
	s := model.Service{Name: model.T("monitor64.svc.power"), Kind: "power", Default: true}
	var parts []string
	if watts.Set && watts.V >= 0 {
		s.Metrics = append(s.Metrics, model.Metric{Name: "watts", Value: round2(watts.V), Unit: "W"})
		parts = append(parts, fmt.Sprintf("%.0f W", watts.V))
	}
	for _, rd := range red {
		if rd.Status.absent() {
			continue
		}
		n := model.T("monitor64.txt.redundancy")
		if rd.Name != "" {
			n = devText(rd.Name)
		}
		t := n
		if rd.Mode != "" {
			t += " (" + devText(rd.Mode) + ")"
		}
		h := firstNonEmpty(rd.Status.Health, rd.Status.HealthRollup)
		switch {
		case rfSev(h) > 0:
			parts = append(parts, t+": "+model.Raw(h))
			code := "device_warn"
			if rfSev(h) == 2 {
				code = "device_crit"
			}
			s.Facts = append(s.Facts, model.Fact{Code: code, Text: n + " " + model.T("monitor64.txt.lost_h", "v", h)})
		case h != "":
			parts = append(parts, t+": "+model.Raw(h))
		}
	}
	if len(s.Metrics) == 0 && len(parts) == 0 {
		return rfItem{}, false
	}
	s.Text = strings.Join(parts, " · ")
	return rfItem{chassis: cid, svc: s}, true
}

// sensors: Temperaturen und Luefter aus der Sensors-Sammlung (Geraete ohne Thermal).
func (r *Redfish) sensors(ctx context.Context, cid, path string, add func(string, error, ...string)) (temps, fans []rfItem) {
	paths, err := r.members(ctx, path, rfMaxSensors)
	if err != nil {
		add(path, err, "temp:", "fan:")
		return nil, nil
	}
	list := make([]*rfSensor, len(paths))
	idx := make([]int, len(paths))
	for i := range idx {
		idx[i] = i
	}
	var mu sync.Mutex
	var errs int
	var first error
	runParallel(ctx, idx, func(ctx context.Context, i int) {
		var s rfSensor
		err := r.get(ctx, paths[i], &s)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			errs++
			if first == nil {
				first = err
			}
			return
		}
		list[i] = &s
	})
	if errs > 0 {
		add(fmt.Sprintf("Sensors (%d)", errs), first, "temp:", "fan:")
	}
	for _, s := range list {
		if s == nil {
			continue
		}
		t := s.Thresholds
		switch strings.ToLower(s.Type) {
		case "temperature":
			if it, ok := rfTempItem(cid, s.Name, s.ID, s.Reading, t.UpperCaution.Reading, t.UpperCritical.Reading, t.UpperFatal.Reading, s.Status); ok {
				temps = append(temps, it)
			}
		case "rotational", "percent":
			if strings.Contains(strings.ToLower(s.Name+" "+s.ID), "fan") {
				if it, ok := rfFanItem(cid, firstNonEmpty(s.Name, s.ID), s.Reading, s.Units, optF{}, t.LowerCritical.Reading, optF{}, s.Status); ok {
					fans = append(fans, it)
				}
			}
		}
	}
	return temps, fans
}

// powerSubsystem: Netzteile aus PowerSubsystem/PowerSupplies (neueres Schema).
func (r *Redfish) powerSubsystem(ctx context.Context, cid, path string, add func(string, error, ...string)) []rfItem {
	var ps struct {
		Supplies rfLink `json:"PowerSupplies"`
	}
	if err := r.get(ctx, path, &ps); err != nil {
		add(path, err, "psu:")
		return nil
	}
	if ps.Supplies.ID == "" {
		return nil
	}
	paths, err := r.members(ctx, ps.Supplies.ID, rfMaxMembers)
	if err != nil {
		add(ps.Supplies.ID, err, "psu:")
		return nil
	}
	var out []rfItem
	for _, p := range paths {
		var x struct {
			rfPSU
			Metrics rfLink `json:"Metrics"`
		}
		if err := r.get(ctx, p, &x); err != nil {
			add(p, err, "psu:")
			continue
		}
		if it, ok := rfPSUItem(cid, x.rfPSU); ok {
			out = append(out, it)
		}
	}
	return out
}

// rfStorage ist ein Eintrag aus Systems/{id}/Storage.
type rfStorage struct {
	ID          string   `json:"Id"`
	Name        string   `json:"Name"`
	Status      rfStatus `json:"Status"`
	Controllers []struct {
		Name     string   `json:"Name"`
		Model    string   `json:"Model"`
		Firmware string   `json:"FirmwareVersion"`
		Status   rfStatus `json:"Status"`
	} `json:"StorageControllers"`
	Drives  []rfLink `json:"Drives"`
	Volumes rfLink   `json:"Volumes"`
}

type rfDrive struct {
	ID        string   `json:"Id"`
	Name      string   `json:"Name"`
	Model     string   `json:"Model"`
	Serial    string   `json:"SerialNumber"`
	Capacity  optF     `json:"CapacityBytes"`
	Media     string   `json:"MediaType"`
	Protocol  string   `json:"Protocol"`
	Predicted *bool    `json:"FailurePredicted"`
	LifeLeft  optF     `json:"PredictedMediaLifeLeftPercent"`
	Status    rfStatus `json:"Status"`
}

type rfVolume struct {
	ID         string   `json:"Id"`
	Name       string   `json:"Name"`
	RAIDType   string   `json:"RAIDType"`
	VolumeType string   `json:"VolumeType"`
	Capacity   optF     `json:"CapacityBytes"`
	Status     rfStatus `json:"Status"`
	Operations []struct {
		Name string `json:"OperationName"`
		Pct  optF   `json:"PercentageComplete"`
	} `json:"Operations"`
}

// storage: Controller, Laufwerke und Volumes alle StorageEvery; Fehler lassen den vorigen Stand stehen.
func (r *Redfish) storage(ctx context.Context, now time.Time, systems []rfSystem, allSystems bool, add func(string, error, ...string)) []model.Service {
	every := r.cfg.StorageEvery
	if every <= 0 {
		every = rfStorageEvery
	}
	if !r.storAt.IsZero() && now.Sub(r.storAt) < every {
		return r.stor
	}
	var out []model.Service
	ok := allSystems
	var drives []rfDrive
	var driveStore []string
	for _, s := range systems {
		if s.Storage.ID == "" {
			if s.Simple.ID != "" { // aeltere BMCs: SimpleStorage (Controller mit Geraeten, ohne Volumes)
				ctrls, devs, sids, good := r.simpleStorage(ctx, s.Simple.ID, add)
				out = append(out, ctrls...)
				drives, driveStore = append(drives, devs...), append(driveStore, sids...)
				ok = ok && good
			}
			continue
		}
		paths, err := r.members(ctx, s.Storage.ID, rfMaxMembers)
		if err != nil {
			if !webAbsent(err) {
				add(s.Storage.ID, err, "disk:", "raid:", "ctrl:")
				ok = false
			}
			continue
		}
		for _, sp := range paths {
			var st rfStorage
			if err := r.get(ctx, sp, &st); err != nil {
				add(sp, err, "disk:", "raid:", "ctrl:")
				ok = false
				continue
			}
			sid := firstNonEmpty(st.ID, sp[strings.LastIndex(sp, "/")+1:])
			if svc, has := rfControllerService(sid, st); has {
				out = append(out, svc)
			}
			// Laufwerke parallel (BMCs antworten langsam)
			var links []string
			for _, d := range st.Drives {
				if p, valid := rfPath(d.ID); valid && len(links) < rfMaxMembers {
					links = append(links, p)
				}
			}
			got := make([]*rfDrive, len(links))
			idx := make([]int, len(links))
			for i := range idx {
				idx[i] = i
			}
			var mu sync.Mutex
			var errs int
			var first error
			runParallel(ctx, idx, func(ctx context.Context, i int) {
				var d rfDrive
				err := r.get(ctx, links[i], &d)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					errs++
					if first == nil {
						first = err
					}
					return
				}
				got[i] = &d
			})
			if errs > 0 {
				add(fmt.Sprintf("Drives %s (%d)", model.Raw(sid), errs), first, "disk:")
				ok = false
			}
			for _, d := range got {
				if d != nil && !d.Status.absent() {
					drives = append(drives, *d)
					driveStore = append(driveStore, sid)
				}
			}
			if st.Volumes.ID != "" {
				vols, err := r.members(ctx, st.Volumes.ID, rfMaxMembers)
				if err != nil && !webAbsent(err) {
					add(st.Volumes.ID, err, "raid:"+sid+"/")
					ok = false
				}
				for _, vp := range vols {
					var v rfVolume
					if err := r.get(ctx, vp, &v); err != nil {
						add(vp, err, "raid:"+sid+"/")
						ok = false
						continue
					}
					out = append(out, rfVolumeService(sid, v))
				}
			}
		}
	}
	entries := make([]diskEntry, len(drives))
	for i, d := range drives {
		entries[i] = diskEntry{Name: driveStore[i] + "/" + firstNonEmpty(d.ID, d.Name), Serial: d.Serial}
	}
	keys := diskKeys(entries)
	seen := map[string]bool{}
	for i, d := range drives {
		if seen[keys[i]] {
			continue
		}
		seen[keys[i]] = true
		out = append(out, rfDriveService(keys[i], d))
	}
	sortServices(out)
	// Teilfehler: vorigen Stand der betroffenen Dienste nicht verlieren (der Kern haelt sie ueber die Praefixe);
	// erst ein vollstaendiger Durchlauf gilt als neuer Stand fuer die naechsten Runden
	if ok {
		r.storAt, r.stor = now, out
	} else {
		r.storAt = time.Time{}
	}
	return out
}

// simpleStorage liest SimpleStorage: Controller-Dienste und die Geraete als Laufwerke (ohne Seriennummer: Schluessel
// aus Controller und Platz).
func (r *Redfish) simpleStorage(ctx context.Context, path string, add func(string, error, ...string)) (ctrls []model.Service, devs []rfDrive, sids []string, ok bool) {
	paths, err := r.members(ctx, path, rfMaxMembers)
	if err != nil {
		if webAbsent(err) {
			return nil, nil, nil, true
		}
		add(path, err, "disk:", "ctrl:")
		return nil, nil, nil, false
	}
	ok = true
	for _, sp := range paths {
		var ss struct {
			ID      string   `json:"Id"`
			Name    string   `json:"Name"`
			Desc    string   `json:"Description"`
			Status  rfStatus `json:"Status"`
			Devices []struct {
				Name     string   `json:"Name"`
				Model    string   `json:"Model"`
				Capacity optF     `json:"CapacityBytes"`
				Status   rfStatus `json:"Status"`
			} `json:"Devices"`
		}
		if err := r.get(ctx, sp, &ss); err != nil {
			add(sp, err, "disk:", "ctrl:")
			ok = false
			continue
		}
		sid := firstNonEmpty(ss.ID, sp[strings.LastIndex(sp, "/")+1:])
		name := ss.Name
		if ss.Desc != "" {
			name = strings.TrimSpace(name + " " + ss.Desc)
		}
		if svc, has := rfControllerService(sid, rfStorage{ID: sid, Name: name, Status: ss.Status}); has {
			ctrls = append(ctrls, svc)
		}
		for i, d := range ss.Devices {
			if d.Status.absent() || i >= rfMaxMembers {
				continue
			}
			n := firstNonEmpty(d.Name, fmt.Sprintf("Device %d", i))
			devs = append(devs, rfDrive{ID: n, Name: n, Model: d.Model, Capacity: d.Capacity, Status: d.Status})
			sids = append(sids, sid)
		}
	}
	return ctrls, devs, sids, ok
}

func rfControllerService(sid string, st rfStorage) (model.Service, bool) {
	if len(st.Controllers) == 0 && st.Status.Health == "" {
		return model.Service{}, false
	}
	name := shortText(firstNonEmpty(st.Name, sid))
	s := model.Service{Key: "ctrl:" + sid, Name: "Controller " + model.Raw(name), Kind: "ctrl", Default: true}
	var parts []string
	worst := st.Status.Health
	for _, c := range st.Controllers {
		if c.Status.absent() {
			continue
		}
		t := shortText(firstNonEmpty(c.Model, c.Name))
		if c.Firmware != "" {
			t += " (FW " + shortText(c.Firmware) + ")"
		}
		if t != "" {
			parts = append(parts, model.Raw(t))
		}
		if rfSev(c.Status.Health) > rfSev(worst) {
			worst = c.Status.Health
		}
	}
	if h := worst; h != "" {
		parts = append(parts, model.T("monitor64.txt.health_v", "v", shortText(h)))
	}
	rfHealthFacts(&s, s.Name, worst)
	s.Text = strings.Join(parts, " · ")
	return s, true
}

func rfDriveService(key string, d rfDrive) model.Service {
	name := shortText(firstNonEmpty(d.Name, d.ID))
	if d.Model != "" && !strings.Contains(name, strings.TrimSpace(d.Model)) {
		name += " (" + shortText(d.Model) + ")"
	}
	s := model.Service{Key: key, Name: model.Raw(name), Kind: "disk", Default: true}
	var parts []string
	if d.Capacity.Set && d.Capacity.V > 0 {
		parts = append(parts, bytesText(d.Capacity.V))
	}
	if t := strings.TrimSpace(d.Media + " " + d.Protocol); t != "" {
		parts = append(parts, devText(t))
	}
	h := d.Status.Health
	if h != "" {
		parts = append(parts, model.T("monitor64.txt.health_v", "v", shortText(h)))
	}
	switch {
	case rfSev(h) == 2:
		s.Facts = append(s.Facts, model.Fact{Code: "smart_failed", Text: model.T("monitor64.txt.drive_health", "v", h)})
	case d.Predicted != nil && *d.Predicted:
		s.Facts = append(s.Facts, model.Fact{Code: "smart_failed", Text: model.T("monitor64.txt.failure_predicted_long")})
	case rfSev(h) == 1:
		s.Facts = append(s.Facts, model.Fact{Code: "disk_errors", Text: model.T("monitor64.txt.drive_health", "v", h)})
	}
	if d.Predicted != nil && *d.Predicted && rfSev(h) == 2 {
		parts = append(parts, model.T("monitor64.txt.failure_predicted"))
	}
	if l := d.LifeLeft; l.Set && strings.EqualFold(d.Media, "SSD") {
		w := min(max(100-l.V, 0), 100)
		s.Metrics = append(s.Metrics, model.Metric{Name: "wear", Value: round2(w), Unit: "%", Rule: model.RuleWear})
		parts = append(parts, model.T("monitor64.txt.wear", "v", fmt.Sprintf("%.0f", w)))
	}
	s.Text = strings.Join(parts, " · ")
	return s
}

func rfVolumeService(sid string, v rfVolume) model.Service {
	id := firstNonEmpty(v.ID, v.Name)
	name := shortText(firstNonEmpty(v.Name, v.ID))
	s := model.Service{Key: "raid:" + sid + "/" + id, Name: "Volume " + model.Raw(name), Kind: "raid", Default: true}
	var parts []string
	if t := firstNonEmpty(v.RAIDType, v.VolumeType); t != "" {
		parts = append(parts, devText(t))
	}
	if v.Capacity.Set && v.Capacity.V > 0 {
		parts = append(parts, bytesText(v.Capacity.V))
	}
	h := v.Status.Health
	if h != "" {
		parts = append(parts, model.T("monitor64.txt.health_v", "v", shortText(h)))
	}
	for _, op := range v.Operations {
		if op.Name != "" {
			parts = append(parts, fmt.Sprintf("%s %.0f %%", devText(op.Name), op.Pct.V))
		}
	}
	if rfSev(h) > 0 {
		s.Facts = append(s.Facts, model.Fact{Code: "raid_degraded", Text: s.Name + ": " + model.T("monitor64.txt.health_v", "v", shortText(h))})
	}
	s.Text = strings.Join(parts, " · ")
	return s
}
