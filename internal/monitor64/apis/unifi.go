package apis

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/model"
)

// UniFi Network Application ueber die Controller-API (UniFi-OS-Konsolen wie UDM, UDR, UCG, Cloud Key und der selbst
// gehostete Network Server). Es wird nur gelesen. Zwei Arten der Anmeldung:
//
//   - API-Schluessel (Kopf X-API-KEY, in der Konsole unter "Integrations" angelegt): nur auf UniFi OS, ohne Sitzung.
//   - Benutzer und Passwort eines lokalen Nur-Lese-Admins: Anmeldung per POST /api/auth/login (UniFi OS) bzw.
//     /api/login (selbst gehostet, erkannt an der Antwort auf GET /status); Cookie und CSRF-Token gelten fuer die
//     folgenden Abfragen, bei 401 wird einmal neu angemeldet. Nach einer abgelehnten Anmeldung wartet der Sammler
//     (5, 15, 60 min) – die Konsole sperrt sonst immer laenger.
//
// Auf UniFi OS liegen die Pfade der Network Application unter /proxy/network. Je Runde:
//
//	/api/s/{site}/stat/device   Geraete (Zustand, CPU, RAM, Temperatur, Clients, Firmware, Ports mit PoE)
//	/api/s/{site}/stat/health   Internet/WAN (Status, Latenz, Durchsatz), Zahl der Clients
//	/api/s/{site}/list/alarm    offene Alarme (in neueren Versionen entfernt – dann ohne Dienst)
//
// Alle 30 min /api/s/{site}/stat/sysinfo (Version, Update der Network Application). Die offizielle "Integration API"
// (/integration/v1) liefert weder WAN-Zustand noch Temperaturen, PoE-Leistung oder Portzaehler – deshalb diese
// Endpunkte; der API-Schluessel gilt auf UniFi OS auch fuer sie.
//
// Zahlen kommen je nach Firmware als Zahl oder als Text ("3.1"), Wahrheitswerte ebenso – alles wird nachsichtig
// gelesen, unbekannte Zustaende bleiben roh.

const (
	ufSlowEvery   = 30 * time.Minute
	ufAbsentEvery = 6 * time.Hour
	ufMaxDevices  = 500
	ufMaxPorts    = 64
	ufOSPrefix    = "/proxy/network"
)

var ufSiteRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// ValidUnifiSite prueft den Schluessel einer Site ("default" bzw. die Zeichenfolge aus der Adresse der Oberflaeche).
func ValidUnifiSite(s string) bool { return s == "" || ufSiteRE.MatchString(s) }

// UnifiConfig sind die Verbindungsdaten einer UniFi Network Application.
type UnifiConfig struct {
	Address string        // https://192.168.1.1 (UniFi OS) bzw. https://unifi.lan:8443 (selbst gehostet)
	User    string        // lokaler Nur-Lese-Admin; leer = Secret ist ein API-Schluessel
	Secret  string        // API-Schluessel bzw. Passwort (Geheimnis, nie ausgeben)
	Site    string        // leer = default
	Pin     string        // SHA-256 des Zertifikats (hex); leer = System-CA
	Timeout time.Duration // ganze Runde (0 = DefaultTimeout)
}

// Unifi ist der Sammler einer UniFi Network Application.
type Unifi struct {
	cfg    UnifiConfig
	wc     *webClient
	now    func() time.Time
	mu     sync.Mutex // eine Runde zur Zeit
	site   string
	apiKey bool

	sm         sync.Mutex // Sitzung (nur mit Benutzer und Passwort)
	detected   bool
	unifiOS    bool
	cookie     string
	csrf       string
	loginErr   error
	loginRetry time.Time
	loginFails int

	prev       *counter
	alarmsGone time.Time
	slowAt     time.Time
	sys        *ufSysinfo
}

// NewUnifi baut den Sammler (prueft Adresse, Zugangsdaten und Pin; fragt noch nichts ab).
func NewUnifi(cfg UnifiConfig) (*Unifi, error) { return newUnifi(cfg, nil) }

func newUnifi(cfg UnifiConfig, roots *x509.CertPool) (*Unifi, error) {
	t, err := parseWebAddr(cfg.Address, "https", "", false)
	if err != nil {
		return nil, err
	}
	user := strings.TrimSpace(cfg.User)
	secret := cfg.Secret
	if user == "" {
		secret = strings.TrimSpace(secret)
	}
	switch {
	case secret == "" && user == "":
		return nil, errors.New(model.T("monitor64.txt.apikey_missing"))
	case secret == "":
		return nil, errors.New(model.T("monitor64.txt.cred_required"))
	case strings.ContainsAny(user, "\r\n") || strings.ContainsAny(secret, "\r\n"):
		return nil, errors.New(model.T("monitor64.txt.cred_newline"))
	case !ValidUnifiSite(strings.TrimSpace(cfg.Site)):
		return nil, errors.New(model.T("monitor64.txt.uf_site_invalid"))
	}
	wc, err := newWebClient(t, cfg.Pin, roots)
	if err != nil {
		return nil, err
	}
	cfg.User, cfg.Secret = user, secret
	u := &Unifi{cfg: cfg, wc: wc, now: time.Now, site: firstNonEmpty(strings.TrimSpace(cfg.Site), "default"), apiKey: user == ""}
	wc.header = func(h http.Header) {
		if u.apiKey {
			h.Set("X-API-KEY", secret)
			return
		}
		u.sm.Lock()
		defer u.sm.Unlock()
		if u.cookie != "" {
			h.Set("Cookie", u.cookie)
		}
		if u.csrf != "" {
			h.Set("X-Csrf-Token", u.csrf)
		}
	}
	return u, nil
}

func (u *Unifi) timeout() time.Duration {
	if u.cfg.Timeout > 0 {
		return u.cfg.Timeout
	}
	return DefaultTimeout
}

func (u *Unifi) secrets() []string { return []string{u.cfg.Secret} }

// Close meldet die Sitzung ab (nur mit Benutzer und Passwort) und gibt Verbindungen frei.
func (u *Unifi) Close() {
	u.sm.Lock()
	cookie, os := u.cookie, u.unifiOS
	u.sm.Unlock()
	if !u.apiKey && cookie != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		path := "/api/logout"
		if os {
			path = "/api/auth/logout"
		}
		_, _ = u.wc.do(ctx, http.MethodPost, path, nil, map[string]string{}, nil)
		cancel()
		u.sm.Lock()
		u.cookie, u.csrf = "", ""
		u.sm.Unlock()
	}
	u.wc.close()
}

// Queries nennt die Abfragen ("Was wird abgefragt?").
func (u *Unifi) Queries() []string {
	p := "/api/s/" + u.site
	out := []string{"GET " + p + "/stat/device", "GET " + p + "/stat/health", "GET " + p + "/list/alarm", "GET " + p + "/stat/sysinfo", "GET /api/self/sites"}
	if u.apiKey {
		return append([]string{"X-API-KEY, " + ufOSPrefix + "/…"}, out...)
	}
	return append([]string{"POST /api/auth/login bzw. /api/login"}, out...)
}

// prefix: auf UniFi OS liegen die Pfade der Network Application unter /proxy/network.
func (u *Unifi) prefix() string {
	if u.apiKey {
		return ufOSPrefix
	}
	u.sm.Lock()
	defer u.sm.Unlock()
	if u.unifiOS {
		return ufOSPrefix
	}
	return ""
}

// ufPause: Wartezeit nach abgelehnten Anmeldungen (die Konsole verlaengert ihre Sperre mit jedem weiteren Versuch).
func ufPause(fails int) time.Duration {
	switch {
	case fails <= 1:
		return 5 * time.Minute
	case fails == 2:
		return 15 * time.Minute
	}
	return time.Hour
}

// login meldet mit Benutzer und Passwort an (erkennt vorher einmal, ob UniFi OS antwortet).
func (u *Unifi) login(ctx context.Context) error {
	u.sm.Lock()
	if u.loginErr != nil && u.now().Before(u.loginRetry) {
		err := u.loginErr
		u.sm.Unlock()
		return err
	}
	detected := u.detected
	u.cookie, u.csrf = "", ""
	u.sm.Unlock()
	if !detected {
		// Der selbst gehostete Network Server beantwortet GET /status ohne Anmeldung mit seiner Huelle
		// ({"meta":{"rc":"ok","up":true,...}}); auf UniFi OS liegt die Network Application unter /proxy/network, dort
		// kommt an dieser Stelle etwas anderes. (GET / taugt nicht: ein startender Server antwortet darauf mit 200
		// statt mit der Weiterleitung – so gesehen an einem echten Network Server 10.0.162.)
		var st struct {
			Meta struct {
				RC string `json:"rc"`
				Up *bool  `json:"up"`
			} `json:"meta"`
		}
		_, err := u.wc.do(ctx, http.MethodGet, "/status", nil, nil, &st)
		var we *webError
		if err != nil && !(errors.As(err, &we) && we.Status != 0) {
			return err // Netz, Zertifikat: keine Antwort, die etwas ueber die Art sagt
		}
		os := err != nil || st.Meta.RC == ""
		if !os && st.Meta.Up != nil && !*st.Meta.Up {
			return &webError{Kind: errWebResp, Detail: model.T("monitor64.txt.uf_starting"), Where: "GET /status"}
		}
		u.sm.Lock()
		u.detected, u.unifiOS = true, os
		u.sm.Unlock()
	}
	u.sm.Lock()
	os := u.unifiOS
	u.sm.Unlock()
	path := "/api/login"
	if os {
		path = "/api/auth/login"
	}
	hdr, err := u.wc.do(ctx, http.MethodPost, path, nil, map[string]string{"username": u.cfg.User, "password": u.cfg.Secret}, nil)
	if err != nil {
		return u.loginFailed(err)
	}
	var parts []string
	csrf := firstNonEmpty(hdr.Get("X-Updated-Csrf-Token"), hdr.Get("X-Csrf-Token"))
	for _, c := range (&http.Response{Header: hdr}).Cookies() {
		if c.Value == "" {
			continue
		}
		parts = append(parts, c.Name+"="+c.Value)
		if c.Name == "csrf_token" && csrf == "" {
			csrf = c.Value
		}
	}
	if len(parts) == 0 {
		return u.loginFailed(&webError{Kind: errWebResp, Detail: model.T("monitor64.txt.uf_no_session"), Where: "POST " + path})
	}
	u.sm.Lock()
	u.cookie, u.csrf = strings.Join(parts, "; "), csrf
	u.loginErr, u.loginFails = nil, 0
	u.sm.Unlock()
	return nil
}

// loginFailed ordnet eine abgelehnte Anmeldung ein und setzt die Wartezeit bis zum naechsten Versuch.
func (u *Unifi) loginFailed(err error) error {
	var we *webError
	if !errors.As(err, &we) || we.Status == 0 {
		return err // Netz bzw. Zertifikat: naechste Runde wieder
	}
	d := strings.ToLower(we.Detail)
	switch {
	case we.Status == 499 || strings.Contains(d, "2fa") || strings.Contains(d, "mfa"):
		we.Kind, we.Detail = errWebAuth, model.T("monitor64.txt.uf_mfa")
	case we.Status == http.StatusTooManyRequests || strings.Contains(d, "limit_reached"):
		we.Kind, we.Detail = errWebAuth, model.T("monitor64.txt.uf_locked")
	case we.Status == 400 || we.Status == 401 || we.Status == 403:
		we.Kind = errWebAuth
	default:
		return err
	}
	u.sm.Lock()
	defer u.sm.Unlock()
	u.loginFails++
	pause := ufPause(u.loginFails)
	u.loginErr = fmt.Errorf("%w – %s", we, model.T("monitor64.txt.uf_login_pause", "n", int(pause/time.Minute)))
	u.loginRetry = u.now().Add(pause)
	return u.loginErr
}

// ufEnvelope ist die Huelle der Controller-API: {"meta":{"rc":"ok"},"data":[...]}.
type ufEnvelope struct {
	Meta struct {
		RC  string `json:"rc"`
		Msg string `json:"msg"`
	} `json:"meta"`
	Data json.RawMessage `json:"data"`
}

// get fragt einen Pfad der Network Application ab (ohne Praefix) und legt data in out ab.
func (u *Unifi) get(ctx context.Context, path string, out any) error {
	if !u.apiKey {
		u.sm.Lock()
		have := u.cookie != ""
		u.sm.Unlock()
		if !have {
			if err := u.login(ctx); err != nil {
				return err
			}
		}
	}
	var env ufEnvelope
	call := func() error {
		hdr, err := u.wc.do(ctx, http.MethodGet, u.prefix()+path, nil, nil, &env)
		if t := firstNonEmpty(hdr.Get("X-Updated-Csrf-Token"), hdr.Get("X-Csrf-Token")); t != "" && !u.apiKey {
			u.sm.Lock()
			u.csrf = t
			u.sm.Unlock()
		}
		return err
	}
	err := call()
	// Sitzung abgelaufen: einmal neu anmelden. Eine unbekannte Site meldet der Controller ebenfalls mit 401
	// (api.err.NoSiteContext) – dafuer nicht bei jeder Runde neu anmelden.
	var we *webError
	if !u.apiKey && errors.Is(err, errWebAuth) && !(errors.As(err, &we) && strings.Contains(we.Detail, "NoSiteContext")) {
		u.sm.Lock()
		u.cookie = ""
		u.sm.Unlock()
		if lerr := u.login(ctx); lerr != nil {
			return lerr
		}
		env = ufEnvelope{}
		err = call()
	}
	if err != nil {
		return err
	}
	if strings.EqualFold(env.Meta.RC, "error") {
		return &webError{Kind: errWebResp, Detail: devText(env.Meta.Msg), Where: "GET " + path}
	}
	if b := bytes.TrimSpace(env.Data); len(b) > 0 && string(b) != "null" && out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			return &webError{Kind: errWebResp, Detail: model.T("monitor64.txt.resp_json") + ": " + devText(err.Error()), Where: "GET " + path}
		}
	}
	return nil
}

// ufGone: den Endpunkt gibt es in dieser Version nicht mehr (Alarme: 404 bzw. 400 api.err.InvalidObject).
func ufGone(err error) bool {
	var we *webError
	if !errors.As(err, &we) {
		return false
	}
	return we.Status == 404 || (we.Status == 400 && strings.Contains(we.Detail, "InvalidObject"))
}

func (u *Unifi) hint(err error) error {
	var we *webError
	switch {
	case errors.As(err, &we) && strings.Contains(we.Detail, "NoSiteContext"):
		return fmt.Errorf("%w – %s", err, model.T("monitor64.txt.uf_hint_site", "s", u.site))
	case errors.Is(err, errWebAuth) && u.apiKey:
		return fmt.Errorf("%w – %s", err, model.T("monitor64.txt.uf_hint_key"))
	case errors.Is(err, errWebAuth):
		return fmt.Errorf("%w – %s", err, model.T("monitor64.txt.uf_hint_login"))
	case errors.Is(err, errWebPerm):
		return fmt.Errorf("%w – %s", err, model.T("monitor64.txt.uf_hint_perm"))
	case u.apiKey && errors.As(err, &we) && we.Status == 404:
		return fmt.Errorf("%w – %s", err, model.T("monitor64.txt.uf_hint_no_os"))
	}
	return err
}

// ufBool ist ein Wahrheitswert, der als true, "true", 1 oder "1" kommen kann (Set false = fehlt).
type ufBool struct{ V, Set bool }

func (b *ufBool) UnmarshalJSON(raw []byte) error {
	switch strings.ToLower(strings.Trim(strings.TrimSpace(string(raw)), `"`)) {
	case "true", "1":
		*b = ufBool{V: true, Set: true}
	case "false", "0":
		*b = ufBool{Set: true}
	default:
		*b = ufBool{}
	}
	return nil
}

// ufPort ist ein Eintrag aus port_table.
type ufPort struct {
	Idx        optNum `json:"port_idx"`
	Name       string `json:"name"`
	Up         ufBool `json:"up"`
	Enable     ufBool `json:"enable"`
	Speed      optNum `json:"speed"`
	FullDuplex ufBool `json:"full_duplex"`
	IsUplink   ufBool `json:"is_uplink"`
	RxRate     optNum `json:"rx_bytes-r"`
	TxRate     optNum `json:"tx_bytes-r"`
	RxPackets  optNum `json:"rx_packets"`
	TxPackets  optNum `json:"tx_packets"`
	RxErrors   optNum `json:"rx_errors"`
	TxErrors   optNum `json:"tx_errors"`
	PortPoE    ufBool `json:"port_poe"`
	PoEEnable  ufBool `json:"poe_enable"`
	PoEPower   optNum `json:"poe_power"`
}

// ufDevice ist ein Geraet aus stat/device.
type ufDevice struct {
	Mac         string `json:"mac"`
	Name        string `json:"name"`
	Model       string `json:"model"`     // interner Code, z. B. UAPA6A9
	Shortname   string `json:"shortname"` // lesbares Kuerzel, z. B. U7PROXG (neuere Versionen)
	Type        string `json:"type"`
	Version     string `json:"version"`
	Adopted     ufBool `json:"adopted"`
	Disabled    ufBool `json:"disabled"`
	State       optNum `json:"state"`
	Uptime      optNum `json:"uptime"`
	Upgradable  ufBool `json:"upgradable"`
	UpgradeTo   string `json:"upgrade_to_firmware"`
	NumSta      optNum `json:"num_sta"`
	SystemStats struct {
		CPU optNum `json:"cpu"`
		Mem optNum `json:"mem"`
	} `json:"system-stats"`
	GeneralTemp  optNum `json:"general_temperature"`
	Temperatures []struct {
		Name  string `json:"name"`
		Type  string `json:"type"`
		Value optNum `json:"value"`
	} `json:"temperatures"`
	Overheating   ufBool   `json:"overheating"`
	TotalMaxPower optNum   `json:"total_max_power"`
	PortTable     []ufPort `json:"port_table"`
	// LastWanStatus: Gateways – Zustand je WAN-Leitung ({"WAN":"online","WAN2":"online"})
	LastWanStatus map[string]string `json:"last_wan_status"`
}

func (d ufDevice) label() string {
	if n := shortText(d.Name); n != "" {
		return n
	}
	return shortText(strings.TrimSpace(d.Model + " " + d.Mac))
}

// ufHealth ist ein Teilsystem aus stat/health (wan, www, wlan, lan, vpn).
type ufHealth struct {
	Subsystem string `json:"subsystem"`
	Status    string `json:"status"`
	WanIP     string `json:"wan_ip"`
	ISP       string `json:"isp_name"`
	NumGw     optNum `json:"num_gw"`
	NumUser   optNum `json:"num_user"`
	NumGuest  optNum `json:"num_guest"`
	RxRate    optNum `json:"rx_bytes-r"`
	TxRate    optNum `json:"tx_bytes-r"`
	Latency   optNum `json:"latency"`
	XputUp    optNum `json:"xput_up"`
	XputDown  optNum `json:"xput_down"`
}

// ufSysinfo ist stat/sysinfo.
type ufSysinfo struct {
	Version         string `json:"version"`
	UpdateAvailable ufBool `json:"update_available"`
	ConsoleVersion  string `json:"console_display_version"`
	Name            string `json:"name"`
}

// ufAlarm ist ein Eintrag aus list/alarm.
type ufAlarm struct {
	Key      string `json:"key"`
	Msg      string `json:"msg"`
	Datetime string `json:"datetime"`
	Archived ufBool `json:"archived"`
}

// ufSite ist ein Eintrag aus /api/self/sites.
type ufSite struct {
	Name string `json:"name"`
	Desc string `json:"desc"`
}

// Test prueft die Verbindung im Assistenten (Zertifikat, Anmeldung, Site, Version).
func (u *Unifi) Test(ctx context.Context) TestResult {
	ctx, cancel := context.WithTimeout(ctx, u.timeout())
	defer cancel()
	res, proceed := probeCert(ctx, u.wc.t, u.wc.pin, u.wc.roots)
	if !proceed {
		return res
	}
	fail := func(err error) TestResult {
		res.Error = scrub(u.hint(err).Error(), u.secrets()...)
		return res
	}
	var sites []ufSite
	if err := u.get(ctx, "/api/self/sites", &sites); err != nil {
		return fail(err)
	}
	found := len(sites) == 0 // ohne Liste: die Abfrage der Geraete entscheidet
	var names []string
	for _, s := range sites {
		if s.Name == u.site {
			found = true
		}
		n := shortText(s.Name)
		if d := shortText(s.Desc); d != "" && d != n {
			n += " (" + d + ")"
		}
		names = append(names, n)
	}
	if !found {
		sort.Strings(names)
		res.Error = model.T("monitor64.txt.uf_site_unknown", "s", u.site, "list", model.Raw(strings.Join(limitList(names, 8), ", ")))
		return res
	}
	var devs []ufDevice
	if err := u.get(ctx, "/api/s/"+url.PathEscape(u.site)+"/stat/device", &devs); err != nil {
		return fail(err)
	}
	res.OK = true
	n := 0
	for _, d := range devs {
		if d.Adopted.V || !d.Adopted.Set {
			n++
		}
	}
	res.Summary = model.T("monitor64.txt.uf_summary", "n", n)
	var si []ufSysinfo
	if err := u.get(ctx, "/api/s/"+url.PathEscape(u.site)+"/stat/sysinfo", &si); err == nil && len(si) > 0 {
		res.Version = shortText(si[0].Version)
	}
	return res
}

// Collect ist eine Abfragerunde (nicht gleichzeitig mit sich selbst aufrufen).
func (u *Unifi) Collect(ctx context.Context) ([]model.Service, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, u.timeout())
	defer cancel()
	now := u.now()
	base := "/api/s/" + url.PathEscape(u.site)
	var devs []ufDevice
	if err := u.get(ctx, base+"/stat/device", &devs); err != nil {
		return nil, scrubErr(u.hint(err), u.secrets()...)
	}
	part := hintPartial{partial: &partial{secrets: u.secrets()}, hint: u.hint}
	if len(devs) > ufMaxDevices {
		devs = devs[:ufMaxDevices]
	}
	cur := &counter{t: now, v: map[string]float64{}}
	var out []model.Service
	total, offline := 0, 0
	var fw []string
	var wans map[string]string
	for _, d := range devs {
		if (d.Adopted.Set && !d.Adopted.V) || d.Disabled.V || strings.TrimSpace(d.Mac) == "" {
			continue // wartet auf Uebernahme bzw. abgeschaltet: nicht unser Geraet
		}
		total++
		online := d.State.Set && d.State.V == 1
		if d.State.Set && d.State.V == 0 {
			offline++
		}
		if d.Upgradable.V {
			fw = append(fw, strings.TrimSpace(d.label()+" "+shortText(d.UpgradeTo)))
		}
		if online && len(d.LastWanStatus) > 0 && wans == nil {
			wans = d.LastWanStatus
		}
		out = append(out, ufDeviceService(d, online))
		if ufHasPorts(d.Type) {
			out = append(out, ufPortServices(d, online, u.prev, cur)...)
		}
	}
	u.prev = cur

	var health []ufHealth
	if err := u.get(ctx, base+"/stat/health", &health); err != nil {
		part.add("stat/health", err, "wan", "clients")
	} else {
		out = append(out, ufHealthServices(health, wans)...)
	}

	if u.alarmsGone.IsZero() || now.Sub(u.alarmsGone) >= ufAbsentEvery {
		var alarms []ufAlarm
		switch err := u.get(ctx, base+"/list/alarm", &alarms); {
		case ufGone(err):
			u.alarmsGone = now
		case err != nil:
			part.add("list/alarm", err, "alerts")
		default:
			u.alarmsGone = time.Time{}
			out = append(out, ufAlarms(alarms))
		}
	}

	if u.slowAt.IsZero() || now.Sub(u.slowAt) >= ufSlowEvery {
		var si []ufSysinfo
		if err := u.get(ctx, base+"/stat/sysinfo", &si); err == nil && len(si) > 0 {
			u.sys = &si[0]
		} else if err != nil && !webAbsent(err) {
			part.add("stat/sysinfo", err)
		}
		u.slowAt = now
	}
	out = append(out, ufSystem(u.sys, total, offline), ufUpdates(u.sys, fw))
	sortServices(out)
	return out, part.result()
}

// ufStates: Zustand eines Geraets (state) als Text; fact = Meldung dazu ("" = keine).
var ufStates = map[int]struct{ text, fact string }{
	0:  {"monitor64.txt.uf_st_offline", "device_crit"},
	1:  {"monitor64.txt.uf_st_online", ""},
	2:  {"monitor64.txt.uf_st_pending", ""},
	3:  {"monitor64.txt.uf_st_fw_mismatch", "device_warn"},
	4:  {"monitor64.txt.uf_st_upgrading", ""},
	5:  {"monitor64.txt.uf_st_provisioning", ""},
	6:  {"monitor64.txt.uf_st_heartbeat", "device_warn"},
	7:  {"monitor64.txt.uf_st_adopting", ""},
	9:  {"monitor64.txt.uf_st_inform_error", "device_warn"},
	10: {"monitor64.txt.uf_st_adopt_failed", "device_warn"},
	11: {"monitor64.txt.uf_st_isolated", "device_warn"},
}

// ufDeviceService: ein Dienst je Geraet (Access Point, Switch, Gateway) mit Zustand, CPU, RAM, Temperatur, Clients.
func ufDeviceService(d ufDevice, online bool) model.Service {
	name := d.label()
	s := model.Service{Key: "dev:" + strings.ToLower(strings.TrimSpace(d.Mac)), Name: model.Raw(name), Kind: "netdev", Default: true}
	var parts []string
	st, known := ufStates[int(d.State.V)]
	switch {
	case !d.State.Set:
		parts = append(parts, model.T("monitor64.txt.unknown"))
	case !known:
		parts = append(parts, model.T("monitor64.txt.uf_st_other", "n", int(d.State.V)))
	default:
		parts = append(parts, model.T(st.text))
		if st.fact != "" {
			s.Facts = append(s.Facts, model.Fact{Code: st.fact, Text: model.T("monitor64.txt.uf_dev_state", "name", name, "s", model.Sub(model.T(st.text)))})
		}
	}
	if m := shortText(firstNonEmpty(strings.TrimSpace(d.Shortname), d.Model)); m != "" {
		parts = append(parts, model.Raw(m))
	}
	if online {
		if v := d.SystemStats.CPU; v.Set && v.V >= 0 {
			s.Metrics = append(s.Metrics, model.Metric{Name: "cpu", Value: round2(math.Min(v.V, 100)), Unit: "%", Rule: model.RuleCPU})
		}
		if v := d.SystemStats.Mem; v.Set && v.V >= 0 {
			s.Metrics = append(s.Metrics, model.Metric{Name: "mem", Value: round2(math.Min(v.V, 100)), Unit: "%", Rule: model.RuleMem})
		}
		temp := d.GeneralTemp
		for _, t := range d.Temperatures { // Gateways: CPU vor Platine
			if t.Value.Set && (!temp.Set || strings.EqualFold(t.Type, "cpu")) {
				temp = t.Value
				if strings.EqualFold(t.Type, "cpu") {
					break
				}
			}
		}
		if temp.Set && temp.V > 0 && temp.V < 150 {
			s.Metrics = append(s.Metrics, model.Metric{Name: "temp", Value: round2(temp.V), Unit: "°C", Rule: model.RuleTemp})
			parts = append(parts, fmt.Sprintf("%.0f °C", temp.V))
		}
		if d.NumSta.Set {
			s.Metrics = append(s.Metrics, model.Metric{Name: "clients", Value: d.NumSta.V})
			parts = append(parts, model.T("monitor64.txt.uf_clients_n", "n", int(d.NumSta.V)))
		}
		if d.Uptime.Set && d.Uptime.V >= 0 {
			s.Metrics = append(s.Metrics, model.Metric{Name: "uptime", Value: math.Floor(d.Uptime.V), Unit: "s"})
		}
	}
	if d.Overheating.V {
		s.Facts = append(s.Facts, model.Fact{Code: "device_warn", Text: model.T("monitor64.txt.uf_overheating", "name", name)})
		parts = append(parts, model.T("monitor64.txt.uf_overheating_short"))
	}
	if v := shortText(d.Version); v != "" {
		parts = append(parts, model.T("monitor64.txt.uf_firmware", "v", v))
	}
	if d.Upgradable.V {
		parts = append(parts, model.T("monitor64.txt.update_available"))
	}
	s.Text = strings.Join(parts, " · ")
	return s
}

// ufHasPorts: Geraete, deren Ports einzeln zaehlen (Switches und Gateways; Access Points haben nur ihren Uplink).
func ufHasPorts(typ string) bool {
	switch strings.ToLower(strings.TrimSpace(typ)) {
	case "usw", "udm", "ugw", "uxg", "ucg", "usg":
		return true
	}
	return false
}

// ufPortServices: je Port ein Dienst (Zustand, Durchsatz aus den Raten des Controllers, Fehler aus den Zaehlern,
// PoE-Leistung) und je Switch mit PoE-Budget ein Dienst "PoE". Ist das Geraet nicht verbunden, bleiben die Ports
// ohne Werte stehen (statt als verschwunden zu gelten).
func ufPortServices(d ufDevice, online bool, prev, cur *counter) []model.Service {
	var out []model.Service
	mac := strings.ToLower(strings.TrimSpace(d.Mac))
	dev := d.label()
	poeSum, poePorts := 0.0, 0
	for i, p := range d.PortTable {
		if i >= ufMaxPorts || !p.Idx.Set {
			continue
		}
		idx := strconv.Itoa(int(p.Idx.V))
		pname := shortText(p.Name)
		if pname == "" {
			pname = "Port " + idx
		}
		enabled := !p.Enable.Set || p.Enable.V
		s := model.Service{Key: "port:" + mac + ":" + idx, Name: model.Raw(dev) + " · " + model.Raw(pname), Kind: "if", Default: online && p.Up.V}
		if !online {
			s.Text = model.T("monitor64.txt.uf_dev_offline")
			out = append(out, s)
			continue
		}
		var parts []string
		if p.Up.V && p.Speed.Set && p.Speed.V > 0 {
			parts = append(parts, mbitText(p.Speed.V))
		}
		if p.Up.V && p.RxRate.Set && p.TxRate.Set {
			inM, outM := p.RxRate.V*8/1e6, p.TxRate.V*8/1e6
			s.Metrics = append(s.Metrics, model.Metric{Name: "in", Value: round2(inM), Unit: "Mbit/s"}, model.Metric{Name: "out", Value: round2(outM), Unit: "Mbit/s"})
			if p.Speed.V > 0 {
				s.Metrics = append(s.Metrics, model.Metric{Name: "util", Value: round2(math.Min(100, math.Max(inM, outM)/p.Speed.V*100)), Unit: "%", Rule: model.RuleIfUtil})
			}
			parts = append(parts, fmt.Sprintf("↓ %s · ↑ %s", mbitText(inM), mbitText(outM)))
		}
		if p.RxErrors.Set && p.TxErrors.Set && p.RxPackets.Set && p.TxPackets.Set {
			k := mac + "|" + idx + "|"
			cur.v[k+"e"], cur.v[k+"p"] = p.RxErrors.V+p.TxErrors.V, p.RxPackets.V+p.TxPackets.V
			er, ok1 := rate(prev, cur.t, k+"e", cur.v[k+"e"])
			pr, ok2 := rate(prev, cur.t, k+"p", cur.v[k+"p"])
			if ok1 && ok2 {
				dt := cur.t.Sub(prev.t).Seconds()
				errs, pk := math.Round(er*dt), pr*dt
				pctErr := 0.0
				if pk > 0 {
					pctErr = errs / pk * 100
				}
				s.Metrics = append(s.Metrics, model.Metric{Name: "errrate", Value: math.Round(math.Min(100, pctErr)*1e4) / 1e4, Unit: "%", Rule: model.RuleIfErrRate},
					model.Metric{Name: "errors", Value: errs})
				if errs > 0 {
					parts = append(parts, model.T("monitor64.txt.errors_n", "n", fmt.Sprintf("%.0f", errs)))
				}
			}
		}
		if p.PortPoE.V && p.PoEEnable.V && p.PoEPower.Set && p.PoEPower.V >= 0 {
			s.Metrics = append(s.Metrics, model.Metric{Name: "poe", Value: round2(p.PoEPower.V), Unit: "W"})
			poeSum += p.PoEPower.V
			poePorts++
			if p.PoEPower.V > 0 {
				parts = append(parts, "PoE "+strings.Replace(strconv.FormatFloat(round2(p.PoEPower.V), 'f', 1, 64), ".", ",", 1)+" W")
			}
		}
		switch {
		case !enabled:
			parts = []string{model.T("monitor64.txt.disabled")}
		case !p.Up.V:
			parts = append([]string{"down"}, parts...)
			s.Facts = append(s.Facts, model.Fact{Code: "if_down", Text: model.T("monitor64.txt.no_link", "name", dev+" "+pname)})
		case p.FullDuplex.Set && !p.FullDuplex.V:
			s.Facts = append(s.Facts, model.Fact{Code: "if_half_duplex", Text: model.T("monitor64.txt.half_duplex_name", "name", dev+" "+pname)})
			parts = append(parts, model.T("monitor64.txt.half_duplex"))
		}
		s.Text = strings.Join(parts, " · ")
		out = append(out, s)
	}
	if online && d.TotalMaxPower.Set && d.TotalMaxPower.V > 0 {
		used := math.Min(100, poeSum/d.TotalMaxPower.V*100)
		out = append(out, model.Service{Key: "poe:" + mac, Name: model.Raw(dev) + " · PoE", Kind: "poe", Default: true,
			Metrics: []model.Metric{{Name: "used", Value: round2(used), Unit: "%", Rule: model.RulePoEUsed, Max: d.TotalMaxPower.V},
				{Name: "watts", Value: round2(poeSum), Unit: "W"}},
			Text: model.T("monitor64.txt.uf_poe", "w", strings.Replace(strconv.FormatFloat(round2(poeSum), 'f', 1, 64), ".", ",", 1),
				"max", fmt.Sprintf("%.0f", d.TotalMaxPower.V), "n", poePorts)})
	}
	return out
}

// ufHealthServices: Internetverbindung (Teilsysteme wan und www, nur mit Gateway) und die Zahl der Clients. wans ist
// der Zustand der einzelnen WAN-Leitungen des Gateways (nil = unbekannt): faellt bei mehreren Leitungen eine aus,
// bleibt die Verbindung insgesamt in Ordnung – der Dienst warnt dann mit dem Namen der Leitung.
func ufHealthServices(list []ufHealth, wans map[string]string) []model.Service {
	sub := map[string]ufHealth{}
	for _, h := range list {
		sub[strings.ToLower(strings.TrimSpace(h.Subsystem))] = h
	}
	var out []model.Service
	wan, www := sub["wan"], sub["www"]
	if (wan.NumGw.Set && wan.NumGw.V > 0) || strings.TrimSpace(wan.WanIP) != "" {
		s := model.Service{Key: "wan", Name: model.T("monitor64.svc.fb_wan"), Kind: "wan", Default: true}
		var parts []string
		worst := ""
		for _, st := range []string{strings.ToLower(wan.Status), strings.ToLower(www.Status)} {
			if st == "error" || (st == "warning" && worst == "") {
				worst = st
			}
		}
		switch worst {
		case "error":
			t := model.T("monitor64.txt.uf_wan_down")
			s.Facts = append(s.Facts, model.Fact{Code: "device_crit", Text: t})
			parts = append(parts, t)
		case "warning":
			t := model.T("monitor64.txt.uf_wan_warn")
			s.Facts = append(s.Facts, model.Fact{Code: "device_warn", Text: t})
			parts = append(parts, t)
		default:
			var down []string
			for name, st := range wans {
				if !strings.EqualFold(strings.TrimSpace(st), "online") {
					down = append(down, shortText(name))
				}
			}
			sort.Strings(down)
			switch {
			case len(wans) > 1 && len(down) > 0:
				t := model.T("monitor64.txt.uf_wan_line_down", "list", model.Raw(strings.Join(limitList(down, 4), ", ")))
				s.Facts = append(s.Facts, model.Fact{Code: "device_warn", Text: t})
				parts = append(parts, t)
			case len(wans) > 1:
				parts = append(parts, model.T("monitor64.txt.uf_wans_online", "n", len(wans)))
			default:
				parts = append(parts, model.T("monitor64.txt.uf_st_online"))
			}
		}
		if ip := shortText(wan.WanIP); ip != "" {
			parts = append(parts, model.Raw(ip))
		}
		if isp := shortText(wan.ISP); isp != "" {
			parts = append(parts, model.Raw(isp))
		}
		if www.Latency.Set && www.Latency.V >= 0 {
			s.Metrics = append(s.Metrics, model.Metric{Name: "latency", Value: round2(www.Latency.V), Unit: "ms"})
			parts = append(parts, fmt.Sprintf("%.0f ms", www.Latency.V))
		}
		if wan.RxRate.Set && wan.TxRate.Set {
			inM, outM := wan.RxRate.V*8/1e6, wan.TxRate.V*8/1e6
			s.Metrics = append(s.Metrics, model.Metric{Name: "in", Value: round2(inM), Unit: "Mbit/s"}, model.Metric{Name: "out", Value: round2(outM), Unit: "Mbit/s"})
			parts = append(parts, fmt.Sprintf("↓ %s · ↑ %s", mbitText(inM), mbitText(outM)))
		}
		if www.XputDown.Set && www.XputDown.V > 0 {
			s.Metrics = append(s.Metrics, model.Metric{Name: "speedtest_down", Value: round2(www.XputDown.V), Unit: "Mbit/s"},
				model.Metric{Name: "speedtest_up", Value: round2(www.XputUp.V), Unit: "Mbit/s"})
		}
		s.Text = strings.Join(parts, " · ")
		out = append(out, s)
	}
	wlan, lan := sub["wlan"], sub["lan"]
	if wlan.NumUser.Set || lan.NumUser.Set {
		w, l, g := int(wlan.NumUser.V), int(lan.NumUser.V), int(wlan.NumGuest.V+lan.NumGuest.V)
		out = append(out, model.Service{Key: "clients", Name: model.T("monitor64.svc.uf_clients"), Kind: "wlan", Default: true,
			Metrics: []model.Metric{{Name: "wlan", Value: float64(w)}, {Name: "lan", Value: float64(l)}, {Name: "guests", Value: float64(g)}},
			Text:    model.T("monitor64.txt.uf_clients", "w", w, "l", l, "g", g)})
	}
	return out
}

// ufAlarms: offene (nicht archivierte) Alarme der Site.
func ufAlarms(list []ufAlarm) model.Service {
	var open []ufAlarm
	for _, a := range list {
		if !a.Archived.V {
			open = append(open, a)
		}
	}
	sort.SliceStable(open, func(i, j int) bool { return open[i].Datetime > open[j].Datetime }) // neueste zuerst (RFC 3339)
	s := model.Service{Key: "alerts", Name: model.T("monitor64.svc.alerts"), Kind: "alerts", Default: true,
		Metrics: []model.Metric{{Name: "count", Value: float64(len(open))}}}
	if len(open) == 0 {
		s.Text = model.T("monitor64.txt.uf_alarms_none")
		return s
	}
	var msgs []string
	for _, a := range open {
		if m := stripTags(firstNonEmpty(a.Msg, a.Key)); m != "" {
			msgs = append(msgs, m)
		}
	}
	t := model.T("monitor64.txt.uf_alarms", "n", len(open))
	if len(msgs) > 0 {
		t += ": " + model.Raw(strings.Join(limitList(msgs, 3), "; "))
	}
	s.Text = t
	s.Facts = append(s.Facts, model.Fact{Code: "device_warn", Text: t})
	return s
}

// ufSystem: die Network Application selbst (Version, Zahl der Geraete).
func ufSystem(si *ufSysinfo, total, offline int) model.Service {
	s := model.Service{Key: "system", Name: "UniFi Network", Kind: "system", Default: true,
		Metrics: []model.Metric{{Name: "devices", Value: float64(total)}, {Name: "offline", Value: float64(offline)}}}
	var parts []string
	if si != nil {
		if v := shortText(si.Version); v != "" {
			parts = append(parts, model.T("monitor64.txt.uf_version", "v", v))
		}
		if v := shortText(si.ConsoleVersion); v != "" {
			parts = append(parts, "UniFi OS "+model.Raw(v))
		}
	}
	parts = append(parts, model.T("monitor64.txt.uf_devices", "n", total, "off", offline))
	s.Text = strings.Join(parts, " · ")
	return s
}

// ufUpdates: Update der Network Application und Firmware-Updates der Geraete in einem Dienst.
func ufUpdates(si *ufSysinfo, fw []string) model.Service {
	s := model.Service{Key: "updates", Name: "Updates", Kind: "updates", Default: true}
	var parts []string
	n := len(fw)
	if si != nil && si.UpdateAvailable.V {
		n++
		parts = append(parts, model.T("monitor64.txt.uf_update_app"))
	}
	if len(fw) > 0 {
		sort.Strings(fw)
		parts = append(parts, model.T("monitor64.txt.uf_update_fw", "n", len(fw), "list", model.Raw(strings.Join(limitList(fw, 5), ", "))))
	}
	s.Metrics = []model.Metric{{Name: "pending", Value: float64(n)}}
	if n == 0 {
		s.Text = model.T("monitor64.txt.none_pending")
		return s
	}
	s.Text = strings.Join(parts, " · ")
	s.Facts = append(s.Facts, model.Fact{Code: "updates_security", Text: s.Text})
	return s
}
