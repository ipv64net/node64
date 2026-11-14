package apis

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/model"
)

// FRITZ!Box ueber TR-064 (SOAP ueber HTTPS, Port 49443; Dienste und Felder nach den Dokumenten "TR-064 Support" von
// FRITZ!/AVM). Anmeldung per HTTP-Digest mit einem FRITZ!Box-Benutzer; das Kennwort geht dabei nie ueber die Leitung.
// Die Beschreibung /tr64desc.xml (ohne Anmeldung) nennt Modell, FRITZ!OS und die Adressen der Dienste. Je Runde:
//
//	Layer3Forwarding:GetDefaultConnectionService        welche Verbindung gilt (PPP bei DSL, IP bei Kabel/Glasfaser)
//	WANPPPConnection bzw. WANIPConnection:GetInfo       Status, Dauer, externe Adresse (wan)
//	WANCommonInterfaceConfig:GetCommonLinkProperties    Zugangsart, Leitung
//	WANCommonInterfaceConfig:X_AVM-DE_GetOnlineMonitor  aktueller Durchsatz
//	WANDSLInterfaceConfig:GetInfo, GetStatisticsTotal   DSL-Sync, Stoerabstand, Daempfung, CRC-Fehler (dsl; nur bei DSL)
//	DeviceInfo:GetInfo                                  Laufzeit (system)
//
// Stuendlich UserInterface:GetInfo (Update verfuegbar). Die meisten Lese-Aktionen verlangen das Recht
// "FRITZ!Box Einstellungen"; ohne es (UPnP-Fehler 606) fehlt nur der jeweilige Teil.

const (
	fbMaxBody     = 1 << 20
	fbUpdateEvery = time.Hour
	fbConnEvery   = 10 * time.Minute // Art der Verbindung neu bestimmen

	fbSvcDeviceInfo = "urn:dslforum-org:service:DeviceInfo:1"
	fbSvcLayer3     = "urn:dslforum-org:service:Layer3Forwarding:1"
	fbSvcWANCommon  = "urn:dslforum-org:service:WANCommonInterfaceConfig:1"
	fbSvcWANDSL     = "urn:dslforum-org:service:WANDSLInterfaceConfig:1"
	fbSvcWANPPP     = "urn:dslforum-org:service:WANPPPConnection:1"
	fbSvcWANIP      = "urn:dslforum-org:service:WANIPConnection:1"
	fbSvcUserIf     = "urn:dslforum-org:service:UserInterface:1"
)

// FritzboxConfig sind die Verbindungsdaten einer FRITZ!Box.
type FritzboxConfig struct {
	Address  string        // https://fritz.box:49443
	User     string        // FRITZ!Box-Benutzer
	Password string        // Kennwort (Geheimnis, nie ausgeben)
	Pin      string        // SHA-256 des Zertifikats (hex); leer = System-CA
	Timeout  time.Duration // ganze Runde (0 = DefaultTimeout)
}

// fbDesc ist, was /tr64desc.xml liefert.
type fbDesc struct {
	Model   string
	Version string            // FRITZ!OS, z. B. "8.02"
	Ctrl    map[string]string // Diensttyp -> Steuer-Adresse
}

// Fritzbox ist der Sammler einer FRITZ!Box.
type Fritzbox struct {
	cfg FritzboxConfig
	wc  *webClient
	now func() time.Time
	mu  sync.Mutex // eine Runde zur Zeit

	desc    *fbDesc
	digMu   sync.Mutex
	dig     fbChallenge
	nc      int
	connSvc string // Diensttyp der gueltigen Verbindung
	connAt  time.Time
	crc     *float64 // CRC-Zaehler der vorigen Runde
	updAt   time.Time
	upd     *model.Service
}

// NewFritzbox baut den Sammler (prueft Adresse, Benutzer und Pin; fragt noch nichts ab).
func NewFritzbox(cfg FritzboxConfig) (*Fritzbox, error) { return newFritzbox(cfg, nil) }

func newFritzbox(cfg FritzboxConfig, roots *x509.CertPool) (*Fritzbox, error) {
	t, err := parseWebAddr(cfg.Address, "https", "49443", false)
	if err != nil {
		return nil, err
	}
	if u := strings.TrimSpace(cfg.User); u == "" || strings.ContainsAny(u, "\r\n\":") {
		return nil, errors.New(model.T("monitor64.txt.fb_user_missing"))
	}
	if cfg.Password == "" {
		return nil, errors.New(model.T("monitor64.txt.pmg_pw_missing"))
	}
	wc, err := newWebClient(t, cfg.Pin, roots)
	if err != nil {
		return nil, err
	}
	return &Fritzbox{cfg: cfg, wc: wc, now: time.Now}, nil
}

func (f *Fritzbox) timeout() time.Duration {
	if f.cfg.Timeout > 0 {
		return f.cfg.Timeout
	}
	return DefaultTimeout
}

func (f *Fritzbox) secrets() []string { return []string{f.cfg.Password} }

// Close gibt Verbindungen frei.
func (f *Fritzbox) Close() { f.wc.close() }

// Queries nennt die Abfragen ("Was wird abgefragt?").
func (f *Fritzbox) Queries() []string {
	return []string{"GET /tr64desc.xml", "SOAP Layer3Forwarding:GetDefaultConnectionService", "SOAP WANPPPConnection/WANIPConnection:GetInfo",
		"SOAP WANCommonInterfaceConfig:GetCommonLinkProperties", "SOAP WANCommonInterfaceConfig:X_AVM-DE_GetOnlineMonitor",
		"SOAP WANDSLInterfaceConfig:GetInfo", "SOAP WANDSLInterfaceConfig:GetStatisticsTotal", "SOAP DeviceInfo:GetInfo", "SOAP UserInterface:GetInfo"}
}

func (f *Fritzbox) hint(err error) error {
	switch {
	case errors.Is(err, errWebAuth):
		return fmt.Errorf("%w – %s", err, model.T("monitor64.txt.fb_hint_auth"))
	case errors.Is(err, errWebPerm):
		return fmt.Errorf("%w – %s", err, model.T("monitor64.txt.fb_hint_perm"))
	}
	return err
}

// ---------------------------------------------------------------------------------------------------------
// HTTP: Beschreibung, Digest, SOAP

// fetch sendet eine Anfrage ohne bzw. mit Digest-Kopf und liefert Status, Kopfzeilen und Inhalt (begrenzt).
func (f *Fritzbox) fetch(ctx context.Context, method, path string, body []byte, hdr map[string]string) (int, http.Header, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, f.wc.reqTO)
	defer cancel()
	where := method + " " + path
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, f.wc.t.base+path, rd)
	if err != nil {
		return 0, nil, nil, &webError{Kind: errWebResp, Detail: devText(err.Error()), Where: where}
	}
	req.Header.Set("User-Agent", "node64-monitor64")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := f.wc.hc.Do(req)
	if err != nil {
		return 0, nil, nil, webClassify(err, where)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, fbMaxBody+1))
	if err != nil {
		return 0, nil, nil, webClassify(err, where)
	}
	if len(b) > fbMaxBody {
		return 0, nil, nil, &webError{Kind: errWebResp, Status: resp.StatusCode, Detail: model.T("monitor64.txt.resp_too_large"), Where: where}
	}
	return resp.StatusCode, resp.Header, b, nil
}

// description laedt /tr64desc.xml einmal (ohne Anmeldung).
func (f *Fritzbox) description(ctx context.Context) (*fbDesc, error) {
	if f.desc != nil {
		return f.desc, nil
	}
	st, _, b, err := f.fetch(ctx, http.MethodGet, "/tr64desc.xml", nil, nil)
	if err != nil {
		return nil, err
	}
	if st != http.StatusOK {
		return nil, &webError{Kind: errWebResp, Status: st, Detail: model.T("monitor64.txt.fb_no_tr064"), Where: "GET /tr64desc.xml"}
	}
	d, err := parseFBDesc(b)
	if err != nil || len(d.Ctrl) == 0 {
		return nil, &webError{Kind: errWebResp, Status: st, Detail: model.T("monitor64.txt.fb_no_tr064"), Where: "GET /tr64desc.xml"}
	}
	f.desc = d
	return d, nil
}

// parseFBDesc liest Modell, FRITZ!OS-Version und je Dienst die Steuer-Adresse aus der Beschreibung.
func parseFBDesc(b []byte) (*fbDesc, error) {
	d := &fbDesc{Ctrl: map[string]string{}}
	dec := xml.NewDecoder(bytes.NewReader(b))
	var stack []string
	var svcType, ctrl string
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			stack = append(stack, t.Name.Local)
			if t.Name.Local == "service" {
				svcType, ctrl = "", ""
			}
		case xml.EndElement:
			if t.Name.Local == "service" && svcType != "" && strings.HasPrefix(ctrl, "/") && len(d.Ctrl) < 200 {
				if _, dup := d.Ctrl[svcType]; !dup {
					d.Ctrl[svcType] = ctrl
				}
			}
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			if len(stack) == 0 {
				continue
			}
			v := strings.TrimSpace(string(t))
			if v == "" {
				continue
			}
			parent := ""
			if len(stack) > 1 {
				parent = stack[len(stack)-2]
			}
			switch cur := stack[len(stack)-1]; {
			case cur == "serviceType" && parent == "service":
				svcType = v
			case cur == "controlURL" && parent == "service":
				ctrl = v
			case cur == "modelName" && d.Model == "":
				d.Model = shortText(v)
			case cur == "Display" && parent == "systemVersion":
				d.Version = shortText(v)
			}
		}
	}
	return d, nil
}

// fbChallenge ist die Aufforderung der FRITZ!Box aus WWW-Authenticate (Digest, RFC 2617).
type fbChallenge struct {
	Realm, Nonce, Opaque, QOP, Algorithm string
}

// parseFBChallenge liest einen Digest-Kopf: Liste name=wert bzw. name="wert".
func parseFBChallenge(h string) (fbChallenge, bool) {
	var c fbChallenge
	rest, ok := strings.CutPrefix(strings.TrimSpace(h), "Digest ")
	if !ok && !strings.HasPrefix(strings.ToLower(h), "digest ") {
		return c, false
	}
	if !ok {
		rest = strings.TrimSpace(h)[7:]
	}
	for rest != "" {
		rest = strings.TrimLeft(rest, " ,")
		eq := strings.Index(rest, "=")
		if eq < 0 {
			break
		}
		key := strings.ToLower(strings.TrimSpace(rest[:eq]))
		rest = rest[eq+1:]
		var val string
		if strings.HasPrefix(rest, `"`) {
			end := strings.Index(rest[1:], `"`)
			if end < 0 {
				break
			}
			val, rest = rest[1:1+end], rest[end+2:]
		} else if i := strings.Index(rest, ","); i >= 0 {
			val, rest = strings.TrimSpace(rest[:i]), rest[i+1:]
		} else {
			val, rest = strings.TrimSpace(rest), ""
		}
		switch key {
		case "realm":
			c.Realm = val
		case "nonce":
			c.Nonce = val
		case "opaque":
			c.Opaque = val
		case "qop":
			c.QOP = val
		case "algorithm":
			c.Algorithm = val
		}
	}
	if c.Nonce == "" || len(c.Nonce) > 512 || len(c.Realm) > 256 || strings.ContainsAny(c.Nonce+c.Realm+c.Opaque, "\r\n\"") {
		return c, false
	}
	if a := strings.ToUpper(c.Algorithm); a != "" && a != "MD5" {
		return c, false
	}
	return c, true
}

func md5hex(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

// authorization baut den Digest-Kopf fuer eine Anfrage ("" = noch keine Aufforderung bekannt).
func (f *Fritzbox) authorization(method, uri string) string {
	f.digMu.Lock()
	defer f.digMu.Unlock()
	c := f.dig
	if c.Nonce == "" {
		return ""
	}
	user := strings.TrimSpace(f.cfg.User)
	ha1 := md5hex(user + ":" + c.Realm + ":" + f.cfg.Password)
	ha2 := md5hex(method + ":" + uri)
	h := `Digest username="` + user + `", realm="` + c.Realm + `", nonce="` + c.Nonce + `", uri="` + uri + `", algorithm=MD5`
	if strings.Contains(c.QOP, "auth") {
		f.nc++
		nc := fmt.Sprintf("%08x", f.nc)
		var rb [8]byte
		_, _ = rand.Read(rb[:])
		cnonce := hex.EncodeToString(rb[:])
		h += `, response="` + md5hex(ha1+":"+c.Nonce+":"+nc+":"+cnonce+":auth:"+ha2) + `", qop=auth, nc=` + nc + `, cnonce="` + cnonce + `"`
	} else {
		h += `, response="` + md5hex(ha1+":"+c.Nonce+":"+ha2) + `"`
	}
	if c.Opaque != "" {
		h += `, opaque="` + c.Opaque + `"`
	}
	return h
}

// fbFault ist ein UPnP-Fehler aus einer SOAP-Antwort.
type fbFault struct {
	Code int
	Desc string
}

// soap ruft eine Aktion auf und liefert die Ausgabe-Argumente. Bei 401 wird die Aufforderung uebernommen und einmal
// wiederholt; UPnP-Fehler 606 (Recht fehlt) zaehlt als "keine Berechtigung".
func (f *Fritzbox) soap(ctx context.Context, svc, action string, in map[string]string) (map[string]string, error) {
	d, err := f.description(ctx)
	if err != nil {
		return nil, err
	}
	ctrl, ok := d.Ctrl[svc]
	name := svc
	if f := strings.Split(svc, ":"); len(f) >= 2 {
		name = f[len(f)-2]
	}
	where := "SOAP " + name + "#" + action
	if !ok { // Dienst gibt es auf diesem Modell nicht (z. B. DSL an einer Kabel-Box)
		return nil, &webError{Kind: errWebResp, Status: http.StatusNotFound, Detail: model.T("monitor64.txt.fb_no_service"), Where: where}
	}
	var args strings.Builder
	for k, v := range in {
		args.WriteString("<" + k + ">")
		_ = xml.EscapeText(&args, []byte(v))
		args.WriteString("</" + k + ">")
	}
	body := []byte(`<?xml version="1.0" encoding="utf-8"?>` +
		`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">` +
		`<s:Body><u:` + action + ` xmlns:u="` + svc + `">` + args.String() + `</u:` + action + `></s:Body></s:Envelope>`)
	hdr := map[string]string{"Content-Type": `text/xml; charset="utf-8"`, "SOAPACTION": `"` + svc + "#" + action + `"`}
	for try := 0; ; try++ {
		if a := f.authorization(http.MethodPost, ctrl); a != "" {
			hdr["Authorization"] = a
		}
		st, h, b, err := f.fetch(ctx, http.MethodPost, ctrl, body, hdr)
		if err != nil {
			return nil, err
		}
		switch {
		case st == http.StatusUnauthorized:
			// erste Antwort ohne bzw. mit abgelaufener Aufforderung: uebernehmen und einmal wiederholen; danach sind
			// Benutzer oder Kennwort falsch
			c, ok := parseFBChallenge(h.Get("WWW-Authenticate"))
			if !ok {
				return nil, &webError{Kind: errWebAuth, Status: st, Detail: model.T("monitor64.txt.fb_no_digest"), Where: where}
			}
			f.digMu.Lock()
			f.dig, f.nc = c, 0
			f.digMu.Unlock()
			if try >= 1 {
				return nil, &webError{Kind: errWebAuth, Status: st, Where: where}
			}
		case st == http.StatusServiceUnavailable:
			return nil, &webError{Kind: errWebAuth, Status: st, Detail: model.T("monitor64.txt.fb_too_many"), Where: where}
		case st == http.StatusOK:
			out, _, perr := parseFBResponse(b)
			if perr != nil {
				return nil, &webError{Kind: errWebResp, Status: st, Detail: model.T("monitor64.txt.resp_json") + ": " + devText(perr.Error()), Where: where}
			}
			return out, nil
		default:
			_, fault, _ := parseFBResponse(b)
			e := &webError{Kind: errWebResp, Status: st, Where: where}
			if fault != nil {
				e.Detail = devText("UPnP " + strconv.Itoa(fault.Code) + " " + fault.Desc)
				if fault.Code == 606 {
					e.Kind = errWebPerm
				}
			}
			return nil, e
		}
	}
}

// parseFBResponse liest die Argumente der Antwort (Kinder des ersten Elements im Body) bzw. den UPnP-Fehler.
func parseFBResponse(b []byte) (map[string]string, *fbFault, error) {
	dec := xml.NewDecoder(bytes.NewReader(b))
	out := map[string]string{}
	var fault *fbFault
	depth, bodyAt := 0, -1
	var cur string
	var val strings.Builder
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			switch {
			case t.Name.Local == "Body" && bodyAt < 0:
				bodyAt = depth
			case bodyAt > 0 && depth == bodyAt+2:
				cur = t.Name.Local
				val.Reset()
			case t.Name.Local == "errorCode" || t.Name.Local == "errorDescription":
				cur = t.Name.Local
				val.Reset()
			}
		case xml.CharData:
			if cur != "" && val.Len() < 64<<10 {
				val.Write(t)
			}
		case xml.EndElement:
			if cur != "" && t.Name.Local == cur {
				v := strings.TrimSpace(val.String())
				switch cur {
				case "errorCode":
					if fault == nil {
						fault = &fbFault{}
					}
					fault.Code, _ = strconv.Atoi(v)
				case "errorDescription":
					if fault == nil {
						fault = &fbFault{}
					}
					fault.Desc = v
				default:
					if len(out) < 200 {
						out[cur] = v
					}
				}
				cur = ""
			}
			depth--
		}
	}
	if bodyAt < 0 {
		return nil, nil, errors.New("kein SOAP-Body")
	}
	return out, fault, nil
}

// ---------------------------------------------------------------------------------------------------------
// Test und Runde

// Test prueft die Verbindung im Assistenten (Zertifikat, TR-064 eingeschaltet, Anmeldung, Rechte).
func (f *Fritzbox) Test(ctx context.Context) TestResult {
	ctx, cancel := context.WithTimeout(ctx, f.timeout())
	defer cancel()
	res, proceed := probeCert(ctx, f.wc.t, f.wc.pin, f.wc.roots)
	if !proceed {
		return res
	}
	d, err := f.description(ctx)
	if err != nil {
		res.Error = scrub(f.hint(err).Error(), f.secrets()...)
		return res
	}
	// Anmeldung pruefen: braucht nur irgendein Recht
	link, err := f.soap(ctx, fbSvcWANCommon, "GetCommonLinkProperties", nil)
	if err != nil {
		res.Error = scrub(f.hint(err).Error(), f.secrets()...)
		return res
	}
	res.OK = true
	res.Version, res.Node = d.Version, d.Model
	res.Summary = model.T("monitor64.txt.fb_summary", "m", firstNonEmpty(d.Model, "FRITZ!Box"), "a", fbAccess(link["NewWANAccessType"]))
	var warn []string
	if res.Warning != "" {
		warn = append(warn, res.Warning)
	}
	if _, err := f.soap(ctx, fbSvcDeviceInfo, "GetInfo", nil); errors.Is(err, errWebPerm) {
		warn = append(warn, model.T("monitor64.txt.fb_hint_perm"))
	}
	res.Warning = strings.Join(warn, "; ")
	return res
}

// fbAccess: Zugangsart fuer die Anzeige.
func fbAccess(t string) string {
	switch t {
	case "X_AVM-DE_Fiber":
		return model.T("monitor64.txt.fb_fiber")
	case "X_AVM-DE_Cable":
		return model.T("monitor64.txt.fb_cable")
	case "X_AVM-DE_UMTS", "X_AVM-DE_LTE":
		return model.T("monitor64.txt.fb_mobile")
	case "":
		return "?"
	}
	return shortText(t) // DSL, Ethernet
}

func fbNum(m map[string]string, k string) float64 {
	v, _ := strconv.ParseFloat(strings.TrimSpace(m[k]), 64)
	if !finite(v) {
		return 0
	}
	return v
}

// fbFirst: erster Wert einer Komma-Liste (Online-Monitor: neuester Wert zuerst).
func fbFirst(s string) float64 {
	s, _, _ = strings.Cut(s, ",")
	v, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if !finite(v) || v < 0 {
		return 0
	}
	return v
}

// Collect ist eine Abfragerunde (nicht gleichzeitig mit sich selbst aufrufen).
func (f *Fritzbox) Collect(ctx context.Context) ([]model.Service, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, f.timeout())
	defer cancel()
	now := f.now()
	d, err := f.description(ctx)
	if err != nil {
		return nil, scrubErr(f.hint(err), f.secrets()...)
	}
	link, err := f.soap(ctx, fbSvcWANCommon, "GetCommonLinkProperties", nil)
	if err != nil {
		return nil, scrubErr(f.hint(err), f.secrets()...)
	}
	part := &partial{secrets: f.secrets()}
	add := func(what string, err error, prefixes ...string) { part.add(what, f.hint(err), prefixes...) }
	var out []model.Service
	out = append(out, f.wan(ctx, now, link, add))
	if link["NewWANAccessType"] == "DSL" {
		if s, ok := f.dsl(ctx, add); ok {
			out = append(out, s)
		}
	}
	sys := model.Service{Key: "system", Name: model.Raw(firstNonEmpty(d.Model, "FRITZ!Box")), Kind: "system", Default: true}
	info, err := f.soap(ctx, fbSvcDeviceInfo, "GetInfo", nil)
	ver := d.Version
	switch {
	case err == nil:
		up := time.Duration(fbNum(info, "NewUpTime")) * time.Second
		sys.Metrics = []model.Metric{{Name: "uptime", Value: up.Seconds(), Unit: "s"}}
		sys.Text = model.T("monitor64.txt.fb_system", "v", firstNonEmpty(ver, shortText(info["NewSoftwareVersion"])), "t", model.Sub(hoursText(up)))
	case errors.Is(err, errWebPerm): // ohne das Recht: nur, was die Beschreibung nennt
		sys.Text = model.T("monitor64.txt.fb_system_plain", "v", firstNonEmpty(ver, "?"))
	default:
		add("DeviceInfo", err, "system")
		sys.Text = model.T("monitor64.txt.fb_system_plain", "v", firstNonEmpty(ver, "?"))
	}
	out = append(out, sys)
	if f.updAt.IsZero() || now.Sub(f.updAt) >= fbUpdateEvery {
		ui, err := f.soap(ctx, fbSvcUserIf, "GetInfo", nil)
		if err != nil {
			add("UserInterface", err, "updates")
		} else {
			s := model.Service{Key: "updates", Name: "Updates", Kind: "updates", Default: true, Text: model.T("monitor64.txt.none_pending")}
			if v := strings.TrimSpace(ui["NewUpgradeAvailable"]); v == "1" || strings.EqualFold(v, "true") {
				t := model.T("monitor64.txt.fb_update", "v", firstNonEmpty(shortText(ui["NewX_AVM-DE_Version"]), "?"))
				s.Text = t
				s.Metrics = []model.Metric{{Name: "pending", Value: 1}}
				s.Facts = append(s.Facts, model.Fact{Code: "firmware_update", Text: t})
			} else {
				s.Metrics = []model.Metric{{Name: "pending", Value: 0}}
			}
			f.upd, f.updAt = &s, now
		}
	}
	if f.upd != nil {
		out = append(out, *f.upd)
	}
	sortServices(out)
	return out, part.result()
}

// wan: Internetverbindung (Status, Dauer, externe Adresse, Durchsatz) samt Zustand der Leitung.
func (f *Fritzbox) wan(ctx context.Context, now time.Time, link map[string]string, add func(string, error, ...string)) model.Service {
	s := model.Service{Key: "wan", Name: model.T("monitor64.svc.fb_wan"), Kind: "wan", Default: true}
	parts := []string{fbAccess(link["NewWANAccessType"])}
	if st := link["NewPhysicalLinkStatus"]; st != "" && !strings.EqualFold(st, "Up") {
		t := model.T("monitor64.txt.fb_link_down", "s", shortText(st))
		s.Facts = append(s.Facts, model.Fact{Code: "device_crit", Text: t})
		parts = append(parts, t)
	}
	// Art der Verbindung (PPP bzw. IP) bestimmen und merken
	if f.connSvc == "" || now.Sub(f.connAt) >= fbConnEvery {
		f.connSvc = ""
		if l3, err := f.soap(ctx, fbSvcLayer3, "GetDefaultConnectionService", nil); err == nil {
			switch v := l3["NewDefaultConnectionService"]; {
			case strings.Contains(v, "WANPPPConnection"):
				f.connSvc = fbSvcWANPPP
			case strings.Contains(v, "WANIPConnection"):
				f.connSvc = fbSvcWANIP
			}
		} else if !errors.Is(err, errWebPerm) && !webAbsent(err) {
			add("Layer3Forwarding", err, "wan")
		}
		f.connAt = now
	}
	try := []string{f.connSvc}
	if f.connSvc == "" {
		try = []string{fbSvcWANPPP, fbSvcWANIP}
	}
	var conn map[string]string
	var cerr error
	for _, svc := range try {
		conn, cerr = f.soap(ctx, svc, "GetInfo", nil)
		if cerr == nil && (f.connSvc != "" || strings.EqualFold(conn["NewConnectionStatus"], "Connected") || svc == try[len(try)-1]) {
			break
		}
	}
	switch {
	case cerr != nil:
		add("WANConnection", cerr, "wan")
	case !strings.EqualFold(conn["NewConnectionStatus"], "Connected"):
		t := model.T("monitor64.txt.fb_wan_down", "s", shortText(firstNonEmpty(conn["NewConnectionStatus"], "?")))
		if e := conn["NewLastConnectionError"]; e != "" && e != "ERROR_NONE" {
			t += " (" + devText(e) + ")"
		}
		s.Facts = append(s.Facts, model.Fact{Code: "device_crit", Text: t})
		parts = append(parts, t)
	default:
		up := time.Duration(fbNum(conn, "NewUptime")) * time.Second
		s.Metrics = append(s.Metrics, model.Metric{Name: "uptime", Value: up.Seconds(), Unit: "s"})
		parts = append(parts, model.T("monitor64.txt.fb_wan_up", "t", model.Sub(hoursText(up))))
		if ip := shortText(conn["NewExternalIPAddress"]); ip != "" && ip != "0.0.0.0" {
			parts = append(parts, model.Raw(ip))
		}
	}
	if mon, err := f.soap(ctx, fbSvcWANCommon, "X_AVM-DE_GetOnlineMonitor", map[string]string{"NewSyncGroupIndex": "0"}); err == nil {
		down := (fbFirst(mon["Newds_current_bps"]) + fbFirst(mon["Newmc_current_bps"])) * 8 / 1e6
		up := fbFirst(mon["Newus_current_bps"]) * 8 / 1e6
		s.Metrics = append(s.Metrics, model.Metric{Name: "down", Value: round2(down), Unit: "Mbit/s"}, model.Metric{Name: "up", Value: round2(up), Unit: "Mbit/s"})
		parts = append(parts, model.T("monitor64.txt.fb_rates", "d", mbitText(down), "u", mbitText(up)))
	} else if !errors.Is(err, errWebPerm) && !webAbsent(err) {
		add("OnlineMonitor", err)
	}
	s.Text = strings.Join(parts, " · ")
	return s
}

// dsl: Sync-Raten, Stoerabstand, Daempfung und CRC-Fehler seit der vorigen Runde (false = keine DSL-Werte lesbar).
func (f *Fritzbox) dsl(ctx context.Context, add func(string, error, ...string)) (model.Service, bool) {
	info, err := f.soap(ctx, fbSvcWANDSL, "GetInfo", nil)
	if err != nil {
		if !webAbsent(err) {
			add("WANDSLInterfaceConfig", err, "dsl")
		}
		return model.Service{}, false
	}
	s := model.Service{Key: "dsl", Name: "DSL", Kind: "dsl", Default: true}
	down, up := fbNum(info, "NewDownstreamCurrRate")/1000, fbNum(info, "NewUpstreamCurrRate")/1000 // kbit/s
	snrD, snrU := fbNum(info, "NewDownstreamNoiseMargin")/10, fbNum(info, "NewUpstreamNoiseMargin")/10
	attD, attU := fbNum(info, "NewDownstreamAttenuation")/10, fbNum(info, "NewUpstreamAttenuation")/10
	s.Metrics = []model.Metric{{Name: "down", Value: round2(down), Unit: "Mbit/s"}, {Name: "up", Value: round2(up), Unit: "Mbit/s"},
		{Name: "snr_down", Value: snrD, Unit: "dB"}, {Name: "snr_up", Value: snrU, Unit: "dB"},
		{Name: "att_down", Value: attD, Unit: "dB"}, {Name: "att_up", Value: attU, Unit: "dB"}}
	if st := info["NewStatus"]; !strings.EqualFold(st, "Up") {
		t := model.T("monitor64.txt.fb_dsl_down", "s", shortText(firstNonEmpty(st, "?")))
		s.Facts = append(s.Facts, model.Fact{Code: "device_crit", Text: t})
		s.Text = t
		f.crc = nil
		return s, true
	}
	s.Text = model.T("monitor64.txt.fb_dsl", "d", mbitText(down), "u", mbitText(up),
		"sd", fmt.Sprintf("%.0f", snrD), "su", fmt.Sprintf("%.0f", snrU))
	if st, err := f.soap(ctx, fbSvcWANDSL, "GetStatisticsTotal", nil); err == nil {
		total := fbNum(st, "NewCRCErrors") + fbNum(st, "NewATUCCRCErrors")
		if f.crc != nil && total >= *f.crc {
			s.Metrics = append(s.Metrics, model.Metric{Name: "crc", Value: total - *f.crc})
		}
		f.crc = &total
	} else if !errors.Is(err, errWebPerm) && !webAbsent(err) {
		add("WANDSLInterfaceConfig statistics", err)
	}
	return s, true
}
