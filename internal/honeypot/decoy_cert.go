package honeypot

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/certs"
	"github.com/ipv64net/node64/internal/ipv64api"
)

// Gueltige Zertifikate fuer Koeder-Namen (Modul): Auswahl eines Zertifikats der zentralen Verwaltung (Config.CertID)
// oder Anlegen eines neuen fuer einzelne, glaubwuerdige Namen (mail., vpn., cloud. …, kein Wildcard) unter einer
// ipv64-Domain des Accounts. Ausgestellt wird ueber den vorhandenen Weg der Verwaltung (certs.Manager.Create, DNS-01
// ueber ipv64), nichts eigenes. Auf Wunsch legt das Modul dazu A/AAAA- bzw. CNAME-Records bei ipv64 an (ueber den
// zentralen API-Key, vorhandene Records bleiben unberuehrt). Die Namen stehen danach oeffentlich in den
// Certificate-Transparency-Logs – deshalb eine eigene Domain bzw. Subdomain nehmen, nicht die Hauptdomain.

const (
	certMaxNames = 20 // Namen je neuem Zertifikat
	certMaxPorts = 64 // Eintraege in CertPorts
	certOwner    = "Honeypot64"
)

// certManager ist, was das Modul von der Zertifikatsverwaltung braucht (*certs.Manager; Tests setzen einen Ersatz ein).
type certManager interface {
	List(ctx context.Context) ([]*certs.Cert, error)
	Get(ctx context.Context, id int64) (*certs.Cert, error)
	Create(ctx context.Context, req certs.Request) (*certs.Cert, error)
	Domains(ctx context.Context) ([]string, error)
	DNSReady(ctx context.Context) bool
	ByID(id int64) *tls.Certificate
}

// certSourcer: Sensor, der Zertifikate der Verwaltung zeigen kann (*Sensor).
type certSourcer interface {
	SetCertSource(func(int64) *tls.Certificate)
}

// decoyDNS ist der Zugriff auf die Records des ipv64-Accounts (ueber den zentralen API-Key; Tests setzen einen Ersatz ein).
type decoyDNS interface {
	Records(ctx context.Context, domain string) ([]ipv64api.Record, error)
	Add(ctx context.Context, domain, typ, prefix, content string) error
}

// keyDNS ist decoyDNS ueber den zentralen API-Key.
type keyDNS struct{ k *ipv64api.Key }

func (d keyDNS) Records(ctx context.Context, domain string) ([]ipv64api.Record, error) {
	return d.k.Client().Records(ctx, d.k.Get(ctx), domain)
}

func (d keyDNS) Add(ctx context.Context, domain, typ, prefix, content string) error {
	_, err := d.k.Client().AddRecord(ctx, d.k.Get(ctx), domain, typ, prefix, content)
	return err
}

// SetCerts verbindet das Modul mit der zentralen Zertifikatsverwaltung (nil = keine: alle Fallen selbst signiert).
// Die Verwaltung zeigt das gewaehlte Zertifikat als „benutzt von Honeypot64“ und loescht es nicht ungefragt.
func (m *Module) SetCerts(c *certs.Manager) {
	if c == nil {
		m.certs = nil
		return
	}
	m.certs = c
	c.SetUsers(Name, m.certUsers)
}

// certUsers: Zertifikat der Einstellung (auch bei ausgeschaltetem Modul, damit es nicht ungefragt verschwindet).
func (m *Module) certUsers(ctx context.Context) map[int64][]string {
	if id := m.loadConfig(ctx).CertID; id > 0 {
		return map[int64][]string{id: {certOwner}}
	}
	return nil
}

// certSource liefert die Quelle fuer den Sensor (nil = keine Verwaltung).
func (m *Module) certSource() func(int64) *tls.Certificate {
	if m.certs == nil {
		return nil
	}
	return m.certs.ByID
}

// dnsRecords liefert den Zugriff auf die ipv64-Records (nil = kein API-Key).
func (m *Module) dnsRecords(ctx context.Context) decoyDNS {
	if m.dnsrec != nil {
		return m.dnsrec
	}
	if m.key == nil || m.key.Get(ctx) == "" {
		return nil
	}
	return keyDNS{m.key}
}

// certProblems prueft Zertifikat und Ports (normalisiert CertPorts: sortiert, ohne Doppelte).
func (m *Module) certProblems(ctx context.Context, c *Config) map[string]string {
	out := map[string]string{}
	if c.CertID < 0 {
		c.CertID = 0
	}
	if c.CertID > 0 && m.certs != nil {
		if crt, err := m.certs.Get(ctx, c.CertID); err != nil || crt == nil {
			out["cert_id"] = "honeypot.err.cert|" + strconv.FormatInt(c.CertID, 10)
		}
	}
	var bad []string
	ports := []int{}
	for _, p := range c.CertPorts {
		if p < 1 || p > 65535 {
			bad = append(bad, strconv.Itoa(p))
			continue
		}
		if !slices.Contains(ports, p) {
			ports = append(ports, p)
		}
	}
	slices.Sort(ports)
	switch {
	case len(bad) > 0:
		out["cert_ports"] = "honeypot.err.cert_ports|" + strings.Join(bad, ", ")
	case len(ports) > certMaxPorts:
		out["cert_ports"] = "honeypot.err.cert_ports_many|" + strconv.Itoa(certMaxPorts)
	}
	c.CertPorts = ports
	if len(ports) == 0 {
		c.CertPorts = nil
	}
	return out
}

// parsePorts liest eine Liste von Ports ("443, 8443 10443"); ungueltige Eintraege werden -1 (validate meldet sie).
func parsePorts(v string) []int {
	var out []int
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\r' || r == '\t' }) {
		n, err := strconv.Atoi(f)
		if err != nil {
			n = -1
		}
		out = append(out, n)
	}
	return out
}

// portsText: Ports fuer das Formular.
func portsText(list []int) string {
	parts := make([]string, 0, len(list))
	for _, p := range list {
		parts = append(parts, strconv.Itoa(p))
	}
	return strings.Join(parts, ", ")
}

// CertUses liefert die Dienste der Auswahl, die das Zertifikat zeigen (z. B. "https 443"), fuer Oberflaeche und Tests.
func CertUses(c Config, list []Service, seed string) []string {
	if c.CertID <= 0 {
		return nil
	}
	ps := newSensorPersonas(seed, c.Hostname, c.Personas, c.Vulnerable)
	var out []string
	for _, s := range list {
		k := sensorKey{Service: s.Service, Port: s.Port, Page: s.Page}
		if CertCapable(s.Service) && (slices.Contains(c.CertPorts, s.Port) || CertPublic(s.Service, s.Page, ps.of(k))) {
			out = append(out, s.Service+" "+strconv.Itoa(s.Port))
		}
	}
	return out
}

// uiCert ist ein Zertifikat in der Auswahl.
type uiCert struct {
	ID      int64
	Title   string
	Valid   bool // gueltig und ausgestellt
	Staging bool
	Until   time.Time
	Status  string
}

// certViews liefert die Zertifikate der Verwaltung fuer die Auswahl (ohne Wildcard-Kennzeichnung, alle Wege).
func (m *Module) certViews(ctx context.Context) []uiCert {
	if m.certs == nil {
		return nil
	}
	list, err := m.certs.List(ctx)
	if err != nil {
		m.log.Warn("honeypot: certificates not listed", "err", err)
		return nil
	}
	now := time.Now()
	out := make([]uiCert, 0, len(list))
	for _, c := range list {
		out = append(out, uiCert{ID: c.ID, Title: c.Title(), Staging: c.Staging, Until: c.NotAfter, Status: c.Status,
			Valid: !c.NotAfter.IsZero() && now.Before(c.NotAfter)})
	}
	return out
}

// DecoyNames macht aus der Eingabe (Praefixe oder ganze Namen, getrennt durch Komma, Leerzeichen oder Zeilen) die
// Namen unter domain. Wildcards, Namen ausserhalb der Domain und die Domain selbst sind Fehler (i18n-Schluessel).
func DecoyNames(input, domain string) ([]string, string) {
	domain = strings.Trim(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" || !ValidHostname(domain) {
		return nil, "honeypot.err.cert_domain"
	}
	var out []string
	for _, f := range strings.FieldsFunc(input, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\r' || r == '\t' }) {
		n := strings.Trim(strings.ToLower(f), ".")
		switch {
		case strings.Contains(n, "*"):
			return nil, "honeypot.err.cert_wildcard|" + storeClip(f, 80)
		case n == domain:
			return nil, "honeypot.err.cert_apex|" + domain
		case !strings.HasSuffix(n, "."+domain):
			n += "." + domain
		}
		if !ValidHostname(n) {
			return nil, "honeypot.err.cert_name|" + storeClip(f, 80)
		}
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	switch {
	case len(out) == 0:
		return nil, "honeypot.err.cert_names"
	case len(out) > certMaxNames:
		return nil, "honeypot.err.cert_many|" + strconv.Itoa(certMaxNames)
	}
	return out, ""
}

// dnsTargets liest die Ziele der Records: IPv4 (A), IPv6 (AAAA) oder ein Name (CNAME, dann nur dieser). Leer = keine.
func dnsTargets(v string) (typ map[string]string, err string) {
	out := map[string]string{}
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ';' || r == ' ' }) {
		if a, e := netip.ParseAddr(f); e == nil && a.Zone() == "" {
			a = a.Unmap()
			t := "AAAA"
			if a.Is4() {
				t = "A"
			}
			if out[t] != "" || out["CNAME"] != "" || !reportable(a) {
				return nil, "honeypot.err.cert_dns|" + storeClip(f, 80)
			}
			out[t] = a.String()
			continue
		}
		n := strings.Trim(strings.ToLower(f), ".")
		if !ValidHostname(n) || !strings.Contains(n, ".") || len(out) > 0 {
			return nil, "honeypot.err.cert_dns|" + storeClip(f, 80)
		}
		out["CNAME"] = n
	}
	return out, ""
}

// DNSResult ist das Ergebnis je Name und Typ.
type DNSResult struct {
	Name, Type, Result, Error string // Result: created, exists, error
}

// decoyRecords legt fuer die Namen (alle unter zone) die Records an. Hat ein Name schon A, AAAA oder CNAME, bleibt er
// unberuehrt (exists).
func decoyRecords(ctx context.Context, d decoyDNS, zone string, names []string, targets map[string]string) ([]DNSResult, error) {
	recs, err := d.Records(ctx, zone)
	if err != nil {
		return nil, err
	}
	var out []DNSResult
	for _, n := range names {
		prefix := strings.TrimSuffix(n, "."+zone)
		exists := slices.ContainsFunc(recs, func(r ipv64api.Record) bool {
			t := strings.ToUpper(r.Type)
			return strings.EqualFold(r.Prefix, prefix) && (t == "A" || t == "AAAA" || t == "CNAME")
		})
		for _, typ := range []string{"A", "AAAA", "CNAME"} {
			v := targets[typ]
			if v == "" {
				continue
			}
			res := DNSResult{Name: n, Type: typ, Result: "created"}
			switch {
			case exists:
				res.Result = "exists"
			default:
				if err := d.Add(ctx, zone, typ, prefix, v); err != nil {
					res.Result, res.Error = "error", err.Error()
				}
			}
			out = append(out, res)
		}
	}
	return out, nil
}

// pageCert legt ein Zertifikat fuer Koeder-Namen an (Weg der Verwaltung), waehlt es in der Einstellung und legt auf
// Wunsch die DNS-Records an.
func (m *Module) pageCert(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	back := func(kind, text string) {
		m.g.Flash(w, r, kind, text)
		http.Redirect(w, r, "/honeypot/settings#zertifikat", http.StatusSeeOther)
	}
	if m.certs == nil {
		back("danger", m.g.T(r, "honeypot.cert.unavailable"))
		return
	}
	if !m.certs.DNSReady(ctx) {
		back("danger", m.g.T(r, "honeypot.cert.nokey"))
		return
	}
	domain := strings.ToLower(strings.TrimSpace(r.PostFormValue("cert_domain")))
	domains, err := m.certs.Domains(ctx)
	if err != nil {
		back("danger", m.g.T(r, "honeypot.cert.err_domains", "error", err.Error()))
		return
	}
	if !slices.Contains(domains, domain) {
		back("danger", m.errText(r, "honeypot.err.cert_domain"))
		return
	}
	names, bad := DecoyNames(r.PostFormValue("cert_names"), domain)
	if bad != "" {
		back("danger", m.errText(r, bad))
		return
	}
	targets, bad := dnsTargets(r.PostFormValue("dns_target"))
	if bad != "" {
		back("danger", m.errText(r, bad))
		return
	}
	crt, err := m.certs.Create(ctx, certs.Request{Names: names, Source: certs.SourceIPv64})
	var ve *certs.ValidationError
	switch {
	case errors.Is(err, certs.ErrTOS):
		back("danger", m.g.T(r, "honeypot.cert.err_tos"))
		return
	case errors.Is(err, certs.ErrNoKey):
		back("danger", m.g.T(r, "honeypot.cert.nokey"))
		return
	case errors.As(err, &ve):
		back("danger", m.g.T(r, "honeypot.cert.err_create", "error", ve.Error()))
		return
	case err != nil:
		m.log.Error("honeypot: certificate not created", "err", err)
		back("danger", m.g.T(r, "honeypot.cert.err_create", "error", err.Error()))
		return
	}
	c := m.loadConfig(ctx)
	c.CertID = crt.ID
	details := "cert=" + strconv.FormatInt(crt.ID, 10) + " names=" + strings.Join(names, ",")
	msg, kind := m.g.T(r, "honeypot.cert.created", "names", strings.Join(names, ", ")), "success"
	if _, err := m.SaveConfig(ctx, c); err != nil { // z. B. andere Einstellung inzwischen ungueltig: von Hand waehlen
		m.log.Warn("honeypot: certificate created but not selected", "id", crt.ID, "err", err)
		msg, kind = m.g.T(r, "honeypot.cert.created_unselected", "names", strings.Join(names, ", ")), "warning"
	}
	if len(targets) > 0 {
		var res []DNSResult
		d := m.dnsRecords(ctx)
		if d == nil {
			err = errors.New("no ipv64 API key")
		} else {
			res, err = decoyRecords(ctx, d, domain, names, targets)
		}
		if err != nil {
			msg += " " + m.g.T(r, "honeypot.cert.dns_failed", "error", err.Error())
			kind = "warning"
		} else {
			var created, exists, failed []string
			for _, x := range res {
				switch x.Result {
				case "created":
					created = append(created, x.Name+" "+x.Type)
				case "exists":
					exists = append(exists, x.Name)
				default:
					failed = append(failed, x.Name+" "+x.Type+": "+x.Error)
					kind = "warning"
				}
			}
			slices.Sort(exists)
			exists = slices.Compact(exists)
			msg += " " + m.g.T(r, "honeypot.cert.dns_created", "count", len(created))
			if len(exists) > 0 {
				msg += " " + m.g.T(r, "honeypot.cert.dns_exists", "names", strings.Join(exists, ", "))
			}
			if len(failed) > 0 {
				msg += " " + m.g.T(r, "honeypot.cert.dns_errors", "errors", strings.Join(failed, "; "))
			}
			details += " dns=" + strconv.Itoa(len(created))
		}
	}
	m.log.Info("decoy certificate requested", "id", crt.ID, "names", strings.Join(names, ","), "by", m.g.Actor(r))
	m.g.Audit(r, "honeypot.config", "cert", details)
	back(kind, msg)
}
