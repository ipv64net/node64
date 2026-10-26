package checks

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/idna"
)

// WHOIS-Check: fragt die Registrierungsdaten einer Domain, einer IP (bzw. eines Netzes) oder eines AS ab – zuerst per
// RDAP (HTTPS/JSON, zustaendiger Server ueber den IANA-Bootstrap), sonst per klassischem WHOIS (Port 43, Kette
// whois.iana.org -> zustaendiger Server; noetig z. B. fuer .de, DENIC hat kein vollstaendiges RDAP).
//
// Bewertung: gestoert, wenn die Abfrage scheitert, die Domain nicht (mehr) registriert ist, sie in weniger als
// min_days Tagen ablaeuft oder ein erwarteter Wert fehlt (contains, z. B. "nameserver: ns1.example.org").
// Die gefundenen Angaben stehen in den Details. Ein Mindestintervall (MinIntervalWhois) schont die Server.

// WhoisParams gelten fuer den Typ whois.
type WhoisParams struct {
	Source   string   `json:"source,omitempty"`   // auto (Standard: RDAP, sonst WHOIS), rdap, whois
	MinDays  *int     `json:"min_days,omitempty"` // Domains: Restlaufzeit-Schwelle in Tagen, Standard 14, 0 = nur abgelaufen
	Contains []string `json:"contains,omitempty"` // erwartete Werte: "text" oder "feld: text" (registrar, nameserver, status, org, country, city, netname, cidr, asn)
}

const (
	DefaultWhoisMinDays = 14
	MinIntervalWhois    = time.Hour        // WHOIS/RDAP-Server begrenzen Abfragen: hoechstens stuendlich
	MinRetryWhois       = 10 * time.Minute // Wiederholung im gestoerten Zustand
	whoisMaxBody        = 256 << 10
	whoisPort           = "43"
)

// WhoisSources ist die Auswahl im Formular.
var WhoisSources = []string{"auto", "rdap", "whois"}

// WhoisFields sind die Felder, die eine contains-Regel nennen darf.
var WhoisFields = []string{"registrar", "nameserver", "status", "org", "country", "city", "netname", "cidr", "asn", "name"}

// Gruende des WHOIS-Checks.
const (
	ReasonWhoisFailed   Reason = "whois_failed"
	ReasonWhoisNotFound Reason = "whois_not_found"
	ReasonWhoisExpiring Reason = "whois_expiring"
	ReasonWhoisExpired  Reason = "whois_expired"
	ReasonWhoisMismatch Reason = "whois_mismatch"
)

// WhoisInfo ist das gemeinsame Ergebnis von RDAP und WHOIS.
type WhoisInfo struct {
	Kind        string    // domain, ip, asn
	Source      string    // rdap, whois
	Server      string    // abgefragter Server (URL bzw. host)
	Name        string    // Domain bzw. Netz-/AS-Name (netname)
	Handle      string    // Kennung beim Register
	Registrar   string    // Domains
	Status      []string  // Domains: Status
	Nameservers []string  // Domains
	Created     time.Time // Registrierung
	Updated     time.Time // letzte Aenderung
	Expires     time.Time // Domains: Ablauf
	CIDR        []string  // IP: Netze
	Range       string    // IP: erste - letzte Adresse
	ASN         string    // AS bzw. Ursprungs-AS einer Route
	Org         string    // Inhaber/Organisation
	Country     string
	City        string
	Address     string
	Abuse       string // Abuse-Kontakt (E-Mail)
	NotFound    bool   // nicht registriert
}

// whoisKind ordnet das Ziel ein: ip (Adresse oder Netz), asn (AS123 oder 123) oder domain.
func whoisKind(target string) (kind, query string, err error) {
	t := strings.TrimSpace(target)
	t = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(t, "https://"), "http://"), "/")
	if i := strings.IndexAny(t, "/?#"); i >= 0 && !strings.Contains(t[:i], ":") && net.ParseIP(t[:i]) == nil {
		t = t[:i] // URL-Pfad weg
	}
	if p, err := netip.ParsePrefix(t); err == nil {
		return "ip", p.Masked().String(), nil
	}
	if a, err := netip.ParseAddr(strings.Trim(t, "[]")); err == nil {
		return "ip", a.Unmap().String(), nil
	}
	u := strings.ToUpper(t)
	if n, ok := strings.CutPrefix(u, "AS"); ok {
		u = n
	}
	if n, err := strconv.ParseUint(u, 10, 32); err == nil && n > 0 {
		return "asn", strconv.FormatUint(n, 10), nil
	}
	d := strings.ToLower(strings.TrimSuffix(t, "."))
	if !strings.Contains(d, ".") || strings.ContainsAny(d, " @:") || len(d) > 253 {
		return "", "", errors.New("target must be a domain, an IP address/network or an AS number (AS3320)")
	}
	if a, err := idna.Lookup.ToASCII(d); err == nil { // Umlaut-Domains als Punycode (wie der DNS-Check)
		d = a
	}
	return "domain", d, nil
}

func validateWhois(def Definition) error {
	if _, _, err := whoisKind(def.Target); err != nil {
		return err
	}
	var p WhoisParams
	if err := decode(def.Params, &p); err != nil {
		return err
	}
	switch p.Source {
	case "", "auto", "rdap", "whois":
	default:
		return errors.New("source must be auto, rdap or whois")
	}
	if p.MinDays != nil && (*p.MinDays < 0 || *p.MinDays > 3650) {
		return errors.New("min_days must be between 0 and 3650")
	}
	if len(p.Contains) > 20 {
		return errors.New("at most 20 contains rules")
	}
	for _, c := range p.Contains {
		if len(c) > 200 {
			return errors.New("contains: rule too long (max. 200 characters)")
		}
	}
	return nil
}

func slicesContains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// splitWhoisRule: "feld: text" mit bekanntem Feld (WhoisFields) -> (feld, text, true); sonst ganzer Text ("", r, false)
// – gesucht wird dann in allen Angaben (z. B. eine IPv6-Adresse mit Doppelpunkten).
func splitWhoisRule(r string) (field, text string, ok bool) {
	r = strings.TrimSpace(r)
	if i := strings.Index(r, ":"); i > 0 {
		if f := strings.ToLower(strings.TrimSpace(r[:i])); slicesContains(WhoisFields, f) {
			return f, strings.TrimSpace(r[i+1:]), true
		}
	}
	return "", r, false
}

type whoisChecker struct{ r *Runner }

func (whoisChecker) Type() Type { return TypeWhois }

func (c whoisChecker) Check(ctx context.Context, def Definition, _ net.IP) Result {
	var p WhoisParams
	if err := decode(def.Params, &p); err != nil {
		return fail(ReasonInvalid, err.Error(), 0, nil)
	}
	kind, query, err := whoisKind(def.Target)
	if err != nil {
		return fail(ReasonInvalid, err.Error(), 0, nil)
	}
	start := time.Now()
	info, err := c.lookup(ctx, kind, query, p.Source)
	lat := time.Since(start)
	if err != nil {
		if isTimeout(err) {
			return fail(ReasonTimeout, "whois: "+shortErr(err), lat, map[string]any{"kind": kind, "query": query})
		}
		return fail(ReasonWhoisFailed, shortErr(err), lat, map[string]any{"kind": kind, "query": query})
	}
	details := info.details()
	details["query"] = query
	if info.NotFound {
		return fail(ReasonWhoisNotFound, query+" is not registered", lat, details)
	}
	if kind == "domain" && !info.Expires.IsZero() {
		minDays := DefaultWhoisMinDays
		if p.MinDays != nil {
			minDays = *p.MinDays
		}
		days := int(time.Until(info.Expires).Hours() / 24)
		details["days_left"] = days
		if time.Now().After(info.Expires) {
			return fail(ReasonWhoisExpired, fmt.Sprintf("domain expired on %s", info.Expires.UTC().Format("2006-01-02")), lat, details)
		}
		if days < minDays {
			return fail(ReasonWhoisExpiring, fmt.Sprintf("domain expires in %d days (%s)", days, info.Expires.UTC().Format("2006-01-02")), lat, details)
		}
	}
	if miss := info.missing(p.Contains); miss != "" {
		return fail(ReasonWhoisMismatch, "expected not found: "+miss, lat, details)
	}
	return Result{Status: Up, Reason: ReasonOK, Message: info.summary(), Latency: lat, Details: details}
}

// lookup: RDAP, bei source auto ohne RDAP-Server oder mit Fehler (ausser "nicht gefunden") per WHOIS.
func (c whoisChecker) lookup(ctx context.Context, kind, query, source string) (*WhoisInfo, error) {
	if source != "whois" {
		info, err := rdapLookup(ctx, kind, query)
		if err == nil || source == "rdap" {
			return info, err
		}
		if winfo, werr := whoisLookup(ctx, kind, query); werr == nil {
			return winfo, nil
		} else {
			return nil, fmt.Errorf("rdap: %v; whois: %v", shortErr(err), shortErr(werr))
		}
	}
	return whoisLookup(ctx, kind, query)
}

// ---------------------------------------------------------------- Ergebnis

func (i *WhoisInfo) details() map[string]any {
	d := map[string]any{"kind": i.Kind, "source": i.Source, "server": i.Server}
	set := func(k, v string) {
		if strings.TrimSpace(v) != "" {
			d[k] = strings.TrimSpace(v)
		}
	}
	set("name", i.Name)
	set("handle", i.Handle)
	set("registrar", i.Registrar)
	set("range", i.Range)
	set("asn", i.ASN)
	set("org", i.Org)
	set("country", i.Country)
	set("city", i.City)
	set("address", i.Address)
	set("abuse", i.Abuse)
	if len(i.Status) > 0 {
		d["status"] = i.Status
	}
	if len(i.Nameservers) > 0 {
		d["nameservers"] = i.Nameservers
	}
	if len(i.CIDR) > 0 {
		d["cidr"] = i.CIDR
	}
	for k, t := range map[string]time.Time{"created": i.Created, "updated": i.Updated, "expires": i.Expires} {
		if !t.IsZero() {
			d[k] = t.UTC().Format("2006-01-02")
		}
	}
	return d
}

func (i *WhoisInfo) summary() string {
	var parts []string
	add := func(label, v string) {
		if v != "" {
			parts = append(parts, label+" "+v)
		}
	}
	switch i.Kind {
	case "domain":
		add("registrar", i.Registrar)
		if !i.Expires.IsZero() {
			parts = append(parts, fmt.Sprintf("expires %s (%d days)", i.Expires.UTC().Format("2006-01-02"), int(time.Until(i.Expires).Hours()/24)))
		}
		if len(i.Nameservers) > 0 {
			parts = append(parts, "ns "+strings.Join(i.Nameservers, ", "))
		}
		if len(parts) == 0 && len(i.Status) > 0 {
			parts = append(parts, "status "+strings.Join(i.Status, ", "))
		}
	default:
		add("", i.Name)
		if len(i.CIDR) > 0 {
			parts = append(parts, strings.Join(i.CIDR, ", "))
		} else {
			add("", i.Range)
		}
		add("AS", strings.TrimPrefix(strings.ToUpper(i.ASN), "AS"))
		add("", i.Org)
		add("", strings.TrimSpace(strings.Join([]string{i.City, i.Country}, " ")))
	}
	s := strings.TrimSpace(strings.Join(parts, " · "))
	s = strings.ReplaceAll(s, "  ", " ")
	if s == "" {
		s = i.Source + " answer from " + i.Server
	}
	return strings.TrimPrefix(s, " ")
}

// hasData: die Antwort enthaelt verwertbare Angaben.
func (i *WhoisInfo) hasData() bool {
	return i.Registrar != "" || len(i.Nameservers) > 0 || len(i.Status) > 0 || !i.Expires.IsZero() || !i.Created.IsZero() || !i.Updated.IsZero() ||
		i.Range != "" || len(i.CIDR) > 0 || i.ASN != "" || i.Org != "" || (i.Kind != "domain" && i.Name != "")
}

// fieldValues: Werte eines Felds fuer contains-Regeln.
func (i *WhoisInfo) fieldValues(f string) []string {
	switch f {
	case "registrar":
		return []string{i.Registrar}
	case "nameserver":
		return i.Nameservers
	case "status":
		return i.Status
	case "org":
		return []string{i.Org}
	case "country":
		return []string{i.Country}
	case "city":
		return []string{i.City, i.Address}
	case "netname", "name":
		return []string{i.Name}
	case "cidr":
		return append(append([]string{}, i.CIDR...), i.Range)
	case "asn":
		return []string{i.ASN, "AS" + strings.TrimPrefix(strings.ToUpper(i.ASN), "AS")}
	}
	return nil
}

// missing: erste Regel, die nicht passt ("" = alle passen). Vergleich ohne Gross-/Kleinschreibung, Teilstring.
func (i *WhoisInfo) missing(rules []string) string {
	all := strings.ToLower(strings.Join(append(append(append([]string{i.Name, i.Handle, i.Registrar, i.Range, i.ASN, i.Org, i.Country, i.City, i.Address, i.Abuse},
		i.Status...), i.Nameservers...), i.CIDR...), "\n"))
	for _, r := range rules {
		f, want, ok := splitWhoisRule(r)
		w := strings.ToLower(strings.TrimSuffix(want, "."))
		if w == "" {
			continue
		}
		if !ok {
			if !strings.Contains(all, w) {
				return r
			}
			continue
		}
		found := false
		for _, v := range i.fieldValues(f) {
			if strings.Contains(strings.ToLower(strings.TrimSuffix(v, ".")), w) {
				found = true
				break
			}
		}
		if !found {
			return r
		}
	}
	return ""
}

// ---------------------------------------------------------------- RDAP

// rdapBootstrapURL: IANA-Verzeichnisse der RDAP-Server; austauschbar fuer Tests.
var rdapBootstrapURL = "https://data.iana.org/rdap/"

type rdapBootstrap struct {
	Services [][][]string `json:"services"`
}

var rdapCache struct {
	mu   sync.Mutex
	at   map[string]time.Time
	data map[string]*rdapBootstrap
}

// rdapBase liefert die RDAP-Basis-URL fuer eine Anfrage aus dem IANA-Bootstrap (24 h zwischengespeichert).
func rdapBase(ctx context.Context, kind, query string) (string, error) {
	file := map[string]string{"domain": "dns.json", "asn": "asn.json"}[kind]
	if kind == "ip" {
		file = "ipv4.json"
		if strings.Contains(query, ":") {
			file = "ipv6.json"
		}
	}
	rdapCache.mu.Lock()
	if rdapCache.data == nil {
		rdapCache.at, rdapCache.data = map[string]time.Time{}, map[string]*rdapBootstrap{}
	}
	bs, at := rdapCache.data[file], rdapCache.at[file]
	rdapCache.mu.Unlock()
	if bs == nil || time.Since(at) > 24*time.Hour {
		var fresh rdapBootstrap
		if err := httpJSON(ctx, rdapBootstrapURL+file, "application/json", &fresh); err != nil {
			if bs == nil {
				return "", fmt.Errorf("rdap bootstrap: %w", err)
			}
		} else {
			bs = &fresh
			rdapCache.mu.Lock()
			rdapCache.data[file], rdapCache.at[file] = bs, time.Now()
			rdapCache.mu.Unlock()
		}
	}
	best, bestLen := "", -1
	for _, svc := range bs.Services {
		if len(svc) < 2 || len(svc[1]) == 0 {
			continue
		}
		for _, key := range svc[0] {
			if l, ok := rdapMatch(kind, query, key); ok && l > bestLen {
				best, bestLen = svc[1][0], l
				for _, u := range svc[1] { // https bevorzugen
					if strings.HasPrefix(u, "https://") {
						best = u
						break
					}
				}
			}
		}
	}
	if best == "" {
		return "", errNoRDAP
	}
	return strings.TrimSuffix(best, "/") + "/", nil
}

var errNoRDAP = errors.New("no RDAP server for this target")

// rdapMatch: passt ein Bootstrap-Eintrag (TLD, Netz bzw. AS-Bereich)? l = Laenge fuer "genauester gewinnt".
func rdapMatch(kind, query, key string) (int, bool) {
	switch kind {
	case "domain":
		k := strings.ToLower(key)
		if query == k || strings.HasSuffix(query, "."+k) {
			return len(k), true
		}
	case "ip":
		pfx, err := netip.ParsePrefix(key)
		if err != nil {
			return 0, false
		}
		var a netip.Addr
		if p, err := netip.ParsePrefix(query); err == nil {
			a = p.Addr()
		} else if a, err = netip.ParseAddr(query); err != nil {
			return 0, false
		}
		if pfx.Contains(a) {
			return pfx.Bits(), true
		}
	case "asn":
		lo, hi, ok := strings.Cut(key, "-")
		if !ok {
			hi = lo
		}
		n, _ := strconv.ParseUint(query, 10, 32)
		l, e1 := strconv.ParseUint(lo, 10, 32)
		h, e2 := strconv.ParseUint(hi, 10, 32)
		if e1 == nil && e2 == nil && n >= l && n <= h {
			return int(4294967295 - (h - l)), true
		}
	}
	return 0, false
}

type rdapEntity struct {
	Roles      []string        `json:"roles"`
	Handle     string          `json:"handle"`
	VCardArray json.RawMessage `json:"vcardArray"`
	Entities   []rdapEntity    `json:"entities"`
}

type rdapEvent struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

type rdapObject struct {
	ObjectClass string       `json:"objectClassName"`
	Handle      string       `json:"handle"`
	LDHName     string       `json:"ldhName"`
	Name        string       `json:"name"`
	Status      []string     `json:"status"`
	Events      []rdapEvent  `json:"events"`
	Entities    []rdapEntity `json:"entities"`
	Nameservers []struct {
		LDHName string `json:"ldhName"`
	} `json:"nameservers"`
	StartAddress string `json:"startAddress"`
	EndAddress   string `json:"endAddress"`
	Country      string `json:"country"`
	CIDRs        []struct {
		V4Prefix string `json:"v4prefix"`
		V6Prefix string `json:"v6prefix"`
		Length   int    `json:"length"`
	} `json:"cidr0_cidrs"`
	StartAutnum int `json:"startAutnum"`
	EndAutnum   int `json:"endAutnum"`
}

func rdapLookup(ctx context.Context, kind, query string) (*WhoisInfo, error) {
	base, err := rdapBase(ctx, kind, query)
	if err != nil {
		return nil, err
	}
	path := map[string]string{"domain": "domain/", "ip": "ip/", "asn": "autnum/"}[kind] + query
	var o rdapObject
	url := base + path
	if err := httpJSON(ctx, url, "application/rdap+json", &o); err != nil {
		var nf errNotFound
		if errors.As(err, &nf) {
			return &WhoisInfo{Kind: kind, Source: "rdap", Server: hostOf(url), NotFound: true}, nil
		}
		return nil, err
	}
	i := &WhoisInfo{Kind: kind, Source: "rdap", Server: hostOf(url), Handle: o.Handle, Status: o.Status, Country: o.Country}
	i.Name = o.Name
	if kind == "domain" {
		i.Name = strings.ToLower(o.LDHName)
	}
	for _, ev := range o.Events {
		t := parseWhoisTime(ev.Date)
		switch ev.Action {
		case "registration":
			i.Created = t
		case "last changed":
			i.Updated = t
		case "expiration":
			i.Expires = t
		}
	}
	for _, ns := range o.Nameservers {
		if n := strings.ToLower(strings.TrimSuffix(ns.LDHName, ".")); n != "" {
			i.Nameservers = append(i.Nameservers, n)
		}
	}
	sort.Strings(i.Nameservers)
	if o.StartAddress != "" {
		i.Range = o.StartAddress + " - " + o.EndAddress
	}
	for _, c := range o.CIDRs {
		if c.V4Prefix != "" {
			i.CIDR = append(i.CIDR, c.V4Prefix+"/"+strconv.Itoa(c.Length))
		} else if c.V6Prefix != "" {
			i.CIDR = append(i.CIDR, c.V6Prefix+"/"+strconv.Itoa(c.Length))
		}
	}
	if o.StartAutnum > 0 {
		i.ASN = strconv.Itoa(o.StartAutnum)
	}
	var walk func([]rdapEntity)
	walk = func(list []rdapEntity) {
		for _, e := range list {
			v := parseVCard(e.VCardArray)
			for _, role := range e.Roles {
				switch role {
				case "registrar":
					if i.Registrar == "" {
						i.Registrar = v.fn
					}
				case "registrant", "administrative":
					if i.Org == "" && (v.org != "" || v.fn != "") {
						i.Org = firstNonEmpty(v.org, v.fn)
						if i.Country == "" {
							i.Country = v.country
						}
						i.City, i.Address = firstNonEmpty(i.City, v.city), firstNonEmpty(i.Address, v.address)
					}
				case "abuse":
					if i.Abuse == "" {
						i.Abuse = v.email
					}
				}
			}
			walk(e.Entities)
		}
	}
	walk(o.Entities)
	return i, nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

type vcard struct{ fn, org, email, city, country, address string }

// parseVCard liest jCard (RFC 7095): ["vcard", [[name, params, type, value], ...]].
func parseVCard(raw json.RawMessage) vcard {
	var v vcard
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) != nil || len(arr) < 2 {
		return v
	}
	var props [][]json.RawMessage
	if json.Unmarshal(arr[1], &props) != nil {
		return v
	}
	str := func(r json.RawMessage) string {
		var s string
		if json.Unmarshal(r, &s) == nil {
			return s
		}
		return ""
	}
	for _, p := range props {
		if len(p) < 4 {
			continue
		}
		switch str(p[0]) {
		case "fn":
			v.fn = str(p[3])
		case "org":
			if s := str(p[3]); s != "" {
				v.org = s
			} else {
				var a []string
				if json.Unmarshal(p[3], &a) == nil && len(a) > 0 {
					v.org = a[0]
				}
			}
		case "email":
			v.email = str(p[3])
		case "adr":
			var params struct {
				Label string `json:"label"`
				CC    string `json:"cc"`
			}
			_ = json.Unmarshal(p[1], &params)
			v.address = strings.Join(strings.Fields(strings.ReplaceAll(params.Label, "\n", ", ")), " ")
			var parts []any
			if json.Unmarshal(p[3], &parts) == nil && len(parts) >= 7 {
				if s, ok := parts[3].(string); ok {
					v.city = s
				}
				if s, ok := parts[6].(string); ok && len(s) == 2 {
					v.country = strings.ToUpper(s)
				}
			}
			if v.country == "" && len(params.CC) == 2 {
				v.country = strings.ToUpper(params.CC)
			}
		}
	}
	return v
}

type errNotFound struct{ status int }

func (e errNotFound) Error() string { return "not found (HTTP " + strconv.Itoa(e.status) + ")" }

// whoisHTTP: Client fuer RDAP (Ziel-Pruefung ueber guard: auf den hubs nur oeffentliche Adressen, auch nach
// Weiterleitungen – die RIRs leiten zwischen einander weiter).
func whoisHTTP(ctx context.Context) *http.Client {
	d := guard(ctx, &net.Dialer{Timeout: 5 * time.Second})
	tr := &http.Transport{Proxy: nil, DialContext: d.DialContext, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 15 * time.Second,
		DisableKeepAlives: true, MaxResponseHeaderBytes: 64 << 10}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second, CheckRedirect: func(_ *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errTooManyRedirects
		}
		return nil
	}}
}

func httpJSON(ctx context.Context, url, accept string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", UserAgent)
	c := whoisHTTP(ctx)
	defer c.CloseIdleConnections()
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, whoisMaxBody))
	if resp.StatusCode == http.StatusNotFound {
		return errNotFound{resp.StatusCode}
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, hostOf(url))
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("invalid answer from %s", hostOf(url))
	}
	return nil
}

func hostOf(u string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return s
}

// ---------------------------------------------------------------- WHOIS (Port 43)

// whoisIANA: Startpunkt der Referral-Kette; austauschbar fuer Tests ("host:port").
var whoisIANA = "whois.iana.org:43"

// whoisQueryFor: Anfrage je Server (DENIC liefert Nameserver nur mit -T dn, ARIN Netze mit "n").
func whoisQueryFor(server, kind, query string) string {
	host := strings.ToLower(server)
	if i := strings.LastIndexByte(host, ':'); i > 0 {
		host = host[:i]
	}
	switch {
	case host == "whois.denic.de" && kind == "domain":
		return "-T dn " + query
	case host == "whois.arin.net" && kind == "ip":
		return "n + " + query
	case host == "whois.arin.net" && kind == "asn":
		return "a + " + query
	case kind == "asn":
		return "AS" + query
	}
	return query
}

func whoisLookup(ctx context.Context, kind, query string) (*WhoisInfo, error) {
	server := whoisIANA
	q := query
	if kind == "asn" {
		q = "AS" + query
	}
	var text string
	for hop := 0; hop < 3; hop++ {
		t, err := whoisQuery(ctx, server, q)
		if err != nil {
			if hop == 0 {
				return nil, err
			}
			break // naechster Server nicht erreichbar: mit dem letzten Stand weiter
		}
		text = t
		ref := whoisReferral(t)
		if ref == "" || strings.EqualFold(ref, server) || hop == 2 {
			break
		}
		if !strings.Contains(ref, ":") {
			ref += ":" + whoisPort
		}
		if strings.EqualFold(ref, server) {
			break
		}
		server = ref
		q = whoisQueryFor(server, kind, query)
	}
	i := parseWhoisText(text, kind)
	i.Source, i.Server = "whois", strings.TrimSuffix(server, ":"+whoisPort)
	if !i.NotFound && !i.hasData() {
		return nil, fmt.Errorf("no whois data from %s", i.Server)
	}
	return i, nil
}

// whoisReferral: zustaendiger Server aus einer Antwort (IANA "refer:", Registry "Registrar WHOIS Server:" nur, wenn
// noch keine Daten da sind – die Registry-Antwort reicht fuer Ablauf und Nameserver).
func whoisReferral(text string) string {
	for _, line := range strings.Split(text, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "refer", "whois":
			v = strings.TrimSpace(v)
			if v != "" && !strings.Contains(v, " ") {
				return strings.TrimPrefix(strings.TrimPrefix(v, "whois://"), "rwhois://")
			}
		}
	}
	return ""
}

func whoisQuery(ctx context.Context, server, query string) (string, error) {
	d := guard(ctx, &net.Dialer{Timeout: 5 * time.Second})
	conn, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	deadline := time.Now().Add(15 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	if _, err := io.WriteString(conn, query+"\r\n"); err != nil {
		return "", err
	}
	b, err := io.ReadAll(io.LimitReader(conn, whoisMaxBody))
	if err != nil && len(b) == 0 {
		return "", err
	}
	return string(b), nil
}

var whoisNotFound = regexp.MustCompile(`(?i)^(no match|not found|no entries found|no data found|status:\s*free|domain not found|the queried object does not exist|% no such domain|no object found|this query returned 0 objects)`)

// parseWhoisText liest die gaengigen Schluessel der Registries und RIRs (Gross-/Kleinschreibung egal).
func parseWhoisText(text, kind string) *WhoisInfo {
	i := &WhoisInfo{Kind: kind}
	var addr []string
	seenNS := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64<<10), whoisMaxBody)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ">>>") {
			if whoisNotFound.MatchString(strings.TrimLeft(line, "%# ")) {
				i.NotFound = true
			}
			continue
		}
		if whoisNotFound.MatchString(line) {
			i.NotFound = true
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		if v == "" {
			continue
		}
		switch k {
		case "domain name", "domain":
			if i.Name == "" && kind == "domain" {
				i.Name = strings.ToLower(v)
			}
		case "registrar", "sponsoring registrar", "registrar name":
			if i.Registrar == "" {
				i.Registrar = v
			}
		case "name server", "nserver", "nameserver", "name servers":
			n := strings.ToLower(strings.TrimSuffix(strings.Fields(v)[0], "."))
			if !seenNS[n] {
				seenNS[n] = true
				i.Nameservers = append(i.Nameservers, n)
			}
		case "domain status", "status":
			s := strings.Fields(v)[0]
			if kind == "domain" && !slicesContains(i.Status, s) {
				i.Status = append(i.Status, s)
			}
			if kind == "domain" && strings.EqualFold(s, "free") {
				i.NotFound = true
			}
		case "registry expiry date", "registrar registration expiration date", "expiration date", "expiry date", "expires", "expire", "paid-till", "renewal date", "valid until":
			if t := parseWhoisTime(v); !t.IsZero() && (i.Expires.IsZero() || t.Before(i.Expires)) {
				i.Expires = t
			}
		case "creation date", "created", "registered", "registration time", "regdate":
			if t := parseWhoisTime(v); !t.IsZero() && i.Created.IsZero() {
				i.Created = t
			}
		case "updated date", "changed", "last-modified", "last modified", "updated":
			if t := parseWhoisTime(v); !t.IsZero() && t.After(i.Updated) {
				i.Updated = t
			}
		case "netname", "net-name":
			if i.Name == "" {
				i.Name = v
			}
		case "as-name", "asname":
			if i.Name == "" {
				i.Name = v
			}
		case "inetnum", "inet6num", "netrange":
			if i.Range == "" {
				i.Range = strings.Join(strings.Fields(v), " ")
			}
		case "cidr", "route", "route6":
			for _, c := range strings.Split(v, ",") {
				if c = strings.TrimSpace(c); c != "" && !slicesContains(i.CIDR, c) {
					i.CIDR = append(i.CIDR, c)
				}
			}
		case "origin", "originas", "aut-num":
			if i.ASN == "" {
				i.ASN = strings.TrimPrefix(strings.ToUpper(v), "AS")
			}
		case "org-name", "orgname", "organization", "organisation", "registrant organization", "owner", "descr":
			if i.Org == "" || k != "descr" {
				if k == "descr" && i.Org != "" {
					continue
				}
				i.Org = v
			}
		case "country", "registrant country":
			if i.Country == "" {
				i.Country = strings.ToUpper(v)
			}
		case "city", "registrant city":
			if i.City == "" {
				i.City = v
			}
		case "address":
			if len(addr) < 4 {
				addr = append(addr, v)
			}
		case "abuse-mailbox", "orgabuseemail", "registrar abuse contact email":
			if i.Abuse == "" {
				i.Abuse = v
			}
		case "nic-hdl", "handle":
			if i.Handle == "" {
				i.Handle = v
			}
		}
	}
	if len(addr) > 0 {
		i.Address = strings.Join(addr, ", ")
	}
	// wer Daten liefert, ist registriert (z. B. "Status: connect" bei DENIC)
	if i.NotFound && (len(i.Nameservers) > 0 || !i.Expires.IsZero() || i.Registrar != "") {
		i.NotFound = false
	}
	if kind == "domain" && slicesContains(i.Status, "free") {
		i.NotFound = true
	}
	return i
}

func parseWhoisTime(s string) time.Time {
	s = strings.TrimSpace(s)
	for _, f := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05Z0700", "2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02", "02-Jan-2006", "2006.01.02", "02.01.2006", "20060102"} {
		if t, err := time.Parse(f, s); err == nil {
			return t
		}
	}
	if len(s) >= 10 {
		if t, err := time.Parse("2006-01-02", s[:10]); err == nil {
			return t
		}
	}
	return time.Time{}
}
