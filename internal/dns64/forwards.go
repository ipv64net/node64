package dns64

import (
	"context"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/ipv64net/node64/internal/dns64/dnsserver"
	"github.com/ipv64net/node64/internal/dns64/upstream"
)

// Weiterleitungen (Tabelle dns64_forwards): Namen einer Domain gehen an eigene DNS-Server, z. B. firma.local an
// den VPN-DNS oder 10.in-addr.arpa an den Router. Umschreiben (dns64_rewrites): ein Name antwortet wie ein anderer.
// Beides gilt sofort ohne Neustart (Momentaufnahme wie bei den eigenen Eintraegen).

// Forward ist eine Weiterleitung.
type Forward struct {
	ID        int64     `json:"id"`
	Domain    string    `json:"domain"`  // gilt mit allen Unternamen
	Servers   []string  `json:"servers"` // 192.168.1.1, 10.0.0.53:5353, tls://dns.firma.de, https://…/dns-query, quic://…
	Comment   string    `json:"comment,omitempty"`
	LocalOnly bool      `json:"local_only,omitempty"` // nur diese Node (nie im Cluster abgeglichen)
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

// Rewrite: Name (auch *.domain) antwortet wie Target.
type Rewrite struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Target    string    `json:"target"`
	Comment   string    `json:"comment,omitempty"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

type fwdEntry struct {
	f  Forward
	up *upstream.Resolver
	ds *dnsserver.Forward
}

type fwdTable struct {
	byDomain map[string]*fwdEntry
	byID     map[int64]*fwdEntry
}

type rwTable struct {
	exact, wild map[string]string // wild: Schluessel ohne "*."
}

// forwardFor: Weiterleitung fuer name, die laengste passende Domain gewinnt (dnsserver.ForwardFunc).
func (m *Module) forwardFor(name string) *dnsserver.Forward {
	t := m.fwd.Load()
	if t == nil || len(t.byDomain) == 0 {
		return nil
	}
	for s := name; ; {
		if e := t.byDomain[s]; e != nil {
			return e.ds
		}
		i := strings.IndexByte(s, '.')
		if i < 0 {
			return nil
		}
		s = s[i+1:]
	}
}

// rewriteFor: Ziel, wenn name umgeschrieben wird (dnsserver.RewriteFunc); genauer Name vor *.domain.
func (m *Module) rewriteFor(name string) (string, bool) {
	t := m.rw.Load()
	if t == nil {
		return "", false
	}
	if target, ok := t.exact[name]; ok {
		return target, true
	}
	for s := name; ; {
		i := strings.IndexByte(s, '.')
		if i < 0 {
			return "", false
		}
		s = s[i+1:]
		if target, ok := t.wild[s]; ok {
			return target, true
		}
	}
}

// loadForwards baut Weiterleitungen und Umschreiben neu (beim Start und nach jeder Aenderung).
func (m *Module) loadForwards(ctx context.Context) error {
	fl, err := m.Forwards(ctx)
	if err != nil && !m.noTable(err) {
		return err
	}
	rl, err := m.Rewrites(ctx)
	if err != nil && !m.noTable(err) {
		return err
	}
	t := &fwdTable{byDomain: map[string]*fwdEntry{}, byID: map[int64]*fwdEntry{}}
	for _, f := range fl {
		if !f.Enabled {
			continue
		}
		e := &fwdEntry{f: f, up: newForwardResolver(f)}
		e.ds = &dnsserver.Forward{Domain: f.Domain, Exchange: e.up.Exchange}
		t.byDomain[f.Domain], t.byID[f.ID] = e, e
	}
	rt := &rwTable{exact: map[string]string{}, wild: map[string]string{}}
	for _, r := range rl {
		if !r.Enabled {
			continue
		}
		if rest, ok := strings.CutPrefix(r.Name, "*."); ok {
			rt.wild[rest] = r.Target
		} else {
			rt.exact[r.Name] = r.Target
		}
	}
	m.rw.Store(rt)
	m.clChanged(ctx, ItemForwards)
	if old := m.fwd.Swap(t); old != nil { // laufende Anfragen duerfen die alten Verbindungen noch zu Ende nutzen
		time.AfterFunc(30*time.Second, func() {
			for _, e := range old.byID {
				e.up.Close()
			}
		})
	}
	return nil
}

func newForwardResolver(f Forward) *upstream.Resolver {
	servers := make([]upstream.Server, 0, len(f.Servers))
	for _, s := range f.Servers {
		servers = append(servers, upstream.Server{Name: serverLabel(s), URL: s})
	}
	return upstream.New(servers, upstream.ModeOrdered) // der Reihe nach, Ausfall -> naechster
}

// normalizeServer: IP, IP:Port oder URL (dns://, tls://, https://, quic://) -> gespeicherte URL.
func normalizeServer(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "://") {
		if ap, err := netip.ParseAddrPort(s); err == nil {
			return plainURL(netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())), nil
		}
		if a, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil && !strings.ContainsAny(a.Zone(), "[]:") {
			return plainURL(netip.AddrPortFrom(a.Unmap(), 53)), nil
		}
		return "", errCfg("err_fwd_server")
	}
	u, err := url.Parse(s)
	if err != nil || u.Hostname() == "" || upstream.Proto(s) == "" || u.User != nil {
		return "", errCfg("err_fwd_server")
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return "", errCfg("err_fwd_server")
		}
	}
	u.Scheme, u.Host = strings.ToLower(u.Scheme), strings.ToLower(u.Host)
	if u.Scheme == "https" && (u.Path == "" || u.Path == "/") {
		u.Path = "/dns-query"
	}
	if u.Scheme != "https" {
		u.Path, u.RawQuery = "", ""
	}
	if u.Scheme == "dns" && u.Port() == "" {
		u.Host = netJoin(u.Hostname(), "53")
	}
	return u.String(), nil
}

func netJoin(host, port string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}

// serverLabel: Anzeige eines Servers (dns://192.168.1.1:53 -> 192.168.1.1).
func serverLabel(s string) string {
	if rest, ok := strings.CutPrefix(s, "dns://"); ok {
		if r, err := url.PathUnescape(rest); err == nil {
			rest = r // Zone (%25)
		}
		if ap, err := netip.ParseAddrPort(rest); err == nil && ap.Port() == 53 {
			return ap.Addr().String()
		}
		return rest
	}
	return s
}

// reverseZone: Netz (192.168.0.0/16, fd00::/8) -> Reverse-Zone; nur ganze Oktette bzw. Nibbles.
func reverseZone(s string) (string, bool) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return "", false
	}
	p = p.Masked()
	if p.Addr().Is4() {
		if p.Bits()%8 != 0 || p.Bits() == 0 {
			return "", false
		}
		b := p.Addr().As4()
		var labels []string
		for i := p.Bits()/8 - 1; i >= 0; i-- {
			labels = append(labels, strconv.Itoa(int(b[i])))
		}
		return strings.Join(labels, ".") + ".in-addr.arpa", true
	}
	if p.Bits()%4 != 0 || p.Bits() == 0 {
		return "", false
	}
	arpa, _ := dns.ReverseAddr(p.Addr().String()) // alle 32 Nibbles, davon die ersten Bits/4
	labels := strings.Split(strings.TrimSuffix(arpa, ".ip6.arpa."), ".")
	return strings.Join(labels[32-p.Bits()/4:], ".") + ".ip6.arpa", true
}

func normalizeForward(f *Forward) error {
	d := strings.TrimSpace(f.Domain)
	if z, ok := reverseZone(d); ok {
		d = z
	}
	f.Domain = strings.TrimSuffix(strings.TrimPrefix(hostName(d), "*."), ".")
	if !validName(f.Domain) {
		return errCfg("err_fwd_domain")
	}
	var out []string
	for _, s := range f.Servers {
		for _, x := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' || r == ' ' || r == '\t' || r == '\r' }) {
			n, err := normalizeServer(x)
			if err != nil {
				return err
			}
			if !has(out, n) {
				out = append(out, n)
			}
		}
	}
	if len(out) == 0 || len(out) > 8 {
		return errCfg("err_fwd_server")
	}
	f.Servers = out
	f.Comment = strings.TrimSpace(f.Comment)
	if len(f.Comment) > 200 {
		return errCfg("err_comment")
	}
	return nil
}

func has(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func normalizeRewrite(r *Rewrite) error {
	r.Name, r.Target = hostName(r.Name), hostName(strings.TrimPrefix(strings.TrimSpace(r.Target), "*."))
	if !validName(strings.TrimPrefix(r.Name, "*.")) {
		return errCfg("err_name")
	}
	if !validName(r.Target) || r.Target == r.Name {
		return errCfg("err_target")
	}
	r.Comment = strings.TrimSpace(r.Comment)
	if len(r.Comment) > 200 {
		return errCfg("err_comment")
	}
	return nil
}

// ---- Speicher ----

// Forwards liefert alle Weiterleitungen, nach Domain sortiert.
func (m *Module) Forwards(ctx context.Context) ([]Forward, error) {
	rows, err := m.core.Reader().QueryContext(ctx, `SELECT id, domain, servers, comment, local_only, enabled, created_at FROM dns64_forwards ORDER BY domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Forward{}
	for rows.Next() {
		var f Forward
		var servers, created string
		if err := rows.Scan(&f.ID, &f.Domain, &servers, &f.Comment, &f.LocalOnly, &f.Enabled, &created); err != nil {
			return nil, err
		}
		f.Servers = strings.Fields(servers)
		f.CreatedAt, _ = time.Parse(time.RFC3339, created)
		out = append(out, f)
	}
	return out, rows.Err()
}

// AddForward legt eine Weiterleitung an (Domain eindeutig).
func (m *Module) AddForward(ctx context.Context, f Forward) (Forward, error) {
	if err := normalizeForward(&f); err != nil {
		return f, err
	}
	f.Enabled, f.CreatedAt = true, time.Now().UTC()
	res, err := m.core.Writer().ExecContext(ctx, `INSERT INTO dns64_forwards (domain, servers, comment, local_only, enabled, created_at) VALUES (?,?,?,?,1,?)`,
		f.Domain, strings.Join(f.Servers, "\n"), f.Comment, f.LocalOnly, f.CreatedAt.Format(time.RFC3339))
	if isUnique(err) {
		return f, errCfg("err_fwd_dup")
	}
	if err != nil {
		return f, err
	}
	f.ID, _ = res.LastInsertId()
	return f, m.loadForwards(ctx)
}

// UpdateForward aendert Domain, Server und Kommentar; an/aus bleibt.
func (m *Module) UpdateForward(ctx context.Context, id int64, f Forward) (Forward, error) {
	if err := normalizeForward(&f); err != nil {
		return f, err
	}
	err := m.fwdExec(ctx, `UPDATE dns64_forwards SET domain = ?, servers = ?, comment = ?, local_only = ? WHERE id = ?`, f.Domain, strings.Join(f.Servers, "\n"), f.Comment, f.LocalOnly, id)
	if isUnique(err) {
		return f, errCfg("err_fwd_dup")
	}
	f.ID = id
	return f, err
}

// DeleteForward loescht eine Weiterleitung.
func (m *Module) DeleteForward(ctx context.Context, id int64) error {
	return m.fwdExec(ctx, `DELETE FROM dns64_forwards WHERE id = ?`, id)
}

// SetForwardEnabled schaltet eine Weiterleitung an oder aus.
func (m *Module) SetForwardEnabled(ctx context.Context, id int64, on bool) error {
	return m.fwdExec(ctx, `UPDATE dns64_forwards SET enabled = ? WHERE id = ?`, on, id)
}

// Rewrites liefert alle Umschreibungen, nach Name sortiert.
func (m *Module) Rewrites(ctx context.Context) ([]Rewrite, error) {
	rows, err := m.core.Reader().QueryContext(ctx, `SELECT id, name, target, comment, enabled, created_at FROM dns64_rewrites ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Rewrite{}
	for rows.Next() {
		var r Rewrite
		var created string
		if err := rows.Scan(&r.ID, &r.Name, &r.Target, &r.Comment, &r.Enabled, &created); err != nil {
			return nil, err
		}
		r.CreatedAt, _ = time.Parse(time.RFC3339, created)
		out = append(out, r)
	}
	return out, rows.Err()
}

// AddRewrite legt eine Umschreibung an (Name eindeutig).
func (m *Module) AddRewrite(ctx context.Context, r Rewrite) (Rewrite, error) {
	if err := normalizeRewrite(&r); err != nil {
		return r, err
	}
	r.Enabled, r.CreatedAt = true, time.Now().UTC()
	res, err := m.core.Writer().ExecContext(ctx, `INSERT INTO dns64_rewrites (name, target, comment, enabled, created_at) VALUES (?,?,?,1,?)`,
		r.Name, r.Target, r.Comment, r.CreatedAt.Format(time.RFC3339))
	if isUnique(err) {
		return r, errCfg("err_rw_dup")
	}
	if err != nil {
		return r, err
	}
	r.ID, _ = res.LastInsertId()
	return r, m.loadForwards(ctx)
}

// UpdateRewrite aendert Name, Ziel und Kommentar; an/aus bleibt.
func (m *Module) UpdateRewrite(ctx context.Context, id int64, r Rewrite) (Rewrite, error) {
	if err := normalizeRewrite(&r); err != nil {
		return r, err
	}
	err := m.fwdExec(ctx, `UPDATE dns64_rewrites SET name = ?, target = ?, comment = ? WHERE id = ?`, r.Name, r.Target, r.Comment, id)
	if isUnique(err) {
		return r, errCfg("err_rw_dup")
	}
	r.ID = id
	return r, err
}

// DeleteRewrite loescht eine Umschreibung.
func (m *Module) DeleteRewrite(ctx context.Context, id int64) error {
	return m.fwdExec(ctx, `DELETE FROM dns64_rewrites WHERE id = ?`, id)
}

// SetRewriteEnabled schaltet eine Umschreibung an oder aus.
func (m *Module) SetRewriteEnabled(ctx context.Context, id int64, on bool) error {
	return m.fwdExec(ctx, `UPDATE dns64_rewrites SET enabled = ? WHERE id = ?`, on, id)
}

func (m *Module) fwdExec(ctx context.Context, q string, args ...any) error {
	res, err := m.core.Writer().ExecContext(ctx, q, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return m.loadForwards(ctx)
}

func isUnique(err error) bool { return err != nil && strings.Contains(err.Error(), "UNIQUE") }

// ---- Zustand und Test ----

// fwdServerView: ein Server einer Weiterleitung mit seiner Statistik (laufender Dienst).
type fwdServerView struct {
	Label     string    `json:"label"`
	URL       string    `json:"url"`
	Requests  uint64    `json:"requests"`
	Errors    uint64    `json:"errors"`
	AvgMs     float64   `json:"avg_ms"`
	Healthy   bool      `json:"healthy"`
	LastErr   string    `json:"last_error,omitempty"`
	LastErrAt time.Time `json:"last_error_at,omitzero"`
}

// forwardView: Weiterleitung fuer Seite und API.
type forwardView struct {
	Forward
	State []fwdServerView `json:"state,omitempty"`
}

func (m *Module) forwardViews(list []Forward) []forwardView {
	t := m.fwd.Load()
	out := make([]forwardView, 0, len(list))
	for _, f := range list {
		v := forwardView{Forward: f}
		if t != nil {
			if e := t.byID[f.ID]; e != nil {
				for _, s := range e.up.Stats() {
					v.State = append(v.State, fwdServerView{Label: s.Name, URL: s.URL, Requests: s.Requests, Errors: s.Errors, AvgMs: s.AvgMs, Healthy: s.Healthy, LastErr: s.LastError, LastErrAt: s.LastErrAt})
				}
			}
		}
		if v.State == nil {
			for _, s := range f.Servers {
				v.State = append(v.State, fwdServerView{Label: serverLabel(s), URL: s, Healthy: true})
			}
		}
		out = append(out, v)
	}
	return out
}

// fwdTest ist das Ergebnis einer Testabfrage (SOA der Domain).
type fwdTest struct {
	OK     bool    `json:"ok"`
	Rcode  string  `json:"rcode,omitempty"`
	Server string  `json:"server,omitempty"`
	Ms     float64 `json:"ms"`
	Error  string  `json:"error,omitempty"`
}

// TestForward fragt die Server der Weiterleitung nach dem SOA der Domain (auch wenn sie ausgeschaltet ist).
func (m *Module) TestForward(ctx context.Context, id int64) (fwdTest, error) {
	list, err := m.Forwards(ctx)
	if err != nil {
		return fwdTest{}, err
	}
	for _, f := range list {
		if f.ID != id {
			continue
		}
		up := newForwardResolver(f)
		defer up.Close()
		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn(f.Domain), dns.TypeSOA)
		q.RecursionDesired = true
		tctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		start := time.Now()
		resp, server, err := up.Exchange(tctx, q)
		t := fwdTest{Server: serverLabel(server), Ms: float64(time.Since(start).Microseconds()) / 1000}
		if err != nil {
			t.Error = err.Error()
			return t, nil
		}
		t.Rcode = dns.RcodeToString[resp.Rcode]
		t.OK = resp.Rcode == dns.RcodeSuccess || resp.Rcode == dns.RcodeNameError
		return t, nil
	}
	return fwdTest{}, errNotFound
}
