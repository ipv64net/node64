package dns64

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Reiter "Verschluesselung": Einstellungen fuer DoH/DoT/DoQ, Zustand, Verbindungsdaten fuer Geraete,
// CA-Zertifikat und iOS-/macOS-Profil zum Herunterladen.

type encRow struct {
	Proto, Label string
	On           bool
	Addr, Err    string
}

type encView struct {
	ACME     acmeView
	Domains  []string // Domains des ipv64-Accounts (fuer Let's Encrypt)
	KeyOK    bool     // zentraler API-Key eingetragen
	TOS      bool     // Nutzungsbedingungen von Let's Encrypt akzeptiert
	LANIP    string   // Vorschlag fuer den eigenen Eintrag im Heimnetz
	Rows     []encRow
	Names    []string // im Zertifikat
	NotAfter time.Time
	Host     string // Name fuer die Geraete
	DoHURL   string
	DoQURL   string
	CA       bool // eigene CA (zum Herunterladen)
}

func (m *Module) encView(r *http.Request, c config) encView {
	v := encView{CA: c.CertMode == certSelf}
	e := m.running()
	for _, p := range []struct {
		proto, label string
		on           bool
	}{{"doh", "DNS-over-HTTPS", c.DoH}, {"dot", "DNS-over-TLS", c.DoT}, {"doq", "DNS-over-QUIC", c.DoQ}} {
		row := encRow{Proto: p.proto, Label: p.label, On: p.on}
		if e != nil && e.enc != nil {
			row.Addr, row.Err = e.enc.addrs[p.proto], e.enc.errs[p.proto]
		}
		v.Rows = append(v.Rows, row)
	}
	if e != nil && e.enc != nil {
		v.NotAfter = e.enc.notAfter
		for _, n := range e.enc.names { // Auswahl fuer Geraete ohne localhost/Loopback
			if ip := net.ParseIP(n); n == "localhost" || (ip != nil && ip.IsLoopback()) {
				continue
			}
			v.Names = append(v.Names, n)
		}
	}
	// Name fuer die Geraete: Auswahl (?host=), sonst der erste eingestellte Name, sonst die Adresse im Browser
	v.Host = r.URL.Query().Get("host")
	if v.Host == "" || (len(v.Names) > 0 && !slices.Contains(v.Names, v.Host)) {
		v.Host = firstOr(c.Names, "")
	}
	if v.Host == "" {
		v.Host = r.Host
		if h, _, err := net.SplitHostPort(r.Host); err == nil {
			v.Host = h
		}
	}
	v.ACME = m.acmeView(c)
	v.TOS = m.core.SettingOr(r.Context(), setACMETOS, "") != ""
	v.KeyOK, v.Domains = m.accountDomains(r)
	v.LANIP = lanIP(r)
	if v.ACME.Name != "" && c.CertMode == certACME && v.ACME.Issuer != "" {
		v.Host = v.ACME.Name // mit Let's Encrypt gilt das Zertifikat nur fuer diesen Namen
	}
	v.DoHURL = dohURL(v.Host, c.DoHPort)
	v.DoQURL = "quic://" + hostPort(v.Host, c.DoTPort)
	return v
}

// accountDomains liefert die Domains des ipv64-Accounts (5 Minuten zwischengespeichert).
func (m *Module) accountDomains(r *http.Request) (bool, []string) {
	if m.key == nil || m.key.Get(r.Context()) == "" {
		return false, nil
	}
	m.domMu.Lock()
	defer m.domMu.Unlock()
	if time.Since(m.domAt) < 5*time.Minute {
		return true, m.domList
	}
	list, err := m.key.Client().Domains(r.Context(), m.key.Get(r.Context()))
	if err != nil {
		m.log.Warn("ipv64 domains", "err", err)
		return true, m.domList
	}
	m.domList = nil
	for _, d := range list {
		m.domList = append(m.domList, d.Name)
	}
	m.domAt = time.Now()
	return true, m.domList
}

// lanIP schlaegt die IP der Node im Heimnetz vor: die Adresse im Browser, sonst die erste private IPv4.
func lanIP(r *http.Request) string {
	h := r.Host
	if x, _, err := net.SplitHostPort(r.Host); err == nil {
		h = x
	}
	if ip := net.ParseIP(h); ip != nil && ip.To4() != nil && !ip.IsLoopback() {
		return ip.String()
	}
	_, ips := wantedNames(nil)
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil && !v4.IsLoopback() && !(v4[0] == 172 && v4[1] >= 17 && v4[1] <= 31) {
			return v4.String()
		}
	}
	return ""
}

// pageACME speichert die Angaben fuer Let's Encrypt, legt den eigenen Eintrag im Heimnetz an und holt das
// Zertifikat im Hintergrund.
func (m *Module) pageACME(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	back := func(kind, msg string) {
		m.g.Flash(w, r, kind, msg)
		http.Redirect(w, r, "/dns64/encrypted#acme", http.StatusSeeOther)
	}
	if r.PostFormValue("tos") == "" {
		back("danger", m.g.T(r, "dns64.err.acme_tos"))
		return
	}
	c := m.loadConfig(ctx)
	c.CertMode, c.ACMEDomain, c.ACMEPrefix = certACME, r.PostFormValue("domain"), r.PostFormValue("prefix")
	c.ACMEEmail, c.ACMEStaging = r.PostFormValue("email"), r.PostFormValue("staging") != ""
	if err := m.saveConfig(ctx, c); err != nil {
		back("danger", m.errText(r, err))
		return
	}
	_ = m.core.SetSetting(ctx, setACMETOS, time.Now().UTC().Format(time.RFC3339))
	c = m.loadConfig(ctx)
	name := acmeName(c)
	if ip := strings.TrimSpace(r.PostFormValue("lan_ip")); ip != "" { // Name zeigt im Heimnetz auf die Node
		typ := "A"
		if a := net.ParseIP(ip); a != nil && a.To4() == nil {
			typ = "AAAA"
		}
		if _, err := m.AddRecord(ctx, Record{Name: name, Type: typ, Value: ip}); err != nil && !isDup(err) {
			back("danger", m.errText(r, err))
			return
		}
	}
	m.log.Info("acme configured", "name", name, "staging", c.ACMEStaging, "by", m.g.Actor(r))
	if err := m.restart(ctx); err != nil {
		back("danger", m.g.T(r, "dns64.err.restart", "err", err.Error()))
		return
	}
	m.startACME("issue")
	back("success", m.g.T(r, "dns64.acme.started", "name", name))
}

func (m *Module) pageACMERenew(w http.ResponseWriter, r *http.Request) {
	if m.startACME("manual") {
		m.g.Flash(w, r, "success", m.g.T(r, "dns64.acme.started", "name", acmeName(m.loadConfig(r.Context()))))
	}
	http.Redirect(w, r, "/dns64/encrypted#acme", http.StatusSeeOther)
}

func isDup(err error) bool {
	var ce *cfgError
	return errors.As(err, &ce) && ce.Key == "err_dup"
}

func hostPort(host string, port int) string {
	if strings.Contains(host, ":") { // IPv6
		host = "[" + host + "]"
	}
	return host + ":" + strconv.Itoa(port)
}

func dohURL(host string, port int) string {
	if port == 443 {
		if strings.Contains(host, ":") {
			return "https://[" + host + "]/dns-query"
		}
		return "https://" + host + "/dns-query"
	}
	return "https://" + hostPort(host, port) + "/dns-query"
}

func (m *Module) pageEncryptedSave(w http.ResponseWriter, r *http.Request) {
	c := m.loadConfig(r.Context())
	c.DoH, c.DoT, c.DoQ = r.PostFormValue("doh") != "", r.PostFormValue("dot") != "", r.PostFormValue("doq") != ""
	c.DoHPort, c.DoTPort = formInt(r, "doh_port"), formInt(r, "dot_port")
	c.Names = splitLines(r.PostFormValue("names"))
	c.CertMode = r.PostFormValue("cert_mode")
	m.apply(w, r, "/dns64/encrypted", c)
}

// caDER liefert die Heimnetz-CA (nil, wenn es keine gibt).
func (m *Module) caDER() []byte {
	raw, err := os.ReadFile(m.caFile())
	if err != nil {
		return nil
	}
	b, _ := pem.Decode(raw)
	if b == nil {
		return nil
	}
	if _, err := x509.ParseCertificate(b.Bytes); err != nil {
		return nil
	}
	return b.Bytes
}

// pageCA: die CA zum Installieren (DER, .crt wie Windows/Android es erwarten).
func (m *Module) pageCA(w http.ResponseWriter, r *http.Request) {
	der := m.caDER()
	if der == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="node64-dns64-ca.crt"`)
	_, _ = w.Write(der)
}

// pageProfile: Konfigurationsprofil fuer iOS/macOS (DNS-Einstellung DoH oder DoT, bei eigener CA mit Zertifikat).
func (m *Module) pageProfile(w http.ResponseWriter, r *http.Request) {
	c := m.loadConfig(r.Context())
	v := m.encView(r, c)
	proto := r.URL.Query().Get("proto")
	if proto != "dot" {
		proto = "doh"
	}
	var der []byte
	if c.CertMode == certSelf {
		der = m.caDER()
	}
	body := mobileconfig(proto, v.Host, v.DoHURL, der)
	name := "dns64-" + proto + ".mobileconfig"
	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	_, _ = w.Write([]byte(body))
}

// uuid erzeugt eine feste UUID aus den Teilen (gleiches Profil = gleiche UUID, ersetzt sich beim Neuinstallieren).
func uuid(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return fmt.Sprintf("%X-%X-%X-%X-%X", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
}

func mobileconfig(proto, host, dohURL string, caDER []byte) string {
	x := html.EscapeString
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
`)
	if caDER != nil {
		id := uuid("ca", string(caDER))
		fmt.Fprintf(&b, `		<dict>
			<key>PayloadCertificateFileName</key><string>node64-dns64-ca.cer</string>
			<key>PayloadContent</key><data>%s</data>
			<key>PayloadDisplayName</key><string>Node64 DNS64 CA</string>
			<key>PayloadIdentifier</key><string>net.ipv64.node64.dns64.ca.%s</string>
			<key>PayloadType</key><string>com.apple.security.root</string>
			<key>PayloadUUID</key><string>%s</string>
			<key>PayloadVersion</key><integer>1</integer>
		</dict>
`, base64.StdEncoding.EncodeToString(caDER), id, id)
	}
	id := uuid("dns", proto, host)
	settings := `<key>DNSProtocol</key><string>HTTPS</string><key>ServerURL</key><string>` + x(dohURL) + `</string>`
	if proto == "dot" {
		settings = `<key>DNSProtocol</key><string>TLS</string><key>ServerName</key><string>` + x(host) + `</string>`
	}
	if ip := net.ParseIP(host); ip != nil {
		settings += `<key>ServerAddresses</key><array><string>` + x(ip.String()) + `</string></array>`
	}
	fmt.Fprintf(&b, `		<dict>
			<key>DNSSettings</key><dict>%s</dict>
			<key>PayloadDisplayName</key><string>DNS64 (%s)</string>
			<key>PayloadIdentifier</key><string>net.ipv64.node64.dns64.dns.%s</string>
			<key>PayloadType</key><string>com.apple.dnsSettings.managed</string>
			<key>PayloadUUID</key><string>%s</string>
			<key>PayloadVersion</key><integer>1</integer>
		</dict>
`, settings, strings.ToUpper(map[string]string{"doh": "DoH", "dot": "DoT"}[proto]), id, id)
	top := uuid("profile", proto, host)
	fmt.Fprintf(&b, `	</array>
	<key>PayloadDescription</key><string>Verschluesseltes DNS ueber Node64 DNS64 (%s)</string>
	<key>PayloadDisplayName</key><string>Node64 DNS64 (%s)</string>
	<key>PayloadIdentifier</key><string>net.ipv64.node64.dns64.%s</string>
	<key>PayloadRemovalDisallowed</key><false/>
	<key>PayloadType</key><string>Configuration</string>
	<key>PayloadUUID</key><string>%s</string>
	<key>PayloadVersion</key><integer>1</integer>
</dict>
</plist>
`, x(host), x(host), top, top)
	return b.String()
}
