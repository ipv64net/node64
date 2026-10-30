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
	MigErr   string // Umzug in die Zertifikatsverwaltung steht noch aus: Grund
	Rows     []encRow
	Names    []string // im Zertifikat
	NotAfter time.Time
	Host     string // Name fuer die Geraete
	DoHURL   string
	DoQURL   string
	CA       bool // eigene CA (zum Herunterladen)
	Central  bool // zentrale Zertifikatsverwaltung vorhanden
	Certs    []centralOpt
	Current  *centralOpt // central: das gewaehlte Zertifikat
}

func (m *Module) encView(r *http.Request, c config) encView {
	v := encView{CA: c.CertMode == certSelf, Central: m.certs != nil}
	if v.Central {
		v.Certs = m.centralList(r.Context())
		for i := range v.Certs {
			if v.Certs[i].ID == c.CertID {
				v.Current = &v.Certs[i]
			}
		}
	}
	e := m.running()
	for _, p := range []struct {
		proto, label string
		on           bool
	}{{"doh", "DNS-over-HTTPS", c.DoH}, {"dot", "DNS-over-TLS", c.DoT}, {"doq", "DNS-over-QUIC", c.DoQ}} {
		row := encRow{Proto: p.proto, Label: p.label, On: p.on}
		if e != nil && e.enc != nil {
			row.Addr, row.Err = e.enc.addrs[p.proto], e.enc.errs[p.proto]
			if p.proto == "doh" && e.enc.release != nil { // ueber den Eingang: dessen Port-Fehler zeigen
				if _, er := m.edgeState(); er != "" {
					row.Err = er
				}
			}
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
		v.Host = strings.Trim(v.Host, "[]") // IPv6 ohne Port ("[fd00::5]"): hostPort/dohURL klammern selbst
	}
	m.mu.Lock()
	v.MigErr = m.migErr
	m.mu.Unlock()
	if c.CertMode == certCentral && v.Current != nil && v.Current.Name != "" {
		v.Host = v.Current.Name // ein Zertifikat der Verwaltung (z. B. Let's Encrypt) gilt nur fuer seine Namen
	} else if _, leaf := m.acmeCert(acmeName(c)); c.CertMode == certACME && leaf != nil {
		v.Host = acmeName(c)
	}
	v.DoHURL = dohURL(v.Host, c.DoHPort)
	v.DoQURL = "quic://" + hostPort(v.Host, c.DoTPort)
	return v
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
	if id, err := strconv.ParseInt(r.PostFormValue("cert_id"), 10, 64); err == nil {
		c.CertID = id
	}
	m.apply(w, r, "/dns64/encrypted", c, "dns64.encrypted", "doh="+b2s(c.DoH)+" dot="+b2s(c.DoT)+" doq="+b2s(c.DoQ)+" cert="+c.CertMode)
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
