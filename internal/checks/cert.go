package checks

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

// CertParams gelten fuer den Typ cert.
type CertParams struct {
	Port         int    `json:"port,omitempty"`        // Standard 443
	MinDays      int    `json:"min_days,omitempty"`    // Restlaufzeit-Schwelle, Standard 14
	ServerName   string `json:"server_name,omitempty"` // SNI/Hostname-Abgleich, Standard = Ziel-Host
	SkipChain    bool   `json:"skip_chain,omitempty"`  // Kette nicht gegen System-CAs pruefen (private CA)
	SkipHostname bool   `json:"skip_hostname,omitempty"`
}

const DefaultCertMinDays = 14

type certChecker struct{}

func (certChecker) Type() Type { return TypeCert }

func (certChecker) Check(ctx context.Context, def Definition, ip net.IP) Result {
	var p CertParams
	if err := decode(def.Params, &p); err != nil {
		return fail(ReasonInvalid, err.Error(), 0, nil)
	}
	port := p.Port
	if port == 0 {
		if pp, err := portOf(def, 0); err == nil {
			port = pp
		} else {
			port = 443
		}
	}
	minDays := p.MinDays
	if minDays == 0 {
		minDays = DefaultCertMinDays
	}
	host := TargetHost(def)
	serverName := strings.TrimSpace(p.ServerName)
	if serverName == "" {
		serverName = host
	}
	details := map[string]any{"port": port, "server_name": serverName}
	start := time.Now()
	raw, err := dialIP(ctx, ip, port, def.Timeouts.Connect)
	if err != nil {
		lat := time.Since(start)
		if isTimeout(err) {
			return fail(ReasonTimeout, "connect timeout", lat, details)
		}
		return fail(ReasonConnectFailed, shortErr(err), lat, details)
	}
	defer raw.Close()
	cfg := &tls.Config{ServerName: serverName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} //nolint:gosec // Pruefung erfolgt unten ausfuehrlich
	if net.ParseIP(serverName) != nil {
		cfg.ServerName = ""
	}
	conn := tls.Client(raw, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		return fail(ReasonTLSFailed, shortErr(err), time.Since(start), details)
	}
	lat := time.Since(start)
	st := conn.ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return fail(ReasonTLSFailed, "no certificate presented", lat, details)
	}
	leaf := st.PeerCertificates[0]
	now := time.Now()
	daysLeft := int(leaf.NotAfter.Sub(now).Hours() / 24)
	details["subject"] = leaf.Subject.CommonName
	details["issuer"] = leaf.Issuer.CommonName
	details["not_before"] = leaf.NotBefore.UTC().Format(time.RFC3339)
	details["not_after"] = leaf.NotAfter.UTC().Format(time.RFC3339)
	details["days_left"] = daysLeft
	details["dns_names"] = leaf.DNSNames
	details["tls_version"] = tls.VersionName(st.Version)

	if now.After(leaf.NotAfter) {
		return fail(ReasonCertExpired, "certificate expired on "+leaf.NotAfter.UTC().Format("2006-01-02"), lat, details)
	}
	if now.Before(leaf.NotBefore) {
		return fail(ReasonCertInvalid, "certificate not valid before "+leaf.NotBefore.UTC().Format("2006-01-02"), lat, details)
	}
	if !p.SkipChain {
		opts := x509.VerifyOptions{Intermediates: x509.NewCertPool(), CurrentTime: now, Roots: trustRoots()} // nil = System-CAs, sonst plus eigene CAs (#190)
		for _, c := range st.PeerCertificates[1:] {
			opts.Intermediates.AddCert(c)
		}
		if _, err := leaf.Verify(opts); err != nil {
			return fail(ReasonCertInvalid, "chain: "+shortErr(err), lat, details)
		}
	}
	if !p.SkipHostname && net.ParseIP(serverName) == nil {
		if err := leaf.VerifyHostname(serverName); err != nil {
			return fail(ReasonCertHostname, "certificate is not valid for "+serverName, lat, details)
		}
	}
	if daysLeft < minDays {
		return fail(ReasonCertExpiring, fmt.Sprintf("certificate expires in %d days (threshold %d)", daysLeft, minDays), lat, details)
	}
	return ok(fmt.Sprintf("valid, %d days left", daysLeft), lat, details)
}
