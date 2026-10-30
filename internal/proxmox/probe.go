package proxmox

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"
)

// Probe prueft eine Verbindung im Assistenten: holt das Zertifikat (auch ein ungueltiges) und zeigt Fingerabdruck,
// Subject und ob die System-CA es bestaetigt; danach version, cluster/status und cluster/resources mit dem Token.
//
// Ohne Pin und mit nicht vertrauenswuerdigem Zertifikat wird das Token nicht gesendet: Probe liefert nur den
// Fingerabdruck (NeedConfirm); nach der Bestaetigung testet der Assistent erneut mit ihm als Pin. Ist ein Pin gesetzt
// und passt nicht, bricht Probe mit Fehler ab.
func Probe(ctx context.Context, sys System) ProbeResult {
	return probe(ctx, sys, nil, pveDialTimeout, pveRequestTimeout)
}

func probe(ctx context.Context, sys System, roots *x509.CertPool, dialTO, reqTO time.Duration) ProbeResult {
	var res ProbeResult
	pin, ok := NormalizePin(sys.PinSHA256)
	if !ok {
		res.Error = "fingerprint must be 64 hex digits (SHA-256)"
		return res
	}
	// Zertifikat von der ersten erreichbaren Adresse.
	var addrs []string
	for _, a := range sys.Addresses {
		if n, ok := NormalizeAddressFor(sys.Kind, a); ok {
			addrs = append(addrs, n)
		}
	}
	if len(addrs) == 0 {
		res.Error = "no valid address (use https://host:8006)"
		return res
	}
	var used string
	var certErr error
	for _, a := range addrs {
		cert, trusted, err := pveFetchCert(ctx, a, roots, dialTO)
		if err != nil {
			if certErr == nil {
				certErr = err
			}
			continue
		}
		used = a
		res.CertSHA256 = CertFingerprint(cert.Raw)
		res.CertSubject = cert.Subject.String()
		res.CertTrusted = trusted
		break
	}
	if used == "" {
		res.Error = certErr.Error()
		return res
	}
	switch {
	case pin != "" && pin != res.CertSHA256:
		res.Error = (&Error{Kind: ErrCertMismatch, Address: used, Detail: "got " + res.CertSHA256}).Error()
		return res
	case pin == "" && !res.CertTrusted:
		res.NeedConfirm = true // Secret nie an ein unbestaetigtes Zertifikat
		return res
	}

	// Mit dem Token nur die Adresse testen, deren Zertifikat eben gesehen wurde.
	test := sys
	test.Addresses = []string{used}
	test.PinSHA256 = pin
	c, err := newClient(test, roots, dialTO, reqTO)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	if sys.IsPBS() {
		pbsProbe(ctx, c, sys, &res)
		return res
	}
	var v pveVersion
	if err := c.Get(ctx, "/version", &v); err != nil {
		res.Error = err.Error()
		return res
	}
	res.OK = true
	res.Version = v.Version

	var warn []string
	var st []pveStatusEntry
	if err := c.Get(ctx, "/cluster/status", &st); err != nil {
		if errors.Is(err, ErrPermission) {
			warn = append(warn, "the token may not read cluster/status (Sys.Audit missing)")
		} else {
			warn = append(warn, "cluster/status failed: "+err.Error())
		}
	} else {
		cl, _, up, _ := pveParseStatus(st)
		res.Cluster = cl
		for n := range up {
			res.Nodes = append(res.Nodes, n)
		}
	}
	var raw []pveResource
	nodesSeen := 0
	if err := c.Get(ctx, "/cluster/resources", &raw); err != nil {
		if errors.Is(err, ErrPermission) {
			warn = append(warn, "the token may not read cluster/resources")
		} else {
			warn = append(warn, "cluster/resources failed: "+err.Error())
		}
	} else {
		for _, r := range raw {
			switch r.Type {
			case TypeQEMU, TypeLXC:
				if r.Template == 0 {
					res.Guests++
				}
			case TypeNode:
				nodesSeen++
				if !slices.Contains(res.Nodes, r.Node) {
					res.Nodes = append(res.Nodes, r.Node)
				}
			}
		}
		switch {
		case nodesSeen == 0:
			warn = append(warn, "the token sees no nodes and no guests")
		case res.Guests == 0:
			warn = append(warn, "the token sees no VMs or containers (fine if there are none)")
		}
	}
	sort.Strings(res.Nodes)
	if len(warn) > 0 {
		res.PermWarning = strings.Join(warn, "; ") + " – with „Privilege Separation“ the token needs its own rights: " +
			"grant role PVEAuditor on path / to the token (Datacenter → Permissions → Add → API Token Permission, " +
			"or: pveum acl modify / --tokens '" + sys.TokenID + "' --roles PVEAuditor)"
	}
	return res
}

// pveFetchCert holt das Leaf-Zertifikat ohne Pruefung und prueft danach selbst gegen die CA (roots nil = System).
func pveFetchCert(ctx context.Context, addr string, roots *x509.CertPool, dialTO time.Duration) (*x509.Certificate, bool, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return nil, false, err
	}
	host := u.Hostname()
	ctx, cancel := context.WithTimeout(ctx, dialTO)
	defer cancel()
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: dialTO},
		// Nur zum Lesen des Zertifikats (Fingerabdruck anzeigen); ueber diese Verbindung geht nichts.
		Config: &tls.Config{InsecureSkipVerify: true, ServerName: host, MinVersion: tls.VersionTLS12},
	}
	conn, err := d.DialContext(ctx, "tcp", u.Host)
	if err != nil {
		return nil, false, pveClassify(addr, err)
	}
	defer conn.Close()
	state := conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, false, &Error{Kind: ErrCertInvalid, Address: addr, Detail: "no certificate"}
	}
	leaf := state.PeerCertificates[0]
	inter := x509.NewCertPool()
	for _, c := range state.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	_, verr := leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: inter})
	return leaf, verr == nil, nil
}
