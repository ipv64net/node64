package cdn64

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"testing"
)

// TLS nach BSI TR-02102-2: TLS 1.2 nur ECDHE mit AES-GCM, keine CBC-Suite, kein X25519 allein; TLS 1.3 und die
// hybriden ML-KEM-Verfahren gehen. Ohne die Wahl bleibt es bei den Standards von Go.
func TestTLSBSI(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	port, _ := echoBackend(t, "bsi")
	for _, n := range []string{"bsi.test", "std.test"} {
		certPEM, keyPEM := selfSigned(t, n)
		if _, err := e.crt.Upload(ctx, certPEM, keyPEM); err != nil {
			t.Fatal(err)
		}
		h := newHost()
		h.Names, h.TargetHost, h.TargetPort = []string{n}, "127.0.0.1", port
		if n == "bsi.test" {
			h.MinTLS = TLSBSI
		}
		if err := e.m.saveHost(ctx, h); err != nil {
			t.Fatal(err)
		}
		if got, _ := e.m.host(ctx, h.ID); got.MinTLS != h.MinTLS {
			t.Fatalf("min_tls not stored: %q", got.MinTLS)
		}
	}
	hs := func(name string, c *tls.Config) (*tls.ConnectionState, error) {
		c.ServerName, c.InsecureSkipVerify = name, true //nolint:gosec // Test
		conn, err := tls.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(e.cfg.HTTPSPort)), c)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		st := conn.ConnectionState()
		return &st, nil
	}
	tls12 := func(suite uint16, curve tls.CurveID) *tls.Config {
		return &tls.Config{MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{suite}, CurvePreferences: []tls.CurveID{curve}}
	}
	cbc := tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
	gcm := tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	chacha := tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
	for _, c := range []struct {
		name string
		cfg  *tls.Config
		ok   bool
	}{
		{"bsi.test", tls12(gcm, tls.CurveP256), true},
		{"bsi.test", tls12(gcm, tls.CurveP384), true},
		{"bsi.test", tls12(cbc, tls.CurveP256), false},
		{"bsi.test", tls12(chacha, tls.CurveP256), false},
		{"bsi.test", tls12(gcm, tls.X25519), false},
		{"bsi.test", &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}}, false},
		{"bsi.test", &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.SecP256r1MLKEM768}}, true},
		{"bsi.test", &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}, true},
		{"std.test", tls12(cbc, tls.X25519), true},
	} {
		if _, err := hs(c.name, c.cfg); (err == nil) != c.ok {
			t.Fatalf("%s %+v: ok=%v err=%v", c.name, c.cfg.CurvePreferences, err == nil, err)
		}
	}
	// TLS 1.3: die Suites legt Go fest; ohne AES-Hardware (z. B. Raspberry Pi 4, diese Testmaschine) kann es ChaCha20
	// werden - die einzige Abweichung von der Richtlinie, steht in der Doku.
}
