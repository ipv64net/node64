package edge

import (
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"
)

// chunkConn schreibt in kleinen Stuecken (ClientHello ueber viele TCP-Segmente).
type chunkConn struct {
	net.Conn
	n int
}

func (c chunkConn) Write(p []byte) (int, error) {
	done := 0
	for done < len(p) {
		k := min(c.n, len(p)-done)
		w, err := c.Conn.Write(p[done : done+k])
		done += w
		if err != nil {
			return done, err
		}
		time.Sleep(time.Millisecond)
	}
	return done, nil
}

// TestPeekHelloLarge: grosses ClientHello (ML-KEM-Schluessel, viele ALPN-Eintraege; Issue #31) in 100-Byte-Stuecken -
// Name, ALPN und alle Bytes kommen an.
func TestPeekHelloLarge(t *testing.T) {
	for _, tc := range []struct {
		name  string
		alpn  int
		chunk int
	}{{"mlkem", 2, 100}, {"mlkem+alpn", 400, 100}, {"mlkem, one segment", 2, 1 << 20}} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			protos := []string{"h2", "http/1.1"}
			for i := len(protos); i < tc.alpn; i++ {
				protos = append(protos, "proto-"+strings.Repeat("x", 20)+string(rune('a'+i%26)))
			}
			go func() {
				c := tls.Client(chunkConn{Conn: b, n: tc.chunk}, &tls.Config{ServerName: "big.example", NextProtos: protos,
					CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519}, InsecureSkipVerify: true})
				_ = c.Handshake()
			}()
			_ = a.SetDeadline(time.Now().Add(5 * time.Second))
			sni, alpn, data, ok := PeekHello(a)
			if !ok || sni != "big.example" || len(alpn) != len(protos) {
				t.Fatalf("ok=%v sni=%q alpn=%d", ok, sni, len(alpn))
			}
			if len(data) < 1500 {
				t.Fatalf("client hello only %d bytes, expected ML-KEM size", len(data))
			}
			t.Logf("client hello %d bytes", len(data))
		})
	}
}
