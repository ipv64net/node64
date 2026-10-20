package honeypot

import (
	"bytes"
	"io"
	"math/rand/v2"
	"net"
	"strings"
	"testing"
	"time"
)

func sensorMQTTStr(s string) []byte { return append([]byte{byte(len(s) >> 8), byte(len(s))}, s...) }

// sensorMQTTPacket baut ein Paket mit fester Kopfzeile (Typ/Flags) und Remaining Length.
func sensorMQTTPacket(first byte, body []byte) []byte {
	out := []byte{first}
	n := len(body)
	for {
		b := byte(n % 128)
		if n /= 128; n > 0 {
			b |= 0x80
		}
		out = append(out, b)
		if n == 0 {
			break
		}
	}
	return append(out, body...)
}

// sensorMQTTConn baut ein CONNECT; user/pass nil = Flag aus, will != "" setzt eine Will-Nachricht.
func sensorMQTTConn(name string, level byte, client, will string, user, pass *string) []byte {
	var flags byte = 0x02
	if will != "" {
		flags |= 0x04
	}
	if user != nil {
		flags |= 0x80
	}
	if pass != nil {
		flags |= 0x40
	}
	b := append(sensorMQTTStr(name), level, flags, 0, 60)
	if level == 5 {
		b = append(b, 3, 0x21, 0, 10) // Properties: Receive Maximum
	}
	b = append(b, sensorMQTTStr(client)...)
	if will != "" {
		if level == 5 {
			b = append(b, 0)
		}
		b = append(b, sensorMQTTStr(will)...)
		b = append(b, sensorMQTTStr("bye")...)
	}
	if user != nil {
		b = append(b, sensorMQTTStr(*user)...)
	}
	if pass != nil {
		b = append(b, sensorMQTTStr(*pass)...)
	}
	return sensorMQTTPacket(0x10, b)
}

// sensorMQTTSend schickt b und liefert alles bis zum Schliessen durch den Sensor.
func sensorMQTTSend(t *testing.T, port int, b []byte) []byte {
	t.Helper()
	c, err := net.Dial("tcp", sensorAddrOf(port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if len(b) > 0 {
		_, _ = c.Write(b)
	}
	_ = c.(*net.TCPConn).CloseWrite()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	out, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("nicht getrennt: %v", err)
	}
	return out
}

func TestSensorMQTT(t *testing.T) {
	sensorPlainNoDelay(t)
	p := sensorFreePort(t)
	s, rec := sensorStart(t, Config{Services: []Service{{SvcMQTT, p, ""}}})
	str := func(v string) *string { return &v }

	// 3.1.1 mit Username/Password -> CONNACK 4
	out := sensorMQTTSend(t, p, sensorMQTTConn("MQTT", 4, "mosq-"+strings.Repeat("c", 100), "", str("admin"), str("public")))
	if !bytes.Equal(out, []byte{0x20, 2, 0, 4}) {
		t.Fatalf("CONNACK 3.1.1: %x", out)
	}
	e := rec.wait(t, sensorKind(KindMQTTBrute))
	if e.Username != "admin" || e.Password != "public" || e.Service != SvcMQTT || e.Port != p || e.Client != "MQTT 3.1.1" ||
		e.Detail != "client=mosq-"+strings.Repeat("c", sensorPlainClient-5) {
		t.Fatalf("Ereignis 3.1.1: %+v", e)
	}

	// 5.0 mit Properties und Will -> CONNACK 0x86
	out = sensorMQTTSend(t, p, sensorMQTTConn("MQTT", 5, "c5", "dev/status", str("user5"), str("pw5")))
	if !bytes.Equal(out, []byte{0x20, 3, 0, 0x86, 0}) {
		t.Fatalf("CONNACK 5: %x", out)
	}
	e = rec.wait(t, func(e Event) bool { return e.Username == "user5" })
	if e.Password != "pw5" || e.Client != "MQTT 5.0" || e.Detail != "client=c5" {
		t.Fatalf("Ereignis 5: %+v", e)
	}

	// 3.1 (MQIsdp), nur Username
	out = sensorMQTTSend(t, p, sensorMQTTConn("MQIsdp", 3, "", "", str("guest"), nil))
	if !bytes.Equal(out, []byte{0x20, 2, 0, 4}) {
		t.Fatalf("CONNACK 3.1: %x", out)
	}
	e = rec.wait(t, func(e Event) bool { return e.Username == "guest" })
	if e.Password != "" || e.Client != "MQTT 3.1" || e.Detail != "" {
		t.Fatalf("Ereignis 3.1: %+v", e)
	}

	// ohne Anmeldedaten -> CONNACK 5, Probe; ein nachgeschobenes SUBSCRIBE wird nicht beantwortet
	sub := sensorMQTTPacket(0x82, append([]byte{0, 1}, append(sensorMQTTStr("#"), 0)...))
	out = sensorMQTTSend(t, p, append(sensorMQTTConn("MQTT", 4, "anon", "", nil, nil), sub...))
	if !bytes.Equal(out, []byte{0x20, 2, 0, 5}) {
		t.Fatalf("CONNACK anonym: %x", out)
	}
	e = rec.wait(t, sensorKind(KindProbe))
	if e.Username != "" || e.Detail != "client=anon" || e.Client != "MQTT 3.1.1" {
		t.Fatalf("Probe: %+v", e)
	}
	if n := rec.count(sensorKind(KindMQTTBrute)); n != 3 || s.counters.Logins.Load() != 3 {
		t.Fatalf("Logins: %d/%d", n, s.counters.Logins.Load())
	}
}

func TestSensorMQTTJunk(t *testing.T) {
	sensorPlainNoDelay(t)
	p := sensorFreePort(t)
	_, rec := sensorStart(t, Config{Services: []Service{{SvcMQTT, p, ""}}})

	cases := []struct {
		in     []byte
		detail string
	}{
		{[]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), "mqtt: no connect"},
		{sensorMQTTPacket(0x30, append(sensorMQTTStr("t"), 'x')), "mqtt: no connect"}, // PUBLISH ohne CONNECT
		{[]byte{0x10, 0xff, 0xff, 0xff, 0x7f}, "mqtt: no connect"},                    // zu gross
		{[]byte{0x10, 0xff, 0xff, 0xff, 0xff, 0x01}, "mqtt: no connect"},              // Laenge ungueltig
		{[]byte{0x10, 20, 0, 4, 'M', 'Q'}, "mqtt: short connect"},
		{sensorMQTTPacket(0x10, append(sensorMQTTStr("MQTT"), 9, 0x02, 0, 60, 0, 0)), "mqtt: bad connect"}, // Version
		{sensorMQTTPacket(0x10, append(sensorMQTTStr("MQTT"), 4, 0xc2, 0, 60, 0, 0)), "mqtt: bad connect"}, // Flags ohne Felder
		{sensorMQTTPacket(0x10, append(sensorMQTTStr("MQTT"), 5, 0x02, 0, 60, 0xff)), "mqtt: bad connect"}, // Properties
	}
	for _, tc := range cases {
		if out := sensorMQTTSend(t, p, tc.in); len(out) != 0 {
			t.Fatalf("Antwort auf %x: %x", tc.in, out)
		}
		in := tc.in
		e := rec.wait(t, func(e Event) bool {
			return e.Detail == tc.detail && bytes.Equal(e.Payload, in[:min(len(in), MaxPayload)])
		})
		if e.Kind != KindProbe || e.Username != "" {
			t.Fatalf("%x: %+v", tc.in, e)
		}
	}
	// nur Verbindung
	sensorMQTTSend(t, p, nil)
	rec.wait(t, func(e Event) bool { return e.Kind == KindProbe && e.Detail == "" && len(e.Payload) == 0 })

	// Zufallsdaten durch den Parser: keine Panik
	r := rand.New(rand.NewPCG(1, 2))
	good := sensorMQTTConn("MQTT", 5, "c", "w", nil, nil)[2:]
	for i := 0; i < 20000; i++ {
		b := make([]byte, r.IntN(64))
		for j := range b {
			b[j] = byte(r.UintN(256))
		}
		sensorMQTTParse(b)
		g := append([]byte(nil), good...)
		g[r.IntN(len(g))] = byte(r.UintN(256))
		sensorMQTTParse(g[:r.IntN(len(g)+1)])
	}
}
