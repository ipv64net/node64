package honeypot

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func icsDial(t *testing.T, port int) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", sensorAddrOf(port), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	return c
}

// Modbus: lesen = ics:scan, schreiben = ics:exploit, Antwort jeweils die 9-Byte-Exception (nie groesser als die
// Anfrage).
func TestSensorModbus(t *testing.T) {
	p := sensorFreePort(t)
	_, rec := sensorStart(t, Config{Services: []Service{{SvcModbus, p, ""}}})
	c := icsDial(t, p)
	read := []byte{0, 1, 0, 0, 0, 6, 1, 3, 0, 0, 0, 10}  // Read Holding Registers
	write := []byte{0, 2, 0, 0, 0, 6, 1, 6, 0, 1, 0, 42} // Write Single Register
	for i, req := range [][]byte{read, write} {
		if _, err := c.Write(req); err != nil {
			t.Fatal(err)
		}
		out := make([]byte, 9)
		if _, err := io.ReadFull(c, out); err != nil {
			t.Fatal(err)
		}
		if len(out) > len(req) || out[0] != req[0] || out[1] != req[1] || out[7] != req[7]|0x80 || out[8] != 1 {
			t.Fatalf("reply %d: % x", i, out)
		}
	}
	rec.wait(t, func(e Event) bool { return e.Kind == KindICSScan && strings.HasPrefix(e.Detail, "modbus fc=3") })
	rec.wait(t, func(e Event) bool { return e.Kind == KindICSExploit && strings.HasPrefix(e.Detail, "modbus fc=6") })
}

// S7: COTP-Verbindung bekommt eine Bestaetigung gleicher Groesse, der S7-Job wird eingeordnet, danach Ende.
func TestSensorS7(t *testing.T) {
	p := sensorFreePort(t)
	_, rec := sensorStart(t, Config{Services: []Service{{SvcS7, p, ""}}})
	c := icsDial(t, p)
	cr := []byte{3, 0, 0, 22, 17, 0xe0, 0, 0, 0, 1, 0, 0xc0, 1, 10, 0xc1, 2, 1, 0, 0xc2, 2, 1, 2}
	if _, err := c.Write(cr); err != nil {
		t.Fatal(err)
	}
	cc := make([]byte, len(cr))
	if _, err := io.ReadFull(c, cc); err != nil {
		t.Fatal(err)
	}
	if cc[5] != 0xd0 || cc[6] != 0 || cc[7] != 1 || !bytes.Equal(cc[10:], cr[10:]) {
		t.Fatalf("cc: % x", cc)
	}
	job := []byte{3, 0, 0, 25, 2, 0xf0, 0x80, 0x32, 1, 0, 0, 0, 0, 0, 8, 0, 0, 0xf0, 0, 0, 1, 0, 1, 1, 0xe0}
	binary.BigEndian.PutUint16(job[2:], uint16(len(job)))
	if _, err := c.Write(job); err != nil {
		t.Fatal(err)
	}
	rec.wait(t, func(e Event) bool { return e.Kind == KindICSScan && e.Detail == "s7 setup-communication" })
	if n, _ := c.Read(make([]byte, 64)); n != 0 {
		t.Fatalf("no reply expected after the job: %d", n)
	}
}

// BACnet: Who-Is wird erfasst, aber nie beantwortet.
func TestSensorBACnet(t *testing.T) {
	p := sensorFreeUDPPort(t)
	_, rec := sensorStart(t, Config{Services: []Service{{SvcBACnet, p, ""}}})
	c := sensorUDPDial(t, p)
	whoIs := []byte{0x81, 0x0b, 0, 8, 1, 0x20, 0xff, 0xff, 0, 0xff, 0x10, 8}
	if got := sensorUDPReply(t, c, whoIs, 300*time.Millisecond); got != nil {
		t.Fatalf("reply: % x", got)
	}
	rec.wait(t, func(e Event) bool { return e.Kind == KindICSScan && e.Detail == "bacnet who-is" })
}

// ADB: CNXN bekommt ein Geraet (nie groesser als die Anfrage), OPEN shell wird als iot:exploit erfasst und mit CLSE
// geschlossen.
func TestSensorADB(t *testing.T) {
	p := sensorFreePort(t)
	_, rec := sensorStart(t, Config{Services: []Service{{SvcADB, p, ""}}})
	c := icsDial(t, p)
	hello := sensorADBBytes(adbCNXN, 0x01000000, 4096, []byte("host::features=shell_v2,cmd,stat_v2,ls_v2,fixed_push_mkdir,apex,abb"))
	if _, err := c.Write(hello); err != nil {
		t.Fatal(err)
	}
	h := make([]byte, 24)
	if _, err := io.ReadFull(c, h); err != nil {
		t.Fatal(err)
	}
	n := binary.LittleEndian.Uint32(h[12:])
	body := make([]byte, n)
	if _, err := io.ReadFull(c, body); err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(h) != adbCNXN || 24+int(n) > len(hello) || !strings.HasPrefix(string(body), "device::") {
		t.Fatalf("cnxn: % x %q", h, body)
	}
	if _, err := c.Write(sensorADBBytes(adbOPEN, 1, 0, []byte("shell:id\x00"))); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, h); err != nil || binary.LittleEndian.Uint32(h) != adbCLSE {
		t.Fatalf("clse: % x %v", h, err)
	}
	rec.wait(t, func(e Event) bool {
		return e.Kind == KindIoTExploit && e.Detail == "adb shell" && string(e.Payload) == "id"
	})
}
