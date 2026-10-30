package honeypot

import (
	"bufio"
	"encoding/binary"
	"io"
	"strings"
	"time"
)

// ADB-Falle (H8 Phase 4, Port 5555): offenes Android Debug Bridge, wie es Botnetze (Mirai-Abkoemmlinge,
// Krypto-Miner) suchen. Auf CNXN antwortet die Falle mit einem CNXN eines Geraets (Nutzlast hoechstens so gross wie
// die der Anfrage), dann wird jedes OPEN erfasst: "shell:…"/"exec:…" als iot:exploit mit dem Befehl (Adressen darin
// werden nur notiert, nie aufgerufen), alles andere als generic:probe – und mit CLSE geschlossen. Ausgefuehrt,
// geschrieben oder herunter geladen wird nichts.

func init() {
	RegisterTCP(&TCPProto{Service: SvcADB, Budget: 16 << 10, Handle: (*Sensor).handleADB})
}

const (
	sensorADBWait = 20 * time.Second // ganze Verbindung
	sensorADBMsgs = 6                // Nachrichten je Verbindung
	sensorADBData = 4096             // Nutzlast je Nachricht

	adbCNXN = 0x4e584e43
	adbOPEN = 0x4e45504f
	adbCLSE = 0x45534c43
)

// sensorADBMsg ist eine ADB-Nachricht (Kopf 24 Bytes, little endian, dann die Nutzlast).
type sensorADBMsg struct {
	cmd, arg0, arg1 uint32
	data            []byte
}

func sensorADBRead(br *bufio.Reader) (sensorADBMsg, []byte, bool) {
	h := make([]byte, 24)
	if n, err := io.ReadFull(br, h); err != nil {
		return sensorADBMsg{}, h[:n], false
	}
	m := sensorADBMsg{cmd: binary.LittleEndian.Uint32(h), arg0: binary.LittleEndian.Uint32(h[4:]), arg1: binary.LittleEndian.Uint32(h[8:])}
	ln := binary.LittleEndian.Uint32(h[12:])
	if binary.LittleEndian.Uint32(h[20:]) != m.cmd^0xffffffff || ln > sensorADBData {
		return m, h, false
	}
	m.data = make([]byte, ln)
	if _, err := io.ReadFull(br, m.data); err != nil {
		return m, h, false
	}
	return m, h, true
}

func sensorADBBytes(cmd, arg0, arg1 uint32, data []byte) []byte {
	b := make([]byte, 24, 24+len(data))
	var sum uint32
	for _, x := range data {
		sum += uint32(x)
	}
	binary.LittleEndian.PutUint32(b, cmd)
	binary.LittleEndian.PutUint32(b[4:], arg0)
	binary.LittleEndian.PutUint32(b[8:], arg1)
	binary.LittleEndian.PutUint32(b[12:], uint32(len(data)))
	binary.LittleEndian.PutUint32(b[16:], sum)
	binary.LittleEndian.PutUint32(b[20:], cmd^0xffffffff)
	return append(b, data...)
}

func (s *Sensor) handleADB(c *trapConn) {
	_ = c.SetDeadline(time.Now().Add(sensorADBWait))
	br := bufio.NewReaderSize(c, 1024)
	m, head, ok := sensorADBRead(br)
	if !ok || m.cmd != adbCNXN {
		e := c.event(KindProbe)
		e.Detail, e.Payload = "adb: no connect", head[:min(len(head), MaxPayload)]
		s.emit(e)
		return
	}
	// Geraet wie ein offenes Android-TV bzw. eine Set-Top-Box (Profil je Sensor), nie groesser als die Anfrage
	p := s.personas()
	model := p.id.choose("adb-model", "p230", "q9s", "x96max", "tx3", "h96max")
	dev := []byte("device::ro.product.name=" + model + ";ro.product.model=" + model + ";ro.product.device=" + model + ";features=shell_v2,cmd")
	if len(dev) > len(m.data) {
		dev = []byte("device::")[:min(8, len(m.data))]
	}
	if _, err := c.Write(sensorADBBytes(adbCNXN, 0x01000000, sensorADBData, dev)); err != nil {
		return
	}
	hello := m.data // Kennung des Clients (host::features=…)
	got := false
	for n := 0; n < sensorADBMsgs; n++ {
		m, _, ok = sensorADBRead(br)
		if !ok {
			break
		}
		if m.cmd != adbOPEN {
			continue // OKAY, WRTE ohne offenen Strom, AUTH-Antworten: ignorieren
		}
		svc := strings.TrimRight(string(m.data), "\x00")
		kind, detail := KindProbe, "adb open"
		if v, cut := strings.CutPrefix(svc, "shell:"); cut || strings.HasPrefix(svc, "exec:") || strings.HasPrefix(svc, "sync:") {
			if !cut {
				v = svc
			}
			kind, detail = KindIoTExploit, "adb "+strings.SplitN(svc, ":", 2)[0]
			svc = v
		}
		e := c.event(kind)
		e.Detail = detail
		e.Payload = []byte(svc)[:min(len(svc), MaxPayload)]
		s.emit(e)
		got = true
		// CLSE (24 Bytes, kleiner als das OPEN): der Strom ist zu, es kommt nichts zurueck
		if _, err := c.Write(sensorADBBytes(adbCLSE, 0, m.arg0, nil)); err != nil {
			return
		}
	}
	if !got {
		e := c.event(KindProbe)
		e.Detail = "adb connect"
		e.Payload = hello[:min(len(hello), MaxPayload)]
		s.emit(e)
	}
}
