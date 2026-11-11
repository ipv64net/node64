package m64linux

import (
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/m64proto"
)

// Stromversorgung eines Raspberry Pi. Zwei Quellen (Stand: Kernel-Quellen raspberrypi/linux und Doku zu vcgencmd):
//
//   - "vcgencmd get_throttled" ("throttled=0x50005"): alle Flags, die oberen Bits gelten seit dem Start. Braucht das
//     Programm (Raspberry Pi OS) und Zugriff auf /dev/vcio (root bzw. Gruppe video).
//   - hwmon-Geraet rpi_volt, in0_lcrit_alarm: 1, solange der Kernel bei seiner Abfrage alle zwei Sekunden eine
//     Unterspannung sieht – also nur "jetzt", ohne Drosselung und ohne "seit dem Start".
//
// Die Datei /sys/devices/platform/soc/soc:firmware/get_throttled wird bewusst nicht gelesen: Der Pi-Kernel fuehrt sie
// als veraltet (erster Lesezugriff schreibt eine Warnung mit Stacktrace ins Kernel-Log), ab Kernel 6.12 fehlt sie.

// ParseThrottled liest die Ausgabe von "vcgencmd get_throttled".
func ParseThrottled(out []byte) (uint32, bool) {
	s := strings.TrimSpace(string(out))
	_, val, ok := strings.Cut(s, "throttled=")
	if !ok {
		return 0, false
	}
	val = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(val)), "0x")
	v, err := strconv.ParseUint(val, 16, 32)
	if err != nil {
		return 0, false
	}
	return uint32(v), true
}

// readPowerHwmon liest den Unterspannungs-Alarm von rpi_volt (nil = kein Raspberry Pi bzw. kein Alarm-Wert).
func readPowerHwmon(src source) *m64proto.Power {
	for _, h := range src.ReadDir("/sys/class/hwmon") {
		base := "/sys/class/hwmon/" + h
		if readStr(src, base+"/name") != "rpi_volt" {
			continue
		}
		switch readStr(src, base+"/in0_lcrit_alarm") {
		case "0":
			return &m64proto.Power{}
		case "1":
			return &m64proto.Power{Flags: m64proto.PowerUnderVolt}
		}
		return nil
	}
	return nil
}

// powerFrom fuehrt beide Quellen zusammen: vcgencmd (wenn lesbar) traegt alle Flags, der Alarm des Kernels ergaenzt
// "Unterspannung jetzt".
func powerFrom(throttled []byte, src source) *m64proto.Power {
	hw := readPowerHwmon(src)
	if v, ok := ParseThrottled(throttled); ok {
		p := &m64proto.Power{Flags: v}
		if hw != nil {
			p.Flags |= hw.Flags
		}
		return p
	}
	return hw
}
