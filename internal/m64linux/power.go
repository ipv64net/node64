package m64linux

import (
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/m64proto"
)

// piThrottled ist der Stand der Raspberry-Pi-Firmware (wie "vcgencmd get_throttled", als Hex-Zahl).
const piThrottled = "/sys/devices/platform/soc/soc:firmware/get_throttled"

// readPower liest die Stromversorgung eines Raspberry Pi: Unterspannung und Drosselung, jetzt und seit dem Start.
// Ohne die Datei der Firmware (Kernel ohne Raspberry-Pi-Treiber) bleibt der Unterspannungs-Alarm des hwmon-Geraets
// rpi_volt (meldet nur "seit dem letzten Lesen"). nil = kein Raspberry Pi bzw. nichts lesbar.
func readPower(src source) *m64proto.Power {
	if s := strings.TrimPrefix(strings.ToLower(readStr(src, piThrottled)), "0x"); s != "" {
		if v, err := strconv.ParseUint(s, 16, 32); err == nil {
			return &m64proto.Power{Flags: uint32(v)}
		}
	}
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
