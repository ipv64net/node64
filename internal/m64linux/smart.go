package m64linux

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/ipv64net/node64/internal/m64proto"
)

// DeviceRE prueft Geraetenamen, bevor sie an smartctl gehen (Plan, Abschnitt "Sicherheit").
var DeviceRE = regexp.MustCompile(`^/dev/[a-z0-9/]+$`)

// smartTypeRE prueft den Geraetetyp fuer "smartctl -d" (sat, nvme, scsi, sat,12, megaraid,0, usbjmicron ...).
var smartTypeRE = regexp.MustCompile(`^[a-z0-9][a-z0-9,_+-]{0,31}$`)

// SmartErrStandby steht in SMART.Error, wenn die Platte schlief und nicht geweckt wurde (smartctl -n standby).
// Die Node behaelt dann den letzten Stand.
const SmartErrStandby = "standby"

// smartStandbyRE erkennt die Meldung von "smartctl -n standby" fuer eine schlafende Platte: "Device is in STANDBY
// mode", "SLEEP mode" und die EPC-Zustaende "STANDBY_Y"/"STANDBY_Z" (smartmontools >= 7.3).
var smartStandbyRE = regexp.MustCompile(`(?i)\b(standby|sleep)(_[a-z])?\s+mode\b`)

// maxSmartDevices begrenzt die Zahl der abgefragten Platten.
const maxSmartDevices = 64

// SmartDevice ist ein Eintrag aus "smartctl --scan-open".
type SmartDevice struct {
	Name string // /dev/sda
	Type string // sat, nvme, scsi ...
}

// ValidSmartDevice prueft Name und Typ eines Geraets.
func ValidSmartDevice(d SmartDevice) bool {
	if strings.Contains(d.Name, "..") || !DeviceRE.MatchString(d.Name) || len(d.Name) > 64 {
		return false
	}
	return d.Type == "" || smartTypeRE.MatchString(d.Type)
}

// ParseSmartScan liest "smartctl --scan-open -j" (JSON) oder die Textform "/dev/sda -d sat # ...".
// Ungueltige Namen werden verworfen.
func ParseSmartScan(b []byte) ([]SmartDevice, error) {
	var out []SmartDevice
	add := func(d SmartDevice) {
		if ValidSmartDevice(d) && len(out) < maxSmartDevices {
			out = append(out, d)
		}
	}
	t := strings.TrimSpace(string(b))
	if strings.HasPrefix(t, "{") {
		var v struct {
			Devices []struct {
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"devices"`
		}
		if err := json.Unmarshal([]byte(t), &v); err != nil {
			return nil, err
		}
		for _, d := range v.Devices {
			add(SmartDevice{Name: d.Name, Type: d.Type})
		}
		return out, nil
	}
	for _, ln := range lines(b) {
		f := strings.Fields(ln)
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		d := SmartDevice{Name: f[0]}
		if len(f) >= 3 && f[1] == "-d" {
			d.Type = f[2]
		}
		add(d)
	}
	return out, nil
}

// smartJSON ist der benoetigte Teil von "smartctl -j -a".
type smartJSON struct {
	Smartctl struct {
		ExitStatus int `json:"exit_status"`
		Messages   []struct {
			String   string `json:"string"`
			Severity string `json:"severity"`
		} `json:"messages"`
	} `json:"smartctl"`
	Device struct {
		Name     string `json:"name"`
		Type     string `json:"type"`
		Protocol string `json:"protocol"`
	} `json:"device"`
	ModelName     string `json:"model_name"`
	ScsiModelName string `json:"scsi_model_name"`
	ScsiProduct   string `json:"scsi_product"`
	SerialNumber  string `json:"serial_number"`
	UserCapacity  struct {
		Bytes uint64 `json:"bytes"`
	} `json:"user_capacity"`
	NvmeTotalCapacity uint64 `json:"nvme_total_capacity"`
	SmartSupport      *struct {
		Available *bool `json:"available"`
		Enabled   *bool `json:"enabled"`
	} `json:"smart_support"`
	SmartStatus *struct {
		Passed *bool `json:"passed"`
	} `json:"smart_status"`
	Temperature *struct {
		Current *float64 `json:"current"`
	} `json:"temperature"`
	PowerOnTime *struct {
		Hours *uint64 `json:"hours"`
	} `json:"power_on_time"`
	ATAAttrs *struct {
		Table []struct {
			ID    int `json:"id"`
			Value int `json:"value"`
			Raw   struct {
				Value uint64 `json:"value"`
			} `json:"raw"`
		} `json:"table"`
	} `json:"ata_smart_attributes"`
	NVMeLog *struct {
		CriticalWarning *uint64  `json:"critical_warning"`
		Temperature     *float64 `json:"temperature"`
		PercentageUsed  *float64 `json:"percentage_used"`
		PowerOnHours    *uint64  `json:"power_on_hours"`
		MediaErrors     *uint64  `json:"media_errors"`
	} `json:"nvme_smart_health_information_log"`
	ScsiGrownDefects *uint64 `json:"scsi_grown_defect_list"`
	ScsiErrorLog     *struct {
		Read *struct {
			Uncorrected *uint64 `json:"total_uncorrected_errors"`
		} `json:"read"`
		Write *struct {
			Uncorrected *uint64 `json:"total_uncorrected_errors"`
		} `json:"write"`
	} `json:"scsi_error_counter_log"`
	ScsiEndurance *struct {
		Used *float64 `json:"current_percentage_used_endurance_indicator"`
	} `json:"scsi_percentage_used_endurance_indicator"`
}

// ParseSmartctl liest "smartctl -j -a <dev>" (smartmontools >= 7). dev ist der abgefragte Name (Fallback, falls
// die Ausgabe keinen enthaelt). Platten ohne SMART (USB-Bridges, VMs) bekommen Error statt Werten.
func ParseSmartctl(dev string, b []byte) m64proto.SMART {
	s := m64proto.SMART{Device: dev}
	var j smartJSON
	t := strings.TrimSpace(string(b))
	if !strings.HasPrefix(t, "{") {
		s.Error = "keine JSON-Ausgabe (smartctl < 7?)"
		if l := lines([]byte(t)); len(l) > 0 {
			s.Error += ": " + clip(l[0])
		}
		s.Error = clip(s.Error)
		return s
	}
	if err := json.Unmarshal([]byte(t), &j); err != nil {
		s.Error = clip("JSON: " + err.Error())
		return s
	}
	if j.Device.Name != "" && DeviceRE.MatchString(j.Device.Name) {
		s.Device = j.Device.Name
	}
	s.Type = clip(strings.ToLower(j.Device.Protocol))
	if s.Type == "" {
		s.Type = clip(j.Device.Type)
	}
	s.Model = clip(j.ModelName)
	if s.Model == "" {
		s.Model = clip(j.ScsiModelName)
	}
	if s.Model == "" {
		s.Model = clip(j.ScsiProduct)
	}
	s.Serial = clip(j.SerialNumber)
	s.CapacityBytes = j.UserCapacity.Bytes
	if s.CapacityBytes == 0 {
		s.CapacityBytes = j.NvmeTotalCapacity
	}

	// Meldungen: Standby, Fehler
	var firstErr string
	for _, m := range j.Smartctl.Messages {
		if smartStandbyRE.MatchString(m.String) {
			s.Error = SmartErrStandby
			return s
		}
		if firstErr == "" && m.Severity == "error" {
			firstErr = m.String
		}
	}

	if j.SmartStatus != nil && j.SmartStatus.Passed != nil {
		s.Passed = ptrBool(*j.SmartStatus.Passed)
	} else if j.Smartctl.ExitStatus&8 != 0 {
		s.Passed = ptrBool(false)
	}
	if j.Temperature != nil && j.Temperature.Current != nil && *j.Temperature.Current > 0 && *j.Temperature.Current < 150 {
		s.TempC = ptrF64(*j.Temperature.Current)
	}
	if j.PowerOnTime != nil && j.PowerOnTime.Hours != nil {
		s.PowerOnHours = ptrU64(*j.PowerOnTime.Hours)
	}
	if j.ATAAttrs != nil {
		for _, a := range j.ATAAttrs.Table {
			switch a.ID {
			case 5:
				s.Reallocated = ptrU64(a.Raw.Value)
			case 197:
				s.Pending = ptrU64(a.Raw.Value)
			case 198:
				s.Uncorrectable = ptrU64(a.Raw.Value)
			case 199:
				s.CRCErrors = ptrU64(a.Raw.Value)
			case 177, 231, 233, 202, 169:
				// normierter Wert = verbleibende Lebensdauer in % (Samsung 177, 231 SSD_Life_Left,
				// Intel 233, Crucial 202, WD 169); erster Treffer gilt
				if s.WearPercentUsed == nil && a.Value > 0 && a.Value <= 100 {
					s.WearPercentUsed = ptrF64(float64(100 - a.Value))
				}
			}
		}
	}
	if n := j.NVMeLog; n != nil {
		if n.CriticalWarning != nil {
			s.CriticalWarning = ptrU64(*n.CriticalWarning)
		}
		if n.MediaErrors != nil {
			s.MediaErrors = ptrU64(*n.MediaErrors)
		}
		if n.PercentageUsed != nil {
			s.WearPercentUsed = ptrF64(*n.PercentageUsed)
		}
		if s.PowerOnHours == nil && n.PowerOnHours != nil {
			s.PowerOnHours = ptrU64(*n.PowerOnHours)
		}
		if s.TempC == nil && n.Temperature != nil && *n.Temperature > 0 && *n.Temperature < 150 {
			s.TempC = ptrF64(*n.Temperature)
		}
	}
	if j.ScsiGrownDefects != nil {
		s.Reallocated = ptrU64(*j.ScsiGrownDefects)
	}
	if e := j.ScsiErrorLog; e != nil {
		var sum uint64
		has := false
		if e.Read != nil && e.Read.Uncorrected != nil {
			sum += *e.Read.Uncorrected
			has = true
		}
		if e.Write != nil && e.Write.Uncorrected != nil {
			sum += *e.Write.Uncorrected
			has = true
		}
		if has {
			s.Uncorrectable = ptrU64(sum)
		}
	}
	if j.ScsiEndurance != nil && j.ScsiEndurance.Used != nil {
		s.WearPercentUsed = ptrF64(*j.ScsiEndurance.Used)
	}

	if s.Passed == nil {
		switch {
		case j.SmartSupport != nil && j.SmartSupport.Available != nil && !*j.SmartSupport.Available:
			s.Error = "SMART nicht verfuegbar"
		case j.SmartSupport != nil && j.SmartSupport.Enabled != nil && !*j.SmartSupport.Enabled:
			s.Error = "SMART ausgeschaltet"
		case firstErr != "":
			s.Error = clip(firstErr)
		case j.Smartctl.ExitStatus&3 != 0:
			s.Error = "Geraet nicht lesbar"
		}
	}
	return s
}
