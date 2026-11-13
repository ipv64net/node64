package apis

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var (
	ufMacRE = regexp.MustCompile(`(?i)([0-9a-f]{2}:){4}([0-9a-f]{2}:[0-9a-f]{2})`)
	ufIPRE  = regexp.MustCompile(`(\d{1,3}\.\d{1,3})\.\d{1,3}\.\d{1,3}`)
)

// ufMask kuerzt MAC- und IPv4-Adressen in der Ausgabe des Tests (das Protokoll soll kein fremdes Netz abbilden).
func ufMask(s string) string {
	return ufIPRE.ReplaceAllString(ufMacRE.ReplaceAllString(s, "xx:xx:xx:xx:${2}"), "${1}.x.x")
}

// Gegen eine echte UniFi Network Application (Konsole oder selbst gehosteter Server): Test mit Bestaetigung des
// Fingerabdrucks, zwei Runden, falsche Zugangsdaten. Zugangsdaten nur ueber die Umgebung, nie im Repo:
//
//	M64_UF_ADDR=https://127.0.0.1:18444 M64_UF_USER=monitor64 M64_UF_SECRET=... [M64_UF_SITE=default] go test -run TestIntegrationUnifi -v ./internal/monitor64/apis/
//
// Ohne M64_UF_USER gilt M64_UF_SECRET als API-Schluessel (nur UniFi OS).
func TestIntegrationUnifi(t *testing.T) {
	addr := os.Getenv("M64_UF_ADDR")
	if addr == "" {
		t.Skip("M64_UF_ADDR nicht gesetzt")
	}
	cfg := UnifiConfig{Address: addr, User: os.Getenv("M64_UF_USER"), Secret: os.Getenv("M64_UF_SECRET"), Site: os.Getenv("M64_UF_SITE")}
	u, err := NewUnifi(cfg)
	if err != nil {
		t.Fatal(err)
	}
	res := u.Test(context.Background())
	u.Close()
	if !res.NeedConfirm || res.Fingerprint == "" {
		t.Fatalf("ohne Pin: %+v", res)
	}
	t.Logf("Zertifikat %s (%s)", res.Fingerprint, res.CertSubject)
	cfg.Pin = res.Fingerprint
	if u, err = NewUnifi(cfg); err != nil {
		t.Fatal(err)
	}
	res = u.Test(context.Background())
	if !res.OK {
		u.Close()
		t.Fatalf("Test: %s", de(res.Error))
	}
	t.Logf("Test: Version %q, %s, UniFi OS=%v", res.Version, de(res.Summary), u.prefix() == ufOSPrefix)
	if os.Getenv("M64_UF_SHAPE") != "" {
		ufLogShapes(t, u)
	}
	for round := 1; round <= 2; round++ {
		svcs, err := u.Collect(context.Background())
		if err != nil {
			t.Errorf("Runde %d: %v", round, deErr(err))
		}
		for _, s := range svcs {
			var ms []string
			for _, x := range s.Metrics {
				ms = append(ms, fmt.Sprintf("%s=%g%s", x.Name, x.Value, x.Unit))
			}
			t.Log(ufMask(fmt.Sprintf("Runde %d: %-28s %-8s vorgewaehlt=%-5v %s | %s | %v | Facts %d", round, s.Key, s.Kind, s.Default, de(s.Name), de(s.Text), ms, len(s.Facts))))
		}
		if len(svcs) < 2 {
			t.Fatalf("Runde %d: nur %d Dienste", round, len(svcs))
		}
	}
	t.Logf("Alarme entfernt seit: %v", u.alarmsGone)
	u.Close()
	bad := cfg
	bad.Secret += "-falsch"
	b, err := NewUnifi(bad)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if _, err := b.Collect(context.Background()); err == nil || strings.Contains(deErr(err), cfg.Secret) {
		t.Errorf("falsche Zugangsdaten: %v", err)
	} else {
		t.Logf("falsche Zugangsdaten: %s", deErr(err))
	}
}

// ufShapeValues: Felder, deren Werte beim Abgleich der Formate gezeigt werden duerfen (Zustaende, Zahlen, Versionen).
// Alles andere – Namen, Adressen, MACs, Seriennummern, Texte – erscheint nur mit seinem Typ.
var ufShapeValues = map[string]bool{"type": true, "state": true, "status": true, "subsystem": true, "model": true, "version": true, "adopted": true,
	"disabled": true, "upgradable": true, "upgrade_to_firmware": true, "up": true, "enable": true, "speed": true, "full_duplex": true, "is_uplink": true,
	"media": true, "port_poe": true, "poe_enable": true, "poe_power": true, "poe_good": true, "poe_mode": true, "port_idx": true, "cpu": true, "mem": true,
	"general_temperature": true, "value": true, "overheating": true, "total_max_power": true, "num_sta": true, "latency": true, "xput_up": true,
	"xput_down": true, "num_gw": true, "num_user": true, "num_guest": true, "rx_bytes-r": true, "tx_bytes-r": true, "update_available": true,
	"console_display_version": true, "archived": true, "role": true, "has_fan": true, "fan_level": true, "uptime": true, "rx_errors": true, "tx_errors": true,
	"rx_packets": true, "tx_packets": true, "op_mode": true, "autoneg": true, "has_temperature": true, "num_ap": true, "num_sw": true, "num_adopted": true,
	"num_disconnected": true, "num_pending": true, "drops": true, "speedtest_status": true, "upgrade_state": true, "rx_dropped": true, "tx_dropped": true,
	"loadavg_1": true, "mem_total": true, "mem_used": true, "satisfaction": true, "is_cloud_console": true, "ubnt_device_type": true, "udm_version": true,
	"availability": true, "latency_average": true, "key": true, "max_speed": true, "shortname": true, "WAN": true, "WAN2": true, "internet": true}

// ufLogShapes zeigt je Abfrage die Feldnamen mit JSON-Typ (und fuer unkritische Felder die Werte), um die Formate
// eines echten Controllers mit den Structs abzugleichen – ohne Namen, Adressen oder MACs des Netzes auszugeben.
func ufLogShapes(t *testing.T, u *Unifi) {
	base := "/api/s/" + u.site
	for _, p := range []string{"/api/self/sites", base + "/stat/device", base + "/stat/health", base + "/stat/sysinfo", base + "/list/alarm"} {
		var raw json.RawMessage
		if err := u.get(context.Background(), p, &raw); err != nil {
			t.Logf("FORM %s: Fehler %s", p, deErr(err))
			continue
		}
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Logf("FORM %s: %v", p, err)
			continue
		}
		shape := map[string]map[string]bool{}
		ufShape(shape, "", "", v, 0)
		keys := make([]string, 0, len(shape))
		for k := range shape {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		n := 0
		if l, ok := v.([]any); ok {
			n = len(l)
		}
		t.Logf("FORM %s: %d Eintraege, %d Felder", p, n, len(keys))
		for _, k := range keys {
			vals := make([]string, 0, len(shape[k]))
			for x := range shape[k] {
				vals = append(vals, x)
			}
			sort.Strings(vals)
			if len(vals) > 8 {
				vals = append(vals[:8], "…")
			}
			t.Logf("FORM   %-58s %s", k, strings.Join(vals, " | "))
		}
	}
}

func ufShape(out map[string]map[string]bool, path, key string, v any, depth int) {
	add := func(s string) {
		if out[path] == nil {
			out[path] = map[string]bool{}
		}
		out[path][s] = true
	}
	show := ufShapeValues[key]
	switch x := v.(type) {
	case nil:
		add("null")
	case bool:
		if show {
			add(fmt.Sprintf("bool:%v", x))
		} else {
			add("bool")
		}
	case float64:
		if show {
			add(fmt.Sprintf("zahl:%g", x))
		} else {
			add("zahl")
		}
	case string:
		if show {
			add(fmt.Sprintf("text:%q", x))
		} else {
			add("text")
		}
	case []any:
		if path != "" {
			add(fmt.Sprintf("liste(%d)", len(x)))
		}
		if depth < 4 {
			for _, e := range x {
				ufShape(out, path+"[]", key, e, depth+1)
			}
		}
	case map[string]any:
		if path != "" {
			add("objekt")
		}
		if depth < 4 {
			for k, e := range x {
				ufShape(out, path+"."+k, k, e, depth+1)
			}
		}
	}
}

func TestUfMask(t *testing.T) {
	if got := ufMask("dev:84:78:48:10:9c:c8 online · 203.0.113.154 · 9 ms"); got != "dev:xx:xx:xx:xx:9c:c8 online · 203.0.x.x · 9 ms" {
		t.Fatalf("ufMask: %q", got)
	}
}
