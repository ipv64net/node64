package snmp

import (
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

func sysMIB(descr, objectID string) *mib {
	m := newMIB()
	m.set(oidSysDescr, gosnmp.OctetString, []byte(descr))
	m.set(oidSysObjectID, gosnmp.ObjectIdentifier, objectID)
	m.set(oidSysUpTime, gosnmp.TimeTicks, uint32(100000))
	m.set(oidSysName, gosnmp.OctetString, []byte("dev"))
	return m
}

func TestQNAPProfile(t *testing.T) {
	m := sysMIB("Linux TS-453D 5.10.60-qnap #1 SMP", ".1.3.6.1.4.1.8072.3.2.10")
	q := ".1.3.6.1.4.1.24681.1.2"
	m.set(q+".4.0", gosnmp.OctetString, []byte("3.8 GB"))
	m.set(q+".5.0", gosnmp.OctetString, []byte("47 C/116 F"))
	m.set(q+".6.0", gosnmp.OctetString, []byte("39 C/102 F"))
	m.set(q+".11.1.2.1", gosnmp.OctetString, []byte("HDD1"))
	m.set(q+".11.1.2.2", gosnmp.OctetString, []byte("HDD2"))
	m.set(q+".11.1.3.1", gosnmp.OctetString, []byte("35 C/95 F"))
	m.set(q+".11.1.3.2", gosnmp.OctetString, []byte("--"))
	m.set(q+".11.1.4.1", gosnmp.Integer, 0)
	m.set(q+".11.1.4.2", gosnmp.Integer, -9)
	m.set(q+".11.1.7.1", gosnmp.OctetString, []byte("GOOD"))
	m.set(q+".11.1.7.2", gosnmp.OctetString, []byte("Abnormal"))
	m.set(q+".17.1.2.1", gosnmp.OctetString, []byte("DataVol1"))
	m.set(q+".17.1.6.1", gosnmp.OctetString, []byte("Degraded"))
	c, _, _ := newTestCollector(t, m, Config{})
	s := collect(t, c)
	if c.profiles[0].ID != "qnap" || len(c.profiles) != 1 {
		t.Fatalf("Profile: %v", c.profiles)
	}
	if v := metric(t, svcByKey(t, s, "temp:cpu"), "temp"); v.Value != 47 {
		t.Fatalf("CPU-Temperatur aus Text: %+v", v)
	}
	h1 := svcByKey(t, s, "disk:HDD1")
	if v := metric(t, h1, "temp"); v.Value != 35 || len(h1.Facts) > 0 || h1.Text != "35 °C · SMART gut" {
		t.Fatalf("HDD1: %+v", h1)
	}
	h2 := svcByKey(t, s, "disk:HDD2")
	if hasMetric(h2, "temp") {
		t.Fatal("'--' ist keine Temperatur")
	}
	if f, ok := fact(h2, factSmartFailed); !ok || f.Text != "SMART auffällig" {
		t.Fatalf("HDD2: %+v", h2)
	}
	if _, ok := fact(svcByKey(t, s, "store:DataVol1"), factRAIDDegraded); !ok {
		t.Fatal("Volume beeintraechtigt")
	}
}

func TestTrueNASAndUniFiProfiles(t *testing.T) {
	m := sysMIB("TrueNAS-SCALE-24.10", ".1.3.6.1.4.1.8072.3.2.10")
	z := ".1.3.6.1.4.1.50536.1.1.1.1"
	m.set(z+".2.1", gosnmp.OctetString, []byte("tank"))
	m.set(z+".2.2", gosnmp.OctetString, []byte("boot-pool"))
	m.set(z+".3.1", gosnmp.Integer, 1)
	m.set(z+".3.2", gosnmp.Integer, 0)
	m.set(".1.3.6.1.4.1.50536.3.1.1.2.1", gosnmp.OctetString, []byte("sda"))
	m.set(".1.3.6.1.4.1.50536.3.1.1.3.1", gosnmp.Gauge32, uint(41000))
	c, _, _ := newTestCollector(t, m, Config{})
	s := collect(t, c)
	if f, ok := fact(svcByKey(t, s, "zfs:tank"), factZFSDegraded); !ok || f.Text != "Pool nicht ONLINE" {
		t.Fatal("tank DEGRADED")
	}
	if bp := svcByKey(t, s, "zfs:boot-pool"); len(bp.Facts) > 0 || bp.Text != "ONLINE" {
		t.Fatalf("boot-pool: %+v", bp)
	}
	if v := metric(t, svcByKey(t, s, "disk:sda"), "temp"); v.Value != 41 {
		t.Fatalf("Millicelsius: %+v", v)
	}

	u := sysMIB("UAP-AC-Pro 6.6.77", ".1.3.6.1.4.1.41112")
	u.set(".1.3.6.1.4.1.41112.1.6.3.3.0", gosnmp.OctetString, []byte("UAP-AC-Pro"))
	vap := ".1.3.6.1.4.1.41112.1.6.1.2.1"
	u.set(vap+".6.1", gosnmp.OctetString, []byte("Heim"))
	u.set(vap+".7.1", gosnmp.OctetString, []byte("ath0"))
	u.set(vap+".8.1", gosnmp.Gauge32, uint(12))
	u.set(vap+".9.1", gosnmp.OctetString, []byte("ng"))
	c, _, _ = newTestCollector(t, u, Config{})
	d := collect(t, c)
	w := svcByKey(t, d, "wlan:ath0")
	if v := metric(t, w, "clients"); v.Value != 12 || w.Text != "SSID Heim · Funk ng · 12" {
		t.Fatalf("WLAN: %+v", w)
	}
	if c.deviceKind(d) != "ap" {
		t.Fatalf("Geraeteart: %s", c.deviceKind(d))
	}
}

func TestNewPortRefreshesNames(t *testing.T) {
	m := loadWalk(t, "testdata/switch.walk")
	c, _, now := newTestCollector(t, m, Config{})
	collect(t, c)
	// neuer Port erscheint zwischen zwei Namens-Abfragen
	m.set(ifOper+".6", gosnmp.Integer, 1)
	m.set(ifAdmin+".6", gosnmp.Integer, 1)
	*now = now.Add(time.Minute)
	if hasKey(collect(t, c), "if:Gi1/0/6") {
		t.Fatal("ohne Namen noch nicht")
	}
	m.set(ifName+".6", gosnmp.OctetString, []byte("Gi1/0/6"))
	m.set(ifType+".6", gosnmp.Integer, 6)
	*now = now.Add(time.Minute)
	if !hasKey(collect(t, c), "if:Gi1/0/6") {
		t.Fatal("neuer Port nach der naechsten Runde")
	}
}
