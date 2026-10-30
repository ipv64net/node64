package proxmox

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakePBS antwortet wie ein Proxmox Backup Server 4.2 (Feldnamen wie gemessen; nur die Endpunkte, die Node64 liest).
type fakePBS struct {
	mu        sync.Mutex
	auths     []string
	paths     []string
	uptime    int
	denyStat  bool // /nodes/localhost/status: 403 (ohne Sys.Audit)
	stores    []map[string]any
	rrdBroken bool
	proxy     string // Zustand von proxmox-backup-proxy
}

func newFakePBS() *fakePBS {
	return &fakePBS{uptime: 5000, proxy: "running", stores: []map[string]any{
		{"store": "zeta", "total": 1000, "used": 900, "avail": 100, "estimated-full-date": time.Now().Add(10 * 24 * time.Hour).Unix(),
			"mount-status": "nonremovable", "backend-type": "filesystem", "history": []any{0.5, nil, 0.9}, "history-start": 1, "history-delta": 1800,
			"gc-status": map[string]any{"disk-bytes": 400, "index-data-bytes": 1000, "pending-bytes": 0, "upid": "UPID:x"}},
		{"store": "alpha", "total": 2000, "used": 500, "avail": 1500, "estimated-full-date": 1, "backend-type": "s3"}, // in der Vergangenheit
		{"store": "usb", "total": -1, "used": -1, "avail": -1, "error": "datastore not mounted", "mount-status": "notmounted"},
	}}
}

func (f *fakePBS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.auths = append(f.auths, r.Header.Get("Authorization"))
	f.paths = append(f.paths, r.Method+" "+r.URL.RequestURI())
	reply := func(v any) { _ = json.NewEncoder(w).Encode(map[string]any{"data": v}) }
	switch r.URL.Path {
	case "/api2/json/version":
		reply(map[string]any{"version": "4.2", "release": "6", "repoid": "abc"})
	case "/api2/json/nodes/localhost/status":
		if f.denyStat {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"data":null,"message":"permission check failed"}`))
			return
		}
		reply(map[string]any{"cpu": 0.25, "wait": 0.01, "cpuinfo": map[string]any{"cpus": 8, "model": "x", "sockets": 1},
			"memory": map[string]any{"total": 16000, "used": 4000, "free": 12000}, "root": map[string]any{"total": 100000, "used": 25000, "avail": 75000},
			"swap": map[string]any{"total": 0, "used": 0, "free": 0}, "loadavg": []float64{0.1, 0.2, 0.3}, "kversion": "Linux 6.14",
			"uptime": f.uptime, "current-kernel": map[string]any{"sysname": "pbs1", "release": "6.14"}, "info": map[string]any{"fingerprint": "aa:bb"}})
	case "/api2/json/nodes/localhost/rrd":
		if r.URL.Query().Get("timeframe") != "hour" || f.rrdBroken {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		reply([]map[string]any{
			{"time": 1, "netin": 100, "netout": 200, "read_bytes": 300, "write_bytes": 400},
			{"time": 2, "cpu": 0.2, "iowait": 0.01, "io_ticks": 5, "loadavg": 0.3, "memtotal": 16000, "memused": 4000, "netin": 1000, "netout": 2000,
				"read_bytes": 3000, "write_bytes": 4000, "read_ios": 1, "write_ios": 2, "swaptotal": 0, "swapused": 0, "total": 100000, "used": 25000},
			{"time": 3, "netin": nil, "netout": nil}, // juengste Minute noch ohne Werte
		})
	case "/api2/json/nodes/localhost/services":
		reply([]map[string]any{{"service": "proxmox-backup", "state": "running", "unit-state": "enabled"},
			{"service": "proxmox-backup-proxy", "state": f.proxy, "unit-state": "enabled"}, {"service": "sshd", "state": "running"}})
	case "/api2/json/status/datastore-usage":
		reply(f.stores)
	case "/api2/json/nodes/localhost/apt/update":
		reply([]map[string]any{{"Package": "proxmox-backup-client", "OldVersion": "4.2.6-1", "Version": "4.2.8-1"},
			{"Package": "proxmox-backup-server", "OldVersion": "4.2.6-1", "Version": "4.2.8-1"}})
	case "/api2/json/admin/datastore/zeta/namespace":
		reply([]map[string]any{{"ns": ""}, {"ns": "X64-Web"}})
	case "/api2/json/admin/datastore/alpha/namespace":
		reply([]map[string]any{{"ns": ""}})
	case "/api2/json/admin/datastore/zeta/groups":
		if r.URL.Query().Get("ns") == "X64-Web" { // die Backups liegen im Namespace
			reply([]map[string]any{{"backup-type": "vm", "backup-id": "100", "backup-count": 7, "last-backup": 1700000500, "owner": "x@pbs", "files": []string{"a"}},
				{"backup-type": "ct", "backup-id": "200", "backup-count": 3, "last-backup": 1700000900}})
			return
		}
		reply([]map[string]any{})
	case "/api2/json/admin/datastore/alpha/groups":
		reply([]map[string]any{})
	case "/api2/json/nodes/localhost/tasks":
		if r.URL.Query().Get("errors") != "1" || r.URL.Query().Get("since") == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		now := time.Now().Unix()
		reply([]map[string]any{
			{"upid": "a", "worker_type": "verify", "worker_id": "zeta", "starttime": now - 7200, "endtime": now - 7000, "status": "verification failed"},
			{"upid": "b", "worker_type": "backup", "worker_id": "zeta:vm/100", "starttime": now - 60, "endtime": now - 30, "status": "connection error"},
			{"upid": "c", "worker_type": "garbage_collection", "worker_id": "zeta", "starttime": now - 30*86400, "endtime": now - 30*86400 + 5, "status": "old"},
		})
	default:
		w.WriteHeader(http.StatusNotImplemented)
	}
}

func pbsSys(pin string, addrs ...string) System {
	return System{ID: 9, Kind: KindPBS, Name: "backup", Addresses: addrs, TokenID: "monitor@pbs!node64", Secret: testSecret,
		PinSHA256: pin, Interval: 30, Enabled: true}
}

func TestPBSPollerSnapshot(t *testing.T) {
	f := newFakePBS()
	srv := startTLS(t, f, "", nil)
	sys := pbsSys(pinOf(srv), srv.URL)
	c := mustClient(t, sys, nil)
	var got *Snapshot
	p := newPBSPoller(testLog, sys, func(_ context.Context, s *Snapshot) { got = s }, c, nil)
	s := p.Poll(context.Background())
	if got != s || !s.OK || s.Error != "" || s.Warning != "" {
		t.Fatalf("snapshot %+v", s)
	}
	if f.auths[0] != "PBSAPIToken=monitor@pbs!node64:"+testSecret {
		t.Fatalf("auth header %q", f.auths[0])
	}
	if s.Version != "4.2.6" {
		t.Fatalf("version %q", s.Version)
	}
	if len(s.Resources) != 1 {
		t.Fatalf("resources %+v", s.Resources)
	}
	r := s.Resources[0]
	if r.Key() != "node/localhost" || r.Name != "backup" || r.State != StateOnline || !r.Measurable() || r.CPU != 0.25 || r.MaxCPU != 8 || r.Mem != 4000 || r.MaxMem != 16000 ||
		r.Disk != 25000 || r.MaxDisk != 100000 || r.Uptime != 5000 || r.Restarted {
		t.Fatalf("node %+v", r)
	}
	if r.NetIn != 1000 || r.NetOut != 2000 || r.DiskRead != 3000 || r.DiskWrite != 4000 { // letzte Minute mit Werten
		t.Fatalf("rates %+v", r)
	}
	if s.PBS == nil || len(s.PBS.Datastores) != 3 || s.PBS.Datastores[0].Store != "alpha" || s.PBS.Datastores[2].Store != "zeta" {
		t.Fatalf("datastores %+v", s.PBS)
	}
	z := s.PBS.Datastores[2]
	if v, ok := z.UsedPercent(); !ok || v != 90 {
		t.Fatalf("used %v %v", v, ok)
	}
	if _, ok := z.FullTime(time.Now()); !ok {
		t.Fatal("zeta: full estimate in the future")
	}
	if _, ok := s.PBS.Datastores[0].FullTime(time.Now()); ok {
		t.Fatal("alpha: estimate in the past is no estimate")
	}
	u := s.PBS.Datastores[1]
	if _, ok := u.UsedPercent(); ok || u.Error == "" || u.Mount != "notmounted" {
		t.Fatalf("usb %+v", u)
	}
	for _, path := range f.paths {
		if !strings.HasPrefix(path, "GET ") {
			t.Fatalf("not only GET: %s", path) // nur lesen (Rolle Audit)
		}
	}
	pi := s.PBS
	if pi.Update != "4.2.8-1" || !pi.UpdateOK || len(pi.Services) != 2 || len(pi.ServicesDown()) != 0 {
		t.Fatalf("update/services %+v", pi)
	}
	if z.Dedup != 2.5 || !z.Known || z.Groups != 2 || z.Snapshots != 10 || z.LastBackup != 1700000900 {
		t.Fatalf("zeta backups %+v", z)
	}
	if a := s.PBS.Datastores[0]; !a.Known || a.Groups != 0 || a.Dedup != 0 {
		t.Fatalf("alpha backups %+v", a)
	}
	if u := s.PBS.Datastores[1]; u.Known {
		t.Fatalf("usb (not mounted) must not be queried: %+v", u)
	}
	if len(pi.Failed) != 2 || pi.Failed[0].Type != "backup" || pi.Failed[1].Status != "verification failed" { // neueste zuerst, ohne den alten
		t.Fatalf("failed tasks %+v", pi.Failed)
	}

	// Neustart: Uptime springt zurueck; ohne RRD bleiben die Raten 0
	f.mu.Lock()
	f.uptime, f.rrdBroken, f.proxy = 60, true, "dead"
	n := len(f.paths)
	f.mu.Unlock()
	s = p.Poll(context.Background())
	if !s.OK || !s.Resources[0].Restarted || s.Resources[0].NetIn != 0 {
		t.Fatalf("restart %+v", s.Resources)
	}
	if d := s.PBS.ServicesDown(); len(d) != 1 || d[0] != "proxmox-backup-proxy" || s.PBS.Datastores[2].Groups != 2 {
		t.Fatalf("services down %v, cached backups %+v", d, s.PBS.Datastores[2])
	}
	f.mu.Lock()
	for _, path := range f.paths[n:] {
		if strings.Contains(path, "/groups") || strings.Contains(path, "/apt/") {
			t.Fatalf("slow data again within 10 min: %s", path)
		}
	}
	f.mu.Unlock()
}

func TestPBSPollerRights(t *testing.T) {
	f := newFakePBS()
	f.stores = []map[string]any{} // Token ohne Datastore.Audit: leere Liste
	srv := startTLS(t, f, "", nil)
	sys := pbsSys(pinOf(srv), srv.URL)
	p := newPBSPoller(testLog, sys, nil, mustClient(t, sys, nil), nil)
	s := p.Poll(context.Background())
	if !s.OK || !strings.Contains(s.Warning, "Datastore.Audit") || s.PBS == nil || len(s.PBS.Datastores) != 0 {
		t.Fatalf("no datastores: %+v", s)
	}
	f.mu.Lock()
	f.denyStat = true
	f.mu.Unlock()
	s = p.Poll(context.Background())
	if s.OK || !strings.Contains(s.Error, "Sys.Audit") || len(s.Resources) != 0 || s.PBS != nil {
		t.Fatalf("status denied: %+v", s)
	}
}

func TestPBSProbe(t *testing.T) {
	f := newFakePBS()
	srv := startTLS(t, f, "", nil)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	r := probe(context.Background(), pbsSys("", srv.URL), roots, time.Second, 2*time.Second)
	if !r.OK || !r.CertTrusted || r.Version != "4.2.6" || len(r.Nodes) != 0 || r.Datastores != 3 || r.PermWarning != "" {
		t.Fatalf("probe %+v", r)
	}
	for _, a := range f.auths {
		if a != "" && !strings.HasPrefix(a, "PBSAPIToken=") {
			t.Fatalf("auth %q", a)
		}
	}
}

func TestPBSAddressAndValidate(t *testing.T) {
	if a, ok := NormalizeAddressFor(KindPBS, "pbs.lan"); !ok || a != "https://pbs.lan:8007" {
		t.Fatalf("pbs default port: %q", a)
	}
	if a, ok := NormalizeAddressFor(KindPVE, "pve.lan"); !ok || a != "https://pve.lan:8006" {
		t.Fatalf("pve default port: %q", a)
	}
	sys := System{Kind: KindPBS, Name: "b", Addresses: []string{"pbs.lan"}, TokenID: "monitor@pbs!node64", Secret: "s", Interval: 30}
	if err := ValidateSystem(&sys, true); err != nil || sys.Addresses[0] != "https://pbs.lan:8007" {
		t.Fatalf("validate: %v %v", err, sys.Addresses)
	}
	a := System{Kind: KindPBS, Addresses: []string{"https://pbs.lan:8007"}}
	b := System{Kind: KindPBS, Addresses: []string{"pbs.lan"}}
	if !SameEndpoint(&a, &b) {
		t.Fatal("same endpoint with default port 8007")
	}
	if NewSource(testLog, sys, nil).(*PBSPoller) == nil {
		t.Fatal("source")
	}
	if pbsVersionText(pveVersion{Version: "3.4", Release: "7"}) != "3.4.7" || pbsVersionText(pveVersion{Version: "4.0.1"}) != "4.0.1" {
		t.Fatal("version text")
	}
}
