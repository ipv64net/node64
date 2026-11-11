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
