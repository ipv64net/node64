package monitor64

import (
	"context"
	"fmt"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/apis"
	"github.com/ipv64net/node64/internal/monitor64/model"
)

// "Verbindung testen" fuer API-Zugaenge (Proxmox VE, PBS, Docker): erst Test (Fingerabdruck, Bestaetigung,
// Cluster-Nodes), danach – nur wenn verbunden und bestaetigt – eine Abfragerunde fuer die Liste der Dienste.

type apiTester interface {
	Test(ctx context.Context) apis.TestResult
	Collect(ctx context.Context) ([]model.Service, error)
}

// newAPITester baut den Sammler eines API-Zugangs fuer den Test; done gibt Verbindungen frei (Docker ssh://).
func newAPITester(typ string, h *Host, cfg accessConfig, secret string) (t apiTester, done func(), err error) {
	addr := cfg.URL
	switch typ {
	case "pve":
		if addr == "" {
			addr = "https://" + apiHostPort(h.Address, 8006)
		}
		c, err := apis.NewPVE(apis.PVEConfig{Addresses: splitAddrs(addr), TokenID: cfg.TokenID, Secret: secret, Pin: cfg.Pin, Node: cfg.Node})
		if err != nil {
			return nil, nil, err
		}
		return c, func() {}, nil
	case "pbs":
		if addr == "" {
			addr = "https://" + apiHostPort(h.Address, 8007)
		}
		c, err := apis.NewPBS(apis.PBSConfig{Addresses: splitAddrs(addr), TokenID: cfg.TokenID, Secret: secret, Pin: cfg.Pin,
			BackupMaxAge: time.Duration(cfg.BackupMaxAgeH) * time.Hour})
		if err != nil {
			return nil, nil, err
		}
		return c, func() {}, nil
	case "docker":
		c, err := apis.NewDocker(apis.DockerConfig{Host: addr, Pin: cfg.Pin, Secret: secret})
		if err != nil {
			return nil, nil, err
		}
		return c, c.Close, nil
	case "prom":
		c, err := newProm(h, cfg, secret)
		if err != nil {
			return nil, nil, err
		}
		return c, c.Close, nil
	case "nut", "truenas", "unraid", "redfish", "pmg", "mailcow", "fritzbox":
		return newDeviceAPI(typ, h, cfg, secret)
	}
	return nil, nil, fmt.Errorf("monitor64: no api access %q", typ)
}

// isAPIAccess: Zugang ueber eine API (Test mit Fingerabdruck und Bestaetigung).
func isAPIAccess(typ string) bool {
	switch typ {
	case "pve", "pbs", "pmg", "mailcow", "fritzbox", "docker", "prom", "nut", "truenas", "unraid", "redfish", "snmp": // snmp: eigener Test (testSNMP)
		return true
	}
	return false
}
