package monitor64

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/apis"
	"github.com/ipv64net/node64/internal/monitor64/model"
	"github.com/ipv64net/node64/internal/monitor64/promscrape"
)

// API-Zugaenge (Paket apis): Proxmox VE, Proxmox Backup Server, Docker. Teilfehler (eine Abfrage scheitert)
// liefern die uebrigen Dienste; der Zugang zeigt den Fehler.

type apiSource interface {
	Collect(ctx context.Context) ([]model.Service, error)
}

type apiCollector struct {
	src   apiSource
	close func()
}

func (a *apiCollector) collect(ctx context.Context) ([]model.Service, error) {
	return a.src.Collect(ctx)
}

func (a *apiCollector) closeFn() {
	if a.close != nil {
		a.close()
	}
}

// newAPICollector baut den Sammler fuer Proxmox VE, PBS, Docker, Prometheus, Geraete-APIs und SNMP.
func (m *Module) newAPICollector(a *Access, h *Host, cfg accessConfig, secret string) (collector, error) {
	addr := cfg.URL
	typ := a.Type
	switch typ {
	case "pve":
		if addr == "" {
			addr = "https://" + apiHostPort(h.Address, 8006)
		}
		c, err := apis.NewPVE(apis.PVEConfig{Addresses: splitAddrs(addr), TokenID: cfg.TokenID, Secret: secret, Pin: cfg.Pin, Node: cfg.Node, Seen: m.pveSeen})
		if err != nil {
			return nil, err
		}
		ad := &apiAdapter{apiCollector: apiCollector{src: c}}
		if cfg.Node == "" {
			// erkannte Node speichern: nach Neustart oder Aenderung am Zugang nicht still eine andere Node abfragen,
			// wenn die erste Adresse gerade nicht antwortet (Failover-Adressen)
			uid := a.UID
			ad.node = c.Node
			ad.saveNode = func(n string) {
				if err := m.store.SetAccessNode(context.Background(), uid, n); err != nil {
					m.log.Warn("monitor64: save pve node", "err", err)
				}
			}
		}
		return ad, nil
	case "pbs":
		if addr == "" {
			addr = "https://" + apiHostPort(h.Address, 8007)
		}
		c, err := apis.NewPBS(apis.PBSConfig{Addresses: splitAddrs(addr), TokenID: cfg.TokenID, Secret: secret, Pin: cfg.Pin,
			BackupMaxAge: time.Duration(cfg.BackupMaxAgeH) * time.Hour})
		if err != nil {
			return nil, err
		}
		return &apiAdapter{apiCollector: apiCollector{src: c}}, nil
	case "docker":
		c, err := apis.NewDocker(apis.DockerConfig{Host: addr, Pin: cfg.Pin, Secret: secret})
		if err != nil {
			return nil, err
		}
		return &apiAdapter{apiCollector: apiCollector{src: c, close: c.Close}}, nil
	case "prom":
		c, err := newProm(h, cfg, secret)
		if err != nil {
			return nil, err
		}
		return &apiAdapter{apiCollector: apiCollector{src: c, close: c.Close}}, nil
	case "nut", "truenas", "unraid", "redfish", "pmg", "mailcow", "fritzbox", "mikrotik":
		src, done, err := newDeviceAPI(typ, h, cfg, secret)
		if err != nil {
			return nil, err
		}
		return &apiAdapter{apiCollector: apiCollector{src: src, close: done}}, nil
	case "snmp":
		c, err := newSNMP(h, cfg, secret)
		if err != nil {
			return nil, err
		}
		return &apiAdapter{apiCollector: apiCollector{src: c, close: c.Close}}, nil
	}
	return nil, fmt.Errorf("unbekannter Zugang %q", typ)
}

// newProm: Prometheus-Exporter (ohne Adresse: Host, Port 9100, /metrics); Bericht ueber den Mapper des Kerns.
func newProm(h *Host, cfg accessConfig, secret string) (*promscrape.Collector, error) {
	u := cfg.URL
	if u == "" {
		u = apiHostPort(h.Address, promscrape.DefaultPort)
	}
	return promscrape.New(promscrape.Config{URL: u, User: cfg.User, Secret: secret, Pin: cfg.Pin, Metrics: cfg.Metrics, Map: MapReport})
}

// deviceAPI: Sammler fuer NUT, TrueNAS, Unraid, Redfish, Proxmox Mail Gateway und mailcow (Collect und Test).
type deviceAPI interface {
	apiSource
	Test(ctx context.Context) apis.TestResult
}

// newDeviceAPI baut NUT/TrueNAS/Unraid/Redfish; done schliesst Verbindungen bzw. meldet die Redfish-Sitzung ab.
func newDeviceAPI(typ string, h *Host, cfg accessConfig, secret string) (deviceAPI, func(), error) {
	addr := cfg.URL
	switch typ {
	case "nut":
		if addr == "" {
			addr = apiHostPort(h.Address, 3493)
		}
		c, err := apis.NewNUT(apis.NUTConfig{Address: addr, UPS: splitAddrs(cfg.UPS), User: cfg.User, Password: secret, TLS: cfg.TLS, Pin: cfg.Pin})
		if err != nil {
			return nil, nil, err
		}
		return c, func() {}, nil
	case "truenas":
		if addr == "" {
			addr = "https://" + apiHostPort(h.Address, 443)
		}
		c, err := apis.NewTrueNAS(apis.TrueNASConfig{Address: addr, APIKey: secret, User: cfg.User, Pin: cfg.Pin, API: cfg.API})
		if err != nil {
			return nil, nil, err
		}
		return c, c.Close, nil
	case "unraid":
		if addr == "" {
			addr = "http://" + apiHostPort(h.Address, 80)
		}
		c, err := apis.NewUnraid(apis.UnraidConfig{Address: addr, APIKey: secret, Pin: cfg.Pin})
		if err != nil {
			return nil, nil, err
		}
		return c, c.Close, nil
	case "redfish":
		if addr == "" {
			addr = "https://" + apiHostPort(h.Address, 443)
		}
		c, err := apis.NewRedfish(apis.RedfishConfig{Address: addr, User: cfg.User, Password: secret, Pin: cfg.Pin, Session: cfg.Session})
		if err != nil {
			return nil, nil, err
		}
		return c, c.Close, nil
	case "pmg":
		if addr == "" {
			addr = "https://" + apiHostPort(h.Address, 8006)
		}
		c, err := apis.NewPMG(apis.PMGConfig{Address: addr, User: cfg.User, Password: secret, Pin: cfg.Pin})
		if err != nil {
			return nil, nil, err
		}
		return c, c.Close, nil
	case "mailcow":
		if addr == "" {
			addr = "https://" + apiHostPort(h.Address, 443)
		}
		c, err := apis.NewMailcow(apis.MailcowConfig{Address: addr, APIKey: secret, Pin: cfg.Pin})
		if err != nil {
			return nil, nil, err
		}
		return c, c.Close, nil
	case "fritzbox":
		if addr == "" {
			addr = "https://" + apiHostPort(h.Address, 49443)
		}
		c, err := apis.NewFritzbox(apis.FritzboxConfig{Address: addr, User: cfg.User, Password: secret, Pin: cfg.Pin})
		if err != nil {
			return nil, nil, err
		}
		return c, c.Close, nil
	case "mikrotik":
		if addr == "" {
			addr = "https://" + apiHostPort(h.Address, 443)
		}
		c, err := apis.NewMikrotik(apis.MikrotikConfig{Address: addr, User: cfg.User, Password: secret, Pin: cfg.Pin})
		if err != nil {
			return nil, nil, err
		}
		return c, c.Close, nil
	}
	return nil, nil, fmt.Errorf("unbekannter Zugang %q", typ)
}

// apiAdapter erfuellt das collector-Interface des Kerns.
type apiAdapter struct {
	apiCollector
	node     func() string // Proxmox VE ohne eingestellte Node: erkannte Node
	saveNode func(string)
	saved    bool
}

func (a *apiAdapter) collect(ctx context.Context) ([]model.Service, error) {
	svcs, err := a.apiCollector.collect(ctx)
	if !a.saved && a.saveNode != nil && len(svcs) > 0 {
		if n := a.node(); n != "" {
			a.saved = true
			a.saveNode(n)
		}
	}
	return svcs, err
}
func (a *apiAdapter) close() { a.closeFn() }

func splitAddrs(s string) []string {
	var out []string
	for _, a := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		if a != "" {
			out = append(out, a)
		}
	}
	return out
}
