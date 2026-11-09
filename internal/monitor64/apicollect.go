package monitor64

import (
	"context"
	"fmt"
	"strings"

	"github.com/ipv64net/node64/internal/monitor64/apis"
	"github.com/ipv64net/node64/internal/monitor64/model"
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

// newAPICollector baut den Sammler fuer Proxmox VE, PBS und Docker.
func newAPICollector(typ string, h *Host, cfg accessConfig, secret string) (collector, error) {
	addr := cfg.URL
	switch typ {
	case "pve":
		if addr == "" {
			addr = "https://" + hostPort(h.Address, 8006)
		}
		c, err := apis.NewPVE(apis.PVEConfig{Addresses: splitAddrs(addr), TokenID: cfg.TokenID, Secret: secret, Pin: cfg.Pin, Node: cfg.Node})
		if err != nil {
			return nil, err
		}
		return &apiAdapter{apiCollector{src: c}}, nil
	case "pbs":
		if addr == "" {
			addr = "https://" + hostPort(h.Address, 8007)
		}
		c, err := apis.NewPBS(apis.PBSConfig{Addresses: splitAddrs(addr), TokenID: cfg.TokenID, Secret: secret, Pin: cfg.Pin})
		if err != nil {
			return nil, err
		}
		return &apiAdapter{apiCollector{src: c}}, nil
	case "docker":
		c, err := apis.NewDocker(apis.DockerConfig{Host: addr, Pin: cfg.Pin, Secret: secret})
		if err != nil {
			return nil, err
		}
		return &apiAdapter{apiCollector{src: c, close: c.Close}}, nil
	}
	return nil, fmt.Errorf("unbekannter Zugang %q", typ)
}

// apiAdapter erfuellt das collector-Interface des Kerns.
type apiAdapter struct{ apiCollector }

func (a *apiAdapter) collect(ctx context.Context) ([]model.Service, error) {
	return a.apiCollector.collect(ctx)
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
