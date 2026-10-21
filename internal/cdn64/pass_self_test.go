package cdn64

import (
	"context"
	"errors"
	"testing"

	"github.com/ipv64net/node64/internal/ports"
)

// Durchreichen auf die eigene Oberflaeche wird abgelehnt (Fremde saehen sonst wie das Heimnetz aus), andere Ziele
// und andere Ports gehen.
func TestPassthroughToOwnUIRefused(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	reg := ports.New()
	reg.Provide("web", func(context.Context) []ports.Claim {
		return []ports.Claim{{Purpose: "HTTPS", Proto: ports.TCP, Port: 8443, Active: true}}
	})
	e.m.SetPorts(reg)
	e.enable(t)
	for i, x := range []struct {
		host string
		port int
		bad  bool
	}{{"127.0.0.1", 8443, true}, {"localhost", 8443, true}, {"::1", 8443, true}, {"127.0.0.1", 9443, false}, {"192.0.2.10", 8443, false}} {
		h := newHostKind(KindPass)
		h.Names, h.TargetHost, h.TargetPort = []string{"pass" + string(rune('a'+i)) + ".test"}, x.host, x.port
		err := e.m.saveHost(ctx, h)
		var fe *FieldError
		if got := errors.As(err, &fe) && fe.Key == "cdn64.err.pass_self"; got != x.bad || (!x.bad && err != nil) {
			t.Fatalf("%s:%d: err=%v", x.host, x.port, err)
		}
	}
}
