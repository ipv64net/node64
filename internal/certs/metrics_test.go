package certs

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/metrics"
)

// Kennzahlen: Ablauf, Zustand, Fehler und Erneuerung je Zertifikat.
func TestMetrics(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	certPEM, keyPEM := selfSignedPEM(t, 30, "metrics.example.org")
	c, err := e.m.Upload(ctx, certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	w := metrics.New()
	e.m.Metrics(ctx, w)
	var sb strings.Builder
	_, _ = w.WriteTo(&sb)
	out := sb.String()
	l := `cert_id="` + strconv.FormatInt(c.ID, 10) + `",name="metrics.example.org",source="upload"`
	for _, want := range []string{
		"node64_certs 1",
		`node64_cert_status{` + l + `,status="` + c.Status + `"} 1`,
		`node64_cert_error{` + l + `} 0`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}
