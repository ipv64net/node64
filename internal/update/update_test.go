package update

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewer(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"1.2.3", "1.2.2", true}, {"v1.3.0", "1.2.9", true}, {"1.2.3", "1.2.3", false}, {"1.2.3-dev", "1.2.3", false},
		{"2.0.0", "1.9.9", true}, {"0.4.0", "0.4.0-dev", false}, {"dev", "1.0.0", false}, {"1.0.0", "dev", false},
	}
	for _, c := range cases {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%q,%q)=%v want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("User-Agent"), "node64/") {
			w.WriteHeader(400)
			return
		}
		w.Write([]byte(`{"version":"0.5.0","url":"https://example.com/release","notes":"x"}`))
	}))
	defer srv.Close()
	c := New("0.4.0")
	c.URL = srv.URL
	info, err := c.Check(context.Background())
	if err != nil || !info.Newer || info.Version != "0.5.0" || info.URL == "" {
		t.Fatalf("check: %+v %v", info, err)
	}
	c.Current = "0.5.0"
	if info, _ := c.Check(context.Background()); info.Newer {
		t.Fatal("same version must not be newer")
	}
}
