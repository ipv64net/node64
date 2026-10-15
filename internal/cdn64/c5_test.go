package cdn64

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type fakeRecords struct {
	mu   sync.Mutex
	recs map[string][]Record // Domain -> Records
}

func (f *fakeRecords) Ready(context.Context) bool { return true }

func (f *fakeRecords) Domains(context.Context) ([]string, error) {
	return []string{"home.ipv64.de", "sub.home.ipv64.de"}, nil
}

func (f *fakeRecords) Records(_ context.Context, d string) ([]Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Record(nil), f.recs[d]...), nil
}

func (f *fakeRecords) Add(_ context.Context, d, typ, prefix, content string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recs[d] = append(f.recs[d], Record{Prefix: prefix, Type: typ, Content: content})
	return nil
}

func TestCreateDNSRecords(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	fr := &fakeRecords{recs: map[string][]Record{"home.ipv64.de": {{Prefix: "nas", Type: "A", Content: "192.0.2.1"}}}}
	e.m.SetDNSRecords(fr)
	e.enable(t)
	res, err := e.m.createRecords(ctx, []string{"nas.home.ipv64.de", "cloud.home.ipv64.de", "home.ipv64.de", "x.sub.home.ipv64.de", "www.example.org"},
		DNSRequest{Type: "cname", Content: "Dyn.Home.ipv64.de."})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"nas.home.ipv64.de": "exists", "cloud.home.ipv64.de": "created", "home.ipv64.de": "apex_cname",
		"x.sub.home.ipv64.de": "created", "www.example.org": "not_ipv64"}
	for _, r := range res {
		if want[r.Name] != r.Result {
			t.Errorf("%s: %s (want %s) %s", r.Name, r.Result, want[r.Name], r.Error)
		}
	}
	got := fr.recs["home.ipv64.de"]
	if len(got) != 2 || got[1] != (Record{Prefix: "cloud", Type: "CNAME", Content: "dyn.home.ipv64.de"}) {
		t.Fatalf("records: %+v", got)
	}
	if sub := fr.recs["sub.home.ipv64.de"]; len(sub) != 1 || sub[0].Prefix != "x" {
		t.Fatalf("longest zone wins: %+v", fr.recs)
	}
	var fe *FieldError
	if _, err := e.m.createRecords(ctx, []string{"a.home.ipv64.de"}, DNSRequest{Type: "A", Content: "2001:db8::1"}); !errors.As(err, &fe) {
		t.Fatalf("A with IPv6: %v", err)
	}
	if _, err := e.m.createRecords(ctx, []string{"a.home.ipv64.de"}, DNSRequest{Type: "MX", Content: "x"}); !errors.As(err, &fe) {
		t.Fatalf("unknown type: %v", err)
	}
	// ueber die API beim Anlegen eines Hosts
	body := `{"names":["api.home.ipv64.de","home.ipv64.de"],"target_host":"127.0.0.1","target_port":9,"cert_id":-1,"create_dns_record":{"type":"AAAA","content":"2001:db8::5"}}`
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, httptest.NewRequest("POST", "/api/cdn64/hosts", strings.NewReader(body)))
	var out struct {
		ID         int64       `json:"id"`
		DNSRecords []DNSResult `json:"dns_records"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != 201 || out.ID == 0 || len(out.DNSRecords) != 2 || out.DNSRecords[0].Result != "created" || out.DNSRecords[1].Result != "created" {
		t.Fatalf("api: %d %s", rec.Code, rec.Body)
	}
}
