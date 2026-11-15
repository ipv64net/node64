package environment

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// Status-Cache: frisch aus dem Speicher, aelter im Hintergrund neu gefragt, sehr alt oder nach Aendern der Node neu.
func TestCachedStatus(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"status":"ok","version":"1.7.2"}`))
	}))
	defer srv.Close()
	now := time.Now()
	fc := &fakeCluster{areas: map[string]bool{}}
	s := New(fc.deps(testStore(t), &now))
	ctx := context.Background()
	n, err := s.AddNode(ctx, NodeInput{URL: srv.URL}, "")
	if err != nil {
		t.Fatal(err)
	}
	if st := s.CachedStatus(ctx, n); !st.Online || st.Version != "1.7.2" || hits.Load() != 1 {
		t.Fatalf("first: %+v %d", st, hits.Load())
	}
	now = now.Add(10 * time.Second)
	s.CachedStatus(ctx, n)
	if hits.Load() != 1 {
		t.Fatal("fresh status fetched again")
	}
	now = now.Add(time.Minute) // alt: sofort der gemerkte Stand, im Hintergrund neu
	if st := s.CachedStatus(ctx, n); !st.Online {
		t.Fatal("stale status not returned")
	}
	for i := 0; i < 100 && hits.Load() < 2; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if hits.Load() != 2 {
		t.Fatalf("no background refresh: %d", hits.Load())
	}
	n.UpdatedAt = n.UpdatedAt.Add(time.Second) // Node geaendert: neu fragen
	s.CachedStatus(ctx, n)
	if hits.Load() != 3 {
		t.Fatalf("changed node not fetched: %d", hits.Load())
	}
	now = now.Add(time.Hour)
	s.CachedStatus(ctx, n)
	if hits.Load() != 4 {
		t.Fatalf("old status not fetched: %d", hits.Load())
	}
}
