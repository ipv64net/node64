package ipv64api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRecordWrites(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer k" {
			w.WriteHeader(401)
			return
		}
		body, _ := io.ReadAll(r.Body)
		got = append(got, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery+" "+string(body))
		if r.Method == http.MethodPost {
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"id": 7, "type": "TXT", "prefix": "_acme-challenge.dns", "content": "abc"}})
			return
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "test")
	rec, err := c.AddRecord(context.Background(), "k", "home.ipv64.net", "TXT", "_acme-challenge.dns", "abc")
	if err != nil || rec.ID != 7 {
		t.Fatalf("add: %v %+v", err, rec)
	}
	if err := c.DeleteRecordByContent(context.Background(), "k", "home.ipv64.net", "TXT", "_acme-challenge.dns", "abc"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		`POST /domains/home.ipv64.net/records? {"content":"abc","prefix":"_acme-challenge.dns","type":"TXT"}`,
		`DELETE /domains/home.ipv64.net/records?content=abc&prefix=_acme-challenge.dns&type=TXT `,
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("request %d:\n got %s\nwant %s", i, got[i], want[i])
		}
	}
}
