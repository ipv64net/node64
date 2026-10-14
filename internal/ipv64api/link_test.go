package ipv64api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLinkNode(t *testing.T) {
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/hc2/nodes/link" || r.Header.Get("Authorization") != "Bearer "+testKey {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		if got["code"] == "UNKNOWN1" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"status":404,"code":"code_unknown","detail":"Code unknown, expired or already used."}`)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"data":{"accepted":true}}`)
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "test")
	if err := c.LinkNode(context.Background(), testKey, "ABCD1234", "Keller", "full"); err != nil {
		t.Fatal(err)
	}
	if got["code"] != "ABCD1234" || got["location"] != "Keller" || got["remote_mgmt"] != "full" {
		t.Fatalf("body = %v", got)
	}
	if err := c.LinkNode(context.Background(), testKey, "UNKNOWN1", "", "full"); err == nil {
		t.Fatal("unknown code must fail")
	}
	if err := c.LinkNode(context.Background(), "wrong", "ABCD1234", "", "full"); err == nil {
		t.Fatal("wrong key must fail")
	}
}
