package cdn64

import (
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/edge"
)

// Docker-Bridge-Netz ohne veroeffentlichte Ports: die Host-Liste warnt mit fertigen Angaben fuer docker run.
func TestHostsPublishedWarning(t *testing.T) {
	pub := edge.Published{Bridge: true, Gateway: "172.17.0.1", H3Port: 443,
		Missing: []edge.ListenerStatus{{Name: "http", Port: 80}, {Name: "https", Port: 443}}}
	body := renderHosts(t, listData{Kind: KindProxy, Pub: pub})
	for _, want := range []string{"cdn64.pub_missing", `value="-p 80:80 -p 443:443 -p 443:443/udp"`, `href="/settings/ports#published"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("page misses %q", want)
		}
	}
	if body := renderHosts(t, listData{Kind: KindProxy, Pub: edge.Published{Bridge: true}}); strings.Contains(body, "cdn64.pub_missing") {
		t.Fatal("warning without missing ports")
	}
}
