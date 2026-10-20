package hpbridge

import (
	"net/http"
	"net/netip"
	"testing"
)

func TestBridge(t *testing.T) {
	if Decoy() != nil || AccessActive() {
		t.Fatal("not empty at start")
	}
	SetDecoy(http.NotFoundHandler())
	if Decoy() == nil {
		t.Fatal("decoy missing")
	}
	SetDecoy(nil)
	var got []Access
	SetAccessSink(func(a Access) { got = append(got, a) })
	Report(Access{Path: "/x"})
	SetAccessSink(nil)
	Report(Access{Path: "/y"})
	if len(got) != 1 || got[0].Path != "/x" {
		t.Fatalf("access: %+v", got)
	}
	var blocks []Block
	cancel := SubscribeBlocks(func(b Block) { blocks = append(blocks, b) })
	PublishBlock(Block{IP: netip.MustParseAddr("192.0.2.1")})
	cancel()
	PublishBlock(Block{IP: netip.MustParseAddr("192.0.2.2")})
	if len(blocks) != 1 {
		t.Fatalf("blocks: %+v", blocks)
	}
}
