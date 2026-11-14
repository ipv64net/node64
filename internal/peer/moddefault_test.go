package peer

import (
	"context"
	"encoding/json"
	"testing"
)

type defaultProv struct{}

func (defaultProv) ClusterModule() ModuleInfo {
	return ModuleInfo{ID: "envtest", Default: true, Items: []ItemInfo{{ID: "login", Default: true}}}
}
func (defaultProv) ClusterIDs(context.Context, string) ([]string, error) { return nil, nil }
func (defaultProv) ClusterGet(context.Context, string, string) (json.RawMessage, bool, error) {
	return nil, false, nil
}
func (defaultProv) ClusterApply(context.Context, string, string, json.RawMessage, bool) error {
	return nil
}

// Modul mit Default: ohne Einstellung eingeschaltet (wie environment/login), ausschaltbar wie jedes Modul.
func TestModuleDefaultOn(t *testing.T) {
	ctx := context.Background()
	n := newNode(t, "node-a", "A", 522)
	n.m.RegisterProvider(defaultProv{})
	if !n.m.syncOn(ctx, "envtest", "login") {
		t.Fatal("module with Default is off")
	}
	if on, ok := n.m.switchValue(ctx, "envtest"); !ok || !on {
		t.Fatalf("switch value: %v %v", on, ok)
	}
	if _, err := n.m.setSyncLocal(ctx, "envtest", "", false); err != nil {
		t.Fatal(err)
	}
	if n.m.syncOn(ctx, "envtest", "login") {
		t.Fatal("module still on after switching it off")
	}
}
