package privdrop

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestSocketGroups(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "docker.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Skip("unix socket:", err)
	}
	defer l.Close()
	env := func(v string) func(string) string {
		return func(k string) string {
			if k == "NODE64_DOCKER_HOST" {
				return v
			}
			return ""
		}
	}
	if err := os.Chmod(sock, 0o660); err != nil {
		t.Fatal(err)
	}
	if g := socketGroups(env("unix://"+sock), os.Stat); len(g) != 1 || g[0] != os.Getgid() {
		t.Fatalf("groups %v, want [%d]", g, os.Getgid())
	}
	if err := os.Chmod(sock, 0o600); err != nil {
		t.Fatal(err)
	}
	if g := socketGroups(env("unix://"+sock), os.Stat); g != nil {
		t.Fatalf("owner-only socket: %v", g)
	}
	if g := socketGroups(env("tcp://socket-proxy:2375"), os.Stat); g != nil {
		t.Fatalf("tcp: %v", g)
	}
	if g := socketGroups(env("unix://"+sock+".missing"), os.Stat); g != nil {
		t.Fatalf("missing: %v", g)
	}
	file := filepath.Join(t.TempDir(), "plain")
	_ = os.WriteFile(file, nil, 0o660)
	if g := socketGroups(env("unix://"+file), os.Stat); g != nil {
		t.Fatalf("no socket: %v", g)
	}
}
