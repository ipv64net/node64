package main

import (
	"io"
	"path/filepath"
	"testing"
)

func TestParseRunFlags(t *testing.T) {
	f, err := parseRunFlags([]string{"--port", "16465", "--dir", "/tmp/m64"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if f.port != 16465 || f.keys != filepath.Join("/tmp/m64", "keys") || f.hostKey != filepath.Join("/tmp/m64", "hostkey") ||
		f.localDir != filepath.Join("/tmp/m64", "local.d") {
		t.Fatalf("flags = %+v", f)
	}
	for _, bad := range [][]string{{"--port", "0"}, {"--port", "70000"}, {"extra"}, {"--unknown"}} {
		if _, err := parseRunFlags(bad, io.Discard); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}
