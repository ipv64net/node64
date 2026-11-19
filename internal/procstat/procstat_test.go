package procstat

import (
	"runtime"
	"testing"
)

func TestParseStat(t *testing.T) {
	// Prozessname mit Leerzeichen und Klammern; utime 1234, stime 766, 17 Threads, vsize 2 GiB, rss 5000 Seiten
	line := "4242 (node64 (test) x) S 1 4242 4242 0 -1 4194560 900 0 3 0 1234 766 0 0 20 0 17 0 123456 2147483648 5000 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0\n"
	st, ok := parseStat(line, 4096)
	if !ok {
		t.Fatal("nicht gelesen")
	}
	if st.CPUSeconds != 20 || st.Threads != 17 || st.VSize != 2147483648 || st.RSS != 5000*4096 {
		t.Fatalf("falsch gelesen: %+v", st)
	}
	for _, bad := range []string{"", "1 (x) S 1 2", "1 (x) S 1 4242 4242 0 -1 4194560 900 0 3 0 abc 766 0 0 20 0 17 0 123456 2147483648 5000 1"} {
		if _, ok := parseStat(bad, 4096); ok {
			t.Errorf("%q haette scheitern muessen", bad)
		}
	}
}

func TestParseLimit(t *testing.T) {
	if v, ok := parseLimit("536870912\n"); !ok || v != 536870912 {
		t.Fatalf("Grenze: %d %v", v, ok)
	}
	for _, none := range []string{"max\n", "", "9223372036854771712", "0", "x"} {
		if _, ok := parseLimit(none); ok {
			t.Errorf("%q ist keine Grenze", none)
		}
	}
}

func TestSelf(t *testing.T) {
	st, ok := Self()
	if runtime.GOOS != "linux" {
		if ok {
			t.Fatal("ausserhalb von Linux gibt es keine Werte")
		}
		return
	}
	if !ok || st.RSS == 0 || st.Threads < 1 || st.OpenFDs < 3 || st.MaxFDs == 0 {
		t.Fatalf("eigene Werte unplausibel: %+v %v", st, ok)
	}
	d, ok := DiskOf(t.TempDir())
	if !ok || d.Size == 0 || d.Free > d.Size {
		t.Fatalf("Speicherplatz unplausibel: %+v %v", d, ok)
	}
}
