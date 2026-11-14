package m64linux

import (
	"strings"
	"testing"
)

// #140: getrennte virtiofs-Mounts, zwei davon mit der Quelle "none" (Ausgabe von findmnt aus dem Issue). Sie sind
// verschiedene Dateisysteme und muessen einzeln bleiben – bisher fielen sie zusammen, der laengere Pfad fehlte und galt
// nach drei Runden als verschwunden. Bind-Mounts desselben Geraets bleiben weiterhin einer.
const virtiofsMounts = `shared-volume /mnt/shared-volume virtiofs rw,relatime 0 0
none /mnt/shared-volume/archive virtiofs rw,relatime 0 0
none /mnt/shared-volume/data virtiofs rw,relatime 0 0
/dev/sda1 / ext4 rw,relatime 0 0
/dev/sda1 /srv/bind ext4 rw,relatime 0 0
`

func vfsSet(t *testing.T, fs []string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, m := range fs {
		out[m] = true
	}
	return out
}

func TestVirtiofsNoneSeparate(t *testing.T) {
	want := []string{"/", "/mnt/shared-volume", "/mnt/shared-volume/archive", "/mnt/shared-volume/data"}
	check := func(name string, got []string) {
		t.Helper()
		m := vfsSet(t, got)
		for _, w := range want {
			if !m[w] {
				t.Errorf("%s: %s fehlt (gemeldet: %v)", name, w, got)
			}
		}
		if m["/srv/bind"] || len(got) != len(want) {
			t.Errorf("%s: Bind-Mount nicht zusammengefasst bzw. zu viele: %v", name, got)
		}
	}

	// Agent: /proc/mounts und statfs
	fsl, errs := FSFromStatfs(ParseMounts([]byte(virtiofsMounts)), func(p string) (StatFS, error) {
		return StatFS{Total: 100 << 30, Free: 40 << 30, Avail: 40 << 30}, nil
	})
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	var got []string
	for _, f := range fsl {
		got = append(got, f.Mount)
	}
	check("Agent", got)

	// SSH: df -PkT
	df := strings.Join([]string{
		"Filesystem     Type     1024-blocks     Used Available Capacity Mounted on",
		"shared-volume  virtiofs   104857600 62914560  41943040      60% /mnt/shared-volume",
		"none           virtiofs   104857600 62914560  41943040      60% /mnt/shared-volume/archive",
		"none           virtiofs   104857600 62914560  41943040      60% /mnt/shared-volume/data",
		"/dev/sda1      ext4        30832548 10240000  19000000      36% /",
		"/dev/sda1      ext4        30832548 10240000  19000000      36% /srv/bind",
	}, "\n")
	got = nil
	for _, f := range FSFromDF(ParseDF([]byte(df)), ParseMounts([]byte(virtiofsMounts)), nil) {
		got = append(got, f.Mount)
	}
	check("SSH", got)
}

// Generische Quellen: leer, "none", "nodev" und "-" taugen nicht als Kennung des Geraets; Namen wie "shfs" schon.
func TestGenericFSSource(t *testing.T) {
	for dev, want := range map[string]bool{
		"none": true, "": true, "nodev": true, "-": true, " NONE ": true,
		"shared-volume": false, "/dev/sda1": false, "tank/data": false, "shfs": false, "/mnt/disk1:/mnt/disk2": false,
	} {
		if got := genericFSSource(dev); got != want {
			t.Errorf("genericFSSource(%q) = %v", dev, got)
		}
	}
}
