package m64linux

import (
	"strings"
	"testing"
)

// Issue #97: Mit ProtectSystem=strict sieht der Dienst fast alles "ro"; ob ein Dateisystem wirklich nur lesbar
// ist, sagt die Mount-Liste von PID 1.
func TestHostReadOnly(t *testing.T) {
	own := ParseMounts([]byte("/dev/sda2 / ext4 ro,nosuid,relatime 0 0\n" +
		"/dev/sdb1 /mnt/backup ext4 ro,nosuid,noatime 0 0\n" +
		"/dev/sr0 /media/cdrom iso9660 ro,relatime 0 0\n" +
		"tmpfs /tmp tmpfs rw,nosuid 0 0\n" +
		"/dev/sda3 /var/lib/monitor64-agent ext4 rw,relatime 0 0\n"))
	host := ParseMounts([]byte("/dev/sda2 / ext4 rw,relatime 0 0\n" +
		"/dev/sdb1 /mnt/backup ext4 rw,noatime 0 0\n" +
		"/dev/sr0 /media/cdrom iso9660 ro,relatime 0 0\n" +
		"/dev/sdc1 /mnt/defekt ext4 rw 0 0\n/dev/sdc1 /mnt/defekt ext4 ro 0 0\n"))
	HostReadOnly(own, host)
	want := map[string]bool{"/": false, "/mnt/backup": false, "/media/cdrom": true, "/tmp": false, "/var/lib/monitor64-agent": false}
	for _, m := range own {
		if m.ReadOnly != want[m.Mount] {
			t.Errorf("%s: nur lesbar = %v", m.Mount, m.ReadOnly)
		}
	}
	// der letzte Eintrag je Mount-Punkt gilt (nach I/O-Fehlern nur lesbar neu eingehaengt)
	bad := ParseMounts([]byte("/dev/sdc1 /mnt/defekt ext4 rw 0 0\n"))
	HostReadOnly(bad, host)
	if !bad[0].ReadOnly {
		t.Error("/mnt/defekt muss nur lesbar sein")
	}
}

// Issue #96 (Kommentar): UGOS verweigert jedes Upgrade ueber apt – kein Fehler, sondern ein Hinweis.
func TestAptUpgradeLocked(t *testing.T) {
	ugos := "The 'upgrade' operation is not allowed.\nPlease do not perform upgrade, there is an irrecoverable disaster to the system, at your own risk.\n"
	if !AptUpgradeLocked([]byte(ugos)) {
		t.Error("UGOS-Meldung nicht erkannt")
	}
	for _, other := range []string{"", "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)", "Inst libc6 [2.36-9] (2.36-10 Debian)"} {
		if AptUpgradeLocked([]byte(other)) {
			t.Errorf("faelschlich erkannt: %q", other)
		}
	}
	if !strings.Contains(Script, `m64_note updates "{m64:upgrade_locked}"`) {
		t.Error("Skript meldet die Sperre nicht als Hinweis")
	}
}
