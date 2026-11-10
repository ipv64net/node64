package main

import (
	"fmt"
	"strings"
)

// Reine Logik fuer install unter FreeBSD (ohne Build-Tag, damit die Tests auf jedem System laufen; die Schritte
// selbst stehen in install_freebsd.go).

// Plattformen, die install unterscheidet.
const (
	bsdPlain    = "freebsd"
	bsdOPNsense = "opnsense"
	bsdPfSense  = "pfsense"
	bsdTrueNAS  = "truenas"
)

// Ablage des Dienstes. Der Schalter steht auf allen Plattformen in einer eigenen Datei unter /etc/rc.conf.d: rc.subr
// liest sie selbst (auch dort, wo /etc/rc.conf nicht ausgewertet wird), OPNsense zusaetzlich beim Hochfahren
// (rc.freebsd), und uninstall muss keine gemeinsame Datei bearbeiten.
const (
	bsdRCName = "monitor64_agent"
	bsdRCDir  = "/usr/local/etc/rc.d"
	bsdRCConf = "/etc/rc.conf.d/" + bsdRCName
)

// bsdFlavor ordnet die erkannte Plattform (m64bsd.DetectPlatform, z. B. "OPNsense 25.1.5", "pfSense 2.7.2-RELEASE",
// "TrueNAS-13.0-U6.1", "FreeBSD 14.3-RELEASE") einer der vier Arten zu. exists prueft zusaetzlich Dateien, die es
// nur auf den Firewalls gibt: sehen deren Versionsdateien einmal anders aus, wuerde der Dienst unter pfSense sonst
// ohne .sh angelegt und beim Hochfahren nicht gestartet.
func bsdFlavor(platform string, exists func(path string) bool) string {
	p := strings.ToLower(strings.TrimSpace(platform))
	switch {
	case strings.HasPrefix(p, "opnsense"):
		return bsdOPNsense
	case strings.HasPrefix(p, "pfsense"):
		return bsdPfSense
	case strings.HasPrefix(p, "truenas"), strings.HasPrefix(p, "freenas"):
		return bsdTrueNAS
	case exists("/etc/pfSense-rc"):
		return bsdPfSense
	case exists("/usr/local/etc/rc.freebsd") && exists("/usr/local/opnsense"):
		return bsdOPNsense
	}
	return bsdPlain
}

// bsdRCFile liefert den Pfad des rc.d-Skripts und den jeweils anderen Namen (wird bei install entfernt). pfSense
// startet beim Hochfahren nur Dateien, die auf .sh enden (/etc/rc.start_packages).
func bsdRCFile(flavor string) (file, other string) {
	plain, sh := bsdRCDir+"/"+bsdRCName, bsdRCDir+"/"+bsdRCName+".sh"
	if flavor == bsdPfSense {
		return sh, plain
	}
	return plain, sh
}

// bsdRCVars sind die Zeilen, die install in /etc/rc.conf.d/monitor64_agent setzt.
func bsdRCVars(port int, noListen bool) [][2]string {
	nl := "NO"
	if noListen {
		nl = "YES"
	}
	return [][2]string{{bsdRCName + "_enable", "YES"}, {bsdRCName + "_port", fmt.Sprint(port)}, {bsdRCName + "_nolisten", nl}}
}

// setRCVars setzt Werte in einer rc.conf-Datei: vorhandene Zeilen dieser Namen fallen weg, die neuen stehen am
// Ende; alles andere (z. B. von Hand eingetragenes monitor64_agent_args) bleibt. Die Werte hier sind nur YES/NO und
// Zahlen, brauchen also keine Maskierung.
func setRCVars(old string, vars [][2]string) string {
	var out []string
	for _, line := range strings.Split(strings.ReplaceAll(old, "\r", ""), "\n") {
		name, _, ok := strings.Cut(strings.TrimSpace(line), "=")
		drop := false
		for _, v := range vars {
			if ok && name == v[0] {
				drop = true
			}
		}
		if !drop {
			out = append(out, line)
		}
	}
	for len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
		out = out[:len(out)-1]
	}
	for _, v := range vars {
		out = append(out, v[0]+`="`+v[1]+`"`)
	}
	return strings.Join(out, "\n") + "\n"
}

// bsdHints sind die Hinweise nach install: was der Benutzer selbst tun muss (Firewall) bzw. wissen sollte
// (Verhalten der Plattform bei Neustart und Updates). rcFile ist das angelegte rc.d-Skript.
func bsdHints(flavor string, port int, noListen bool, rcFile string) []string {
	var h []string
	if !noListen {
		switch flavor {
		case bsdOPNsense, bsdPfSense:
			h = append(h, fmt.Sprintf("firewall: allow TCP port %d from the address of your Node64 to this firewall "+
				"(Firewall > Rules, on the interface the node is reached through) - the installer does not change rules", port))
		case bsdPlain:
			h = append(h, fmt.Sprintf("if a packet filter (pf, ipfw) is active, allow TCP port %d from the address of your Node64", port))
		}
	}
	switch flavor {
	case bsdOPNsense:
		h = append(h, "OPNsense: the agent is not part of the firmware. Its files are normally kept by updates; "+
			"if it is missing after a major upgrade, run the installer again")
	case bsdPfSense:
		h = append(h, "pfSense: started at boot through "+rcFile+" (pfSense only starts files ending in .sh). "+
			"If the agent is missing after an upgrade, run the installer again")
	case bsdTrueNAS:
		h = append(h, "TrueNAS CORE: a system update can remove files outside the pools, and own services are not "+
			"always started at boot. Add a task under Tasks > Init/Shutdown Scripts (Type: Command, When: Post Init): "+
			"service "+bsdRCName+" onestart",
			"TrueNAS CORE: if the agent does not answer after an update, run the installer again (if the settings "+
				"are gone too, Node64 asks you to confirm the new host key)")
	}
	return h
}
