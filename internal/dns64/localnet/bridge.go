package localnet

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// Docker-Bridge-Netz: Die Node laeuft in einem Container mit eigenem Netz (nicht network_mode: host). Dann erreicht
// das Heimnetz einen Port nur, wenn er auf dem Docker-Host veroeffentlicht ist (-p 53:53/udp), und Docker kann
// Absender-Adressen durch die des Gateways ersetzen (Userland-Proxy, IPv6 ohne ip6tables, manche NAS-Systeme).

// Bridge meldet, ob die Node in einem Container im Bridge-Netz laeuft: Container-Datei vorhanden und nur virtuelle
// Schnittstellen (im Host-Netz sieht der Container die echten Netzwerkkarten des Hosts). Auch fuer andere Module
// (PROXY64): das Paket importiert nichts aus internal/dns64.
func Bridge() bool {
	return inBridge(fileExists("/.dockerenv") || fileExists("/run/.containerenv"), readIfaces("/sys/class/net"))
}

// Gateway: IPv4-Default-Gateway (im Bridge-Netz der Docker-Host, z. B. 172.17.0.1).
//
// Hairpin-Annahme fuer die Pruefung "auf dem Host veroeffentlicht?": Ein mit -p veroeffentlichter Port ist auch ueber
// das Gateway erreichbar und fuehrt zurueck in den Container (Docker-NAT bzw. docker-proxy auf 0.0.0.0). Eine Anfrage
// an Gateway:Port, die beim eigenen Dienst ankommt, heisst also: veroeffentlicht - unter derselben Portnummer. Ist der
// Port nur an eine bestimmte Host-Adresse gebunden (-p 192.168.1.5:53:53) oder auf eine andere Nummer gelegt, meldet die
// Pruefung ihn als fehlend.
func Gateway() netip.Addr { return defaultGateway() }

// iface: ifindex und iflink einer Schnittstelle (gleich = echte Schnittstelle, verschieden = veth-Paar).
type iface struct{ index, link string }

func inBridge(container bool, ifs map[string]iface) bool {
	if !container {
		return false
	}
	n := 0
	for name, x := range ifs {
		if name == "lo" {
			continue
		}
		if name == "docker0" || x.index == x.link { // Host-Netz: echte Karte bzw. Docker-Bruecke des Hosts sichtbar
			return false
		}
		n++
	}
	return n > 0
}

func readIfaces(dir string) map[string]iface {
	out := map[string]iface{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		idx, err1 := os.ReadFile(filepath.Join(dir, e.Name(), "ifindex"))
		link, err2 := os.ReadFile(filepath.Join(dir, e.Name(), "iflink"))
		if err1 == nil && err2 == nil {
			out[e.Name()] = iface{strings.TrimSpace(string(idx)), strings.TrimSpace(string(link))}
		}
	}
	return out
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// Probe schickt mit send einen Pruefnamen (z. B. ueber das Docker-Gateway an einen veroeffentlichten Port) und meldet,
// ob er beim eigenen DNS-Dienst ankam (SelfProbe). send kehrt nach der Antwort bzw. dem Fehler zurueck.
func (r *Resolver) Probe(ctx context.Context, send func(ctx context.Context, name string) error) bool {
	var nonce [8]byte
	_, _ = rand.Read(nonce[:])
	name := hex.EncodeToString(nonce[:]) + probeSuffix
	r.probes.Store(name, false)
	_ = send(ctx, name)
	v, _ := r.probes.LoadAndDelete(name)
	return v == true
}
