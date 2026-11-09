package m64linux

import (
	"strings"

	"github.com/ipv64net/node64/internal/m64proto"
)

// ParseNetDev liest /proc/net/dev (ohne lo).
func ParseNetDev(b []byte) []m64proto.NetIf {
	var out []m64proto.NetIf
	seen := map[string]bool{}
	for _, ln := range lines(b) {
		name, rest, ok := strings.Cut(ln, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		f := strings.Fields(rest)
		if name == "" || name == "lo" || len(f) < 16 || seen[name] || strings.ContainsAny(name, " /") {
			continue
		}
		seen[name] = true
		out = append(out, m64proto.NetIf{
			Name:      name,
			RxBytes:   u64(f[0]),
			RxPackets: u64(f[1]),
			RxErrors:  u64(f[2]),
			RxDropped: u64(f[3]),
			TxBytes:   u64(f[8]),
			TxPackets: u64(f[9]),
			TxErrors:  u64(f[10]),
			TxDropped: u64(f[11]),
		})
		if len(out) >= maxItems {
			break
		}
	}
	return out
}

// Namen virtueller Schnittstellen (Docker, Proxmox-Firewall, VMs, Tunnel).
var virtualPrefixes = []string{"veth", "docker", "br-", "tap", "fwbr", "fwpr", "fwln", "virbr", "vnet", "tun",
	"lxc", "cali", "flannel", "cni", "vxlan", "kube-", "dummy", "ifb", "zt", "tailscale", "wg"}

// netKind bestimmt die Art einer Schnittstelle: virtual, bond, bridge, vlan oder physical.
func netKind(src source, name string) string {
	for _, p := range virtualPrefixes {
		if strings.HasPrefix(name, p) {
			return "virtual"
		}
	}
	base := "/sys/class/net/" + name
	switch {
	case src.Exists(base + "/bonding"):
		return "bond"
	case src.Exists(base + "/bridge"):
		return "bridge"
	}
	if b, err := src.ReadFile(base + "/uevent"); err == nil {
		for _, ln := range lines(b) {
			if ln == "DEVTYPE=vlan" {
				return "vlan"
			}
		}
	}
	if src.Exists(base + "/device") {
		return "physical"
	}
	return "virtual"
}

// netSysInfo ergaenzt Zustand, Geschwindigkeit, MAC, MTU, Master und CRC-Fehler aus /sys/class/net/<if>.
func netSysInfo(src source, n *m64proto.NetIf) {
	base := "/sys/class/net/" + n.Name
	n.Kind = netKind(src, n.Name)
	n.Master = linkBase(src, base+"/master")
	switch readStr(src, base+"/operstate") {
	case "up":
		n.Up = true
	case "unknown": // manche Treiber (tun, ppp, USB) melden keinen Zustand; dann zaehlt carrier
		n.Up = readStr(src, base+"/carrier") == "1"
	}
	if v, ok := readInt(src, base+"/speed"); ok && v > 0 && v < 10_000_000 {
		n.SpeedMbit = int(v)
	}
	if d := readStr(src, base+"/duplex"); d == "full" || d == "half" {
		n.Duplex = d
	}
	if mac := readStr(src, base+"/address"); len(mac) <= 64 {
		n.MAC = clip(mac)
	}
	if v, ok := readInt(src, base+"/mtu"); ok && v > 0 && v < 1<<20 {
		n.MTU = int(v)
	}
	// rx_crc_errors ist ein Teil von rx_errors (Kernel: "part of aggregate frame errors in rx_errors"): RxCRC
	// zeigt nur die Art, RxErrors enthaelt die CRC-Fehler schon - nicht zusammenzaehlen. Drops sind keine Fehler.
	if v, ok := readInt(src, base+"/statistics/rx_crc_errors"); ok && v > 0 {
		n.RxCRC = uint64(v)
	}
}

// readNet liest die Netzwerkschnittstellen.
func readNet(src source) ([]m64proto.NetIf, error) {
	b, err := src.ReadFile("/proc/net/dev")
	if err != nil {
		return nil, err
	}
	ns := ParseNetDev(b)
	for i := range ns {
		netSysInfo(src, &ns[i])
	}
	return ns, nil
}
