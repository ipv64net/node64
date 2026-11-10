package m64bsd

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/m64proto"
)

// netstatArgs: Schnittstellen-Zaehler mit Bytes (-b), ohne Namensaufloesung (-n), als JSON (libxo).
var netstatArgs = []string{"-i", "-b", "-n", "--libxo", "json"}

// flexNum ist eine Zahl aus libxo-JSON (als Zahl oder als Text, z. B. "0x8843"); unlesbar = 0.
type flexNum uint64

func (n *flexNum) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	var v uint64
	var err error
	if strings.HasPrefix(s, "0x") {
		v, err = strconv.ParseUint(s[2:], 16, 64)
	} else {
		v, err = strconv.ParseUint(s, 10, 64)
	}
	if err != nil {
		v = 0
	}
	*n = flexNum(v)
	return nil
}

// netstatIf ist ein Eintrag aus "netstat -i --libxo json" (eine Zeile je Adresse; Zaehler nur aus <Link#N>).
type netstatIf struct {
	Name      string   `json:"name"`
	MTU       flexNum  `json:"mtu"`
	Network   string   `json:"network"`
	Address   string   `json:"address"`
	RxPackets *flexNum `json:"received-packets"`
	RxErrors  flexNum  `json:"received-errors"`
	RxDropped flexNum  `json:"dropped-packets"`
	RxBytes   *flexNum `json:"received-bytes"`
	TxPackets flexNum  `json:"sent-packets"`
	TxErrors  flexNum  `json:"send-errors"`
	TxBytes   flexNum  `json:"sent-bytes"`
}

// ParseNetstatJSON liest "netstat -i -b -n --libxo json" ({"statistics":{"interface":[...]}}). Nur Link-Eintraege
// zaehlen; ein "*" am Namen (Schnittstelle abgeschaltet) faellt weg, admin-down meldet down=true.
func ParseNetstatJSON(b []byte) (ifs []m64proto.NetIf, down map[string]bool, err error) {
	var v struct {
		Statistics struct {
			Interface []netstatIf `json:"interface"`
		} `json:"statistics"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(b), &v); err != nil {
		return nil, nil, err
	}
	seen := map[string]bool{}
	down = map[string]bool{}
	counted := false
	for _, e := range v.Statistics.Interface {
		if !strings.HasPrefix(e.Network, "<Link#") {
			continue
		}
		name := strings.TrimSuffix(e.Name, "*")
		if !validIfName(name) || seen[name] {
			continue
		}
		if e.RxPackets != nil || e.RxBytes != nil {
			counted = true
		}
		seen[name] = true
		if name != e.Name {
			down[name] = true
		}
		if strings.HasPrefix(name, "lo") && isDigits(name[2:]) {
			continue
		}
		n := m64proto.NetIf{Name: name, RxErrors: uint64(e.RxErrors), RxDropped: uint64(e.RxDropped),
			TxPackets: uint64(e.TxPackets), TxErrors: uint64(e.TxErrors), TxBytes: uint64(e.TxBytes)}
		if e.RxPackets != nil {
			n.RxPackets = uint64(*e.RxPackets)
		}
		if e.RxBytes != nil {
			n.RxBytes = uint64(*e.RxBytes)
		}
		if e.MTU > 0 && e.MTU < 1<<20 {
			n.MTU = int(e.MTU)
		}
		if macRE.MatchString(e.Address) {
			n.MAC = e.Address
		}
		ifs = append(ifs, n)
		if len(ifs) >= maxItems {
			break
		}
	}
	if len(seen) > 0 && !counted { // Schluessel anders als erwartet: lieber Fehler als lauter Nullen
		return nil, nil, errFormat
	}
	return ifs, down, nil
}

var (
	ifNameRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.\-]{0,31}$`)
	macRE    = regexp.MustCompile(`^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$`)
	// Kopfzeile von ifconfig: "igb0: flags=8843<UP,BROADCAST,...> metric 0 mtu 1500" (bzw. "enc0: flags=0 metric 0 mtu 1536")
	ifcHeadRE = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9_.\-]{0,31}): flags=[0-9a-fA-F]+(?:<([^>]*)>)?(?:.*\bmtu (\d+))?`)
	// Medium-Untertyp: 1000baseT, 10Gbase-T, 2500Base-T, 25GBase-SR, 100baseTX, 10baseT/UTP
	mediaSpeedRE = regexp.MustCompile(`(?i)^(\d+)(g?)base`)
	// laggport: igb2 flags=1c<ACTIVE,COLLECTING,DISTRIBUTING>
	laggPortRE = regexp.MustCompile(`^laggport: (\S+) flags=[0-9a-fA-F]+<([^>]*)>`)
	// member: igb3 flags=143<LEARNING,DISCOVER,AUTOEDGE,AUTOPTP>
	bridgeMemberRE = regexp.MustCompile(`^member: (\S+) flags=`)
)

func validIfName(s string) bool { return ifNameRE.MatchString(s) }

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// IfConfig sind die Angaben aus "ifconfig -a" zu einer Schnittstelle.
type IfConfig struct {
	Name      string
	Flags     []string // UP, RUNNING, ...
	MTU       int
	MAC       string
	Status    string // "active", "no carrier", "associated" ... ("" = keine Zeile)
	HasMedia  bool
	SpeedMbit int
	Duplex    string
	Groups    []string
	VLAN      bool
	LaggProto string     // lacp, failover, loadbalance, roundrobin, broadcast, none
	LaggPorts []LaggPort // Mitglieder eines lagg
	Members   []string   // Mitglieder einer bridge
}

// LaggPort ist ein Mitglied eines lagg.
type LaggPort struct {
	Name  string
	Flags []string // ACTIVE, COLLECTING, DISTRIBUTING, MASTER ...
}

func hasWord(l []string, w string) bool {
	for _, s := range l {
		if s == w {
			return true
		}
	}
	return false
}

// ParseIfconfig liest "ifconfig -a" (Kopfzeile je Schnittstelle, Eigenschaften eingerueckt).
func ParseIfconfig(b []byte) []IfConfig {
	var out []IfConfig
	var cur *IfConfig
	for _, ln := range lines(b) {
		if ln == "" {
			continue
		}
		if ln[0] != '\t' && ln[0] != ' ' {
			cur = nil
			m := ifcHeadRE.FindStringSubmatch(ln)
			if m == nil || len(out) >= maxItems {
				continue
			}
			c := IfConfig{Name: m[1]}
			if m[2] != "" {
				c.Flags = strings.Split(m[2], ",")
			}
			if v, err := strconv.Atoi(m[3]); err == nil && v > 0 && v < 1<<20 {
				c.MTU = v
			}
			out = append(out, c)
			cur = &out[len(out)-1]
			continue
		}
		if cur == nil {
			continue
		}
		t := strings.TrimSpace(ln)
		key, val, _ := strings.Cut(t, " ")
		switch key {
		case "ether":
			if f := strings.Fields(val); len(f) > 0 && macRE.MatchString(f[0]) && cur.MAC == "" {
				cur.MAC = f[0]
			}
		case "hwaddr": // Mitglied eines lagg: ether ist die Adresse des Verbunds, hwaddr die eigene
			if f := strings.Fields(val); len(f) > 0 && macRE.MatchString(f[0]) && f[0] != "00:00:00:00:00:00" {
				cur.MAC = f[0]
			}
		case "status:":
			cur.Status = clipN(val, 40)
		case "media:":
			cur.HasMedia = true
			cur.SpeedMbit, cur.Duplex = parseMedia(val)
		case "groups:":
			if len(cur.Groups) < 32 {
				cur.Groups = append(cur.Groups, strings.Fields(val)...)
			}
		case "vlan:":
			cur.VLAN = true
		case "laggproto":
			if f := strings.Fields(val); len(f) > 0 {
				cur.LaggProto = clipN(f[0], 20)
			}
		case "laggport:":
			if m := laggPortRE.FindStringSubmatch(t); m != nil && validIfName(m[1]) && len(cur.LaggPorts) < 64 {
				p := LaggPort{Name: m[1]}
				if m[2] != "" {
					p.Flags = strings.Split(m[2], ",")
				}
				cur.LaggPorts = append(cur.LaggPorts, p)
			}
		case "member:":
			if m := bridgeMemberRE.FindStringSubmatch(t); m != nil && validIfName(m[1]) && len(cur.Members) < 256 {
				cur.Members = append(cur.Members, m[1])
			}
		}
	}
	return out
}

// parseMedia liest Geschwindigkeit und Duplex aus "Ethernet autoselect (1000baseT <full-duplex>)" bzw.
// "Ethernet 10Gbase-T <full-duplex>". Ohne aktiven Untertyp (kein Link) 0.
func parseMedia(s string) (speed int, duplex string) {
	act := s
	if i := strings.IndexByte(s, '('); i >= 0 {
		act = strings.TrimSuffix(s[i+1:], ")")
	} else if f := strings.Fields(s); len(f) >= 2 {
		act = strings.Join(f[1:], " ") // fest eingestellt: "Ethernet 1000baseT <full-duplex>"
	}
	f := strings.Fields(act)
	if len(f) == 0 {
		return 0, ""
	}
	if m := mediaSpeedRE.FindStringSubmatch(f[0]); m != nil {
		if v, err := strconv.Atoi(m[1]); err == nil && v > 0 && v <= 1_000_000 {
			if m[2] != "" {
				v *= 1000
			}
			if v <= 10_000_000 {
				speed = v
			}
		}
	}
	switch {
	case strings.Contains(act, "full-duplex"):
		duplex = "full"
	case strings.Contains(act, "half-duplex"):
		duplex = "half"
	}
	return speed, duplex
}

// Namen virtueller Schnittstellen (Firewall-Log, Tunnel, VPN, Jails, PPP).
var virtualPrefixes = []string{"lo", "pflog", "pfsync", "enc", "tun", "tap", "ovpn", "wg", "gif", "gre", "ipsec",
	"epair", "vnet", "stf", "pppoe", "ppp", "l2tp", "pptp", "ng", "vxlan", "tailscale", "zt", "carp", "openvpn",
	"faith", "me", "usbus", "vm-"}

// virtualByName prueft den Namen gegen die Liste (Praefix plus Ziffer bzw. Ende, damit "me" nicht "mlxen0" trifft).
func virtualByName(name string) bool {
	for _, p := range virtualPrefixes {
		if !strings.HasPrefix(name, p) {
			continue
		}
		rest := name[len(p):]
		if rest == "" || (rest[0] >= '0' && rest[0] <= '9') || p == "vm-" || p == "ovpn" {
			return true
		}
	}
	return false
}

// ifKind bestimmt die Art: bond (lagg), bridge, vlan, virtual oder physical.
func ifKind(name string, c *IfConfig) string {
	if c != nil {
		switch {
		case c.LaggProto != "" || hasWord(c.Groups, "lagg"):
			return "bond"
		case hasWord(c.Groups, "bridge"):
			return "bridge"
		case c.VLAN || hasWord(c.Groups, "vlan"):
			return "vlan"
		}
	}
	switch {
	case strings.HasPrefix(name, "lagg") && isDigits(name[4:]):
		return "bond"
	case strings.HasPrefix(name, "bridge") && isDigits(name[6:]):
		return "bridge"
	case strings.HasPrefix(name, "vlan") && name != "vlan":
		return "vlan"
	case virtualByName(name):
		return "virtual"
	case c != nil && c.HasMedia:
		return "physical"
	case c == nil && strings.ContainsAny(name, "._"): // igb0.10, igb0_vlan10 (OPNsense)
		return "vlan"
	}
	return "virtual"
}

// ifUp: eingeschaltet (Flag UP) und Link vorhanden. Mit Statuszeile zaehlt sie (active, associated), sonst das
// Flag RUNNING. (netstat markiert abgeschaltete Schnittstellen nur in der Textausgabe mit "*".)
func ifUp(c *IfConfig) bool {
	if c == nil || !hasWord(c.Flags, "UP") {
		return false
	}
	if c.Status != "" {
		return c.Status == "active" || c.Status == "associated" || c.Status == "running"
	}
	return hasWord(c.Flags, "RUNNING")
}

// BuildNet verbindet Zaehler (netstat) und Zustand (ifconfig) zu Schnittstellen und lagg-Verbunden. Ohne ifconfig
// (Fehler) bleiben Zustand und Art aus dem Namen.
func BuildNet(counters []m64proto.NetIf, down map[string]bool, cfgs []IfConfig) ([]m64proto.NetIf, []m64proto.Bond) {
	byName := map[string]*IfConfig{}
	for i := range cfgs {
		byName[cfgs[i].Name] = &cfgs[i]
	}
	master := map[string]string{}
	for i := range cfgs {
		c := &cfgs[i]
		for _, p := range c.LaggPorts {
			master[p.Name] = c.Name
		}
		for _, m := range c.Members {
			if _, ok := master[m]; !ok {
				master[m] = c.Name
			}
		}
	}
	out := make([]m64proto.NetIf, 0, len(counters))
	for _, n := range counters {
		c := byName[n.Name]
		n.Kind = ifKind(n.Name, c)
		n.Master = master[n.Name]
		n.Up = ifUp(c) && !down[n.Name]
		if c != nil {
			if c.MTU > 0 {
				n.MTU = c.MTU
			}
			if c.MAC != "" {
				n.MAC = c.MAC
			}
			if n.Up {
				n.SpeedMbit, n.Duplex = c.SpeedMbit, c.Duplex
			}
		}
		out = append(out, n)
	}
	var bonds []m64proto.Bond
	for i := range cfgs {
		c := &cfgs[i]
		if c.LaggProto == "" || len(bonds) >= 64 {
			continue
		}
		b := m64proto.Bond{Name: c.Name, Mode: c.LaggProto, MII: "down", Members: []m64proto.BondSlave{}}
		lacp := c.LaggProto == "lacp"
		if lacp {
			b.Mode = "IEEE 802.3ad (lacp)"
		}
		if ifUp(c) {
			b.MII = "up"
		}
		for _, p := range c.LaggPorts {
			m := byName[p.Name]
			s := m64proto.BondSlave{Name: p.Name, MII: "down"}
			// Link des Mitglieds; bei LACP muss es zusaetzlich im Aggregat verteilen (sonst passt die Gegenstelle nicht)
			if ifUp(m) && (!lacp || hasWord(p.Flags, "DISTRIBUTING")) {
				s.MII = "up"
			}
			if m != nil && ifUp(m) {
				s.SpeedMbit = m.SpeedMbit
			}
			b.Members = append(b.Members, s)
		}
		bonds = append(bonds, b)
	}
	return out, bonds
}
