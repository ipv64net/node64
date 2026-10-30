package healthchecks

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/proxmox"
)

// Neuer Check aus einem ueberwachten System: Im Formular stehen beim Typ zusaetzlich „Proxmox VE“ und „Docker“
// (Werte sys:proxmox, sys:docker). Danach waehlt man das System bzw. den Docker-Host und die Maschine bzw. den
// Container aus dem letzten Abruf; angelegt wird wie mit „Als Check fuehren“ (pveSetAsCheck: Kanaele der Regeln,
// Intervall der Abfrage, keine doppelte Meldung). Der rohe Typ docker steht bei neuen Checks nicht mehr zur Wahl.

const (
	sysTypePVE    = checks.Type("sys:proxmox")
	sysTypeDocker = checks.Type("sys:docker")
)

// sysPick ist ein System in der Auswahl mit seinen Maschinen bzw. Containern.
type sysPick struct {
	ID   int64
	Name string
	Res  []sysPickRes
}

type sysPickRes struct {
	Key, Name, TypeKey, Detail string
	Taken                      bool // schon als Check gefuehrt
}

// sysPicks: Proxmox-Systeme (docker=false) bzw. Docker-Hosts mit den Eintraegen des letzten Abrufs.
func (m *Module) sysPicks(ctx context.Context, docker bool) []sysPick {
	if m.pve == nil || m.pve.st == nil {
		return nil
	}
	list, err := m.pve.st.Systems(ctx)
	if err != nil {
		return nil
	}
	sort.Slice(list, func(i, j int) bool { return strings.ToLower(list[i].Name) < strings.ToLower(list[j].Name) })
	var out []sysPick
	for _, sys := range list {
		if sys.IsDocker() != docker {
			continue
		}
		p := sysPick{ID: sys.ID, Name: sys.Name}
		set, _ := m.pve.st.Settings(ctx, sys.ID)
		if s := m.pveLast(sys.ID); s != nil {
			for i := range s.Resources {
				res := &s.Resources[i]
				if res.Excluded() {
					continue
				}
				o := sysPickRes{Key: res.Key(), Name: res.Name, TypeKey: "pve.type." + res.Type}
				if res.Type == proxmox.TypeQEMU || res.Type == proxmox.TypeLXC {
					o.Detail = strconv.Itoa(res.VMID) + " · " + res.Node
				}
				if o.Name == "" {
					o.Name = o.Key
				}
				if set != nil {
					if it := set.Item(o.Key); it != nil && it.AsCheck && it.CheckToken != "" {
						o.Taken = true
					}
				}
				p.Res = append(p.Res, o)
			}
		}
		sort.SliceStable(p.Res, func(i, j int) bool { // Nodes zuerst, dann nach Name
			ni, nj := p.Res[i].TypeKey == "pve.type.node", p.Res[j].TypeKey == "pve.type.node"
			if ni != nj {
				return ni
			}
			return strings.ToLower(p.Res[i].Name) < strings.ToLower(p.Res[j].Name)
		})
		out = append(out, p)
	}
	return out
}

// formSystemCheck legt den Check fuer die gewaehlte Maschine bzw. den Container an (POST /healthchecks/new mit
// type=sys:proxmox bzw. sys:docker). Ein schon gefuehrter Eintrag fuehrt zu seinem Check.
func (m *Module) formSystemCheck(w http.ResponseWriter, r *http.Request, kind string) {
	ctx := r.Context()
	id, _ := strconv.ParseInt(r.PostFormValue("sys_id_"+kind), 10, 64)
	key := strings.TrimSpace(r.PostFormValue("sys_key_" + kind))
	sys, err := m.pve.st.System(ctx, id)
	if err == nil && sys.IsDocker() != (kind == "docker") {
		err = proxmox.ErrNotFound
	}
	if err == nil && (key == "" || !proxmox.ValidKey(key)) {
		err = errors.New(m.g.T(r, "hc.pick.err_res"))
	}
	var tok string
	if err == nil {
		err = m.pveSetAsCheckNamed(r, sys, key, true, strings.TrimSpace(r.PostFormValue("name")))
	}
	if err == nil {
		if set, serr := m.pve.st.Settings(ctx, sys.ID); serr == nil {
			if it := set.Item(key); it != nil {
				tok = it.CheckToken
			}
		}
	}
	if err != nil || tok == "" {
		if errors.Is(err, proxmox.ErrNotFound) {
			err = errors.New(m.g.T(r, "pve.not_found"))
		}
		var fe *proxmox.FieldError
		if errors.As(err, &fe) {
			err = errors.New(m.g.T(r, fe.Key))
		}
		if err == nil {
			err = errors.New(m.g.T(r, "hc.pick.err_res"))
		}
		_ = r.ParseForm()
		d := formData{Form: formDefaults(), Error: err.Error()}
		for k := range r.PostForm {
			d.Form[k] = r.PostFormValue(k)
		}
		m.formPage(w, r, http.StatusUnprocessableEntity, d)
		return
	}
	m.g.Flash(w, r, "success", m.g.T(r, "pve.check.added"))
	http.Redirect(w, r, "/healthchecks/"+tok, http.StatusSeeOther)
}

// subGroupOf liefert fuer die Liste je Check der Gruppen „Proxmox VE“ und „Docker“ die Untergruppe, jedes Mal frisch
// aus der Ueberwachung: bei Proxmox der Clustername aus dem letzten Abruf (sonst der Name des Systems), bei Docker
// der Name des Docker-Hosts. Checks einer anderen Node: Name des Systems aus ihren Parametern (Docker mit der Node),
// sonst die Node (deren System-IDs gelten hier nicht). Von Hand gesetzt (params.system_custom) gilt immer params.system.
func (m *Module) subGroupOf(ctx context.Context, r *http.Request) func(row) string {
	systems := map[int64]*proxmox.System{}
	byHost := map[string]*proxmox.System{}
	if m.pve != nil && m.pve.st != nil {
		if list, err := m.pve.st.Systems(ctx); err == nil {
			for _, s := range list {
				systems[s.ID] = s
				if s.IsDocker() {
					byHost[dockerSysHost(s)] = s
				}
			}
		}
	}
	peers := map[string]string{}
	for _, p := range m.peers(ctx) {
		peers[p.ID] = p.Name
	}
	pveName := map[int64]string{}
	return func(rw row) string {
		c := rw.Check
		if c == nil || (c.Type != checks.TypeProxmox && c.Type != checks.TypeDocker) {
			return ""
		}
		if c.Foreign() { // Name des Systems aus den Parametern (setzt die andere Node), sonst die Node
			var p struct {
				System       string `json:"system"`
				SystemCustom bool   `json:"system_custom"`
			}
			_ = json.Unmarshal(c.Params, &p)
			if p.SystemCustom && p.System != "" {
				return p.System
			}
			node := ""
			for _, id := range c.Nodes {
				if n := peers[id]; n != "" {
					node = n
					break
				}
			}
			switch {
			case p.System != "" && c.Type == checks.TypeProxmox:
				return p.System
			case p.System != "" && node != "":
				return p.System + " · " + node
			case p.System != "":
				return p.System
			case node != "":
				return m.g.T(r, "hc.sub.node", "name", node)
			}
			return m.g.T(r, "hc.sub.other_node")
		}
		if c.Type == checks.TypeProxmox {
			var pp checks.ProxmoxParams
			_ = json.Unmarshal(c.Params, &pp)
			if pp.SystemCustom && pp.System != "" { // Untergruppe von Hand gesetzt
				return pp.System
			}
			if n, ok := pveName[pp.SystemID]; ok {
				return n
			}
			n := m.g.T(r, "hc.sub.unknown")
			if sys := systems[pp.SystemID]; sys != nil && !sys.IsDocker() {
				n = sys.Name
				if s := m.pveLast(sys.ID); s != nil && s.Cluster != "" {
					n = s.Cluster
				}
			}
			pveName[pp.SystemID] = n
			return n
		}
		var dp checks.DockerParams
		_ = json.Unmarshal(c.Params, &dp)
		if dp.SystemCustom && dp.System != "" {
			return dp.System
		}
		h := strings.TrimSpace(dp.Host)
		if h == "" {
			h = checks.DefaultDockerHost()
		}
		if sys := byHost[h]; sys != nil {
			return sys.Name
		}
		if h == checks.DefaultDockerHost() {
			return m.g.T(r, "docker.local")
		}
		return h
	}
}

// sysLabel: von Hand gesetzte Untergruppe eines Proxmox- bzw. Docker-Checks (getrimmt, hoechstens 100 Zeichen).
func sysLabel(s string) string {
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > 100 {
		s = strings.TrimSpace(string(r[:100]))
	}
	return s
}

// checkSystemOf: Name des Proxmox-Systems bzw. Docker-Hosts aus den Parametern eines Checks (params.system, "" = keiner).
func checkSystemOf(c *Check) string {
	if c == nil || (c.Type != checks.TypeProxmox && c.Type != checks.TypeDocker) {
		return ""
	}
	var p struct {
		System string `json:"system"`
	}
	_ = json.Unmarshal(c.Params, &p)
	return strings.TrimSpace(p.System)
}

// statusGroupName: Gruppe eines Checks auf Statusseiten; in „Proxmox VE“ und „Docker“ mit dem Namen des Systems.
func statusGroupName(c *Check) string {
	g := strings.TrimSpace(c.Group)
	if sys := checkSystemOf(c); sys != "" && sys != g && (g == pveCheckGroup || g == dockerCheckGroup) {
		return g + " · " + sys
	}
	return g
}

// sysChan: Kanaele eines Checks „als Check“ (Proxmox VE bzw. Docker). Sie kommen aus den Regeln des Systems und
// werden dort gesetzt; das Check-Formular zeigt sie nur an.
type sysChan struct {
	Path, System, Item string
	Docker             bool
	Names              []string // wirksame Kanaele
	Default            bool     // keine Auswahl in den Regeln: Standardkanaele
}

// sysChanOf liefert die Kanaele, wenn token ein Check „als Check“ eines Systems ist (sonst nil).
func (m *Module) sysChanOf(ctx context.Context, token string) *sysChan {
	if m.pve == nil || m.pve.st == nil || token == "" {
		return nil
	}
	list, err := m.pve.st.Systems(ctx)
	if err != nil {
		return nil
	}
	for _, sys := range list {
		set, err := m.pve.st.Settings(ctx, sys.ID)
		if err != nil {
			continue
		}
		for key, it := range set.Items {
			if !it.AsCheck || it.CheckToken != token {
				continue
			}
			sc := &sysChan{Path: pveResPath(sys.ID, key), System: sys.Name, Item: m.pveResName(sys.ID, key), Docker: sys.IsDocker()}
			ids := m.pveChannels(ctx, set.Effective(key, m.pveNodeOf(sys.ID, key)).Channels)
			sc.Default = len(ids) == 0
			want := map[int64]bool{}
			for _, id := range ids {
				want[id] = true
			}
			if chans, err := m.channels(ctx); err == nil {
				for _, ch := range chans {
					if want[ch.ID] || (sc.Default && ch.Default) {
						sc.Names = append(sc.Names, ch.Name)
					}
				}
			}
			return sc
		}
	}
	return nil
}
