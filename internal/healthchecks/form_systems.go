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
// der Name des Docker-Hosts. Checks einer anderen Node laufen unter deren Namen (deren System-IDs gelten hier nicht).
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
		if c.Foreign() {
			for _, id := range c.Nodes {
				if n := peers[id]; n != "" {
					return m.g.T(r, "hc.sub.node", "name", n)
				}
			}
			return m.g.T(r, "hc.sub.other_node")
		}
		if c.Type == checks.TypeProxmox {
			var pp checks.ProxmoxParams
			_ = json.Unmarshal(c.Params, &pp)
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
