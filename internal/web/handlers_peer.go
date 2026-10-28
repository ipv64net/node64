package web

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/certs"
	"github.com/ipv64net/node64/internal/peer"
)

// Seite "Cluster" (frueher lokale Gruppe auf der Seite "Healthchecks-Sync"): Code fuer eine weitere Node zeigen,
// einem Cluster beitreten, Nodes entfernen, Adresse aendern, ausgesetzte Nodes wieder aufnehmen, Cluster verlassen
// und je Modul und Bereich einschalten, was abgeglichen wird. Die Nodes selbst sprechen ueber /peer/ (peer-Paket).

type groupData struct {
	Available bool
	Account   int64 // 0 = ohne ipv64-Account (dann alle Nodes ohne)
	Members   []memberRow
	Code      string
	CodeExp   time.Time
	SelfURL   string // vorgeschlagene Adresse dieser Node fuer die anderen (HTTPS-Port, wenn an)
	Linked    bool   // diese Node ist mit ipv64 verknuepft
	Forwarder string // Node, die Aenderungen der Nodes ohne Sync an ipv64 weiterreicht ("" = keine)
	FwdSelf   bool   // das ist diese Node
	HTTPSPort int    // eigener HTTPS-Port, 0 = keiner (der HTTP-Port spricht auch TLS, dualport.go)
	Modules   []peer.ModuleState
	ACME      []acmeRow // verschiedene ACME-Konten im Cluster zur Wahl (leer = keine Abweichung)
}

// acmeRow ist ein ACME-Konto zur Wahl mit dem Namen der Node.
type acmeRow struct {
	certs.AccountChoice
	Name string
}

// memberRow ist ein Mitglied mit seinen Bereichen (Titel-Schluessel; Both: auch hier eingeschaltet).
type memberRow struct {
	peer.Member
	Areas  []memberArea
	NoSync bool // aeltere Version ohne Angabe der Bereiche
}

type memberArea struct {
	Key  string
	Both bool
}

func (s *Server) peerRoutes() {
	if s.Peer == nil {
		return
	}
	s.Peer.Register(s.mux)
	s.mux.Handle("GET /cluster", s.auth(s.clusterPage))
	s.mux.Handle("POST /cluster/code", s.auth(s.groupCode))
	s.mux.Handle("POST /cluster/join", s.auth(s.groupJoin))
	s.mux.Handle("POST /cluster/leave", s.auth(s.groupLeave))
	s.mux.Handle("POST /cluster/sync", s.auth(s.groupSync))
	s.mux.Handle("POST /cluster/{id}/remove", s.auth(s.groupRemove))
	s.mux.Handle("POST /cluster/{id}/url", s.auth(s.groupURL))
	s.mux.Handle("POST /cluster/{id}/resume", s.auth(s.groupResume))
	s.mux.Handle("POST /cluster/acme", s.auth(s.groupACME))
}

func (s *Server) clusterPage(w http.ResponseWriter, r *http.Request) {
	v := s.view(r, "cluster.title")
	v.Data = s.groupView(r)
	s.render(w, r, http.StatusOK, "cluster", v)
}

func (s *Server) groupView(r *http.Request) groupData {
	g := groupData{Available: s.Peer != nil, HTTPSPort: s.Cfg.HTTPSPort}
	if s.Peer == nil {
		return g
	}
	ctx := r.Context()
	g.Account = s.Peer.Account()
	g.Modules = s.Peer.SyncModules(ctx)
	titles, on := map[string]string{}, map[string]bool{}
	for _, m := range g.Modules {
		for _, it := range m.Items {
			titles[m.ID+"/"+it.ID] = it.TitleKey
			on[m.ID+"/"+it.ID] = m.Available && m.Enabled && it.Enabled
		}
	}
	list, _ := s.Peer.Members(ctx)
	for _, x := range list {
		row := memberRow{Member: x, NoSync: x.Sync == nil}
		for _, a := range x.Sync {
			k := titles[a]
			if k == "" {
				k = a
			}
			row.Areas = append(row.Areas, memberArea{Key: k, Both: on[a]})
		}
		g.Members = append(g.Members, row)
	}
	g.ACME = s.acmeChoices(ctx, list)
	g.Code, g.CodeExp = s.Peer.PairingCode()
	g.Linked = s.Peer.LinkedSelf()
	_, g.Forwarder, g.FwdSelf = s.Peer.Forwarder(ctx)
	g.SelfURL = selfURL(r, g.HTTPSPort)
	return g
}

// selfURL schlaegt die Adresse dieser Node vor (der Cluster laeuft nur ueber HTTPS): der Host, unter dem der
// Browser sie gerade erreicht, mit dem HTTPS-Port; ohne HTTPS-Port der aktuelle Port, der HTTP-Port spricht auch
// TLS (dualport.go).
func selfURL(r *http.Request, httpsPort int) string {
	if httpsPort <= 0 {
		return "https://" + r.Host
	}
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = strings.Trim(r.Host, "[]")
	}
	return "https://" + net.JoinHostPort(host, strconv.Itoa(httpsPort))
}

func (s *Server) groupBack(w http.ResponseWriter, r *http.Request, kind, msg string) {
	if msg != "" {
		s.flash(w, r, kind, msg)
	}
	http.Redirect(w, r, "/cluster", http.StatusSeeOther)
}

func (s *Server) groupErr(r *http.Request, err error) string {
	switch {
	case errors.Is(err, peer.ErrNoAccount):
		return s.tr(r, "cluster.err_no_account")
	case errors.Is(err, peer.ErrAccountMismatch):
		return s.tr(r, "cluster.err_account")
	case errors.Is(err, peer.ErrCode):
		return s.tr(r, "cluster.err_code")
	case errors.Is(err, peer.ErrSelf):
		return s.tr(r, "cluster.err_self")
	case errors.Is(err, peer.ErrUnknownMember):
		return s.tr(r, "cluster.err_unknown")
	}
	return s.tr(r, "cluster.err_other", "err", err.Error())
}

func (s *Server) groupCode(w http.ResponseWriter, r *http.Request) {
	if r.PostFormValue("cancel") != "" {
		s.Peer.CancelPairing()
		s.audit(r, "peer.code_cancel", "", "")
		s.groupBack(w, r, "", "")
		return
	}
	if _, _, err := s.Peer.StartPairing(); err != nil {
		s.groupBack(w, r, "danger", s.groupErr(r, err))
		return
	}
	s.audit(r, "peer.code", "", "")
	s.groupBack(w, r, "", "")
}

func (s *Server) groupJoin(w http.ResponseWriter, r *http.Request) {
	addr, code, self := strings.TrimSpace(r.PostFormValue("addr")), r.PostFormValue("code"), strings.TrimSpace(r.PostFormValue("self_url"))
	if addr == "" || code == "" || self == "" {
		s.groupBack(w, r, "danger", s.tr(r, "errors.validation"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if err := s.Peer.Join(ctx, addr, code, self); err != nil {
		s.log.Warn("join cluster failed", "addr", addr, "err", err)
		s.groupBack(w, r, "danger", s.groupErr(r, err))
		return
	}
	s.audit(r, "peer.join", addr, "")
	s.groupBack(w, r, "success", s.tr(r, "cluster.joined"))
}

func (s *Server) groupRemove(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := s.Peer.Remove(ctx, r.PathValue("id")); err != nil {
		s.groupBack(w, r, "danger", s.groupErr(r, err))
		return
	}
	s.audit(r, "peer.remove", r.PathValue("id"), "")
	s.groupBack(w, r, "success", s.tr(r, "cluster.removed"))
}

func (s *Server) groupURL(w http.ResponseWriter, r *http.Request) {
	u := strings.TrimSpace(r.PostFormValue("url"))
	if !validPeerURL(u) {
		s.groupBack(w, r, "danger", s.tr(r, "cluster.err_url"))
		return
	}
	if err := s.Peer.SetURL(r.Context(), r.PathValue("id"), u); err != nil {
		if errors.Is(err, peer.ErrUnknownMember) {
			s.groupBack(w, r, "danger", s.groupErr(r, err))
			return
		}
		s.fail(w, r, err)
		return
	}
	s.audit(r, "peer.url", r.PathValue("id"), u)
	s.groupBack(w, r, "success", s.tr(r, "common.saved"))
}

// groupResume nimmt eine ausgesetzte Node wieder auf (passt es weiterhin nicht, bleibt sie ausgesetzt).
func (s *Server) groupResume(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := s.Peer.Resume(ctx, r.PathValue("id")); err != nil {
		if x := s.suspendedMember(r.Context(), r.PathValue("id")); x != nil {
			s.groupBack(w, r, "warning", s.tr(r, "cluster.still_suspended", "reason", s.tr(r, "cluster.reason."+x.Reason)))
			return
		}
		s.groupBack(w, r, "danger", s.groupErr(r, err))
		return
	}
	s.audit(r, "peer.resume", r.PathValue("id"), "")
	s.groupBack(w, r, "success", s.tr(r, "cluster.resumed"))
}

// suspendedMember: das Mitglied, wenn es (weiterhin) ausgesetzt ist, sonst nil.
func (s *Server) suspendedMember(ctx context.Context, nodeID string) *peer.Member {
	list, _ := s.Peer.Members(ctx)
	for i := range list {
		if list[i].NodeID == nodeID && list[i].Suspended() {
			return &list[i]
		}
	}
	return nil
}

// groupSync schaltet ein Modul (item leer) oder einen Bereich; from=link kommt von der Seite Healthchecks-Sync.
func (s *Server) groupSync(w http.ResponseWriter, r *http.Request) {
	mod, item, on := r.PostFormValue("module"), r.PostFormValue("item"), r.PostFormValue("enabled") == "on"
	back := func(kind, msg string) {
		if r.PostFormValue("from") == "link" {
			s.flash(w, r, kind, msg)
			http.Redirect(w, r, "/link", http.StatusSeeOther)
			return
		}
		s.groupBack(w, r, kind, msg)
	}
	if err := s.Peer.SetSync(r.Context(), mod, item, on); err != nil {
		if errors.Is(err, peer.ErrUnknownSync) {
			back("danger", s.tr(r, "errors.validation"))
			return
		}
		s.fail(w, r, err)
		return
	}
	s.audit(r, "peer.sync", syncTarget(mod, item), "enabled="+strconv.FormatBool(on))
	back("success", s.tr(r, "common.saved"))
}

// syncTarget: "modul" bzw. "modul/bereich" fuer das Audit-Log.
func syncTarget(mod, item string) string {
	if item == "" {
		return mod
	}
	return mod + "/" + item
}

// acmeChoices: verschiedene ACME-Konten im Cluster (das eigene zuerst) von Nodes, die noch Mitglied sind; nil =
// keine Abweichung.
func (s *Server) acmeChoices(ctx context.Context, members []peer.Member) []acmeRow {
	if s.Certs == nil {
		return nil
	}
	names := map[string]string{}
	for _, x := range members {
		names[x.NodeID] = x.Name
	}
	var out []acmeRow
	for _, c := range s.Certs.AccountConflicts(ctx) {
		name, ok := names[c.Node]
		if !c.Own && !ok {
			continue // Node nicht mehr im Cluster
		}
		if name == "" {
			name = c.Node
		}
		out = append(out, acmeRow{AccountChoice: c, Name: name})
	}
	if len(out) < 2 {
		return nil
	}
	return out
}

// groupACME waehlt das ACME-Konto fuer den ganzen Cluster; die anderen werden verworfen (Audit nennt sie).
func (s *Server) groupACME(w http.ResponseWriter, r *http.Request) {
	if s.Certs == nil {
		s.groupBack(w, r, "danger", s.tr(r, "errors.validation"))
		return
	}
	_, err := s.chooseACME(r, r.PostFormValue("thumbprint"))
	if errors.Is(err, certs.ErrAccountChoice) {
		s.groupBack(w, r, "danger", s.tr(r, "cluster.acme_unknown"))
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.groupBack(w, r, "success", s.tr(r, "cluster.acme_chosen"))
}

// chooseACME fuehrt die Wahl aus und vermerkt sie samt verworfener Konten im Audit-Log.
func (s *Server) chooseACME(r *http.Request, thumb string) ([]certs.AccountChoice, error) {
	dropped, err := s.Certs.ChooseAccount(r.Context(), thumb)
	if err != nil {
		return nil, err
	}
	parts := make([]string, 0, len(dropped))
	for _, d := range dropped {
		parts = append(parts, d.Node+":"+d.Email+":"+d.Thumbprint[:min(16, len(d.Thumbprint))])
	}
	s.audit(r, "cert.account.choose", thumb[:min(16, len(thumb))], "dropped="+strings.Join(parts, ","))
	return dropped, nil
}

func (s *Server) groupLeave(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := s.Peer.Leave(ctx); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, "peer.leave", "", "")
	s.groupBack(w, r, "success", s.tr(r, "cluster.left"))
}
