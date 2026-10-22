package dns64

import (
	"net/http"
	"strings"

	"github.com/ipv64net/node64/internal/module"
)

// Seite und API fuer Weiterleitungen und Umschreiben (forwards.go).

func (m *Module) forwardRoutes(mux *http.ServeMux, g module.Guards) {
	page := func(h http.HandlerFunc) http.Handler { return g.Enabled(g.Auth(h)) }
	mux.Handle("GET /dns64/forwards", page(m.pageTab("forwards", "dns64.forwards.title")))
	mux.Handle("POST /dns64/forwards", page(m.pageForwardSave))
	mux.Handle("POST /dns64/forwards/{id}/edit", page(m.pageForwardSave))
	mux.Handle("POST /dns64/forwards/{id}/delete", page(m.pageForwardDelete))
	mux.Handle("POST /dns64/forwards/{id}/toggle", page(m.pageForwardToggle))
	mux.Handle("POST /dns64/rewrites", page(m.pageRewriteSave))
	mux.Handle("POST /dns64/rewrites/{id}/edit", page(m.pageRewriteSave))
	mux.Handle("POST /dns64/rewrites/{id}/delete", page(m.pageRewriteDelete))
	mux.Handle("POST /dns64/rewrites/{id}/toggle", page(m.pageRewriteToggle))

	api := func(h http.HandlerFunc) http.Handler { return g.Enabled(g.Auth(h)) }
	mux.Handle("GET /api/dns64/forwards", api(m.apiForwards))
	mux.Handle("POST /api/dns64/forwards", api(m.apiForwardSave))
	mux.Handle("PUT /api/dns64/forwards/{id}", api(m.apiForwardSave))
	mux.Handle("DELETE /api/dns64/forwards/{id}", api(m.apiForwardDelete))
	mux.Handle("POST /api/dns64/forwards/{id}/enable", api(m.apiForwardToggle(true)))
	mux.Handle("POST /api/dns64/forwards/{id}/disable", api(m.apiForwardToggle(false)))
	mux.Handle("POST /api/dns64/forwards/{id}/test", api(m.apiForwardTest))
	mux.Handle("GET /api/dns64/rewrites", api(m.apiRewrites))
	mux.Handle("POST /api/dns64/rewrites", api(m.apiRewriteSave))
	mux.Handle("PUT /api/dns64/rewrites/{id}", api(m.apiRewriteSave))
	mux.Handle("DELETE /api/dns64/rewrites/{id}", api(m.apiRewriteDelete))
	mux.Handle("POST /api/dns64/rewrites/{id}/enable", api(m.apiRewriteToggle(true)))
	mux.Handle("POST /api/dns64/rewrites/{id}/disable", api(m.apiRewriteToggle(false)))
}

func (m *Module) forwardBack(w http.ResponseWriter, r *http.Request, err error, okKey string) {
	if err != nil {
		m.g.Flash(w, r, "danger", m.errText(r, err))
	} else if okKey != "" {
		m.g.Flash(w, r, "success", m.g.T(r, okKey))
	}
	http.Redirect(w, r, "/dns64/forwards", http.StatusSeeOther)
}

func onOff(on bool) string { return map[bool]string{true: "enable", false: "disable"}[on] }

// ---- Seite ----

func (m *Module) pageForwardSave(w http.ResponseWriter, r *http.Request) {
	f := Forward{Domain: r.PostFormValue("domain"), Servers: []string{r.PostFormValue("servers")}, Comment: r.PostFormValue("comment")}
	var err error
	if id := pathID(r); id > 0 {
		f, err = m.UpdateForward(r.Context(), id, f)
		if err == nil {
			m.audit(r, "dns64.forward.edit", f.Domain, strings.Join(f.Servers, " "))
		}
		m.forwardBack(w, r, err, "dns64.forwards.saved")
		return
	}
	f, err = m.AddForward(r.Context(), f)
	if err == nil {
		m.log.Info("forward added", "domain", f.Domain, "servers", f.Servers, "by", m.g.Actor(r))
		m.audit(r, "dns64.forward.add", f.Domain, strings.Join(f.Servers, " "))
	}
	m.forwardBack(w, r, err, "dns64.forwards.added")
}

func (m *Module) pageForwardDelete(w http.ResponseWriter, r *http.Request) {
	err := m.DeleteForward(r.Context(), pathID(r))
	if err == nil {
		m.audit(r, "dns64.forward.delete", r.PathValue("id"), "")
	}
	m.forwardBack(w, r, err, "dns64.forwards.deleted")
}

func (m *Module) pageForwardToggle(w http.ResponseWriter, r *http.Request) {
	on := r.PostFormValue("on") == "1"
	err := m.SetForwardEnabled(r.Context(), pathID(r), on)
	if err == nil {
		m.audit(r, "dns64.forward."+onOff(on), r.PathValue("id"), "")
	}
	m.forwardBack(w, r, err, "")
}

func (m *Module) pageRewriteSave(w http.ResponseWriter, r *http.Request) {
	x := Rewrite{Name: r.PostFormValue("name"), Target: r.PostFormValue("target"), Comment: r.PostFormValue("comment")}
	var err error
	if id := pathID(r); id > 0 {
		x, err = m.UpdateRewrite(r.Context(), id, x)
		if err == nil {
			m.audit(r, "dns64.rewrite.edit", x.Name, x.Target)
		}
		m.forwardBack(w, r, err, "dns64.forwards.saved")
		return
	}
	x, err = m.AddRewrite(r.Context(), x)
	if err == nil {
		m.log.Info("rewrite added", "name", x.Name, "target", x.Target, "by", m.g.Actor(r))
		m.audit(r, "dns64.rewrite.add", x.Name, x.Target)
	}
	m.forwardBack(w, r, err, "dns64.forwards.rw_added")
}

func (m *Module) pageRewriteDelete(w http.ResponseWriter, r *http.Request) {
	err := m.DeleteRewrite(r.Context(), pathID(r))
	if err == nil {
		m.audit(r, "dns64.rewrite.delete", r.PathValue("id"), "")
	}
	m.forwardBack(w, r, err, "dns64.forwards.deleted")
}

func (m *Module) pageRewriteToggle(w http.ResponseWriter, r *http.Request) {
	on := r.PostFormValue("on") == "1"
	err := m.SetRewriteEnabled(r.Context(), pathID(r), on)
	if err == nil {
		m.audit(r, "dns64.rewrite."+onOff(on), r.PathValue("id"), "")
	}
	m.forwardBack(w, r, err, "")
}

// ---- API ----

func (m *Module) apiForwards(w http.ResponseWriter, r *http.Request) {
	list, err := m.Forwards(r.Context())
	m.apiResult(w, r, err, http.StatusOK, m.forwardViews(list))
}

func (m *Module) apiForwardSave(w http.ResponseWriter, r *http.Request) {
	var in Forward
	if !decode(w, r, &in) {
		return
	}
	var err error
	status := http.StatusCreated
	if id := pathID(r); id > 0 {
		in, err = m.UpdateForward(r.Context(), id, in)
		status = http.StatusOK
	} else {
		in, err = m.AddForward(r.Context(), in)
	}
	if err == nil {
		m.audit(r, "dns64.forward."+map[bool]string{true: "add", false: "edit"}[status == http.StatusCreated], in.Domain, strings.Join(in.Servers, " "))
	}
	m.apiResult(w, r, err, status, in)
}

func (m *Module) apiForwardDelete(w http.ResponseWriter, r *http.Request) {
	err := m.DeleteForward(r.Context(), pathID(r))
	if err == nil {
		m.audit(r, "dns64.forward.delete", r.PathValue("id"), "")
	}
	m.apiResult(w, r, err, 0, nil)
}

func (m *Module) apiForwardToggle(on bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := m.SetForwardEnabled(r.Context(), pathID(r), on)
		if err == nil {
			m.audit(r, "dns64.forward."+onOff(on), r.PathValue("id"), "")
		}
		m.apiResult(w, r, err, 0, nil)
	}
}

func (m *Module) apiForwardTest(w http.ResponseWriter, r *http.Request) {
	t, err := m.TestForward(r.Context(), pathID(r))
	m.apiResult(w, r, err, http.StatusOK, t)
}

func (m *Module) apiRewrites(w http.ResponseWriter, r *http.Request) {
	list, err := m.Rewrites(r.Context())
	m.apiResult(w, r, err, http.StatusOK, list)
}

func (m *Module) apiRewriteSave(w http.ResponseWriter, r *http.Request) {
	var in Rewrite
	if !decode(w, r, &in) {
		return
	}
	var err error
	status := http.StatusCreated
	if id := pathID(r); id > 0 {
		in, err = m.UpdateRewrite(r.Context(), id, in)
		status = http.StatusOK
	} else {
		in, err = m.AddRewrite(r.Context(), in)
	}
	if err == nil {
		m.audit(r, "dns64.rewrite."+map[bool]string{true: "add", false: "edit"}[status == http.StatusCreated], in.Name, in.Target)
	}
	m.apiResult(w, r, err, status, in)
}

func (m *Module) apiRewriteDelete(w http.ResponseWriter, r *http.Request) {
	err := m.DeleteRewrite(r.Context(), pathID(r))
	if err == nil {
		m.audit(r, "dns64.rewrite.delete", r.PathValue("id"), "")
	}
	m.apiResult(w, r, err, 0, nil)
}

func (m *Module) apiRewriteToggle(on bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := m.SetRewriteEnabled(r.Context(), pathID(r), on)
		if err == nil {
			m.audit(r, "dns64.rewrite."+onOff(on), r.PathValue("id"), "")
		}
		m.apiResult(w, r, err, 0, nil)
	}
}
