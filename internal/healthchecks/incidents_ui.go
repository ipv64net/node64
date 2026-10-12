package healthchecks

import (
	"net/http"
	"strconv"
	"time"
)

// Stoerungen aller Checks (wie die Portal-Seite "Stoerungen"): offene zuerst, Zeitraum waehlbar.

type incidentRow struct {
	Incident
	Name     string
	Exists   bool
	Duration time.Duration
}

type incidentsData struct {
	Rows     []incidentRow
	Days     int
	Choices  []int
	OnlyOpen bool
	Open     int
	Total    time.Duration
}

func (m *Module) incidentsRoutes(mux *http.ServeMux, page func(http.HandlerFunc) http.Handler) {
	mux.Handle("GET /healthchecks/incidents", page(m.pageIncidents))
}

func (m *Module) pageIncidents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	d := incidentsData{Days: 30, Choices: []int{7, 30, 90, 365}, OnlyOpen: r.URL.Query().Get("open") == "1"}
	if v, err := strconv.Atoi(r.URL.Query().Get("days")); err == nil {
		for _, c := range d.Choices {
			if c == v {
				d.Days = v
			}
		}
	}
	names := map[string]string{}
	if list, err := m.st.Checks(ctx); err == nil {
		for _, c := range list {
			names[c.Token] = c.Name
		}
	}
	q := `SELECT id, token, started_at, ended_at, reason, message FROM hc_incidents WHERE (started_at >= ? OR ended_at = '')`
	if d.OnlyOpen {
		q += ` AND ended_at = ''`
	}
	q += ` ORDER BY ended_at = '' DESC, started_at DESC LIMIT 500`
	rows, err := m.st.r.QueryContext(ctx, q, ft(time.Now().Add(-time.Duration(d.Days)*24*time.Hour)))
	if err != nil {
		m.fail(w, r, err)
		return
	}
	defer rows.Close()
	now := time.Now()
	for rows.Next() {
		var x incidentRow
		var st, en string
		if rows.Scan(&x.ID, &x.Token, &st, &en, &x.Reason, &x.Message) != nil {
			continue
		}
		x.StartedAt, x.EndedAt, x.Open = pt(st), pt(en), en == ""
		x.Name, x.Exists = names[x.Token]
		end := x.EndedAt
		if x.Open {
			end = now
			d.Open++
		}
		if x.Duration = end.Sub(x.StartedAt); x.Duration < 0 {
			x.Duration = 0
		}
		d.Total += x.Duration
		d.Rows = append(d.Rows, x)
	}
	m.g.Render(w, r, http.StatusOK, Name+"/incidents", "hc.incident_list.title", d)
}
