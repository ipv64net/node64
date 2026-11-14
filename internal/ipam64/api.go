package ipam64

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/ipv64net/node64/internal/module"
)

// Lokale JSON-API des Moduls (Doku: internal/web/static/openapi.json, Tag "IPAM64"). Ist das Modul aus: 404. Rolle
// "Nur lesen": aendernde Anfragen beantwortet der Kern mit 403. Eingaben werden streng gelesen (unbekannte Felder =
// Fehler, hoechstens 64 KiB).

const maxBody = 64 << 10

var allocMu sync.Mutex // "naechste freie Adresse vergeben" am Stueck (pruefen und eintragen)

func (m *Module) apiRoutes(mux *http.ServeMux, g module.Guards) {
	api := func(h http.HandlerFunc) http.Handler { return g.Enabled(g.Auth(h)) }
	mux.Handle("GET /api/ipam64/prefixes", api(m.apiPrefixes))
	mux.Handle("POST /api/ipam64/prefixes", api(m.apiPrefixSave))
	mux.Handle("PUT /api/ipam64/prefixes/{uid}", api(m.apiPrefixSave))
	mux.Handle("DELETE /api/ipam64/prefixes/{uid}", api(m.apiPrefixDelete))
	mux.Handle("GET /api/ipam64/ranges", api(m.apiRanges))
	mux.Handle("POST /api/ipam64/ranges", api(m.apiRangeSave))
	mux.Handle("PUT /api/ipam64/ranges/{uid}", api(m.apiRangeSave))
	mux.Handle("DELETE /api/ipam64/ranges/{uid}", api(m.apiRangeDelete))
	mux.Handle("GET /api/ipam64/addresses", api(m.apiAddresses))
	mux.Handle("POST /api/ipam64/addresses", api(m.apiAddressSave))
	mux.Handle("PUT /api/ipam64/addresses/{uid}", api(m.apiAddressSave))
	mux.Handle("DELETE /api/ipam64/addresses/{uid}", api(m.apiAddressDelete))
	mux.Handle("GET /api/ipam64/available", api(m.apiAvailable))
	mux.Handle("POST /api/ipam64/available", api(m.apiAllocate))
	mux.Handle("GET /api/ipam64/scan", api(m.apiScanStatus))
	mux.Handle("POST /api/ipam64/scan", api(m.apiScan))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (m *Module) apiFail(w http.ResponseWriter, err error) {
	if k := m.dnsErrKey(err); k != "" { // aus DNS64: Schluessel als Code
		writeJSON(w, http.StatusConflict, map[string]string{"error": "dns64: " + strings.TrimPrefix(k, "dns64.err.")})
		return
	}
	if errKey(err) == "" {
		m.log.Error("ipam64: api", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	status := http.StatusBadRequest
	switch {
	case errors.Is(err, ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, ErrDup), errors.Is(err, ErrTaken), errors.Is(err, ErrOverlap), errors.Is(err, ErrBusy):
		status = http.StatusConflict
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

var errBody = errors.New("ipam64: invalid request body")

// decode liest den Rumpf streng (unbekannte Felder = Fehler).
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": errBody.Error()})
		return false
	}
	return true
}

func (m *Module) apiPrefixes(w http.ResponseWriter, r *http.Request) {
	snap, err := m.Snapshot(r.Context())
	if err != nil {
		m.apiFail(w, err)
		return
	}
	out := snap.Nets
	if out == nil {
		out = []Net{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"prefixes": out})
}

// prefixIn sind die Felder eines Praefixes, die die API annimmt.
type prefixIn struct {
	Prefix      string   `json:"prefix"`
	Name        string   `json:"name"`
	Status      string   `json:"status"`
	Role        string   `json:"role"`
	VLAN        int      `json:"vlan"`
	Tags        []string `json:"tags"`
	Description string   `json:"description"`
	MarkFull    bool     `json:"mark_full"`
	DNSZone     string   `json:"dns_zone"`
	Scan        string   `json:"scan"`
}

func (m *Module) apiPrefixSave(w http.ResponseWriter, r *http.Request) {
	var in prefixIn
	if !decode(w, r, &in) {
		return
	}
	p := Prefix{UID: r.PathValue("uid"), Prefix: in.Prefix, Name: in.Name, Status: in.Status, Role: in.Role, VLAN: in.VLAN, Tags: in.Tags,
		Description: in.Description, MarkFull: in.MarkFull, DNSZone: in.DNSZone, Scan: in.Scan}
	if p.UID != "" { // Felder, die die API nicht kennt, bleiben
		if cur, err := m.prefixByUID(r.Context(), p.UID); err == nil && cur != nil {
			p.ScanNode, p.DynParent, p.DynIndex, p.DynSource = cur.ScanNode, cur.DynParent, cur.DynIndex, cur.DynSource
		}
	}
	out, err := m.SavePrefix(r.Context(), p, m.g.Actor(r))
	if err != nil {
		m.apiFail(w, err)
		return
	}
	m.g.Audit(r, "ipam64.prefix.save", out.Prefix, out.Name)
	status := http.StatusOK
	if r.Method == http.MethodPost {
		status = http.StatusCreated
	}
	writeJSON(w, status, out)
}

func (m *Module) apiPrefixDelete(w http.ResponseWriter, r *http.Request) {
	p, err := m.DeletePrefix(r.Context(), r.PathValue("uid"))
	if err != nil {
		m.apiFail(w, err)
		return
	}
	m.g.Audit(r, "ipam64.prefix.delete", p.Prefix, p.Name)
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) apiRanges(w http.ResponseWriter, r *http.Request) {
	list, err := m.Ranges(r.Context())
	if err != nil {
		m.apiFail(w, err)
		return
	}
	if list == nil {
		list = []Range{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ranges": list})
}

type rangeIn struct {
	Start       string `json:"start"`
	End         string `json:"end"`
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (m *Module) apiRangeSave(w http.ResponseWriter, r *http.Request) {
	var in rangeIn
	if !decode(w, r, &in) {
		return
	}
	out, err := m.SaveRange(r.Context(), Range{UID: r.PathValue("uid"), Start: in.Start, End: in.End, Kind: in.Kind, Name: in.Name, Description: in.Description},
		m.g.Actor(r))
	if err != nil {
		m.apiFail(w, err)
		return
	}
	m.g.Audit(r, "ipam64.range.save", out.Start+"-"+out.End, out.Name)
	status := http.StatusOK
	if r.Method == http.MethodPost {
		status = http.StatusCreated
	}
	writeJSON(w, status, out)
}

func (m *Module) apiRangeDelete(w http.ResponseWriter, r *http.Request) {
	rg, err := m.DeleteRange(r.Context(), r.PathValue("uid"))
	if err != nil {
		m.apiFail(w, err)
		return
	}
	m.g.Audit(r, "ipam64.range.delete", rg.Start+"-"+rg.End, rg.Name)
	w.WriteHeader(http.StatusNoContent)
}

// AddressOut ist eine belegte Adresse mit ihrem Praefix (GET /api/ipam64/addresses).
type AddressOut struct {
	Prefix string `json:"prefix"`
	Entry
}

// apiAddresses: belegte Adressen aller bzw. eines Praefixes (?prefix=), Suche (?q=), Seiten (?limit=, ?offset=).
func (m *Module) apiAddresses(w http.ResponseWriter, r *http.Request) {
	snap, err := m.Snapshot(r.Context())
	if err != nil {
		m.apiFail(w, err)
		return
	}
	q := r.URL.Query()
	var only *Net
	if p := q.Get("prefix"); p != "" {
		if only = snap.Net(p); only == nil {
			m.apiFail(w, ErrNotFound)
			return
		}
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}
	offset, _ := strconv.Atoi(q.Get("offset"))
	offset = max(offset, 0)
	lq := strings.ToLower(strings.TrimSpace(q.Get("q")))
	out := []AddressOut{}
	total := 0
	for _, n := range snap.Nets {
		if only != nil && n.Prefix != only.Prefix {
			continue
		}
		for _, e := range snap.Entries(n.Prefix) {
			if !matches(e, lq) {
				continue
			}
			if total >= offset && len(out) < limit {
				if e.Sources == nil {
					e.Sources = []string{}
				}
				out = append(out, AddressOut{n.CIDR, e})
			}
			total++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"addresses": out, "total": total, "offset": offset, "limit": limit})
}

type addressIn struct {
	Address     string   `json:"address"`
	Status      string   `json:"status"`
	Role        string   `json:"role"`
	Name        string   `json:"name"`
	MAC         string   `json:"mac"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	DNS         *bool    `json:"dns"`      // lokaler Eintrag in DNS64 (fehlt: bisheriger Wert, neu: aus)
	DNSZone     *string  `json:"dns_zone"` // fehlt: bisheriger Wert (leer = Zone des Praefixes)
	PTR         *bool    `json:"ptr"`      // fehlt: bisheriger Wert, neu: an
	DHCP        *bool    `json:"dhcp"`     // Reservierung im DHCP-Server (fehlt: bisheriger Wert, neu: aus)
}

// address baut die Adresse; Felder fuer DNS/DHCP, die fehlen, kommen aus cur (nil = neu).
func (in addressIn) address(uid string, cur *Address) Address {
	a := Address{UID: uid, Address: in.Address, Status: in.Status, Role: in.Role, Name: in.Name, MAC: in.MAC, Description: in.Description, Tags: in.Tags, PTR: true}
	if cur != nil {
		a.DNS, a.DNSZone, a.PTR, a.DHCP = cur.DNS, cur.DNSZone, cur.PTR, cur.DHCP
	}
	if in.DNS != nil {
		a.DNS = *in.DNS
	}
	if in.DNSZone != nil {
		a.DNSZone = *in.DNSZone
	}
	if in.PTR != nil {
		a.PTR = *in.PTR
	}
	if in.DHCP != nil {
		a.DHCP = *in.DHCP
	}
	return a
}

func (m *Module) apiAddressSave(w http.ResponseWriter, r *http.Request) {
	var in addressIn
	if !decode(w, r, &in) {
		return
	}
	var cur *Address
	if uid := r.PathValue("uid"); uid != "" {
		var err error
		if cur, err = m.addressWhere(r.Context(), `uid = ?`, uid); err != nil {
			m.apiFail(w, err)
			return
		}
	}
	out, err := m.ApplyAddress(r.Context(), in.address(r.PathValue("uid"), cur), m.g.Actor(r))
	if err != nil {
		m.apiFail(w, err)
		return
	}
	m.g.Audit(r, "ipam64.address.save", out.Address, m.effectText(r.Context(), out))
	status := http.StatusOK
	if r.Method == http.MethodPost {
		status = http.StatusCreated
	}
	writeJSON(w, status, out)
}

func (m *Module) apiAddressDelete(w http.ResponseWriter, r *http.Request) {
	a, err := m.RemoveAddress(r.Context(), r.PathValue("uid"))
	if err != nil {
		m.apiFail(w, err)
		return
	}
	m.g.Audit(r, "ipam64.address.delete", a.Address, a.Name)
	w.WriteHeader(http.StatusNoContent)
}

// apiAvailable: freie Adressen eines Praefixes (?prefix=, optional ?range=<uid>, ?count= bis 256).
func (m *Module) apiAvailable(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	n, _ := strconv.Atoi(q.Get("count"))
	if n <= 0 || n > 256 {
		n = 10
	}
	list, err := m.Available(r.Context(), q.Get("prefix"), q.Get("range"), n)
	if err != nil {
		m.apiFail(w, err)
		return
	}
	out := make([]string, 0, len(list))
	for _, a := range list {
		out = append(out, a.String())
	}
	writeJSON(w, http.StatusOK, map[string]any{"prefix": q.Get("prefix"), "available": out})
}

// apiAllocate vergibt die naechste freie Adresse eines Praefixes am Stueck ({"prefix": ..., "range": ..., Felder einer
// Adresse ohne "address"}).
func (m *Module) apiAllocate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Prefix string `json:"prefix"`
		Range  string `json:"range"`
		addressIn
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Address != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": errBody.Error()})
		return
	}
	allocMu.Lock()
	defer allocMu.Unlock()
	m.invalidate() // frischer Stand, sonst koennte eine eben vergebene Adresse noch frei aussehen
	list, err := m.Available(r.Context(), in.Prefix, in.Range, 1)
	if err != nil {
		m.apiFail(w, err)
		return
	}
	if len(list) == 0 {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "ipam64: no free address"})
		return
	}
	in.Address = list[0].String()
	out, err := m.ApplyAddress(r.Context(), in.address("", nil), m.g.Actor(r))
	if err != nil {
		m.apiFail(w, err)
		return
	}
	m.g.Audit(r, "ipam64.address.save", out.Address, m.effectText(r.Context(), out))
	writeJSON(w, http.StatusCreated, out)
}

func (m *Module) apiScanStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, m.Scanning())
}

// apiScan startet den Netz-Scan eines Praefixes im Hintergrund ({"prefix":"192.168.1.0/24"}); Stand ueber GET.
func (m *Module) apiScan(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Prefix string `json:"prefix"`
	}
	if !decode(w, r, &in) {
		return
	}
	if err := m.StartScan(r.Context(), in.Prefix); err != nil {
		m.apiFail(w, err)
		return
	}
	m.g.Audit(r, "ipam64.scan", in.Prefix, "")
	writeJSON(w, http.StatusAccepted, m.Scanning())
}
