package monitor64

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/ipv64net/node64/internal/m64proto"
	"github.com/ipv64net/node64/internal/monitor64/model"
)

// Alle SMART-Werte einer Platte zum Nachschlagen (Knopf in der Dienste-Tabelle). Die Sammler haengen den zuletzt
// gelesenen Satz an den Dienst (model.Service.Smart); der Kern haelt je Platte nur diesen einen Satz im Speicher
// (hostRT.smart) – nichts davon steht in der Datenbank oder im Verlauf. Nach einem Neustart der Node ist der Satz
// mit der naechsten Abfrage wieder da. Im Cluster liegt er bei der zustaendigen Node; die anderen fragen dort nach.

const (
	callSmart        = "smart"
	smartCallTimeout = 8 * time.Second
	maxSmartText     = 128
)

// smartDetail macht aus den SMART-Werten eines Berichts (Agent, SSH) den Satz fuer den Dialog. Liefert die Quelle
// nur die ausgewerteten Werte (Windows, Agents vor 0.1.4), stehen diese als Werte da (Partial).
func smartDetail(sm *m64proto.SMART, reportMs int64) *model.SmartDetail {
	d := &model.SmartDetail{Type: clipText(sm.Type, 16), Model: clipText(sm.Model, maxSmartText), Serial: clipText(sm.Serial, maxSmartText),
		Firmware: clipText(sm.Firmware, maxSmartText), Size: sm.CapacityBytes, Passed: sm.Passed}
	switch {
	case sm.ReadAt > 0:
		d.At = time.Unix(sm.ReadAt, 0)
	case reportMs > 0:
		d.At = time.UnixMilli(reportMs)
	}
	for i, a := range sm.Attrs {
		if i >= m64proto.MaxSmartRows {
			break
		}
		v, w, t := a.Value, a.Worst, a.Thresh
		row := model.SmartAttr{ID: a.ID, Name: clipText(a.Name, maxSmartText), Value: &v, Worst: &w, Thresh: &t, Raw: clipText(a.Raw, maxSmartText)}
		if a.Fail == "now" || a.Fail == "past" {
			row.Failed = a.Fail
		}
		d.Attrs = append(d.Attrs, row)
	}
	for i, v := range sm.Values {
		if i >= m64proto.MaxSmartRows {
			break
		}
		d.Values = append(d.Values, model.SmartValue{Key: clipText(v.Key, 64), Value: v.Value, Unit: clipText(v.Unit, 8), Text: clipText(v.Text, maxSmartText)})
	}
	if len(d.Attrs) == 0 && len(d.Values) == 0 {
		d.Partial = true
		d.Values = smartSummary(sm.TempC, sm.WearPercentUsed, sm.PowerOnHours, sm.Reallocated, sm.Pending, sm.Uncorrectable, sm.CRCErrors,
			sm.MediaErrors, sm.CriticalWarning)
	}
	return d
}

// smartSummary: die ausgewerteten Werte als Zeilen (fuer Quellen ohne vollstaendige Tabelle).
func smartSummary(temp, wear *float64, poh, realloc, pending, uncorr, crc, mediaErr, critWarn *uint64) []model.SmartValue {
	var out []model.SmartValue
	f := func(key string, v *float64, unit string) {
		if v != nil {
			out = append(out, model.SmartValue{Key: key, Value: *v, Unit: unit})
		}
	}
	u := func(key string, v *uint64, unit string) {
		if v != nil {
			out = append(out, model.SmartValue{Key: key, Value: float64(*v), Unit: unit})
		}
	}
	f("temperature", temp, "°C")
	f("percentage_used", wear, "%")
	u("power_on_hours", poh, "h")
	u("reallocated", realloc, "")
	u("pending", pending, "")
	u("uncorrectable", uncorr, "")
	u("crc_errors", crc, "")
	u("media_errors", mediaErr, "")
	u("critical_warning", critWarn, "hex")
	return out
}

func clipText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 { // nicht mitten in einem UTF-8-Zeichen trennen
		n--
	}
	return s[:n]
}

// setSmart uebernimmt die Saetze der Runde: found = Dienste dieser Runde mit SMART-Werten, keep = Schluessel der
// uebernommenen Dienste (ein Satz bleibt, solange es den Dienst gibt – auch wenn der Zugang gerade nicht antwortet).
func (rt *hostRT) setSmart(found map[string]*model.SmartDetail, keep map[string]bool, now time.Time) {
	rt.viewMu.Lock()
	defer rt.viewMu.Unlock()
	next := make(map[string]*model.SmartDetail, len(found))
	for k, d := range rt.smart {
		if keep[k] {
			next[k] = d
		}
	}
	for k, d := range found {
		if d.At.IsZero() {
			c := *d
			c.At = now
			d = &c
		}
		next[k] = d
	}
	rt.smart = next
}

func (rt *hostRT) smartOf(key string) *model.SmartDetail {
	rt.viewMu.Lock()
	defer rt.viewMu.Unlock()
	return rt.smart[key]
}

type smartReq struct {
	Host string `json:"host"`
	Key  string `json:"key"`
}

// smartOut ist die Antwort von GET /api/monitor64/hosts/{uid}/smart?key=.
type smartOut struct {
	Key   string             `json:"key"`
	Smart *model.SmartDetail `json:"smart"`
}

// smartLocal: der Satz dieser Node (nil = keiner).
func (m *Module) smartLocal(uid, key string) *model.SmartDetail {
	m.rtMu.Lock()
	rt := m.rts[uid]
	m.rtMu.Unlock()
	if rt == nil {
		return nil
	}
	return rt.smartOf(key)
}

// smartFor: der Satz einer Platte – von dieser Node oder, im Cluster, von der zustaendigen.
func (m *Module) smartFor(ctx context.Context, uid, key string) *model.SmartDetail {
	if d := m.smartLocal(uid, key); d != nil {
		return d
	}
	owner, ok := m.trapOwner(uid) // zustaendige andere Node, sofern erreichbar
	call := m.hooks().Call
	if !ok || call == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, smartCallTimeout)
	defer cancel()
	var out smartOut
	if err := call(ctx, owner, callSmart, smartReq{Host: uid, Key: key}, &out); err != nil {
		m.log.Debug("monitor64: smart: ask owner", "host", uid, "node", owner, "err", err)
		return nil
	}
	return out.Smart
}

// handleSmartCall beantwortet die Anfrage einer anderen Node.
func (m *Module) handleSmartCall(body []byte) (any, error) {
	var in smartReq
	if err := json.Unmarshal(body, &in); err != nil || !reUID.MatchString(in.Host) || in.Key == "" || len(in.Key) > 512 {
		return nil, errBad("call")
	}
	return smartOut{Key: in.Key, Smart: m.smartLocal(in.Host, in.Key)}, nil
}

// apiSmart: GET alle zuletzt gelesenen SMART-Werte einer Platte (?key=<Dienst>). 404, wenn es keine gibt.
func (m *Module) apiSmart(w http.ResponseWriter, r *http.Request) {
	h, err := m.store.Host(r.Context(), r.PathValue("uid"))
	if err != nil {
		m.fail(w, r, err)
		return
	}
	key := r.URL.Query().Get("key")
	var d *model.SmartDetail
	if key != "" && len(key) <= 512 {
		d = m.smartFor(r.Context(), h.UID, key)
	}
	if d == nil {
		m.fail(w, r, ErrNotFound)
		return
	}
	writeJSON(w, http.StatusOK, smartOut{Key: key, Smart: d})
}
