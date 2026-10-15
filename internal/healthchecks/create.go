package healthchecks

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
)

// CreateFromJSON legt einen Check an wie POST /api/checks – fuer andere Module (z. B. CDN64: "Healthcheck fuer
// dieses Ziel anlegen"). r liefert Benutzer und IP fuer das Audit; body ist das JSON wie bei der API.
func (m *Module) CreateFromJSON(r *http.Request, body []byte) (token string, err error) {
	req := r.Clone(r.Context())
	req.Method = http.MethodPost
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.Header = r.Header.Clone()
	req.Header.Set("Content-Type", "application/json")
	rec := &memWriter{header: http.Header{}}
	m.apiCreate(rec, req)
	var out struct {
		Token string `json:"token"`
		Error string `json:"error"`
	}
	_ = json.Unmarshal(rec.buf.Bytes(), &out)
	if rec.status != http.StatusCreated {
		if out.Error == "" {
			out.Error = "status " + strconv.Itoa(rec.status)
		}
		return "", errors.New(out.Error)
	}
	return out.Token, nil
}

// memWriter nimmt eine Antwort im Speicher auf.
type memWriter struct {
	header http.Header
	status int
	buf    bytes.Buffer
}

func (w *memWriter) Header() http.Header { return w.header }

func (w *memWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
}

func (w *memWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.buf.Write(b)
}
