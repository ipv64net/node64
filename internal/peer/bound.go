package peer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// Gebundene Anfragen an Nodes ausserhalb des Clusters (Environment, hinzugefuegte Nodes mit Zugangsschluessel): gleiche
// Uebertragung wie im Cluster (TLS ohne Zertifikatspruefung, Exporter der Verbindung), die Antwort signiert die Node
// mit ihrem Ed25519-Schluessel ueber Status, Nonce, Kennung, Bindung und Body. Die Gegenseite kennt der Aufrufer aus
// dem Zugangsschluessel (Kennung und oeffentlicher Schluessel), nicht aus der Kopplung. Wie sich der Aufrufer
// ausweist, legt er selbst fest (auth; die Bindung geht dort ein): ein Mittelsmann, der TLS terminiert, hat zu beiden
// Seiten andere Werte - die Node lehnt die Anfrage ab und der Aufrufer erkennt die Antwort nicht an.

// maxBoundBody: Obergrenze fuer Anfragen und Antworten gebundener Endpunkte (kleine JSON-Objekte).
const maxBoundBody = 64 << 10

// BoundConn ist eine TLS-Verbindung zu einer Node, deren Antworten an die Verbindung gebunden sind.
type BoundConn struct {
	p      *peerConn
	nodeID string
	pubKey string // base64 (StdEncoding), wie Member.PubKey
}

// DialBound baut die Verbindung zu raw auf; nodeID und pubKey (base64) sind die erwartete Gegenseite.
func DialBound(ctx context.Context, raw, nodeID, pubKey string) (*BoundConn, error) {
	p, err := dialPeer(ctx, raw)
	if err != nil {
		return nil, err
	}
	return &BoundConn{p: p, nodeID: nodeID, pubKey: pubKey}, nil
}

// Bind ist der Exporter dieser Verbindung (geht in die eigene Anmeldung ein).
func (c *BoundConn) Bind() []byte { return c.p.bind }

// Close schliesst die Verbindung.
func (c *BoundConn) Close() { c.p.Close() }

// Post schickt body an path; auth liefert zur Nonce die Kopfzeilen der eigenen Anmeldung. Die Antwort muss von der
// erwarteten Node ueber genau diese Verbindung signiert sein, sonst Fehler (Status und Body bleiben fuer die Meldung).
func (c *BoundConn) Post(ctx context.Context, path string, body []byte, auth func(nonce string) http.Header) (int, []byte, error) {
	n := make([]byte, 16)
	if _, err := rand.Read(n); err != nil {
		return 0, nil, err
	}
	nonce := hex.EncodeToString(n)
	hdr := http.Header{}
	if auth != nil {
		hdr = auth(nonce)
	}
	hdr.Set("Content-Type", "application/json")
	hdr.Set("User-Agent", "node64")
	hdr.Set(hdrNonce, nonce)
	hdr.Set(hdrBind, hex.EncodeToString(c.p.bind))
	st, rh, b, err := c.p.do(ctx, http.MethodPost, path, body, hdr)
	if err != nil {
		return 0, nil, err
	}
	if len(b) > maxBoundBody {
		return 0, nil, fmt.Errorf("answer larger than %d bytes", maxBoundBody)
	}
	if err := checkResp(Member{NodeID: c.nodeID, PubKey: c.pubKey}, st, rh, b, c.p.bind, nonce); err != nil {
		return st, b, err
	}
	return st, b, nil
}

// BoundNonce ist die Nonce einer gebundenen Anfrage (vom Aufrufer, geht in dessen Anmeldung und in die Antwort ein).
func BoundNonce(r *http.Request) string { return r.Header.Get(hdrNonce) }

// HandleBound prueft TLS, leitet die Bindung ab und signiert die Antwort von h mit dem Schluessel dieser Node. Die
// Anmeldung des Aufrufers prueft h selbst (mit bind); ohne TLS kommt die Anfrage nicht an h.
func (m *Manager) HandleBound(h func(w http.ResponseWriter, r *http.Request, bind, body []byte)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			rejectPlain(w)
			return
		}
		bind, err := tlsBind(r.TLS)
		sw := &sigWriter{hdr: http.Header{}}
		defer m.sendSigned(w, sw, r, bind)
		if err != nil {
			writeJSON(sw, http.StatusForbidden, map[string]string{"error": ErrTLSBinding.Error()})
			return
		}
		nonce := r.Header.Get(hdrNonce)
		if len(nonce) < 16 || len(nonce) > 64 {
			writeJSON(sw, http.StatusUnauthorized, map[string]string{"error": "bad request"})
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBoundBody+1))
		if err != nil || len(body) > maxBoundBody {
			writeJSON(sw, http.StatusRequestEntityTooLarge, map[string]string{"error": "request too large"})
			return
		}
		h(sw, r, bind, body)
	})
}

// NodeID ist die Kennung dieser Node.
func (m *Manager) NodeID() string { return m.d.NodeID() }

// NonceCache merkt sich Nonces gebundener Anfragen, solange ihr Zeitstempel gilt (Wiederholung abgelehnt). Hart
// begrenzt: ist er nach dem Aufraeumen voll, wird abgelehnt (lieber eine echte Anfrage spaeter als unbegrenzt Speicher).
type NonceCache struct {
	TTL time.Duration // so lange gilt eine Anfrage (Zeitstempel +/- Toleranz)
	Max int           // hoechstens so viele Eintraege
	mu  sync.Mutex
	m   map[string]time.Time
}

// Fresh merkt sich n (false = schon gesehen oder voll).
func (c *NonceCache) Fresh(n string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]time.Time{}
	}
	if _, seen := c.m[n]; seen {
		return false
	}
	if len(c.m) >= c.Max/2 {
		for k, t := range c.m {
			if now.Sub(t) > c.TTL {
				delete(c.m, k)
			}
		}
	}
	if len(c.m) >= c.Max {
		return false
	}
	c.m[n] = now
	return true
}
