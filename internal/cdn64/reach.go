package cdn64

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Erreichbarkeit der Ziele: jedes Ziel eines eingeschalteten Hosts wird jede Minute geprueft (TCP-Verbindung,
// bei http/https dazu eine kurze HEAD-Anfrage; jede HTTP-Antwort zaehlt als erreichbar). Eine Goroutine fuer
// alle, hoechstens 8 Pruefungen gleichzeitig.

const (
	reachEvery   = time.Minute
	reachTimeout = 5 * time.Second
	reachSlow    = 1500 * time.Millisecond
	reachWorkers = 8
)

// Zustaende.
const (
	ReachUnknown = "unknown"
	ReachUp      = "up"
	ReachSlow    = "slow"
	ReachDown    = "down"
)

// Reach ist der letzte Stand eines Ziels.
type Reach struct {
	State   string    `json:"state"`
	Ms      int64     `json:"ms,omitempty"`
	Error   string    `json:"error,omitempty"`
	Checked time.Time `json:"checked_at,omitzero"`
	Since   time.Time `json:"since,omitzero"` // Zustand seit
}

type reacher struct {
	mu    sync.Mutex
	state map[int64]Reach
	kick  chan int64
}

func newReacher() *reacher { return &reacher{state: map[int64]Reach{}, kick: make(chan int64, 16)} }

func (r *reacher) get(id int64) Reach {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.state[id]; ok {
		return s
	}
	return Reach{State: ReachUnknown}
}

func (r *reacher) set(id int64, s Reach) {
	r.mu.Lock()
	defer r.mu.Unlock()
	old := r.state[id]
	s.Since = old.Since
	if old.State != s.State || old.Since.IsZero() {
		s.Since = s.Checked
	}
	r.state[id] = s
}

func (r *reacher) forget(id int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.state, id)
}

// checkSoon prueft einen Host gleich (nach dem Speichern).
func (m *Module) checkSoon(id int64) {
	select {
	case m.reach.kick <- id:
	default:
	}
}

func (m *Module) reachLoop(ctx context.Context) {
	t := time.NewTicker(reachEvery)
	defer t.Stop()
	m.checkAll(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.checkAll(ctx)
		case id := <-m.reach.kick:
			if id == 0 {
				m.checkAll(ctx)
			} else if h, err := m.host(ctx, id); err == nil && h.Enabled {
				m.reach.set(id, m.probe(ctx, h))
			}
		}
	}
}

func (m *Module) checkAll(ctx context.Context) {
	list, err := m.hosts(ctx)
	if err != nil {
		return
	}
	sem := make(chan struct{}, reachWorkers)
	var wg sync.WaitGroup
	for _, h := range list {
		if !h.Enabled {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(h *Host) {
			defer wg.Done()
			defer func() { <-sem }()
			m.reach.set(h.ID, m.probe(ctx, h))
		}(h)
	}
	wg.Wait()
}

// probe prueft ein Ziel.
func (m *Module) probe(ctx context.Context, h *Host) Reach {
	start := time.Now()
	addr := net.JoinHostPort(h.TargetHost, strconv.Itoa(h.TargetPort))
	cctx, cancel := context.WithTimeout(ctx, reachTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(cctx, "tcp", addr)
	if err != nil {
		return Reach{State: ReachDown, Error: shortErr(err), Checked: time.Now()}
	}
	_ = conn.Close()
	req, err := http.NewRequestWithContext(cctx, http.MethodHead, h.Target()+"/", nil)
	if err == nil {
		req.Host = h.Names[0]
		req.Header.Set("User-Agent", "Node64-CDN64-Check")
		req.Header.Set(loopHeader, "check")
		cl := &http.Client{Transport: m.transport(h.VerifyTarget), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := cl.Do(req)
		if err != nil {
			return Reach{State: ReachDown, Error: shortErr(err), Checked: time.Now()}
		}
		_ = resp.Body.Close()
	}
	d := time.Since(start)
	s := Reach{State: ReachUp, Ms: d.Milliseconds(), Checked: time.Now()}
	if d > reachSlow {
		s.State = ReachSlow
	}
	return s
}

func shortErr(err error) string {
	s := err.Error()
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
