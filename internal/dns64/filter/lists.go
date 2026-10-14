package filter

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"
)

type List struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// DefaultLists is the "balanced" preset: good coverage with few false positives.
var DefaultLists = []List{
	{"StevenBlack Unified", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"},
	{"AdGuard DNS Filter", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"},
	{"OISD Small", "https://small.oisd.nl/"},
	{"HaGeZi Multi Normal", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt"},
	{"EasyPrivacy", "https://easylist.to/easylist/easyprivacy.txt"},
	{"URLhaus Malware", "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-agh.txt"},
}

const (
	updateInterval = 24 * time.Hour
	maxListSize    = 64 << 20
)

type ListStatus struct {
	List
	Rules     int       `json:"rules"`
	UpdatedAt time.Time `json:"updatedAt"`
	Error     string    `json:"error,omitempty"`
}

// Manager downloads the blocklists, keeps them cached on disk and publishes
// a fresh Matcher after every update without interrupting DNS traffic.
type Manager struct {
	dir    string
	lists  []List
	client *http.Client
	log    *slog.Logger
	Allow  *Allowlist

	cur       atomic.Pointer[Matcher]
	rebuildMu sync.Mutex // one rebuild at a time; parallel downloads trigger it

	mu      sync.RWMutex
	status  []ListStatus
	updated time.Time
}

func NewManager(dir string, allow *Allowlist, client *http.Client, log *slog.Logger) (*Manager, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	m := &Manager{dir: dir, lists: DefaultLists, client: client, log: log, Allow: allow}
	m.status = make([]ListStatus, len(m.lists))
	for i, l := range m.lists {
		m.status[i].List = l
	}
	// Serve cached lists right away; downloads happen in Run.
	m.rebuild()
	return m, nil
}

func (m *Manager) Matcher() *Matcher { return m.cur.Load() }

// Check decides whether name is blocked. reason names the blocking list, or
// notes that a released domain would otherwise have been blocked.
func (m *Manager) Check(name string) (blocked bool, reason string) {
	blocked, list := m.cur.Load().Match(name)
	if blocked && m.Allow.Contains(name) {
		return false, "Freigegeben (sonst: " + list + ")"
	}
	return blocked, list
}

func (m *Manager) Status() ([]ListStatus, time.Time) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]ListStatus(nil), m.status...), m.updated
}

// Run refreshes stale lists immediately and then once per updateInterval.
func (m *Manager) Run(ctx context.Context) {
	wait := 2 * time.Second // let the DNS listener come up; downloads resolve through it
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if m.refresh(ctx) {
			wait = 5 * time.Minute
		} else {
			wait = time.Hour
		}
	}
}

func (m *Manager) path(i int) string { return filepath.Join(m.dir, fmt.Sprintf("list-%d.txt", i)) }

// refresh downloads stale lists in parallel and reports whether any download
// failed. Each list goes live as soon as it arrives, so one slow server does
// not hold back the others.
func (m *Manager) refresh(ctx context.Context) (failed bool) {
	var wg sync.WaitGroup
	for i, l := range m.lists {
		if fi, err := os.Stat(m.path(i)); err == nil && time.Since(fi.ModTime()) < updateInterval {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := m.download(ctx, l.URL, m.path(i))
			m.mu.Lock()
			if err != nil {
				failed = true
				m.status[i].Error = err.Error()
				m.log.Warn("blocklist download failed", "list", l.Name, "err", err)
			} else {
				m.status[i].Error = ""
			}
			m.mu.Unlock()
			if err == nil {
				m.rebuild()
			}
		}()
	}
	wg.Wait()
	return failed
}

func (m *Manager) download(ctx context.Context, url, dst string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "dns64/1.0")
	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %s", resp.Status)
	}
	tmp := dst + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(resp.Body, maxListSize))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n == 0 {
		err = fmt.Errorf("empty response")
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

func (m *Manager) rebuild() {
	m.rebuildMu.Lock()
	defer m.rebuildMu.Unlock()
	start := time.Now()
	names := make([]string, len(m.lists))
	for i, l := range m.lists {
		names[i] = l.Name
	}
	mt := newMatcher(names)
	counts := make([]int, len(m.lists))
	mtimes := make([]time.Time, len(m.lists))
	for i := range m.lists {
		f, err := os.Open(m.path(i))
		if err != nil {
			continue
		}
		if fi, err := f.Stat(); err == nil {
			mtimes[i] = fi.ModTime()
		}
		counts[i], err = mt.load(uint8(i), f)
		f.Close()
		if err != nil {
			m.log.Warn("blocklist parse error", "list", m.lists[i].Name, "err", err)
		}
	}
	m.cur.Store(mt)

	m.mu.Lock()
	for i := range m.status {
		m.status[i].Rules = counts[i]
		m.status[i].UpdatedAt = mtimes[i]
	}
	m.updated = time.Now()
	m.mu.Unlock()

	// The old matcher can be large; hand the memory back promptly.
	debug.FreeOSMemory()
	m.log.Info("blocklists loaded", "domains", mt.Size(), "took", time.Since(start).Round(time.Millisecond))
}
