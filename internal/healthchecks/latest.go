package healthchecks

// Neueste Version von Proxmox VE und Docker: nur fuer ein kleines Hinweis-Badge in den Uebersichten, ohne Meldung,
// Ereignis oder Zustand. Abgerufen wird selten (latestEvery) und im Hintergrund; die Seiten lesen nur den Zwischenstand.
// Ohne Antwort oder bei unklarer Version gibt es kein Badge.
//
//   - Docker Engine: Verzeichnis der statischen Pakete download.docker.com/linux/static/stable/x86_64/ (docker-X.Y.Z.tgz;
//     ohne Anmeldung, ohne Ratenlimit wie bei der GitHub-API, nur stabile Versionen).
//   - Proxmox VE: Version von pve-manager im Repository pve-no-subscription (download.proxmox.com) der Debian-Version zur
//     Hauptversion (8 = bookworm, 9 = trixie, 10 = forky); /version des Systems meldet dieselbe Paketversion. Gelesen
//     wird die Hauptversion des Systems und die naechste (neue Hauptversion nur ohne Update in der eigenen Linie).
//   - Proxmox Backup Server: ebenso, Paket proxmox-backup-server im Repository pbs-no-subscription (3 = bookworm,
//     4 = trixie, 5 = forky); /version des PBS meldet Version und Release ("4.0" + "11" = 4.0.11).

import (
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/proxmox"
)

const (
	latestEvery = 12 * time.Hour // erfolgreicher Abruf gilt so lange
	latestRetry = time.Hour      // nach einem Fehler erst wieder nach dieser Zeit
)

// pveDists bzw. pbsDists: Hauptversion von Proxmox VE bzw. Backup Server -> Debian-Version des Repositorys.
var (
	pveDists = map[int]string{8: "bookworm", 9: "trixie", 10: "forky"}
	pbsDists = map[int]string{3: "bookworm", 4: "trixie", 5: "forky"}
)

// pxRepo ist das Repository eines Proxmox-Produkts (latestPVE).
type pxRepo struct {
	dists         map[int]string
	path, pkg, ky string // Pfad unter debian/, Paket, Schluessel im Zwischenstand ("pve" bzw. "pbs")
}

var (
	pveRepo = pxRepo{pveDists, "pve/dists/%s/pve-no-subscription", "pve-manager", "pve"}
	pbsRepo = pxRepo{pbsDists, "pbs/dists/%s/pbs-no-subscription", "proxmox-backup-server", "pbs"}
)

type fetchFunc func(ctx context.Context, url string) (io.ReadCloser, error)

// latestFetch holt eine Adresse (in Tests ersetzt).
var latestFetch fetchFunc = func(ctx context.Context, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "node64")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return resp.Body, nil
}

// latestEntry ist der Zwischenstand einer Quelle ("docker", "pve/<Hauptversion>" bzw. "pbs/<Hauptversion>").
type latestEntry struct {
	version string // "" = unbekannt
	at      time.Time
	ok      bool
	running bool
}

var latest = struct {
	mu sync.Mutex
	m  map[string]*latestEntry
}{m: map[string]*latestEntry{}}

// latestGet liefert die bekannte neueste Version einer Quelle und stoesst bei Bedarf den Abruf im Hintergrund an.
func latestGet(key string) string {
	latest.mu.Lock()
	defer latest.mu.Unlock()
	e := latest.m[key]
	if e == nil {
		e = &latestEntry{}
		latest.m[key] = e
	}
	wait := latestRetry
	if e.ok {
		wait = latestEvery
	}
	if !e.running && (e.at.IsZero() || time.Since(e.at) >= wait) {
		e.running = true
		go latestRefresh(key)
	}
	return e.version
}

func latestRefresh(key string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var v string
	var err error
	if key == "docker" {
		v, err = latestDocker(ctx, latestFetch)
	} else if major, e := strconv.Atoi(strings.TrimPrefix(key, "pve/")); e == nil {
		v, err = latestPVE(ctx, latestFetch, pveRepo, major)
	} else if major, e := strconv.Atoi(strings.TrimPrefix(key, "pbs/")); e == nil {
		v, err = latestPVE(ctx, latestFetch, pbsRepo, major)
	}
	latest.mu.Lock()
	defer latest.mu.Unlock()
	e := latest.m[key]
	if e == nil {
		return
	}
	e.running, e.at, e.ok = false, time.Now(), err == nil && v != ""
	if e.ok {
		e.version = v
	}
}

var dockerTgz = regexp.MustCompile(`docker-(\d+\.\d+\.\d+)\.tgz`)

// latestDocker: hoechste Version im Verzeichnis der statischen Pakete.
func latestDocker(ctx context.Context, fetch fetchFunc) (string, error) {
	body, err := fetch(ctx, "https://download.docker.com/linux/static/stable/x86_64/")
	if err != nil {
		return "", err
	}
	defer body.Close()
	b, err := io.ReadAll(io.LimitReader(body, 1<<20))
	if err != nil {
		return "", err
	}
	best := ""
	for _, m := range dockerTgz.FindAllStringSubmatch(string(b), -1) {
		if best == "" || verCompare(m[1], best) > 0 {
			best = m[1]
		}
	}
	return best, nil
}

// latestPVE: hoechste Version des Pakets (pve-manager bzw. proxmox-backup-server) im Repository der Hauptversion
// (Packages.gz, zeilenweise gelesen).
func latestPVE(ctx context.Context, fetch fetchFunc, repo pxRepo, major int) (string, error) {
	dist := repo.dists[major]
	if dist == "" {
		return "", fmt.Errorf("unknown major %d", major)
	}
	body, err := fetch(ctx, "http://download.proxmox.com/debian/"+fmt.Sprintf(repo.path, dist)+"/binary-amd64/Packages.gz")
	if err != nil {
		return "", err
	}
	defer body.Close()
	zr, err := gzip.NewReader(io.LimitReader(body, 64<<20))
	if err != nil {
		return "", err
	}
	return debPkgVersion(zr, repo.pkg)
}

// pveManagerVersion sucht in einer Debian-Paketliste die hoechste Version von pve-manager.
func pveManagerVersion(r io.Reader) (string, error) { return debPkgVersion(r, "pve-manager") }

// debPkgVersion sucht in einer Debian-Paketliste die hoechste Version eines Pakets.
func debPkgVersion(r io.Reader, pkg string) (string, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	best, in := "", false
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "Package: "):
			in = line == "Package: "+pkg
		case in && strings.HasPrefix(line, "Version: "):
			if v := strings.TrimPrefix(line, "Version: "); verCore(v) != "" && (best == "" || verCompare(v, best) > 0) {
				best = v
			}
		}
	}
	return verCore(best), sc.Err()
}

var verRe = regexp.MustCompile(`^v?(\d+)\.(\d+)(?:\.(\d+))?`)

// verCore: "X.Y.Z" vom Anfang einer Versionsangabe ("28.5.1+dfsg1", "9.0.11~1" -> "28.5.1", "9.0.11"), sonst "".
func verCore(v string) string {
	m := verRe.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return ""
	}
	if m[3] == "" {
		m[3] = "0"
	}
	return m[1] + "." + m[2] + "." + m[3]
}

func verParts(v string) [3]int {
	var p [3]int
	for i, s := range strings.SplitN(verCore(v), ".", 3) {
		p[i], _ = strconv.Atoi(s)
	}
	return p
}

// verCompare vergleicht X.Y.Z (-1, 0, 1).
func verCompare(a, b string) int {
	pa, pb := verParts(a), verParts(b)
	for i := range pa {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// verUpdate ist der Hinweis auf eine neuere Version (Badge in der Uebersicht).
type verUpdate struct {
	Installed string
	Latest    string
	Major     bool // neue Hauptversion
}

// latestUpdate: neuere Version fuer ein System (Art pve, pbs bzw. docker) mit der gemeldeten Version, sonst nil.
func latestUpdate(kind, installed string) *verUpdate {
	cur := verCore(installed)
	if cur == "" {
		return nil
	}
	if kind == proxmox.KindDocker {
		if l := latestGet("docker"); l != "" && verCompare(l, cur) > 0 {
			return &verUpdate{Installed: cur, Latest: l, Major: verParts(l)[0] > verParts(cur)[0]}
		}
		return nil
	}
	repo := pveRepo
	if kind == proxmox.KindPBS {
		repo = pbsRepo
	}
	major := verParts(cur)[0]
	if repo.dists[major] == "" {
		return nil
	}
	// zuerst ein Update in der eigenen Linie (direkt einspielbar), sonst eine neue Hauptversion
	if l := latestGet(fmt.Sprintf("%s/%d", repo.ky, major)); l != "" && verCompare(l, cur) > 0 {
		return &verUpdate{Installed: cur, Latest: l}
	}
	if repo.dists[major+1] != "" {
		if l := latestGet(fmt.Sprintf("%s/%d", repo.ky, major+1)); l != "" && verParts(l)[0] == major+1 {
			return &verUpdate{Installed: cur, Latest: l, Major: true}
		}
	}
	return nil
}

// aptUpdate: Hinweis aus der Paketliste des Systems selbst (PBS: apt/update), sonst nil.
func aptUpdate(installed, available string) *verUpdate {
	cur, l := verCore(installed), verCore(available)
	if cur == "" || l == "" || verCompare(l, cur) <= 0 {
		return nil
	}
	return &verUpdate{Installed: cur, Latest: l, Major: verParts(l)[0] > verParts(cur)[0]}
}
