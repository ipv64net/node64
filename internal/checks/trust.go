package checks

import (
	"crypto/x509"
	"sync"
	"sync/atomic"
	"time"
)

// Zusaetzliche Vertrauensanker fuer HTTPS- und Zertifikats-Checks: Auf der Node setzt main die eigenen CAs der
// Zertifikatsverwaltung (System-CAs plus eigene CAs, #190 - Dienste mit Zertifikat einer eigenen CA galten sonst als
// "certificate signed by unknown authority"). Ohne Quelle (hubs, Tests) gelten nur die System-CAs.
var trustSource atomic.Pointer[func() (*x509.CertPool, error)]

// SetTrustPool setzt die Quelle der Vertrauensanker (nil = nur System-CAs). Sie liefert nil, solange es keine eigene
// CA gibt, und einen Fehler, wenn sie die CAs nicht lesen konnte.
func SetTrustPool(f func() (*x509.CertPool, error)) {
	if f == nil {
		trustSource.Store(nil)
	} else {
		trustSource.Store(&f)
	}
	trustCache.Lock()
	trustCache.pool, trustCache.at = nil, time.Time{}
	trustCache.Unlock()
}

// trustCache haelt den Pool eine Minute (die Quelle liest die Datenbank, Checks laufen sehr oft). Ein Lesefehler wird
// nicht gemerkt (sonst galten Dienste mit Zertifikat einer eigenen CA eine Minute als "unknown authority"): es gilt
// der bisherige Pool, der naechste Check fragt erneut.
var trustCache struct {
	sync.Mutex
	pool *x509.CertPool
	at   time.Time
}

const trustTTL = time.Minute

// trustRoots: Roots fuer die Pruefung; nil = System-CAs.
func trustRoots() *x509.CertPool {
	f := trustSource.Load()
	if f == nil {
		return nil
	}
	trustCache.Lock()
	defer trustCache.Unlock()
	if time.Since(trustCache.at) > trustTTL {
		if pool, err := (*f)(); err == nil {
			trustCache.pool, trustCache.at = pool, time.Now()
		}
	}
	return trustCache.pool
}
