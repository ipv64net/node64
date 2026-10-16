package dns64

import (
	"context"
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/certs"
)

// Zertifikate aus der zentralen Verwaltung des Kerns (internal/certs):
//   - "central": ein Zertifikat der Verwaltung (z. B. Let's Encrypt), fest per Kennung (dns64.cert_id);
//   - "self": die Heimnetz-CA liegt in der Verwaltung, das Server-Zertifikat stellt sie fuer DNS64 aus und neu
//     aus, wenn sich Namen oder IPs aendern (EnsureIssued).
// Erneuert die Verwaltung ein Zertifikat, tauscht DNS64 es ohne Neustart (OnChange -> m.cur).
// Beim ersten Start mit Verwaltung zieht DNS64 einmal um: die eigene CA (gleicher Schluessel, die Geraete vertrauen
// ihr weiter) und ein vorhandenes Let's-Encrypt-Zertifikat samt Schluessel. Die Dateien in tls/ und acme/ bleiben
// als Rueckfall liegen. Ohne Verwaltung (Tests) laeuft alles wie bisher.

const (
	certCentral    = "central"
	setCertID      = "dns64.cert_id"          // Kennung bei "central"
	setCAID        = "dns64.ca_id"            // Heimnetz-CA in der Verwaltung
	setCentralDone = "dns64.central_migrated" // Umzug erledigt (Zeitpunkt)
	caName         = "DNS64 Heimnetz-CA"
	certOwner      = Name // Abnehmer fuer EnsureIssued und "benutzt von"
)

// SetCerts setzt die zentrale Zertifikatsverwaltung (vor dem Start).
func (m *Module) SetCerts(c *certs.Manager) {
	m.certs = c
	c.OnChange(m.certChanged)
	c.SetUsers(certOwner, func(context.Context) map[int64][]string {
		if id := m.certInUse.Load(); id > 0 {
			return map[int64][]string{id: {"DNS64"}}
		}
		return nil
	})
}

// migrateCentral zieht einmal in die Verwaltung um (beim Start, m.mu gehalten). Scheitert etwas, bleibt alles,
// wie es war, und es wird beim naechsten Start wieder versucht.
func (m *Module) migrateCentral(ctx context.Context, c *config) {
	if m.certs == nil || m.core.SettingOr(ctx, setCentralDone, "") != "" {
		return
	}
	if err := m.doMigrate(ctx, c); err != nil {
		m.log.Warn("dns64 certificates not moved to the certificate management yet", "err", err)
		return
	}
	_ = m.core.SetSetting(ctx, setCentralDone, time.Now().UTC().Format(time.RFC3339))
}

func (m *Module) doMigrate(ctx context.Context, c *config) error {
	if _, err := os.Stat(m.caFile()); err == nil {
		if _, err := m.centralCA(ctx); err != nil {
			return err
		}
	}
	if c.CertMode != certACME || acmeName(*c) == "" {
		return nil
	}
	if err := m.centralAccount(ctx, *c); err != nil {
		return err
	}
	var id int64
	certPEM, err1 := os.ReadFile(filepath.Join(m.acmeDir(), "cert.pem"))
	keyPEM, err2 := os.ReadFile(filepath.Join(m.acmeDir(), "key.pem"))
	if crt, leaf := m.acmeCert(acmeName(*c)); crt != nil && err1 == nil && err2 == nil && time.Now().Before(leaf.NotAfter) {
		got, err := m.certs.ImportIssued(ctx, certs.ImportRequest{Source: certs.SourceIPv64, Staging: c.ACMEStaging, CertPEM: string(certPEM), KeyPEM: string(keyPEM)})
		if err != nil {
			return err
		}
		id = got.ID
	} else { // eingerichtet, aber noch kein Zertifikat: die Verwaltung holt es
		got, err := m.certs.Create(ctx, certs.Request{Names: []string{acmeName(*c)}, Source: certs.SourceIPv64, Staging: c.ACMEStaging})
		if err != nil {
			return err
		}
		id = got.ID
	}
	c.CertMode, c.CertID = certCentral, id
	return m.saveConfig(ctx, *c)
}

// centralAccount uebertraegt die Zustimmung zu den Nutzungsbedingungen von Let's Encrypt (in DNS64 gegeben) in die
// Verwaltung, falls sie dort noch fehlt; eine dort schon eingetragene Mail bleibt.
func (m *Module) centralAccount(ctx context.Context, c config) error {
	acc := m.certs.Account(ctx)
	if acc.TOSAccepted {
		return nil
	}
	if m.core.SettingOr(ctx, setACMETOS, "") == "" {
		return errors.New("let's encrypt terms not accepted")
	}
	email := acc.Email
	if email == "" {
		email = c.ACMEEmail
	}
	return m.certs.SetAccount(ctx, email, true)
}

// centralCA: die Heimnetz-CA in der Verwaltung (beim ersten Mal aus tls/ca.pem uebernommen bzw. neu erzeugt).
func (m *Module) centralCA(ctx context.Context) (int64, error) {
	if id, _ := strconv.ParseInt(m.core.SettingOr(ctx, setCAID, ""), 10, 64); id > 0 {
		if _, err := m.certs.GetCA(ctx, id); err == nil {
			return id, nil
		}
	}
	if _, _, err := m.loadOrCreateCA(); err != nil {
		return 0, err
	}
	certPEM, err := os.ReadFile(m.caFile())
	if err != nil {
		return 0, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(m.tlsDir(), "ca.key"))
	if err != nil {
		return 0, err
	}
	ca, err := m.certs.EnsureCA(ctx, caName, string(certPEM), string(keyPEM))
	if err != nil {
		return 0, err
	}
	return ca.ID, m.core.SetSetting(ctx, setCAID, strconv.FormatInt(ca.ID, 10))
}

// centralSelf: Server-Zertifikat der Heimnetz-CA aus der Verwaltung (Namen und private IPs der Node).
func (m *Module) centralSelf(ctx context.Context, c config) (*tls.Certificate, int64, error) {
	caID, err := m.centralCA(ctx)
	if err != nil {
		return nil, 0, err
	}
	dnsNames, ips := wantedNames(c.Names)
	// passt das vorhandene, ohne die Verwaltung zu bemuehen (EnsureIssued wartet auf laufende Abrufe)
	if own, err := m.certs.Owned(ctx, certOwner); err == nil && own.CAID == caID && time.Until(own.NotAfter) > renewDays*24*time.Hour {
		if crt := m.certs.ByID(own.ID); crt != nil && covers(crt.Leaf, dnsNames, ips) {
			return crt, own.ID, nil
		}
	}
	names := slices.Clone(dnsNames)
	for _, ip := range ips {
		names = append(names, ip.String())
	}
	got, err := m.certs.EnsureIssued(ctx, certOwner, caID, names, leafDays)
	if err != nil {
		return nil, 0, err
	}
	crt := m.certs.ByID(got.ID)
	if crt == nil {
		return nil, 0, errors.New("issued certificate not loadable")
	}
	return crt, got.ID, nil
}

// certChanged: die Verwaltung hat ein Zertifikat neu ausgestellt bzw. erneuert. Ist es das von DNS64, gilt es
// sofort (m.cur); aendern sich dabei die Namen, startet DNS64 neu (Anmeldung beim Eingang).
func (m *Module) certChanged(id int64) {
	if m.certs == nil || id != m.certInUse.Load() {
		return
	}
	crt := m.certs.ByID(id)
	if crt == nil {
		return
	}
	m.mu.Lock()
	e := m.eng
	var restart bool
	if e != nil && e.enc != nil {
		m.cur.Store(crt)
		e.enc.notAfter = crt.Leaf.NotAfter
		restart = !slices.Equal(sorted(certNames(crt.Leaf)), sorted(e.enc.names))
	}
	m.mu.Unlock()
	if e == nil {
		return
	}
	m.log.Info("dns64 certificate updated from the certificate management", "id", id)
	if restart {
		_ = m.restart(context.Background())
	}
}

func sorted(s []string) []string {
	s = slices.Clone(s)
	slices.Sort(s)
	return s
}

// centralOpt: ein Zertifikat der Verwaltung zur Auswahl auf der Seite.
type centralOpt struct {
	ID       int64
	Title    string
	Issuer   string
	NotAfter time.Time
}

// centralList: gueltige Zertifikate der Verwaltung zur Auswahl (ohne das, das DNS64 selbst fuer die CA haelt).
func (m *Module) centralList(ctx context.Context) []centralOpt {
	if m.certs == nil {
		return nil
	}
	list, err := m.certs.List(ctx)
	if err != nil {
		return nil
	}
	owned, _ := m.certs.Owned(ctx, certOwner)
	var out []centralOpt
	for _, c := range list {
		if c.Status != certs.StatusValid || (owned != nil && c.ID == owned.ID) {
			continue
		}
		out = append(out, centralOpt{ID: c.ID, Title: strings.Join(c.Names, ", "), Issuer: c.Issuer, NotAfter: c.NotAfter})
	}
	return out
}
