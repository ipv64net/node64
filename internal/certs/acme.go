package certs

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/store"
)

const (
	letsEncrypt        = acme.LetsEncryptURL
	letsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// start holt ein Zertifikat im Hintergrund (je Zertifikat hoechstens ein Abruf gleichzeitig).
func (m *Manager) start(id int64, reason string) error {
	m.mu.Lock()
	if m.steps[id] != "" {
		m.mu.Unlock()
		return ErrBusy
	}
	if m.base.Err() != nil {
		m.mu.Unlock()
		return errors.New("certificate manager stopped")
	}
	m.steps[id] = "queued"
	m.bg.Add(1)
	m.mu.Unlock()
	go func() {
		defer m.bg.Done()
		defer func() {
			m.mu.Lock()
			delete(m.steps, id)
			m.mu.Unlock()
		}()
		m.issue(m.base, id, reason) // Zeitlimit setzt obtain erst nach der ACME-Sperre (Warten zaehlt nicht)
	}()
	return nil
}

func (m *Manager) step(id int64, s string) {
	m.mu.Lock()
	if _, ok := m.steps[id]; ok {
		m.steps[id] = s
	}
	m.mu.Unlock()
	m.log.Debug("acme", "cert", id, "step", s)
}

// issue fuehrt einen Abruf aus und haelt Ergebnis, Fehler und Meldungen fest.
func (m *Manager) issue(ctx context.Context, id int64, reason string) {
	c, err := m.Get(ctx, id)
	if err != nil {
		return
	}
	prevStatus := c.Status
	m.log.Info("certificate requested", "cert", id, "names", strings.Join(c.Names, ","), "source", c.Source, "reason", reason)
	err = m.obtain(ctx, c)
	now := store.Now()
	if err != nil {
		if m.base.Err() != nil {
			return // Node wird beendet: kein Fehler festhalten
		}
		msg := notify.RedactSecrets(err.Error()) // DNS-Provider liefern teils Zugangsdaten in Fehlertexten (z. B. URL mit token=)
		if len(msg) > 500 {
			msg = msg[:500]
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			// Zeitlimit: Fehler nur festhalten, Status bleibt; die Erneuerung versucht es beim naechsten Lauf
			// wieder (nicht erst nach retryAfter) und meldet nichts
			_, _ = m.w.ExecContext(context.WithoutCancel(ctx), `UPDATE certs SET last_error = ?, last_attempt = ?, updated_at = ? WHERE id = ?`,
				msg, now, now, id)
			m.changed(context.WithoutCancel(ctx), ItemCertificates, id)
			m.log.Warn("certificate not obtained in time, retrying later", "cert", id, "names", c.Title(), "err", msg)
			return
		}
		_, _ = m.w.ExecContext(context.WithoutCancel(ctx), `UPDATE certs SET status = ?, last_error = ?, last_attempt = ?, updated_at = ? WHERE id = ?`,
			StatusError, msg, now, now, id)
		m.changed(context.WithoutCancel(ctx), ItemCertificates, id)
		m.log.Error("certificate not obtained", "cert", id, "names", c.Title(), "err", msg)
		if prevStatus != StatusError { // einmal je Stoerung
			m.alert(c, notify.KindCertFail, msg, "")
		}
		return
	}
	m.log.Info("certificate obtained", "cert", id, "names", c.Title())
	if prevStatus == StatusError {
		m.alert(c, notify.KindCertOK, "", "")
	}
}

// client liefert den ACME-Client fuer die Stelle (Konto wird beim ersten Abruf angemeldet).
func (m *Manager) client(ctx context.Context, staging bool) (*acme.Client, error) {
	key, err := m.accountKey(ctx)
	if err != nil {
		return nil, err
	}
	dir := m.d.Directory
	if dir == "" {
		dir = letsEncrypt
	}
	if staging {
		dir = m.d.StagingDirectory
		if dir == "" {
			dir = letsEncryptStaging
		}
	}
	cl := &acme.Client{Key: key, DirectoryURL: dir, UserAgent: "Node64/" + m.d.Version}
	m.mu.Lock()
	done := m.reg[dir]
	m.mu.Unlock()
	if done {
		return cl, nil
	}
	acct := &acme.Account{}
	if e := m.Account(ctx).Email; e != "" {
		acct.Contact = []string{"mailto:" + e}
	}
	if _, err := cl.Register(ctx, acct, acme.AcceptTOS); err != nil {
		if !errors.Is(err, acme.ErrAccountAlreadyExists) {
			return nil, fmt.Errorf("account: %w", err)
		}
		if len(acct.Contact) > 0 {
			_, _ = cl.UpdateReg(ctx, acct) // Kontaktadresse aktuell halten
		}
	}
	m.mu.Lock()
	m.reg[dir] = true
	m.mu.Unlock()
	return cl, nil
}

// accountKey laedt bzw. erzeugt den Kontoschluessel (verschluesselt in den Einstellungen).
func (m *Manager) accountKey(ctx context.Context) (crypto.Signer, error) {
	if sealed := m.d.Store.SettingOr(ctx, setKey, ""); sealed != "" {
		raw, err := m.d.Box.Decrypt(sealed)
		if err != nil {
			return nil, fmt.Errorf("account key: %w", err)
		}
		if b, _ := pem.Decode([]byte(raw)); b != nil {
			if k, err := x509.ParseECPrivateKey(b.Bytes); err == nil {
				return k, nil
			}
		}
		return nil, errors.New("account key unreadable")
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}
	if err := m.d.Store.SetSetting(ctx, setKey, m.d.Box.Encrypt(string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})))); err != nil {
		return nil, err
	}
	m.changedUID(ctx, ItemACME, clusterAccount, false)
	return k, nil
}

// obtain: Auftrag, Pruefungen je Name, Zertifikat.
func (m *Manager) obtain(ctx context.Context, c *Cert) error {
	if c.Source == SourceCA || c.Source == SourceSelf { // eigene CA: sofort, nicht hinter einem laufenden ACME-Abruf
		ctx, cancel := context.WithTimeout(ctx, m.issueTimeout)
		defer cancel()
		if c.Source == SourceSelf {
			return m.issueSelfSigned(ctx, c)
		}
		return m.issueFromCA(ctx, c)
	}
	m.acme.Lock() // ACME nacheinander: schont die Rate-Limits und die ipv64-API
	defer m.acme.Unlock()
	ctx, cancel := context.WithTimeout(ctx, m.issueTimeout) // erst nach der Sperre: wartende Abrufe laufen nicht ab
	defer cancel()
	if c.ACMECA == 0 && !m.Account(ctx).TOSAccepted {
		return ErrTOS
	}
	switch c.Source {
	case SourceIPv64, SourceAlias:
		if m.d.DNS == nil || !m.d.DNS.Ready(ctx) {
			return ErrNoKey
		}
	case SourceHTTP:
		if m.d.HTTP == nil {
			return errors.New("http-01 not available")
		}
	case SourceDNS:
	default:
		return ErrUpload
	}
	if c.Source == SourceAlias {
		m.step(c.ID, "cname")
		if err := m.checkAlias(ctx, c); err != nil {
			return err
		}
	}
	m.step(c.ID, "account")
	cl, err := m.clientFor(ctx, c)
	if err != nil {
		return err
	}
	m.step(c.ID, "order")
	order, err := cl.AuthorizeOrder(ctx, acme.DomainIDs(c.Names...))
	if err != nil {
		return fmt.Errorf("order: %w", err)
	}
	for _, u := range order.AuthzURLs {
		z, err := cl.GetAuthorization(ctx, u)
		if err != nil {
			return fmt.Errorf("authorization: %w", err)
		}
		if z.Status == acme.StatusValid {
			continue
		}
		if err := m.authorize(ctx, cl, c, z); err != nil {
			return err
		}
	}
	m.step(c.ID, "certificate")
	order, err = cl.WaitOrder(ctx, order.URI)
	if err != nil {
		return fmt.Errorf("order: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: c.Names}, key)
	if err != nil {
		return err
	}
	ders, _, err := cl.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return fmt.Errorf("certificate: %w", err)
	}
	if len(ders) == 0 {
		return errors.New("certificate: empty answer")
	}
	leaf, err := x509.ParseCertificate(ders[0])
	if err != nil {
		return fmt.Errorf("certificate: %w", err)
	}
	var chain []byte
	for _, d := range ders {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})...)
	}
	return m.storeIssued(ctx, c.ID, c.Names, string(chain), leaf, key)
}

// authorize beantwortet die Pruefung fuer einen Namen.
func (m *Manager) authorize(ctx context.Context, cl *acme.Client, c *Cert, z *acme.Authorization) error {
	name := z.Identifier.Value
	if z.Wildcard {
		name = "*." + name
	}
	want := "dns-01"
	if c.Source == SourceHTTP {
		want = "http-01"
	}
	var chal *acme.Challenge
	for _, ch := range z.Challenges {
		if ch.Type == want {
			chal = ch
		}
	}
	if chal == nil {
		return fmt.Errorf("%s: no %s challenge offered", name, want)
	}
	var cleanup func()
	if c.Source == SourceDNS { // anderer Anbieter ueber lego: der Anbieter setzt und loescht den TXT-Record selbst
		prov, err := m.dnsProvider(ctx, c.DNSAccount)
		if err != nil {
			return err
		}
		ka, err := cl.HTTP01ChallengeResponse(chal.Token) // Key-Authorization (Token.Fingerabdruck)
		if err != nil {
			return err
		}
		base := strings.TrimPrefix(name, "*.")
		m.step(c.ID, "txt")
		if err := prov.Present(base, chal.Token, ka); err != nil {
			return fmt.Errorf("%s: dns provider: %w", name, err)
		}
		cleanup = func() {
			if err := prov.CleanUp(base, chal.Token, ka); err != nil {
				m.log.Warn("acme TXT record not removed", "name", base, "err", notify.RedactSecrets(err.Error()))
			}
		}
		val, err := cl.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			cleanup()
			return err
		}
		m.step(c.ID, "dns")
		if err := m.txtVisible(ctx, base, "_acme-challenge."+base, val); err != nil {
			cleanup()
			return fmt.Errorf("%s: %w", name, err)
		}
	} else if want == "http-01" {
		ka, err := cl.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return err
		}
		m.step(c.ID, "http")
		release, err := m.d.HTTP.Present(chal.Token, ka)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		cleanup = release
	} else {
		val, err := cl.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return err
		}
		zone, prefix, fqdn := "", "", ""
		if c.Source == SourceAlias {
			zone = c.AliasZone
			prefix, fqdn = aliasTarget(c.AliasZone, c.AliasPrefix)
		} else {
			if zone, prefix, err = m.ipv64Target(ctx, name); err != nil {
				return err
			}
			fqdn = prefix + "." + zone
		}
		m.step(c.ID, "txt")
		if err := m.d.DNS.AddTXT(ctx, zone, prefix, val); err != nil {
			return fmt.Errorf("ipv64 TXT record: %w", err)
		}
		cleanup = func() {
			dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
			defer cancel()
			if err := m.d.DNS.DeleteTXT(dctx, zone, prefix, val); err != nil {
				m.log.Warn("acme TXT record not removed", "zone", zone, "prefix", prefix, "err", notify.RedactSecrets(err.Error()))
			}
		}
		m.step(c.ID, "dns")
		if err := m.txtVisible(ctx, zone, fqdn, val); err != nil {
			cleanup()
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	defer cleanup()
	m.step(c.ID, "validate")
	if _, err := cl.Accept(ctx, chal); err != nil {
		return fmt.Errorf("%s: accept: %w", name, err)
	}
	if _, err := cl.WaitAuthorization(ctx, z.URI); err != nil {
		return fmt.Errorf("%s: validation: %w", name, err)
	}
	return nil
}

// ---------------------------------------------------------------- Erneuerung

// Acquire: ein Abnehmer braucht die Verwaltung; solange es einen gibt, laeuft die Erneuerung.
func (m *Manager) Acquire(owner string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.holds[owner] = true
	if m.stopLp != nil || m.base.Err() != nil {
		return
	}
	ctx, cancel := context.WithCancel(m.base)
	m.stopLp, m.lpDone = cancel, make(chan struct{})
	go m.loop(ctx, m.lpDone)
}

// Release: der Abnehmer braucht sie nicht mehr.
func (m *Manager) Release(owner string) {
	m.mu.Lock()
	delete(m.holds, owner)
	if len(m.holds) > 0 || m.stopLp == nil {
		m.mu.Unlock()
		return
	}
	stop, done := m.stopLp, m.lpDone
	m.stopLp, m.lpDone = nil, nil
	m.mu.Unlock()
	stop()
	<-done
}

func (m *Manager) loop(ctx context.Context, done chan struct{}) {
	defer close(done)
	wait := m.loopFirst
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = m.loopEvery
		m.due(ctx)
	}
}

// due erneuert faellige Zertifikate und warnt vor dem Ablauf.
func (m *Manager) due(ctx context.Context) {
	list, err := m.List(ctx)
	if err != nil {
		m.log.Error("certificates not readable", "err", err)
		return
	}
	for _, c := range list {
		if c.AutoRenew && c.Source != SourceUpload && c.Step == "" && needsRenewal(c) && m.renewHere(ctx, c) { // im Cluster nur eine Node
			_ = m.start(c.ID, "renew")
		}
		m.warnExpiry(ctx, c)
	}
}

func needsRenewal(c *Cert) bool {
	if c.Status == StatusError && time.Since(c.LastAttempt) < retryAfter {
		return false // nach einem Fehler erst in 6 Stunden wieder
	}
	before := renewBefore
	if c.Source == SourceCA || c.Source == SourceSelf {
		before = caRenewBefore(c.Days)
	}
	return !c.hasCert || time.Until(c.NotAfter) < before
}

// caRenewBefore: Zertifikate der eigenen CA werden 30 Tage vor Ablauf erneuert, bei kurzer Laufzeit im letzten
// Drittel (sonst waere ein Zertifikat mit hoechstens 30 Tagen sofort wieder faellig).
func caRenewBefore(days int) time.Duration {
	if d := time.Duration(days) * 24 * time.Hour / 3; days > 0 && d < renewBefore {
		return d
	}
	return renewBefore
}

// warnExpiry meldet einmal 14 und einmal 3 Tage vor Ablauf (benutzte, automatisch erneuerte und hochgeladene
// Zertifikate).
func (m *Manager) warnExpiry(ctx context.Context, c *Cert) {
	if !c.hasCert || (len(c.UsedBy) == 0 && !c.AutoRenew && c.Source != SourceUpload) {
		return
	}
	days, stage := c.DaysLeft(), ""
	switch {
	case days < 0:
		return // abgelaufen: schon gemeldet
	case days <= 3:
		stage = "3"
	case days <= 14:
		stage = "14"
	}
	if stage == "" || c.warned == stage || (c.warned == "3" && stage == "14") || (stage == "14" && c.RenewedBy != "") { // erneuert eine andere Node: erst kurz vor Ablauf
		return
	}
	if _, err := m.w.ExecContext(ctx, `UPDATE certs SET warned = ? WHERE id = ?`, stage, c.ID); err != nil {
		return
	}
	m.alert(c, notify.KindCertExpiry, c.LastError, c.NotAfter.UTC().Format("2006-01-02 15:04 UTC"))
}

func (m *Manager) alert(c *Cert, kind notify.Kind, reason, message string) {
	if m.d.Notify == nil {
		return
	}
	now := time.Now().UTC()
	m.d.Notify(notify.Alert{EventID: fmt.Sprintf("cert-%d-%s-%s", c.ID, kind, now.Format("20060102150405")), Kind: kind, Time: now,
		Check:  notify.CheckInfo{Name: c.Title(), NotifyDown: true, NotifyUp: true, Local: true},
		Reason: reason, Message: message})
}
