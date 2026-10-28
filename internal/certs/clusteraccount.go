package certs

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/store"
)

// ACME-Konto im Cluster (Bereich acme, Eintrag "account"): Jede Node hat ein Konto (Schluessel, Mail,
// Nutzungsbedingungen). Hat die andere Node keins oder dasselbe (gleicher Schluessel), gilt es einfach ueberall.
// Haben zwei Nodes verschiedene Konten, wird nichts ueberschrieben: die Abweichung steht hier (Einstellung
// certs.acme_conflicts) und auf der Seite Cluster waehlt man eines fuer den ganzen Cluster. Bis dahin nutzt jede Node
// ihr eigenes. Die Wahl (Zeitpunkt und die abgeloesten Konten als Fingerabdruck des Schluessels) geht mit dem Konto
// hinaus; eine Node, deren Konto darin abgeloest ist, uebernimmt das gewaehlte. Zertifikate bleiben gueltig, erneuert
// wird ab dann mit dem gewaehlten Konto. Bei zwei verschiedenen Wahlen gilt die juengere.

const (
	setCreated   = "certs.acme_created"   // Konto angelegt bzw. uebernommen (Zeitpunkt)
	setChoice    = "certs.acme_choice"    // Wahl im Cluster: {"at": ..., "replaces": [...]}
	setConflicts = "certs.acme_conflicts" // abweichende Konten anderer Nodes (Schluessel verschluesselt)
)

var (
	// ErrAccountConflict: die andere Node hat ein anderes ACME-Konto (Wahl auf der Seite Cluster).
	ErrAccountConflict = errors.New("ACME account differs from this node's account, choose one on the cluster page")
	// ErrAccountReplaced: das Konto der anderen Node ist durch eine Wahl im Cluster abgeloest.
	ErrAccountReplaced = errors.New("ACME account was replaced by the choice in the cluster")
	// ErrAccountChoice: das gewaehlte Konto gibt es hier nicht (mehr).
	ErrAccountChoice = errors.New("unknown ACME account")
)

type clusterACMEAccount struct {
	Email     string   `json:"email"`
	TOSAt     string   `json:"tos_at,omitempty"`
	Key       string   `json:"key"`
	Node      string   `json:"node,omitempty"` // Node, die es schickt (Anzeige bei Abweichung)
	CA        string   `json:"ca,omitempty"`   // ACME-Stelle (Anzeige)
	CreatedAt string   `json:"created_at,omitempty"`
	ChosenAt  string   `json:"chosen_at,omitempty"` // Wahl im Cluster
	Replaces  []string `json:"replaces,omitempty"`  // durch die Wahl abgeloeste Konten (Fingerabdruck)
}

type accountChoice struct {
	At       string   `json:"at"`
	Replaces []string `json:"replaces"`
}

type accountConflict struct {
	Thumb     string `json:"thumb"`
	Node      string `json:"node"`
	Email     string `json:"email"`
	CA        string `json:"ca"`
	CreatedAt string `json:"created_at"`
	TOSAt     string `json:"tos_at"`
	Key       string `json:"key"` // verschluesselt
}

// AccountChoice ist ein ACME-Konto zur Wahl, wenn Nodes im Cluster verschiedene Konten haben.
type AccountChoice struct {
	Thumbprint string    `json:"thumbprint"` // SHA-256 des oeffentlichen Schluessels
	Node       string    `json:"node_id"`
	Email      string    `json:"email"`
	CA         string    `json:"ca"`
	CreatedAt  time.Time `json:"created_at,omitzero"`
	Own        bool      `json:"own"` // Konto dieser Node
}

// accountThumb: Fingerabdruck eines Kontoschluessels (PEM, EC).
func accountThumb(keyPEM string) (string, error) {
	b, _ := pem.Decode([]byte(keyPEM))
	if b == nil {
		return "", errors.New("account key unreadable")
	}
	k, err := x509.ParseECPrivateKey(b.Bytes)
	if err != nil {
		return "", errors.New("account key unreadable")
	}
	der, err := x509.MarshalPKIXPublicKey(k.Public())
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// accountCA: Name der ACME-Stelle des Kontos (Anzeige).
func (m *Manager) accountCA() string {
	dir := m.d.Directory
	if dir == "" || dir == letsEncrypt {
		return "Let's Encrypt"
	}
	if u, err := url.Parse(dir); err == nil && u.Host != "" {
		return u.Host
	}
	return dir
}

// ownAccount: Konto dieser Node mit Wahl (nil = noch keins).
func (m *Manager) ownAccount(ctx context.Context) (*clusterACMEAccount, string, error) {
	sealed := m.d.Store.SettingOr(ctx, setKey, "")
	if sealed == "" {
		return nil, "", nil
	}
	key, err := m.d.Box.Decrypt(sealed)
	if err != nil {
		return nil, "", err
	}
	thumb, err := accountThumb(key)
	if err != nil {
		return nil, "", err
	}
	tos := m.d.Store.SettingOr(ctx, setTOS, "")
	created := m.d.Store.SettingOr(ctx, setCreated, tos)
	ch := m.accChoice(ctx)
	return &clusterACMEAccount{Email: m.d.Store.SettingOr(ctx, setEmail, ""), TOSAt: tos, Key: key, Node: m.selfID(), CA: m.accountCA(),
		CreatedAt: created, ChosenAt: ch.At, Replaces: ch.Replaces}, thumb, nil
}

func (m *Manager) accChoice(ctx context.Context) accountChoice {
	var c accountChoice
	_ = json.Unmarshal([]byte(m.d.Store.SettingOr(ctx, setChoice, "{}")), &c)
	return c
}

func (m *Manager) accConflicts(ctx context.Context) []accountConflict {
	var c []accountConflict
	_ = json.Unmarshal([]byte(m.d.Store.SettingOr(ctx, setConflicts, "[]")), &c)
	return c
}

func (m *Manager) setJSON(ctx context.Context, key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return m.d.Store.SetSetting(ctx, key, string(b))
}

// later: die Wahl in (at, thumb) ist juenger als die hier (Gleichstand: kleinerer Fingerabdruck).
func later(at, thumb string, local accountChoice, localThumb string) bool {
	a, b := store.ParseTime(at), store.ParseTime(local.At)
	if a.IsZero() {
		return false
	}
	return a.After(b) || a.Equal(b) && thumb < localThumb
}

// latest: der juengere Zeitpunkt (Speicherformat).
func latest(a, b string) string {
	if store.ParseTime(a).After(store.ParseTime(b)) {
		return a
	}
	return b
}

// union: Fingerabdruecke ohne Doppelte und ohne skip, sortiert.
func union(skip string, lists ...[]string) []string {
	out := []string{}
	for _, l := range lists {
		for _, t := range l {
			if t != "" && t != skip && !slices.Contains(out, t) {
				out = append(out, t)
			}
		}
	}
	slices.Sort(out)
	return out
}

// pruneConflicts: Abweichungen, die durch das eigene Konto oder die Wahl erledigt sind, fallen weg.
func (m *Manager) pruneConflicts(ctx context.Context, own string, replaced []string) error {
	list := m.accConflicts(ctx)
	n := len(list)
	list = slices.DeleteFunc(list, func(c accountConflict) bool { return c.Thumb == own || slices.Contains(replaced, c.Thumb) })
	if len(list) == n {
		return nil
	}
	return m.setJSON(ctx, setConflicts, list)
}

// reannounce meldet das eigene Konto neu (eigene Herkunft, jetzt): die andere Node bekommt es auch dann, wenn ihr
// Stand juenger ist, und sieht so die Abweichung bzw. die Wahl.
func (m *Manager) reannounce() {
	m.changedUID(context.Background(), ItemACME, clusterAccount, false)
}

// clusterApplyAccount uebernimmt das ACME-Konto einer anderen Node, wenn hier keins ist, es dasselbe ist oder eine
// Wahl im Cluster das eigene abgeloest hat. Sonst bleibt das eigene und die Abweichung wird zur Wahl vorgemerkt.
func (m *Manager) clusterApplyAccount(ctx context.Context, data json.RawMessage) error {
	var in clusterACMEAccount
	if err := json.Unmarshal(data, &in); err != nil {
		return invalid("data", "%v", err)
	}
	thumb, err := accountThumb(in.Key)
	if err != nil {
		return invalid("key", "account key unreadable")
	}
	m.accMu.Lock()
	defer m.accMu.Unlock()
	own, ownThumb, err := m.ownAccount(ctx)
	if err != nil {
		return err
	}
	ch := m.accChoice(ctx)
	switch {
	case own == nil:
		return m.adoptAccount(ctx, &in, thumb, "", ch)
	case thumb == ownThumb: // dasselbe Konto: Mail und Bedingungen wie bisher, eine juengere Wahl kommt mit
		if err := m.setAccountInfo(ctx, &in); err != nil {
			return err
		}
		if in.ChosenAt != "" && !store.ParseTime(in.ChosenAt).Before(store.ParseTime(ch.At)) {
			ch = accountChoice{At: latest(in.ChosenAt, ch.At), Replaces: union(ownThumb, ch.Replaces, in.Replaces)}
			if err := m.setJSON(ctx, setChoice, ch); err != nil {
				return err
			}
		}
		if err := m.pruneConflicts(ctx, ownThumb, ch.Replaces); err != nil {
			return err
		}
		m.changedUID(ctx, ItemACME, clusterAccount, false)
		return nil
	case slices.Contains(in.Replaces, ownThumb) && (!slices.Contains(ch.Replaces, thumb) || later(in.ChosenAt, thumb, ch, ownThumb)):
		m.log.Info("ACME account replaced by the choice in the cluster", "node", in.Node, "dropped_email", own.Email, "dropped_key", short(ownThumb))
		return m.adoptAccount(ctx, &in, thumb, ownThumb, ch)
	case slices.Contains(ch.Replaces, thumb):
		m.reannounce()
		return ErrAccountReplaced
	}
	list := m.accConflicts(ctx)
	i := slices.IndexFunc(list, func(c accountConflict) bool { return c.Thumb == thumb })
	c := accountConflict{Thumb: thumb, Node: in.Node, Email: strings.TrimSpace(in.Email), CA: in.CA, CreatedAt: in.CreatedAt, TOSAt: in.TOSAt, Key: m.d.Box.Encrypt(in.Key)}
	if i >= 0 {
		list[i] = c
	} else {
		list = append(list, c)
	}
	if err := m.setJSON(ctx, setConflicts, list); err != nil {
		return err
	}
	if i < 0 {
		m.log.Warn("ACME account differs from another cluster node, choose one on the cluster page", "node", in.Node, "email", c.Email)
		m.reannounce()
	}
	return ErrAccountConflict
}

func short(thumb string) string {
	if len(thumb) > 16 {
		return thumb[:16]
	}
	return thumb
}

// setAccountInfo: Mail und Annahme der Bedingungen (diese nur, wenn hier noch nicht angenommen).
func (m *Manager) setAccountInfo(ctx context.Context, in *clusterACMEAccount) error {
	if err := m.d.Store.SetSetting(ctx, setEmail, strings.TrimSpace(in.Email)); err != nil {
		return err
	}
	if in.TOSAt != "" && m.d.Store.SettingOr(ctx, setTOS, "") == "" {
		if err := m.d.Store.SetSetting(ctx, setTOS, in.TOSAt); err != nil {
			return err
		}
	}
	m.mu.Lock()
	m.reg = map[string]bool{} // Kontaktadresse bzw. anderes Konto: beim naechsten Abruf anmelden
	m.mu.Unlock()
	return nil
}

// adoptAccount uebernimmt das Konto in (ownThumb: das bisherige, wird abgeloest) samt Wahl.
func (m *Manager) adoptAccount(ctx context.Context, in *clusterACMEAccount, thumb, ownThumb string, ch accountChoice) error {
	if err := m.d.Store.SetSetting(ctx, setKey, m.d.Box.Encrypt(in.Key)); err != nil {
		return err
	}
	created := in.CreatedAt
	if created == "" {
		created = store.Now()
	}
	if err := m.d.Store.SetSetting(ctx, setCreated, created); err != nil {
		return err
	}
	if err := m.setAccountInfo(ctx, in); err != nil {
		return err
	}
	ch = accountChoice{At: latest(in.ChosenAt, ch.At), Replaces: union(thumb, ch.Replaces, in.Replaces, []string{ownThumb})}
	if ch.At != "" || len(ch.Replaces) > 0 {
		if err := m.setJSON(ctx, setChoice, ch); err != nil {
			return err
		}
	}
	if err := m.pruneConflicts(ctx, thumb, ch.Replaces); err != nil {
		return err
	}
	m.changedUID(ctx, ItemACME, clusterAccount, false)
	return nil
}

// AccountConflicts: die ACME-Konten zur Wahl, wenn Nodes im Cluster verschiedene haben (das eigene zuerst); leer =
// keine Abweichung.
func (m *Manager) AccountConflicts(ctx context.Context) []AccountChoice {
	list := m.accConflicts(ctx)
	if len(list) == 0 {
		return nil
	}
	own, ownThumb, err := m.ownAccount(ctx)
	if err != nil || own == nil {
		return nil
	}
	out := []AccountChoice{{Thumbprint: ownThumb, Node: own.Node, Email: own.Email, CA: own.CA, CreatedAt: store.ParseTime(own.CreatedAt), Own: true}}
	for _, c := range list {
		out = append(out, AccountChoice{Thumbprint: c.Thumb, Node: c.Node, Email: c.Email, CA: c.CA, CreatedAt: store.ParseTime(c.CreatedAt)})
	}
	return out
}

// ChooseAccount waehlt das ACME-Konto fuer den ganzen Cluster (Fingerabdruck aus AccountConflicts). Die anderen
// werden hier verworfen (Rueckgabe fuer das Audit), die Wahl geht an die anderen Nodes.
func (m *Manager) ChooseAccount(ctx context.Context, thumb string) (dropped []AccountChoice, err error) {
	m.accMu.Lock()
	defer m.accMu.Unlock()
	list := m.accConflicts(ctx)
	own, ownThumb, err := m.ownAccount(ctx)
	if err != nil {
		return nil, err
	}
	if own == nil || len(list) == 0 {
		return nil, ErrAccountChoice
	}
	ch := m.accChoice(ctx)
	others := []string{}
	var pick *accountConflict
	for i, c := range list {
		if c.Thumb == thumb {
			pick = &list[i]
			continue
		}
		others = append(others, c.Thumb)
		dropped = append(dropped, AccountChoice{Thumbprint: c.Thumb, Node: c.Node, Email: c.Email, CA: c.CA, CreatedAt: store.ParseTime(c.CreatedAt)})
	}
	now := store.Now()
	if thumb == ownThumb {
		ch = accountChoice{At: now, Replaces: union(ownThumb, ch.Replaces, others)}
		if err := m.setJSON(ctx, setChoice, ch); err != nil {
			return nil, err
		}
		if err := m.setJSON(ctx, setConflicts, []accountConflict{}); err != nil {
			return nil, err
		}
		m.changedUID(ctx, ItemACME, clusterAccount, false)
		return dropped, nil
	}
	if pick == nil {
		return nil, ErrAccountChoice
	}
	key, err := m.d.Box.Decrypt(pick.Key)
	if err != nil {
		return nil, err
	}
	dropped = append([]AccountChoice{{Thumbprint: ownThumb, Node: own.Node, Email: own.Email, CA: own.CA, CreatedAt: store.ParseTime(own.CreatedAt), Own: true}}, dropped...)
	in := &clusterACMEAccount{Email: pick.Email, TOSAt: pick.TOSAt, Key: key, CreatedAt: pick.CreatedAt}
	if err := m.adoptAccount(ctx, in, thumb, ownThumb, accountChoice{At: now, Replaces: union(thumb, ch.Replaces, others)}); err != nil {
		return nil, err
	}
	if err := m.setJSON(ctx, setConflicts, []accountConflict{}); err != nil {
		return nil, err
	}
	return dropped, nil
}
