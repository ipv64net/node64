package cdn64

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/ipv64net/node64/internal/ipv64api"
)

// v64 Blocklist (Honeypot64): Listen der Kategorie honeypot aus index.json. Den Tagesstand bekommen alle unter
// blocklists/<datei>; mit dem Listen-Token aus dem ipv64-Account laedt PROXY64 die Live-Fassung unter
// blocklists/live/<token>/<datei> (nach jeder Bewertung, alle 30 Minuten). Hat das Token keine Berechtigung, liefert
// ipv64 dort den Tagesstand mit Kopfzeile X-IPv64-List: daily; 401/403/404 -> Rueckfall auf den Tagesstand.
// Das Token steht verschluesselt in den Einstellungen, wird nie ausgegeben, geloggt oder exportiert.
// Ohne Token von Hand holt PROXY64 es selbst ueber den zentralen API-Key (GET /honeypot/list-token, legt es bei ipv64
// an, wenn es fehlt): Wer die passende Klasse hat oder Beitragende/r ist, bekommt so automatisch die Live-Fassung.

const (
	setBlockToken     = "cdn64.blocklist_token"      // Listen-Token von Hand (secrets.Box; ohne Schluessel, nur in Tests, Klartext)
	setBlockTokenAuto = "cdn64.blocklist_token_auto" // Listen-Token ueber den API-Key geholt (wie oben verschluesselt)
	blCatHoneypot     = "honeypot"
	blListHeader      = "X-IPv64-List" // "daily": Token ohne Berechtigung, Tagesstand
)

// blTokenRe: Format der Listen-Token (hp_list_tokens.token, 32 Zeichen, docs/PLAN-NODE64-HONEYPOT64.md).
var blTokenRe = regexp.MustCompile(`^[A-Za-z0-9]{32}$`)

// blHTTPError: Antwort von ipv64 ausser 200/304.
type blHTTPError int

func (e blHTTPError) Error() string { return fmt.Sprintf("HTTP %d", int(e)) }

// blTokenValid: leer (loeschen) oder im Format der Listen-Token.
func blTokenValid(tok string) bool {
	tok = strings.TrimSpace(tok)
	return tok == "" || blTokenRe.MatchString(tok)
}

// blMask entfernt das Token aus einer Fehlermeldung (die URL des Live-Abrufs steht in Fehlern des HTTP-Clients).
func blMask(err error, tok string) error {
	if err == nil || tok == "" || !strings.Contains(err.Error(), tok) {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), tok, "***"))
}

// blToken liefert das Listen-Token: von Hand hinterlegt, sonst das ueber den API-Key geholte (leer = keins).
func (m *Module) blToken(ctx context.Context) string {
	if tok := m.blTokenOf(ctx, setBlockToken); tok != "" {
		return tok
	}
	return m.blTokenOf(ctx, setBlockTokenAuto)
}

// blTokenOf liest ein gespeichertes Token (leer = keins oder nicht lesbar).
func (m *Module) blTokenOf(ctx context.Context, key string) string {
	v := m.core.SettingOr(ctx, key, "")
	if v == "" {
		return ""
	}
	tok, err := m.online.box.Decrypt(v)
	if err != nil || !blTokenRe.MatchString(tok) {
		return ""
	}
	return tok
}

// listTokenAPI: ipv64 liefert das Listen-Token zum zentralen API-Key (IPv64Online).
type listTokenAPI interface {
	ListToken(ctx context.Context) (*ipv64api.ListToken, error)
}

// blAutoToken holt das Listen-Token ueber den zentralen API-Key, wenn eine Honeypot-Liste eingeschaltet ist, keins
// von Hand hinterlegt ist und noch keins geholt wurde. Ob live oder Tagesstand, entscheidet ipv64 bei jedem Abruf
// nach Klasse bzw. Beitrag; das Token selbst bleibt gleich.
func (m *Module) blAutoToken(ctx context.Context) {
	if m.blToken(ctx) != "" || !m.blHoneypotOn(ctx) || m.online.api == nil || !m.online.api.Ready(ctx) {
		return
	}
	api, ok := m.online.api.(listTokenAPI)
	if !ok {
		return
	}
	lt, err := api.ListToken(ctx)
	if err != nil {
		m.log.Warn("cdn64 blocklist list token not fetched, loading daily list", "err", err)
		return
	}
	if !blTokenRe.MatchString(lt.Token) {
		return
	}
	if err := m.core.SetSetting(ctx, setBlockTokenAuto, m.online.box.Encrypt(lt.Token)); err != nil {
		m.log.Warn("cdn64 blocklist list token not saved", "err", err)
	}
}

// blHoneypotOn: mindestens eine eingeschaltete Liste der Kategorie honeypot (v64 Blocklist).
func (m *Module) blHoneypotOn(ctx context.Context) bool {
	for _, id := range m.blEnabled(ctx) {
		m.bl.mu.Lock()
		info, ok := m.bl.byID(id)
		m.bl.mu.Unlock()
		if ok && info.Category == blCatHoneypot {
			return true
		}
	}
	return false
}

// blSetToken speichert das Listen-Token (leer = loeschen) und laedt die Listen neu.
func (m *Module) blSetToken(ctx context.Context, tok string) error {
	tok = strings.TrimSpace(tok)
	if !blTokenValid(tok) {
		return ferr("token", "cdn64.bl.err_token")
	}
	if err := m.core.SetSetting(ctx, setBlockToken, m.online.box.Encrypt(tok)); err != nil {
		return err
	}
	m.blKick(ctx)
	return nil
}

// blFetchHoneypot laedt eine Liste der Kategorie honeypot: mit Token live, sonst bzw. im Rueckfall den Tagesstand.
func (m *Module) blFetchHoneypot(ctx context.Context, id, file string) error {
	tok := m.blToken(ctx)
	if tok == "" {
		_, _, err := m.blFetchFrom(ctx, id, file)
		if err == nil {
			m.blEdition(id, "daily", false, "")
		}
		return err
	}
	list, same, err := m.blFetchFrom(ctx, id, "live/"+tok+"/"+file)
	var he blHTTPError
	if errors.As(err, &he) && (he == 401 || he == 403 || he == 404) {
		if he == 404 && m.blTokenOf(ctx, setBlockToken) == "" {
			// geholtes Token bei ipv64 unbekannt (z. B. neu erzeugt): verwerfen, beim naechsten Lauf neu holen
			_ = m.core.SetSetting(ctx, setBlockTokenAuto, "")
		}
		liveErr := "live: " + he.Error()
		m.log.Warn("cdn64 blocklist live not allowed, loading daily list", "list", id, "err", liveErr)
		if _, _, err := m.blFetchFrom(ctx, id, file); err != nil {
			m.blEdition(id, "", false, liveErr)
			return err
		}
		m.blEdition(id, "daily", false, liveErr)
		return nil
	}
	if err != nil {
		return blMask(err, tok)
	}
	switch {
	case strings.EqualFold(list, "daily"):
		m.blEdition(id, "daily", true, "")
	case !same || list != "": // 304 ohne Kopfzeile: Stand wie zuvor
		m.blEdition(id, "live", false, "")
	}
	return nil
}

// blEdition vermerkt die geladene Fassung (leer = unveraendert).
func (m *Module) blEdition(id, edition string, denied bool, liveErr string) {
	m.bl.mu.Lock()
	defer m.bl.mu.Unlock()
	st := m.bl.stateOf(id)
	if edition != "" {
		st.Edition = edition
	}
	st.LiveDenied, st.LiveError = denied, liveErr
}
