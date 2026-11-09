package monitor64

import (
	"context"
	"encoding/json"
	"regexp"
	"slices"
	"strings"

	"github.com/ipv64net/node64/internal/monitor64/snmp"
)

// Zugang SNMP (Paket snmp): Konfiguration pruefen, Geheimnis (Community bzw. v3-Passwoerter als snmp.Secret-JSON)
// zusammenfuehren, Sammler und "Verbindung testen" mit Geraeteart und Profilen.

var (
	reSNMPContext = regexp.MustCompile(`^[A-Za-z0-9._-]{0,32}$`)
	reEngineID    = regexp.MustCompile(`^(0x)?([0-9A-Fa-f]{2}){5,32}$`)
)

const maxSNMPProfiles = 16

// snmpLevels: v3-Stufen in der gespeicherten Schreibweise.
var snmpLevels = map[string]string{"": "authPriv", "authpriv": "authPriv", "authnopriv": "authNoPriv", "noauthnopriv": "noAuthNoPriv"}

// cleanSNMPConfig prueft die SNMP-Felder eines Zugangs (bei anderen Zugaengen muessen sie leer sein) und
// normiert sie. Die Geheimnisse prueft checkSNMPSecret.
func cleanSNMPConfig(typ string, c *accessConfig) error {
	c.SNMPVersion, c.Level, c.Context, c.TrapEngine = strings.TrimSpace(c.SNMPVersion), strings.TrimSpace(c.Level), strings.TrimSpace(c.Context), strings.TrimSpace(c.TrapEngine)
	c.AuthProto, c.PrivProto = strings.ToUpper(strings.TrimSpace(c.AuthProto)), strings.ToUpper(strings.TrimSpace(c.PrivProto))
	if typ != "snmp" {
		if c.SNMPVersion != "" || c.Level != "" || c.AuthProto != "" || c.PrivProto != "" || c.Context != "" || len(c.Custom) > 0 ||
			len(c.Profiles) > 0 || c.Traps || c.TrapEngine != "" {
			return errBad("config", "error", "snmp fields only for snmp")
		}
		return nil
	}
	switch c.SNMPVersion {
	case "", "2c", "2":
		c.SNMPVersion = "2c"
	case "1", "3":
	default:
		return errBad("config", "error", "snmp_version")
	}
	if c.SNMPVersion != "3" { // nur v3: Benutzer, Stufe, Verfahren, Kontext, Engine-ID
		c.User, c.Level, c.AuthProto, c.PrivProto, c.Context, c.TrapEngine = "", "", "", "", "", ""
	} else {
		lvl, ok := snmpLevels[strings.ToLower(c.Level)]
		if !ok {
			return errBad("config", "error", "level")
		}
		c.Level = lvl
		if lvl == "noAuthNoPriv" {
			c.AuthProto = ""
		}
		if lvl != "authPriv" {
			c.PrivProto = ""
		}
	}
	switch {
	case !reSNMPContext.MatchString(c.Context):
		return errBad("config", "error", "context")
	case c.TrapEngine != "" && !reEngineID.MatchString(c.TrapEngine):
		return errBad("config", "error", "trap_engine_id")
	case len(c.Profiles) > maxSNMPProfiles:
		return errBad("config", "error", "profiles")
	}
	c.TrapEngine = strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(c.TrapEngine, "0x"), "0X"))
	// Version, Stufe, Verfahren, eigene OIDs und Profile prueft der Sammler (Geheimnisse hier nur Platzhalter)
	_, err := snmp.New(snmpConfig(&Host{Address: "192.0.2.1"}, *c, snmp.Secret{Community: "x", AuthPass: "xxxxxxxx", PrivPass: "xxxxxxxx"}.String()))
	if err != nil {
		return errBad("config", "error", err.Error())
	}
	return nil
}

// snmpConfig baut die Konfiguration des Sammlers aus Host, Zugang und entschluesseltem Geheimnis.
func snmpConfig(h *Host, cfg accessConfig, secret string) snmp.Config {
	return snmp.Config{Address: h.Address, Port: cfg.Port, Version: cfg.SNMPVersion, User: cfg.User, Level: cfg.Level, AuthProto: cfg.AuthProto,
		PrivProto: cfg.PrivProto, ContextName: cfg.Context, Custom: slices.Clone(cfg.Custom), Profiles: cfg.Profiles, Secret: snmp.ParseSecret(secret)}
}

// newSNMP baut den Sammler eines SNMP-Zugangs.
func newSNMP(h *Host, cfg accessConfig, secret string) (*snmp.Collector, error) {
	return snmp.New(snmpConfig(h, cfg, secret))
}

// mergeSNMPSecret fuehrt ein neues Geheimnis (JSON mit einzelnen Feldern oder nur die Community) mit dem
// gespeicherten zusammen: leere Felder behalten den gespeicherten Wert (Formular ohne erneute Eingabe der
// Passwoerter). Liefert "" , wenn nichts Neues angegeben ist.
func mergeSNMPSecret(in, old string) string {
	n := snmp.ParseSecret(in)
	if n.Community == "" && n.AuthPass == "" && n.PrivPass == "" {
		return ""
	}
	o := snmp.ParseSecret(old)
	if n.Community == "" {
		n.Community = o.Community
	}
	if n.AuthPass == "" {
		n.AuthPass = o.AuthPass
	}
	if n.PrivPass == "" {
		n.PrivPass = o.PrivPass
	}
	return n.String()
}

// checkSNMPSecret prueft Konfiguration und Geheimnis zusammen (Community fehlt, v3-Passwort zu kurz ...).
func checkSNMPSecret(cfg accessConfig, secret string) error {
	if _, err := snmp.New(snmpConfig(&Host{Address: "192.0.2.1"}, cfg, secret)); err != nil {
		return errBad("snmp_secret", "error", err.Error())
	}
	return nil
}

// testSNMP fragt einmal alles ab (Discover): System, Geraeteart, Profile (mit "nicht geprueft"), Dienste und
// Warnungen (v1/v2c, MD5, DES).
func (m *Module) testSNMP(ctx context.Context, h *Host, cfg accessConfig, secret string, res *testResult) {
	c, err := newSNMP(h, cfg, secret)
	if err != nil {
		res.Error = err.Error()
		return
	}
	defer c.Close()
	d, err := c.Discover(ctx)
	if err != nil {
		res.Error = err.Error()
		return
	}
	res.OK, res.Version, res.Node, res.Summary, res.Warning = d.OK, d.Version, d.Name, d.Summary, d.Warning
	res.Device, res.Profiles, res.Queries = d.Device, d.Profiles, c.Queries()
	for _, s := range d.Services {
		res.Services = append(res.Services, serviceIn{Key: s.Key, Name: s.Name, Kind: s.Kind, Default: s.Default})
	}
	if cfg.Traps {
		t := trapServiceIdle()
		res.Services = append(res.Services, serviceIn{Key: t.Key, Name: t.Name, Kind: t.Kind, Default: true})
	}
	slices.SortStableFunc(res.Services, func(x, y serviceIn) int { return kindOrder(x.Kind) - kindOrder(y.Kind) })
}

// snmpSecretIn fuehrt das Geheimnis aus dem Formular mit dem gespeicherten zusammen (in.Secret danach "" = behalten)
// und prueft Konfiguration und Geheimnis zusammen. Laesst sich das gespeicherte nicht entschluesseln, wird nur
// das neue geprueft.
func (m *Module) snmpSecretIn(a *Access, in *accessIn, isNew bool) error {
	old := ""
	if !isNew && !in.ClearSecret && a.Secret != "" {
		if s, err := m.box.Decrypt(a.Secret); err == nil {
			old = s
		}
	}
	if in.Secret != "" {
		in.Secret = mergeSNMPSecret(in.Secret, old)
	}
	final := in.Secret
	if final == "" {
		if in.ClearSecret || (isNew || a.Secret == "") {
			final = ""
		} else if old == "" {
			return nil // gespeichertes Geheimnis nicht lesbar: nicht pruefen (Zugang zeigt den Fehler)
		} else {
			final = old
		}
	}
	var cfg accessConfig
	_ = json.Unmarshal(a.Config, &cfg)
	return checkSNMPSecret(cfg, final)
}
