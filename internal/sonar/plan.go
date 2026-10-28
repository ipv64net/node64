package sonar

// Messplan: Signatur pruefen, Inhalt bereinigen, Gueltigkeit (Vertrag Abschnitte 2 und 8). Ein Plan gilt hoechstens
// 30 min ab Ausgabe bzw. Empfang, danach misst der Knoten nur noch dessen Anker, nach 2 h gar nicht mehr.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var (
	nodeIDRe   = regexp.MustCompile(`^(n[a-z0-9]{11}|a_[a-z0-9]{2,12})$`) // wie S64_NODE_RE bei ipv64
	targetIDRe = nodeIDRe
)

func validNodeID(s string) bool { return nodeIDRe.MatchString(s) }

// activePlan ist ein gepruefter Plan mit seinen Zeitfenstern.
type activePlan struct {
	plan         Plan
	raw          []byte
	kid, sig     string
	etag         string
	got          time.Time
	validUntil   time.Time // Runden aus dem Plan bis hier
	anchorsUntil time.Time // danach nur Anker bis hier
}

// parsePlanKeys dekodiert die Public Keys (Base64 std, 32 Byte).
func parsePlanKeys(keys []string) ([]ed25519.PublicKey, error) {
	var out []ed25519.PublicKey
	for _, k := range keys {
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(k))
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, errors.New("sonar: plan key is not an Ed25519 public key (base64)")
		}
		out = append(out, ed25519.PublicKey(b))
	}
	return out, nil
}

// verifyPlan prueft Signatur und Kopf eines Plans und liefert ihn bereinigt.
func verifyPlan(raw []byte, sig string, keys []ed25519.PublicKey, nodeID string, now time.Time) (*Plan, error) {
	if len(keys) == 0 {
		return nil, errors.New("no plan key configured")
	}
	s, err := base64.StdEncoding.DecodeString(sig)
	if err != nil || len(s) != ed25519.SignatureSize {
		return nil, errors.New("plan signature malformed")
	}
	ok := false
	for _, k := range keys {
		if ed25519.Verify(k, raw, s) {
			ok = true
			break
		}
	}
	if !ok {
		return nil, errors.New("plan signature invalid")
	}
	var p Plan
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, errors.New("plan not readable")
	}
	switch {
	case p.V != ProtoVersion:
		return nil, fmt.Errorf("plan version %d not supported", p.V)
	case p.NodeID != nodeID:
		return nil, errors.New("plan is for another node")
	case p.Issued.IsZero() || !p.Expires.After(p.Issued):
		return nil, errors.New("plan times invalid")
	case p.Issued.After(now.Add(time.Hour)):
		return nil, errors.New("plan issued in the future (check the clock)")
	case !now.Before(p.Issued.Add(AnchorOnlyFor)):
		return nil, errors.New("plan too old")
	}
	if len(p.Rounds) > MaxRounds {
		p.Rounds = p.Rounds[:MaxRounds]
	}
	anchors := p.Anchors[:0:0]
	for _, t := range p.Anchors {
		if len(anchors) >= MaxAnchorTargets {
			break
		}
		if !strings.HasPrefix(t.ID, "a_") {
			continue // Rueckfall nur zu Ankern, nie zu Knoten
		}
		if c, err := cleanTarget(t, true); err == nil {
			anchors = append(anchors, c)
		}
	}
	p.Anchors = anchors
	return &p, nil
}

// window liefert die Zeitfenster eines Plans: Runden bis min(Expires, Issued+30 min, Empfang+30 min), Anker bis
// min(Issued, Empfang)+2 h.
func window(p *Plan, got time.Time) (validUntil, anchorsUntil time.Time) {
	validUntil = p.Expires
	for _, t := range []time.Time{p.Issued.Add(PlanMaxAge), got.Add(PlanMaxAge)} {
		if t.Before(validUntil) {
			validUntil = t
		}
	}
	first := p.Issued
	if got.Before(first) {
		first = got
	}
	anchorsUntil = first.Add(AnchorOnlyFor)
	return validUntil, anchorsUntil
}

// cleanTarget prueft ein Ziel streng und setzt Count/MaxTTL in die Grenzen. anchorsOnly: nur icmp/udp.
func cleanTarget(t Target, anchorsOnly bool) (Target, error) {
	if !targetIDRe.MatchString(t.ID) {
		return t, errors.New("bad id")
	}
	a, ok := targetAddr(t)
	if !ok {
		return t, errors.New("address not public")
	}
	t.Addr = a.String()
	switch t.Method {
	case MethodICMP, MethodUDP:
		t.Count = min(max(t.Count, 1), MaxCount)
		t.MaxTTL = 0
	case MethodTrace:
		if anchorsOnly {
			return t, errors.New("no trace here")
		}
		t.Count = min(max(t.Count, 1), MaxTraceCount)
		if t.MaxTTL <= 0 || t.MaxTTL > MaxTTL {
			t.MaxTTL = MaxTTL
		}
	default:
		return t, errors.New("bad method")
	}
	return t, nil
}

// roundTargets bereinigt die Ziele einer Runde: ungueltige und doppelte weg, eigenes Ziel weg, auf max kuerzen.
func roundTargets(ts []Target, maxN int, self string, anchorsOnly bool) []Target {
	out := make([]Target, 0, min(len(ts), maxN))
	seen := map[string]bool{}
	for _, t := range ts {
		if len(out) >= maxN {
			break
		}
		c, err := cleanTarget(t, anchorsOnly)
		if err != nil || c.ID == self {
			continue
		}
		k := fmt.Sprintf("%s|%d|%s", c.ID, c.Family, c.Method)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, c)
	}
	return out
}
