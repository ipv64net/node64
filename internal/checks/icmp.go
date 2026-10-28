package checks

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	probing "github.com/prometheus-community/pro-bing"
)

// ICMPParams gelten fuer den Typ icmp.
type ICMPParams struct {
	Count          int `json:"count,omitempty"`            // Pakete, Standard 3
	MaxLossPercent int `json:"max_loss_percent,omitempty"` // down, wenn Verlust groesser; Standard 0 = jeder Verlust zaehlt... siehe unten
	MaxLatencyMS   int `json:"max_latency_ms,omitempty"`   // down, wenn mittlere Latenz groesser (0 = aus)
}

const (
	DefaultICMPCount   = 3
	DefaultICMPMaxLoss = 50
)

// icmpChecker pingt zuerst unprivilegiert (UDP, net.ipv4.ping_group_range)
// und faellt auf Raw-Sockets (CAP_NET_RAW) zurueck, wenn das verweigert wird.
type icmpChecker struct {
	mu         sync.Mutex
	privileged *bool // gemerkter Modus, der funktioniert
}

func (*icmpChecker) Type() Type { return TypeICMP }

func (c *icmpChecker) Check(ctx context.Context, def Definition, ip net.IP) Result {
	raw := map[string]any{}
	_ = decodeLoose(def.Params, &raw)
	var p ICMPParams
	if err := decode(def.Params, &p); err != nil {
		return fail(ReasonInvalid, err.Error(), 0, nil)
	}
	count := p.Count
	if count <= 0 {
		count = DefaultICMPCount
	}
	maxLoss := DefaultICMPMaxLoss
	if _, set := raw["max_loss_percent"]; set {
		maxLoss = p.MaxLossPercent
	}
	details := map[string]any{"count": count, "max_loss_percent": maxLoss}

	modes := c.modes()
	var lastErr error
	for _, priv := range modes {
		stats, err := c.ping(ctx, ip, count, def.Timeouts.Total, priv)
		if err != nil {
			lastErr = err
			if permissionDenied(err) {
				continue
			}
			if isTimeout(err) {
				return fail(ReasonTimeout, "ping timeout", 0, details)
			}
			return fail(ReasonConnectFailed, shortErr(err), 0, details)
		}
		c.remember(priv)
		details["sent"] = stats.PacketsSent
		details["received"] = stats.PacketsRecv
		details["loss_percent"] = stats.PacketLoss
		details["min_ms"] = ms(stats.MinRtt)
		details["avg_ms"] = ms(stats.AvgRtt)
		details["max_ms"] = ms(stats.MaxRtt)
		details["privileged"] = priv
		lat := stats.AvgRtt
		if stats.PacketsRecv == 0 {
			return fail(ReasonPacketLoss, fmt.Sprintf("no reply to %d pings", stats.PacketsSent), 0, details)
		}
		if int(stats.PacketLoss+0.5) > maxLoss {
			return fail(ReasonPacketLoss, fmt.Sprintf("%.0f%% packet loss (threshold %d%%)", stats.PacketLoss, maxLoss), lat, details)
		}
		if p.MaxLatencyMS > 0 && lat > time.Duration(p.MaxLatencyMS)*time.Millisecond {
			return fail(ReasonLatencyHigh, fmt.Sprintf("avg %.1f ms above %d ms", ms(lat), p.MaxLatencyMS), lat, details)
		}
		return ok(fmt.Sprintf("%d/%d replies, avg %.1f ms", stats.PacketsRecv, stats.PacketsSent, ms(lat)), lat, details)
	}
	msg := "ICMP not permitted: allow unprivileged ping (sysctl net.ipv4.ping_group_range) or grant CAP_NET_RAW"
	if lastErr != nil {
		msg += " (" + shortErr(lastErr) + ")"
	}
	return fail(ReasonICMPDenied, msg, 0, details)
}

// rtt ist ein einzelner Ping fuer die Latenz anderer Check-Typen (Proxmox, Docker); false = keine Antwort, Fehler
// bzw. ICMP nicht erlaubt.
func (c *icmpChecker) rtt(ctx context.Context, ip net.IP, timeout time.Duration) (time.Duration, bool) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for _, priv := range c.modes() {
		stats, err := c.ping(ctx, ip, 1, timeout, priv)
		if err != nil {
			if permissionDenied(err) {
				continue
			}
			return 0, false
		}
		c.remember(priv)
		if stats.PacketsRecv == 0 {
			return 0, false
		}
		return stats.AvgRtt, true
	}
	return 0, false
}

// Latenz anderer Check-Typen per Ping (Proxmox, Docker): hoechstens LatencyPingTimeout; nach einem Fehlschlag wird
// die Adresse latencyPingPause lang nicht gepingt (ein nicht erreichbares Netz kostete sonst jeden Lauf den Timeout).
const (
	LatencyPingTimeout = 2 * time.Second
	latencyPingPause   = 5 * time.Minute
)

// pingLatency pingt ip fuer die Latenz (nur Anzeige, nie fuer den Status); false = nicht gemessen.
func (r *Runner) pingLatency(ctx context.Context, ip net.IP) (time.Duration, bool) {
	if r == nil || r.ping == nil || ip == nil {
		return 0, false
	}
	key, now := ip.String(), time.Now()
	r.pingMu.Lock()
	t, failed := r.pingFail[key]
	r.pingMu.Unlock()
	if failed && now.Sub(t) < latencyPingPause {
		return 0, false
	}
	timeout := LatencyPingTimeout
	if dl, ok := ctx.Deadline(); ok && time.Until(dl) < timeout {
		timeout = time.Until(dl)
	}
	if timeout < 200*time.Millisecond {
		return 0, false
	}
	d, ok := r.ping(ctx, ip, timeout)
	r.pingMu.Lock()
	defer r.pingMu.Unlock()
	if ok {
		delete(r.pingFail, key)
		return d, true
	}
	if r.pingFail == nil {
		r.pingFail = map[string]time.Time{}
	}
	for k, t := range r.pingFail {
		if now.Sub(t) >= latencyPingPause {
			delete(r.pingFail, k)
		}
	}
	r.pingFail[key] = now
	return 0, false
}

func (c *icmpChecker) modes() []bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.privileged != nil {
		return []bool{*c.privileged}
	}
	if runtime.GOOS == "windows" {
		return []bool{true} // Windows kennt kein unprivilegiertes ICMP ueber UDP
	}
	return []bool{false, true}
}

func (c *icmpChecker) remember(priv bool) {
	c.mu.Lock()
	c.privileged = &priv
	c.mu.Unlock()
}

func (c *icmpChecker) ping(ctx context.Context, ip net.IP, count int, total time.Duration, privileged bool) (*probing.Statistics, error) {
	pinger := probing.New(ip.String())
	pinger.SetIPAddr(&net.IPAddr{IP: ip})
	if ip.To4() == nil {
		pinger.SetNetwork("ip6")
	} else {
		pinger.SetNetwork("ip4")
	}
	pinger.SetPrivileged(privileged)
	pinger.Count = count
	pinger.Interval = 300 * time.Millisecond
	pinger.Timeout = pingTimeout(ctx, total)
	pinger.Size = 56
	if err := pinger.RunWithContext(ctx); err != nil {
		// Laeuft der Check-Kontext ab, nachdem Pakete gesendet wurden, gilt die
		// Statistik trotzdem (verlorene Antworten zaehlen als Verlust, nicht als Timeout)
		stats := pinger.Statistics()
		if errors.Is(err, context.DeadlineExceeded) && stats != nil && stats.PacketsSent > 0 {
			return stats, nil
		}
		return nil, err
	}
	return pinger.Statistics(), nil
}

// pingTimeout endet etwas vor dem Check-Kontext, damit pro-bing regulaer mit
// Statistik beendet statt mit DeadlineExceeded abzubrechen.
func pingTimeout(ctx context.Context, total time.Duration) time.Duration {
	margin := total / 10
	if margin < 100*time.Millisecond {
		margin = 100 * time.Millisecond
	}
	if margin > time.Second {
		margin = time.Second
	}
	t := total - margin
	if dl, ok := ctx.Deadline(); ok {
		if until := time.Until(dl) - margin; until < t {
			t = until
		}
	}
	if t < 100*time.Millisecond {
		t = 100 * time.Millisecond
	}
	return t
}

func permissionDenied(err error) bool {
	if errors.Is(err, os.ErrPermission) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "permission denied") || strings.Contains(s, "operation not permitted") || strings.Contains(s, "socket: ") && strings.Contains(s, "not permitted")
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// decodeLoose liest JSON ohne Feldpruefung (um gesetzte Felder zu erkennen).
func decodeLoose(raw []byte, v any) error {
	if len(raw) == 0 {
		return nil
	}
	return jsonUnmarshal(raw, v)
}
