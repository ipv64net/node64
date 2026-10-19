package sync

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"time"

	"github.com/ipv64net/node64/internal/healthchecks"
)

// HubEvents holt die Ereignisse, die ipv64 selbst bewertet hat (z. B. nicht ueberwacht, wieder geprueft), fuer die
// Detailseite eines Checks. Nur Anzeige: nichts wird gespeichert oder zurueckgeschickt.
func (c *Live) HubEvents(ctx context.Context, token string) ([]healthchecks.Event, error) {
	if !c.Linked() {
		return nil, nil
	}
	hub, tok := c.hubURL(), c.token()
	if hub == "" || tok == "" {
		return nil, errors.New("not linked")
	}
	b, err := c.get(ctx, hub+"/v1/nodes/me/events?limit=50&token="+url.QueryEscape(token), tok)
	if err != nil {
		return nil, err
	}
	var in struct {
		Events []struct {
			EventID     string `json:"event_id"`
			Kind        string `json:"kind"`
			Time        string `json:"time"`
			From        string `json:"from"`
			To          string `json:"to"`
			Reason      string `json:"reason"`
			Message     string `json:"message"`
			DurationSec int64  `json:"duration_seconds"`
			Flags       int    `json:"flags"`
		} `json:"events"`
	}
	if err := json.Unmarshal(b, &in); err != nil {
		return nil, err
	}
	out := make([]healthchecks.Event, 0, len(in.Events))
	for _, e := range in.Events {
		t, err := time.Parse(time.RFC3339Nano, e.Time)
		if err != nil {
			continue
		}
		out = append(out, healthchecks.Event{EventID: e.EventID, Token: token, Kind: e.Kind, Time: t, From: e.From, To: e.To, Reason: e.Reason,
			Message: e.Message, DurationSec: e.DurationSec, Maintenance: e.Flags&1 != 0, Silent: e.Flags&2 != 0, Hub: true})
	}
	return out, nil
}
