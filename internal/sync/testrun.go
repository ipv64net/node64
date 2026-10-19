package sync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/healthchecks"
	"github.com/ipv64net/node64/internal/wire"
)

// OnlineTest laesst ipv64 eine Check-Definition von den Standorten einmal messen (vor dem Umhaengen auf online
// oder hybrid) und wartet hoechstens 70 s auf das Ergebnis.
func (c *Live) OnlineTest(ctx context.Context, def wire.Check, locations []string) (*healthchecks.OnlineTest, error) {
	if !c.Linked() {
		return nil, errors.New("not linked with ipv64")
	}
	hub, tok := c.hubURL(), c.token()
	if hub == "" || tok == "" {
		return nil, errors.New("not linked with ipv64")
	}
	body, _ := json.Marshal(map[string]any{"definition": def, "locations": locations})
	b, status, err := c.postStatus(ctx, hub+"/v1/nodes/me/testruns", tok, body)
	if err != nil {
		return nil, err
	}
	if status != 201 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(b, &e)
		if e.Error == "" {
			e.Error = fmt.Sprintf("HTTP %d", status)
		}
		return &healthchecks.OnlineTest{Status: "failed", Error: e.Error}, nil
	}
	var created struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(b, &created); err != nil || created.ID == 0 {
		return nil, errors.New("hub: invalid testrun answer")
	}
	deadline := time.Now().Add(70 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
		b, err := c.get(ctx, hub+"/v1/nodes/me/testruns/"+strconv.FormatInt(created.ID, 10), tok)
		if err != nil {
			return nil, err
		}
		var tr struct {
			Status  string `json:"status"`
			Results map[string]struct {
				OK      bool            `json:"ok"`
				Error   string          `json:"error"`
				Results json.RawMessage `json:"results"`
			} `json:"results"`
		}
		if err := json.Unmarshal(b, &tr); err != nil {
			return nil, err
		}
		if tr.Status == "pending" || tr.Status == "running" {
			if time.Now().After(deadline) {
				return &healthchecks.OnlineTest{Status: "expired"}, nil
			}
			continue
		}
		out := &healthchecks.OnlineTest{Status: tr.Status}
		for loc, r := range tr.Results {
			msg := r.Error
			if msg == "" {
				var list []struct {
					Status    string  `json:"status"`
					Family    string  `json:"family"`
					LatencyMS float64 `json:"latency_ms"`
					Message   string  `json:"message"`
				}
				_ = json.Unmarshal(r.Results, &list)
				var parts []string
				for _, x := range list {
					p := strings.TrimSpace(x.Family + " " + x.Status + fmt.Sprintf(" %.1f ms", x.LatencyMS))
					if x.Message != "" {
						p += " (" + x.Message + ")"
					}
					parts = append(parts, p)
				}
				msg = strings.Join(parts, " | ")
			}
			out.Results = append(out.Results, healthchecks.OnlineTestRow{Location: loc, OK: r.OK, Message: msg})
		}
		sort.Slice(out.Results, func(i, j int) bool { return out.Results[i].Location < out.Results[j].Location })
		return out, nil
	}
}
