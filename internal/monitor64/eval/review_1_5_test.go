package eval

import "testing"

// Nicht erreichbar zaehlt als Kritisch: taeglich erinnern, solange nicht quittiert (vorher nur eine Meldung).
func TestUnreachableReminder(t *testing.T) {
	g := newRig(t)
	if r := g.at(0, nil, unreachable); len(r.Lines) != 1 || r.Lines[0].Kind != LineUnreachable {
		t.Fatalf("first: %+v", r.Lines)
	}
	if r := g.at(60, nil, unreachable); len(r.Lines) != 0 {
		t.Fatalf("no reminder within a day: %+v", r.Lines)
	}
	if r := g.at(24*60+1, nil, unreachable, quiet); len(r.Lines) != 0 {
		t.Fatalf("no reminder in quiet hours: %+v", r.Lines)
	}
	if r := g.at(24*60+2, nil, unreachable, func(r *Round) { r.HostAcked = true }); len(r.Lines) != 0 {
		t.Fatalf("acknowledged: %+v", r.Lines)
	}
	r := g.at(24*60+3, nil, unreachable)
	if len(r.Lines) != 1 || r.Lines[0].Kind != LineUnreachable || len(r.Messages) != 1 {
		t.Fatalf("reminder: %+v", r)
	}
	if r := g.at(24*60+4, nil, unreachable); len(r.Lines) != 0 {
		t.Fatalf("reminder only once a day: %+v", r.Lines)
	}
	if r := g.at(24*60+5, nil); len(r.Lines) != 1 || r.Lines[0].Kind != LineReachable {
		t.Fatalf("reachable again: %+v", r.Lines)
	}
}
