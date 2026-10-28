package notify

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"time"
)

// Erneute Zustellung: Ein Sender kennzeichnet voruebergehende Fehler (Zeitueberschreitung, Serverfehler 5xx,
// 429) mit Temporary; der Dispatcher versucht die Nachricht dann nach retryDelays erneut. Endgueltige Fehler
// (falsche Adresse, abgelehnt) werden nicht wiederholt. Die Versuche leben im Speicher: ein Neustart verwirft sie.

// retryDelays: Abstaende der erneuten Versuche nach dem ersten Fehlschlag (1, 5 und 15 Minuten).
var retryDelays = []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute}

type tempErr struct{ error }

func (e tempErr) Unwrap() error { return e.error }

// Temporary kennzeichnet einen voruebergehenden Fehler: die Zustellung wird spaeter erneut versucht.
func Temporary(err error) error {
	if err == nil {
		return nil
	}
	return tempErr{err}
}

// IsTemporary: der Fehler ist voruebergehend (Temporary).
func IsTemporary(err error) bool {
	var t tempErr
	return errors.As(err, &t)
}

// retryNote haengt an den Fehlertext, wann der naechste Versuch kommt (Zustellprotokoll und Log).
func retryNote(err error, n int) error {
	if !IsTemporary(err) || n >= len(retryDelays) {
		return err
	}
	return fmt.Errorf("%w (retry %d/%d in %s)", err, n+1, len(retryDelays), retryDelays[n])
}

// retry stellt eine Nachricht nach einem voruebergehenden Fehler erneut zu, solange der Dispatcher laeuft.
func (d *Dispatcher) retry(ch *Channel, s Sender, m Message, n int) {
	if n >= len(retryDelays) || d.ctx == nil {
		return
	}
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		t := time.NewTimer(retryDelays[n])
		defer t.Stop()
		select {
		case <-d.ctx.Done():
			return
		case <-t.C:
		}
		if !d.unchanged(d.ctx, ch) {
			d.log.Info("notification retry dropped, channel deleted, disabled or changed", "channel", ch.Name, "kind", m.Kind)
			return
		}
		sctx, cancel := context.WithTimeout(d.ctx, 30*time.Second)
		err := s.Send(sctx, ch, m)
		cancel()
		d.record(d.ctx, ch, m, retryNote(err, n+1))
		if IsTemporary(err) {
			d.retry(ch, s, m, n+1)
		}
	}()
}

// unchanged laedt den Kanal vor einem erneuten Versuch neu: geloescht, abgeschaltet oder mit anderem Ziel bzw.
// anderen Zugangsdaten = kein Versuch mit dem alten Stand. Ist die Liste gerade nicht lesbar, bleibt es beim Versuch.
func (d *Dispatcher) unchanged(ctx context.Context, ch *Channel) bool {
	same := func(list []*Channel) (found, ok bool) {
		for _, c := range list {
			if c.ID == ch.ID && c.Type == ch.Type {
				return true, c.Enabled && maps.Equal(c.Config, ch.Config)
			}
		}
		return false, false
	}
	list, err := d.st.ChannelsFor(ctx, ch.UserID)
	if err != nil {
		return true
	}
	if found, ok := same(list); found {
		return ok
	}
	if _, _, remote := d.hooks(); remote != nil { // ipv64-Kanaele ohne Verknuepfung (ueber die API)
		if found, ok := same(remote(ctx)); found {
			return ok
		}
	}
	return false
}
