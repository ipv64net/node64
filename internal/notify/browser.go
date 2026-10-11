package notify

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Browser-Benachrichtigungen: Nachrichten gehen an alle geoeffneten Node64-Seiten (Server-Sent
// Events, /notifications/stream). Die Seite zeigt sie als Systembenachrichtigung (nach Zustimmung
// im Browser) und als Hinweis in der Seite. Ohne geoeffnete Seite kommt nichts an – dafuer gibt es
// die anderen Kanaele.

const TypeBrowser Type = "browser"

// BrowserEvent ist das, was die Seite bekommt.
type BrowserEvent struct {
	Kind    string    `json:"kind"`
	Title   string    `json:"title"`
	Text    string    `json:"text"`
	URL     string    `json:"url,omitempty"`
	Token   string    `json:"token,omitempty"`
	Time    time.Time `json:"time"`
	Channel string    `json:"channel"`
}

// Broadcast verteilt Ereignisse an alle verbundenen Browser.
type Broadcast struct {
	mu   sync.Mutex
	subs map[chan BrowserEvent]struct{}
}

// Browser ist die gemeinsame Verteilung der Node.
var Browser = &Broadcast{subs: map[chan BrowserEvent]struct{}{}}

// Subscribe meldet einen Browser an; cancel meldet ihn ab.
func (b *Broadcast) Subscribe() (<-chan BrowserEvent, func()) {
	ch := make(chan BrowserEvent, 16)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		if _, ok := b.subs[ch]; ok {
			delete(b.subs, ch)
			close(ch)
		}
		b.mu.Unlock()
	}
}

// Publish verteilt ein Ereignis und liefert die Zahl der erreichten Browser.
func (b *Broadcast) Publish(e BrowserEvent) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for ch := range b.subs {
		select {
		case ch <- e:
			n++
		default: // Browser haengt: diese Nachricht auslassen
		}
	}
	return n
}

// Clients liefert die Zahl der verbundenen Browser.
func (b *Broadcast) Clients() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.subs)
}

type browserSender struct{}

func (browserSender) Send(_ context.Context, ch *Channel, m Message) error {
	n := Browser.Publish(BrowserEvent{Kind: string(m.Kind), Title: m.Title, Text: m.Text, URL: m.URL, Token: m.Check.Token, Time: m.Time, Channel: ch.Name})
	if n == 0 {
		return errors.New("no browser with Node64 open – the notification could not be shown")
	}
	return nil
}
