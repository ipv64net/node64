package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/wire"
)

// Kleiner Test-Treiber ohne MySQL: protokolliert Befehle, Antworten liefert fn.
type fakeResult struct {
	cols     []string
	rows     [][]driver.Value
	affected int64
	err      error
}

type fakeDB struct {
	mu  sync.Mutex
	log []string
	fn  func(q string, args []driver.NamedValue) fakeResult
}

func (f *fakeDB) call(q string, args []driver.NamedValue) fakeResult {
	f.mu.Lock()
	f.log = append(f.log, q)
	f.mu.Unlock()
	return f.fn(q, args)
}

func (f *fakeDB) count(sub string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, q := range f.log {
		if strings.Contains(q, sub) {
			n++
		}
	}
	return n
}

type fakeConnector struct{ db *fakeDB }

func (c fakeConnector) Connect(context.Context) (driver.Conn, error) { return &fakeConn{c.db}, nil }
func (c fakeConnector) Driver() driver.Driver                        { return nil }

type fakeConn struct{ db *fakeDB }

func (c *fakeConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("not supported") }
func (c *fakeConn) Close() error                        { return nil }
func (c *fakeConn) Begin() (driver.Tx, error)           { return fakeTx{}, nil }
func (c *fakeConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return fakeTx{}, nil
}
func (c *fakeConn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	r := c.db.call(q, args)
	if r.err != nil {
		return nil, r.err
	}
	return driver.RowsAffected(r.affected), nil
}
func (c *fakeConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	r := c.db.call(q, args)
	if r.err != nil {
		return nil, r.err
	}
	return &fakeRows{cols: r.cols, rows: r.rows}, nil
}

type fakeTx struct{}

func (fakeTx) Commit() error   { return nil }
func (fakeTx) Rollback() error { return nil }

type fakeRows struct {
	cols []string
	rows [][]driver.Value
}

func (r *fakeRows) Columns() []string { return r.cols }
func (r *fakeRows) Close() error      { return nil }
func (r *fakeRows) Next(dest []driver.Value) error {
	if len(r.rows) == 0 {
		return io.EOF
	}
	copy(dest, r.rows[0])
	r.rows = r.rows[1:]
	return nil
}

func fakeStore(fn func(q string, args []driver.NamedValue) fakeResult) (*Store, *fakeDB) {
	f := &fakeDB{fn: fn}
	s := &Store{db: sql.OpenDB(fakeConnector{f}), log: slog.New(slog.NewTextHandler(io.Discard, nil)), Metrics: NewMetrics()}
	return s, f
}

// Rueckmeldungen gelten nur fuer Kommandos/Auftraege der meldenden Node.
func TestDoneOnlyForOwnNode(t *testing.T) {
	s, f := fakeStore(func(q string, args []driver.NamedValue) fakeResult {
		if strings.HasPrefix(q, "UPDATE hc2_commands") || strings.HasPrefix(q, "UPDATE hc2_send_orders") {
			if !strings.Contains(q, "node_id = ?") || args[len(args)-1].Value != "node-a" {
				t.Errorf("update without node check: %s %v", q, args)
			}
			return fakeResult{affected: 0} // Kommando gehoert einer anderen Node
		}
		return fakeResult{cols: []string{"args", "node_id"}}
	})
	if err := s.CommandDone(context.Background(), "node-a", wire.CommandResult{ID: 5, OK: true}); err != nil {
		t.Fatal(err)
	}
	if f.count("SELECT args") != 0 {
		t.Fatal("foreign command must not reach the testrun result")
	}
	if err := s.SendOrderDone(context.Background(), "node-a", 7, true, ""); err != nil {
		t.Fatal(err)
	}
}

// Messpunkte nur fuer Checks des eigenen Accounts; Besitzer werden zwischengespeichert.
func TestIngestMeasurementsOwnTokens(t *testing.T) {
	s, f := fakeStore(func(q string, args []driver.NamedValue) fakeResult {
		if strings.HasPrefix(q, "SELECT token, userid FROM hc2_checks") {
			return fakeResult{cols: []string{"token", "userid"}, rows: [][]driver.Value{{"mine", int64(7)}, {"theirs", int64(8)}}}
		}
		return fakeResult{}
	})
	own, err := s.ownedTokens(context.Background(), 7, []string{"mine", "theirs", "unknown", "mine"})
	if err != nil {
		t.Fatal(err)
	}
	if !own["mine"] || own["theirs"] || own["unknown"] {
		t.Fatalf("owned: %v", own)
	}
	// zweiter Stapel: bekannte Tokens aus dem Cache, nur der unbekannte wird erneut gefragt
	own, _ = s.ownedTokens(context.Background(), 8, []string{"mine", "theirs"})
	if own["mine"] || !own["theirs"] || f.count("SELECT token, userid") != 1 {
		t.Fatalf("cache: %v, queries %d", own, f.count("SELECT token, userid"))
	}

	// Stapel nur mit fremden Tokens: nichts schreiben (der Sammel-Schreiber fehlt hier, er wuerde haengen)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	n := &Node{ID: "node-a", UserID: 9, LastAckSeq: 4}
	ack, err := s.IngestMeasurements(ctx, n, []wire.Measurement{{Seq: 3, Token: "mine", Time: time.Now()}, {Seq: 4, Token: "theirs", Time: time.Now()}})
	if err != nil {
		t.Fatal(err)
	}
	if ack.AckSeq != 4 {
		t.Fatalf("ack %d", ack.AckSeq)
	}
}

// Eine aktive Node eines anderen Accounts laesst sich nicht per Code uebernehmen.
func TestLinkPollRefusesForeignNode(t *testing.T) {
	for _, tc := range []struct {
		name       string
		owner      int64
		revoked    any
		want       error
		wantRevoke bool
	}{
		{"foreign active", 8, nil, ErrNodeOwned, false},
		{"foreign revoked", 8, "2026-10-01 00:00:00.000", nil, true},
		{"same account", 7, nil, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, f := fakeStore(func(q string, args []driver.NamedValue) fakeResult {
				switch {
				case strings.HasPrefix(q, "SELECT node_id, node_name"):
					return fakeResult{cols: []string{"node_id", "node_name", "node_version", "poll_secret", "userid", "location", "remote_mgmt", "consumed_at", "expires_at"},
						rows: [][]driver.Value{{"n1", "box", "1", "sec", int64(7), "", "full", nil, "2099-01-01 00:00:00.000"}}}
				case strings.HasPrefix(q, "SELECT userid, revoked_at FROM hc2_nodes"):
					return fakeResult{cols: []string{"userid", "revoked_at"}, rows: [][]driver.Value{{tc.owner, tc.revoked}}}
				case strings.HasPrefix(q, "SELECT"):
					return fakeResult{err: errors.New("not in test")}
				}
				return fakeResult{affected: 1}
			})
			out, err := s.LinkPoll(context.Background(), wire.LinkPoll{Code: "ABCD-EFGH", PollSecret: "sec"})
			if !errors.Is(err, tc.want) {
				t.Fatalf("err %v, want %v", err, tc.want)
			}
			if tc.want != nil {
				if out != nil || f.count("INSERT INTO hc2_nodes") != 0 || f.count("UPDATE hc2_link_codes SET consumed_at") != 1 {
					t.Fatal("refused link must not touch the node, but consume the code")
				}
				return
			}
			if out == nil || out.NodeToken == "" {
				t.Fatal("no token")
			}
			if got := f.count("UPDATE hc2_node_tokens SET revoked_at") == 1; got != tc.wantRevoke {
				t.Fatalf("revoke old tokens: %v, want %v", got, tc.wantRevoke)
			}
		})
	}
}
