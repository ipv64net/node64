package store

import (
	"context"
	"strings"
	"time"
)

// Sammel-Schreiber fuer Messpunkte der Nodes: statt je Nachricht ein INSERT und ein UPDATE
// werden alle Batches eines Zeitfensters (300 ms bzw. 2000 Zeilen) in einem INSERT und einem
// UPDATE geschrieben. Die Node bekommt ihr Ack erst nach dem Schreiben (keine Datenverluste).

type ingestJob struct {
	rows   [][]any // je Zeile 12 Werte wie im INSERT
	nodeID string
	ackSeq int64
	done   chan error
}

const ingestCols = `(token, source, node_seq, time, status, latency_ms, reason, message, family, details, flags, received_at)`

func (s *Store) startIngestWriter() {
	s.ingest = make(chan ingestJob, 20000)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		var batch []ingestJob
		rows := 0
		timer := time.NewTimer(time.Hour)
		timer.Stop()
		flush := func() {
			if len(batch) > 0 {
				err := s.writeIngest(batch)
				for _, j := range batch {
					j.done <- err
				}
			}
			batch, rows = batch[:0], 0
		}
		for {
			select {
			case <-s.stopCh:
				for {
					select {
					case j := <-s.ingest:
						batch = append(batch, j)
					default:
						flush()
						return
					}
				}
			case j := <-s.ingest:
				if len(batch) == 0 {
					timer.Reset(300 * time.Millisecond)
				}
				batch = append(batch, j)
				rows += len(j.rows)
				if rows >= 2000 {
					timer.Stop()
					flush()
				}
			case <-timer.C:
				flush()
			}
		}
	}()
}

func (s *Store) writeIngest(batch []ingestJob) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var sb strings.Builder
	var args []any
	n := 0
	for _, j := range batch {
		for _, r := range j.rows {
			if n == 0 {
				sb.WriteString(`INSERT IGNORE INTO hc2_measurements ` + ingestCols + ` VALUES `)
			} else {
				sb.WriteString(",")
			}
			sb.WriteString("(?,?,?,?,?,?,?,?,?,?,?,?)")
			args = append(args, r...)
			n++
		}
	}
	if n > 0 {
		if _, err := s.db.ExecContext(ctx, sb.String(), args...); err != nil {
			s.Metrics.add(&s.Metrics.DBErrors, 1)
			return err
		}
		s.Metrics.add(&s.Metrics.Measurements, int64(n))
	}
	// last_ack_seq je Node in einem UPDATE
	seqs := map[string]int64{}
	for _, j := range batch {
		if j.ackSeq > seqs[j.nodeID] {
			seqs[j.nodeID] = j.ackSeq
		}
	}
	if len(seqs) > 0 {
		var cs strings.Builder
		var ids []string
		uargs := make([]any, 0, len(seqs)*3)
		cs.WriteString(`UPDATE hc2_nodes SET last_ack_seq = GREATEST(last_ack_seq, CASE node_id`)
		for id, seq := range seqs {
			cs.WriteString(" WHEN ? THEN ?")
			uargs = append(uargs, id, seq)
			ids = append(ids, "?")
		}
		cs.WriteString(" ELSE last_ack_seq END) WHERE node_id IN (" + strings.Join(ids, ",") + ")")
		for id := range seqs {
			uargs = append(uargs, id)
		}
		if _, err := s.db.ExecContext(ctx, cs.String(), uargs...); err != nil {
			s.Metrics.add(&s.Metrics.DBErrors, 1)
			s.log.Warn("last_ack_seq update failed", "err", err)
		}
	}
	return nil
}
