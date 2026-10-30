package honeypot

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"time"
)

// Bericht aus den gespeicherten Ereignissen (Phase H2, Format report_types.go). Quell-IPs aus privaten bzw.
// reservierten Netzen (lokale Tests, interne Scanner) bleiben lokal; sie fehlen in Quellen und Proben.

const reportDetailMax = 200 // Bytes je Detail in einer Quelle

// reportNoNets sind Netze, die nie gemeldet werden (zusaetzlich zu Private, Loopback, Link-Local, Multicast).
var reportNoNets = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "dieses Netz"
	netip.MustParsePrefix("100.64.0.0/10"),   // CGNAT
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF-Protokolle
	netip.MustParsePrefix("192.0.2.0/24"),    // Doku (TEST-NET-1)
	netip.MustParsePrefix("198.18.0.0/15"),   // Benchmark
	netip.MustParsePrefix("198.51.100.0/24"), // Doku (TEST-NET-2)
	netip.MustParsePrefix("203.0.113.0/24"),  // Doku (TEST-NET-3)
	netip.MustParsePrefix("240.0.0.0/4"),     // reserviert, Broadcast
	netip.MustParsePrefix("100::/64"),        // Discard
	netip.MustParsePrefix("2001:db8::/32"),   // Doku
	netip.MustParsePrefix("3fff::/20"),       // Doku (RFC 9637)
}

// reportable: die Quell-IP darf gemeldet werden (oeffentlich, nicht reserviert).
func reportable(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	a = a.Unmap().WithZone("")
	if a.IsUnspecified() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsInterfaceLocalMulticast() || a.IsMulticast() {
		return false
	}
	for _, p := range reportNoNets {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// ownAddr: a ist eine eigene oeffentliche Adresse (IPv4 genau, IPv6 im selben /64). Zugriffe von dort sind eigenes
// Ausprobieren, keine Angriffe - weder Quelle noch Probe (sonst zaehlt z. B. der JA4 des eigenen Browsers).
func ownAddr(a netip.Addr, own []netip.Addr) bool {
	a = a.Unmap().WithZone("")
	for _, o := range own {
		o = o.Unmap()
		switch {
		case o.Is4() && a == o:
			return true
		case o.Is6() && a.Is6():
			if p, err := o.Prefix(64); err == nil && p.Contains(a) {
				return true
			}
		}
	}
	return false
}

// hasEvents: es gibt Ereignisse mit Quell-IP in [start, end) (guenstig ueber den Index auf ts).
func (s *Store) hasEvents(ctx context.Context, start, end time.Time) (bool, error) {
	var n int
	err := s.st.Reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM (SELECT 1 FROM hp_events WHERE ts >= ? AND ts < ? AND src <> '' LIMIT 1)`,
		storeTime(start), storeTime(end)).Scan(&n)
	return n > 0, err
}

// BuildReport baut den Bericht fuer [start, end): Quellen je (src, kind, service, port, source, rule) mit Anzahl und
// erstem/letztem Zeitpunkt, dazu Proben (Zugangsdaten, Pfade, User-Agents, Fingerabdruecke, Payloads; nur aus dem Honeypot), jeweils
// haeufigste zuerst und auf die Grenzen
// aus report_types.go gekuerzt (Rest in Dropped). ReportID und Sensor setzt der Aufrufer. own: eigene oeffentliche
// Adressen, sie bleiben wie private lokal.
func (s *Store) BuildReport(ctx context.Context, start, end time.Time, own ...netip.Addr) (*Report, error) {
	start, end = start.UTC(), end.UTC()
	rep := &Report{Schema: ReportSchema, Period: ReportPeriod{Start: start, End: end}, Sources: []ReportSource{}}
	from, to := storeTime(start), storeTime(end)
	r := s.st.Reader()

	// Quell-IPs, die lokal bleiben (fuer die Proben als Ausschlussliste)
	rows, err := r.QueryContext(ctx, `SELECT DISTINCT src FROM hp_events WHERE ts >= ? AND ts < ? AND src <> ''`, from, to)
	if err != nil {
		return nil, err
	}
	private, total := []string{}, 0
	for rows.Next() {
		var src string
		if err := rows.Scan(&src); err != nil {
			rows.Close()
			return nil, err
		}
		total++
		if a, err := netip.ParseAddr(src); err != nil || !reportable(a) || ownAddr(a, own) {
			private = append(private, src)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(private) == total {
		return rep, nil // keine oder nur lokale Quellen: nichts zu melden
	}
	skip, _ := json.Marshal(private)
	not := ` AND src <> '' AND src NOT IN (SELECT value FROM json_each(?))`
	// Proben (Zugangsdaten, Pfade, User-Agents, Payloads) nur aus dem Honeypot, nie aus echten Logs (Plan Abschnitt 1b)
	hp := not + ` AND source = 'honeypot'`

	// Quellen (private IPs schon in SQL ausgeschlossen), je Quelle und Regel getrennt (H5)
	rows, err = r.QueryContext(ctx, `SELECT src, kind, service, port, source, rule, COUNT(*) AS n, MIN(ts), MAX(ts), MAX(detail) FROM hp_events
		WHERE ts >= ? AND ts < ?`+not+` GROUP BY src, kind, service, port, source, rule ORDER BY n DESC, src, kind, service, port, source, rule`, from, to, string(skip))
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var x ReportSource
		var first, last string
		if err := rows.Scan(&x.IP, &x.Kind, &x.Service, &x.Port, &x.Source, &x.Rule, &x.Count, &first, &last, &x.Detail); err != nil {
			rows.Close()
			return nil, err
		}
		if len(rep.Sources) >= ReportMaxSources {
			rep.Dropped++
			continue
		}
		x.First, x.Last = storeParseTime(first), storeParseTime(last)
		if x.Source == SrcHoneypot {
			x.Rule, x.Detail = "honeypot/"+x.Service+"@1", storeClip(x.Detail, reportDetailMax)
		} else {
			x.Detail = "" // aus echten Logs nur IP, Art, Dienst, Port, Anzahl, Zeitraum und Regel (Plan Abschnitt 1b)
		}
		rep.Sources = append(rep.Sources, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Zugangsdaten (nur Login-Dienste)
	rows, err = r.QueryContext(ctx, `SELECT service, username, password, COUNT(*) AS n FROM hp_events WHERE ts >= ? AND ts < ?`+hp+`
		AND service NOT IN ('tcp', 'scan') AND (username <> '' OR password <> '')
		GROUP BY service, username, password ORDER BY n DESC, service, username, password`, from, to, string(skip))
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var c ReportCred
		if err := rows.Scan(&c.Service, &c.User, &c.Pass, &c.Count); err != nil {
			rows.Close()
			return nil, err
		}
		if len(rep.Samples.Credentials) >= ReportMaxSamples {
			rep.Dropped++
			continue
		}
		rep.Samples.Credentials = append(rep.Samples.Credentials, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Pfade, User-Agents und Fingerabdruecke (H6)
	for _, k := range []struct {
		col string
		dst *[]ReportKey
	}{{"path", &rep.Samples.Paths}, {"ua", &rep.Samples.UserAgents}, {"fingerprint", &rep.Samples.Fingerprints}} {
		rows, err = r.QueryContext(ctx, `SELECT `+k.col+` AS k, COUNT(*) AS n FROM hp_events WHERE ts >= ? AND ts < ?`+hp+` AND `+k.col+` <> ''
			GROUP BY k ORDER BY n DESC, k`, from, to, string(skip))
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var x ReportKey
			if err := rows.Scan(&x.Key, &x.Count); err != nil {
				rows.Close()
				return nil, err
			}
			if len(*k.dst) >= ReportMaxSamples {
				rep.Dropped++
				continue
			}
			*k.dst = append(*k.dst, x)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}

	// Payloads: SHA-256 ueber die gespeicherten Bytes, Anfang als base64
	rows, err = r.QueryContext(ctx, `SELECT payload, service, port, COUNT(*) AS n FROM hp_events WHERE ts >= ? AND ts < ?`+hp+`
		AND payload IS NOT NULL AND length(payload) > 0 GROUP BY payload, service, port ORDER BY n DESC, payload, service, port`, from, to, string(skip))
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var p []byte
		var x ReportPayload
		if err := rows.Scan(&p, &x.Service, &x.Port, &x.Count); err != nil {
			rows.Close()
			return nil, err
		}
		if len(rep.Samples.Payloads) >= ReportMaxSamples {
			rep.Dropped++
			continue
		}
		if len(p) > MaxPayload {
			p = p[:MaxPayload]
		}
		sum := sha256.Sum256(p)
		x.SHA256, x.Head = hex.EncodeToString(sum[:]), base64.StdEncoding.EncodeToString(p)
		rep.Samples.Payloads = append(rep.Samples.Payloads, x)
	}
	rows.Close()
	return rep, rows.Err()
}

// reportIPs zaehlt die verschiedenen Quell-IPs eines Berichts (Anzeige "gemeldete Quellen").
func reportIPs(rep *Report) int64 {
	seen := make(map[string]struct{}, len(rep.Sources))
	for _, x := range rep.Sources {
		seen[x.IP] = struct{}{}
	}
	return int64(len(seen))
}
