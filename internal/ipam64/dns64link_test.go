package ipam64

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// fakeDNS64 bildet die Bruecke in DNS64 nach (je Bezug eine Reservierung, eine Ausnahme, Eintraege) samt Eintraegen
// von Hand: gleiche werden uebernommen (gekennzeichnet), andere mit derselben IP/MAC bzw. demselben Namen und Wert sind
// ein Fehler ("dup"); Release gibt frei (Eintraege werden "von Hand").
type fakeDNS64 struct {
	mu       sync.Mutex
	res      map[string]OwnedRes
	excl     map[string]OwnedExcl
	recs     map[string][]OwnedRec
	handRes  map[string]OwnedRes // MAC -> Reservierung von Hand
	handExcl map[string]bool     // IP
	handRecs map[string]bool     // "name|wert"
	failRes  error
	released int
	noCheck  bool // ohne Vorpruefung (Check nil)
}

type fakeCheckKey struct{}

func checking(ctx context.Context) bool { v, _ := ctx.Value(fakeCheckKey{}).(bool); return v }

func newFake() *fakeDNS64 {
	return &fakeDNS64{res: map[string]OwnedRes{}, excl: map[string]OwnedExcl{}, recs: map[string][]OwnedRec{}, handRes: map[string]OwnedRes{},
		handExcl: map[string]bool{}, handRecs: map[string]bool{}}
}

var errFakeDup = errors.New("dup")

func (f *fakeDNS64) release(ref string) int {
	n := 0
	for k, r := range f.res {
		if ref == "" || k == ref {
			r.Ref = ""
			f.handRes[r.MAC] = r
			delete(f.res, k)
			n++
		}
	}
	for k, x := range f.excl {
		if ref == "" || k == ref {
			f.handExcl[x.IP] = true
			delete(f.excl, k)
			n++
		}
	}
	for k, l := range f.recs {
		if ref == "" || k == ref {
			for _, r := range l {
				f.handRecs[r.Name+"|"+r.Value] = true
			}
			delete(f.recs, k)
			n += len(l)
		}
	}
	return n
}

func (f *fakeDNS64) hooks() DNS64 {
	d := DNS64{
		Running: func() bool { return true },
		PutReservation: func(ctx context.Context, ref, mac, ip, name string) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.failRes != nil {
				return f.failRes
			}
			for k, r := range f.res {
				if k != ref && (r.MAC == mac || r.IP == ip) {
					return errFakeDup
				}
			}
			for _, r := range f.handRes {
				if (r.MAC == mac) != (r.IP == ip) {
					return errFakeDup
				}
			}
			if checking(ctx) {
				return nil
			}
			delete(f.handRes, mac)
			delete(f.excl, ref)
			f.res[ref] = OwnedRes{ref, mac, ip, name}
			return nil
		},
		DeleteReservation: func(ctx context.Context, ref string) error {
			if !checking(ctx) {
				f.mu.Lock()
				delete(f.res, ref)
				f.mu.Unlock()
			}
			return nil
		},
		PutExclude: func(ctx context.Context, ref, ip, _ string) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			for k, r := range f.res {
				if k != ref && r.IP == ip {
					return errFakeDup
				}
			}
			for _, r := range f.handRes {
				if r.IP == ip {
					return errFakeDup
				}
			}
			if checking(ctx) {
				return nil
			}
			delete(f.handExcl, ip)
			delete(f.res, ref)
			f.excl[ref] = OwnedExcl{ref, ip}
			return nil
		},
		DeleteExclude: func(ctx context.Context, ref string) error {
			if !checking(ctx) {
				f.mu.Lock()
				delete(f.excl, ref)
				f.mu.Unlock()
			}
			return nil
		},
		PutRecords: func(ctx context.Context, ref, name string, addrs []netip.Addr, ptr bool) (bool, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			var list []OwnedRec
			claimed := false
			for _, a := range addrs {
				for k, l := range f.recs {
					for _, r := range l {
						if k != ref && r.Name == name && r.Value == a.String() {
							return false, errFakeDup
						}
					}
				}
				claimed = claimed || f.handRecs[name+"|"+a.String()]
				if !checking(ctx) {
					delete(f.handRecs, name+"|"+a.String())
				}
				typ := "A"
				if a.Is6() {
					typ = "AAAA"
				}
				list = append(list, OwnedRec{ref, name, typ, a.String(), !ptr})
			}
			if !checking(ctx) {
				f.recs[ref] = list
			}
			return claimed, nil
		},
		DeleteRecords: func(ctx context.Context, ref string) error {
			if !checking(ctx) {
				f.mu.Lock()
				delete(f.recs, ref)
				f.mu.Unlock()
			}
			return nil
		},
		Release: func(ctx context.Context, ref string) (int64, error) {
			if checking(ctx) {
				return 0, nil
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			n := f.release(ref)
			f.released += n
			return int64(n), nil
		},
		Entries: func(context.Context) (Owned, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			var o Owned
			for _, r := range f.res {
				o.Reservations = append(o.Reservations, r)
			}
			for _, x := range f.excl {
				o.Excludes = append(o.Excludes, x)
			}
			for _, l := range f.recs {
				o.Records = append(o.Records, l...)
			}
			return o, nil
		},
		ErrKey: func(err error) string {
			if err != nil && err.Error() == "dup" {
				return "dns64.err.dhcp_res_dup"
			}
			return ""
		},
	}
	if !f.noCheck {
		d.Check = func(ctx context.Context) context.Context { return context.WithValue(ctx, fakeCheckKey{}, true) }
	}
	return d
}

func TestDNS64Link(t *testing.T) {
	m, _, _ := modTest(t)
	ctx := context.Background()
	f := newFake()
	m.SetDNS64(f.hooks())
	m.SetNetworks(func(context.Context) []NetHint {
		return []NetHint{{Name: "LAN", Subnet: netip.MustParsePrefix("192.168.1.0/24"), Start: ip("192.168.1.100"), End: ip("192.168.1.199"), Domain: "home.lan"}}
	})
	mustPrefix(t, m, Prefix{Prefix: "fd00:10::/64"}) // ohne Zone
	// DNS + DHCP: Reservierung und A-Eintrag mit PTR
	nas, err := m.ApplyAddress(ctx, Address{Address: "192.168.1.10", Name: "nas", MAC: "02:00:00:00:00:0a", DNS: true, PTR: true, DHCP: true}, "t")
	if err != nil {
		t.Fatal(err)
	}
	if f.res[nas.UID].IP != "192.168.1.10" || len(f.recs[nas.UID]) != 1 || f.recs[nas.UID][0].Name != "nas.home.lan" || f.recs[nas.UID][0].NoPTR {
		t.Fatalf("dns64: %+v %+v", f.res, f.recs)
	}
	fx, zoneErr, err := m.Effects(ctx, nas)
	if err != nil || zoneErr || len(fx) != 2 || fx[0].State != "ok" || fx[1].State != "ok" {
		t.Fatalf("effects: %+v %v", fx, err)
	}
	// im Pool ohne Reservierung: Ausnahme
	cam, err := m.ApplyAddress(ctx, Address{Address: "192.168.1.150", Name: "kamera", DNS: true}, "t")
	if err != nil {
		t.Fatal(err)
	}
	if f.excl[cam.UID].IP != "192.168.1.150" || f.res[cam.UID].IP != "" || f.recs[cam.UID][0].NoPTR != true {
		t.Fatalf("exclude: %+v %+v %+v", f.excl, f.res, f.recs)
	}
	// veraltet: alles in DNS64 weg, die Adresse bleibt
	cam.Status = StatusDeprecated
	if _, err := m.ApplyAddress(ctx, cam, "t"); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.excl[cam.UID]; ok || len(f.recs[cam.UID]) != 0 {
		t.Fatalf("deprecated: %+v %+v", f.excl, f.recs)
	}
	// DNS64 lehnt ab: neue Adresse wird nicht angelegt, geaenderte bleibt beim alten Stand
	f.failRes = errors.New("dup")
	if _, err := m.ApplyAddress(ctx, Address{Address: "192.168.1.20", Name: "drucker", MAC: "02:00:00:00:00:14", DHCP: true}, "t"); err == nil || m.dnsErrKey(err) == "" {
		t.Fatalf("new with dns64 error: %v", err)
	}
	if a, _ := m.AddressByIP(ctx, "192.168.1.20"); a != nil {
		t.Fatal("rejected address kept")
	}
	changed := nas
	changed.MAC = "02:00:00:00:00:0b"
	if _, err := m.ApplyAddress(ctx, changed, "t"); err == nil {
		t.Fatal("change with dns64 error accepted")
	}
	if a, _ := m.AddressByIP(ctx, "192.168.1.10"); a.MAC != "02:00:00:00:00:0a" || f.res[nas.UID].MAC != "02:00:00:00:00:0a" {
		t.Fatalf("rollback: %+v %+v", a, f.res[nas.UID])
	}
	f.failRes = nil
	// DNS an ohne Zone: abgelehnt
	if _, err := m.ApplyAddress(ctx, Address{Address: "fd00:10::5", Name: "x", DNS: true}, "t"); !errors.Is(err, ErrNoZone) {
		t.Fatalf("no zone: %v", err)
	}
	// IPv6 mit Zone an der Adresse: AAAA
	v6, err := m.ApplyAddress(ctx, Address{Address: "fd00:10::10", Name: "nas", DNS: true, DNSZone: "home.lan", PTR: true}, "t")
	if err != nil || f.recs[v6.UID][0].Type != "AAAA" {
		t.Fatalf("v6: %+v %v", f.recs, err)
	}
	// Abgleich: fehlender Eintrag wird repariert, sobald die Adresse ruht; Verwaistes erst im zweiten Lauf
	delete(f.recs, nas.UID)
	if n, _ := m.reconcile(ctx); n != 0 {
		t.Fatalf("reconcile too early: %d", n)
	}
	f.res["dead"] = OwnedRes{Ref: "dead", MAC: "02:00:00:00:00:ff", IP: "192.168.1.99"}
	m.now = func() time.Time { return time.Now().Add(settleFor + time.Minute) }
	if n, err := m.reconcile(ctx); err != nil || n != 1 || len(f.recs[nas.UID]) != 1 {
		t.Fatalf("reconcile: %d %v", n, err)
	}
	if _, ok := f.res["dead"]; !ok {
		t.Fatal("orphan removed in first run")
	}
	if n, _ := m.reconcile(ctx); n != 1 {
		t.Fatalf("orphan run: %d", n)
	}
	if _, ok := f.res["dead"]; ok {
		t.Fatal("orphan kept")
	}
	// Loeschen nimmt alles in DNS64 mit
	if _, err := m.RemoveAddress(ctx, v6.UID); err != nil || len(f.recs[v6.UID]) != 0 {
		t.Fatalf("remove: %v %+v", err, f.recs)
	}
	// Uebergabe: Kennzeichen weg, Schalter aus
	n, err := m.Handover(ctx, "t")
	if err != nil || n == 0 || f.released == 0 {
		t.Fatalf("handover: %d %v", n, err)
	}
	if a, _ := m.AddressByIP(ctx, "192.168.1.10"); a.DNS || a.DHCP {
		t.Fatalf("flags after handover: %+v", a)
	}
	if n, _ := m.reconcile(ctx); n != 0 || len(f.res) != 0 {
		t.Fatalf("reconcile after handover: %d %+v", n, f.res)
	}
	// DNS64 aus: nur IPAM64, kein Fehler
	m.SetDNS64(DNS64{Running: func() bool { return false }})
	if _, err := m.ApplyAddress(ctx, Address{Address: "192.168.1.30", Name: "pi", DNS: true}, "t"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Handover(ctx, "t"); !errors.Is(err, ErrNoDNS64) {
		t.Fatalf("handover without dns64: %v", err)
	}
}
