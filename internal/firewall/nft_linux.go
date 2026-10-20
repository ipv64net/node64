//go:build linux

package firewall

import (
	"errors"
	"fmt"
	"os"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// nftables ueber Netlink (github.com/google/nftables, reines Go). Entspricht:
//
//	table inet node64 {
//		set blocklist_v4 { type ipv4_addr; flags interval; }
//		set blocklist_v6 { type ipv6_addr; flags interval; }
//		chain input { type filter hook input priority filter - 10; policy accept;
//			ip saddr @blocklist_v4 counter drop
//			ip6 saddr @blocklist_v6 counter drop }
//		chain forward { type filter hook forward priority filter - 10; policy accept; … wie input }
//	}
//
// Die Elemente gehen in Stuecken (elemChunk) in mehreren Nachrichten derselben Transaktion; der Sendepuffer wird
// passend vergroessert (SO_SNDBUFFORCE, geht mit NET_ADMIN), weil der Kernel einen Batch nur am Stueck annimmt.

const elemChunk = 1000 // Elemente je Netlink-Nachricht (Attribut-Laenge hoechstens 64 KiB)

type nftBackend struct{}

func newNFT() (Backend, error) { return nftBackend{}, nil }

var nftTable = &nftables.Table{Family: nftables.TableFamilyINet, Name: Table}

// conn oeffnet eine Verbindung mit Puffern fuer etwa elems Elemente.
func (nftBackend) conn(elems int) (*nftables.Conn, error) {
	snd := max(elems*80+(1<<20), 4<<20)
	return nftables.New(nftables.WithSockOptions(func(c *netlink.Conn) error {
		rc, err := c.SyscallConn()
		if err != nil {
			return nil
		}
		_ = rc.Control(func(fd uintptr) {
			if unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, snd) != nil {
				_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, snd)
			}
			if unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, 8<<20) != nil {
				_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, 8<<20)
			}
		})
		return nil
	}))
}

func sets() (s4, s6 *nftables.Set) {
	s4 = &nftables.Set{Table: nftTable, Name: SetV4, KeyType: nftables.TypeIPAddr, Interval: true}
	s6 = &nftables.Set{Table: nftTable, Name: SetV6, KeyType: nftables.TypeIP6Addr, Interval: true}
	return s4, s6
}

// elements: je Bereich ein Start- und ein End-Element (End = erste Adresse danach, IntervalEnd).
func elements(rs []Range) []nftables.SetElement {
	out := make([]nftables.SetElement, 0, 2*len(rs))
	for _, r := range rs {
		out = append(out, nftables.SetElement{Key: r.From.AsSlice()})
		if end := r.To.Next(); end.IsValid() { // letzte Adresse der Familie: offenes Ende (kommt nach Reserved nicht vor)
			out = append(out, nftables.SetElement{Key: end.AsSlice(), IntervalEnd: true})
		}
	}
	return out
}

func addElements(c *nftables.Conn, s *nftables.Set, rs []Range) error {
	el := elements(rs)
	for i := 0; i < len(el); i += elemChunk {
		if err := c.SetAddElements(s, el[i:min(i+elemChunk, len(el))]); err != nil {
			return err
		}
	}
	return nil
}

// rule: "<ip|ip6> saddr @set counter drop" fuer inet-Tabellen (Familie vorher pruefen).
func rule(ch *nftables.Chain, s *nftables.Set, v6 bool) *nftables.Rule {
	proto, off, ln := byte(unix.NFPROTO_IPV4), uint32(12), uint32(4)
	if v6 {
		proto, off, ln = byte(unix.NFPROTO_IPV6), 8, 16
	}
	return &nftables.Rule{Table: nftTable, Chain: ch, Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: off, Len: ln},
		&expr.Lookup{SourceRegister: 1, SetName: s.Name, SetID: s.ID},
		&expr.Counter{},
		&expr.Verdict{Kind: expr.VerdictDrop},
	}}
}

func (b nftBackend) Apply(v4, v6 []Range) error {
	c, err := b.conn(2 * (len(v4) + len(v6)))
	if err != nil {
		return err
	}
	// vorhandene Tabelle (stehengelassen oder alter Stand) in derselben Transaktion ersetzen
	c.AddTable(nftTable)
	c.DelTable(nftTable)
	c.AddTable(nftTable)
	s4, s6 := sets()
	if err := c.AddSet(s4, nil); err != nil {
		return err
	}
	if err := c.AddSet(s6, nil); err != nil {
		return err
	}
	if err := addElements(c, s4, v4); err != nil {
		return err
	}
	if err := addElements(c, s6, v6); err != nil {
		return err
	}
	accept := nftables.ChainPolicyAccept
	for _, hook := range []struct {
		name string
		hook *nftables.ChainHook
	}{{"input", nftables.ChainHookInput}, {"forward", nftables.ChainHookForward}} {
		ch := c.AddChain(&nftables.Chain{Name: hook.name, Table: nftTable, Type: nftables.ChainTypeFilter, Hooknum: hook.hook,
			Priority: nftables.ChainPriorityRef(Priority), Policy: &accept})
		c.AddRule(rule(ch, s4, false))
		c.AddRule(rule(ch, s6, true))
	}
	return hint(c.Flush())
}

func (b nftBackend) Update(v4, v6 *[]Range) error {
	n := 0
	if v4 != nil {
		n += len(*v4)
	}
	if v6 != nil {
		n += len(*v6)
	}
	c, err := b.conn(2 * n)
	if err != nil {
		return err
	}
	s4, s6 := sets()
	for _, x := range []struct {
		s  *nftables.Set
		rs *[]Range
	}{{s4, v4}, {s6, v6}} {
		if x.rs == nil {
			continue
		}
		c.FlushSet(x.s)
		if err := addElements(c, x.s, *x.rs); err != nil {
			return err
		}
	}
	return hint(c.Flush())
}

func (b nftBackend) Exists() (bool, error) {
	c, err := b.conn(0)
	if err != nil {
		return false, err
	}
	ts, err := c.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return false, hint(err)
	}
	for _, t := range ts {
		if t.Name == Table {
			return true, nil
		}
	}
	return false, nil
}

func (b nftBackend) Remove() error {
	ok, err := b.Exists()
	if err != nil || !ok {
		return err
	}
	c, err := b.conn(0)
	if err != nil {
		return err
	}
	c.DelTable(nftTable)
	if err := c.Flush(); err != nil && !errors.Is(err, unix.ENOENT) {
		return hint(err)
	}
	return nil
}

// hint ergaenzt fehlende Rechte um den Hinweis auf NET_ADMIN.
func hint(err error) error {
	if err != nil && (errors.Is(err, os.ErrPermission) || errors.Is(err, unix.EPERM)) {
		return fmt.Errorf("%w (nftables needs --cap-add NET_ADMIN and --network host)", err)
	}
	return err
}
