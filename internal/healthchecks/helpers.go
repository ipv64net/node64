package healthchecks

import (
	"net"

	"github.com/ipv64net/node64/internal/store"
)

func splitHostPort(addr string) (string, string, error) { return net.SplitHostPort(addr) }

func auditEntry(actor, action, target, ip string) store.AuditEntry {
	return store.AuditEntry{Actor: actor, Action: action, Target: target, IP: ip, Origin: "local"}
}
