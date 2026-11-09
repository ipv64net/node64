package m64bsd

import (
	"fmt"

	"github.com/ipv64net/node64/internal/m64linux"
	"github.com/ipv64net/node64/internal/m64proto"
)

// mergeZpoolStatus traegt Fehlertext und Scrub in die Pools ein - gleiche Regeln wie im Linux-Sammler (dort nicht
// exportiert): Errors bleibt "No known data errors", solange weder Daten- noch Geraetefehler (READ/WRITE/CKSUM > 0)
// vorliegen; sonst Kurztext, auch bei ONLINE.
func mergeZpoolStatus(pools []m64proto.ZPool, st map[string]m64linux.ZpoolStatus) {
	for i := range pools {
		s, ok := st[pools[i].Name]
		if !ok {
			continue
		}
		errs := s.Errors
		if d := s.DevErrors; d != [3]uint64{} {
			dev := fmt.Sprintf("Geraetefehler READ %d WRITE %d CKSUM %d", d[0], d[1], d[2])
			if errs == "" {
				errs = dev
			} else {
				errs += "; " + dev
			}
		}
		pools[i].Errors = clip(errs)
		if s.Status != "" && pools[i].Health != "ONLINE" {
			pools[i].Errors = clip(s.Status + " " + errs)
		}
		pools[i].ScanText = s.Scan
	}
}
