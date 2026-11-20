package filter

import (
	"bufio"
	"math/bits"
	"os"
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/procstat"
)

// Gesamtgrenze der Regeln nach dem Speicher des Geraets: gemessen gut 38 Byte je Regel im Betrieb; beim Neuladen
// steht der neue Matcher neben dem alten (zusammen gut 100 Byte je Regel). Ein Viertel des Speichers darf das
// belegen - so passt auch die Spitze beim Neuladen auf kleinen Geraeten.
const (
	minRules     = 4_000_000  // nie weniger (Stand bis 1.7.8)
	maxRulesCap  = 32_000_000 // nie mehr (gut 1,2 GB im Betrieb)
	maxRules32   = 8_000_000  // 32-Bit-Systeme: Adressraum
	bytesPerRule = 512        // Speicher je erlaubter Regel (Viertel des Speichers, ca. 128 Byte Spitze je Regel)
)

// autoMaxRules: Grenze aus dem Speicher (Container-Grenze, sonst RAM); unbekannt: minRules.
func autoMaxRules() int { return rulesFor(memoryBytes(), bits.UintSize) }

// rulesFor rechnet die Grenze aus dem Speicher (Bytes, 0 = unbekannt) und der Wortbreite.
func rulesFor(mem uint64, wordBits int) int {
	n := uint64(minRules)
	if mem > 0 {
		n = max(n, mem/bytesPerRule)
	}
	top := uint64(maxRulesCap)
	if wordBits < 64 {
		top = maxRules32
	}
	return int(min(n, top))
}

// memoryBytes: kleinster Wert aus RAM (/proc/meminfo) und Speichergrenze des Containers bzw. Dienstes (procstat).
func memoryBytes() uint64 {
	mem := memTotal()
	if v, ok := procstat.MemoryLimit(); ok && (mem == 0 || v < mem) {
		mem = v
	}
	return mem
}

// memTotal liest MemTotal aus /proc/meminfo (0 = unbekannt, z. B. kein Linux).
func memTotal() uint64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "MemTotal:"); ok {
			kb, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimSpace(v), " kB"), 10, 64)
			if err != nil {
				return 0
			}
			return kb << 10
		}
	}
	return 0
}

// MaxRules: geltende Gesamtgrenze aller Listen (fuer die Anzeige).
func MaxRules() int { return maxRules }
