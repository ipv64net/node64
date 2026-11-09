package monitor64

import (
	"context"
	"math"
	"math/rand/v2"
	"strconv"
	"sync/atomic"
	"time"
)

// Lastgenerator (Plan "Zielwerte"): N Schein-Hosts mit je loadMetrics Messgroessen, abgefragt wie echte Hosts
// (Planer, Intervall 1 min). Nur mit NODE64_MONITOR64_LOADGEN=N, nie in der Oberflaeche.

const loadMetrics = 30

type loadGen struct {
	n      int
	sched  *Scheduler
	ser    Series
	points atomic.Int64
	since  time.Time
}

func newLoadGen(n int, sched *Scheduler, ser Series) *loadGen {
	return &loadGen{n: n, sched: sched, ser: ser, since: time.Now()}
}

func (l *loadGen) start() {
	for i := 0; i < l.n; i++ {
		host := "loadgen-" + strconv.Itoa(i)
		seed := uint64(i)
		l.sched.Set("load:"+host, time.Minute, func(context.Context) { l.poll(host, seed) })
	}
}

// poll erzeugt plausible Werte (Sinus ueber den Tag plus Rauschen), wie sie ein Host liefern wuerde.
func (l *loadGen) poll(host string, seed uint64) {
	now := time.Now()
	r := rand.New(rand.NewPCG(seed, uint64(now.UnixNano())))
	day := float64(now.Unix()%86400) / 86400 * 2 * math.Pi
	for k := 0; k < loadMetrics; k++ {
		base := float64((seed*31+uint64(k)*17)%80) + 5
		v := base + 10*math.Sin(day+float64(k)) + r.Float64()*3
		l.ser.Append(host+"|m"+strconv.Itoa(k), now, math.Round(v*100)/100)
	}
	l.points.Add(loadMetrics)
}

// rate: Messpunkte je Sekunde seit dem Start.
func (l *loadGen) rate() float64 {
	s := time.Since(l.since).Seconds()
	if s <= 0 {
		return 0
	}
	return float64(l.points.Load()) / s
}
