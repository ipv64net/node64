package tsdb

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"sync"
)

// Blockformat (Version 1):
//
//	byte    Version (1)
//	byte    Flags (Bit 0: Rumpf mit deflate komprimiert)
//	Rumpf:
//	  uvarint n                  Anzahl Punkte
//	  varint  t0, d1, dod...     Zeitstempel: erster Wert, erste Differenz, danach Delta-of-Delta (zigzag)
//	  uvarint Spalten
//	  je Spalte:
//	    byte Modus               0..9 = Ganzzahl mit so vielen Nachkommastellen, 0xFF = float64-Bits
//	    Modus Ganzzahl: uvarint Anzahl Sonderwerte, je Sonderwert uvarint Abstand + byte Art
//	                    (NaN, +Inf, -Inf), danach varint-Deltas der uebrigen Werte
//	    Modus float64:  je Wert uvarint (Bits XOR vorige Bits)
//
// Werte werden auf hoechstens digits Nachkommastellen gerundet; die Skalierung je Spalte ergibt sich aus
// den Werten (ganze Zahlen brauchen keine Nachkommastelle). Passt ein Wert nicht mehr exakt in eine
// Ganzzahl (> 2^53), werden zuerst Nachkommastellen geopfert, notfalls die float64-Bits gespeichert.

const (
	codecVersion = 1
	flagDeflate  = 1
	modeFloat    = 0xFF
	maxDigits    = 9
	maxBlockPts  = 1 << 17 // Schutz beim Dekodieren
	maxCols      = 8
	maxBody      = 8 << 20
	minDeflate   = 48 // kleinere Rumpfe lohnen das Komprimieren nicht
	exactInt     = 1 << 53

	specNaN    = 0
	specPosInf = 1
	specNegInf = 2
)

var pow10 = [...]float64{1, 10, 100, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9}

var errBadBlock = errors.New("tsdb: beschaedigter Block")

func finite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }

// encodeBlock packt Zeitstempel (Sekunden) und Spalten gleicher Laenge in einen Block.
func encodeBlock(ts []int64, cols [][]float64, digits int) []byte {
	digits = min(max(digits, 0), maxDigits)
	body := make([]byte, 0, 16+len(ts)*(2+3*len(cols)))
	body = binary.AppendUvarint(body, uint64(len(ts)))
	var prev, prevD int64
	for i, t := range ts {
		switch i {
		case 0:
			body = binary.AppendVarint(body, t)
		case 1:
			prevD = t - prev
			body = binary.AppendVarint(body, prevD)
		default:
			d := t - prev
			body = binary.AppendVarint(body, d-prevD)
			prevD = d
		}
		prev = t
	}
	body = binary.AppendUvarint(body, uint64(len(cols)))
	for _, c := range cols {
		body = appendColumn(body, c[:len(ts)], digits)
	}
	out := make([]byte, 2, 2+len(body))
	out[0] = codecVersion
	if len(body) >= minDeflate {
		if z := deflate(body); len(z) < len(body) {
			out[1] = flagDeflate
			return append(out, z...)
		}
	}
	return append(out, body...)
}

func appendColumn(b []byte, c []float64, digits int) []byte {
	ints, s, ok := scaleColumn(c, digits)
	if !ok {
		b = append(b, modeFloat)
		var prev uint64
		for _, v := range c {
			x := math.Float64bits(v)
			b = binary.AppendUvarint(b, x^prev)
			prev = x
		}
		return b
	}
	b = append(b, byte(s))
	b = binary.AppendUvarint(b, uint64(len(c)-len(ints)))
	last := 0
	for i, v := range c {
		if finite(v) {
			continue
		}
		b = binary.AppendUvarint(b, uint64(i-last))
		last = i
		switch {
		case math.IsNaN(v):
			b = append(b, specNaN)
		case v > 0:
			b = append(b, specPosInf)
		default:
			b = append(b, specNegInf)
		}
	}
	var prev int64
	for _, x := range ints {
		b = binary.AppendVarint(b, x-prev)
		prev = x
	}
	return b
}

// scaleColumn rundet die endlichen Werte auf Ganzzahlen und waehlt die kleinste Zahl an Nachkommastellen,
// die nach dem Runden auf digits Stellen noch noetig ist.
func scaleColumn(c []float64, digits int) (ints []int64, s int, ok bool) {
	maxAbs := 0.0
	for _, v := range c {
		if finite(v) {
			maxAbs = max(maxAbs, math.Abs(v))
		}
	}
	d := digits
	for d >= 0 && math.Round(maxAbs*pow10[d]) > exactInt {
		d--
	}
	if d < 0 {
		return nil, 0, false
	}
	ints = make([]int64, 0, len(c))
	common := d // gemeinsame Nullen am Ende aller Werte
	for _, v := range c {
		if !finite(v) {
			continue
		}
		x := int64(math.Round(v * pow10[d]))
		ints = append(ints, x)
		if x != 0 && common > 0 {
			tz := 0
			for y := x; tz < common && y%10 == 0; y /= 10 {
				tz++
			}
			common = tz
		}
	}
	if common > 0 {
		div := int64(pow10[common])
		for i := range ints {
			ints[i] /= div
		}
	}
	return ints, d - common, true
}

// decodeBlock liest einen Block; Fehler bei jeder Unstimmigkeit, nie Panik.
func decodeBlock(b []byte) (ts []int64, cols [][]float64, err error) {
	if len(b) < 2 || b[0] != codecVersion || b[1]&^flagDeflate != 0 {
		return nil, nil, errBadBlock
	}
	body := b[2:]
	if b[1]&flagDeflate != 0 {
		if body, err = inflate(body); err != nil {
			return nil, nil, err
		}
	}
	r := reader{b: body}
	n := r.uvarint()
	if r.err != nil || n > maxBlockPts || n > uint64(len(body)) {
		return nil, nil, errBadBlock
	}
	ts = make([]int64, n)
	var prev, prevD int64
	for i := range ts {
		x := r.varint()
		switch i {
		case 0:
			prev = x
		case 1:
			prevD = x
			prev += x
		default:
			prevD += x
			prev += prevD
		}
		ts[i] = prev
	}
	nc := r.uvarint()
	if r.err != nil || nc > maxCols {
		return nil, nil, errBadBlock
	}
	cols = make([][]float64, nc)
	for c := range cols {
		vals := make([]float64, n)
		mode := r.byte()
		switch {
		case r.err != nil:
		case mode == modeFloat:
			var prevBits uint64
			for i := range vals {
				prevBits ^= r.uvarint()
				vals[i] = math.Float64frombits(prevBits)
			}
		case mode <= maxDigits:
			nsp := r.uvarint()
			if nsp > n {
				return nil, nil, errBadBlock
			}
			var special []bool
			if nsp > 0 {
				special = make([]bool, n)
			}
			idx := uint64(0)
			for j := uint64(0); j < nsp && r.err == nil; j++ {
				d := r.uvarint()
				if (j > 0 && d == 0) || d >= n {
					return nil, nil, errBadBlock
				}
				idx += d
				if idx >= n {
					return nil, nil, errBadBlock
				}
				special[idx] = true
				switch r.byte() {
				case specNaN:
					vals[idx] = math.NaN()
				case specPosInf:
					vals[idx] = math.Inf(1)
				case specNegInf:
					vals[idx] = math.Inf(-1)
				default:
					return nil, nil, errBadBlock
				}
			}
			p := pow10[mode]
			var x int64
			for i := range vals {
				if special != nil && special[i] {
					continue
				}
				x += r.varint()
				if mode == 0 {
					vals[i] = float64(x)
				} else {
					vals[i] = float64(x) / p
				}
			}
		default:
			return nil, nil, errBadBlock
		}
		if r.err != nil {
			return nil, nil, errBadBlock
		}
		cols[c] = vals
	}
	if r.err != nil || len(r.b) != 0 {
		return nil, nil, errBadBlock
	}
	return ts, cols, nil
}

// reader liest Varints mit haftendem Fehler.
type reader struct {
	b   []byte
	err error
}

func (r *reader) uvarint() uint64 {
	if r.err != nil {
		return 0
	}
	x, n := binary.Uvarint(r.b)
	if n <= 0 {
		r.err = errBadBlock
		return 0
	}
	r.b = r.b[n:]
	return x
}

func (r *reader) varint() int64 {
	if r.err != nil {
		return 0
	}
	x, n := binary.Varint(r.b)
	if n <= 0 {
		r.err = errBadBlock
		return 0
	}
	r.b = r.b[n:]
	return x
}

func (r *reader) byte() byte {
	if r.err != nil {
		return 0
	}
	if len(r.b) == 0 {
		r.err = errBadBlock
		return 0
	}
	c := r.b[0]
	r.b = r.b[1:]
	return c
}

var (
	zwPool = sync.Pool{New: func() any {
		w, _ := flate.NewWriter(nil, flate.DefaultCompression) // kaum groesser als BestCompression, deutlich schneller
		return w
	}}
	zrPool sync.Pool
)

func deflate(b []byte) []byte {
	var buf bytes.Buffer
	buf.Grow(len(b))
	w := zwPool.Get().(*flate.Writer)
	w.Reset(&buf)
	_, _ = w.Write(b)
	_ = w.Close()
	zwPool.Put(w)
	return buf.Bytes()
}

func inflate(b []byte) ([]byte, error) {
	src := bytes.NewReader(b)
	var zr io.ReadCloser
	if v := zrPool.Get(); v != nil {
		zr = v.(io.ReadCloser)
		if err := zr.(flate.Resetter).Reset(src, nil); err != nil {
			return nil, errBadBlock
		}
	} else {
		zr = flate.NewReader(src)
	}
	out, err := io.ReadAll(io.LimitReader(zr, maxBody+1))
	zrPool.Put(zr)
	if err != nil || len(out) > maxBody {
		return nil, errBadBlock
	}
	return out, nil
}
