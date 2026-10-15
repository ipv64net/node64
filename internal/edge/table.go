package edge

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"
)

// table ist der Stand der angemeldeten Namen zum schnellen Nachschlagen (wird bei jeder Aenderung neu gebaut).
type table struct {
	exact map[string][]*Route // Name -> Routen, laengster Pfad zuerst
	wild  map[string][]*Route // Elternname ("example.com" fuer "*.example.com")
}

func buildTable(owners map[string][]Route) *table {
	t := &table{exact: map[string][]*Route{}, wild: map[string][]*Route{}}
	for _, list := range owners {
		for i := range list {
			rt := &list[i]
			for _, n := range rt.Names {
				if parent, ok := strings.CutPrefix(n, "*."); ok {
					t.wild[parent] = append(t.wild[parent], rt)
				} else {
					t.exact[n] = append(t.exact[n], rt)
				}
			}
		}
	}
	for _, m := range []map[string][]*Route{t.exact, t.wild} {
		for _, list := range m {
			sort.SliceStable(list, func(i, j int) bool { return len(list[i].Path) > len(list[j].Path) })
		}
	}
	return t
}

// lookup findet die Routen zu einem Namen: exakt vor Wildcard (eine Ebene). key benennt den Treffer
// ("" = keiner), damit sich Name der Verbindung und Host-Kopf vergleichen lassen.
func (t *table) lookup(name string) (key string, routes []*Route) {
	if name == "" {
		return "", nil
	}
	if list, ok := t.exact[name]; ok {
		return name, list
	}
	if i := strings.IndexByte(name, '.'); i > 0 {
		if list, ok := t.wild[name[i+1:]]; ok {
			return "*." + name[i+1:], list
		}
	}
	return "", nil
}

// pick waehlt die Route mit dem laengsten passenden Pfad (https: nur Routen mit HTTPS-Handler).
func pick(routes []*Route, path string, https bool) *Route {
	for _, rt := range routes {
		if https && rt.Handler == nil {
			continue
		}
		if rt.Path == "" || path == rt.Path || strings.HasPrefix(path, strings.TrimSuffix(rt.Path, "/")+"/") {
			return rt
		}
	}
	return nil
}

// NormalizeName prueft einen Namen und bringt ihn in die Grundform (klein, ohne Punkt am Ende). Erlaubt ist
// ein Wildcard "*." ganz vorn.
func NormalizeName(n string) (string, error) {
	n = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
	if n == "" {
		return "", errors.New("empty name")
	}
	if len(n) > 253 {
		return "", fmt.Errorf("name %q too long", n)
	}
	rest, wild := strings.CutPrefix(n, "*.")
	labels := strings.Split(rest, ".")
	if len(labels) < 2 && wild {
		return "", fmt.Errorf("wildcard %q needs a domain", n)
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", fmt.Errorf("name %q invalid", n)
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", fmt.Errorf("name %q invalid", n)
			}
		}
	}
	return n, nil
}

// fallbackCert ist ein selbstsigniertes Zertifikat fuer Namen ohne eigenes (nur im Speicher; der Browser warnt).
func (e *Edge) fallbackCert() *tls.Certificate {
	e.fallback.once.Do(func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
		tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "node64"}, NotBefore: time.Now().Add(-time.Hour),
			NotAfter: time.Now().AddDate(10, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
		if err != nil {
			panic(err)
		}
		e.fallback.crt = &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	})
	return e.fallback.crt
}
