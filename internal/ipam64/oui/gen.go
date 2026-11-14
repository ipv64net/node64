//go:build ignore

// gen erzeugt oui.txt.gz aus den oeffentlichen Registern der IEEE (MA-L, MA-M, MA-S): go run gen.go
// Nur Praefix und Hersteller (gekuerzt auf 64 Zeichen), sortiert, gepackt.
package main

import (
	"compress/gzip"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

var sources = []string{
	"https://standards-oui.ieee.org/oui/oui.csv",
	"https://standards-oui.ieee.org/oui28/mam.csv",
	"https://standards-oui.ieee.org/oui36/oui36.csv",
}

func main() {
	out := map[string]string{}
	client := &http.Client{Timeout: 2 * time.Minute}
	for _, u := range sources {
		resp, err := client.Get(u)
		if err != nil {
			fail(err)
		}
		if resp.StatusCode != http.StatusOK {
			fail(fmt.Errorf("%s: %s", u, resp.Status))
		}
		r := csv.NewReader(resp.Body)
		r.FieldsPerRecord = -1
		if _, err := r.Read(); err != nil { // Kopfzeile: Registry, Assignment, Organization Name, Organization Address
			fail(err)
		}
		for {
			rec, err := r.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				fail(err)
			}
			if len(rec) < 3 {
				continue
			}
			p := strings.ToLower(strings.TrimSpace(rec[1]))
			name := strings.Join(strings.Fields(rec[2]), " ")
			if len(name) > 64 {
				name = name[:64]
			}
			if (len(p) == 6 || len(p) == 7 || len(p) == 9) && name != "" && !strings.ContainsAny(name, "\t\n") {
				out[p] = name
			}
		}
		resp.Body.Close()
	}
	keys := make([]string, 0, len(out))
	for k := range out {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	f, err := os.Create("oui.txt.gz")
	if err != nil {
		fail(err)
	}
	zw, _ := gzip.NewWriterLevel(f, gzip.BestCompression)
	fmt.Fprintf(zw, "# IEEE MA-L/MA-M/MA-S, %s, %d Eintraege\n", time.Now().UTC().Format("2006-01-02"), len(keys))
	for _, k := range keys {
		fmt.Fprintf(zw, "%s\t%s\n", k, out[k])
	}
	if err := zw.Close(); err != nil {
		fail(err)
	}
	if err := f.Close(); err != nil {
		fail(err)
	}
	fmt.Println("oui.txt.gz:", len(keys), "Eintraege")
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
