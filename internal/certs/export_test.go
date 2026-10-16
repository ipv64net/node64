package certs

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"sort"
	"strings"
	"testing"

	"software.sslmate.com/src/go-pkcs12"
)

func TestExportFormats(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	certPEM, keyPEM := selfSignedPEM(t, 40, "nas.example.org", "*.example.org")
	c, err := e.m.Upload(ctx, certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	b, err := e.m.Bundle(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if b.FileBase() != "nas.example.org" || len(b.Fingerprint) != 64 {
		t.Fatalf("bundle: %s %s", b.FileBase(), b.Fingerprint)
	}
	for f, want := range map[string]string{FormatFullchain: "BEGIN CERTIFICATE", FormatCert: "BEGIN CERTIFICATE", FormatKey: "PRIVATE KEY", FormatPEM: "PRIVATE KEY"} {
		data, name, _, err := b.File(f)
		if err != nil || !strings.Contains(string(data), want) || !strings.HasPrefix(name, "nas.example.org.") {
			t.Fatalf("%s: %v %s", f, err, name)
		}
	}
	if _, _, _, err := b.File("exe"); err == nil {
		t.Fatal("unknown format must fail")
	}
	data, _, _, err := b.File(FormatZIP)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, f := range zr.File {
		files = append(files, f.Name)
		if f.Name == "privkey.pem" {
			rc, _ := f.Open()
			k, _ := io.ReadAll(rc)
			rc.Close()
			if string(k) != b.KeyPEM {
				t.Fatal("zip key differs")
			}
		}
	}
	sort.Strings(files)
	if strings.Join(files, ",") != "cert.pem,chain.pem,fullchain.pem,privkey.pem" {
		t.Fatalf("zip files: %v", files)
	}
	for _, legacy := range []bool{false, true} {
		p12, err := b.P12("geheim12", legacy)
		if err != nil {
			t.Fatal(err)
		}
		key, leaf, _, err := pkcs12.DecodeChain(p12, "geheim12")
		if err != nil || key == nil || leaf.Subject.CommonName != "nas.example.org" {
			t.Fatalf("p12 legacy=%v: %v", legacy, err)
		}
	}
	var ve *ValidationError
	if _, err := b.P12("abc", false); err == nil || !strings.Contains(err.Error(), "password") {
		t.Fatalf("short password: %v %v", err, ve)
	}
	m := b.Meta()
	if m.ID != c.ID || m.Fingerprint != b.Fingerprint || m.DaysLeft < 38 || len(m.Names) != 2 {
		t.Fatalf("meta: %+v", m)
	}
	if !HasKey(FormatZIP) || !HasKey("p12") || HasKey(FormatFullchain) {
		t.Fatal("HasKey")
	}
}

func TestExportPending(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	if _, err := e.m.Bundle(ctx, 99); err != ErrNotFound {
		t.Fatalf("missing: %v", err)
	}
}

// Die neuen Anbieter lassen sich mit ihren Feldern bauen (ohne Netz).
func TestMoreProviders(t *testing.T) {
	vals := map[string]map[string]string{
		"allinkl":     {"login": "w0123", "password": "pw"},
		"autodns":     {"username": "u", "password": "pw"},
		"bunny":       {"key": "k"},
		"checkdomain": {"token": "t"},
		"cloudns":     {"auth_id": "1", "password": "pw"},
		"dynu":        {"key": "k"},
		"hostinger":   {"token": "t"},
		"httpreq":     {"endpoint": "https://hook.example.org/acme"},
		"hurricane":   {"tokens": "example.org:abc, example.net:def"},
		"infomaniak":  {"token": "t"},
		"namecheap":   {"user": "u", "key": "k", "client_ip": "192.0.2.1"},
		"pdns":        {"url": "http://192.168.1.2:8081", "key": "k"},
		"rfc2136":     {"nameserver": "192.168.1.1", "tsig_key": "acme.", "tsig_secret": "c2VjcmV0c2VjcmV0c2VjcmV0"},
		"technitium":  {"url": "http://192.168.1.2:5380/", "token": "t"},
	}
	if n := len(Providers()); n != 26 {
		t.Fatalf("providers: %d", n)
	}
	for id, v := range vals {
		checked, err := checkValues(id, v)
		if err != nil {
			t.Fatalf("%s check: %v", id, err)
		}
		if _, err := buildProvider(id, checked); err != nil {
			t.Fatalf("%s build: %v", id, err)
		}
	}
	if _, err := buildProvider("hurricane", map[string]string{"tokens": "nur-text"}); err == nil {
		t.Fatal("hurricane format must be checked")
	}
	if _, err := buildProvider("cloudns", map[string]string{"password": "pw"}); err == nil {
		t.Fatal("cloudns needs an auth id")
	}
	if _, err := buildProvider("pdns", map[string]string{"url": "192.168.1.2", "key": "k"}); err == nil {
		t.Fatal("pdns url must be http(s)")
	}
}
