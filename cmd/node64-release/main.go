// node64-release: Werkzeug fuer das Selbst-Update (docs/PLAN-SELF-UPDATE.md).
//
//	node64-release keygen -out <datei>                     Schluesselpaar erzeugen; privat in <datei> (0600),
//	                                                        oeffentlich auf stdout (in internal/selfupdate/keys.go)
//	node64-release manifest -version V -channel C -base URL -out manifest.json node64-linux-amd64 ...
//	                                                        Manifest aus den Programmen bauen (Name: node64-linux-<arch>)
//	node64-release sign -key <datei> manifest.json          signieren -> manifest.json.sig
//	                                                        (ohne -key: Umgebungsvariable NODE64_SIGNING_KEY)
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/selfupdate"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: node64-release keygen|manifest|sign ...")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "manifest":
		err = manifest(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "node64-release:", err)
		os.Exit(1)
	}
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "", "file for the private key")
	_ = fs.Parse(args)
	if *out == "" {
		return errors.New("-out is required")
	}
	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("%s exists, not overwriting", *out)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, []byte(base64.StdEncoding.EncodeToString(priv.Seed())+"\n"), 0o600); err != nil {
		return err
	}
	fmt.Println(base64.StdEncoding.EncodeToString(pub))
	return nil
}

func manifest(args []string) error {
	fs := flag.NewFlagSet("manifest", flag.ExitOnError)
	version := fs.String("version", "", "version (without v)")
	channel := fs.String("channel", "", "stable or preview (default: from the version)")
	base := fs.String("base", selfupdate.DefaultBase, "download base URL")
	notes := fs.String("notes", "", "URL of the release notes")
	minv := fs.String("min-version", "", "minimum running version")
	out := fs.String("out", "manifest.json", "output file")
	_ = fs.Parse(args)
	v := strings.TrimPrefix(strings.TrimSpace(*version), "v")
	if v == "" || fs.NArg() == 0 {
		return errors.New("-version and at least one file are required")
	}
	ch := *channel
	if ch == "" {
		ch = "stable"
		if strings.Contains(v, "-") {
			ch = "preview"
		}
	}
	m := selfupdate.Manifest{Version: v, Channel: ch, Date: time.Now().UTC().Format(time.RFC3339), Notes: *notes, MinVersion: *minv, Files: map[string]selfupdate.File{}}
	for _, p := range fs.Args() {
		name := filepath.Base(p)
		arch, ok := strings.CutPrefix(name, "node64-linux-")
		if !ok {
			return fmt.Errorf("%s: expected node64-linux-<arch>", name)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		m.Files[arch] = selfupdate.File{URL: strings.TrimRight(*base, "/") + "/" + v + "/" + name, Size: int64(len(b)), SHA256: hex.EncodeToString(sum[:])}
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	return os.WriteFile(*out, append(b, '\n'), 0o644)
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	keyFile := fs.String("key", "", "private key file (default: env NODE64_SIGNING_KEY)")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("manifest file required")
	}
	raw := os.Getenv("NODE64_SIGNING_KEY")
	if *keyFile != "" {
		b, err := os.ReadFile(*keyFile)
		if err != nil {
			return err
		}
		raw = string(b)
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil || len(seed) != ed25519.SeedSize {
		return errors.New("no valid signing key")
	}
	key := ed25519.NewKeyFromSeed(seed)
	m, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	if _, err := selfupdate.Verify(m, selfupdate.Sign(m, key), []ed25519.PublicKey{key.Public().(ed25519.PublicKey)}); err != nil {
		return err
	}
	return os.WriteFile(fs.Arg(0)+".sig", append(selfupdate.Sign(m, key), '\n'), 0o644)
}
