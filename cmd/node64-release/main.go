// node64-release: Werkzeug fuer das Selbst-Update (docs/PLAN-SELF-UPDATE.md).
//
//	node64-release keygen -out <datei>                     Schluesselpaar erzeugen; privat in <datei> (0600),
//	                                                        oeffentlich auf stdout (in internal/selfupdate/keys.go)
//	node64-release manifest -version V -channel C -base URL -out manifest.json node64-linux-amd64 ...
//	                                                        Manifest aus den Programmen bauen (Name: node64-linux-<arch>)
//	node64-release sign -key <datei> manifest.json          signieren -> manifest.json.sig
//	                                                        (ohne -key: Umgebungsvariable NODE64_SIGNING_KEY)
//	node64-release agent-sign -key <datei> -version V [-os O -arch A] monitor64-agent-O-A ...
//	                                                        Update des Monitor64-Agents signieren -> <datei>.update.json
//	                                                        (Kopfzeile fuer die Anfrage "update"; ohne -key wie sign;
//	                                                        ohne -os/-arch aus dem Dateinamen, dann auch mehrere Dateien)
//	node64-release agent-index -version V -out agents.json <ordner>
//	                                                        Verzeichnis der Agent-Dateien aus dem Ordner bauen
//	                                                        (monitor64-agent-<os>-<arch>[.exe], install.sh, install.ps1),
//	                                                        dazu <ordner>/SHA256SUMS; signieren mit sign
//	                                                        (docs/MONITOR64-AGENT-RELEASE.md)
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

	"github.com/ipv64net/node64/internal/m64proto"
	"github.com/ipv64net/node64/internal/monitor64/agentdist"
	"github.com/ipv64net/node64/internal/selfupdate"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: node64-release keygen|manifest|sign|agent-sign|agent-index ...")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "agent-sign":
		err = agentSign(os.Args[2:])
	case "agent-index":
		err = agentIndex(os.Args[2:])
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

// signingKey liest den privaten Schluessel aus der Datei bzw. der Umgebungsvariablen NODE64_SIGNING_KEY.
func signingKey(keyFile string) (ed25519.PrivateKey, error) {
	raw := os.Getenv("NODE64_SIGNING_KEY")
	if keyFile != "" {
		b, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, err
		}
		raw = string(b)
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("no valid signing key")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// agentSign schreibt die signierte Kopfzeile (m64proto.UpdateHeader) fuer ein Update des Monitor64-Agents.
func agentSign(args []string) error {
	fs := flag.NewFlagSet("agent-sign", flag.ExitOnError)
	keyFile := fs.String("key", "", "private key file (default: env NODE64_SIGNING_KEY)")
	version := fs.String("version", "", "agent version (without v)")
	goos := fs.String("os", "", "GOOS of the binary (default: from the file name)")
	arch := fs.String("arch", "", "GOARCH of the binary (default: from the file name)")
	_ = fs.Parse(args)
	named := *goos != "" || *arch != ""
	if fs.NArg() == 0 || *version == "" || named && (fs.NArg() != 1 || *goos == "" || *arch == "") {
		return errors.New("usage: agent-sign -key <file> -version V [-os O -arch A] <binary> ...")
	}
	key, err := signingKey(*keyFile)
	if err != nil {
		return err
	}
	return agentSignFiles(fs.Args(), strings.TrimPrefix(*version, "v"), *goos, *arch, key)
}

// agentSignFiles schreibt je Datei <datei>.update.json. Ohne goos/goarch kommt die Plattform aus dem Dateinamen
// (monitor64-agent-<os>-<arch>[.exe]); Kopfzeilen eines frueheren Laufs im Muster monitor64-agent-* werden uebergangen.
func agentSignFiles(files []string, version, goos, goarch string, key ed25519.PrivateKey) error {
	for _, p := range files {
		if strings.HasSuffix(p, agentdist.HeaderSuffix) {
			continue
		}
		o, a := goos, goarch
		if o == "" && a == "" {
			var ok bool
			if o, a, ok = agentdist.ParseFileName(filepath.Base(p)); !ok {
				return fmt.Errorf("%s: expected monitor64-agent-<os>-<arch>[.exe] (or give -os and -arch)", p)
			}
		}
		h, err := agentHeader(p, version, o, a, key)
		if err != nil {
			return err
		}
		b, _ := json.Marshal(h)
		if err := os.WriteFile(p+agentdist.HeaderSuffix, append(b, '\n'), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// agentIndex schreibt das Verzeichnis der Agent-Dateien (agents.json) aus einem Ordner mit den gebauten Dateien und
// legt SHA256SUMS dazu (damit pruefen die Installationsskripte). Signiert wird danach mit sign.
func agentIndex(args []string) error {
	fs := flag.NewFlagSet("agent-index", flag.ExitOnError)
	version := fs.String("version", "", "agent version (without v)")
	out := fs.String("out", agentdist.IndexFile, "output file")
	_ = fs.Parse(args)
	if fs.NArg() != 1 || *version == "" {
		return errors.New("usage: agent-index -version V [-out agents.json] <folder>")
	}
	return writeAgentIndex(*version, fs.Arg(0), *out)
}

func writeAgentIndex(version, dir, out string) error {
	ix, err := agentdist.Build(version, dir)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, agentdist.SumsFile), ix.Sums(), 0o644); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(ix, "", "  ")
	return os.WriteFile(out, append(b, '\n'), 0o644)
}

// agentHeader baut die Kopfzeile: Groesse, SHA-256 und Signatur ueber m64proto.SignedMessage.
func agentHeader(path, version, goos, arch string, key ed25519.PrivateKey) (m64proto.UpdateHeader, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return m64proto.UpdateHeader{}, err
	}
	if len(b) == 0 || int64(len(b)) > m64proto.MaxUpdateBytes {
		return m64proto.UpdateHeader{}, fmt.Errorf("%s: invalid size %d", path, len(b))
	}
	sum := sha256.Sum256(b)
	h := m64proto.UpdateHeader{Version: version, OS: goos, Arch: arch, Size: int64(len(b)), SHA256: hex.EncodeToString(sum[:])}
	h.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, m64proto.SignedMessage(h.Version, h.OS, h.Arch, h.SHA256)))
	return h, nil
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	keyFile := fs.String("key", "", "private key file (default: env NODE64_SIGNING_KEY)")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("manifest file required")
	}
	key, err := signingKey(*keyFile)
	if err != nil {
		return err
	}
	m, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	if _, err := selfupdate.Verify(m, selfupdate.Sign(m, key), []ed25519.PublicKey{key.Public().(ed25519.PublicKey)}); err != nil {
		return err
	}
	return os.WriteFile(fs.Arg(0)+".sig", append(selfupdate.Sign(m, key), '\n'), 0o644)
}
