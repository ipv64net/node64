package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/secrets"
)

func rawTOTP(t *testing.T, st *Store, id int64) string {
	t.Helper()
	var v string
	if err := st.Reader().QueryRow(`SELECT totp_secret FROM users WHERE id = ?`, id).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// TOTP-Geheimnis: Altbestand im Klartext bleibt lesbar und wird beim Start verschluesselt; neue Geheimnisse landen
// verschluesselt in der Datenbank, gelesen wird transparent im Klartext; ohne Codec bleibt alles Klartext.
func TestTOTPCodec(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	u, _ := st.CreateUser(ctx, "anna", "$h", "", "UTC")
	v, _ := st.CreateUser(ctx, "bert", "$h", "", "UTC")
	_ = st.SetUserTOTP(ctx, u.ID, "ALTGEHEIM", "r1")
	if rawTOTP(t, st, u.ID) != "ALTGEHEIM" {
		t.Fatal("without codec the secret stays plain")
	}

	box, err := secrets.Load(filepath.Join(t.TempDir(), "secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	st.SetTOTPCodec(box.Encrypt, box.Decrypt)
	if x, _ := st.UserByID(ctx, u.ID); x.TOTPSecret != "ALTGEHEIM" {
		t.Fatalf("plain legacy secret readable: %q", x.TOTPSecret)
	}
	if n, err := st.EncryptTOTPSecrets(ctx); err != nil || n != 1 {
		t.Fatalf("encrypt legacy: %d %v", n, err)
	}
	if raw := rawTOTP(t, st, u.ID); !secrets.IsEncrypted(raw) || strings.Contains(raw, "ALTGEHEIM") {
		t.Fatalf("legacy secret encrypted in the db: %q", raw)
	}
	if n, _ := st.EncryptTOTPSecrets(ctx); n != 0 {
		t.Fatal("second run changes nothing")
	}
	if x, _ := st.UserByName(ctx, "anna"); x.TOTPSecret != "ALTGEHEIM" {
		t.Fatalf("read back: %q", x.TOTPSecret)
	}
	if ok, err := st.EnableUserTOTP(ctx, v.ID, "NEUGEHEIM", "r2", 5); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if raw := rawTOTP(t, st, v.ID); !secrets.IsEncrypted(raw) {
		t.Fatalf("new secret encrypted: %q", raw)
	}
	all, _ := st.Users(ctx)
	if len(all) != 2 || all[1].TOTPSecret != "NEUGEHEIM" {
		t.Fatalf("users list: %+v", all)
	}
	if x, _ := st.UserByUID(ctx, v.UID); x.TOTPSecret != "NEUGEHEIM" {
		t.Fatal("by uid")
	}
	// abschalten: leer bleibt leer (EnableUserTOTP prueft auf '')
	_ = st.UpdateUserTOTP(ctx, v.ID, "")
	if rawTOTP(t, st, v.ID) != "" {
		t.Fatal("empty stays empty")
	}
	// anderer Schluessel: nicht lesbar, 2FA bleibt an (kein Code passt)
	other, _ := secrets.Load(filepath.Join(t.TempDir(), "other.key"))
	st.SetTOTPCodec(other.Encrypt, other.Decrypt)
	if x, _ := st.UserByID(ctx, u.ID); x.TOTPSecret == "" || x.TOTPSecret == "ALTGEHEIM" {
		t.Fatalf("unreadable secret keeps 2fa on: %q", x.TOTPSecret)
	}
	if _, err := st.DecodeTOTP(rawTOTP(t, st, u.ID)); err == nil {
		t.Fatal("decode with the wrong key must fail")
	}
}

// EncodeTOTP verschluesselt einen schon verschluesselten Wert nicht noch einmal (sonst ergaebe das Entschluesseln den
// Chiffretext als vermeintliches Geheimnis).
func TestEncodeTOTPNoDouble(t *testing.T) {
	st := openTest(t)
	box, _ := secrets.Load(filepath.Join(t.TempDir(), "secret.key"))
	other, _ := secrets.Load(filepath.Join(t.TempDir(), "other.key"))
	st.SetTOTPCodec(box.Encrypt, box.Decrypt)
	enc := st.EncodeTOTP("GEHEIM")
	if !secrets.IsEncrypted(enc) {
		t.Fatalf("encrypted: %q", enc)
	}
	if again := st.EncodeTOTP(enc); again != enc {
		t.Fatalf("encrypted twice: %q", again)
	}
	foreign := other.Encrypt("FREMD")
	if again := st.EncodeTOTP(foreign); again != foreign {
		t.Fatalf("foreign ciphertext encrypted again: %q", again)
	}
}
