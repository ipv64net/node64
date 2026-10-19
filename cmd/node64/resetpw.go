package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"

	"github.com/ipv64net/node64/internal/config"
	"github.com/ipv64net/node64/internal/store"
	"github.com/ipv64net/node64/internal/web"
)

// resetPassword ist der Notfallzugang bei vergessenem Passwort: "docker exec node64 /node64 reset-password".
// Wer den Befehl ausfuehren kann, hat ohnehin Zugriff auf den Host und das Volume /data. Er setzt ein neues
// Passwort (zufaellig oder vorgegeben), schaltet auf Wunsch die Zwei-Faktor-Anmeldung ab und beendet alle
// Sitzungen des Benutzers. Der laufende Node muss dafuer nicht angehalten werden.
func resetPassword(args []string) int {
	fs := flag.NewFlagSet("reset-password", flag.ContinueOnError)
	user := fs.String("user", "", "Benutzername (leer = der einzige Benutzer)")
	pw := fs.String("password", "", "neues Passwort, mindestens 10 Zeichen (leer = zufaellig erzeugen)")
	no2fa := fs.Bool("disable-2fa", false, "Zwei-Faktor-Anmeldung abschalten (Authenticator und Wiederherstellungscodes verloren)")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Aufruf: node64 reset-password [-user NAME] [-password NEU] [-disable-2fa]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if _, err := os.Stat(cfg.DBPath()); err != nil {
		fmt.Fprintf(os.Stderr, "Keine Datenbank unter %s – ist die Node schon eingerichtet und das Volume eingehaengt?\n", cfg.DBPath())
		return 1
	}
	ctx := context.Background()
	st, err := store.Open(ctx, cfg.DBPath(), cfg.BackupDir(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Datenbank:", err)
		return 1
	}
	defer st.Close()

	var u *store.User
	if *user != "" {
		if u, err = st.UserByName(ctx, *user); err != nil || u == nil {
			fmt.Fprintf(os.Stderr, "Benutzer %q nicht gefunden.\n", *user)
			return 1
		}
	} else {
		users, err := st.Users(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Benutzer lesen:", err)
			return 1
		}
		switch len(users) {
		case 0:
			fmt.Fprintln(os.Stderr, "Es gibt noch keinen Benutzer – die Einrichtung im Browser starten.")
			return 1
		case 1:
			u = users[0]
		default:
			fmt.Fprintln(os.Stderr, "Mehrere Benutzer – bitte mit -user NAME waehlen:")
			for _, x := range users {
				fmt.Fprintln(os.Stderr, "  "+x.Username)
			}
			return 1
		}
	}

	generated := *pw == ""
	if generated {
		if *pw, err = randomPassword(20); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	if len(*pw) < 10 { // wie checkPassword in der Oberflaeche
		fmt.Fprintln(os.Stderr, "Das Passwort muss mindestens 10 Zeichen lang sein.")
		return 1
	}
	hash, err := web.HashPassword(*pw)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := st.UpdateUserPassword(ctx, u.ID, hash); err != nil {
		fmt.Fprintln(os.Stderr, "Passwort speichern:", err)
		return 1
	}
	details := "reset-password (Kommandozeile)"
	if *no2fa {
		if err := st.SetUserTOTP(ctx, u.ID, "", ""); err != nil {
			fmt.Fprintln(os.Stderr, "Zwei-Faktor-Anmeldung abschalten:", err)
			return 1
		}
		details += ", 2FA abgeschaltet"
	}
	if err := st.DeleteUserSessions(ctx, u.ID, ""); err != nil {
		fmt.Fprintln(os.Stderr, "Sitzungen beenden:", err)
		return 1
	}
	_ = st.Audit(ctx, store.AuditEntry{Actor: u.Username, Action: "settings.password", Details: details})

	fmt.Printf("Passwort fuer %q neu gesetzt, alle Sitzungen beendet.\n", u.Username)
	if *no2fa {
		fmt.Println("Zwei-Faktor-Anmeldung ist abgeschaltet – nach dem Anmelden bitte neu einrichten.")
	}
	if generated {
		fmt.Println("Neues Passwort:", *pw)
		fmt.Println("Bitte nach dem Anmelden unter Einstellungen aendern.")
	}
	return 0
}

// randomPassword: n Zeichen ohne leicht verwechselbare (0/O, 1/l/I).
func randomPassword(n int) (string, error) {
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, n)
	for i := range b {
		k, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		b[i] = alphabet[k.Int64()]
	}
	return string(b), nil
}
