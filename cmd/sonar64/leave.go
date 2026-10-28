package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/ipv64net/node64/internal/sonar"
)

// leave tritt aus Sonar64 aus (sonar64 leave, Vertrag Abschnitt 10.2): meldet den Knoten bei ipv64.net ab und loescht
// Schluessel und Zustand im Datenordner. Exit 0 = erledigt, 1 = ipv64.net nicht erreichbar bzw. Fehler (lokal bleibt
// alles), 2 = falsche Einstellung. Meldungen enthalten nie das Token.
func leave(getenv func(string) string, out, errOut io.Writer) int {
	opt, err := loadEnv(getenv)
	if err != nil {
		fmt.Fprintln(errOut, "sonar64 leave: invalid settings:", err)
		return 2
	}
	cfg := opt.Config
	cfg.Version = Version
	cfg.Log = slog.New(slog.NewTextHandler(errOut, &slog.HandlerOptions{Level: slog.LevelError}))
	r, err := sonar.New(cfg)
	if err != nil {
		fmt.Fprintln(errOut, "sonar64 leave:", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := r.Leave(ctx); err != nil {
		fmt.Fprintln(errOut, "sonar64 leave: not signed off at ipv64.net:", err)
		fmt.Fprintln(errOut, "sonar64 leave: local key and state kept; ipv64.net signs off nodes without reports after 30 days")
		return 1
	}
	fmt.Fprintln(out, "sonar64: signed off at ipv64.net, key and state in", cfg.DataDir, "removed")
	return 0
}
