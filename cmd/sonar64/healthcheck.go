package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

// healthcheck fragt GET /health des Mini-Status ab (Docker HEALTHCHECK). Ohne SONAR64_STATUS gibt es keinen Port;
// dann meldet er gesund, solange der Prozess laeuft (der Container lebt nur mit ihm).
func healthcheck(getenv func(string) string) int {
	v := getenv("SONAR64_STATUS")
	if v == "" {
		return 0
	}
	addr, err := parseStatusAddr(v)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	host, port, _ := net.SplitHostPort(addr)
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + net.JoinHostPort(host, port) + "/health")
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "healthcheck: status", resp.StatusCode)
		return 1
	}
	return 0
}
