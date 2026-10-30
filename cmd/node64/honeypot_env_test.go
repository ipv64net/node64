package main

import (
	"strings"
	"testing"
)

// Dienst-Profile, Hostname der Fallen und Name in der Node-Uebersicht aus der Umgebung (Modus ohne Oberflaeche).
func TestHoneypotEnvPersonas(t *testing.T) {
	hc, err := honeypotModeFromEnv(hpEnv(nil))
	if err != nil || hc.Sensor.Personas != nil || hc.Sensor.Hostname != "" || hc.Name != "" {
		t.Fatalf("defaults: %+v %v", hc, err)
	}
	hc, err = honeypotModeFromEnv(hpEnv(map[string]string{"NODE64_HONEYPOT_PERSONAS": " SSH:22=Dropbear, http:8080=apache,,ssh:2222=openssh-ubuntu",
		"NODE64_HONEYPOT_HOSTNAME": "Web01.Example.net", "NODE64_NAME": "Keller-Pi ✓"}))
	if err != nil {
		t.Fatal(err)
	}
	if p := hc.Sensor.Personas; len(p) != 3 || p["ssh:22"] != "dropbear" || p["http:8080"] != "apache" || p["ssh:2222"] != "openssh-ubuntu" {
		t.Fatalf("personas: %v", p)
	}
	if hc.Sensor.Hostname != "web01.example.net" || hc.Name != "Keller-Pi ✓" {
		t.Fatalf("hostname/name: %q %q", hc.Sensor.Hostname, hc.Name)
	}
	// „verwundbar wirken“: nur aktive Fallen mit aelteren Versionen (http, https, ssh, mysql)
	if hc, err = honeypotModeFromEnv(hpEnv(map[string]string{"NODE64_HONEYPOT_VULNERABLE": " SSH:22,http:80"})); err != nil ||
		strings.Join(hc.Sensor.Vulnerable, ",") != "http:80,ssh:22" {
		t.Fatalf("vulnerable: %+v %v", hc, err)
	}
	for env, want := range map[string]string{"ssh:2200": "ssh:2200 is not an active trap", "telnet:23": "cannot look vulnerable"} {
		if _, err := honeypotModeFromEnv(hpEnv(map[string]string{"NODE64_HONEYPOT_VULNERABLE": env})); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("vulnerable %q: %v", env, err)
		}
	}
	// eigene Dienste: Profil fuer einen Port der Liste
	if hc, err = honeypotModeFromEnv(hpEnv(map[string]string{"NODE64_HONEYPOT_SERVICES": "https:8443,ssh:22", "NODE64_HONEYPOT_PERSONAS": "https:8443=pve"})); err != nil ||
		hc.Sensor.Personas["https:8443"] != "pve" {
		t.Fatalf("custom: %+v %v", hc, err)
	}
	for env, want := range map[string]string{
		"ssh:22":                      "is not service:port=profile",
		"ssh:22=":                     "is not service:port=profile",
		"ssh:22=dropbear,ssh:22=nope": "listed twice",
		"ssh:22=nginx":                `profile "nginx" is not available for "ssh:22"`,
		"ftp:21=dropbear":             "is not available",
		"ssh:99999=dropbear":          "is not available",
		"ssh:2200=dropbear":           "ssh:2200 is not an active trap",
	} {
		_, err := honeypotModeFromEnv(hpEnv(map[string]string{"NODE64_HONEYPOT_PERSONAS": env}))
		if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "NODE64_HONEYPOT_PERSONAS") {
			t.Errorf("%q: %v", env, err)
		}
	}
	for _, h := range []string{"-bad", "a..b", "unter_strich", strings.Repeat("a", 64)} {
		if _, err := honeypotModeFromEnv(hpEnv(map[string]string{"NODE64_HONEYPOT_HOSTNAME": h})); err == nil || !strings.Contains(err.Error(), "hostname") {
			t.Errorf("hostname %q: %v", h, err)
		}
	}
	for _, n := range []string{strings.Repeat("x", 65), "a\tb", "a\x7fb", "\xff"} {
		if _, err := honeypotModeFromEnv(hpEnv(map[string]string{"NODE64_NAME": n})); err == nil || !strings.Contains(err.Error(), "NODE64_NAME") {
			t.Errorf("name %q: %v", n, err)
		}
	}
	// neue Mail-Fallen mit TLS
	if hc, err = honeypotModeFromEnv(hpEnv(map[string]string{"NODE64_HONEYPOT_SERVICES": "smtps:465,imaps:993,pop3s:995"})); err != nil || len(hc.Sensor.Services) != 3 {
		t.Fatalf("mail tls: %+v %v", hc, err)
	}
}
