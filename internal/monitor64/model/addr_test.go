package model

import "testing"

func TestURLHostV6(t *testing.T) {
	for in, want := range map[string]string{
		"fd00::1":                            "[fd00::1]",
		"::1":                                "[::1]",
		"[fd00::1]":                          "[fd00::1]",
		"[fd00::1]:9100":                     "[fd00::1]:9100",
		"fd00::1/metrics":                    "[fd00::1]/metrics",
		"https://fd00::1":                    "https://[fd00::1]",
		"https://[fd00::1]:8006/":            "https://[fd00::1]:8006/",
		"ssh://root@fd00::1":                 "ssh://root@[fd00::1]",
		"ssh://root@fd00::1/run/podman.sock": "ssh://root@[fd00::1]/run/podman.sock",
		"tcp://fd00::1":                      "tcp://[fd00::1]",
		"fe80::1%eth0":                       "[fe80::1%25eth0]",
		"[fe80::1%eth0]:8006":                "[fe80::1%25eth0]:8006",
		"https://[fe80::1%25eth0]:8006":      "https://[fe80::1%25eth0]:8006",
		"::ffff:192.168.1.5":                 "[::ffff:192.168.1.5]",
		"10.0.0.5":                           "10.0.0.5",
		"10.0.0.5:9100":                      "10.0.0.5:9100",
		"nas.lan:9182":                       "nas.lan:9182",
		"https://nas.lan/api?x=a:b::c":       "https://nas.lan/api?x=a:b::c",
		"unix:///var/run/docker.sock":        "unix:///var/run/docker.sock",
		"http://user:pw@host":                "http://user:pw@host",
		"[kein::v6::]":                       "[kein::v6::]",
		"":                                   "",
	} {
		if got := URLHostV6(in); got != want {
			t.Errorf("URLHostV6(%q) = %q, erwartet %q", in, got, want)
		}
	}
	if NoZone("fe80::1%eth0") != "fe80::1" || NoZone("nas") != "nas" {
		t.Error("NoZone")
	}
}
