package dnsserver

import "testing"

func TestSafeTarget(t *testing.T) {
	for name, want := range map[string]string{
		"google.de": "forcesafesearch.google.com", "www.google.com": "forcesafesearch.google.com", "www.google.co.uk": "forcesafesearch.google.com",
		"google.com.au": "forcesafesearch.google.com", "mail.google.com": "", "google.example.org": "", "forcesafesearch.google.com": "",
		"www.youtube.com": "restrict.youtube.com", "youtubei.googleapis.com": "restrict.youtube.com", "www.bing.com": "strict.bing.com",
		"duckduckgo.com": "safe.duckduckgo.com", "heise.de": "",
	} {
		if got := safeTarget(name, YouTubeStrict); got != want {
			t.Errorf("%s: %q, want %q", name, got, want)
		}
	}
	if safeTarget("m.youtube.com", YouTubeModerate) != "restrictmoderate.youtube.com" || safeTarget("m.youtube.com", YouTubeOff) != "" {
		t.Fatal("youtube levels")
	}
}
