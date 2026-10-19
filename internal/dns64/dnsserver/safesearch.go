package dnsserver

import "strings"

// SafeSearch und Schutz gegen Umgehen (Geraetegruppen, Phase G3). Umgeleitet wird per CNAME auf die Adressen,
// die die Anbieter dafuer vorsehen; HTTPS bleibt unberuehrt, es braucht keine Zertifikate.

// YouTube-Stufen.
const (
	YouTubeStrict   = "strict"   // restrict.youtube.com
	YouTubeModerate = "moderate" // restrictmoderate.youtube.com
	YouTubeOff      = "off"
)

// Gruende im Abfrage-Log.
const (
	ReasonSafeSearch = "safesearch:" // safesearch:<Ziel>
	ReasonCanary     = "canary"      // use-application-dns.net (Firefox schaltet sein DoH ab)
	ReasonBypass     = "bypass:"     // bypass:icloud (iCloud Private Relay aus)
)

// canaryName: Loest DNS64 ihn nicht auf, schaltet Firefox sein eingebautes DoH ab.
const canaryName = "use-application-dns.net"

// relayNames: iCloud Private Relay ist aus, wenn diese Namen nicht aufloesen.
var relayNames = map[string]bool{"mask.icloud.com": true, "mask-h2.icloud.com": true}

var youtubeNames = map[string]bool{
	"www.youtube.com": true, "m.youtube.com": true, "youtube.com": true, "youtubei.googleapis.com": true,
	"youtube.googleapis.com": true, "www.youtube-nocookie.com": true,
}

// safeTarget liefert das SafeSearch-Ziel fuer name ("" = keine Umleitung).
func safeTarget(name, youtube string) string {
	switch {
	case youtubeNames[name]:
		switch youtube {
		case YouTubeOff:
			return ""
		case YouTubeModerate:
			return "restrictmoderate.youtube.com"
		}
		return "restrict.youtube.com"
	case name == "bing.com" || name == "www.bing.com":
		return "strict.bing.com"
	case name == "duckduckgo.com" || name == "www.duckduckgo.com" || name == "start.duckduckgo.com":
		return "safe.duckduckgo.com"
	case isGoogleSearch(name):
		return "forcesafesearch.google.com"
	}
	return ""
}

// isGoogleSearch: google.<endung> und www.google.<endung> (alle Laender, auch google.co.uk, google.com.au).
func isGoogleSearch(name string) bool {
	rest, ok := strings.CutPrefix(strings.TrimPrefix(name, "www."), "google.")
	if !ok || rest == "" {
		return false
	}
	labels := strings.Split(rest, ".")
	if len(labels) > 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 3 && l != "com" { // Endungen sind kurz (de, com, co, uk, com.au)
			return false
		}
	}
	return true
}
