package ipv64api

// v64 Blocklist: seit 2026-10 gibt es nur noch die eine Liste "v64". Die frueheren Teillisten (nach Angriff) liefert
// ipv64.net nicht mehr; eine gespeicherte Auswahl davon gilt als die v64 Blocklist (PROXY64, Firewall-Helfer).
var v64Old = map[string]bool{"v64_ssh": true, "v64_web": true, "v64_mail": true, "v64_rdp": true, "v64_scanner": true, "v64_research": true}

// V64ListID liefert die Kennung einer Liste, fruehere Teillisten der v64 Blocklist als "v64".
func V64ListID(id string) string {
	if v64Old[id] {
		return "v64"
	}
	return id
}
