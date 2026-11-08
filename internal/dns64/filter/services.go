package filter

import (
	"slices"
	"strings"
)

// Dienste zum Sperren per Klick (je Geraetegruppe, wie "Gesperrte Dienste" bei AdGuard Home): kleine, von
// Node64 gepflegte Domainlisten je Dienst. In den Kategorien einer Gruppe bzw. eines Zeitplans stehen sie als
// "svc:<id>" neben den Kategorien (social, games ...). Gemeinsame Infrastruktur (z. B. Google, Microsoft, AWS)
// bleibt bewusst aussen vor, damit eine Sperre nicht andere Dienste trifft.

// ServicePrefix kennzeichnet einen Dienst unter den Kategorien einer Gruppe.
const ServicePrefix = "svc:"

// Service ist ein Dienst mit seinen Domains (jeweils samt Subdomains).
type Service struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Group   string   `json:"group"` // ai, social, messenger, streaming, games, dating
	Domains []string `json:"domains"`
}

// ServiceGroups ist die Anzeigereihenfolge der Dienst-Gruppen.
var ServiceGroups = []string{"ai", "social", "messenger", "streaming", "games", "dating"}

// Services ist der Katalog (Reihenfolge = Anzeige).
var Services = []Service{
	{"chatgpt", "ChatGPT", "ai", []string{"chatgpt.com", "openai.com", "oaiusercontent.com", "oaistatic.com", "chat.com"}},
	{"claude", "Claude", "ai", []string{"claude.ai", "claude.com", "anthropic.com", "claudeusercontent.com"}},
	{"copilot", "Microsoft Copilot", "ai", []string{"copilot.microsoft.com", "copilot.cloud.microsoft", "sydney.bing.com"}},
	{"gemini", "Google Gemini", "ai", []string{"gemini.google.com", "bard.google.com", "aistudio.google.com", "gemini.google"}},
	{"deepseek", "DeepSeek", "ai", []string{"deepseek.com"}},
	{"grok", "Grok", "ai", []string{"grok.com", "x.ai"}},
	{"perplexity", "Perplexity", "ai", []string{"perplexity.ai", "pplx.ai"}},
	{"mistral", "Mistral Le Chat", "ai", []string{"mistral.ai"}},

	{"tiktok", "TikTok", "social", []string{"tiktok.com", "tiktokv.com", "tiktokcdn.com", "tiktokcdn-us.com", "tiktokv.us", "tiktok.us", "byteoversea.com", "ibytedtos.com", "ibyteimg.com", "musical.ly", "tiktokw.us"}},
	{"instagram", "Instagram", "social", []string{"instagram.com", "cdninstagram.com", "ig.me", "instagr.am"}},
	{"facebook", "Facebook", "social", []string{"facebook.com", "facebook.net", "fbcdn.net", "fb.com", "fb.me", "fbsbx.com", "messenger.com"}},
	{"snapchat", "Snapchat", "social", []string{"snapchat.com", "snap.com", "snapkit.co", "sc-cdn.net", "snap-dev.net", "snapads.com", "sc-static.net", "feelinsonice-hrd.appspot.com"}},
	{"x", "X (Twitter)", "social", []string{"x.com", "twitter.com", "twimg.com", "t.co"}},
	{"reddit", "Reddit", "social", []string{"reddit.com", "redd.it", "redditmedia.com", "redditstatic.com"}},
	{"pinterest", "Pinterest", "social", []string{"pinterest.com", "pinterest.de", "pinimg.com"}},
	{"bereal", "BeReal", "social", []string{"bereal.com", "bere.al", "bereal.team"}},
	{"tumblr", "Tumblr", "social", []string{"tumblr.com"}},
	{"threads", "Threads", "social", []string{"threads.net", "threads.com"}},
	{"bluesky", "Bluesky", "social", []string{"bsky.app", "bsky.social", "bsky.network"}},

	{"whatsapp", "WhatsApp", "messenger", []string{"whatsapp.com", "whatsapp.net", "wa.me"}},
	{"telegram", "Telegram", "messenger", []string{"telegram.org", "telegram.me", "t.me", "telesco.pe", "tdesktop.com", "telegra.ph"}},
	{"discord", "Discord", "messenger", []string{"discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media", "discordcdn.com"}},
	{"signal", "Signal", "messenger", []string{"signal.org", "signal.group", "whispersystems.org"}},

	{"youtube", "YouTube", "streaming", []string{"youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "youtube-nocookie.com", "youtubei.googleapis.com", "yt.be"}},
	{"netflix", "Netflix", "streaming", []string{"netflix.com", "netflix.net", "nflxvideo.net", "nflximg.net", "nflximg.com", "nflxext.com", "nflxso.net"}},
	{"twitch", "Twitch", "streaming", []string{"twitch.tv", "ttvnw.net", "jtvnw.net", "twitchcdn.net", "twitchsvc.net", "twitchapps.com"}},
	{"disneyplus", "Disney+", "streaming", []string{"disneyplus.com", "disney-plus.net", "dssott.com", "bamgrid.com", "disneystreaming.com"}},
	{"primevideo", "Prime Video", "streaming", []string{"primevideo.com", "aiv-cdn.net", "aiv-delivery.net", "amazonvideo.com", "pv-cdn.net"}},
	{"spotify", "Spotify", "streaming", []string{"spotify.com", "scdn.co", "spotifycdn.com", "spotify.link"}},

	{"steam", "Steam", "games", []string{"steampowered.com", "steamcommunity.com", "steamstatic.com", "steamcontent.com", "steamserver.net", "steamgames.com", "steamusercontent.com", "s.team"}},
	{"roblox", "Roblox", "games", []string{"roblox.com", "rbxcdn.com", "rbx.com", "robloxlabs.com", "roblox.cn"}},
	{"epicgames", "Epic Games / Fortnite", "games", []string{"epicgames.com", "epicgames.dev", "fortnite.com", "unrealengine.com", "epicgames.net"}},
	{"minecraft", "Minecraft", "games", []string{"minecraft.net", "mojang.com", "minecraftservices.com", "minecraft-services.net"}},
	{"battlenet", "Battle.net", "games", []string{"battle.net", "blizzard.com", "blizzard.net", "battlenet.com.cn"}},
	{"playstation", "PlayStation Network", "games", []string{"playstation.com", "playstation.net", "sonyentertainmentnetwork.com"}},
	{"xbox", "Xbox Live", "games", []string{"xboxlive.com", "xbox.com", "xboxservices.com"}},

	{"tinder", "Tinder", "dating", []string{"tinder.com", "gotinder.com"}},
	{"bumble", "Bumble", "dating", []string{"bumble.com", "bumble.app", "badoo.com"}},
	{"lovoo", "LOVOO", "dating", []string{"lovoo.com", "lovoo.net"}},
}

var serviceSets = func() map[string]*DomainSet {
	out := make(map[string]*DomainSet, len(Services))
	for _, s := range Services {
		out[ServicePrefix+s.ID] = NewDomainSet(s.Domains)
	}
	return out
}()

// ServiceName liefert den Namen eines Dienstes ("svc:<id>"); "" = kein Dienst.
func ServiceName(key string) string {
	id, ok := strings.CutPrefix(key, ServicePrefix)
	if !ok {
		return ""
	}
	for _, s := range Services {
		if s.ID == id {
			return s.Name
		}
	}
	return ""
}

// IsGroupKey: key ist eine Kategorie oder ein Dienst, den eine Gruppe sperren kann.
func IsGroupKey(key string) bool {
	return slices.Contains(GroupCategories, key) || serviceSets[key] != nil
}

// GroupKeys behaelt von keys die bekannten Kategorien und Dienste: erst Kategorien, dann Dienste, jeweils in
// Anzeigereihenfolge, ohne Doppelte.
func GroupKeys(keys []string) []string {
	var out []string
	for _, c := range GroupCategories {
		if slices.Contains(keys, c) {
			out = append(out, c)
		}
	}
	for _, s := range Services {
		if k := ServicePrefix + s.ID; slices.Contains(keys, k) {
			out = append(out, k)
		}
	}
	return out
}
