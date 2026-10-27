package ipv64api

import (
	"context"
	"encoding/json"
	"strings"
	"time"
)

// Account-Klassen von ipv64.net (GET /plans, oeffentlich; Grenzen live aus user_class). Die Node zeigt sie als
// Uebersicht und verweist bei erreichten Limits darauf. Abgerufen jede Stunde; fehlt bei ipv64 ein Wert, gilt der
// eingebaute; bis der Endpunkt erreichbar ist bzw. ohne Internet gilt der
// eingebaute Stand (Preisseite ipv64.net/pricing, Stand 2026-10-21: neue CDN-Grenzen).

// PricingURL ist die Preisseite von ipv64.net.
const PricingURL = "https://ipv64.net/pricing"

// Plan ist eine Account-Klasse mit Preis und Grenzen (nil = unbegrenzt).
type Plan struct {
	ID           int             `json:"id"`
	Key          string          `json:"key"`        // free, supporter, business, company
	Name         string          `json:"name"`       // Anzeige, z. B. "Home / Supporter"
	ClassName    string          `json:"class_name"` // Name der Klasse im Account (z. B. "Supporter")
	PriceYearEUR float64         `json:"price_year_eur"`
	UpgradeURL   string          `json:"upgrade_url"`
	Limits       map[string]*int `json:"limits"`
}

func lim(n int) *int { return &n }

// builtinPlans: Stand der Preisseite, falls GET /plans (noch) nicht erreichbar ist.
var builtinPlans = []Plan{
	{ID: 1, Key: "free", Name: "Free", ClassName: "Standard", PriceYearEUR: 0, UpgradeURL: "https://ipv64.net/account", Limits: map[string]*int{
		"dyndns_domains": lim(3), "dyndns_updates_24h": lim(64), "own_domains": lim(0), "dyndns_ttl_s": lim(60), "healthchecks": lim(3),
		"healthcheck_pings_24h": lim(1024), "sms_24h": lim(5), "statistics_days": lim(14), "failover_policies": lim(1), "failover_monitors": lim(2),
		"failover_rules": lim(2), "offline_pages": lim(1), "cdn_domains": lim(1), "cdn_traffic_gb": lim(10), "cdn_bandwidth_mbit": lim(50), "cdn_mappings": lim(2), "cdn_tunnel_sessions": lim(1),
		"cloud_routers": lim(1), "vpn_gateways": lim(1), "vpn_peers": lim(2), "vpn_traffic_gb": lim(50), "dns64_clients": lim(1), "log_days": lim(7)}},
	{ID: 6, Key: "supporter", Name: "Home / Supporter", ClassName: "Supporter", PriceYearEUR: 40, UpgradeURL: "https://ipv64.net/account?account_class&type=supporter", Limits: map[string]*int{
		"dyndns_domains": lim(10), "dyndns_updates_24h": lim(1024), "own_domains": lim(3), "dyndns_ttl_s": lim(10), "healthchecks": lim(10),
		"healthcheck_pings_24h": lim(8192), "sms_24h": lim(50), "statistics_days": lim(90), "failover_policies": lim(5), "failover_monitors": lim(25),
		"failover_rules": lim(50), "offline_pages": lim(5), "cdn_domains": lim(5), "cdn_traffic_gb": lim(100), "cdn_bandwidth_mbit": lim(1000), "cdn_mappings": lim(10), "cdn_tunnel_sessions": lim(1),
		"cloud_routers": lim(3), "vpn_gateways": lim(3), "vpn_peers": lim(6), "vpn_traffic_gb": lim(1024), "dns64_clients": lim(5), "log_days": lim(30)}},
	{ID: 4, Key: "business", Name: "Business", ClassName: "Business", PriceYearEUR: 100, UpgradeURL: "https://ipv64.net/account?account_class&type=business", Limits: map[string]*int{
		"dyndns_domains": lim(50), "dyndns_updates_24h": nil, "own_domains": lim(10), "dyndns_ttl_s": lim(10), "healthchecks": lim(50),
		"healthcheck_pings_24h": nil, "sms_24h": nil, "statistics_days": lim(180), "failover_policies": lim(25), "failover_monitors": lim(100),
		"failover_rules": lim(100), "offline_pages": lim(25), "cdn_domains": lim(10), "cdn_traffic_gb": lim(10240), "cdn_bandwidth_mbit": nil, "cdn_mappings": lim(50), "cdn_tunnel_sessions": lim(2),
		"cloud_routers": lim(10), "vpn_gateways": lim(10), "vpn_peers": lim(20), "vpn_traffic_gb": lim(10240), "dns64_clients": lim(10), "log_days": lim(90)}},
	{ID: 5, Key: "company", Name: "Company", ClassName: "Company", PriceYearEUR: 200, UpgradeURL: "https://ipv64.net/account?account_class&type=company", Limits: map[string]*int{
		"dyndns_domains": lim(256), "dyndns_updates_24h": nil, "own_domains": lim(50), "dyndns_ttl_s": lim(10), "healthchecks": lim(250),
		"healthcheck_pings_24h": nil, "sms_24h": nil, "statistics_days": lim(365), "failover_policies": lim(50), "failover_monitors": lim(250),
		"failover_rules": lim(250), "offline_pages": lim(50), "cdn_domains": lim(25), "cdn_traffic_gb": lim(20480), "cdn_bandwidth_mbit": nil, "cdn_mappings": lim(250), "cdn_tunnel_sessions": lim(4),
		"cloud_routers": lim(25), "vpn_gateways": lim(32), "vpn_peers": lim(64), "vpn_traffic_gb": lim(10240), "dns64_clients": lim(50), "log_days": lim(365)}},
}

// PopularKey: die Klasse, die die Uebersicht hervorhebt (trifft die meisten Nutzer).
const PopularKey = "supporter"

// PlanOrder: Reihenfolge der Zeilen in der Uebersicht (Gruppe, Schluessel).
var PlanOrder = [][2]string{
	{"dyndns", "dyndns_domains"}, {"dyndns", "own_domains"}, {"dyndns", "dyndns_updates_24h"}, {"dyndns", "dyndns_ttl_s"},
	{"healthchecks", "healthchecks"}, {"healthchecks", "healthcheck_pings_24h"}, {"healthchecks", "sms_24h"},
	{"failover", "failover_policies"}, {"failover", "failover_monitors"}, {"failover", "failover_rules"}, {"failover", "offline_pages"},
	{"cdn", "cdn_domains"}, {"cdn", "cdn_traffic_gb"}, {"cdn", "cdn_bandwidth_mbit"}, {"cdn", "cdn_mappings"}, {"cdn", "cdn_tunnel_sessions"},
	{"vpn", "cloud_routers"}, {"vpn", "vpn_gateways"}, {"vpn", "vpn_peers"}, {"vpn", "vpn_traffic_gb"},
	{"other", "dns64_clients"}, {"other", "statistics_days"}, {"other", "log_days"},
}

const (
	setPlans   = "ipv64.plans"
	setPlansAt = "ipv64.plans_at"
	plansEvery = time.Hour // Aenderungen in user_class kommen so spaetestens nach einer Stunde an
)

// withBuiltin ergaenzt Grenzen, die ipv64 nicht liefert (Schluessel fehlt), aus dem eingebauten Stand derselben
// Klasse; null von ipv64 heisst unbegrenzt und bleibt.
func withBuiltin(list []Plan) []Plan {
	out := make([]Plan, len(list))
	for i, p := range list {
		lim := map[string]*int{}
		for k, v := range p.Limits {
			lim[k] = v
		}
		for _, b := range builtinPlans {
			if b.Key != p.Key {
				continue
			}
			for k, v := range b.Limits {
				if _, ok := lim[k]; !ok {
					lim[k] = v
				}
			}
		}
		p.Limits = lim
		out[i] = p
	}
	return out
}

// Plans liefert die Account-Klassen: abgerufen (hoechstens einmal am Tag), sonst der letzte Abruf, sonst der
// eingebaute Stand. live = aus der API.
func (k *Key) Plans(ctx context.Context) (list []Plan, live bool) {
	at, _ := time.Parse(time.RFC3339, k.st.SettingOr(ctx, setPlansAt, ""))
	var cached []Plan
	_ = json.Unmarshal([]byte(k.st.SettingOr(ctx, setPlans, "")), &cached)
	if len(cached) > 0 && time.Since(at) < plansEvery {
		return withBuiltin(cached), true
	}
	if time.Since(at) > 10*time.Minute || len(cached) > 0 { // Fehlschlaege hoechstens alle 10 min wiederholen
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		var fresh []Plan
		_ = k.st.SetSetting(ctx, setPlansAt, time.Now().UTC().Format(time.RFC3339))
		if err := k.client.get(cctx, "", "/plans", &fresh); err == nil && len(fresh) > 0 {
			if b, err := json.Marshal(fresh); err == nil {
				_ = k.st.SetSetting(ctx, setPlans, string(b))
			}
			return withBuiltin(fresh), true
		} else if err != nil && k.log != nil {
			k.log.Debug("ipv64 plans not available", "err", err)
		}
	}
	if len(cached) > 0 {
		return withBuiltin(cached), true
	}
	return builtinPlans, false
}

// PlanFor findet die Klasse zum Namen im Account (z. B. "Supporter"); nil = unbekannt (etwa VIP, Premium).
func PlanFor(list []Plan, className string) *Plan {
	for i := range list {
		if strings.EqualFold(list[i].ClassName, className) || strings.EqualFold(list[i].Name, className) {
			return &list[i]
		}
	}
	return nil
}
