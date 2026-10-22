package main

// Anmeldung der Node in der Node-Uebersicht von ipv64.net (ipv64api/hello.go): welche Module laufen und worueber die
// Node sonst mit ipv64 spricht (Healthchecks-Sync, Honeypot64-Sensor, CDN64-Tunnel, DynDNS). Nur Kennungen.

import (
	"context"
	"encoding/json"
	"log/slog"
	"runtime"
	"sync/atomic"

	"github.com/ipv64net/node64/internal/cdn64"
	"github.com/ipv64net/node64/internal/dyndns"
	"github.com/ipv64net/node64/internal/honeypot"
	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/store"
	"github.com/ipv64net/node64/internal/web"
)

// Einstellungen anderer Pakete, die hier nur gelesen werden
const (
	helloSetSensorID = "honeypot.sensor_id" // honeypot/report.go setSensorID
	helloSetCDN64    = "cdn64.online"       // cdn64/online.go setOnline (JSON, Feld tunnel)
)

// nodeHello stellt den Stand der Node fuer POST /node64/hello zusammen.
func nodeHello(ctx context.Context, st *store.Store, mods *module.Registry, linked func() bool) ipv64api.Hello {
	h := ipv64api.Hello{
		NodeID:   st.SettingOr(ctx, web.SettingNodeID, ""),
		Name:     st.SettingOr(ctx, web.SettingNodeName, "Node64"),
		Location: st.SettingOr(ctx, web.SettingNodeLocation, ""),
		Version:  Version,
		OSArch:   runtime.GOOS + "/" + runtime.GOARCH,
		Modules:  []string{},
	}
	for _, m := range mods.List(ctx) {
		if m.Running {
			h.Modules = append(h.Modules, m.Info.Name)
		}
	}
	if linked != nil && linked() {
		h.Features.HCSyncLinked, h.Features.HubNodeID = true, h.NodeID // beim Verknuepfen meldet sich die Node mit node.id
	}
	if mods.IsRunning(honeypot.Name) {
		h.Features.HoneypotSensorID = st.SettingOr(ctx, helloSetSensorID, "")
	}
	if mods.IsRunning(cdn64.Name) {
		var c struct {
			Tunnel string `json:"tunnel"`
		}
		if json.Unmarshal([]byte(st.SettingOr(ctx, helloSetCDN64, "")), &c) == nil {
			h.Features.CDN64Tunnel = c.Tunnel
		}
	}
	h.Features.DynDNS = mods.IsRunning(dyndns.Name)
	return h
}

// headlessPresence: Modus ohne Oberflaeche. Kennung der Node ist die Sensor-Kennung (es gibt kein node.id); entfernt
// meldet sich der Modus bis zum Neustart nicht mehr an (der Key kommt aus der Umgebung, ipv64 weist die Meldungen des
// gesperrten Sensors selbst ab). name ist NODE64_NAME ("" = Honeypot64).
func headlessPresence(api *ipv64api.Client, key, dir, name string, log *slog.Logger) *ipv64api.Presence {
	if name == "" {
		name = "Honeypot64"
	}
	sensor := func() string { id, _ := honeypot.SensorIDFromFile(dir); return id }
	api.SetNodeID(sensor)
	var removed atomic.Bool
	return ipv64api.NewPresence(ipv64api.PresenceConfig{Client: api, Log: log,
		Key: func(context.Context) string { return key },
		Info: func(context.Context) ipv64api.Hello {
			id := sensor()
			return ipv64api.Hello{NodeID: id, Name: name, Version: Version, OSArch: runtime.GOOS + "/" + runtime.GOARCH, Mode: "headless",
				Modules: []string{honeypot.Name}, Features: ipv64api.HelloFeatures{HoneypotSensorID: id}}
		},
		Removed:   func(context.Context) bool { return removed.Load() },
		OnRemoved: func(context.Context) { removed.Store(true) }})
}
