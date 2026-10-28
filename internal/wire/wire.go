// Package wire sind die gemeinsamen Datenformate zwischen Node64 und hub
// (WebSocket-Nachrichten und HTTPS-Abgleich). Feldnamen entsprechen der
// lokalen JSON-API der Node, damit Skripte lokal und online gleich aussehen.
package wire

import (
	"encoding/json"
	"time"
)

// Token-Praefix der Node-Tokens.
const TokenPrefix = "node64t_"

// NotifyDirect: Benachrichtigungen von Checks, die nur eine Node misst, verschickt die Node selbst (ipv64-Kanaele
// ueber die API v2, eigene Kanaele); der hub sendet dafuer nur die uebrigen Portal-Kanaele. Der hub kuendigt es in
// Hello.Features an, die Node in Status.Modules (gespeichert in hc2_nodes.modules).
const NotifyDirect = "notify-direct"

// Check ist die Konfiguration eines Checks (ohne Laufzeitzustand).
type Check struct {
	Token                 string          `json:"token"`
	Name                  string          `json:"name"`
	Type                  string          `json:"type"`
	Target                string          `json:"target"`
	Params                json.RawMessage `json:"params,omitempty"`
	IntervalSeconds       int             `json:"interval_seconds"`
	RetryIntervalSeconds  int             `json:"retry_interval_seconds"`
	Retries               int             `json:"retries"`
	ConnectTimeoutSeconds float64         `json:"connect_timeout_seconds"`
	TimeoutSeconds        float64         `json:"timeout_seconds"`
	Invert                bool            `json:"invert"`
	Stabilize             int             `json:"stabilize"`
	IPMode                string          `json:"ip_mode"`
	Tags                  []string        `json:"tags"`
	Group                 string          `json:"group,omitempty"` // frei benannte Gruppe (Anzeige)
	Description           string          `json:"description"`
	Paused                bool            `json:"paused"`
	Parent                string          `json:"parent"`
	Critical              bool            `json:"critical"`
	Execution             string          `json:"execution"` // local, online, both
	Policy                string          `json:"policy"`
	Locations             []string        `json:"locations"`
	NotifyDegraded        bool            `json:"notify_degraded"`
	NotifyDown            bool            `json:"notify_down"`
	NotifyUp              bool            `json:"notify_up"`
	Channels              []int64         `json:"channels"`
	RepeatMinutes         int             `json:"repeat_minutes"`
	Revision              int64           `json:"revision"`
	NodeID                string          `json:"node_id,omitempty"` // Besitzer-Node (local/both): bearbeitet, benachrichtigt
	Nodes                 []string        `json:"nodes,omitempty"`   // messende Nodes (local/both); leer = nur die Besitzer-Node
	Owner                 string          `json:"owner,omitempty"`   // self, other, online (nur Server -> Node)
	// nur im Cluster (Node -> Node, Bereich notifications/channels): Kanaele ueber ihre Kennung im Cluster; nil = die
	// Zuordnung bleibt je Node
	ChannelUIDs *[]string `json:"channel_uids,omitempty"`
}

// Maintenance ist ein Wartungsfenster.
type Maintenance struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	StartAt     time.Time `json:"start_at"`
	EndAt       time.Time `json:"end_at"`
	Repeat      string    `json:"repeat"`
	RepeatUntil time.Time `json:"repeat_until,omitempty"`
	Tokens      []string  `json:"tokens"`
	Active      bool      `json:"active"`
	Revision    int64     `json:"revision"`
	NodeID      string    `json:"node_id,omitempty"`
}

// Channel ist ein Benachrichtigungskanal. Konfiguration nur bei Node-Kanaelen
// (gehoeren der Node); Server-Kanaele kommen ohne Geheimnisse.
type Channel struct {
	ID         int64             `json:"id"`
	Type       string            `json:"type"`
	Name       string            `json:"name"`
	Config     map[string]string `json:"config,omitempty"`
	Enabled    bool              `json:"enabled"`
	Default    bool              `json:"default"`
	Lang       string            `json:"lang"`
	NotifyDown bool              `json:"notify_down"`
	NotifyUp   bool              `json:"notify_up"`
	Revision   int64             `json:"revision"`
	NodeID     string            `json:"node_id,omitempty"`
	LocalID    int64             `json:"local_id,omitempty"` // ID in der Node (beim Bootstrap)
}

// Change ist ein Eintrag aus dem Konfigurations-Log (Server -> Node).
type Change struct {
	Entity   string          `json:"entity"` // check, channel, maintenance, node, settings
	ID       string          `json:"id"`
	Op       string          `json:"op"` // upsert, delete
	Revision int64           `json:"revision"`
	Data     json.RawMessage `json:"data,omitempty"`
}

// Endpoint ist ein hub-Server.
type Endpoint struct {
	Location string `json:"location"`
	Name     string `json:"name"`
	URL      string `json:"url"`
}

// Account sind die Angaben zum Account in hello.
type Account struct {
	ID         int64          `json:"id"`
	Plan       string         `json:"plan"`
	Limits     map[string]int `json:"limits"`
	HCLocation int            `json:"hc_locations"`
	Usage      map[string]int `json:"usage,omitempty"` // Verbrauch, z. B. sms_today (UTC-Tag)
}

// Hello ist die erste Nachricht des Servers nach dem Verbinden.
type Hello struct {
	ServerTime time.Time  `json:"server_time"`
	Revision   int64      `json:"revision"`
	Account    Account    `json:"account"`
	RemoteMgmt string     `json:"remote_mgmt"`
	NodeName   string     `json:"node_name"`
	Location   string     `json:"location"`
	Endpoints  []Endpoint `json:"endpoints"`
	Hub        string     `json:"hub"` // Standort dieses hubs
	Locations  []Endpoint `json:"locations"`
	Features   []string   `json:"features,omitempty"` // z. B. "proxy": nimmt Stellvertreter-Nodes an
}

// ProxyNode ist ein nicht verknuepftes Mitglied der lokalen Gruppe, das die weiterreichende Node beim hub
// vertritt (Nachricht proxies).
type ProxyNode struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Location string `json:"location"`
	Version  string `json:"version"`
	Online   bool   `json:"online"`
}

// ProxyData sind Zustaende und Messpunkte einer Stellvertreter-Node (Nachricht proxy_data).
type ProxyData struct {
	Node   string        `json:"node"`
	States []State       `json:"states,omitempty"`
	Batch  []Measurement `json:"batch,omitempty"`
}

// Measurement ist ein Messpunkt der Node.
type Measurement struct {
	Seq       int64          `json:"seq"`
	Token     string         `json:"token"`
	Time      time.Time      `json:"time"`
	Status    string         `json:"status"` // up, down
	LatencyMS float64        `json:"latency_ms"`
	Reason    string         `json:"reason"`
	Message   string         `json:"message"`
	Family    string         `json:"family"`
	Details   map[string]any `json:"details,omitempty"`
	Flags     int            `json:"flags"`
}

// State ist der Zustand eines Checks auf der Node (Messstelle node:<id>).
type State struct {
	Token           string    `json:"token"`
	State           string    `json:"state"`
	LastStatus      string    `json:"last_status"`
	LatencyMS       float64   `json:"latency_ms"`
	Reason          string    `json:"reason"`
	Message         string    `json:"message"`
	Since           time.Time `json:"since"`
	LastCheckAt     time.Time `json:"last_check_at"`
	NextCheckAt     time.Time `json:"next_check_at"`
	DownSince       time.Time `json:"down_since"`
	ConsecutiveFail int       `json:"consecutive_fail"`
	ConsecutiveOK   int       `json:"consecutive_ok"`
}

// Event ist ein Statuswechsel auf der Node.
type Event struct {
	EventID     string    `json:"event_id"`
	Token       string    `json:"token"`
	Kind        string    `json:"kind"`
	Time        time.Time `json:"time"`
	From        string    `json:"from"`
	To          string    `json:"to"`
	Reason      string    `json:"reason"`
	Message     string    `json:"message"`
	DurationSec int64     `json:"duration_seconds"`
	Flaps       int       `json:"flaps"`
	Flags       int       `json:"flags"`
}

// Delivery ist ein Eintrag des Zustellprotokolls der Node.
type Delivery struct {
	EventID   string    `json:"event_id"`
	ChannelID int64     `json:"channel_id"` // Server-ID des Kanals
	Kind      string    `json:"kind"`
	Time      time.Time `json:"time"`
	OK        bool      `json:"ok"`
	Error     string    `json:"error"`
}

// Propose ist ein Aenderungsvorschlag der Node.
type Propose struct {
	Entity       string          `json:"entity"`
	Op           string          `json:"op"`
	ID           string          `json:"id"`
	BaseRevision int64           `json:"base_revision"`
	Data         json.RawMessage `json:"data,omitempty"`
	// ChangedAt: wann die Aenderung an der Node gemacht wurde. Passt die Basis nicht (beide Seiten haben
	// geaendert, z. B. waehrend einer Trennung), gewinnt die juengere Aenderung.
	ChangedAt time.Time `json:"changed_at,omitempty"`
}

// ProposeResult ist die Antwort auf propose.
type ProposeResult struct {
	Revision int64           `json:"revision"`
	Data     json.RawMessage `json:"data,omitempty"`
	Conflict bool            `json:"conflict"`
	Server   json.RawMessage `json:"server,omitempty"`
	Error    string          `json:"error,omitempty"`
}

// Status ist die periodische Statusmeldung der Node.
type Status struct {
	Version    string    `json:"version"`
	Modules    []string  `json:"modules"`
	Timezone   string    `json:"timezone"`
	OutboxSize int       `json:"outbox_size"`
	Conflicts  int       `json:"conflicts"`
	LocalTime  time.Time `json:"local_time"`
	Name       string    `json:"name"`
	Location   string    `json:"location"`
}

// Command ist ein Befehl Server -> Node.
type Command struct {
	ID   int64           `json:"id"`
	Name string          `json:"name"`
	Args json.RawMessage `json:"args,omitempty"`
}

// CommandResult ist die Antwort der Node.
type CommandResult struct {
	ID     int64           `json:"id"`
	OK     bool            `json:"ok"`
	Output json.RawMessage `json:"output,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// SendOrder ist ein Sendeauftrag fuer einen Node-Kanal.
type SendOrder struct {
	ID        int64          `json:"id"`
	ChannelID int64          `json:"channel_id"`
	EventID   string         `json:"event_id"`
	Kind      string         `json:"kind"`
	Payload   map[string]any `json:"payload"`
}

// Msg ist der Rahmen aller WebSocket-Nachrichten.
type Msg struct {
	T    string          `json:"t"`
	ID   int64           `json:"id,omitempty"`
	Data json.RawMessage `json:"data,omitempty"`
}

// Ack ist die Bestaetigung einer Nachricht mit Daten.
type Ack struct {
	AckSeq     int64    `json:"ack_seq,omitempty"`
	Rejected   []int64  `json:"rejected,omitempty"`
	Accepted   []string `json:"accepted,omitempty"`
	Duplicates []string `json:"duplicates,omitempty"`
	Error      string   `json:"error,omitempty"`
}

// LinkStart/LinkPoll: Erstverknuepfung per Code.
type LinkStart struct {
	NodeID  string `json:"node_id"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type LinkStarted struct {
	Code       string    `json:"code"`
	PollSecret string    `json:"poll_secret"`
	ExpiresAt  time.Time `json:"expires_at"`
	Interval   int       `json:"interval"`
}

type LinkPoll struct {
	Code       string `json:"code"`
	PollSecret string `json:"poll_secret"`
}

type Linked struct {
	NodeToken  string     `json:"node_token"`
	Account    Account    `json:"account"`
	Name       string     `json:"name"`
	Location   string     `json:"location"`
	RemoteMgmt string     `json:"remote_mgmt"`
	Endpoints  []Endpoint `json:"endpoints"`
}

// Bootstrap ist der Upload der lokalen Konfiguration bei der Erstverknuepfung.
type Bootstrap struct {
	Checks      []Check       `json:"checks"`
	Maintenance []Maintenance `json:"maintenance"`
	Channels    []Channel     `json:"channels"`
}

type Renamed struct {
	OldToken string `json:"old_token"`
	NewToken string `json:"new_token"`
}

type BootstrapResult struct {
	Renamed     []Renamed       `json:"renamed"`
	Revision    int64           `json:"revision"`
	ChannelMap  map[int64]int64 `json:"channel_map"`     // lokale ID -> Server-ID
	MaintMap    map[int64]int64 `json:"maintenance_map"` // lokale ID -> Server-ID
	Checks      []Check         `json:"checks"`
	Maintenance []Maintenance   `json:"maintenance"`
	Channels    []Channel       `json:"channels"`
}

// FullConfig ist der Vollabgleich (Server -> Node).
type FullConfig struct {
	Revision    int64             `json:"revision"`
	Checks      []Check           `json:"checks"`
	Maintenance []Maintenance     `json:"maintenance"`
	Channels    []Channel         `json:"channels"`
	Settings    map[string]string `json:"settings"`
}
