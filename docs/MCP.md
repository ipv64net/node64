# KI-Schnittstelle (MCP)

Node64 spricht das **Model Context Protocol (MCP)**: KI-Anwendungen wie Claude Code, Cursor, VS Code oder Claude
Desktop fragen über `/mcp` den Zustand der Node ab und erklären Zusammenhänge – z. B. „Warum war die Webseite heute
Nacht weg?“, „Was hat der Honeypot diese Woche gesehen?“, „Welche Zertifikate laufen bald ab?“.

Stand: **nur lesen, alle Module.** Über MCP kann die KI nichts ändern. Änderungen macht sie bewusst über die
REST-API `/api` der Node mit einem API-Key; das Werkzeug `api_reference` zeigt ihr dazu die passenden Endpunkte
(siehe [Ändern über die REST-API](#ändern-über-die-rest-api)). Plan: [PLAN-NODE64-MCP.md](PLAN-NODE64-MCP.md).

## Was ist MCP?

MCP ist ein offenes Protokoll (JSON-RPC 2.0), über das eine KI-Anwendung „Werkzeuge“ eines Servers aufruft. Node64
ist der Server: Er beschreibt seine Werkzeuge (Name, Zweck, Parameter als JSON-Schema), die Anwendung entscheidet,
welche sie aufruft, und bekommt kompakte JSON-Antworten. Transport ist „Streamable HTTP“ auf dem Web-Port der Node –
kein zusätzlicher Port, gleiches TLS-Zertifikat. Node64 arbeitet zustandslos (keine Sitzungen) und antwortet als JSON.

## Sicherheit

- **Standard aus.** Ausgeschaltet antwortet `/mcp` mit 404.
- **Nur aus dem Heimnetz.** Erlaubt sind private Netze (RFC 1918, `fc00::/7`), Link-local (`fe80::/10`),
  `100.64.0.0/10` (Tailscale u. a.) und localhost. Alles andere bekommt 403 – auch über PROXY64 oder einen anderen
  Reverse-Proxy: Steht in `X-Forwarded-For`, `X-Real-IP` oder `Forwarded` eine öffentliche Adresse, wird abgewiesen.
  Diese Köpfe können den Zugang nur sperren, nie öffnen. Die Absenderadresse der Verbindung muss ebenfalls privat sein.
- **Eigene MCP-Schlüssel** (`mcp64_…`), getrennt von den API-Keys (`node64_…` gilt hier nicht, `mcp64_…` nicht für
  `/api`). Je Schlüssel: Name, Rechte je Bereich, letzte Nutzung und Adresse, widerrufbar. Gespeichert wird nur der
  Hash; der Schlüssel ist nur direkt nach dem Anlegen sichtbar. Falsche Schlüssel bremsen die Adresse aus (wie bei
  den API-Keys). Sitzungs-Cookies gelten für `/mcp` nicht.
- **Rate-Limit:** 60 Anfragen pro Minute je Schlüssel, darüber 429 mit `Retry-After`.
- **Gleiche Regeln wie die API.** Jedes Werkzeug ruft intern die vorhandene JSON-API auf (gleicher Router, gleiche
  Handler und Prüfungen), angemeldet als Inhaber des Schlüssels. Werkzeuge erscheinen nur, wenn ihr Modul läuft und
  der Schlüssel den Bereich lesen darf.
- **Nie Geheimnisse.** Die Werkzeuge wählen ihre Felder ausdrücklich aus (Positivlisten): keine API-Keys, Tokens,
  Passwörter, privaten Schlüssel, Kanal-Zugangsdaten (Webhook-URLs, Mail-Passwörter), Header-Werte von PROXY64,
  Check-Parameter oder Push-Adressen. Bei Konfigurationen gilt zusätzlich: Benachrichtigungskanäle und DNS-Zugänge
  der Zertifikate nur mit den *Namen* der gesetzten Felder, nie mit Werten; Zugänge von Monitor64 ohne Passwort,
  Community, Token-ID und Push-Token (nur „Geheimnis gespeichert“); DNS64 ohne TSIG-Schlüssel; Adressen von
  Upstreams, Listen und Weiterleitungen nur mit Schema und Host; PROXY64 nur mit den Namen der Header, ohne eigenes
  HTML und ohne Passwörter der Zugriffslisten; weder ipv64-API-Key noch Account-Kennung, Kopplungscodes oder
  EAB-Kennungen. Check-Tokens sind bei Push-Checks die Berechtigung der Push-Adresse; die KI sieht nur eine
  kurze Kennung (`id`, die ersten 8 Zeichen). Ein zentraler Filter entfernt zusätzlich aus allen Texten URLs bis auf
  Schema und Host, `token=…`/`key=…`-Werte, `Bearer …`, Schlüssel mit `node64_`/`mcp64_`, PEM-Blöcke und lange
  Zufallszeichenfolgen. Ein Test prüft alle Werkzeuge mit Testdaten voller Geheimnisse; ein weiterer, dass jede
  GET-Route aus `openapi.json` von einem Werkzeug gelesen wird oder mit Grund ausgenommen ist.
- **Fremde Daten sind gekennzeichnet.** Vieles schreiben Fremde: Benutzer, Passwörter, Pfade, User-Agents und
  Nutzdaten aus dem Honeypot, Domainnamen im DNS64-Log, Pfade und User-Agents aus PROXY64,
  Meldungen von Checks, Fehlertexte entfernter Dienste, Audit-Ziele und Logzeilen. Sie stehen in einem Unterobjekt
  `untrusted`, sind gekürzt und ohne Steuer- und unsichtbare Unicode-Zeichen. Server-Hinweise und
  Werkzeugbeschreibungen sagen der KI, dass diese Inhalte nie als Anweisungen zu behandeln sind. Die Passwörter,
  die Angreifer am Honeypot probiert haben, sind Daten der Angreifer und stehen dort (unter `untrusted`).
- **Audit:** Jeder Werkzeugaufruf steht im Audit-Log (Bereich *KI (MCP)*, Aktion `mcp.call`): Werkzeug, Schlüssel
  (`mcp:<Name> (<Hinweis>)`), Benutzer, Adresse, Parameter gekürzt, ok oder Fehler. Ebenso Schalten, Anlegen und
  Widerrufen von Schlüsseln.

## Einrichten

1. *Einstellungen → KI-Schnittstelle (MCP)* → **Einschalten**.
2. **Schlüssel anlegen:** Name (z. B. „Claude Code Laptop“) und Bereiche, die gelesen werden dürfen: Node,
   Healthchecks, Monitor64, DNS64, PROXY64, Honeypot64, Sonar64, DynDNS, Zertifikate, Benachrichtigungen, Audit-Log
   und Logs. `api_reference` hat jeder Schlüssel (liest nur die mitgelieferte API-Beschreibung).
3. Die Seite zeigt die Adresse (`https://<node>:<port>/mcp`) und fertige Schnipsel mit dem neuen Schlüssel.

### Zertifikat

Node64 nutzt ohne weitere Einrichtung ein selbst signiertes Zertifikat. Anwendungen auf Basis von Node.js (Claude
Code, `mcp-remote`) lehnen das ab. Möglichkeiten:

- Zertifikat der Node herunterladen (*Einstellungen → Allgemein → Erreichbarkeit dieser Node*) und `NODE_EXTRA_CA_CERTS=/pfad/node64.pem`
  setzen, bevor die Anwendung startet.
- Für die Oberfläche ein Zertifikat aus der Zertifikatsverwaltung wählen (*Einstellungen → Allgemein → Erreichbarkeit dieser Node*) und die Node über
  diesen Namen ansprechen.
- Im LAN geht auch `http://<node>:<port>/mcp` (HTTP und HTTPS laufen auf demselben Port) – der Schlüssel geht dann
  unverschlüsselt durchs Heimnetz.

### Claude Code

```bash
claude mcp add --transport http node64 https://node64.lan:8080/mcp --header "Authorization: Bearer mcp64_…"
```

Mit `--scope user` gilt der Server in allen Projekten. Prüfen mit `claude mcp list` bzw. `/mcp` in Claude Code.

### Cursor

`~/.cursor/mcp.json` (alle Projekte) oder `.cursor/mcp.json` im Projekt:

```json
{
  "mcpServers": {
    "node64": {
      "url": "https://node64.lan:8080/mcp",
      "headers": { "Authorization": "Bearer mcp64_…" }
    }
  }
}
```

### VS Code (GitHub Copilot, Agent-Modus)

`.vscode/mcp.json` im Projekt oder über *MCP: Open User Configuration*:

```json
{
  "servers": {
    "node64": {
      "type": "http",
      "url": "https://node64.lan:8080/mcp",
      "headers": { "Authorization": "Bearer mcp64_…" }
    }
  }
}
```

Damit der Schlüssel nicht in der Datei steht, kann VS Code ihn abfragen: `"inputs": [{"type": "promptString",
"id": "node64-key", "description": "Node64 MCP-Schlüssel", "password": true}]` und im Kopf
`"Authorization": "Bearer ${input:node64-key}"`.

### Claude Desktop (prüfen)

Entfernte Server bindet Claude Desktop als „Connectors“ ein; die Verbindung baut dabei die Cloud von Anthropic auf
und erreicht eine Node im Heimnetz nicht. Deshalb über die lokale Brücke
[`mcp-remote`](https://www.npmjs.com/package/mcp-remote) (braucht Node.js), in `claude_desktop_config.json`
(*Einstellungen → Entwickler → Konfiguration bearbeiten*):

```json
{
  "mcpServers": {
    "node64": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://node64.lan:8080/mcp", "--header", "Authorization:${NODE64_AUTH}"],
      "env": { "NODE64_AUTH": "Bearer mcp64_…" }
    }
  }
}
```

Der Schlüssel steht in `env`, weil Leerzeichen in `args` unter Windows Probleme machen. Für ein selbst signiertes
Zertifikat zusätzlich `"NODE_EXTRA_CA_CERTS": "C:\\pfad\\node64.pem"` in `env`; für `http://` braucht `mcp-remote`
den Schalter `--allow-http`. **Prüfen:** Verhalten von Claude Desktop und `mcp-remote` ändert sich häufig – bei
Problemen die aktuelle Doku beider Projekte lesen.

### claude.ai, ChatGPT im Browser

Diese Anwendungen rufen MCP-Server aus ihrer Cloud auf. Dafür müsste die Node öffentlich erreichbar sein und OAuth
können – das kommt frühestens mit Phase M3.

## Werkzeuge (alle nur lesend)

Alle Werkzeuge tragen `readOnlyHint: true`, `destructiveHint: false`. Zeiten sind RFC 3339 in UTC.

| Bereich | Werkzeug | Inhalt |
|---|---|---|
| Node | `node_status` | Version, Laufzeit, Hostname, Datenbankgröße, Module an/aus, Verknüpfung mit ipv64, Zusammenfassung je Modul |
| Node | `list_modules` | Module mit Version, Zustand, letztem Fehler |
| Healthchecks | `list_checks` | Checks mit Zustand, letzter Messung, Latenz; Filter Zustand, Gruppe, Typ, Tag, Text; `limit` |
| Healthchecks | `get_check` | ein Check: Zusammenfassung der Einstellungen, Zustand, Uptime 24 h / 7 d / 30 d, letzte Ereignisse |
| Healthchecks | `check_history` | Messungen zusammengefasst (1h, 24h, 7d, 30d, 1y), Reihe, optional letzte Fehlmessungen |
| Healthchecks | `list_incidents` | Störungen (alle oder ein Check, nur offene), Dauer |
| Healthchecks | `list_maintenance` | Wartungsfenster, betroffene Checks, aktiv |
| Healthchecks | `check_events` | Statuswechsel aller Checks oder eines Checks, Seiten über `before` |
| Healthchecks | `online_checks` | Online-Checks des Accounts (API-Modus ohne Sync; verknüpft stehen sie in `list_checks`) |
| Healthchecks | `list_status_pages` | Statusseiten mit dem, was sie gerade zeigen |
| Healthchecks | `status_page_details` | Konfiguration einer Statusseite (Abschnitte, Einträge mit Quelle) und Ankündigungen – ohne Passwort |
| Monitor64 | `monitor64_overview`, `monitor64_host`, `monitor64_problems`, `monitor64_maintenance` | Hosts, Dienste mit Messwerten, Probleme, Wartungen |
| Monitor64 | `monitor64_config` | `part`: `rules` (Schwellen, Abweichungen), `notify`, `settings`, `traps`, `agent` (Verteilung), `cluster` |
| Monitor64 | `monitor64_details` | `part`: `problem` (Ablauf), `accesses` (Zugänge ohne Geheimnisse, gefundene und ignorierte Dienste), `smart`, `traps`, `series` (Verlauf), `cluster_host` |
| DNS64 | `dns64_summary` | Anfragen, Blockquote, Cache, Clients, Upstreams (ohne URLs), Pause |
| DNS64 | `dns64_top` | Top geblockt / erlaubt / Clients |
| DNS64 | `dns64_query_log` | Suche nach Client und/oder Domain, Status, Zeitraum (Minuten); `limit` bis 200 |
| DNS64 | `dns64_config` | `part`: `settings`, `records`, `zones`, `forwards`, `rewrites`, `groups`, `devices`, `lists`, `own_lists`, `services`, `docker` |
| DNS64 | `dns64_lookup` | warum eine Domain gesperrt oder erlaubt ist |
| DNS64 | `dns64_dhcp` | DHCP: Netze, Vergaben, feste Adressen, fremde DHCP-Server, Ereignisse, IPv6-DNS per Router Advertisement |
| PROXY64 | `proxy_hosts` | Hosts, Ziele, Erreichbarkeit, Zertifikat, Zähler (ohne Header-Werte) |
| PROXY64 | `proxy_access_log` | Zugriffs-Log, Filter Host, Statusklasse, abgewiesen, Text; Pfade ohne Query |
| PROXY64 | `proxy_blocked` | Sofortsperren aus Honeypot64, Rate-Limit-Sperren, Blocklisten, Ländersperren |
| PROXY64 | `proxy_config` | `part`: `host` (alle Einstellungen eines Hosts), `streams`, `access_lists`, `limits`, `protection`, `settings`, `online` (CDN64), `status`, `stats`, `docker`, `geo_lookup` |
| Honeypot64 | `honeypot_stats` | Zeitraum: Ereignisse, IPs, Anmeldeversuche, Dienste, Länder, Top-Listen |
| Honeypot64 | `honeypot_events` | letzte Ereignisse, Filter Quelle, Land, Dienst, Art |
| Honeypot64 | `honeypot_lookup_ip` | alles lokal zu einer IP (Honeypot, mit Recht auch PROXY64-Sperren und -Log) |
| Honeypot64 | `honeypot_config` | `part`: `config`, `status`, `catalog`, `watch` (Frühwarnung), `live` |
| Sonar64 | `sonar64_status` | `part`: `status`, `recent`, `inbound`, `settings` |
| DynDNS | `dyndns_status` | öffentliche IPs, Präfix, Anschluss (CGNAT/DS-Lite), Ziele (ohne Tokens), Update-Limit |
| DynDNS | `dyndns_history` | Updates bei ipv64 oder IP-Prüfungen |
| DynDNS | `dyndns_config` | `part`: `targets` (ohne Tokens), `settings`, `account_names` |
| Zertifikate | `list_certs` | Namen, Aussteller, Ablauf, Zustand, Erneuerung – ohne Schlüssel |
| Zertifikate | `certs_config` | `part`: `cert` (ein Zertifikat mit Seriennummer und Fingerabdruck), `account`, `dns_accounts` (nur Feldnamen), `dns_providers`, `domains`, `cas`, `acme_cas`, `dns_check` |
| Benachrichtigungen | `recent_notifications` | Zustellungen (ok/fehlgeschlagen) und Kanäle ohne Zugangsdaten |
| Benachrichtigungen | `notification_channels` | `part`: `channels` (nur Namen der gesetzten Felder), `ipv64` (Kanäle bei ipv64), `types` (Felder je Typ, welche sensibel sind) |
| Node | `node_config` | `part`: `settings`, `update` (Selbst-Update), `link` (ipv64, offene Konflikte), `ipv64` (zentraler Key: Plan, Ablauf), `overview`, `ports`, `logging`, `retention` |
| Node | `cluster_status` | Mitglieder des Clusters ohne Kopplungscode |
| Audit-Log und Logs | `audit_log` | Audit-Log mit Filter Bereich, Seiten über `before` |
| Audit-Log und Logs | `node_logs` | letzte Logzeilen, Filter Stufe, Modul, Text |
| jeder Schlüssel | `api_reference` | Wegweiser zur REST-API aus `openapi.json`: Module (Tags), Operationen je Modul bzw. Suche (Methode, Pfad, Kurzbeschreibung, Parameter, Felder des Rumpfs), mit `path` alle Einzelheiten |

Nicht über MCP (bewusst): API-Keys, MCP-Schlüssel, Benutzer, Backup, Kopplungscodes, TSIG-Schlüssel, Zertifikate mit
privatem Schlüssel, Dateien und Exporte (CA, Zonendatei, CSV), Push-Endpunkte und neue Push-Tokens.

## Ändern über die REST-API

MCP bleibt nur lesend. Soll die KI etwas ändern (Check pausieren, Domain sperren, Host anlegen …), nutzt sie die
lokale REST-API unter `/api` auf demselben Host und Port – mit einem **API-Key** der Node (`Authorization: Bearer
node64_…`, Seite *API → API-Keys*), nicht mit dem MCP-Schlüssel. Ablauf:

1. `api_reference` ohne Parameter: Module der API und Anmeldung; dann mit `tag` (z. B. `dns64`) und/oder `search`
   die Operationen, mit `path` die Felder des Rumpfs.
2. Mit den lesenden Werkzeugen den Zustand und die Kennungen holen (gekürzte Kennungen wie die Check-`id` über die
   REST-API vollständig lesen).
3. Die geplante Anfrage (Methode, Pfad, JSON) dem Benutzer zeigen und erst nach Bestätigung senden.

Der Prompt `plan_change` führt durch diese Schritte. Die Server-Hinweise sagen der KI dasselbe.

### Prompts

| Prompt | Inhalt |
|---|---|
| `incident_analysis` | Störung analysieren (Parameter `check` und/oder `time`): Check, Verlauf, PROXY64, DNS64, Audit im selben Zeitraum |
| `weekly_report` | Wochenbericht über alle freigegebenen Bereiche |
| `security_overview` | Sicherheitslage: Honeypot64 und PROXY64-Sperren, Anmeldungen |
| `plan_change` | Änderung vorbereiten (Parameter `task`): Endpunkt über `api_reference`, Zustand lesen, Anfrage zeigen und bestätigen lassen |

Prompts nennen nur Werkzeuge, die der Schlüssel auch hat.

## Grenzen

- Nur lesen. Ändern geht bewusst über die REST-API (siehe oben), nicht über MCP-Werkzeuge.
- Nie über MCP: Schlüssel, Benutzer, Anmeldung, Backup/Export/Import, Verknüpfen mit ipv64, Zurücksetzen, Updates.
- Ergebnisse sind begrenzt (`limit`, Zeiträume); große Listen werden gekürzt (`truncated`, `next_before`).
- Kein OAuth, keine öffentliche Erreichbarkeit (M3).
- Der Honeypot hat keine Suche nach IP in der API; `honeypot_lookup_ip` durchsucht die letzten 1000 Ereignisse.

## Fehler

| HTTP | Bedeutung |
|---|---|
| 404 | Schnittstelle ausgeschaltet |
| 403 | Anfrage nicht aus einem privaten Netz (oder POST ohne `Authorization: Bearer`) |
| 401 | Schlüssel fehlt, falsch oder widerrufen |
| 429 | mehr als 60 Anfragen pro Minute mit diesem Schlüssel bzw. zu viele falsche Schlüssel |

Fehler eines Werkzeugs (z. B. Check nicht gefunden, Modul gestoppt) kommen als Werkzeug-Ergebnis mit `isError`.

## Prometheus

`node64_mcp_enabled` und `node64_mcp_calls_total{tool,result}` – siehe [PROMETHEUS.md](PROMETHEUS.md#kern).

## Technik

- Paket `internal/mcp` (Werkzeuge, Filter, Prompts) mit dem offiziellen Go-SDK
  `github.com/modelcontextprotocol/go-sdk` v1.8.0; Transport, Schalter, Schlüssel, Heimnetz-Prüfung und Rate-Limit in
  `internal/web/mcp.go`; Schlüssel in der Tabelle `mcp_keys` (Kern-Migration `0005_mcp.sql`).
- Einstellung `mcp.enabled` (`1`/`0`).

## Änderungen

- **2026-10-21 – M1:** Transport `/mcp`, Schalter, nur private Netze, MCP-Schlüssel mit Rechten je Bereich,
  Rate-Limit, Audit, 25 lesende Werkzeuge, drei Prompts, Prometheus-Zähler.
- **2026-10-21:** Der Schalter `mcp.enabled` zieht mit Export/Import der Konfiguration um; MCP-Schlüssel nie (auch
  nicht mit Passwort). Die Audit-Einträge der Aufrufe (`mcp.call`) folgen der Aufbewahrung des Audit-Logs
  (`audit.keep_days`, Standard 365 Tage).
- **2026-11-06:** Schalter und Schlüssel auch über die lokale API: `GET`/`PUT /api/mcp`, `POST /api/mcp/keys`
  (Schlüssel nur in dieser Antwort), `DELETE /api/mcp/keys/{id}`. Die MCP-Werkzeuge selbst bleiben nur lesend.
- **2026-11-14 – alle Module lesbar (#152, #153):** neue Werkzeuge `node_config`, `notification_channels`,
  `certs_config`, `sonar64_status`, `check_events`, `online_checks`, `status_page_details`, `monitor64_config`,
  `monitor64_details`, `dns64_config`, `dns64_lookup`, `proxy_config`, `dyndns_config`, `honeypot_config`;
  `dns64_summary` mit Zeitverlauf, `dns64_dhcp` mit IPv6-Router-Advertisement. Neuer Bereich `sonar64` (bestehende
  Schlüssel bleiben gültig). Werkzeug `api_reference` (jeder Schlüssel) und Prompt `plan_change`: Änderungen macht die
  KI über die REST-API mit einem API-Key. 44 Werkzeuge.
