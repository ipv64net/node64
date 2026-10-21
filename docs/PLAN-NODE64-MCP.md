# Plan: MCP-Schnittstelle für Node64

Stand 2026-10-21, Wunsch Dennis: KI-Anwendungen (Claude, ChatGPT, Cursor, VS Code …) sollen über das **Model
Context Protocol (MCP)** mit der Node sprechen – Zustand abfragen, Zusammenhänge erklären, später auch gezielt
handeln.

## Grundsätze

1. **Erst lesen, dann (ausdrücklich) handeln.** Erste Version nur lesende Werkzeuge. Ändernde Werkzeuge kommen je
   Bereich einzeln und sind standardmäßig aus.
2. **Nie Geheimnisse.** Keine API-Keys, Passwörter, Tokens, privaten Schlüssel, Secrets, Backups oder Exporte mit
   Geheimnissen – auch nicht teilweise.
3. **Fremde Daten sind Daten, keine Anweisungen.** Vieles, was die Node sammelt, schreiben Fremde: Benutzernamen,
   Passwörter, Pfade, User-Agents aus dem Honeypot, Domainnamen im DNS64-Querylog, Pfade und User-Agents aus PROXY64,
   Namen von VMs, Antworttexte von Checks. Solche Felder werden gekennzeichnet (`untrusted`), gekürzt und von
   Steuerzeichen befreit; die Werkzeugbeschreibungen sagen der KI ausdrücklich, dass darin keine Anweisungen stehen.
   Ändernde Werkzeuge werden nie allein durch Inhalte aus solchen Feldern ausgelöst (Bestätigung, siehe M2).
4. **Gleiche Regeln wie die API.** Jedes Werkzeug läuft intern über den vorhandenen API-Handler (gleiche Prüfungen,
   gleiche Rechte, gleiches Audit-Log) – keine zweite Logik.
5. **Klein und abschaltbar.** Ein Schalter in den Einstellungen; aus = Pfad antwortet 404.

## Technik

- **Transport:** MCP „Streamable HTTP“ unter `/mcp` auf dem vorhandenen Web-Port der Node (gleiches TLS, gleiche
  Reverse-Proxy-Regeln). JSON-RPC 2.0, Antworten als JSON oder SSE. Kein zusätzlicher Port.
- **Anmeldung:** eigene **MCP-Schlüssel** (Bearer), getrennt von normalen API-Keys, je Schlüssel **Rechte je
  Bereich** (lesen; später schreiben), Name, letzte Nutzung, widerrufbar. Später (M3) OAuth 2.1 für Anwendungen, die
  das verlangen (z. B. Connectors in claude.ai).
- **Erreichbarkeit:** Standard nur aus privaten Netzen (Heimnetz, VPN); „überall mit Schlüssel“ als Schalter.
  Öffentlich nur bewusst über PROXY64 mit Zugriffsliste.
- **Grenzen:** Rate-Limit je Schlüssel (z. B. 60 Aufrufe/min), Ergebnisgröße begrenzt (Seiten, `limit`), Zeitraum-
  Parameter mit Obergrenzen.
- **Audit:** jeder Aufruf im Audit-Log (Werkzeug, Schlüsselname, Parameter gekürzt, Ergebnis ok/Fehler).
- **Umsetzung:** neues Paket `internal/mcp`. Entweder offizielles Go-SDK (`github.com/modelcontextprotocol/go-sdk`,
  neue Abhängigkeit) oder schlanke eigene JSON-RPC-Schicht (Protokoll ist überschaubar) – siehe Entscheidungen.
  Werkzeuge mit `annotations` (`readOnlyHint`, `destructiveHint`), sauberen JSON-Schemas und kurzen Beschreibungen
  auf Englisch (KI-Anwendungen arbeiten damit am zuverlässigsten), Ausgaben kompakt.

## Anbindung der KI-Anwendungen (Doku)

- **Claude Code, Cursor, VS Code, viele weitere:** direkt mit URL `https://<node>:<port>/mcp` und Schlüssel im Header.
- **Claude Desktop:** über die lokale Konfiguration (Remote-Server bzw. Brücke `mcp-remote`) im Heimnetz.
- **claude.ai / ChatGPT im Browser:** rufen den Server aus ihrer Cloud auf → Node müsste öffentlich erreichbar sein
  (PROXY64/CDN64) und OAuth können → erst M3.
- Genaue Schritte je Anwendung beim Bau prüfen und in `docs/MCP.md` festhalten.

## Werkzeuge M1 (nur lesen)

| Bereich | Werkzeuge |
|---|---|
| Node | `node_status` (Version, Laufzeit, Module an/aus, Speicher, Verbindung zu ipv64), `list_modules` |
| Healthchecks | `list_checks` (Filter Zustand/Gruppe/Typ), `get_check` (Zustand, letzte Ereignisse, Uptime 24 h/7 d/30 d), `check_history` (Messungen zusammengefasst, Zeitraum), `list_incidents`, `list_maintenance` |
| Proxmox VE | `pve_systems`, `pve_resources` (Nodes/Gäste mit Zustand und Last), `pve_guest_history` (Verlauf zusammengefasst) |
| DNS64 | `dns64_summary` (Anfragen, Blockquote, Upstreams), `dns64_top` (Domains/Clients/geblockt), `dns64_query_log` (Suche nach Client/Domain, Zeitraum, begrenzt) |
| PROXY64 | `proxy_hosts` (Hosts, Ziele, Zertifikate, Zustand), `proxy_access_log` (Suche, begrenzt), `proxy_blocked` (gesperrte IPs inkl. Honeypot-Sofortsperre) |
| Honeypot64 | `honeypot_stats` (Zeitraum, Länder, Arten, Dienste), `honeypot_events` (begrenzt, fremde Felder gekennzeichnet), `honeypot_lookup_ip` (alles zu einer IP lokal) |
| DynDNS | `dyndns_status`, `dyndns_history` |
| Zertifikate | `list_certs` (Namen, Ablauf, Zustand – ohne Schlüssel) |
| Benachrichtigung | `recent_notifications` (zugestellt/fehlgeschlagen, ohne Kanal-Geheimnisse) |
| Protokoll | `audit_log` (Filter), `node_logs` (gekürzt, ohne Geheimnisse) |

Dazu **Prompts** (vorgefertigte Aufgaben, die die Anwendung anbietet): „Störung analysieren“ (Check + Proxmox +
PROXY64 + DNS64 im selben Zeitraum), „Wochenbericht“, „Sicherheitslage“ (Honeypot + PROXY64-Sperren).

## Werkzeuge M2 (ändernd, je Bereich einzeln freischaltbar, Standard aus)

- Healthchecks: Check pausieren/fortsetzen, jetzt prüfen, Check anlegen (einfache Typen), Wartungsfenster anlegen.
- DNS64: Domain erlauben/sperren (eigene Listen), Cache leeren, Filter kurz pausieren.
- PROXY64: Host ein-/ausschalten, IP aus der Sofortsperre lösen.
- DynDNS: Update jetzt auslösen.
- Jedes ändernde Werkzeug: `destructiveHint`, verständliche Zusammenfassung vor der Ausführung (MCP „elicitation“,
  wenn die Anwendung es kann, sonst Parameter `confirm: true` nach Rückfrage), Audit-Eintrag.

**Nie über MCP:** Schlüssel/Benutzer/Anmeldung, Backup/Restore/Export/Import, Verknüpfen/Trennen mit ipv64, Löschen
von Modulen oder Daten im großen Stil, Zertifikate mit privatem Schlüssel, Zurücksetzen, Updates.

## M3 (später)

OAuth 2.1 (Autorisierungsserver in der Node, Zustimmungsseite), damit Cloud-Anwendungen (claude.ai Connectors,
ChatGPT) sicher zugreifen können; Ressourcen (z. B. Kurz-Doku je Modul), Benachrichtigung der KI bei Ereignissen.

## Phasen

| Phase | Inhalt |
|---|---|
| M1 | Transport `/mcp`, MCP-Schlüssel mit Rechten, Schalter, LAN-Standard, Rate-Limit, Audit, Lese-Werkzeuge und Prompts, Doku mit Anleitungen je Anwendung, Tests (auch mit echtem MCP-Client) |
| M2 | Ändernde Werkzeuge je Bereich, Bestätigung, Rechte je Schlüssel |
| M3 | OAuth 2.1, öffentliche Erreichbarkeit über PROXY64, Ressourcen |

## Entscheidungen (offen)

1. Offizielles Go-SDK (neue Abhängigkeit, Protokolländerungen kommen mit) oder eigene schlanke Umsetzung?
2. Standard „nur Heimnetz“ – ok?
3. Welche ändernden Werkzeuge in M2 zuerst?
