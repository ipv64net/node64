# Plan: Statusseiten (Node64)

Stand 2026-10-20, Entwurf zur Abstimmung mit Dennis. Öffentliche Statusseiten aus den Healthchecks: lokal auf der
Node, optional über PROXY64 (eigene Domain) und CDN64, später gespiegelt bei ipv64.

## Vorbilder

| | Uptime Kuma | ipv64 heute (`statuspage.php`, `/status/<slug>`, API v2 `/status-pages`) |
|---|---|---|
| Seiten | mehrere, je Slug, eigene Domains (über Reverse-Proxy) | mehrere, je Slug unter ipv64.net/status/ |
| Inhalt | Gruppen von Monitoren, Balken der letzten Messungen, Verfügbarkeit 24 h, optional Zertifikat-Ablauf und Tags | Liste von Checks |
| Gestaltung | Logo, Beschreibung, Fußzeile (Markdown), hell/dunkel/auto, eigenes CSS, „Powered by“ abschaltbar | 4 Designs, Beschreibung |
| Meldungen | angeheftete Ankündigung (Info/Warnung/Gefahr, Markdown), Wartungen werden angezeigt | – |
| Sonstiges | Badges (SVG: Status, Verfügbarkeit, Latenz, Zertifikat), Analytics, Neuladen alle 5 min (Cache 5 min) | Passwort (im Klartext gespeichert), Auto-Refresh |
| Fehlt | Passwortschutz, Schutz von Zielen ist Sache des Nutzers | Gruppen, Ankündigungen, Wartungen, Badges; liest noch die alten Healthchecks |

## Ziel

Eine Statusseite einmal anlegen. Sie zeigt nur das, was Besucher sehen sollen: Namen, Zustand, Verfügbarkeit,
Störungen, Wartungen und Ankündigungen. Nie gezeigt werden Ziele, IPs, Ports, Fehlermeldungen oder interne Namen.

## Funktionen

### Inhalt einer Seite

- Kopf: Titel, Logo, Beschreibung (Markdown), Gesamtbanner „Alle Systeme betriebsbereit“, „Teilweise gestört“,
  „Störung“, „Wartung“.
- Gruppen (z. B. „Webseiten“, „Heimnetz“) mit Checks in eigener Reihenfolge. Je Eintrag ein eigener Anzeigename,
  denn der Check-Name bleibt intern.
- Je Eintrag: Zustand, Verfügbarkeit (wählbar 24 h / 7 / 30 / 90 Tage), Balken, optional Latenz und
  Zertifikat-Ablauf. Balken je Seite wählbar: die letzten 30–90 Messungen (wie Kuma) oder Tagesbalken für 30/90 Tage
  (wie statuspage.io; Tag rot, wenn eine Störung, gelb bei Teilstörung, grau ohne Daten).
- Störungen automatisch aus den Healthchecks: „Störung seit 10:12“, „behoben nach 28 min“; Grund nur als
  allgemeiner Text (nicht erreichbar, Zeitüberschreitung …), nie die Rohmeldung.
- Wartungsfenster automatisch: laufende oben, geplante der nächsten 7 Tage als Hinweis.
- Ankündigungen von Hand: Titel, Text (Markdown), Stufe Info/Warnung/Störung, mit Updates (Zeitleiste) und „erledigt“.
- Verlauf: die Störungen und Ankündigungen der letzten 30 Tage unten oder als eigene Unterseite.
- Fußzeile (Markdown), „Bereitgestellt mit Node64“ abschaltbar.

### Ansichten (statt der 4 Designs bei ipv64)

| Ansicht | Zweck |
|---|---|
| Liste | Standard, gruppiert mit Balken (wie Kuma) |
| Kacheln | große Kacheln je Eintrag, dunkel, für Monitor/TV an der Wand; lädt alle 30 s neu |
| Kompakt | nur Gesamtbanner und eine Zeile je Gruppe; zum Einbetten (iframe) |

Dazu hell/dunkel/automatisch, Sprache automatisch (Browser) oder fest DE/EN, eine Akzentfarbe statt eigenem CSS
(eigenes CSS später, wenn gefragt).

### Schnittstellen

- `GET /status/<slug>/status.json`: öffentlich, das, was die Seite zeigt (für eigene Widgets, Home Assistant).
- Badges `GET /status/<slug>/badge/<eintrag>.svg?type=status|uptime|latency` und für die ganze Seite.
- Feed `GET /status/<slug>/feed.atom` mit Störungen und Ankündigungen.
- Verwaltung über die bestehende API (`/api/healthchecks/status-pages…`), openapi.

### Zugriff und Schutz

- Optional Passwort (bcrypt, Sitzung per Cookie), optional „nicht indexieren“ (`noindex`).
- Slug frei wählbar, Vorschlag zufällig.
- Öffentliche Routen liegen getrennt von der Oberfläche: kein Login, keine Sitzung der Verwaltung, strenge CSP, nur
  GET. Die Seite fragt `status.json` ab, gerechnet wird alle 30 s im Hintergrund und zwischengespeichert. Viele
  Besucher kosten so kaum etwas. Limits pro IP wie bei PROXY64.

## Wege nach außen (schrittweise)

| Stufe | Weg | Wofür |
|---|---|---|
| 1 | Node direkt: `http(s)://<node>:<port>/status/<slug>` | LAN, Test; Schalter „auf dem Node-Port veröffentlichen“ (Standard aus, Vorschau in der Oberfläche geht immer) |
| 2 | PROXY64: neue Hostart **Statusseite** (Domain → Seite) | eigene Domain wie `status.example.de`, Zertifikat zentral, Blocklisten, Ländersperre und Limits greifen; der Admin-Port bleibt zu |
| 3 | CDN64 | ergibt sich aus Stufe 2: Host bei CDN64 einschalten → über srv07/srv08 erreichbar, IP verborgen |
| 4 | Spiegel bei ipv64 | für verknüpfte Nodes: Definition der Seite geht per hub-Sync zu ipv64, die Seite wird dort aus den hc2-Daten erzeugt (ipv64.net/status/<slug>). Bleibt erreichbar, wenn zu Hause Strom oder Leitung weg ist; genau dann wird eine Statusseite gebraucht. Ersetzt die alte ipv64-Statusseite für die neue Healthchecks-Welt (PLAN-IPV64-SYNC Abschnitt 6) |

Mit dem Cluster (später, siehe PLAN-NODE64-CLUSTER-MODULE) kann jede Node dieselbe Seite ausliefern; zusammen
mit CDN64 auf mehreren Nodes ist die Seite dann ausfallsicher.

## Datenmodell (Node, Migration im Modul Healthchecks)

- `hc_status_pages`: id, slug (eindeutig), title, description, footer, logo (Datei unter /data), layout
  (list/tiles/compact), theme, lang, accent, bars (checks/days), bar_count, uptime_window, show_latency,
  show_cert, show_history, refresh_sec, password_hash, noindex, publish_node (Stufe 1), created/updated.
- `hc_status_groups`: id, page_id, name, sort.
- `hc_status_items`: id, group_id, token (Check), label, sort.
- `hc_status_notices`: id, page_id, title, level, created/updated/resolved; `hc_status_notice_updates`: id,
  notice_id, time, text, level.
- Gelöschter Check → Eintrag verschwindet von selbst; pausierter Check → „pausiert“ (grau).

## Phasen

| Phase | Inhalt |
|---|---|
| S1 | Datenmodell, Verwaltung (Healthchecks › Statusseiten: Liste, Bearbeiten mit Gruppen per Drag & Drop, Vorschau), öffentliche Route Stufe 1, Ansicht Liste, Gesamtbanner, Balken, Verfügbarkeit, Störungen und Wartungen automatisch |
| S2 | Ankündigungen mit Updates, Ansichten Kacheln und Kompakt, Logo, Theme/Akzent, Passwort, `status.json`, Badges, Feed |
| S3 | PROXY64-Hostart „Statusseite“ (eigene Domain); damit CDN64 möglich |
| S4 | Spiegel bei ipv64 (hub-Sync der Definition, Seite auf ipv64 aus hc2, Portal schlank: nur Anzeige, Verwaltung in der Node) |
| S5 | node64.de: Doku und Werbung; Export/Import und Backup nehmen die Seiten mit |

## Offene Entscheidungen

1. Ort in der Oberfläche: Teil von Healthchecks („Statusseiten“ im Untermenü, empfohlen) oder eigenes Modul?
2. Stufe 1 (Node-Port): Standard aus und nur bewusst einschalten (empfohlen), oder an?
3. Spiegel bei ipv64 (S4) einplanen? Wenn ja: bisherige URL ipv64.net/status/<slug> weiterverwenden?
4. Balken: Standard „letzte Messungen“ (Kuma) oder „Tage“ (statuspage.io)?
5. Eigenes CSS zulassen oder nur Akzentfarbe/Logo (empfohlen: zuerst nur Akzent/Logo)?
