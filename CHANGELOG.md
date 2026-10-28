# Changelog – Node64

Kurz, was sich je Version ändert. Einzelheiten je Modul stehen in der Node unter Einstellungen → Module.

## Unveröffentlicht

- Healthchecks: Proxmox-VE- und Docker-Checks zeigen eine echte Latenz (Ping zu Node, Gast bzw. Container, sonst die
  Antwortzeit der API) statt 0 ms.
- Zertifikate/Cluster: Beim Beitritt gleiche Einträge (Zertifikat mit Schlüssel, ACME-Stelle mit EAB, DNS-Zugang,
  CA) werden einmal zusammengeführt, nur Ähnliches bleibt getrennt; verschiedene ACME-Konten werden nicht mehr
  überschrieben, sondern auf der Seite Cluster zur Wahl gestellt.
- Cluster: neue Bereiche „Statusseiten“ und „Kanäle“ (Benachrichtigungen, vor allem für Nodes ohne ipv64.net),
  standardmäßig aus; vorher auf zwei Nodes exakt gleich angelegte Einträge werden zusammengeführt statt doppelt.
- Cluster: neues Modul „Node“ (standardmäßig aus) – ipv64-API-Key nur einmal eintragen (nur gleicher Account,
  Übernahme im Audit-Log) und allgemeine Einstellungen (Zeitzone, Selbst-Update, MCP an/aus) abgleichen.
- Cluster: neuer Bereich „Benutzer & Anmeldung“ (Benutzer mit Passwort, 2FA und SSO-Verknüpfungen, SSO-Einrichtung),
  standardmäßig aus; Passkeys, Sitzungen und Forward-Auth bleiben je Node, gleichnamige verschiedene Benutzer stehen
  auf der Seite Cluster zur Wahl, der letzte Benutzer einer Node wird nie gelöscht. Unter Anmeldung lassen sich andere
  Benutzer der Node löschen.

## 0.12.0-alpha.29 – 2026-10-28

- Interne Verbesserungen.

## 0.12.0-alpha.28 – 2026-10-28

- Interne Verbesserungen.

## 0.12.0-alpha.27 – 2026-10-28

- Sicherheit: Ergebnisse eines großen Code-Reviews behoben – u. a. Location-Zugriffslisten in PROXY64, Hosts über
  CDN64 nur noch unter dem freigegebenen Namen, Abstürze durch präparierte Pakete (Honeypot64 auf arm/v7, DNS64),
  Anmeldung (Speicher, Weiterleitung, X-Forwarded-For, CSRF), Backups ohne Programmdateien.
- Healthchecks: Störungen, Wartungsfenster, abhängige Checks und Flattern melden zuverlässig; Statusseiten beachten
  „Verfügbarkeit/Verlauf zeigen“ auch in JSON.
- Sync und Cluster: große Datenmengen werden geteilt, der Abgleich bleibt nicht mehr hängen.
- Selbst-Update und Zertifikate: sicherer Rückfall, Mindestversion gegen das Image, öffentliche Zertifikate vor eigener CA.
- PROXY64: Docker/Traefik-Labels mit nicht abbildbarem Schutz ergeben einen ausgeschalteten Host statt eines
  ungeschützten; Korrekturen an Forward-Auth und API-Keys.
- DynDNS: Sicherheitsabfrage, wenn mehrere Namen aus dem Account auf einmal übernommen werden.
- Healthchecks: Checks, die nur diese Node misst, meldet sie auch verknüpft selbst (ipv64-Mail/-SMS/App über die
  API, eigene Kanäle direkt); andere Portal-Kanäle sendet weiter ipv64.

## 0.12.0-alpha.26 – 2026-10-28

- PROXY64: Die CDN64 Statistik erklärt, wenn es im Zeitraum noch keine Schutz-Zahlen gibt.
- PROXY64: TLS nach BSI TR-02102-2 je Proxy-Host wählbar.
- PROXY64: Zugriffslisten mit authentik, Authelia, oauth2-proxy oder eigenem Anmeldedienst (Forward-Auth), API-Keys für
  Apps und Skripte, Benutzername auf Wunsch an das Ziel. Traefik-Middlewares mit forwardAuth werden übernommen.
- PROXY64: Proxy-Hosts aus Docker-Labels (`node64.proxy.host`/`port`, auf Wunsch auch Traefik-Labels), neuer Reiter
  Docker, standardmäßig aus.
- PROXY64: neue Standardwerte beim Schutz vor Überlastung (weniger Verbindungen je IP und insgesamt), Hinweis zur
  passenden Gerätegröße.
- Anmeldung: SSO mit authentik funktioniert, die Issuer-URL darf mit „/“ enden (#6).
- Honeypot64: Die Zahlen der Übersicht bleiben vollständig, auch wenn die Obergrenze gespeicherter Ereignisse erreicht
  ist; dazu ein Hinweis (#7).

## 0.12.0-alpha.25 – 2026-10-27

- PROXY64: Die Liste der Proxy-Hosts passt auch auf schmaleren Bildschirmen.
