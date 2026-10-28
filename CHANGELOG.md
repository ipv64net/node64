# Changelog – Node64

Kurz, was sich je Version ändert. Einzelheiten je Modul stehen in der Node unter Einstellungen → Module.

## Unveröffentlicht

- PROXY64: Docker/Traefik-Labels mit nicht abbildbarem Schutz ergeben einen ausgeschalteten Host statt eines
  ungeschützten; Korrekturen an Forward-Auth und API-Keys.
- DynDNS: Sicherheitsabfrage, wenn mehrere Namen aus dem Account auf einmal übernommen werden.

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
