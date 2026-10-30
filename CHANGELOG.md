# Changelog – Node64

Kurz, was sich je Version ändert. Einzelheiten je Modul stehen in der Node unter Einstellungen → Module.

## Unveröffentlicht

- Healthchecks: Proxmox- und Docker-Checks lassen sich beim Bearbeiten von Hand einer anderen Untergruppe zuordnen,
  z. B. wenn zwei Proxmox-Cluster gleich heißen.

## 0.12.0-alpha.34 – 2026-10-30

- IPv6: Durchgehende Prüfung auf gleiche Behandlung von IPv4 und IPv6. Sperren und Limits zählen IPv6 je /64
  (Honeypot-Sperren in PROXY64, Passwortsperre der Statusseiten, Honeypot-Sensoren SIP/SNMP); IPv4-gemappte Netze
  (`::ffff:…/N`) in Sperr-, Freigabe- und Zugriffslisten greifen jetzt; X-Forwarded-For mit `[IPv6]:Port` wird erkannt.
- PROXY64: Bei voller Adresstabelle zählt der DoS-Schutz gröber statt ohne Limit; Heimnetz-Geräte mit globaler
  IPv6-Adresse gelten als Heimnetz; Docker-Container in reinen IPv6-Netzen sind erreichbar.
- Healthchecks: IPv6-Adressen ohne Klammern bei Proxmox VE/PBS, Docker und HTTP-Checks werden richtig erkannt;
  Namen wie `fcbayern.com` gelten nicht mehr als privates Ziel, `::ffff:10.0.0.1` und ähnliche dagegen schon.
- DNS64: Upstreams mit Link-Local-Adresse (`fe80::1%eth0`), Geräte-Einrichtung über eine IPv6-Adresse, PTR für das
  eigene IPv6-Netz und AAAA-Einträge verbessert; Hinweis, wenn eine feste Bind-Adresse nur IPv4 oder IPv6 abdeckt.
- DynDNS: Eine feste IPv6-Adresse in anderer Schreibweise (z. B. Großbuchstaben) löst keine unnötigen Updates mehr aus.
- Honeypot64: Der eigene Standort wird ohne IPv4 über IPv6 ermittelt.
- v64 Blocklist: IPv6 wird je /64 bewertet und gelistet; ein Adresswechsel im eigenen Netz entgeht der Liste nicht.

## 0.12.0-alpha.33 – 2026-10-30

- PROXY64: Neuer Reiter „Sicherheit“ für Blocklisten, DoS-Schutz und Honeypot64. Unter „Zugriffslisten“ gibt es
  jetzt eine Freigabeliste und eine eigene Sperrliste für alle Namen; Sperren des Honeypots lassen sich dort
  aufheben oder dauerhaft freigeben. Die Sperrliste gilt auch auf den CDN64-Servern.
- Healthchecks: Proxmox VE und Docker zeigen in der Übersicht ein kleines Badge, wenn es eine neuere Version gibt
  (nur Hinweis, keine Meldung).
- Healthchecks: Proxmox Backup Server überwachen – Host-System wie ein Proxmox-Node, dazu Datastores (Belegung,
  geschätzt voll), Backups und fehlgeschlagene Tasks zur Information.
- Healthchecks: Proxmox Backup Server – Alarm, wenn ein Datastore voll wird („belegt ab“, Standard 90 %) bzw.
  laut Schätzung bald voll ist („voll in weniger als … Tagen“, Standard aus).
- Healthchecks: Proxmox VE zeigt alle Speicher (lokale je Node, gemeinsame einmal) mit Belegung und meldet volle
  Speicher („Speicher belegt ab“, Standard 90 %).

## 0.12.0-alpha.32 – 2026-10-29

- Cluster: Beim Koppeln gewinnt kein veralteter API-Key mehr gegen einen neueren im Cluster, und ein Entfernen des
  Keys erreicht auch Mitglieder, die beim Koppeln einer neuen Node gerade nicht erreichbar waren. Abgelehnte Einträge
  werden mit wachsendem Abstand (bis 6 h) erneut versucht und gehen bei einem Abbruch des Abholens nicht mehr verloren.
- PROXY64: Bandbreite je Proxy-Host, „TLS durchreichen“ und Stream – Download und Upload in Mbit/s begrenzen (Standard unbegrenzt),
  darüber wird gebremst statt getrennt.
- PROXY64: Streams in einer Tabelle – Namen nur für Streams mit CDN64-Stand und ihren Ports zusammen.
- Zertifikate: Domain und Wildcard über DuckDNS, Hurricane Electric oder RFC2136 klappen wieder (diese Anbieter
  halten nur einen TXT-Wert und werden wieder nacheinander geprüft). Die DNS-01-Prüfung verlangt auch über
  öffentliche Resolver mehrere stabile Runden, und ein Wert, der kurz vor der Frist stabil wird, gilt noch.
- Healthchecks/Cluster: Nodes ohne eigene Verknüpfung prüfen bei Online- und Hybrid-Checks die Grenzen des Accounts
  und reichen Pushes direkt an ipv64 weiter; die zuständige weiterreichende Node wird überall gleich bestimmt.
- API-Log: Check-Tokens im Pfad werden gekürzt.
- Healthchecks: Nach einer Änderung von Ruhezeiten, Grenzen oder Name an einer verknüpften Node blieb ihr Stand bis
  zum Neuverbinden stehen; einmaliger voller Abgleich nach dem Update.

## 0.12.0-alpha.31 – 2026-10-29

- Datenbank: Vor Migrationen bleiben die letzten drei Backups liegen statt fünf (spart je Node mehrere Hundert MB).
- PROXY64: Namen nur für Streams – ein Stream (TCP/UDP) geht über CDN64 ins Internet, ohne Proxy-Host und ohne Ziel;
  unter dem Namen antwortet weder HTTP noch HTTPS.
- Sicherheit: Datenbanken (Node, DNS64-Abfrageprotokoll, PROXY64-Statistik) und ihre Backups sind nur noch für den
  Node-Benutzer lesbar (vorher 0644, auf dem Host für jeden Benutzer lesbar); bestehende Dateien werden beim Start
  angepasst.
- Zertifikate: Domain und Wildcard zusammen (`example.ipv64.de` + `*.example.ipv64.de`) über DNS-01 scheiterten an
  Let's Encrypt („Incorrect TXT record“); beide Prüfwerte werden jetzt gleichzeitig gesetzt, und Node64 wartet, bis
  alle Nameserver den Wert mehrmals hintereinander liefern (die ipv64-Nameserver liefern kurz nach dem Anlegen
  abwechselnd alt und neu).
- Healthchecks: Eine Änderung aus dem Portal, die gleichzeitig mit einer Änderung an der Node entstand, ging auf der
  Node verloren; sie kommt jetzt an (braucht auch die neuen hubs).
- Healthchecks/Cluster: Änderungen einer nicht verknüpften Node aus der Zeit außerhalb des Clusters kommen nach dem
  Wiederkoppeln sofort ins Portal (vorher erst nach einem Neustart).
- Einstellungen → Logging: „API-Anfragen protokollieren“ (Opt-in: aus, nur per API-Key oder alle). Jede Anfrage an
  /api/ steht dann als Zeile im Log mit Methode, Pfad, Status, Dauer, IP, Benutzer und Name des API-Keys – ohne
  Inhalte, Geheimnisse maskiert. Auch über `PUT /api/logging` (`api_log`).
- Healthchecks/Cluster: Nodes ohne eigene ipv64-Verknüpfung können Online- und Hybrid-Checks anlegen und ändern,
  wenn eine verknüpfte Node im Cluster erreichbar ist.
- Cluster: Tritt eine Node mit API-Key einem Cluster bei, in dem der Key vorher entfernt wurde, übernehmen die
  anderen ihren Key – vorher verlor die beitretende Node ihn. Wechselt eine Node ohne Key in einen anderen Cluster,
  entfernt sie dort keinen Key mehr.
- Cluster: Ein abgelehnter Eintrag (z. B. Statusseite mit gleichem Slug, Benutzer zur Wahl) wird alle 5 Minuten
  erneut versucht und kommt an, sobald der Konflikt auf einer Seite gelöst ist – vorher erst, wenn er sich drüben
  wieder änderte.
- Healthchecks: Proxmox VE und Docker – „Gestoppt ist richtig“ an einem gestoppten bzw. beendeten Gast, der als
  Störung gilt: ein Klick, und der Zustand ist in Ordnung (ohne Entwarnung). Ein Backup, das einen gestoppten Gast
  kurz startet, macht ihn nicht mehr zum „soll laufen“ (vorher Fehlalarm „gestoppt“ nach dem Backup).

## 0.12.0-alpha.30 – 2026-10-28

- Healthchecks: Proxmox-VE- und Docker-Checks zeigen eine echte Latenz (Ping zu Node, Gast bzw. Container, sonst die
  Antwortzeit der API) statt 0 ms.
- Zertifikate/Cluster: Beim Beitritt gleiche Einträge (Zertifikat mit Schlüssel, ACME-Stelle mit EAB, DNS-Zugang,
  CA) werden einmal zusammengeführt, nur Ähnliches bleibt getrennt; verschiedene ACME-Konten werden nicht mehr
  überschrieben, sondern auf der Seite Cluster zur Wahl gestellt.
- Cluster: neue Bereiche „Statusseiten“ und „Kanäle“ (Benachrichtigungen, vor allem für Nodes ohne ipv64.net),
  standardmäßig aus; vorher auf zwei Nodes exakt gleich angelegte Einträge werden zusammengeführt statt doppelt.
- Cluster: neues Modul „Node“ (standardmäßig aus) – ipv64-API-Key nur einmal eintragen (gleicher Account oder die
  Node hat noch keinen, nie ein anderer; Übernahme im Audit-Log) und allgemeine Einstellungen (Zeitzone,
  Selbst-Update, MCP an/aus) abgleichen.
- Cluster: Nodes ohne ipv64-Account können einem Cluster mit Account beitreten; bekommt eine Node den Account des
  Clusters (z. B. durch den API-Key) oder verliert sie ihn, wird nichts mehr ausgesetzt. Zwei verschiedene Accounts
  in einem Cluster gibt es weiterhin nie.
- Cluster: neuer Bereich „Benutzer & Anmeldung“ (Benutzer mit Passwort, 2FA und SSO-Verknüpfungen, SSO-Einrichtung),
  standardmäßig aus; Passkeys, Sitzungen und Forward-Auth bleiben je Node, gleichnamige verschiedene Benutzer stehen
  auf der Seite Cluster zur Wahl, der letzte Benutzer einer Node wird nie gelöscht. Unter Anmeldung lassen sich andere
  Benutzer der Node löschen.
- DynDNS/Cluster: neuer Bereich „DynDNS“ (standardmäßig aus) gleicht Namen und Einstellungen ab; es aktualisiert immer
  nur eine Node, fällt sie aus, übernimmt automatisch eine andere (bevorzugte Node auf der Seite DynDNS wählbar).

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
