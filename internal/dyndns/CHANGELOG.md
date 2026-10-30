# Änderungen – DynDNS-Updater

## 1.5.1 – 2026-10-30

### Behoben
- Feste IPv6-Adresse wird einheitlich gespeichert (z. B. `2a01:04F8::1` als `2a01:4f8::1`). Vorher galt der Name
  dauerhaft als abweichend, es gab unnötige Updates und den Zustand „umgeleitet“. IPv4-gemappte Adressen
  (`::ffff:…`) werden als feste IPv6 abgelehnt.

## 1.5.0 – 2026-10-28

### Neu
- Cluster: neuer Bereich „DynDNS“ (Standard aus). Namen samt Token und die Einstellungen gehen an die anderen Nodes;
  zuletzt gemeldete Adressen, Fehler, Pausen und Verlauf bleiben je Node. Vorher auf zwei Nodes exakt gleich angelegte
  Namen werden eins, derselbe Name mit anderer Einstellung bleibt je Node.
- Im Cluster aktualisiert immer nur eine Node die Namen: die bevorzugte, sonst die mit der kleinsten Kennung. Fällt
  sie länger als 2 Minuten aus, übernimmt eine andere und meldet alle Namen einmal; eine zurückgekehrte Node übernimmt
  erst nach 5 Minuten Erreichbarkeit wieder. Stehen die Nodes in verschiedenen Netzen, zeigen die Namen dann auf den
  anderen Anschluss.
- Seite DynDNS: Karte der Namen zeigt, welche Node aktualisiert, mit Wahl der bevorzugten Node. „Jetzt aktualisieren“
  geht nur auf der zuständigen Node. API: `GET /api/dyndns/status` liefert `cluster`.

## 1.4.1 – 2026-10-28

### Behoben
- Rückfrage bei mehreren Namen: Auch der Server verlangt die Bestätigung, ohne sie wird nichts angelegt. Namen mit IPv4
  und IPv6 „aus“ zählen nicht mit (sie werden ohnehin nicht angelegt). Ein Doppelklick auf „Ja, alle übernehmen“ sendet
  nur einmal, nach dem Zurückblättern wird erneut gefragt.

## 1.4.0 – 2026-10-28

### Neu
- Ziele aus dem Account: Sind mehr als ein Name ausgewählt, fragt „Auswahl übernehmen“ in einem Fenster nach. Es nennt
  die Namen und warnt, dass der Updater bei allen gleich die Adresse dieses Anschlusses setzt und vorhandene A- und
  AAAA-Einträge überschreibt.

## 1.3.2 – 2026-10-23

### Behoben
- Benachrichtigungen kommen vollständig in der Sprache des Kanals: „Adresse mehrfach nicht ermittelt“ und „Tageslimit
  erreicht“ waren bisher immer englisch.

## 1.3.1 – 2026-10-19

### Geändert
- Kleine Hilfe-Symbole an Karten und Seiten führen direkt zur passenden Stelle der Online-Dokumentation auf node64.de (in der Sprache der Oberfläche).

## 1.3.0 – 2026-10-19

### Neu
- Prometheus: Zustand, letzte erfolgreiche Aktualisierung und letzter Fehler je Ziel, Anzahl je Zustand und Aufrufe
  bei ipv64.net in 24 Stunden unter `GET /api/metrics` (siehe docs/PROMETHEUS.md).

## 1.2.1 – 2026-10-19

### Behoben
- Darstellung: DynDNS64-Logo im dunklen Design hell.

## 1.2.0 – 2026-10-18

### Geändert
- Namen über den Reverse-Proxy/das CDN von ipv64: Liefert DNS die CDN-Adressen, ist das gewollt. Der Updater pflegt nur die Ursprungsadresse, meldet nicht mehr allein wegen der Abweichung nach (spart Update-Limit, kein „wird woanders geändert“) und zeigt „aktuell · DNS über CDN/Proxy“. Erkannt an der Antwort von ipv64 (Adresse schon bekannt bzw. Familie vom CDN verwaltet) oder schon bei der Auswahl aus dem Account; einmal am Tag wird nachgesehen, ob es dabei geblieben ist.
- Antwort „vom CDN verwaltet“ für eine Familie pausiert das Ziel nicht mehr; die andere Familie wird weiter gemeldet.
- Auswahl aus dem Account: Namen hinter dem CDN sind wählbar (Hinweis „über ipv64-CDN“); die Records des CDN selbst werden nie angefasst.

## 1.1.0 – 2026-10-14

Prüfauftrag: Ergebnisse des Code-Reviews umgesetzt.

### Geändert
- DNS-Abgleich: Die Soll-Adresse muss nur unter den ausgelieferten sein (mehrere A/AAAA erlaubt), beide Nameserver werden gefragt, der Name absolut (mit Punkt).
- Schonfrist nach einem Update mindestens zwei Prüftakte; „wird woanders geändert“ zählt erst ab der zweiten Runde in Folge.
- Automatische Pausen werden wieder aufgenommen: nohost, Konflikt, ignoriert und Flattern nach 6 h; badauth mit API-Key stündlich mit neu geholtem Token.
- Pausen nur noch nach dem Status bzw. der info-Antwort von update.php, nicht nach Text irgendwo in der Antwort; im Präfix-Modus zählt eine 200 nur mit gültigem JSON.
- Server- oder Netzfehler halten nur das betroffene Ziel zurück (2, 4, 8 … höchstens 60 min).
- Im Modus „Adresse dieses Hosts“ wird eine temporäre Privacy-Adresse durch die stabile aus demselben /64 ersetzt.
- Ohne eingeschaltetes Ziel ruht die regelmäßige Prüfung (keine Abfragen, keine Einträge, kein Limit-Abruf); „Jetzt prüfen“ geht weiter.
- „Jetzt aktualisieren“ meldet „läuft gerade“ statt zu warten, und „nichts zu melden“, wenn keine aktuelle Adresse bekannt ist.
- Token-Anzeige nur noch mit den letzten 4 Zeichen.
- Audit über den Kern (Benutzer und IP wie dort), mit Ziel als Target; „Jetzt prüfen“ wird protokolliert.
- Lokale API: Einstellungen (`GET|PUT /api/dyndns/settings`), Auswahl aus dem Account (`GET /api/dyndns/account/names`, `POST /api/dyndns/targets/from-account`), Token neu holen (`POST /api/dyndns/targets/{id}/token`).

### Behoben
- Warnung „Limit fast erreicht“ und „Limit erreicht“ teilten sich einen Tagesmerker; jetzt getrennt, Prüfen und Setzen unter Sperre, ohne Hintergrund-Goroutine.
- Pause wegen „wird woanders geändert“ wurde nicht gemeldet.
- Ein von Hand ausgelöster Fehler unterdrückte spätere automatische Fehlermeldungen; Meldungen jetzt einmal je Störung, Entwarnung sobald der Kern sie kennt.
- Eine dauerhaft gestörte IP-Ermittlung (3 Runden in Folge) wurde nicht gemeldet.
- Beim Stoppen während eines Updates kam eine Fehlermeldung „context canceled“; Protokoll wird auch bei abgebrochenem Aufrufer geschrieben.
- Wurde während einer Runde ein Token gespeichert, schrieb die Runde die alte Pause zurück.
- „Token neu holen“ nahm bei A und AAAA den falschen Record, wenn der AAAA zuerst kam.

## 1.0.1 – 2026-10-14

### Geändert
- Die Anschluss-Analyse (CGNAT/DS-Lite) läuft nach jedem Start des Moduls neu, z. B. nach einem Wechsel ins Host-Netzwerk.

## 1.0.0 – 2026-10-14

Erste vollständige Fassung, auf der Testbox und der Dev-Node live abgenommen (IPv4 und IPv6).

### Neu
- Modul *DynDNS* ersetzt den Platzhalter; ausgeschaltet laufen keine Goroutinen und es gibt keine Tabellen.
- Öffentliche IPv4/IPv6 und /64-Präfix über `ipv4.ipv64.net` / `ipv6.ipv64.net` (Verbindung auf die Familie festgelegt), Rückfall API v2 `/ip`, optional eigene Prüf-URL; Prüftakt 1–60 min (Standard 5).
- Hinweis bei möglichem CGNAT (100.64.0.0/10) oder DS-Lite (192.0.0.1) über die ersten Stationen ins Internet, mit Links zu Artikel, FAQ und Portmapper.
- Ziele aus dem Account auswählen (zentraler ipv64-API-Key in den Einstellungen) oder von Hand anlegen; je Name wählbar, was aktualisiert wird; Ziele unter ihrer Domain gruppiert.
- Immer der sicherste Token: Record-Token vor Domain-Token, im HTTP-Header, verschlüsselt gespeichert, nie ausgegeben.
- IPv6-Modi: Adresse dieses Hosts, nur Präfix (zonenweit), Präfix + Interface-ID, Interface (stabile Adresse), fest, aus.
- Updater: meldet nur bei Abweichung (zuletzt gemeldet und direkte Abfrage der ipv64-Nameserver), nur die geänderte Familie, mindestens 5 s Abstand, Backoff bei Cooldown, Tageslimit, 3 min Schonfrist nach einem Update.
- Automatische Pausen mit Erklärung: Token abgelehnt, Name unbekannt, Konflikt (CNAME/CDN), bei ipv64 ignoriert, wird woanders geändert.
- Verlauf aller Updates und IP-Prüfungen mit Filtern, Aufbewahrung einstellbar; Update-Limit des Accounts mit eigenem Zähler und Warnung ab 80 %.
- Benachrichtigungen (Adresswechsel, Fehler/Pause, Limit) über die Standardkanäle; ipv64-Mail/-SMS direkt über die API, nicht über die hubs.
- Lokale API `/api/dyndns/*` mit OpenAPI-Doku; Export/Import ohne Tokens (Import holt sie mit dem API-Key).

### Behoben während der Abnahme
- `success` mit `ip.ipv4 = ignore`/`cdn` wurde als Erfolg gewertet; das Ziel pausiert jetzt.
- Zweiter Aufruf kurz nach einem Update, solange die Nameserver noch den alten Stand liefern.
- Bei fehlgeschlagener Prüfung einer Familie wurde die zuletzt bekannte, veraltete Adresse gemeldet.
- Fehlermeldung auch bei „Jetzt aktualisieren“ (jetzt nur bei automatischen Läufen).
