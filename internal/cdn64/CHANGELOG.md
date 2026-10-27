# Änderungen – PROXY64

## 1.33.1 – 2026-10-27

### Behoben
- v64 Blocklist: Nach dem Neustart mehrerer Nodes desselben Accounts stand bei der Liste „HTTP 429“. Das Listen-Token
  gilt für den ganzen Account, und ipv64.net ließ dieselbe Datei nur einmal alle 5 Minuten je Token zu.
  - Das Portal hat diese Sperre aufgehoben. Es bleibt bei höchstens 60 Abrufen je 5 Minuten und Token.
  - PROXY64 behält bei einem 429 den vorhandenen Stand und zeigt keinen Fehler. Nur ohne Stand lädt es den
    Tagesstand.

## 1.33.0 – 2026-10-27

### Neu
- Sofort-Sperre aus dem Honeypot: Die gesperrten IPs stehen jetzt auch in der Datenbank und überstehen einen Neustart
  (bisher nur im Speicher). „Freigeben“ entfernt den Eintrag auch dort.
- Die Sofort-Sperre lässt sich auch im Honeypot einschalten („Erkannte Angreifer in PROXY64 sperren“, dort Standard
  an). Unter Zugriffslisten → Honeypot64 steht dann „Eingeschaltet über Honeypot64“; der eigene Schalter bleibt für
  die Sperre ohne diesen Haken.

## 1.32.2 – 2026-10-27

### Geändert
- Zugriffslisten: Die Karte „Schutz vor Überlastung“ heißt jetzt „DoS-Schutz (Denial of Service) – Schutz vor
  Überlastung“.

## 1.32.1 – 2026-10-27

### Geändert
- ipv64-Blocklisten: Die v64 Blocklist steht jetzt oben direkt hinter der Gesamtliste statt am Ende der Liste.

## 1.32.0 – 2026-10-27

### Neu
- v64 Blocklist live ohne Handarbeit: Ist kein Listen-Token von Hand eingetragen, holt PROXY64 es selbst über den
  zentralen ipv64-API-Key (nur wenn die Liste „ipv64 Honeypot“ eingeschaltet ist). Wer berechtigt ist (Beitragende und
  alle Klassen außer Standard), bekommt damit automatisch die Live-Fassung, sonst den Tagesstand; ändert sich die
  Klasse, wechselt die Fassung beim nächsten Abruf von selbst. Ein Token von Hand geht weiter vor.

## 1.31.1 – 2026-10-27

### Geändert
- ipv64-Blocklisten: Von der v64 Blocklist gibt es nur noch die eine Liste (die Teillisten SSH, Web, Mail, RDP,
  Scanner und Forschungs-Scanner liefert ipv64.net nicht mehr). War eine Teilliste eingeschaltet, gilt jetzt die
  v64 Blocklist – der Schutz bleibt ohne Lücke.

## 1.31.0 – 2026-10-26

### Neu
- Wartungsmodus je Proxy-Host (Reiter „Wartung“, Knopf in der Liste): Der Name bleibt erreichbar, Besucher sehen eine
  Wartungsseite statt des Ziels – Terminal im Matrix-Stil (Standard), schlicht mit Zahnrad (hell/dunkel) oder eigenes
  HTML (bis 64 KB, Vorschau). Antwort 503 mit Retry-After, nie zwischengespeichert; zählt weder als abgewiesen noch
  als Fehler, im Zugriffs-Log als „Wartungsmodus“. Gilt auch über CDN64 Modus 1 und 2, nicht für Modus 3.
- Datenverkehr getrennt nach Richtung (Sicht des Besuchers): Download (vom Ziel zum Besucher) und Upload (vom
  Besucher zum Ziel, z. B. hochgeladene Dateien), jeweils so, wie es über die Leitung geht; WebSockets in beide
  Richtungen. Zwei Kacheln oben, je Host „↓ … · ↑ …“, zwei Linien im Diagramm, getrennt auch auf der Seite Zugriffe
  und in der Karte auf der Startseite. Upload zählt ab diesem Stand (ältere Stunden nur Download).

- Zugriffslisten mit Login-Seite (Schalter „Login-Seite statt Browser-Dialog“): Besucher melden sich auf einer Seite im
  Stil von Node64 an (hell/dunkel, Deutsch/Englisch nach Browser), danach hält ein signiertes Cookie die Sitzung
  (12 Stunden, „Angemeldet bleiben“ 30 Tage). Ein neues Passwort beendet bestehende Sitzungen, das Cookie geht nie an
  das Ziel, Fehlversuche zählen wie bisher (Sperre, Honeypot-Meldung). Basic Auth bleibt für Programme möglich;
  Abmelden über /.node64/logout (Knopf). Hat der Host ein Zertifikat, geht die Anmeldung von HTTP immer auf HTTPS;
  ein unbekannter Benutzer dauert so lange wie ein falsches Passwort.

### Geändert
- WebSockets zählen in der Statistik als beantwortet (101) statt als abgebrochen (4xx).


## 1.30.3 – 2026-10-26

### Geändert
- Handy: Die Liste der Hosts, „Weitere Namen in CDN64“ und die Zugriffe zeigen je Eintrag eine Karte (Beschriftung
  links, Inhalt rechts) statt einer breiten Tabelle zum Hin- und Herscrollen.


## 1.30.2 – 2026-10-26

### Behoben
- „Lokal in DNS64 eintragen“: Wildcards (*.example.de) und Hauptdomains (example.de) werden nicht mehr eingetragen –
  DNS64 hätte dort Mail-, TXT- und andere Einträge im Heimnetz verdeckt. Das IPv4-Feld nimmt nur IPv4, das IPv6-Feld
  nur IPv6; Loopback- und link-lokale Adressen werden abgelehnt (auch nicht mehr vorgeschlagen). Ausgeschaltete
  DNS64-Einträge zählen nicht als vorhanden, ein schon vorhandener gleicher Eintrag wird übersprungen statt mit Fehler
  abzubrechen. Die Rückwärtsauflösung der Proxy-Adresse bleibt unverändert (Eintrag ohne PTR).
- Die Spalte mit den Namen bricht in der Host-Liste nicht mehr Buchstabe für Buchstabe um.


## 1.30.1 – 2026-10-26

### Behoben
- Die Kacheln „CDN-Domains“ und „CDN-Traffic“ stehen nur noch unter den Proxy-Hosts, nicht mehr unter Weiterleitungen,
  404-Hosts, Statusseiten und Streams.

## 1.30.0 – 2026-10-26

### Neu
- Host-Liste (Proxys): Knopf „Lokal in DNS64 eintragen“ (Haus-Symbol). Trägt die Namen des Hosts als eigene
  DNS-Einträge in DNS64 ein (ohne Zone) – A und optional AAAA auf die Adresse des Reverse-Proxys. Vorgeschlagen ist die
  Adresse, über die Node64 gerade aufgerufen wird, sonst die der Node im LAN. Vorhandene Einträge desselben Typs und
  CNAMEs bleiben unverändert; ein grünes Haus zeigt, dass alle Namen schon lokal stehen. Nur, wenn DNS64 läuft.
- Fenster „CDN64 einschalten“: Modus 1, 2 und 3 sind oben kurz erklärt, jeweils mit Skizze; ein Klick auf den Kasten
  wählt den Modus. Modus 3 läuft ohne Node64 und verlinkt auf ipv64.net/cdn64.

## 1.29.0 – 2026-10-26

### Geändert
- Statistik: „Fehler“ sind nur noch echte Fehler – 5xx und „Ziel nicht erreichbar“. 4xx-Antworten des Ziels (nicht
  gefunden, nicht angemeldet; z. B. fehlende Icons bei Bitwarden) stehen getrennt in Grau, von PROXY64 abgewiesene
  Anfragen zählen nur noch unter „abgewiesen“ und nicht zusätzlich bei 4xx. Gilt für die Host-Tabelle, die Kennzahlen
  und das Diagramm (auch auf dem Dashboard). Ältere Stunden enthalten Abgewiesenes noch bei 4xx.
- Seite Zugriffslisten: Die Karte Honeypot64 steht rechts unter „Schutz vor Überlastung“ (kompakter).

### Neu
- „An Honeypot“: Anfragen, die statt einer Abweisung den Köder von Honeypot64 bekamen (unbekannte Namen und als
  schädlich erkannte), zählen eigen – je Host in der Tabelle, als Kennzahl, im Diagramm (lila) und im Zugriffs-Log
  (Kennzeichen und Filter). Sichtbar, solange der Köder aktiv ist oder es im Zeitraum Umleitungen gab.

## 1.28.0 – 2026-10-25

### Neu
- Honeypot: Auch als schädlich erkannte Anfragen können statt 403 den Köder von Honeypot64 bekommen – je Art ein
  Schalter unter Zugriffslisten → Honeypot64: IPs der ipv64-Blocklisten, vom Honeypot gemeldete Angreifer, Exploit-Muster,
  KI-Bots/Scanner (alle Standard an) und Ländersperre (Standard aus). Überlast (Rate-Limits) geht nie an den Köder.
  Gilt nur, solange der Köder aktiv ist, und nur für HTTP(S); TCP/UDP-Streams und TLS-Durchreichen weisen weiter ab.
- Läuft Honeypot64 mit der Vorlage „Nur über PROXY64“, ist der Köder automatisch eingeschaltet.

### Geändert
- Gesperrte IPs (Blocklisten, Honeypot-Sperre) trennt der Web-Eingang nicht mehr vor TLS, wenn ihr Weg an den Köder
  an ist – die Anfrage bekommt dann den Köder. Durchgereichte Hosts prüfen die Sperren jetzt selbst nach dem ersten
  TLS-Paket.

## 1.27.2 – 2026-10-24

### Behoben
- Host-Formular: Nach einem Fehler im Formular (z. B. ungültiger Name oder fehlender Haken für die Nutzungsbedingungen)
  bleibt der gewählte Weg zum neuen Zertifikat ausgewählt, statt auf „automatisch“ zurückzuspringen.

## 1.27.1 – 2026-10-24

### Geändert
- Host-Formular, „Neues Zertifikat gleich mit anfordern“: Der Weg zum Zertifikat bietet jetzt alle Wege wie unter
  Zertifikate – Automatisch, ipv64 DNS-01, HTTP-01, anderer DNS-Anbieter (je Zugang), eigene CA (je CA) und selbst
  signiert. Nicht verfügbare Wege stehen ausgegraut mit Grund da (kein API-Key, kein DNS-Zugang, keine CA); Alias über
  ipv64 verweist auf Zertifikate → Neu. Eigene CA und selbst signiert brauchen kein Let's-Encrypt-Konto – der Haken für
  die Nutzungsbedingungen erscheint nur bei den Let's-Encrypt-Wegen.

## 1.27.0 – 2026-10-24

### Neu
- Docker-Bridge-Netz: PROXY64 prüft, ob HTTP- und HTTPS-Port (80/443) auf dem Docker-Host veröffentlicht sind – eine
  Prüfanfrage über das Gateway muss beim eigenen Eingang ankommen, ein anderes Programm auf dem Host zählt nicht.
  Fehlt ein Port, warnt die Host-Liste deutlich mit fertigem `-p …` zum Kopieren; *Einstellungen → Ports* zeigt
  „nicht veröffentlicht“ bzw. „auf dem Host veröffentlicht“ und ein Beispiel für `docker run` und `docker compose`.
  Bisher meldete die Prüfung „lauscht“, sobald der Port im Container offen war, auch wenn von außen nichts ankam.

## 1.26.1 – 2026-10-24

### Behoben
- Proxy-Host mit „neues Zertifikat anfordern“ ohne Let’s-Encrypt-Konto: Bisher wurde der Host gespeichert und das
  Zertifikat scheiterte danach an den nicht angenommenen Nutzungsbedingungen. Jetzt steht im Formular der Haken für die
  Nutzungsbedingungen (mit Link); ohne ihn bleibt der Host ungespeichert und das Formular zeigt den Hinweis.

## 1.26.0 – 2026-10-23

### Neu
- CDN64 für Business und Company: mehrere parallele Tunnel-Verbindungen je Server (4 statt 1, über QUIC, QUIC über
  443 oder TLS, je nachdem, was durchkommt). srv07/srv08 geben neue Besucher an die am wenigsten belastete Verbindung;
  fällt eine aus oder hakt, laufen die Besucher über die anderen weiter. Im Lasttest bremste bisher die eine
  Verbindung je Server bei etwa 650–830 Mbit/s. Die Zahl kommt von ipv64 je Klasse; ändert sich die Klasse, baut die
  Node die Verbindungen von selbst neu auf. In der Host-Liste zeigt der Server „×4“, wenn mehrere Verbindungen stehen.
- Account-Klassen: neue Zeile „Parallele Tunnel-Verbindungen je Server“.
- Ab cdn64-edge 0.18.0 auf den Servern (ältere Server nutzen weiter eine Verbindung).

## 1.25.1 – 2026-10-23

### Geändert
- Proxy-Hosts: Die Zahlen je Host in der Tabelle folgen dem Zeitraum der Verkehrs-Karte (24 Stunden, 7 Tage,
  30 Tage) – Anfragen, neu der Datenverkehr, Fehler (4xx/5xx) und Abgewiesene. Bisher zeigte die Spalte die Anfragen
  der letzten 24 Stunden, Fehler und Abgewiesene aber seit dem Start des Moduls. Spaltenkopf und Kennzahlen nennen den
  gewählten Zeitraum.

## 1.25.0 – 2026-10-22

### Neu
- Je Host „KI-Bots abweisen (User-Agent)“ mit „Nutzer-Abrufe auch sperren“ (Standard an) und „robots.txt mit KI-Sperre
  ausliefern“ (nur wenn das Ziel keine hat). Grundlage ist die Liste „v64 KI-Bots (User-Agent)“ von ipv64.net (Spiegel
  von ai.robots.txt). Abgewiesene KI-Bots bekommen 403 und erscheinen als „KI-Bot“ in Statistik und Zugriffs-Log.
- Die Blockliste „v64 KI-Bots (IP)“ (offizielle Netze von OpenAI, Perplexity, Common Crawl, Mistral, Google-Agent) ist
  auswählbar.

## 1.24.1 – 2026-10-21

### Behoben
- Portmapper über CDN64: höchstens 1024 UDP-Sitzungen und 4096 TCP-Verbindungen je Stream aus dem Tunnel (wie am
  Port des Streams). Vorher waren aus dem Tunnel beliebig viele UDP-Sitzungen möglich (die Server erlauben bis zu
  4096 je Port und Server).

## 1.24.0 – 2026-10-21

### Neu
- Portmapper für CDN64 Modus 1/2: Ein Stream lässt sich über einen CDN64-Namen der Node aus dem Internet erreichen
  (Auswahl „Über CDN64 aus dem Internet erreichbar“ im Stream). srv07/srv08 öffnen dafür einen Port und reichen
  TCP bzw. UDP durch den verschlüsselten Tunnel zum Stream. Zu Hause muss kein Port offen sein, die eigene Adresse
  bleibt verborgen. Blocklisten, Grenzen je IP und Ländersperre gelten nach der echten Besucher-Adresse, TLS-Abschluss
  des Streams ebenso. Der Port der Server steht in der Stream-Liste und in der Zeile des Hosts; er zählt zum
  Kontingent für Portmapper. Pause und Erlauben-/Sperrliste des Namens gelten auch für diese Ports.
- Ab cdn64-edge 0.15.0 auf den Servern.

## 1.23.2 – 2026-10-21

### Geändert
- Steht ein Modus-3-Name in der Zeile seines Hosts, zeigt sie jetzt auch die Portmapper (Port der Server → Port des
  Ziels) und die Erlauben-/Sperrliste.

## 1.23.1 – 2026-10-21

### Geändert
- Pausierte CDN64-Namen sind in der Host-Liste und in „Weitere Namen in CDN64“ gelb hinterlegt.
- Ein Name in Modus 3 (auf ipv64.net) oder von einer anderen Node, zu dem es hier einen Host gibt, steht jetzt in der
  Zeile dieses Hosts: Modus, Status, Cache, Traffic, Pause und Link zum Bearbeiten. Einschalten und Modus wechseln
  gibt es dort nicht mehr. Die Karte „Weitere Namen in CDN64“ zeigt nur noch Namen ohne Host hier.

## 1.23.0 – 2026-10-21

### Neu
- CDN64 pausieren (alle Modi): Ein Klick in der Host-Liste, und srv07/srv08 nehmen für den Namen nichts mehr an.
  Offene Verbindungen trennen die Server nach wenigen Sekunden. Gedacht als schneller Selbstschutz, etwa bei einem
  Angriff. Der Tunnel bleibt verbunden und DNS zeigt weiter auf die Server, die eigene Adresse bleibt also verborgen.
  Einstellungen und Statistik bleiben erhalten. Fortsetzen mit demselben Knopf.
- „Weitere Namen in CDN64“: Namen des Kontos, die diese Node nicht verwaltet, erscheinen unter der Liste. Das sind
  Namen in Modus 3 (auf ipv64.net eingerichtet, die Server gehen direkt zum Ziel) oder Namen in Modus 1/2 über eine
  andere Node. Angezeigt werden Ziel, Cache der Server, Erlauben-/Sperrliste, Portmapper, Status und Traffic im
  Monat. Pausieren geht hier, bearbeitet wird auf ipv64.net bzw. in der anderen Node.
- Den Stand holt die Node jetzt auch ohne eigene CDN64-Namen. Ohne Namen im Konto geschieht das alle 5 Minuten,
  beim Öffnen der Liste sofort.

## 1.22.0 – 2026-10-21

### Behoben
- Asset-Cache: Abgebrochene oder fehlerhafte Antworten des Ziels werden nie mehr zwischengespeichert, auch komprimiert
  und über HTTP/3 bzw. den CDN64-Tunnel.
- Cache-Fassungen richten sich nach den Verfahren, die der Browser wirklich annimmt (q=0 zählt nicht). Was das Ziel
  selbst komprimiert (z. B. deflate), bekommt kein Browser, der es nicht kann.
- 103 Early Hints vom Ziel verhindern Komprimierung und Cache nicht mehr. Accept-Ranges entfällt bei komprimierten
  Antworten.
- Komprimierung braucht deutlich weniger Speicher (kleinere Fenster, ca. 3–6 MB statt bis zu 50 MB je Antwort). Die
  stärkere Stufe gilt nur für Antworten, die wirklich in den Cache kommen, und läuft höchstens 2–4-mal gleichzeitig.
- X-Forwarded-For und X-Real-IP lassen sich unter „Erweitert“ nicht mehr setzen oder entfernen (die echte
  Client-Adresse bleibt verlässlich). Durchreichen auf die eigene Oberfläche der Node wird abgelehnt.
- Import: Statusseiten-Hosts ohne Seitenzuordnung im Export (ältere Exporte oder Healthchecks dort aus) werden
  ausgeschaltet angelegt und gemeldet.
- Statistik: Summen und Verlauf zählen dieselben Stunden (genau N Stunden inkl. der laufenden).
- Kontingent: Kacheln und Startseiten-Karte nutzen dieselben Balkenwerte und Farben.

## 1.21.4 – 2026-10-21

### Behoben
- Export/Import: Hosts der Art „Statusseite“ zeigen nach dem Import auf die Seite mit demselben Slug auf der Ziel-Node
  (die Seiten-ID gilt nur auf der Quelle). Fehlt die Seite dort, wird der Host ausgeschaltet angelegt.
- Node zurücksetzen trägt die Namen von CDN64 online und den Tunnel bei ipv64 auch dann aus, wenn PROXY64 gerade
  ausgeschaltet ist; so bleiben keine Rückstände online.
- „24 Std.“ (Seite, Startseiten-Karte, Prometheus) zählt nur noch volle Stunden-Eimer der letzten 24 Stunden statt
  bis zu 25 Stunden.
- Kontingent-Kacheln auf der PROXY64-Seite: Der Balken ist bei kleinem Verbrauch sichtbar (mindestens 1 %), Domains
  ohne Kontingent im Tarif zählen als voll.

## 1.21.3 – 2026-10-21

### Behoben
- Export/Import der Konfiguration enthält jetzt auch die Honeypot-Schalter (Köder, Zugriffe an den Log-Sensor,
  Sofort-Sperre mit Dauer); nach dem Import gelten sie sofort. Die Sperrliste selbst bleibt auf der Node.
- Port-Übersicht (Einstellungen › Ports): Streams melden, warum ein Port nicht offen ist (z. B. „address already in use“); der Tunnel von CDN64 online erscheint als ausgehende Verbindung (Server, Port, verbunden, letzter Fehler).

## 1.21.2 – 2026-10-21

### Geändert
- Startseiten-Karte: wenn CDN64 online genutzt wird, CDN-Domains und CDN-Traffic dieses Monats als „x / y“ mit Balken
  (grün, ab 80 % gelb, voll rot) und Hinweis, bis wann der Traffic bei gleichem Verbrauch reicht.

## 1.21.1 – 2026-10-21

### Geändert
- CDN-Kontingent unter der Host-Liste als zwei Kacheln mit Fortschrittsbalken (Domains mit Bandbreite, Traffic
  diesen Monat) und Prognose: bei gleichem Verbrauch, ob der Traffic bis zum Monatsende reicht, sonst bis wann.

## 1.21.0 – 2026-10-21

### Neu
- Komprimierung mit zstd und Brotli zusätzlich zu gzip, gewählt nach dem Browser (dynamisch zstd → Brotli → gzip,
  statische Dateien im Cache Brotli → zstd → gzip auf stärkerer Stufe). Für neue Proxy-Hosts standardmäßig an.

### Geändert
- Der Cache liegt jetzt hinter der Komprimierung und liefert die fertig komprimierte Fassung aus; Schalter heißt
  „Antworten komprimieren“. Starke ETags werden beim Komprimieren schwach, `Cache-Control: no-transform` wird beachtet.

## 1.20.1 – 2026-10-20

### Geändert
- Honeypot64: Am Schalter „Unbekannte Anfragen an den Honeypot“ steht, dass die Node danach auf unbekannte Anfragen
  sichtbar antwortet (Login-Seite, Ersatz-Zertifikat) – hervorgehoben, wenn die Standardseite auf „Verbindung
  schließen“ steht. In den Einstellungen (Ports) weist die Standardseite darauf hin, solange der Köder sie ersetzt.

## 1.20.0 – 2026-10-20

### Neu
- Zusammenarbeit mit Honeypot64 (Karte „Honeypot64“ unter Zugriffslisten, drei Schalter, alle standardmäßig aus, nur
  mit laufendem Modul Honeypot64):
  - Unbekannte Anfragen an den Honeypot: Anfragen ohne passenden Host (nur IP, fremde Domain, unbekannter Name)
    bekommt der Web-Köder statt der Standardseite.
  - Zugriffe an den Honeypot geben: je Anfrage nur Metadaten (IP, Host, Methode, Pfad ohne Abfrage, Status,
    fehlgeschlagene Anmeldung) an den Log-Sensor, nie Inhalte.
  - Angreifer aus dem Honeypot sofort sperren: gemeldete IPs werden für alle Hosts und Streams gesperrt (Dauer
    einstellbar, Standard 24 h), private Adressen, Ausnahmen der Blocklisten und Proxys der Hosts nie. Liste mit Grund
    und Ende, einzeln aufhebbar.
- API `GET/PUT /api/cdn64/honeypot`, `DELETE /api/cdn64/honeypot/blocks/{ip}`; Prometheus `node64_cdn64_honeypot_*`.

## 1.19.1 – 2026-10-20

### Behoben
- Ländersperre „nur zulassen“: Solange die Liste eines der erlaubten Länder noch nicht geladen ist (z. B. kurz nach
  dem Start oder wenn ein Download scheitert), wird niemand gesperrt – vorher wurden Besucher dieses erlaubten Landes
  abgewiesen.

## 1.19.0 – 2026-10-20

### Neu
- ipv64-Blocklisten: Die Listen der ipv64-Honeypots (v64 Blocklist und Teillisten SSH, Web, Mail, RDP, Scanner,
  Forschungs-Scanner) erscheinen mit der Markierung „ipv64 Honeypot“, sobald ipv64 sie in `index.json` anbietet.
- Listen-Token für Live-Listen: In der Blocklisten-Karte lässt sich das Listen-Token aus dem ipv64-Account hinterlegen,
  ändern und löschen. Damit lädt PROXY64 die Honeypot-Listen in der Live-Fassung (alle 30 Minuten neu bewertet), ohne
  Token den Tagesstand. Jede Liste zeigt, welche Fassung geladen ist; hat das Token keine Berechtigung, steht dort
  „Tagesstand – Token ohne Berechtigung“, wird es abgelehnt (401/403/404), lädt PROXY64 den Tagesstand und zeigt den
  Fehler.
- Das Token wird verschlüsselt gespeichert, nie angezeigt, geloggt oder exportiert. API: `GET /api/cdn64/blocklists`
  liefert `token_set` und je Liste `edition`, `live_denied`, `live_error`; `PUT` nimmt `token` (leer = löschen).

## 1.18.1 – 2026-10-20

### Behoben
- Ländersperre: Eine Länderliste, die genau während des Ladens für einen neuen Host gebraucht wurde, konnte bis zur
  nächsten Aktualisierung fehlen.

## 1.18.0 – 2026-10-20

### Neu
- Neue Hostart „Statusseite“ (Reiter Statusseiten): Eine eigene Domain zeigt eine Statusseite der Healthchecks direkt
  unter „/“, mit zentralem Zertifikat, Force-SSL, HSTS und HTTP/3.
- Vor der Seite greifen wie bei Proxy-Hosts Blocklisten, Ländersperre, Limits, Exploit-Sperre und Zugriffsliste, dazu
  Statistik und Zugriffs-Log. Über CDN64 ist sie wie ein Proxy-Host in Modus 1 oder 2 einschaltbar.
- Export und Import nehmen die Zuordnung mit. Fehlt die Seite auf der Ziel-Node, antwortet der Host mit 404 (ohne
  Healthchecks mit 503), bis eine Seite gewählt ist.

## 1.17.1 – 2026-10-19

### Neu
- Proxy-Hosts mit CDN64: ein kleines Icon zeigt, wie die Node mit den Servern srv07/srv08 verbunden ist – Blitz für
  QUIC (gefüllt: eigener Port, umrandet: über Port 443), Schloss für den Rückfall HTTPS (TLS über TCP), Stecker, wenn
  kein Server verbunden ist. Der Tooltip nennt den Weg je Server (z. B. „srv07: QUIC · srv08: HTTPS“); der Selbsttest im
  CDN64-Dialog zeigt ihn ebenso. Die API liefert ihn je Server als `via` (`quic`, `quic443`, `tls`).

## 1.17.0 – 2026-10-19

### Geändert
- Neuer Name: Der lokale Reverse-Proxy heißt jetzt **PROXY64** (Menü, Seiten, Dashboard, Ports, Audit, Backup).
  **CDN64** heißt nur noch das Veröffentlichen über die Server srv07/srv08 (Modus 1, 2, 3); aus „CDN64 online“ wird
  „CDN64“ (Spalte, Dialog, Meldungen, Audit). Adressen, API, Einstellungen, Export und Prometheus-Namen bleiben gleich.
- Logo: bis das PROXY64-Logo da ist, steht das Symbol des Moduls an seiner Stelle.

## 1.16.0 – 2026-10-19

### Neu
- Proxy-Hosts: Icons zeigen den Schutz vor Überlastung – ein Tacho, wenn die lokalen Rate-Limits für den Host gelten
  (Klick führt zu den Einstellungen), ein grünes Schild, wenn der Host über CDN64 online läuft und damit auch auf den
  Servern geschützt ist (Blockliste, Grenzen je IP, faire Drossel).

## 1.15.0 – 2026-10-19

### Neu
- Ländersperre auch für Streams (TCP und UDP): Länder sperren oder nur bestimmte zulassen, wie bei den Hosts. Eine
  Änderung gilt sofort, ohne den Stream neu zu starten; bei UDP entscheidet das erste Paket eines Clients.

## 1.14.0 – 2026-10-19

### Neu
- Ländersperre je Host (Proxy, Weiterleitung, TLS durchreichen): Besucher aus bestimmten Ländern sperren oder nur
  bestimmte Länder zulassen. Die Länderlisten kommen täglich von ipv64.net und werden nur für genutzte Länder geladen
  und zwischengespeichert. Private Netze, CGNAT und die Ausnahmen der Blocklisten werden nie gesperrt; hinter
  Cloudflare o. Ä. zählt die echte Client-IP. Abgewiesene erscheinen in Statistik und Zugriffs-Log als „Ländersperre“.
- Blocklisten: Die Auswahl kommt jetzt aus `index.json` von ipv64.net. Neue Listen erscheinen ohne Update von
  Node64, z. B. Gesamtliste ohne Tor, abuse.ch Feodo Tracker, ET Compromised, CINS Army, IPsum, Tor (alle Relays) und
  die Netze von AWS, Google Cloud und Cloudflare. Jede Liste zeigt Lizenz und Beschreibung.

### Geändert
- „IPv64 Gesamtliste“ ist nicht mehr als empfohlen markiert, weil sie Tor enthält; empfohlen ist jetzt die
  Gesamtliste ohne Tor.

## 1.13.1 – 2026-10-19

### Neu
- Hilfe-Links: Ein Fragezeichen an Seiten und Karten öffnet die passende Stelle der Doku auf node64.de (Proxy-Hosts,
  Optionen, Zugriffslisten, Blocklisten, Rate-Limits, Standardseite, Statistik, TLS durchreichen, CDN64 online).

## 1.13.0 – 2026-10-19

### Neu
- Prometheus (`/api/metrics`): je Host Anfragen, Fehler und Abgewiesene seit dem Start sowie der letzten 24 Stunden
  (nach Statusklasse, Bytes), Erreichbarkeit und Antwortzeit des Ziels; CDN64 online mit eingeschalteten Namen,
  Tunnel je Server (verbunden, Laufzeit, Streams), Zustand und Traffic je Name bei ipv64 und Kontingent.
- Node zurücksetzen: CDN64-online-Namen und Tunnel werden vorher bei ipv64 ausgetragen.
- Konfig-Export komplett: Zugriffslisten (mit Benutzern), Blocklisten, Ausnahmen, Limits und Einstellungen des
  Zugriffs-Logs kommen mit; Hosts und Locations zeigen nach dem Import auf die Listen der neuen Node, feste
  Zertifikate werden nach ihren Namen wiedergefunden. Vorhandene Einstellungen bleiben.

## 1.12.0 – 2026-10-19

### Neu
- Dashboard-Karte: Anfragen, Datenverkehr, Fehler 5xx (mit Anteil) und Abgewiesene der letzten 24 Stunden sowie aktive TCP-Streams.

### Behoben
- Statistik: Auswertungen über große Zeiträume konnten mit „disk I/O error“ scheitern (kein Verzeichnis für SQLite-Zwischendateien im Container); Zwischenergebnisse bleiben jetzt im Speicher.
- Darstellung: CDN64-Logo im dunklen Design hell.
- Audit: „Listen jetzt laden“ und „Ziele jetzt prüfen“ (Oberfläche und API) werden protokolliert.

## 1.11.0 – 2026-10-19

CDN64 online: HTTP/3 auch in Modus 1.

### Neu
- Modus 1 (durchreichen) kann HTTP/3: srv07/srv08 lesen den Namen aus dem ersten QUIC-Paket und reichen QUIC roh
  durch den Tunnel zur Node. TLS und HTTP/3 enden wie bei TCP erst in der Node, mit der echten Besucher-Adresse.
  Gilt für Proxy-Hosts mit „HTTP/3“ (Standard).
- Antworten über den Tunnel tragen den Hinweis auf HTTP/3 (Alt-Svc), sobald alle verbundenen Server das
  Durchreichen beherrschen.

### Geändert
- Modus 3 (direkt zum Ziel, ohne Tunnel) gibt es nur noch auf ipv64.net/cdn64; der Einschalt-Dialog zeigt dazu einen
  Hinweis mit Link. Früher in der Node eingeschaltete Modus-3-Namen lassen sich auf Modus 1/2 umstellen oder
  ausschalten.

## 1.10.0 – 2026-10-18

CDN64 online Modus 3.

### Neu
- Modus 3 wählbar: srv07/srv08 gehen ohne Tunnel direkt zum Ziel des Proxy-Hosts (nur, wenn das Ziel öffentlich
  erreichbar ist; sonst Modus 1 oder 2). Wechsel zwischen Modus 3 und 1/2 schaltet den Namen bei ipv64 aus und neu ein.

## 1.9.0 – 2026-10-18

CDN64 online im Betrieb.

### Neu
- Je eingeschaltetem Host die Zahlen der Server im Monat (Traffic, Anfragen, Abweisungen), darunter das
  CDN-Kontingent des Accounts.
- Meldungen über die Benachrichtigungskanäle: Tunnel 3 Minuten zu keinem Server, wieder verbunden, Name bei ipv64
  gesperrt.
- Der Tunnel nimmt Port 443, wenn 7844 gesperrt ist.

### Geändert
- Modus 2: Anfragen zählen nicht mehr als neue Verbindungen (das Verbindungs-Limit hat Besucher sonst gebremst).
- Der Abgleich übernimmt anderswo gewechselte Modi und setzt Modus 2 bei „TLS durchreichen“ auf 1 zurück.

## 1.8.0 – 2026-10-18

CDN64 online Modus 2.

### Neu
- Modus 2 wählbar: TLS endet auf srv07/srv08 (HTTP/1.1, HTTP/2, HTTP/3), Schutz und Anfrage-Limits greifen schon
  dort, die Anfragen kommen mit echter Besucher-IP als HTTPS in der Node an. Zertifikate holen die Server selbst;
  bis dahin wird durchgereicht, ein Wechsel fällt nie aus.
- Knopf *Modus wechseln* und Abzeichen „Modus 1/2“ in der Liste; der Selbsttest schickt eine echte Anfrage.

## 1.7.0 – 2026-10-18

CDN64 online per Klick.

### Neu
- Spalte *CDN64 online* in den Host-Listen: *Einschalten* macht einen Host über srv07/srv08.cdn64.de aus dem
  Internet erreichbar (IPv4 und IPv6, ohne offene Ports).
  - Ablauf im Fenster: Account prüfen, Tunnel anmelden und aufbauen, Namen bei ipv64 einschalten (DNS), Selbsttest
    über das Internet. Jeder Schritt mit Ergebnis und Fehlertext mit Abhilfe.
  - Modus 1 (TLS wird durchgereicht, das Zertifikat bleibt in der Node); auf Wunsch gleich ein Online-Healthcheck.
  - Abzeichen je Server (verbunden, über den anderen Server, kein Tunnel), „gesperrt“, Selbsttest, weitere Namen
    einschalten, Ausschalten.
  - Ausschalten stellt den DNS zurück; mit dem letzten Namen wird der Tunnel abgemeldet. Gelöschte Hosts und
    entfernte Namen trägt der Abgleich (jede Minute) bei ipv64 aus.
  - Hinweise bei gesperrtem UDP (Tunnel über TCP) und zu kleinem UDP-Puffer des Docker-Hosts.
- Im Heimnetz beantwortet DNS64 eingeschaltete Namen mit der Adresse der Node (geteilter DNS).
- API: `POST /api/cdn64/online/tunnel`, `POST|DELETE /api/cdn64/hosts/{id}/online`,
  `POST /api/cdn64/hosts/{id}/online/test`; `GET /api/cdn64/online` zeigt zusätzlich Namen, Kontingent und
  UDP-Puffer.

## 1.6.0 – 2026-10-17

Abweisungen in Statistik und Log, gleiches Diagramm wie auf dem Dashboard.

### Neu
- Jede Abweisung wird erfasst: Blocklisten, Sperren, Limits, Zugriffslisten und Exploit-Sperre.
  - Sie steht immer im Zugriffs-Log (Reiter *Zugriffe*), mit Grund und Filter „Abgewiesen“, auch ohne eingeschaltetes Zugriffs-Log; gebremst auf einen Eintrag je Adresse und Grund alle 10 Sekunden.
  - Verbindungen, die vor der ersten Anfrage getrennt werden, erscheinen als „Verbindung abgewiesen“.
  - Überlastung (Verbindungen insgesamt voll, Ziel ausgelastet) und Sperren stehen als Warnung im Log der Node.
- Kachel „Abgewiesen“ (24 Stunden) auf dem Reiter *Zugriffe*.

### Geändert
- Das Diagramm in der Übersicht der Proxy-Hosts und das auf dem Dashboard sind jetzt dasselbe: Anfragen und Abgewiesene gestapelt, Datenverkehr als Linie.
- Reiter *Zugriffslisten*: ipv64-Blocklisten und Schutz vor Überlastung nebeneinander, die eigenen Zugriffslisten darunter.

## 1.5.0 – 2026-10-17

Schutz vor Überlastung, ipv64-Blocklisten, Verkehr in der Übersicht.

### Neu
- Schutz vor Überlastung (Reiter *Zugriffslisten*), wie beim HAProxy, mit Standardwerten eingeschaltet:
  - je IP (IPv6 je /64): 200 gleichzeitige Verbindungen, 20 neue Verbindungen je Sekunde (kurzzeitig 200),
    50 Anfragen je Sekunde (kurzzeitig 500, darüber 429);
  - insgesamt 10.000 Verbindungen; je Proxy-Host 200 gleichzeitige Anfragen an das Ziel, weitere warten bis
    10 Sekunden, dann 503 (WebSockets zählen nicht);
  - wer in einer Minute 300-mal abprallt, wird 10 Minuten schon beim Verbindungsaufbau abgewiesen; gesperrte
    Adressen stehen in der Karte und lassen sich freigeben;
  - ausgenommen: Heimnetz (abschaltbar), vertrauenswürdige Proxys der Hosts und die Ausnahmen der Blocklisten;
    je Host unter *Erweitert* „Ohne Limits je IP“;
  - gilt auch für TCP-Streams; API `/api/cdn64/limits`.
- ipv64-Blocklisten per Schalter, abgewiesen vor TLS; API `/api/cdn64/blocklists`.
- Karte *Verkehr* in der Übersicht der Proxy-Hosts (Anfragen nach 2xx–5xx, Datenmenge, 24 Stunden bis 30 Tage).
- Die Tabelle zeigt, ob ein Healthcheck genau dieses Ziel überwacht (lokal oder ipv64/andere Node).

## 1.4.1 – 2026-10-16

### Geändert
- Die Zertifikate haben einen eigenen Menüpunkt *Zertifikate* im Kern und gehören nicht mehr zu CDN64.
  - Der Reiter *SSL-Zertifikate* führt dorthin.
  - Die alten Adressen unter `/cdn64/certificates` und `/cdn64/dns-accounts` leiten weiter.
- Zertifikate werden auch erneuert, wenn CDN64 aus ist.

## 1.4.0 – 2026-10-15

Zertifikate auch bei anderen DNS-Anbietern, DNS-Einträge bei ipv64 beim Anlegen.

### Neu
- DNS-Zugänge für Let's Encrypt per DNS-01 bei anderen Anbietern, auch für Wildcards:
  - Anbieter: Cloudflare, Hetzner, netcup, INWX, IONOS, deSEC, Duck DNS, Porkbun, GoDaddy, DigitalOcean, Gandi, OVHcloud.
  - Die Zugangsdaten liegen verschlüsselt und werden nie wieder angezeigt; beim Bearbeiten bleiben leere Felder unverändert.
  - Ein Zugang, den ein Zertifikat benutzt, lässt sich nicht löschen.
- Neuer Weg „Anderer DNS-Anbieter“ beim Anfordern; ebenso im Host-Formular bei „Zertifikat gleich mit anfordern“.
- DNS-Eintrag bei ipv64 beim Anlegen eines Hosts:
  - CNAME (z. B. auf die DynDNS-Domain) oder A/AAAA, für jede Domain des Hosts im ipv64-Account;
  - vorhandene Einträge bleiben unverändert;
  - in der API über `create_dns_record`.

## 1.3.0 – 2026-10-15

Custom Locations, Zugriffslisten, erweiterte Optionen, Statistik und Zugriffs-Log.

### Neu
- Custom Locations: Pfade eines Proxy-Hosts mit eigenem Ziel (z. B. /api auf einen anderen Dienst).
  - Optional mit anderem Pfad beim Ziel, eigener WebSocket-Einstellung und eigener Zugriffsliste.
  - Der längste passende Pfad gewinnt.
- Zugriffslisten:
  - Benutzer mit Passwort (nur als bcrypt-Hash gespeichert) und IP-Regeln (allow/deny, erster Treffer gilt, sonst gesperrt).
  - „Beides nötig“ oder „eine Bedingung genügt“; die Anmeldung lässt sich an das Ziel weiterreichen.
  - Nach 10 falschen Anmeldungen in 5 Minuten ist die IP 15 Minuten gesperrt; die Sperre steht im Audit.
  - Gilt für Proxy-Hosts, Locations und Weiterleitungen.
- Erweitert:
  - Kopfzeilen zum Ziel und zum Besucher setzen bzw. entfernen;
  - Host-Kopf (Name des Besuchers, des Ziels oder fester Wert);
  - Timeout zum Ziel, Upload-Grenze (413), nicht puffern, gzip für Text-Antworten;
  - vertrauenswürdige Proxys mit Cloudflare-Vorlage für die echte Client-IP.
- Statistik: Anfragen je Host und Stunde (2xx–5xx, Datenmenge) über 90 Tage. Die Liste zeigt die Anfragen der letzten 24 Stunden.
- Zugriffs-Log je Host einschaltbar:
  - Reiter „Zugriffe“ mit Filter nach Host, Status und Suche;
  - Aufbewahrung 1–90 Tage, Client-IPs auf Wunsch gekürzt;
  - eigene Datei cdn64.db.
- „Healthcheck für dieses Ziel anlegen“ bei Proxy-Hosts, TLS durchreichen und TCP-Streams (braucht das Modul Healthchecks).
- API: Zugriffslisten, Zugriffs-Log, Statistik, Einstellungen, Healthcheck anlegen.

## 1.2.0 – 2026-10-15

Weiterleitungen, 404-Hosts, Streams, TLS durchreichen und die Standardseite.

### Neu
- Weiterleitungen (Redirection Hosts):
  - Domains auf eine andere Domain, optional mit Port und Pfad;
  - Code 301, 302, 303, 307, 308 oder 300;
  - Schema wie die Anfrage oder fest;
  - Pfad und Abfrage mitnehmen;
  - SSL-Optionen wie bei Proxy-Hosts.
- 404-Hosts: Domains, die bewusst mit „nicht gefunden“ antworten, auch per HTTPS.
- Streams:
  - ein Port (TCP und/oder UDP) wird roh an ein Ziel weitergereicht;
  - bei TCP optional mit TLS-Abschluss über ein Zertifikat der Verwaltung;
  - Ports werden gegen die anderen Teile geprüft; ist einer belegt, steht der Grund am Stream;
  - Zähler für Verbindungen und Datenmenge, Erreichbarkeit des Ziels.
- TLS durchreichen: Ein Name auf Port 443 geht roh an einen Dienst mit eigenem Zertifikat, ohne Entschlüsselung hier. Alle anderen Namen auf 443 bleiben bei Node64.
- Standardseite für unbekannte Namen: 404, Verbindung schließen, Weiterleitung oder eigene HTML-Seite.
- Export/Import enthält jetzt auch die Streams.

## 1.1.0 – 2026-10-15

Reiter SSL-Zertifikate.

### Neu
- Liste aller Zertifikate:
  - Namen, Weg, Aussteller;
  - Ablauf als Pille (grün, ab 30 Tagen vor Ablauf gelb, ab 7 Tagen rot) mit Datum;
  - benutzt von welchen Hosts, automatische Erneuerung an/aus;
  - Erneuern, Herunterladen (ohne Schlüssel), Löschen (benutzte nur nach Rückfrage);
  - der laufende Schritt beim Abruf, die Seite lädt dabei selbst neu.
- Zertifikat anfordern bei Let's Encrypt:
  - automatisch (ipv64, wenn alle Namen im Account liegen, sonst HTTP-01) oder gezielt per ipv64 DNS-01 (auch Wildcards);
  - Alias über ipv64 für fremde Domains, mit Vorschau der nötigen CNAME-Einträge;
  - per HTTP-01;
  - Testumgebung wählbar.
- Eigenes Zertifikat hochladen (Datei oder hineinkopieren).
- Let's-Encrypt-Konto: Mail und Zustimmung zu den Nutzungsbedingungen.
- Host-Formular: „Neues Zertifikat gleich mit anfordern“; in der API über `request_certificate` beim Anlegen oder Ändern eines Hosts.

## 1.0.0 – 2026-10-15

Erste Version des Reverse-Proxys, angelehnt an den Nginx Proxy Manager.

### Neu
- Proxy-Hosts mit mehreren Domains (auch Wildcards) und Ziel per http oder https, Name oder IP, Port.
- Optionen je Host:
  - WebSockets;
  - Block Common Exploits (Regeln wie beim NPM, dazu Sperre für .git und .env);
  - Cache Assets: statische Dateien im Speicher, höchstens 64 MB.
- SSL je Host:
  - Zertifikat aus der Zertifikatsverwaltung (passend nach Namen oder fest gewählt) oder nur HTTP.
  - HTTPS erzwingen, HSTS (auch für Subdomains), HTTP/2, HTTP/3 (QUIC), mindestens TLS 1.2 oder 1.3.
- Erreichbarkeit der Ziele: jede Minute geprüft, in der Liste mit Antwortzeit bzw. „nicht erreichbar seit …“.
- Ein nicht erreichbares Ziel bekommt eine neutrale Seite „502“. Schleifen (Ziel zeigt auf den Proxy selbst) werden erkannt.
- Zähler je Host seit dem Start: Anfragen, Fehler, gesperrte Anfragen.
- Dashboard-Karte, Audit für alle Änderungen, lokale API unter `/api/cdn64/…`.
- Export und Import der Hosts.
- Ausgeschaltet läuft nichts: keine Routen, keine Prüfung, kein Cache, und der gemeinsame Eingang schließt seine Ports.
