# Änderungen – PROXY64

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
