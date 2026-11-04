# Datenschutzerklärung ipv64.net – Entwurf für die neuen Dienste (Stand 2026-11-04)

Entwurf für `datenschutz.php` (Verantwortlicher bleibt Prox IT UG). Grundlage: Code-Stand Container `5bb54ab`
(Fundstellen im Abschnitt „Belege“). **Keine Rechtsberatung** – vor dem Hochladen von Dennis freigeben, im Zweifel
anwaltlich prüfen lassen. `[[…]]` = Angabe fehlt bzw. Entscheidung nötig (siehe „Offene Punkte“).

---

## A. CDN64 (ersetzt den bisherigen Abschnitt)

**CDN64 (srv07.cdn64.de, srv08.cdn64.de, srv09.cdn64.de, srv10.cdn64.de)**

*Art und Zweck der Verarbeitung:* Nutzer von IPv64.net können Domains über unser Content Delivery Network CDN64
erreichbar machen. Ruft jemand eine solche Domain auf, laufen die Verbindung und die IP-Adresse der aufrufenden Person
über unsere Server in Nürnberg (srv07, srv10) und Falkenstein (srv08, srv09). Dabei verarbeiten wir:

- die **IP-Adresse** der aufrufenden Person, um die Verbindung weiterzuleiten, Missbrauch abzuwehren (Grenzen je
  IP-Adresse bzw. je IPv6-/64-Netz, öffentliche Sperrlisten von IPv64.net) und die vom Domain-Inhaber eingestellten
  Erlauben-/Sperrlisten anzuwenden. Diese Angaben werden nur im Arbeitsspeicher gehalten und in der Regel spätestens
  zwei Minuten nach der letzten Verbindung verworfen; gesperrte Adressen werden bis zur nächsten Übermittlung der Summen
  (normalerweise jede Minute) gezählt, übermittelt wird nur ihre Anzahl,
- den **TLS-Fingerabdruck (JA4)** des aufrufenden Programms, um bekannte Angriffswerkzeuge zu erkennen und – je nach
  Einstellung des Domain-Inhabers – zu sperren. Gespeichert werden nur die häufigsten Fingerabdrücke je Domain und Tag,
  ohne IP-Adresse, für 35 Tage,
- in Modus 2 und 3 **Pfad und User-Agent** der Anfrage, um bekannte Angriffsmuster (Web Application Firewall) zu
  erkennen; Treffer werden nur gezählt,
- den Namen der aufgerufenen Domain sowie Datenmengen und Anzahl der Verbindungen, Anfragen und abgewehrten Zugriffe,
  nur als Summen je Domain und Tag ohne IP-Adressen, für das Kontingent und die Statistik des Domain-Inhabers
  ([[Frist: siehe Offene Punkte 2]]),
- die übertragenen Inhalte: In Modus 1 bleiben sie bis zum Dienst des Domain-Inhabers verschlüsselt, unsere Server
  können sie nicht lesen. In Modus 2 und 3 endet die Verschlüsselung auf unseren Servern; Inhalte werden dort nur zur
  Weiterleitung im Arbeitsspeicher verarbeitet. Schaltet der Domain-Inhaber in Modus 3 den Zwischenspeicher (Cache) ein,
  werden öffentlich zwischenspeicherbare Antworten (z. B. Bilder oder Skripte, nie Antworten mit Cookies oder als privat
  gekennzeichnete) auf den Servern abgelegt und nach der vom Domain-Inhaber gewählten Dauer gelöscht (Standard
  10 Minuten, höchstens 24 Stunden).

Eine Sperre nach Herkunftsland wendet nicht CDN64 an, sondern die Node64-Installation des Domain-Inhabers mit einer
lokalen Länderdatenbank; dabei werden keine Daten an Dritte übermittelt.

Der Dienst des Domain-Inhabers erhält die IP-Adresse der aufrufenden Person (über Node64 bzw. in den Kopfzeilen
X-Forwarded-For und X-Real-IP), damit er seinen Dienst betreiben und absichern kann; beim Portmapper sieht er nur die
Adresse unserer Server. Für die Verarbeitung in seinem Dienst ist der Domain-Inhaber verantwortlich.

*Rechtsgrundlage und berechtigtes Interesse:* unverändert (Art. 6 Abs. 1 lit. b bzw. lit. f DSGVO; zusätzlich: Schutz
der Dienste vor Angriffen).

*Zertifikate, Empfänger, Missbrauch:* unverändert.

*Speicherdauer:* IP-Adressen aufrufender Personen werden nicht gespeichert, sondern nur während der Verbindung und kurz
danach im Arbeitsspeicher gehalten. Die Systemprotokolle der Server werden nach 14 Tagen gelöscht. JA4-Fingerabdrücke je
Domain und Tag: 35 Tage. Vom Domain-Inhaber eingetragene Erlauben-/Sperrlisten werden 14 Tage nach dem Entfernen seines
Tunnels gelöscht.

---

## B. Healthchecks

*Art und Zweck der Verarbeitung:* Mit den Healthchecks überwachen Nutzer Webseiten, Server und Dienste. Wir speichern
die Einstellungen der Checks (z. B. Ziel-Adresse, Name, Beschreibung) und deren Messergebnisse (Zustand, Antwortzeit,
Fehlergrund). Gemessen wird von unseren Servern hc-srv01 (Falkenstein) und hc-srv02 (Nürnberg) und ggf. von der
Node64-Installation des Nutzers. Bei Push-Checks speichern wir zur Fehlersuche die IP-Adresse, von der der Push kam.

*Rechtsgrundlage:* Art. 6 Abs. 1 lit. b DSGVO (Erbringung des Dienstes).

*Empfänger:* Die Server werden bei der Hetzner Online GmbH, Gunzenhausen, als Auftragsverarbeiter betrieben.

*Speicherdauer:* Einzelmessungen 2 Tage, Stundenwerte 90 Tage, Ereignisse 1 Jahr, [[Tageswerte, Störungen,
Versandprotokoll: Frist siehe Offene Punkte 2]]. Gelöschte Checks werden nach 90 Tagen endgültig entfernt. Mit dem
Konto werden alle Daten gelöscht.

## C. Benachrichtigungen

*Art und Zweck:* Für Benachrichtigungen hinterlegen Nutzer Kanäle (z. B. E-Mail, SMS, Telegram, Discord, Slack,
Microsoft Teams, Pushover, ntfy, Gotify, Matrix, Webhook, IPv64 App). Zugangsdaten der Kanäle (Tokens, Passwörter)
speichern wir verschlüsselt. Eine Nachricht enthält den Namen des Checks, seinen Zustand und den Fehlergrund.

*Empfänger:* Nachrichten gehen an den vom Nutzer gewählten Dienst, z. B. Telegram (Telegram Messenger Inc.),
Pushover (Superblock LLC, USA), ntfy.sh, matrix.org oder einen vom Nutzer angegebenen Server. Für diese Anbieter gelten
deren Datenschutzbestimmungen; einige haben ihren Sitz außerhalb der EU (Drittland). Die Übermittlung erfolgt auf
Veranlassung des Nutzers (Art. 49 Abs. 1 lit. b DSGVO bzw. Art. 6 Abs. 1 lit. b DSGVO). E-Mails versenden wir über
[[Mailserver/Anbieter]], SMS über [[SMS-Anbieter]].

## D. Node64 und die Verknüpfung mit IPv64.net

*Art und Zweck:* Node64 ist ein Container, den Nutzer selbst betreiben; was er lokal speichert, bleibt beim Nutzer.
Verknüpft der Nutzer Node64 mit seinem Konto, übermittelt die Installation Name, Standort-Bezeichnung, Version,
Zeitzone, eingeschaltete Module sowie die Messergebnisse und Ereignisse ihrer Checks; wir speichern zusätzlich die
zuletzt verwendete IP-Adresse der Installation, um Verbindungsprobleme und Missbrauch zu erkennen.

Zur Prüfung auf Updates ruft Node64 regelmäßig (stündlich) eine Datei auf ipv64.net ab; dabei werden die IP-Adresse
und die Versionsnummer übermittelt ([[ggf. Hinweis auf Logs des Webservers, siehe Offene Punkte 4]]).

*Rechtsgrundlage:* Art. 6 Abs. 1 lit. b DSGVO; beim Update-Abruf Art. 6 Abs. 1 lit. f DSGVO (sichere, aktuelle
Software).

*Speicherdauer:* bis der Nutzer die Installation im Portal entfernt oder das Konto löscht [[bzw. Frist für die
IP-Adresse, siehe Offene Punkte 2]].

## E. Honeypot64 und die IPv64-Bedrohungsdaten

*Art und Zweck:* Nutzer können mit Node64 Fallen-Dienste (Honeypot-Sensoren) betreiben. Sensoren melden Zugriffe auf
diese Fallen an IPv64.net: die IP-Adresse der zugreifenden Stelle, Dienst, Port, Zeitpunkt und Anzahl sowie
Merkmale des Angriffs (z. B. versuchte Benutzernamen und Passwörter, aufgerufene Pfade, User-Agent, TLS-Fingerabdruck).
Wir werten diese Meldungen aus, um Angreifer zu erkennen und unsere Nutzer davor zu schützen.

Veröffentlicht werden:
- **IPv64-Blocklisten (v64):** IP-Adressen, die von mehreren unabhängigen Konten gemeldet wurden,
- **Listen häufiger Angriffsmerkmale** (Benutzernamen, Passwörter, User-Agents, Pfade, Fingerabdrücke), nur wenn sie von
  mehreren unabhängigen Konten gemeldet wurden,
- die **IP-Auskunft** (Bewertung, Listen, Angriffsarten, Ports, Zeitraum, Land/Netzbetreiber einer Adresse) – nie,
  welcher Sensor oder welches Konto gemeldet hat,
- eine **Live-Karte** mit auf /24 (IPv4) bzw. /48 (IPv6) gekürzten Adressen.

Meldet ein Sensor ohne Konto (anonym), speichern wir seine IP-Adresse nur am Sensor-Eintrag und leeren sie 30 Tage
nach seiner letzten Meldung.

**Passwort-Check:** Das eingegebene Passwort verlässt den Browser nicht. Der Browser berechnet einen Hash und sendet nur
dessen erste 5 Zeichen; wir speichern die Anfrage nicht.

**Frühwarnung:** Nutzer können eigene Netze (IP-Bereiche) und ihre DynDNS-Adressen überwachen lassen; Treffer werden
mit Zeitpunkt und Adresse gespeichert und per E-Mail an die Adresse des Kontos gemeldet.

*Rechtsgrundlage:* gegenüber den Nutzern Art. 6 Abs. 1 lit. b DSGVO; gegenüber den gemeldeten Stellen Art. 6 Abs. 1
lit. f DSGVO – unser berechtigtes Interesse und das unserer Nutzer an der Sicherheit von Netzen und Diensten
(Erwägungsgrund 49 DSGVO). Gemeldet werden nur Zugriffe auf Fallen-Dienste, die kein legitimer Nutzer aufruft.

*Widerspruch/Austragung:* Wer meint, zu Unrecht gelistet zu sein, kann über die IP-Auskunft eine Freigabe beantragen
oder sich an abuse@ipv64.net wenden.

*Speicherdauer:* vollständige IP-Adressen in den Meldungen 90 Tage, danach auf /24 bzw. /48 gekürzt bis 24 Monate;
Bewertungen 14 Tage; Treffer der Frühwarnung 90 Tage; Freigabe-Anträge 365 Tage (E-Mail-Adressen anonymer Antragsteller
90 Tage nach der Entscheidung); versuchte Zugangsdaten [[Frist siehe Offene Punkte 1]].

## F. IPv64 App (Push-Benachrichtigungen)

*Art und Zweck:* Für Push-Nachrichten an die IPv64 App übermitteln wir die Nachricht über den Dienst SecNtfy
([[Betreiber, Sitz, Drittland? siehe Offene Punkte 3]]). Titel und Text sind Ende-zu-Ende mit dem Schlüssel des Geräts
verschlüsselt; SecNtfy erhält nur den Geräte-Token und die verschlüsselte Nachricht.

---

## Offene Punkte (Entscheidung Dennis)

1. **Honeypot: versuchte Zugangsdaten** (`hp_samples_creds`, Benutzername/Passwort im Klartext) haben **keine
   Löschfrist**. Empfehlung: 365 Tage (wie die Datenbasis des Passwort-Checks) – kleiner Job in `honeypot_cleanup.php`.
   Versuchte Passwörter sind meist keine personenbezogenen Daten, können aber welche enthalten (z. B. echte Namen).
2. **Tabellen ohne Löschjob:** `cdn64o_traffic`, `cdn64o_events` (CDN64-Statistik), `hc2_daily`, `hc2_incidents`,
   `hc2_deliveries` (Healthchecks), `node64_nodes.last_ip`, `weekly_report_log`. Empfehlung: Statistik/Tageswerte und
   Störungen 13 Monate, Versandprotokoll 90 Tage, `last_ip` nur solange die Node verknüpft ist. Alternativ in der
   Erklärung „bis zur Löschung des Kontos“ schreiben.
3. **SecNtfy:** Wer betreibt `api.secntfy.app`, wo (EU/Drittland), Push-Weg über Apple/Google? Ggf. AV-Vertrag.
4. **Logs:** Mailserver/SMS-Anbieter (stehen in `dbconnect.php`, das ich nicht öffne); Aufbewahrung der nginx-Logs der
   hubs (mit IP-Adressen) und der Webserver-Logs von ipv64.net (Update-Abruf).
5. **Wochenbericht:** erst aufnehmen, wenn der Versand eingeschaltet wird (`send.on`).

## Belege (Code)

CDN64: `deploy/sql/cdn64_servers.sql`, `internal/cdnedge/guard.go:222`, `ja4.go:31,54-71`, `waf.go:8-31`,
`route.go:179-262`, `api.go:95,360`, `cache.go:20-22`, `deploy/web/api_v2_cdn64o.php:496,524`,
`bots/cdn64_orphans.php:27-75`, `deploy/server/setup-edge.sh:103-108`, `internal/cdn64/geo.go:21-24`.
Healthchecks: `internal/hub/store/store.go:29-30`, `aggregate.go:188-200`, `orders.go:164-170`, `hc2_schema.sql`.
Kanäle: `internal/notify/channel.go:22-125`, `senders.go:315,391`, `internal/secrets/secrets.go`.
Node64: `internal/wire/wire.go:221-230`, `deploy/sql/node64_nodes.sql`, `internal/update/update.go:20,48`.
Honeypot64: `internal/honeypot/report_types.go`, `bots/honeypot_cleanup.php`, `honeypot.sql:134-142`,
`api_v2_threat.php:8-13`, `honeypot/password.php`, `honeypot_h5.sql`, `honeypot_h3_release.sql`.
App: `internal/notify/secntfy.go:19-31`.
