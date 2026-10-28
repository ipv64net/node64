# Node64 – Modul DynDNS (Planung)

Stand 2026-10-14. Abgestimmt mit Dennis, Umsetzung beginnt mit D1.

Rahmen (entschieden, Dennis 2026-10-14):
- Kein Nachbau der Domain-Verwaltung von ipv64. Node64 ist ein **DynDNS-Updater**: der Nutzer wählt, welche Domains/Records von dieser Node aus aktuell gehalten werden.
- IPv4 und IPv6, IP automatisch ermitteln. Gemeldet wird die **öffentliche Adresse des Anschlusses** (Router), nie die interne Container-Adresse.
- IPv6-Präfix-Update, auch **nur Präfix** (für reine IPv6-Anschlüsse).
- Immer den **sichersten möglichen Token**: Record-Token vor Domain-Token. Der Account-Token wird nicht benutzt.
- Update **nur bei Änderung** der IP-Adresse.
- Modul optional: ausgeschaltet keine Goroutinen, keine Tabellen, keine Last.
- **Nur im Container.** Auf der Webseite und am hub wird nichts geändert.
- Lokales Protokoll: wann welche IP geprüft wurde, wann was mit welchem Ergebnis aktualisiert wurde. Update-Limit des Accounts anzeigen.

---

## Was ipv64 heute schon bietet (Bestandsaufnahme Webseite)

**Update-Endpunkt `update.php`** (auch `/nic/update`):
- Token per `key=`, Bearer oder Basic Auth (24 oder 32 Zeichen). Reihenfolge der Prüfung:
  1. Account-Token: `users.updatehash`.
  2. Domain-Token: `subdomains.update_hash`.
  3. Record-Token: `subdomain_records.record_key`.
- Wirkung je Token:
  - Record-Token: nur dieser Name. A und AAAA mit diesem Präfix gleichzeitig.
  - Domain-Token: die Zone samt Unterhosts (`praefix=`).
- Parameter:
  - `ipv4=` / `ipv6=` (je auch `auto`), `praefix=` für den Host.
  - `ipv6prefix=` mit `/len` oder `auto`. Achtung: `prefix=` ist ein Alias für das IPv6-Präfix, nicht der Host.
  - `onlyprefix` (Flag): nur das Präfix wird aktualisiert.
  - `output=full`: Antwort als JSON.
- **Präfix-Update:**
  - Setzt `subdomains.ipv6prefix`.
  - Ändert alle AAAA-Records der Zone, deren Inhalt mit `::` beginnt (Interface-ID, z. B. `::1:2:3:4`).
  - Gilt immer für die ganze Zone, auch mit Record-Token.
  - `ipv6prefix=auto` funktioniert nur, wenn die Anfrage über IPv6 kommt.
- **Antwort (JSON):**
  - Felder: `status`, `info` (`good`, `nochg`, `badauth`, `nohost` …), `ip.ipv4`, `ip.ipv6`, `ipv6prefix`.
  - Bei geändertem Präfix fehlt `status`.
  - `output=min` liefert bei Präfix-Updates immer `911`, deshalb immer `full` verwenden.
- **Limit:**
  - Jede verarbeitete IP zählt auf `users.dyndns_updates`, auch `nochg`. Dual-Stack zählt 2.
  - Das Limit ist `user_class.dyndns_update_limit` (0 = unbegrenzt). Bei Überschreitung kommt 429 „Updateintervall overcommited“.
  - Der Zähler wird täglich durch `bots/reset_counter.php` zurückgesetzt.
- **Cooldown:** ab 3 `logging`-Einträgen des Accounts in 10 s kommt 429 („abuse“). Es zählen auch andere Log-Einträge, z. B. Aufrufe der API v1.
- „good“ heißt nur „vorgemerkt“: der DNS-Bot schreibt die Records nach 2–5 s.

**IP-Ermittlung:**
- `ipv4.ipv64.net` / `ipv6.ipv64.net` sind Single-Stack-Namen.
- `ipcheck.php?ipv4` bzw. `?ipv6` liefert die IP als reinen Text, leer bei falscher Familie, ohne Logging.
- Zusätzlich gibt es `update.php?howismyip` (JSON) und API v2 `GET /ip`.

**API v2** (Header `Authorization: Bearer <API-Key>`):
- `GET /me`: `usage.dyndns_updates_24h {used, limit}`.
- `GET /domains?kind=dyndns|own`: das Domain-Objekt enthält `update_token` und `ipv6_prefix`.
- `GET /domains/{domain}/records`: das Record-Objekt enthält `token` (Record-Token) und `prefix`.
- `GET /me/logs`.
- Den Account-Token gibt v2 nicht heraus. Das passt, wir brauchen ihn nicht.

---

## Grundentwurf

**Ablauf je Prüfrunde** (Standard alle 5 min, einstellbar 1–60 min):
1. Öffentliche IPv4 über `ipv4.ipv64.net` ermitteln.
2. Öffentliche IPv6 und IPv6-Präfix über `ipv6.ipv64.net` ermitteln.
3. Jedes ausgewählte Ziel vergleichen: Soll-IP gegen zuletzt erfolgreich gemeldete IP **und** gegen das, was der ipv64-Nameserver tatsächlich ausliefert (direkte DNS-Abfrage).
   - Stimmt beides, gibt es keinen Aufruf. Das spart Limit, denn `nochg` würde mitzählen.
4. Bei Abweichung eine Aktualisierung in die **Warteschlange**: höchstens 1 Aufruf je 5 s (Cooldown 3/10 s), bei 429 Pause mit wachsendem Abstand.
5. Jede Prüfung und jeden Aufruf ins lokale Protokoll schreiben.

**„Router-IP statt Container-IP“:**
- **IPv4:** Hinter NAT sieht ipv64 automatisch die WAN-Adresse des Routers. Die Container-Adresse (172.17.x) taucht nie auf, weil wir nie lokale Interfaces auslesen, sondern immer von außen fragen.
- **IPv6:** Es gibt kein NAT. Was ipv64 sieht, ist die Adresse von Host oder Container. Deshalb drei Modi je Ziel:
  - *Adresse dieses Hosts:* AAAA = die von außen gesehene Adresse. Sinnvoll mit `network_mode: host`.
  - *Nur Präfix:* das ermittelte /64-Präfix melden (`onlyprefix`). Die Geräte-Records tragen bei ipv64 nur ihre Interface-ID (`::1:2:3:4`). Das ist der Normalfall für Geräte im LAN.
  - *Präfix + Interface-ID (lokal):* Node64 setzt aus dem ermittelten Präfix und einer je Ziel eingetragenen Interface-ID die volle Adresse zusammen und meldet sie mit dem Record-Token. Wirkt nur auf diesen Record, anders als das zonenweite Präfix-Update. Ist zugleich das Mittel gegen wechselnde Privacy-Adressen.
  - *Interface (nur `network_mode: host`):* stabile globale Adresse direkt vom Interface. Temporäre Privacy-Adressen (Flag `temporary`), ULA und Link-Local werden übersprungen.
  - *Fest / aus.*
- Hat der Container kein IPv6 (Docker-Bridge ohne IPv6), zeigt die Oberfläche das klar an, mit Hinweis auf `network_mode: host` oder IPv6 in Docker.
- DS-Lite: Die IPv4 ist dann eine geteilte Adresse des Providers. Je Ziel lässt sich IPv4 abschalten. Ein automatischer DS-Lite-Hinweis ist von innen nicht zuverlässig möglich (in D2 geprüft), deshalb nur ein Hilfetext.

**Tokens und Zugang:**
- **Mit API-Key (Standard, bequem):**
  - Der Nutzer trägt einmal einen ipv64-API-Key ein. Node64 listet Domains und Records, der Nutzer hakt an, was aktualisiert werden soll.
  - Node64 holt je Auswahl den **Record-Token**. Nur wo kein Record passt (z. B. reines Präfix-Update der Zone), nimmt es den Domain-Token.
  - Der API-Key dient danach nur noch für Limit-Anzeige, Auswahl-Aktualisierung und Token-Erneuerung. Die eigentlichen Updates laufen nie mit dem API-Key.
- **Ohne API-Key (manuell):** Domain, Host und Record- oder Domain-Token von Hand eintragen. Volle Funktion, nur ohne Liste und ohne Limit-Anzeige.
- Alle Tokens und der API-Key liegen verschlüsselt (secrets.Box, wie Kanal-Geheimnisse), in Logs maskiert und in der Oberfläche nur maskiert sichtbar.

**Speicherung** (Migrationsbereich `dyndns`, Tabellen `dyn_*`):
- `dyn_targets`:
  - Domain, Host, Record-ID, Token-Art (record/domain), Token (verschlüsselt).
  - Modus IPv4 (auto/fest/aus), Modus IPv6 (host/präfix/fest/aus).
  - Aktiv, zuletzt gemeldete v4/v6, letzter Erfolg, letzter Fehler.
- `dyn_checks`: jede IP-Prüfung (Zeit, Familie, Quelle, Ergebnis-IP oder Fehler, Dauer, geändert ja/nein). Aufbewahrung einstellbar, Standard 30 Tage, etwa 600 KB im Monat.
- `dyn_updates`: jeder Aufruf bei ipv64 (Zeit, Ziel, gesendete IPs/Präfix, HTTP-Code, `status`/`info`, Dauer, Auslöser auto/manuell). Aufbewahrung Standard 365 Tage.
- Einstellungen in `settings`: `dyndns.interval`, `dyndns.apikey` (verschlüsselt), `dyndns.keep_checks`, `dyndns.keep_updates`, Quellen.

---

## Stand (2026-10-14, nach D6)

- D1 bis D6 umgesetzt und auf der Testbox live erprobt (IPv4-Update im Testaccount, echter IP-Wechsel erkannt und gemeldet).
- Abweichung vom Plan: Der API-Key liegt **zentral in den Container-Einstellungen** (Paket `internal/ipv64api`), alle Module bedienen sich daran; Name und Ablaufdatum werden angezeigt.
- Ergänzt: Auswahl je Name direkt in der Liste, Ziele unter ihrer Domain gruppiert, CGNAT/DS-Lite-Hinweis über die ersten Stationen, Schonfrist 3 min nach einem Update, Pause bei `ignore`/`cdn` in der Antwort.
- D6: Meldungen (Adresswechsel, Fehler/Pause nur bei automatischen Läufen, Limit höchstens einmal am Tag) über die lokalen Standardkanäle, auch bei verknüpfter Node; in der Ruhezeit verworfen. Lokale API `/api/dyndns/*` (OpenAPI 1.2.0), Export/Import ohne Tokens, README.
- IPv6 live abgenommen (Dev-Node, node64test.blog.ipv64.net): Adresse dieses Hosts, Präfix + Interface-ID und nur Präfix je mit HTTP 200, AAAA am Nameserver geprüft, zweite Runde ohne Aufruf. Dabei behoben: bei fehlgeschlagener Prüfung wird die alte Adresse nicht mehr gemeldet.
- Offen: Dashboard-Kachel (Dashboard ist auf Healthchecks zugeschnitten), (erledigt) DynDNS-Meldungen über ipv64-Mail/-SMS laufen seit 2026-10-14 direkt über die API v2 (`POST /hc2/channels/{id}/send`, zentraler API-Key), nicht über die hubs; Ende-zu-Ende mit dem Testaccount abgenommen (Mail angekommen, Design passt).

## Cluster (2026-10-28, DynDNS 1.5.0)

- Bereich `dyndns/config` (Standard aus): Namen samt Token, Einstellungen und bevorzugte Node gehen an die Nodes, bei
  denen der Bereich ebenfalls an ist; Laufzeitstand (gemeldete Adressen, Fehler, Pause, DNS-Stand) und Verlauf bleiben
  je Node. Exakt gleiche Namen beider Nodes werden eins, derselbe Name mit anderer Einstellung bleibt je Node.
- Nur eine Node aktualisiert alle Namen: die bevorzugte, sonst die kleinste Kennung unter den seit 5 min erreichbaren.
  Fällt sie 2 min aus, übernimmt die nächste und meldet alle Namen einmal; eine zurückgekehrte Node übernimmt erst nach
  5 min wieder. In verschiedenen Netzen zeigen die Namen dann auf den anderen Anschluss (gewollt: Ausfallsicherheit).
- Seite DynDNS zeigt die zuständige Node und die Wahl der bevorzugten. Einzelheiten: [CLUSTER.md](CLUSTER.md)
  („DynDNS: zuständige Node“). Code: `internal/dyndns/cluster.go`, `internal/dyndns/ddcluster`.

## Überblick: 6 Phasen

| Phase | Inhalt | Abnahme (kurz) |
|---|---|---|
| D1 Grundgerüst | Modul ersetzt den Platzhalter, Ein/Aus, Migrationen, leere Seite | Ein/Aus ohne Restlast, Tests grün |
| D2 IP-Ermittlung | v4/v6/Präfix ermitteln, Statuskarte, Prüfprotokoll | richtige Router-IP auf Box und Dev-Node, IPv6-Hinweis ohne v6 |
| D3 Anbindung und Auswahl | API-Key, Domains/Records listen, Ziele anlegen, Tokens holen, manueller Modus | Ziel mit Record-Token angelegt, Token nirgends im Klartext |
| D4 Updater | Vergleich, Warteschlange, update.php, Präfix-Update, Backoff, „Jetzt aktualisieren“ | IP-Wechsel simuliert → genau 1 Aufruf, danach keine weiteren |
| D5 Protokoll und Limit | Protokollseiten, Filter, Aufbewahrung, Limit-Anzeige, Dashboard-Kachel | Verlauf vollständig nachvollziehbar, Limit stimmt mit ipv64 überein |
| D6 Abrundung | Benachrichtigungen, lokale API + OpenAPI, Export/Import, README | API-Doku vollständig, Mail bei Fehler kommt an |

## Phase D1 – Grundgerüst

**Ziel:** Modul `dyndns` (Pfad `/dyndns`, Logo `dyndns64.webp`) ersetzt den Platzhalter. Ausgeschaltet bleibt es vollständig ruhig.

**Schritte:**
1. `internal/dyndns/module.go`: Info, Migrations (embed), Routes, Start/Stop mit Kontext und WaitGroup. Aufbau wie healthchecks.
2. Registrierung in `cmd/node64/main.go` statt `module.Placeholder`. secrets.Box, Notify und Sync-Status kommen über den Konstruktor.
3. Navigation: Logo auch im aktiven Zustand zeigen (`nav.html` zeigt `Image` bisher nur beim Platzhalter).
4. „dyndns“ in die Log-Level-Liste (`handlers_core.go`).
5. Den Test `server_test.go`, der „dyndns nicht aktivierbar“ prüft, anpassen.

**Abnahme:**
- Modul an/aus über Einstellungen und API.
- Ausgeschaltet: keine Goroutine, 404 auf `/dyndns`, keine `dyn_*`-Tabellen vor der ersten Aktivierung.

## Phase D2 – IP-Ermittlung

**Ziel:** Zuverlässig wissen, welche öffentliche IPv4, IPv6 und welches /64-Präfix der Anschluss hat. Nachvollziehbar protokolliert.

**Schritte:**
1. Ermittler mit erzwungener Familie (Dialer `tcp4`/`tcp6`).
   - Quellen der Reihe nach: `ipv4.ipv64.net/ipcheck.php?ipv4` bzw. `ipv6.ipv64.net/ipcheck.php?ipv6`, Ausweichquelle API v2 `GET /ip`.
   - Ergebnis prüfen: gültige, öffentliche Adresse.
   - Optional eigene Prüf-URL.
2. Familien-Probe (Route vorhanden?) aus `checks` übernehmen. Ohne IPv6-Route wird nicht gefragt, sondern Status „kein IPv6 im Container“ gesetzt.
3. Präfix = erste 64 Bit der ermittelten IPv6.
   - Liegt die von außen gesehene IPv6 auf einer temporären Privacy-Adresse, gibt es einen Hinweis. Für AAAA-Records stattdessen *Präfix + Interface-ID* oder *Interface* verwenden.
   - Interface-Quelle (nur Host-Netzwerk): `/proc/net/if_inet6` auswerten, temporäre und deprecated Adressen auslassen, Interface wählbar.
4. Prüfrunde im Takt `dyndns.interval` mit leichtem Zufallsversatz, damit nicht alle Nodes zur gleichen Sekunde fragen. Jede Prüfung landet in `dyn_checks`.
5. Seite `/dyndns`, Karte „Anschluss“: aktuelle IPv4/IPv6/Präfix, Quelle, letzte Prüfung, letzte Änderung, Hinweise (kein IPv6, temporäre Privacy-Adresse). Erledigt 2026-10-14.

**Abnahme:**
- Auf der Box (Bridge ohne IPv6) zeigt sie die Router-IPv4 und den IPv6-Hinweis.
- Mit `network_mode: host` zeigt sie IPv6 und Präfix.
- Die Prüfungen stehen im Protokoll.

## Phase D3 – Anbindung und Auswahl

**Ziel:** Ziele bequem und mit dem sichersten Token einrichten.

**Schritte:**
1. Einstellungskarte „ipv64-Zugang“:
   - API-Key eintragen, prüfen (`GET /me`), verschlüsselt speichern, entfernen.
   - Ohne Key manueller Modus.
2. Auswahl-Dialog: Domains (`GET /domains`) mit Records (`GET /domains/{d}/records`, nur A/AAAA) als Liste zum Anhaken. Je Eintrag Modus IPv4 und IPv6 wählen.
3. Token-Wahl:
   - Record vorhanden: Record-Token.
   - Zonenweites Präfix-Update oder noch nicht existierender Host: Domain-Token, mit Hinweis.
   - Der Account-Token wird nie benutzt.
4. Ziele bearbeiten, pausieren und löschen. Tokens bei Bedarf über die API neu holen, z. B. nach Token-Rotation auf ipv64.
5. Prüfen, dass Token und Ziel zusammenpassen. Dafür gibt es keinen Testaufruf, weil der Limit kostet. Stattdessen Abgleich über die API-Liste.

**Abnahme:**
- Ziel im Testaccount mit Record-Token angelegt.
- Der Token erscheint weder in Logs noch im HTML noch in der API-Antwort (nur maskiert).

## Phase D4 – Updater

**Ziel:** Nur bei echter Änderung aktualisieren, sauber, limitschonend und robust.

**Schritte:**
1. Soll/Ist je Ziel:
   - Soll aus der Prüfrunde.
   - Ist aus „zuletzt gemeldet“ und direkter DNS-Abfrage am ipv64-Nameserver (fängt Änderungen von außen ab).
2. Warteschlange mit globalem Abstand von mindestens 5 s zwischen Aufrufen.
   - Bei 429: Cooldown abwarten, dann wachsend (1, 5, 15 min).
   - Bei „Updateintervall overcommited“ bis zum nächsten Tag keine weiteren Versuche, mit Anzeige.
3. Aufruf `update.php` mit `output=full`:
   - Record-Token: `ipv4`/`ipv6` nur für geänderte Familien.
   - Präfix-Modus: `ipv6prefix=<präfix>/64&onlyprefix`.
4. Antwort auswerten:
   - `status`, `info`, `ip.*`, `ipv6prefix`. Fehlendes `status` bei Präfix-Updates gilt als Erfolg.
   - `badauth`/`nohost` sind dauerhafte Fehler: das Ziel pausiert, statt es endlos zu versuchen.
5. Nach Erfolg kurz per DNS gegenprüfen, ob der Record nachgezogen hat (der Bot braucht 2–5 s).
6. Beim Start der Node bzw. beim Einschalten des Moduls eine Prüfrunde nach kurzer Wartezeit (Netz bereit).
7. Knöpfe „Jetzt prüfen“ und „Jetzt aktualisieren“ (erzwingt einen Aufruf, mit Hinweis auf das Limit).

**Abnahme:**
- IP-Wechsel simuliert (Ziel kurz auf eine falsche Adresse setzen): genau ein Aufruf, danach Ruhe.
- Ein Präfix-Update ändert die Interface-ID-Records im Testaccount.
- Bei 429 keine Aufruf-Schleife.

## Phase D5 – Protokoll und Limit

**Ziel:** Alles nachvollziehbar, Limit im Blick.

**Schritte:**
1. Seite „Verlauf“ mit den Reitern Updates und IP-Prüfungen.
   - Filter: Ziel, Familie, Ergebnis, Zeitraum.
   - Badges für good/nochg/Fehler, wie bei den Healthchecks-Ereignissen.
2. Aufbewahrung einstellbar (Prüfungen 7/30/90 Tage, Updates 90/365/unbegrenzt), Aufräumen stündlich.
3. Limit-Anzeige (nur mit API-Key):
   - `GET /me` → „heute X von Y Updates“, höchstens alle 15 min abgefragt.
   - Warnung ab 80 %.
   - Dazu eigener Zähler der Aufrufe dieser Node.
4. Je Ziel ein Status „DNS stimmt / weicht ab“ aus der letzten DNS-Gegenprüfung.
5. Dashboard-Kachel (DashboardProvider): Anzahl Ziele aktuell / Fehler / pausiert, aktuelle IPs.

**Abnahme:**
- Der Verlauf zeigt jede Prüfung und jeden Aufruf.
- Die Limit-Zahl stimmt mit ipv64 überein.

## Phase D6 – Abrundung

**Schritte:**
1. Benachrichtigungen über die vorhandenen Kanäle, je Art abschaltbar:
   - „IP geändert“, „Update fehlgeschlagen“, „Limit fast erreicht“.
   - Neue Arten in `notify` und eigene Texte.
2. Lokale API:
   - `GET /api/dyndns/status`, `GET|POST|PUT|DELETE /api/dyndns/targets`, `POST /api/dyndns/check`, `POST /api/dyndns/targets/{id}/update`, `GET /api/dyndns/history`.
   - In der OpenAPI-Datei dokumentiert, mit eigenem Tag „DynDNS“.
3. Optional Lebenszeichen an einen Push-Check des Healthchecks-Moduls nach jeder erfolgreichen Prüfrunde. Fällt der Updater aus, meldet Healthchecks das.
4. Export/Import (Exporter): Ziele mit. Tokens und API-Key nur im Passwort-Modus, wie bei den Kanälen.
5. README-Abschnitt (Docker-Netzwerk und IPv6, Modi, Limits) und Hilfetexte in der Oberfläche.

**Abnahme:**
- API-Doku vollständig.
- Testmail bei Fehler kommt an.
- Export ohne Passwort enthält keine Tokens.

---

## Entscheidungen (Dennis, 2026-10-14)

1. API-Key wird dauerhaft gespeichert, verschlüsselt.
2. Der hub hat mit DynDNS nichts zu tun. Node64 spricht direkt mit ipv64 (update.php, API v2). DynDNS-Meldungen gehen immer über die lokalen Kanäle, auch bei verknüpfter Node.
3. Prüftakt: Standard 5 min, Minimum 1 min.
4. IP-Quellen: nur ipv64, optional eigene URLs.
5. Mehrere Nodes für dasselbe Ziel: erlaubt, mit Warnung; bei Flattern pausiert das Ziel (Vorschlag, nicht widersprochen).
6. Router direkt fragen (FRITZ!Box, UPnP): später.

## Ideen aus anderen lokalen Updatern

Angesehen: ddclient, inadyn, qdm12/ddns-updater, favonia/cloudflare-ddns, ddns-go.

- **Übernommen:**
  - IPv6 aus Präfix + Interface-ID (ddns-updater `ipv6_suffix`).
  - Interface-Quelle ohne temporäre Adressen (inadyn `iface`, cloudflare-ddns `local.iface`). Dafür braucht es Host-Netzwerk.
  - Status „DNS stimmt“ je Ziel (ddns-updater-Healthcheck).
  - Lebenszeichen an einen Healthchecks-Push (cloudflare-ddns mit Healthchecks/Uptime Kuma).
  - Meldung mit Ergebnis über Webhook (ddns-go). Bei uns über die vorhandenen Kanäle, Webhook eingeschlossen.
  - Prüfrunde beim Start.
  - IP-Historie (ddns-updater) über `dyn_checks`/`dyn_updates`.
- **Bewusst nicht:**
  - Erzwungenes Update nach X Tagen (inadyn/OpenWrt): ipv64-Records laufen nicht ab. Die DNS-Gegenprüfung deckt Abweichungen ab, und jedes Update kostet Limit.
  - IP per DNS über Dritte (OpenDNS, Cloudflare): nur ipv64-Quellen.
  - Cron-Ausdrücke: der feste Takt genügt.

## Risiken und Gegenmittel

| Risiko | Gegenmittel |
|---|---|
| `nochg` verbraucht Limit | lokaler Vergleich + DNS-Gegenprüfung, nur bei Abweichung aufrufen |
| Cooldown 3/10 s, zählt auch fremde Log-Einträge | globale Warteschlange ≥ 5 s, 429-Backoff |
| Container ohne IPv6 meldet falsche oder keine IPv6 | Familien-Probe, klarer Hinweis, Präfix-Modus |
| DS-Lite: IPv4 ist Provider-Adresse | IPv4 je Ziel abschaltbar, Hinweis |
| Token-Rotation auf ipv64 → badauth | Ziel pausiert, „Token neu holen“ (mit API-Key automatisch anbietbar) |
| Präfix-Update wirkt zonenweit | in der Oberfläche deutlich anzeigen |
