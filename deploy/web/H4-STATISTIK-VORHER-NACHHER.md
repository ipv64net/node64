# Honeypot64 – Phase H4, Teil Statistik + Listen einspielen (ipv64.net)

Öffentliche Statistik unter `/honeypot/stats.php` (Überblick für alle, volle Seite für alle Klassen außer Standard),
API `GET /threat/stats`, Text-Listen mit Passwörtern, Benutzernamen, User-Agents (+ nginx-`map`) und Angriffs-Pfaden
(+ nginx-`location`), Schutz gegen Vergiften (Proben zählen je Account). Planung: `docs/PLAN-NODE64-HONEYPOT64.md`
(Abschnitte 7, 8, 10, 13). Der Teil **Leitfaden** hat eine eigene Anleitung (die DNSBL ist entfallen, 2026-10-27).

Getestet in einer abgeschotteten Testumgebung auf der Testbox (MariaDB 10.5, PHP 8.3, echte `api_v2.php`, echter
Generator, nginx 1.27 für `nginx -t` und Sperrtests mit der erzeugten map und dem location-Snippet): 89 + 25 Prüfungen,
alle grün (`deploy/web/honeypot/tests/h4_stats/run_agentbox.sh`), danach alles entfernt.

## Was es macht

| Teil | Inhalt |
|---|---|
| Schutz gegen Vergiften | Neue Tabelle `hp_sample_contrib`: jede Probe (Zugangsdaten, Pfad, User-Agent, Payload) zusätzlich je Account und Tag, in derselben Transaktion wie die Meldung. Ranglisten und Listen nehmen nur Einträge, die **mindestens N Accounts in den letzten 30 Tagen** gemeldet haben: **N = 2 unter 20 aktiven Accounts, sonst 3** (aktiv = Meldung in 7 Tagen, wie die Bewertung). Altbestand ohne Account-Bezug (Proben vor H4, letzte 30 Tage) wird beim Einspielen als Account 0 übernommen und zählt als **ein** Account. Zusätzlich zählt eine Probe je Account und Tag höchstens 10 000-mal (Rangfolge nicht kaufbar). |
| Bereinigung | Einträge mit Steuer-, Bidi-, unsichtbaren oder 4-Byte-Zeichen, führenden/abschließenden Leerzeichen, E-Mail-Adressen, zufälligen Strings (Hash, Token, Base64) oder Überlänge (Passwort/Benutzer 64, Pfad/User-Agent 256 Zeichen) fallen ganz weg; Benutzernamen ohne Telefonnummern; Pfade ohne Allerweltspfade (`/`, `/robots.txt`, `/.well-known/…`); User-Agents ohne normale Browser und ohne Suchmaschinen/Monitoring (Googlebot, UptimeRobot, Let’s Encrypt …). |
| Text-Listen (Cron alle 6 h) | `blocklists/ipv64_passwords.txt` (bis 10 000, häufigste zuerst, ohne Zählung), `ipv64_passwords_sha1.txt` (SHA-1 groß, sortiert), `ipv64_usernames.txt` (bis 10 000), `ipv64_bad_useragents.txt` (bis 2 000) + `ipv64_bad_useragents.nginx.map`, `ipv64_attack_paths.txt` (bis 5 000) + `ipv64_attack_paths.nginx.conf`. Atomar geschrieben (Temp-Datei + rename, 0644). |
| index.json | Eigene Einträge unter **`"data"`** (nicht unter `"lists"`), Kategorie `honeypot-data`, Lizenz „CC BY 4.0 (IPv64.net Honeypot64), provided as is without warranty“. Grund: Node64/PROXY64 nimmt jeden Eintrag in `lists` mit `files.all` als IP-Liste – Passwörter dort wären falsch. |
| Statistik `/honeypot/stats.php` | Überblick für alle: aktive Sensoren/Accounts (7 Tage), Angriffe und Angreifer-IPs 24 h, Verlauf 30 Tage (Chart.js aus `/js/chartjs/`), Top 10 Ports und Arten (7 Tage), Größe der Listen, Top 10 Benutzernamen/Passwörter/Pfade/User-Agents. Volle Seite (eingeloggt, `user_class` ≠ 1): Top 100, „Neu gelistet heute“ (mit Link zur IP-Auskunft), „Neue Pfade heute“ (erstmals gesehen), Suche, CSV-Export (Formel-Injektion entschärft). Beitragende sehen den Verweis auf `/honeypot/`. Deutsch, `?lang=en` Englisch. **Land** fehlt (noch keine Anreicherung) und wird weggelassen. |
| API `GET /threat/stats` | Überblick wie die Seite (Top 10), öffentlich; Limit wie `/threat/ip` (ohne Key 10 sofort, dann 1/min je Client-IP; mit Key 120/2 je s je Account), eigener Topf. Antwort aus dem Cache. |
| Cache | Tabelle `hp_stats_cache`, höchstens alle **10 Minuten** neu gerechnet (`GET_LOCK`: ein Prozess rechnet, die anderen nehmen den alten Stand). Die Ranglisten liegen in `hp_sample_top`. |

## 1. SQL einspielen (Hauptdatenbank ipv64) – ZUERST

Voraussetzung: `honeypot.sql` (H2) und `honeypot_h3_scoring.sql` (H3) sind drin. Dann
`deploy/sql/honeypot_h4_stats.sql` – mehrfach ausführbar. Legt an: `hp_sample_contrib`, `hp_sample_top`,
`hp_stats_cache`; übernimmt den Altbestand der letzten 30 Tage als Account 0; ergänzt den Index
`hp_samples_paths.key_day (key_hash, day)` (`ADD INDEX IF NOT EXISTS`, InnoDB online).

```bash
mysql ipv64 < honeypot_h4_stats.sql
```

**Reihenfolge wichtig:** erst SQL, dann `api_v2_honeypot.php`. Die neue Annahme schreibt `hp_sample_contrib` in
derselben Transaktion; fehlt die Tabelle, werden Meldungen mit 500 abgewiesen (die Sensoren holen sie aus ihrem
Puffer nach, bis 7 Tage).

## 2. Dateien hochladen

| Datei im Repo | Ziel im Webroot (`/var/www/clients/client1/web58/web/`) |
|---|---|
| `deploy/web/api_v2_honeypot.php` | `api_v2_honeypot.php` (ersetzt: nur ein Block nach den Proben-INSERTs + eine Kommentarzeile) |
| `deploy/web/api_v2_honeypot_stats.php` | `api_v2_honeypot_stats.php` (neu) |
| `deploy/web/api_v2_openapi.json` | `api_v2_openapi.json` (ersetzt: nur `/threat/stats`, `ThreatStats`, `ThreatStatsEntry` dazu) |
| `deploy/web/honeypot/hp_stats_lib.php` | `honeypot/hp_stats_lib.php` (neu) |
| `deploy/web/honeypot/stats.php` | `honeypot/stats.php` (neu) |
| `deploy/web/bots/honeypot_lists.php` | `bots/honeypot_lists.php` (neu, Cron) |
| `deploy/web/bots/honeypot_lists_index.php` | `bots/honeypot_lists_index.php` (neu, nur Konstanten + eine Funktion) |
| `deploy/web/blocklists/site/bots/blocklist/create_blocklists_v2.php` | `bots/blocklist/create_blocklists_v2.php` (ersetzt: 2 Zeilen vor dem Schreiben von index.json) |

**Nicht hochladen:** `deploy/web/honeypot/tests/` (Stubs und Testskripte).

Änderung in `create_blocklists_v2.php` (voller Lauf, kurz vor `write_atomic("$OUT/index.json", …)`):

```php
// Honeypot64 Text-Listen (bots/honeypot_lists.php) unter "data", nicht unter "lists" (dort waeren es IP-Listen)
if(is_file(__DIR__."/../honeypot_lists_index.php")) { require_once __DIR__."/../honeypot_lists_index.php"; $index['data'] = hpl_index_entries($OUT); }
```

Der Lauf `--only=v64` lässt `"data"` ohnehin stehen (ersetzt nur die Kategorie `honeypot`).

## 3. `api_v2.php`: eine Zeile vor dem Start-Block

VORHER (seit H3):

```php
require __DIR__ . '/api_v2_honeypot.php';
require __DIR__ . '/api_v2_threat.php';

// ===================================================================
//  Start
```

NACHHER:

```php
require __DIR__ . '/api_v2_honeypot.php';
require __DIR__ . '/api_v2_threat.php';
require __DIR__ . '/api_v2_honeypot_stats.php';

// ===================================================================
//  Start
```

## 4. Cron

```cron
# Honeypot64 Text-Listen + Statistik-Cache (alle 6 Stunden)
17 */6 * * * php /var/www/clients/client1/web58/web/bots/honeypot_lists.php > /dev/null
```

Einmal von Hand starten (schreibt die Listen, trägt sie in `index.json` ein, rechnet den Cache, löscht
`hp_sample_contrib` älter als 35 Tage):

```bash
php /var/www/clients/client1/web58/web/bots/honeypot_lists.php
php /var/www/clients/client1/web58/web/bots/honeypot_lists.php --dry      # nur Zahlen, keine Dateien
```

Fehlt `index.json` noch, kommen die Einträge mit dem nächsten vollen Lauf von `create_blocklists_v2.php` hinein.
Am Anfang (wenige Beitragende, Schwelle 2) können die Listen leer oder kurz sein – das ist gewollt: ein einzelner
Account kann nichts hineinbringen.

## 5. Link in „Secure“ (`v64_secure.php`) – Vorschlag, nicht umgesetzt

In der Karte „IPv64 Blocklists“ die Linkliste ergänzen.

VORHER:

```html
				<ul>
					<li><a href="https://ipv64.net/v64_blocklists" title="IPv64.net Blocklists">IPv64 Blocklists</a></li>
					<li><a href="v64_blocklist_integration_guide">Read the IPv64 Blocklist integration Guide <i class="fa-solid fa-book"></i></a></li>
				</ul>
```

NACHHER:

```html
				<ul>
					<li><a href="https://ipv64.net/v64_blocklists" title="IPv64.net Blocklists">IPv64 Blocklists</a></li>
					<li><a href="v64_blocklist_integration_guide">Read the IPv64 Blocklist integration Guide <i class="fa-solid fa-book"></i></a></li>
					<li><a href="/honeypot/stats.php?lang=en" title="Honeypot64 statistics">Honeypot64 statistics: attacks, top passwords, usernames, paths and user agents <i class="fa-solid fa-chart-line"></i></a></li>
				</ul>
```

Optional (nicht umgesetzt) in `v64_blocklists.php` unter der v64-Zeile ein Hinweis auf die Text-Listen, z. B.
`<small>Attacker passwords, usernames, user agents and paths: <a href="/honeypot/stats.php?lang=en">Honeypot64 statistics</a></small>`.

## 6. Hinweise

- **nginx-map:** Lange Schlüssel brauchen im `http {}`-Block `map_hash_bucket_size 512;` und `map_hash_max_size 4096;`
  (steht als Kommentar im Kopf der Datei). Vergleich exakt, ohne Groß-/Kleinschreibung (nginx); Doppelte nur in
  Schreibweise sind entfernt. Sonderfälle (`~` am Anfang, `\`, `"`, `default`, `include`, …) sind maskiert und mit
  `nginx -t` sowie echten Anfragen geprüft.
- **nginx-location:** reguläre Ausdrücke mit exaktem Vergleich (`location ~ "^(?:/\.env|…)$" { return 403; }`) in
  Blöcken unter 4096 Bytes je Parameter; kollidiert nicht mit eigenen `location =`-Blöcken. Nur Pfade mit
  unkritischen Zeichen (ohne Abfrage, ohne `..`, `%`, `"`, `\`, `$`). Nur für Seiten gedacht, die diese Pfade nicht
  selbst nutzen (z. B. steht `/wp-login.php` drin) – steht im Kopf der Datei.
- **Text-Listen** haben keinen Kommentarkopf (ein `#` wäre sonst ein Passwort); Lizenz und Stand stehen in
  `index.json` und auf der Statistikseite.
- **Datenschutz:** veröffentlicht werden nur Statistiken und Einträge ab der Account-Schwelle; keine Sensor-IPs,
  keine Accounts. `hp_sample_contrib` (Account ↔ Probe) bleibt intern und wird nach 35 Tagen gelöscht.
- **Statistikseite** ohne Menülink; erreichbar über den Link in „Secure“ (Abschnitt 5).

## 7. Offen

- Herkunft nach Land/Netzbetreiber (Plan Abschnitt 10): erst mit der Anreicherung (ASN/Land) möglich.
- Volle Seite: Verlauf je Benutzername/Passwort, Kampagnen, Länder der Sensoren (Plan Abschnitt 10) noch nicht.
- Schwelle zählt Accounts, nicht Gruppen im selben /24 (wie die Bewertung es tut); bei Bedarf nachziehen.
- Leitfaden (Firmen-Firewalls/MikroTik) und node64.de-Doku sollten die neuen Listen und `GET /threat/stats` nennen.
