# Umstieg: DNS Failover auf die neuen Healthchecks (hc2)

Stand 2026-10-26: **vorbereitet, nicht live.** DNS Failover liest bisher nur die alte Tabelle `healthchecks`. Die
Umstellung liegt fertig in `deploy/web` (Commits `c7ea3ae`, `6401c2a`) hinter dem Schalter `FAILOVER_HC2`
(Standard aus – ohne Schalter verhält sich alles wie vorher).

**Wann:** sobald Dennis sagt, dass auf die neuen Healthchecks umgeschaltet wird. Dann diese Liste vollständig
abarbeiten und Dennis jeden Punkt nennen.

## Wie es funktioniert

- Neue Healthchecks haben denselben Token wie die alten (`hc2_checks.token` = `healthchecks.healthtoken`). Die Tabelle
  `dns_failover_monitors` bleibt unverändert, **keine SQL nötig**.
- `failover_hc2_lib.php` liefert Monitore im Format der alten Tabelle. Mit Schalter: neue Healthchecks zuerst, alte
  als Rückfall (solange es sie gibt). Zustände: `up` = online (1), `down` = gestört (4), `paused` = pausiert (2),
  `degraded`/`flapping`/`dependent` = Warnung (3, löst nichts aus), `stabilizing` = 5, sonst 0.
- Gelöschte Checks und Checks anderer Nutzer zählen nicht; Namen aus hc2 werden maskiert.

## 1. Voraussetzungen prüfen

- [ ] Neue Healthchecks sind live und für die Nutzer erreichbar (`/healthchecks2/`, Menüpunkt, ggf. Freischaltung je
      Konto über `users.hc2`).
- [ ] Live ist `hc2_pdo()` verfügbar (steht in `dbconnect_hc2.php` bzw. live in `dbconnect.php`). Fehlt sie, lädt die
      Bibliothek `dbconnect_hc2.php` aus dem Webroot nach.

## 2. Dateien hochladen (über `deploy/upload/web/`, 1:1 ins Webroot)

| Datei | Änderung |
|---|---|
| `failover_hc2_lib.php` | **neu** – Bibliothek, enthält den Schalter |
| `dns_failover.php` | Monitore hinzufügen/anzeigen/auswählen über die Bibliothek (Basis: Live-Kopie aus `ipv64net_webseite`) |
| `bots/failover_checker.php` | Zustand der Monitore über die Bibliothek |
| `healthchecks2/hc2_lib.php` | `hc2_failover_uses()` / `hc2_failover_warning()` |
| `healthchecks2/check.php` | Hinweis „Monitor in DNS Failover“ + Löschabfrage + Warnung nach dem Löschen |
| `healthchecks2/index.php` | Warnung nach Massenlöschen |
| `api_v2_hc2.php` | `DELETE /hc2/checks/{token}`: Header `Warning: 299` |

Vorher prüfen, ob `dns_failover.php` live seit dem 2026-10-26 geändert wurde (Basis ist die Kopie in
`ipv64net_webseite`) – sonst die Live-Änderungen nachziehen.

## 3. Schalter umlegen

- [ ] In `failover_hc2_lib.php` die Zeile `defined('FAILOVER_HC2') || define('FAILOVER_HC2', false);` auf `true`
      setzen. Gilt für Seite, Bot und die Warnungen in den Healthchecks gleichzeitig.
- [ ] Kein Neustart nötig: `failover_checker.php` läuft drei Runden (je 18 s Pause) und beendet sich; der nächste
      Cron-Start lädt den neuen Code.

## 4. Prüfen

- [ ] `dns_failover.php`: Auswahlliste zeigt die neuen Checks; bestehende Monitore zeigen den richtigen Zustand.
- [ ] Testpolicy mit einem neuen Check: Check auf gestört bringen → Failover löst aus; wieder OK → Fallback.
- [ ] Check löschen, der Monitor ist → gelbe Warnung mit Policy-Namen; Policy zählt ihn danach nicht mehr.

## 5. Doku nachziehen (`ipv64_docs`, danach `go run .` und `public/` hochladen)

- [ ] `pages/dyndns_failover.{de,en}.html`, Abschnitt `#monitore`: Satz „Zur Auswahl stehen derzeit nur die
      Healthchecks der bisherigen Healthcheck-Seite …“ samt `todo` ersetzen – neue Healthchecks sind Monitore,
      Zustände wie oben (degraded/instabil löst nicht aus), Warnung beim Löschen.
- [ ] `pages/faq.{de,en}.html`, Frage `#failover`: neue Healthchecks nennen.
- [ ] `pages/healthchecks.{de,en}.html`: Hinweis, dass Checks als DNS-Failover-Monitor dienen können (mit Link auf
      `dyndns/failover#monitore`); `pages/healthchecks_api.{de,en}.html`: Header `Warning: 299` bei `DELETE`.
- [ ] Webseiten-Sitzung (node64.de) informieren, falls dort DNS Failover erwähnt ist.

## 6. Später

- Wenn die alten Healthchecks abgeschaltet sind: Rückfall auf die Tabelle `healthchecks` in `failover_checks()`
  entfernen.
