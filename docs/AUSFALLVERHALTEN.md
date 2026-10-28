# Ausfallverhalten Healthchecks 2.0 / Node64

Stand 2026-10-11 (hub 0.9.4-dev, Node64 0.9.4-dev). Beschreibt, was im Betrieb wirklich passiert – nicht den Wunschzustand.

## Aufbau in einem Satz

Zwei gleichwertige hubs (`hc-srv01` = Falkenstein `fsn`, `hc-srv02` = Nürnberg `nbg`) mit beiden Rollen (Nodes anbinden, Online-Checks messen). Gemeinsamer Zustand liegt **nur in MySQL** (`ipv64_hc` auf 10.100.0.110). Redis läuft auf `hc-srv02`, wird vom hub derzeit aber nicht benutzt (die hubs fragen das Änderungsprotokoll in MySQL jede Sekunde ab).

## Mit welchem hub verbindet sich eine Node?

- Jede Node hat einen **Stamm-hub**, fest aus ihrer Node-ID berechnet (`crc32(node_id) mod Anzahl hubs`, hubs nach URL sortiert). Damit verteilen sich die Nodes etwa hälftig auf beide hubs, und eine Node landet immer am selben.
- Die Liste der hubs kommt aus dem `hello` des hubs (Tabelle `hc2_locations`), ersatzweise aus der eingebauten Liste.
- Ist der Stamm-hub nicht erreichbar, nimmt die Node einen anderen.
- Läuft sie nicht am Stamm-hub, prüft sie alle 10–20 Minuten (zufällig, damit nicht alle gleichzeitig wechseln) dessen `/v1/health` und wechselt bei `status: ok` zurück.
- Erstverknüpfung (Code anfordern) fragt ebenfalls zuerst den Stamm-hub.
- Für Tests überschreibt `NODE64_HUB_URL` alles.

## Was passiert bei einem Ausfall?

| Fall | Node merkt es nach | wieder verbunden |
| --- | --- | --- |
| Update/Neustart des hub (`bye`) | sofort | ca. 1 s, am anderen hub |
| hub-Prozess oder Server abgestürzt (Verbindung bricht ab) | sofort | ca. 1–2 s |
| hub hängt / Netz verwirft Pakete | bis ca. 40 s (eigener Ping alle 30 s, 10 s Timeout; oder 30 s ohne Bestätigung) | danach ca. 1–2 s |
| beide hubs weg | wie oben | Wiederholung mit Backoff 1 s … 60 s, die Node läuft solange standalone weiter |
| Stamm-hub wieder da | – | Rückkehr nach 10–20 min |

Während keine Verbindung besteht, misst die Node weiter, speichert Messpunkte und Ereignisse lokal und lädt sie nach (über die laufende Nummer `node_seq`, nichts geht verloren). Eigene Änderungen liegen im Postausgang und werden nach dem Wiederverbinden abgespielt; Überschneidungen mit Änderungen im Portal werden als Konflikt angezeigt (gleiche Inhalte zählen nicht als Konflikt).

**Benachrichtigungen:** Verbunden und mit funktionierender Bestätigung sendet der hub (eigene Kanäle der Node per Sendeauftrag). Ist die Node nicht verbunden **oder** bestätigt der hub nichts mehr (z. B. weil seine Datenbank weg ist), sendet die Node ihre eigenen Kanäle selbst. Meldet die Node einen Zustand verspätet (älter als 5 min), trägt der hub ihn still nach, damit kein Alarm doppelt kommt.

**Checks, die nur eine Node misst** (Healthchecks 2.40.0, lokal, Besitzer-Node, keine weiteren Messstellen): Die Node sendet Ausfall, Entwarnung, Flattern und Erinnerungen selbst – ipv64-Mail/-SMS/App über die API v2 (`/hc2/channels/{id}/send`), eigene Kanäle direkt –, auch verbunden und auch während einer Trennung. Der hub sendet dafür nur die übrigen Portal-Kanäle (Webhook, Telegram …, deren Geheimnisse nur bei ipv64 liegen) und Kanäle anderer Nodes; „wird nicht geprüft“/„wird wieder geprüft“ sendet er wie bisher ganz. Voraussetzung auf beiden Seiten: Der hub kündigt `notify-direct` im `hello` an, die Node meldet `notify-direct` in `status.modules` (nur mit API-Key, steht dann in `hc2_nodes.modules`). Ältere hubs oder Nodes: alles wie bisher.

Auf hub-Seite gilt eine getrennte Node nach 60 s als offline; ihre Messstelle zählt dann in Hybrid-Checks nicht mehr mit.

## Online-Checks

- Jeder hub misst die Checks seines Standorts (`locations` des Checks). Fällt ein hub aus, misst der andere Standort weiter; der ausgefallene liefert nichts.
- Der Gesamtzustand ignoriert Messstellen ohne frische Daten (älter als 3 × Intervall, mindestens 5 min). Ein Check mit `nbg,fsn` läuft also mit einem Standort weiter; ein Check nur mit `fsn` hat während eines fsn-Ausfalls keine Messung.
- **Push-Checks** wertet der **erste lebende** Standort des Checks aus (normal `nbg`). Fällt er aus, übernimmt der nächste innerhalb von ca. 10–20 s (Heartbeat der hubs). Der letzte Push wird aus `hc2_checks.last_push_at` übernommen, es gibt also keinen Fehlalarm beim Wechsel. Pushes kommen über `health.php` oder `/v1/push/{token}` an beiden hubs an.

## Datenbank 10.100.0.110 fällt aus

Bewusst so akzeptiert (Entscheidung Dennis 2026-10-11):

- hubs können nichts lesen oder schreiben: Online-Messungen in dieser Zeit gehen verloren, keine Alarme über den hub, Portal ohne Healthchecks.
- Nodes bleiben verbunden, bekommen aber Fehler-Bestätigungen und **senden ihre eigenen Kanäle selbst**; ihre Messdaten laden sie nach der Rückkehr nach.
- Startet ein hub neu, während die Datenbank weg ist, kommt er nicht hoch (systemd versucht es weiter).
- Betriebsalarm: jeder hub meldet „Datenbank gestört“ an die Kanäle in `ops.alerts` (Pushover folgt).

## Redis fällt aus

Keine Auswirkung. Das Portal schickt Signale an Redis und ignoriert Fehler; die hubs pollen MySQL.

## Betriebsalarme

Jeder hub prüft jede Minute den anderen (`/v1/health` über das Internet) und die eigene Datenbank. Alarm nach 3 Fehlversuchen, Erinnerung stündlich, Entwarnung nach 2 Erfolgen. Kanäle stehen in `/etc/ipv64-hub/config.yaml` unter `ops.alerts`, Test mit `/opt/ipv64-hub/hub -ops-test`. Fallen beide hubs gleichzeitig aus, meldet niemand – dafür ist ein externer Monitor vorgesehen.

## Tests, die das belegen (2026-10-11)

- Netztrennung 10 min und 2 h mit Änderungen auf beiden Seiten, Neustart der Node während der Trennung.
- Rolling-Deploy beider hubs bei verbundenen Nodes (`bye`, Wechsel in ca. 1 s).
- hc-srv02 gestoppt: Betriebsalarm nach ca. 45 s, Entwarnung nach Neustart; Push-Auswertung wandert nach fsn und zurück (Testprotokoll unten).
- Lasttest 10.000 Nodes an einem hub (`cmd/hubload`).

### Testprotokoll Failover 2026-10-11 (hub 0.9.4-dev)

- Stamm-hubs: Dev-Node `nz5EcC…` → hc-srv01, Testbox-Node `qFhQgD…` → hc-srv02 (je Node fest).
- 19:33:22 UTC hc-srv02 gestoppt: Testbox-Node um 19:33:23 mit hc-srv01 verbunden (1 s).
- Push-Check `t2hubpush…` (Standorte nbg,fsn, Push alle 20 s): Auswertung wanderte nach fsn (erste Messung 19:33:48), Gesamtzustand blieb „OK“, kein Fehlalarm; nach dem Neustart von hc-srv02 (19:37:26) übernahm nbg wieder, ebenfalls ohne Fehlalarm.
- 19:51:25 UTC: Testbox-Node kehrte automatisch zu ihrem Stamm-hub hc-srv02 zurück (18 min nach dem Wechsel, Umschalten in < 0,1 s).
