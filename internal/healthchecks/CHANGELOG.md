# Änderungen – Healthchecks

## 2.21.0 – 2026-10-21

### Behoben
- Proxmox VE: „Verbindung testen“ schickt das Token nie an ein unbestätigtes Zertifikat. Erst den Fingerabdruck
  bestätigen, dann erneut testen. Das gespeicherte Secret gilt nur für die eingerichteten Adressen mit demselben
  Fingerabdruck.
- Proxmox VE: Keine doppelten Meldungen mehr bei „als Check führen“; eine schon gemeldete Störung übernimmt der Check.
  Eine Störung, die während „als Check“ oder bei abgeschalteter Regel erkannt wurde, wird nachgeholt.
- Proxmox VE: Checks „als Check“ nutzen die Kanäle der Proxmox-Regeln, auch nach Änderungen; bei abgeschaltetem System
  werden sie pausiert angelegt.
- Proxmox VE: „Nicht erreichbar“ wartet die eingestellte Verzögerung auch zeitlich ab. Fortgesetzte bzw. neu
  gestartete VMs zeigen keinen alten Zustand „angehalten/abgestürzt“ mehr. Ein gestoppter Gast mit hängendem Lock gilt
  nach 4 Stunden als gestoppt. Direkt nach einem Neustart meldet der Check keine kurze Störung mehr.
- Proxmox VE: Import schaltet abgeschaltete Systeme richtig ab; gleichnamige Systeme werden über die Adressen
  zugeordnet, sonst neu angelegt. Gleichzeitiges Speichern startet keine zweite Abfrage mehr.
- Proxmox VE: Prometheus-Kennzahlen mit zusätzlichem Label `system_id`. Filter der Systemseite sendet direkt ab, Raten
  im Zahlenformat der Sprache, Systemseite lädt schneller.
- Benachrichtigungen: In der Ruhezeit zurückgehaltene Meldungen werden gespeichert und gehen bei einem Neustart nicht
  mehr verloren. Geheimnisse in Fehlertexten werden gründlicher geschwärzt (client_secret, auth_token, JSON-Paare,
  Authorization mit beliebigem Schema); „basic constraints“ bleibt lesbar.

## 2.20.1 – 2026-10-21

### Behoben
- Startseiten-Karte „Proxmox VE“: Ein System zählt nur noch mit eigenem Problem (nicht erreichbar, Node offline,
  Quorum verloren) als gestört. Gestörte Gäste stehen allein unter „Gäste gestört“ und werden nicht doppelt gezählt.

## 2.20.0 – 2026-10-21

### Neu
- Export/Import der Konfiguration enthält die Statusseiten (Einstellungen, Gruppen, Einträge, Logo; abgeglichen über den
  Slug). Der Passwort-Hash einer geschützten Seite nur beim Export mit Passwort; ohne ihn kommt die Seite
  ausgeschaltet an. Ankündigungen bleiben auf der Node.

### Geändert
- Datenhaltung: abgeschlossene Störungen werden wie Stundenwerte und Ereignisse nach „Stundenwerte aufbewahren“
  gelöscht (unbegrenzt = bleiben); bisher blieben sie für immer.

## 2.19.1 – 2026-10-21

### Neu
- Proxmox VE: Kanäle je Ebene wählbar (System, Node, Gast) wie bei Checks – Standardkanäle oder bestimmte Kanäle;
  Node und Gast erben die Auswahl sichtbar („vom System geerbt“, „vom Node geerbt“). Gelöschte Kanäle werden beim
  Senden übergangen; Export/Import schreibt die Kanäle wie bei Checks um. API: `rules.channels`.

### Geändert
- Proxmox-Meldungen in der Ruhezeit werden nicht mehr verworfen, sondern wie Check-Meldungen zurückgehalten und danach
  in der Sammelmeldung verschickt (mit Art der Meldung und Link auf die Proxmox-Seite).

## 2.19.0 – 2026-10-21

### Neu
- Prometheus je Gast zusätzlich Netz und Disk-I/O (Byte/s), RAM in Byte und CPUs; Systemseite zeigt einen Hinweis, wenn dem Token Leserechte fehlen (häufigster Einrichtungsfehler: Token mit Privilege Separation ohne eigene Rolle).
- Proxmox-Meldungen halten sich an Ruhezeiten (auch Abstürze) und Wartungsfenster (Fenster für alle Checks; für bestimmte Checks, wenn der Gast als Check geführt wird).
- Proxmox VE: neuer Menüpunkt „Proxmox VE“ unter Healthchecks. Überwacht Proxmox-VE-Systeme (Einzel-Node oder
  Cluster) nur lesend über ein API-Token: Nodes, VMs und Container mit Zustand (inkl. Backup, Lock, Absturz per
  qmpstatus), CPU, RAM, Disk, Netz und Laufzeit; Filter nach Zustand, Node, Typ und Suche.
- Assistent „System hinzufügen“: Adresse(n), Token, „Verbindung testen“ mit SHA-256-Fingerabdruck zum Festpinnen
  (selbstsignierte Zertifikate), pveum-Befehle für ein Leser-Token (PVEAuditor); Bearbeiten, Ausschalten, Löschen.
- Detailseite je Gast und Node mit Graphen (1 h, 24 h, 7 Tage, 30 Tage) und Regeln mit sichtbarer Vererbung
  (System → Node → Gast): Absturz, gestoppt, angehalten, suspendiert, Node offline, nicht erreichbar, Neustart,
  Schwellen für CPU/RAM/Disk mit Dauer, Verzögerung, stumm.
- Benachrichtigung über die vorhandenen Kanäle und Ruhezeiten mit neuen Arten (Störung, Entwarnung, Schwelle,
  Neustart); ein Absturz meldet mit hoher Priorität. Offene Störungen überstehen einen Neustart der Node.
- „Als Check führen“ je Gast und Node: neuer Check-Typ `proxmox` (nur lokal), damit Statusseiten, Uptime und der
  Sync mit ipv64 greifen; Zustandsmeldungen kommen dann nur über den Check.
- Startseiten-Karte „Proxmox VE“, Prometheus-Kennzahlen (`node64_pve_*`), API unter `/api/healthchecks/proxmox`,
  Export/Import (Token-Secret nur mit Export-Passwort).

## 2.18.3 – 2026-10-20

### Behoben
- Statusseiten, Ansicht Kacheln: Die Schrift wuchs auf breiten Bildschirmen zu stark (bis 40 px). Sie wächst jetzt nur
  noch sanft mit und bleibt bei höchstens 22 px.

## 2.18.2 – 2026-10-20

### Behoben
- Statusseiten, Ansichten Liste und Kompakt: Auf großen Bildschirmen wuchs die Schrift mit der Fensterbreite (bis 30 px),
  die Seite wirkte stark vergrößert. Sie bleibt jetzt bei höchstens 17 px; nur die Kacheln für den Wandmonitor wachsen mit.

## 2.18.1 – 2026-10-20

### Behoben
- Statusseiten, Ansicht Kacheln: Gruppen mit wenigen Checks füllten auf großen Bildschirmen nur einen Teil der Breite;
  die Kacheln teilen sich jetzt die ganze Zeile.

## 2.18.0 – 2026-10-20

### Neu
- Statusseiten: eigenes Logo je Seite (PNG, JPEG, WebP oder SVG bis 256 KB) im Kopf neben dem Namen, auch als Favicon;
  ohne eigenes Logo zeigt der Tab das Node64-Logo. „Bereitgestellt mit“ zeigt das Node64-Logo.
- Statusseiten: Option „Gruppen der Healthchecks übernehmen“ – die Einträge erscheinen in ihren Healthchecks-Gruppen als
  Blöcke (ohne Gruppe unter „Weitere“), in allen Ansichten.
- Statusseiten: responsiv vom Handy bis zum 4K-Monitor (Schrift, Kacheln und Balken wachsen mit; auf großen
  Bildschirmen mehr Kacheln je Zeile).

### Geändert
- Neue Statusseiten werden standardmäßig direkt auf dem Node-Port veröffentlicht; PROXY64 mit eigener Domain ist der
  optionale Weg.

### Behoben
- Statusseiten: Online-Checks hatten keine Verfügbarkeit und keine Tagesbalken. Jetzt zählen die Messungen von ipv64,
  wenn es für den Tag keine eigenen gibt (kein Doppelzählen bei „beides“).
- Statusseiten: Ohne Daten steht „–“ statt einer leeren Stelle; Kacheln und Zeilen bleiben gleich hoch.

## 2.17.0 – 2026-10-20

### Neu
- **Statusseiten** (Healthchecks › Statusseiten): öffentliche Übersicht über beliebig viele Checks in Gruppen, mit
  Gesamtbanner, Tagesbalken (30/60/90 Tage) und Verfügbarkeit; gestörte Gruppen stehen offen, Probleme zuerst. Ein Klick
  auf einen Eintrag zeigt Verfügbarkeit über 24 h/7/30 Tage, mittlere Latenz, 24 Stundenbalken und die letzten Störungen.
  Störungen und Wartungsfenster erscheinen automatisch, Ankündigungen gibt es von Hand (mit Updates).
- Ansichten Liste, Kacheln (für einen Monitor an der Wand) und Kompakt (zum Einbetten); hell/dunkel, Akzentfarbe,
  Sprache, einfaches Markdown in Beschreibung und Fußzeile, optional Passwort und „nicht indexieren“.
- Besucher sehen nur Anzeigenamen, Zustand und Verfügbarkeit, nie Ziele, IPs, Ports oder Fehlermeldungen.
- Statusseiten sind aus, bis man sie einschaltet; vorher läuft nichts. Erreichbar über PROXY64 (Hostart
  „Statusseite“, eigene Domain, auch über CDN64) oder, bewusst eingeschaltet, direkt auf dem Node-Port unter
  `/status/<name>`. Berechnet wird nur auf Abruf (30 s zwischengespeichert, komprimiert).
- Dazu `status.json`, Badges (SVG) und ein Atom-Feed je Seite; API `/api/status-pages`.

## 2.16.1 – 2026-10-20

### Geändert
- Healthchecks-Sync-Seite: Der Schalter für den Abgleich über den Cluster ist weg; die Seite zeigt nur noch, ob er an
  ist, und verweist auf die Cluster-Seite. Geschaltet wird nur noch dort.

### Behoben
- Online-Checks blieben nach einem Tag mit aufgebrauchtem Kontingent auf „Wartet“, obwohl ipv64 wieder maß und alle
  Standorte OK meldeten (hub): Steht der Gesamtzustand auf „Wartet“, bewertet der hub jetzt schon die nächste Messung
  eines Standorts neu.

## 2.16.0 – 2026-10-19

### Neu
- **Cluster** statt „lokale Gruppe“: eigener Menüpunkt, Nodes auch in verschiedenen Netzen. Healthchecks gleichen weiter über die hubs ab; über den Cluster ist es ein zusätzlicher, abschaltbarer Weg (Schalter auf der Healthchecks-Sync-Seite und unter Cluster, einzeln für Checks und Wartungsfenster; die Benachrichtigungs-Einstellungen sind unter Cluster ein eigener Punkt „Benachrichtigungen“).
- Cluster ganz ohne ipv64: Sind alle Nodes ohne ipv64-Account, laufen Checks, Messwerte, Bewertung und Benachrichtigungen rein lokal im Cluster.
- Verbindung zwischen den Nodes immer verschlüsselt (HTTPS, auch über den normalen Web-Port); ein gültiges Zertifikat ist nicht nötig.

### Geändert
- Mitglieder ohne eingeschaltete Healthchecks zählen nicht mehr für Messwerte, Benachrichtigungen und das Weiterreichen an ipv64; ausgesetzte Nodes ebenso nicht.

## 2.15.0 – 2026-10-19

### Neu
- Formular: **Von ipv64 testen** – vor dem Umstellen auf online oder hybrid messen die Standorte von ipv64 die Eingabe einmal und zeigen das Ergebnis je Standort (API: `POST /api/checks/online-test`).
- Formular: Online-Limit wie im Portal – Standorte über der Account-Klasse gesperrt, belegte Online-Messstellen angezeigt und beim Speichern geprüft.
- Liste: Filter nach Ausführungsort und Node, Konto-Leiste mit Klasse, Online-Messstellen (belegt/Limit), Verteilung online/lokal/hybrid und Nodes online.
- Detailseite: Ereignisse, die ipv64 selbst bewertet hat (z. B. nicht überwacht, wieder geprüft, teilweise gestört), erscheinen mit Wolken-Symbol neben den eigenen.
- Ereignisarten als farbige, übersetzte Kennzeichnung; Dauer und Grund bei Störungen (Detailseite und Störungsliste).

## 2.14.1 – 2026-10-19

### Behoben
- Tageskontingent aufgebraucht: Online-Checks zeigen „Kontingent aufgebraucht“ (Liste, Detailseite mit Hinweis bis Mitternacht) statt „Nicht überwacht“. Auch ipv64 bewertet sie so, still und ohne eigene Meldung je Check – die eine Meldung „Kontingent erreicht“ genügt; um Mitternacht geht es ebenso still weiter.
- Erinnerungen bei Störung: bis zu 10080 Minuten (eine Woche) wie im Portal; bisher lehnte die Node Werte über 1440 ab.
- Gründe „Nicht überwacht“ und „Tageskontingent aufgebraucht“ übersetzt; Sortierung nach Zustand kennt alle Zustände.

## 2.14.0 – 2026-10-19

### Neu
- Check-Typ **JSON**: ruft eine URL ab wie HTTP und prüft Werte in der JSON-Antwort, eine Bedingung je Zeile, z. B. `status == ok`, `queue < 100`, `items[0].up == true`, `tags contains web`, `version exists`, `name ~ ^web-[0-9]+$`. Alle Bedingungen müssen erfüllt sein, wahlweise genügt eine. Der Wert der ersten Bedingung steht in der Meldung, als Zahl auch in den Messdetails.
- Check-Typ **DNS**: fragt einen Namen ab (A, AAAA, CNAME, MX, TXT, NS, SRV, CAA, PTR, SOA) über den Standard-Resolver, einen bestimmten Server oder direkt die zuständigen Nameserver der Zone. Erwartung: irgendeine Antwort, enthält Werte, genau diese Werte, Regex, Name existiert nicht (NXDOMAIN) oder „zeigt auf meine öffentliche IP“ (für DynDNS-Domains). Optional DNSSEC-Validierung und Mindest-TTL; gemessen wird die Antwortzeit.
- Beide laufen lokal, online und hybrid. Nur lokal: private Ziele, ein DNS-Server im Heimnetz und „zeigt auf meine öffentliche IP“.

## 2.13.0 – 2026-10-19

### Neu
- Prometheus: Zustand, Antwortzeit, letzte Messung, Fehlschläge in Folge, Wartung und Zertifikatsablauf je Check
  sowie Anzahl je Zustand und offene Störungen unter `GET /api/metrics` (siehe docs/PROMETHEUS.md).

### Behoben
- Konfiguration exportieren: Gruppe und messende Nodes der Checks fehlten im Export.

## 2.12.2 – 2026-10-19

### Behoben
- Konfiguration importieren: Die Benachrichtigungskanäle der Checks zeigen auf die importierten Kanäle dieser Node. Bisher wurden die Kanal-Nummern der alten Node übernommen, sodass Checks auf einer anderen Node an falsche oder keine Kanäle meldeten (gilt für Exporte ab dieser Version).

## 2.12.1 – 2026-10-16

### Neu
- Hinweise auf Grenzen (Tageskontingent, vom hub abgelehnte Änderung wegen Online-Limit, Standorte im Formular)
  verlinken die neue Übersicht der Account-Klassen.

## 2.12.0 – 2026-10-16

### Neu
- Eigener Zustand „Nicht überwacht“: Ein Check ohne Messung seit 3 Intervallen (mindestens 5 Minuten) steht nicht mehr
  als „OK“ da, sondern als „Nicht überwacht“ (gelb gestreift) – in Liste, Filter und Kopf der Detailseite. Die
  Detailseite sagt dazu, dass alle Werte von der letzten Messung stammen (mit Zeit und damaligem Zustand) und welche
  Nodes messen. API: `state.unchecked: true` (`state.state` bleibt der Zustand der letzten Messung).
- Dashboard: nicht überwachte Checks zählen nicht mehr als „OK“, sondern in einer eigenen Kachel „Nicht überwacht“.

## 2.11.0 – 2026-10-16

### Neu
- „Wird nicht geprüft“: Misst seit 3 Intervallen (mindestens 5 Minuten) keine Messstelle einen Check mehr, etwa weil
  die einzige messende Node offline ist, ist seine Zeile in der Liste gelb markiert (Sanduhr mit der letzten Messung).
- ipv64 (hub) erkennt das selbst: Der Check geht auf „ausstehend“, und es kommt die Meldung „wird nicht mehr geprüft“
  mit den nicht erreichbaren Nodes; misst wieder jemand, „wird wieder geprüft“. Eine offene Störung bleibt dabei offen.
  Kurze Verbindungsabbrüche lösen nichts aus; nach einem Neustart oder Datenbankfehler des hub wartet die Prüfung 10 Minuten.
- Liste: Zeilen sind leicht eingefärbt – gestört rot, instabil oder teilweise gestört orange, nicht geprüft gelb.

## 2.10.0 – 2026-10-15

### Neu
- Andere Module können einen Check anlegen, auf demselben Weg wie die API (Prüfung, Sync, lokale Gruppe, Limits und Audit inklusive). Zuerst nutzt das CDN64 mit „Healthcheck für dieses Ziel anlegen“.

## 2.9.1 – 2026-10-15

### Behoben
- Lokale Gruppe: Nach „gestört“ → „teilweise gestört“ → „OK“ meldet die Gruppe „wieder erreichbar“ wie der hub
  (die Störung bleibt bis „OK“ offen, Merker `group_open`, wird in der Gruppe ausgetauscht). Bisher kam nur
  „teilweise Störung beendet“, das ohne „teilweise gestört melden“ unterdrückt wurde – das Ende fehlte.
- Meldungen, die die Node selbst schickt (Gruppe, Module): Portal-Kanäle wie Webhook oder Telegram sendet die
  Node selbst; über die ipv64-API gehen nur Mail, SMS und App (bisher Fehler 422).

## 2.9.0 – 2026-10-15

### Neu
- Stellvertreter-Nodes: Checks, die Nodes der lokalen Gruppe ohne eigene ipv64-Verknüpfung messen, erscheinen über
  die weiterreichende Node mit Zuständen und Messwerten im Portal. Benachrichtigungen bleiben bei der Gruppe; den
  Gesamtzustand solcher Checks bewertet die Gruppe auch auf verknüpften Nodes.

## 2.8.0 – 2026-10-15

### Neu
- `POST /api/checks/bulk`: Sammelaktionen per API (pausieren, fortsetzen, jetzt prüfen, löschen, Tag setzen oder
  entfernen) mit Ergebnis je Check; Sammelaktionen (auch in der Oberfläche) bekommen einen Sammeleintrag im Audit.

## 2.7.2 – 2026-10-15

### Behoben
- Der Check-Token (zugleich Berechtigung der Push-Adresse) steht in Audit und Logs nur noch gekürzt
  (erste 6 Zeichen), nicht mehr vollständig.

## 2.7.1 – 2026-10-15

### Behoben
- `PUT /api/online-checks/{token}`: nicht genannte Felder behalten ihren Wert bei ipv64 (wie `PUT /api/checks`),
  statt weggelassen zu werden.
- Audit: Einträge von Healthchecks laufen über den Kern und zeigen die Herkunft (Oberfläche oder welcher API-Key);
  das Anlegen eines Online-Checks nennt den Token, damit spätere Einträge zuzuordnen sind.

## 2.7.0 – 2026-10-14

### Neu
- JSON-API für Online-Checks im API-Modus (nur ipv64-API-Key, kein Sync): `/api/online-checks` – auflisten,
  anlegen, lesen, ändern, löschen, pausieren, fortsetzen, jetzt prüfen; gleiche Prüfung der Eingaben und gleiche
  Audit-Einträge wie in der Oberfläche.

## 2.6.2 – 2026-10-14

### Behoben
- Der erste Zustand eines neuen Checks ging verloren, wenn er beim hub ankam, bevor der Check dort angelegt war;
  bei langen Intervallen (z. B. Zertifikat) blieb der Check im Portal und auf anderen Nodes stundenlang
  „ausstehend“. Nach dem Anlegen meldet die Node den Zustand jetzt erneut.
- Audit: Als Akteur stand bei Checks und Wartungsfenstern immer „api“ (und per API-Key fälschbar) statt des
  Benutzers; die IP wird jetzt wie im Kern bestimmt (auch hinter einem Proxy).
- Audit-Einträge ergänzt für „Jetzt prüfen“ und für Online-Checks im API-Modus (anlegen, ändern, pausieren,
  fortsetzen, prüfen, löschen); Fehler dabei werden geloggt.
- Lokale Gruppe: ohne laufendes Healthchecks keine Pings mehr; die Account-Prüfung je Anfrage liest nicht mehr
  den ganzen Sync-Status; wird Healthchecks erst nach dem Start eingeschaltet, kommen die vorhandenen Checks
  trotzdem in die Gruppe.

## 2.6.1 – 2026-10-14

### Behoben
- Lokale Gruppe: Eine Node ohne Healthchecks-Sync blieb beim Übernehmen der weitergereichten hub-Daten hängen
  (sie wartete in der Datenbank auf sich selbst) und war für die Gruppe nicht mehr erreichbar.

## 2.6.0 – 2026-10-14

### Neu
- Lokale Gruppe: Eine mit ipv64 verknüpfte Node reicht die Daten vom hub an Nodes ohne Healthchecks-Sync weiter –
  den Gesamtzustand von Checks, die keine Node der Gruppe misst (z. B. Online-Checks), und die Messstellen
  außerhalb der Gruppe (ipv64-Standorte, andere Nodes) samt Verlauf. Eine Node ohne Sync zeigt so alle Checks
  vollständig an.

## 2.5.0 – 2026-10-14

### Neu
- Lokale Gruppe: Die Benachrichtigungs-Einstellungen des Accounts (Ruhezeiten, Grenzen, Sammelmeldung) werden
  zwischen den Nodes abgeglichen; Änderungen auf einer Node ohne Healthchecks-Sync gehen über die Gruppe an ipv64.
- Detailseite: „Benachrichtigt“ zeigt, wer bei einem Statuswechsel meldet (ipv64, diese Node oder eine Node der
  Gruppe).
- Die Gruppen-Karte erklärt, was abgeglichen wird, zeigt, welche Nodes mit ipv64 verknüpft sind und welche Node
  Änderungen an ipv64 weiterreicht.
- Die Auswahl der messenden Nodes steht auch ohne ipv64-Sync zur Verfügung, sobald die Node in einer Gruppe ist.

## 2.4.0 – 2026-10-14

### Neu
- Lokale Gruppe: Wartungsfenster werden zwischen den Nodes abgeglichen (anlegen, ändern, löschen auf jeder Node).
  Fenster von Nodes ohne Healthchecks-Sync reicht eine verknüpfte Node an ipv64 weiter; dasselbe Fenster vom hub
  und aus der Gruppe wird zusammengeführt, nicht doppelt angelegt.

### Behoben
- Änderungen von ipv64 liefen zwischen verknüpften Nodes der Gruppe noch einmal hin und her.
- Lehnte ipv64 eine einzelne Änderung inhaltlich ab, galt der hub als „bestätigt nicht“ und die Node verschickte
  ihre Meldungen selbst; das gilt jetzt nur noch bei einem echten Ausfall (Datenbankfehler, keine Antwort).
- Gruppen-Benachrichtigung: Übernahm eine Node bei Ausfall der meldenden, konnte ihr ein Wechsel entgehen (z. B.
  die Entwarnung), weil sie den Zustand einer anderen Node übernommen hatte. Den gemeldeten Zustand schreibt jetzt
  nur die meldende Node.

## 2.3.0 – 2026-10-14

### Neu
- Lokale Gruppe: Messen mehrere Nodes der Gruppe einen Check, benachrichtigt genau eine – die erste erreichbare
  in der Liste der messenden Nodes (die Besitzer-Node, fällt sie aus, die nächste). Gemeldet wird der
  Gesamtzustand aller Messstellen wie bei ipv64 (inkl. „teilweise gestört“, wenn eingeschaltet). Kommt eine Node
  zurück, übernimmt sie den Stand der Gruppe und meldet nichts doppelt.
- Ohne ipv64-Sync oder für Checks, die ipv64 nicht kennt, gehen diese Meldungen über die Kanäle der meldenden
  Node (ipv64-Mail/-SMS über den API-Key); sonst meldet weiter ipv64.
- Die Nodes der lokalen Gruppe stehen bei den messenden Nodes zur Auswahl (auch ohne ipv64-Sync).

### Behoben
- Erinnerungen („noch gestört“) schickte auch eine Node, die den Check nicht misst oder nicht besitzt.

## 2.2.0 – 2026-10-14

### Neu
- Lokale Gruppe: Messwerte und Zustände werden zwischen den Nodes ausgetauscht. Jede Node zeigt die Checks der
  anderen mit aktuellem Zustand, Messstellen-Tabelle und Diagramm (eine neue Node bekommt die letzten 24 h).
- Ohne Healthchecks-Sync (oder für Checks, die ipv64 nicht kennt) bestimmt die Node den Gesamtzustand aus den
  Messstellen der Gruppe nach derselben Regel wie ipv64, inklusive Störungen. Ist die messende Node nicht
  erreichbar, wird der Zustand nach 2 Minuten „ausstehend“; eine offene Störung bleibt offen.

## 2.1.0 – 2026-10-14

### Neu
- Lokale Gruppe: Nodes desselben ipv64-Accounts im lokalen Netz gleichen ihre Checks untereinander ab (anlegen,
  ändern, löschen auf jeder Node, nach wenigen Sekunden überall). Die jüngere Änderung gewinnt; Kanäle bleiben je
  Node eigene Einstellung.
- Änderungen von Nodes ohne Healthchecks-Sync reicht eine verknüpfte Node der Gruppe an ipv64 weiter. Checks, die
  nur auf Nodes ohne Sync gemessen werden, bleiben in der Gruppe.

### Behoben
- Ohne Sync (nur API-Key) erschienen Online-Checks, die aus der Gruppe kamen, doppelt in der Übersicht.

## 2.0.0 – 2026-10-14

Healthchecks 2.0: erste vollständige Fassung in Node64, lokal und zusammen mit den ipv64-hubs.

### Neu
- Check-Arten HTTP(S), Schlüsselwort, Ping, TCP-Port, DNS, Zertifikatsablauf, Push und Docker-Container (Socket/TCP); Port nur im Port-Feld, host:port im Ziel wird übernommen.
- Messstellen je Check: Lokal, Online (ipv64-hubs), Hybrid und mehrere messende Nodes; Anzeige, wo ein Check gemessen wird (Online, Hybrid, Lokal, Andere Node).
- Healthchecks-Sync mit ipv64: Verknüpfung per Code oder mit einem Klick über den API-Key, Postausgang und Konflikte, alles von jeder Node änderbar (Checks, Kanäle, Wartung, Jetzt prüfen über den hub).
- Online-Checks auch ohne Sync direkt über die ipv64 API v2 (nur API-Key).
- Tageskontingent der Online-Checks wie im alten System: Vorschau im Formular, Hochrechnung im Dashboard, Benachrichtigung beim Erreichen.
- Übersicht mit Ziel-Badges, Gruppen, Filtern, Massenaktionen und Countdown bis zur nächsten Messung; Ansicht für Handy und Tablet.
- Detailseite mit Diagramm je Messstelle (Legende filtert), Ereignissen mit Grund- und HTTP-Code, Störungen und Wartungsfenstern.
- Verlauf fremder Messstellen wird vom hub nachgeladen (Einzelmessungen 2 Tage, Stundenwerte 90 Tage).
- Benachrichtigungen über die Kanäle des Kerns, Browser-Benachrichtigungen; Datenhaltung und Diagramm-Auflösung einstellbar.
- Lokale API `/api/healthchecks/*` mit OpenAPI-Doku; Export/Import.

### Behoben während der Abnahme
- Online-Checks und Checks anderer Nodes kamen in den lokalen Scheduler.
- Historie fremder Messstellen ging beim Ändern der Messstellen verloren.
- Besitz eines Checks blieb bei einer Node, die ihn nicht mehr misst; er geht jetzt an die erste messende Node.
