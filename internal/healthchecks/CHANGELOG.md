# Änderungen – Healthchecks

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
