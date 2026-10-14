# Änderungen – Healthchecks

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
