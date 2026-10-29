# Lokale Gruppe (Node64)

> **Ab 2026-10-19 heißt die lokale Gruppe „Cluster“** (eigener Menüpunkt `/cluster`, Healthchecks 2.16.0). Neu:
> Nodes auch in verschiedenen Netzen, nur HTTPS (mit Bindung an die Kopplung, Zertifikat muss nicht gültig sein),
> gleicher ipv64-Account oder alle ohne (dann alles rein lokal), Aussetzen bei grundlegender Änderung, Schalter je
> Modul und Bereich, Zertifikate als erstes weiteres Modul (`/peer/v2/sync`). Plan und Schnittstellen:
> [PLAN-NODE64-CLUSTER.md](PLAN-NODE64-CLUSTER.md). Der Healthchecks-Ablauf unten gilt weiter.

Stand 2026-10-14 (Healthchecks 2.6.0). Beschreibt, was im Betrieb wirklich passiert. Code: `internal/peer`
(Protokoll, Abgleich, Rollen) und in `internal/healthchecks` die Dateien `peersync.go`, `peerdata.go`,
`peermaint.go` und `groupnotify.go`.

## Wozu

Mehrere Nodes desselben ipv64-Accounts im lokalen Netz gleichen Healthchecks direkt untereinander ab. Das geht
mit und ohne Healthchecks-Sync zu ipv64. Eine Node ohne Sync (nur API-Key) sieht und bearbeitet so dieselben
Checks wie die verknüpften, und die Gruppe benachrichtigt auch dann, wenn ipv64 nicht erreichbar ist.

## Mitgliedschaft und Sicherheit

- **Erreichbarkeit:** nur per IP im LAN, über den normalen Web-Port. Es gibt keinen Extra-Port; die Endpunkte
  liegen unter `/peer/v1/` und sind von Sitzung und CSRF ausgenommen.
- **Account:** nur Nodes desselben ipv64-Accounts. Er kommt aus dem Healthchecks-Sync oder ersatzweise aus dem
  API-Key. Ohne Account gibt es keine Gruppe.
- **Beitritt:** mit einem Code, den eine Node der Gruppe anzeigt.
  - Der Code hat 8 Zeichen, gilt 10 Minuten, nur einmal und erlaubt 5 Versuche.
  - Er wird erst verbraucht, wenn alle Prüfungen bestanden sind; eine Node mit anderem Account verbraucht ihn
    nicht.
  - Der Austausch ist mit HMAC über den Code gesichert, eine Nonce bindet die Antwort an die Anfrage.
- **Schlüssel:** Jede Node hat einen Ed25519-Schlüssel; er liegt verschlüsselt in `peer.key`.
- **Jede Anfrage** ist signiert über Methode, Pfad, Zeit, Account und den Hash des Inhalts. Die Uhrzeit darf
  höchstens 5 Minuten abweichen, und der Account wird jedes Mal geprüft. Wechselt eine Node den Account,
  scheitern ihre Anfragen in alle Richtungen.
- **Mitgliederliste:** Neue und entfernte Mitglieder erfahren alle per Weitermeldung. Ein Ping läuft alle 30 s,
  und jede gültige Anfrage gilt als Lebenszeichen. Online heißt: innerhalb der letzten 2 Minuten erreicht.

## Was abgeglichen wird

| Was | Wie | Konfliktregel |
| --- | --- | --- |
| Checks | Änderungsprotokoll `peer_log` je Node (nur der letzte Stand je Eintrag); die anderen holen ab ihrem Stand ab, angestoßen per `/peer/v1/poke`, sonst alle 15 s | jüngere Änderung gewinnt, der Zeitpunkt bleibt beim Weiterreichen erhalten; ein Löschvermerk hält ältere Änderungen ab |
| Wartungsfenster | wie Checks, mit fester Kennung `uid` (die lokale Nummer ist je Node verschieden) | wie Checks; dasselbe Fenster unter zwei Kennungen wird über die Server-ID zusammengeführt; gelöscht wird nur mit echtem Löschvermerk `m:<uid>` |
| Benachrichtigungs-Einstellungen (Ruhezeiten, Grenzen, Sammelmeldung) | als ein Paket, erkannt an der Änderung des Inhalts | jüngeres Paket gewinnt; eine verknüpfte Node bringt beim ersten Mal die Einstellungen des Accounts mit |
| Messwerte | `/peer/v1/measurements`: eigene Messpunkte ab einer Nummer, eine neue Node bekommt zuerst die letzten 24 h | doppelte Punkte werden verworfen |
| Zustände | mit dem ersten Abruf jeder Runde | gelten 2 Minuten bzw. 3 × Intervall nach der letzten Messung |
| Daten vom hub (nur für Nodes ohne Sync) | `/peer/v1/relay` bei der weiterreichenden Node: Gesamtzustand der Checks, die keine Node der Gruppe misst, und Messstellen außerhalb der Gruppe samt Messpunkten (erster Abruf: 24 h) | was ein Mitglied selbst misst, kommt von ihm |

**Kanäle** bleiben je Node eigene Einstellung und werden nicht abgeglichen.

**Ablage:** Messpunkte anderer Nodes landen wie die Daten vom hub als Messstelle `node:<id>`. Messstellen-Tabelle,
Diagramm und Verlauf funktionieren dadurch unverändert.

## Zusammenspiel mit ipv64

- **Änderungen vom hub:** Verknüpfte Nodes bekommen sie direkt vom hub und übernehmen sie nicht noch einmal aus der
  Gruppe, damit nichts hin und her pendelt.
- **Änderungen von Nodes ohne Sync:** Genau eine verknüpfte Node reicht sie an den hub weiter. Ist eine solche Node
  erreichbar, kann eine Node ohne Sync auch Online- und Hybrid-Checks anlegen, ändern und verschieben (Healthchecks
  2.42.0, `SetViaCluster`); ohne sie bleibt es bei lokalen Checks bzw. den Online-Checks über die API v2. Das ist die mit
  der kleinsten Kennung unter den erreichbaren verknüpften Nodes; die Gruppen-Karte zeigt, welche es ist.
- **Checks von Nodes ohne Sync (Stellvertreter-Nodes):** Die weiterreichende Node meldet alle Mitglieder ohne
  Sync beim hub als Stellvertreter-Nodes an (`hc2_nodes.proxy_via` = ihre Kennung, kein Token) und reicht deren
  Zustände und Messpunkte weiter (Nachrichten `proxies` und `proxy_data`, alle 15 s). Damit erscheinen auch
  Checks, die solche Nodes messen, mit Messwerten im Portal. Checks, die bisher in der Gruppe blieben, schickt sie
  einmal an den hub, sobald er das Mitglied führt – und erneut, wenn das Mitglied nach einer Pause (Cluster verlassen,
  widerrufen) wieder Stellvertreter-Node wird; so kommen auch Änderungen aus der Zwischenzeit ins Portal.
  - Der hub zeigt diese Checks nur an und benachrichtigt nicht (auch keine Erinnerungen): das macht weiter die
    Gruppe, sonst käme jede Meldung doppelt.
  - Online ist eine Stellvertreter-Node, solange die weiterreichende Node sie als erreichbar meldet (nach 3 Minuten
    ohne Meldung offline, wie bei verknüpften Nodes).
  - Verlässt ein Mitglied die Gruppe oder verknüpft es sich selbst, nimmt die weiterreichende Node es aus der Liste;
    der hub widerruft dann die Stellvertreter-Node. Im Portal entfernt, legt die nächste Meldung sie wieder an.
  - Ohne weiterreichende Node (keine verknüpfte Node erreichbar) bleibt alles in der Gruppe wie bisher.
- **Wartungsfenster** von Nodes ohne Sync gehen über die weiterreichende Node an den hub. Nach der Bestätigung
  erfährt die Gruppe die Server-ID.
- **„hub bestätigt nicht“** gilt nur bei einem Datenbankfehler des hub oder wenn keine Antwort kommt. Eine
  inhaltliche Ablehnung einzelner Änderungen zählt nicht.

## Gesamtzustand

- **Mit hub:** Der hub bewertet, wenn die Node verknüpft ist und alle messenden Nodes verknüpft sind. Misst eine
  Stellvertreter-Node mit, bewertet die Gruppe; der Gesamtzustand vom hub wird dann nicht übernommen.
- **Ohne hub:** Sonst bewertet die Node selbst, mit `scheduler.Overall` wie der hub und mit den Regeln „alle“,
  „eine“ oder „Mehrheit“, und führt dabei auch die Störungen.
- **Messende Node nicht erreichbar:** Nach 2 Minuten ist der Zustand „ausstehend“. Eine offene Störung bleibt
  offen, die letzte Messung bleibt stehen.

## Benachrichtigungen

- **Eine messende Node:** Diese Node meldet, oder ipv64, wenn sie verknüpft ist. Das ist das bisherige
  Verhalten.
- **Mehrere messende Nodes der Gruppe**, und der hub meldet nicht: Genau eine Node meldet, die erste erreichbare
  in der Liste der messenden Nodes. Das ist die Besitzer-Node; fällt sie aus, übernimmt die nächste.
  - Gemeldet wird der Gesamtzustand aller Messstellen, mit denselben Ereignisarten wie beim hub. „Teilweise
    gestört“ wird nur gemeldet, wenn es am Check eingeschaltet ist.
  - Den gemeldeten Zustand (`hc_checks.group_state`) schreibt nur die meldende Node. Die anderen übernehmen ihn
    beim Abgleich (jüngerer gewinnt), damit die nächste beim Übernehmen weiß, was schon gemeldet ist.
  - Nach dem Start bewertet eine Node erst nach dem ersten Abgleich, damit eine zurückkehrende Node nichts
    doppelt meldet.
  - Die Meldung geht über die Kanäle der meldenden Node; ipv64-Mail und -SMS laufen dabei über den API-Key.
- **Erinnerungen („noch gestört“)** schickt nur die Node, die an der Reihe ist bzw. den Check misst und besitzt.
- **Anzeige:** Auf der Detailseite steht unter „Benachrichtigt“, wer meldet: ipv64, diese Node oder eine Node der
  Gruppe.

## Bekannte Grenzen

- Teilt sich das LAN so, dass zwei Teile einander nicht mehr erreichen, hält sich in jedem Teil eine Node für
  zuständig. Es kann dann doppelte Meldungen geben.
- Eine Node, die die Gruppe verlässt, behält ihre Kopien der Checks der anderen. Sie werden dort nicht mehr
  aktualisiert.
- Ändern zwei Nodes dasselbe innerhalb derselben Millisekunde, ist das Ergebnis zufällig. Es ist aber auf allen
  Nodes gleich.
