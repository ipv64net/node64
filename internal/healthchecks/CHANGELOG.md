# Änderungen – Healthchecks

## 2.42.0 – 2026-10-29

### Behoben
- Verknüpfte Node: Eine Änderung aus dem Portal oder der API (z. B. neuer Online-Check), die im selben Moment wie
  eine Änderung an dieser Node entstand, kam auf dieser Node nie an – auch nicht nach einem Neuverbinden. Der Stand
  springt jetzt nur noch direkt anschließend weiter (Node und hub).

### Neu
- Cluster: Eine nicht verknüpfte Node kann Online- und Hybrid-Checks anlegen, ändern und dorthin verschieben, wenn
  eine verknüpfte Node des Clusters erreichbar ist (sie reicht die Änderung an ipv64 weiter). Vorher lehnte sie das ab
  („need the ipv64 link“), auch beim bloßen Umbenennen eines Online-Checks.
- Proxmox VE und Docker: „Gestoppt ist richtig“ – an einem Gast bzw. Container, der als gestört gilt, weil er
  gestoppt bzw. beendet ist (Zeile der Systemseite und Seite des Gasts). Setzt „Gestoppt ist eine Störung“ auf nein:
  sofort in Ordnung, eine gemeldete Störung erledigt sich still (keine Entwarnung), die letzte Störung auf der
  Startseite verschwindet, wenn es dieser Gast war. Zurücknehmen in den Einstellungen des Gasts. Audit `proxmox.ack`;
  API über die Einstellungen (`expect_running: false`). Das gilt auch, wenn die Einstellung von Hand bzw. per API auf
  nein gesetzt wird.

### Behoben
- Proxmox VE: Ein Backup, das einen gestoppten Gast kurz startet (Lock `backup`), machte ihn zum „lief schon
  einmal“ – danach meldete Node64 „gestoppt“, obwohl sich nichts geändert hatte. Laufen mit Lock und die Abfrage direkt
  nach einem Lock zählen nicht mehr als Lauf (Messwerte werden weiter aufgezeichnet).

## 2.41.0 – 2026-10-28

### Neu
- Cluster: Statusseiten lassen sich abgleichen (Bereich „Statusseiten“, standardmäßig aus) – mit Gruppen, Checks in
  ihrer Reihenfolge, Optionen, Sichtbarkeit, Passwort, Logo und Ankündigungen. PROXY64-Hosts einer Statusseite
  bleiben je Node. Gleicher Slug mit anderem Inhalt wird nicht übernommen (Hinweis im Log).
- Cluster: Benachrichtigungskanäle lassen sich abgleichen (Bereich „Kanäle“ unter Benachrichtigungen, standardmäßig
  aus) – nur die eigenen Kanäle der Node samt Zugangsdaten (auf der anderen Node mit deren Schlüssel gespeichert),
  nie die des Portals, nicht der Browser-Kanal und keine mit „Geheimnis nur lokal“. Die Kanäle der Checks stimmen
  dann auf jeder Node. Nötig vor allem für Nodes ohne Verbindung zu ipv64.net.

### Geändert
- Proxmox VE und Docker: Checks zeigen eine echte Latenz statt 0 ms bzw. der Zeit der Docker-API – Ping zur Adresse
  des Nodes, Gasts bzw. Containers (ein Paket, höchstens 2 s), sonst die Antwortzeit der Proxmox- bzw. Docker-API.
  Die Quelle steht im Rohergebnis (`latency_source`: `ping` oder `api`). Der Status bleibt unverändert, ein
  fehlgeschlagener Ping macht keinen Check rot.
  - Proxmox: Node-Adressen aus `cluster/status`; Adressen laufender Gäste als Check alle 5 Minuten über den Gast-Agent
    (VMs, Recht `VM.Monitor` bzw. ab PVE 9 `VM.GuestAgent.Audit`) bzw. `lxc/{vmid}/interfaces` (Container).
- Cluster: Was auf zwei Nodes schon vorher exakt gleich angelegt war (Statusseite, Kanal, Proxmox-System,
  Docker-Host, Wartungsfenster), wird beim Beitreten bzw. Einschalten des Bereichs zu einem Eintrag zusammengeführt
  statt doppelt angelegt. Nur ähnliche Einträge bleiben getrennt. Checks werden nie zusammengeführt (gleicher Check
  auf zwei Nodes = zwei Messstellen).

## 2.40.0 – 2026-10-28

### Geändert
- Benachrichtigungen direkt über die ipv64 API: Checks, die nur diese Node misst (lokal, keine weiteren Messstellen),
  meldet die Node auch verknüpft selbst – ipv64-Mail, -SMS und App über die API v2, eigene Kanäle direkt (bisher per
  Sendeauftrag über den hub). Das gilt für Ausfall, Entwarnung, Flattern und Erinnerungen.
  - Andere Portal-Kanäle (z. B. Webhook, Telegram) sendet weiter der hub, ihre Geheimnisse liegen nur bei ipv64. Für
    solche Checks schickt der hub jetzt auch Erinnerungen an diese Kanäle.
  - Checks mit Online-Messung oder mehreren messenden Nodes (auch im Cluster) sowie „wird nicht geprüft“ melden wie
    bisher.
  - Nur mit API-Key und neuem hub; sonst wie bisher.

## 2.39.0 – 2026-10-28

### Behoben
- Wartungsfenster: Ein Ausfall, der in der Wartung beginnt und danach andauert, wird gemeldet; Erinnerungen und
  Gruppenmeldungen pausieren in der Wartung; wiederkehrende Fenster behalten nach der Zeitumstellung ihre Uhrzeit.
- Abhängige Checks melden den Ausfall, sobald der übergeordnete Check wieder läuft; Flattern, das gestört endet, kommt
  als Ausfall statt „wieder stabil“.
- Störungen werden zuverlässig beendet (Flattern, Pause/Fortsetzen, Besitzerwechsel) und nicht doppelt angelegt; Push
  verliert bei abgebrochenen Anfragen nichts mehr.
- Statusseiten: Ohne „Verfügbarkeit zeigen“ bzw. „Verlauf zeigen“ fehlen diese Daten auch in JSON und Badges.
- Verlaufswerte am Rand der Aufbewahrung werden nicht mehr verfälscht; übernommene Messwerte anderer Messstellen gehen
  nicht mehr als eigene an ipv64.
- ICMP: Ein verlorener Ping zählt als Paketverlust statt als Zeitüberschreitung; HTTP/Keyword/JSON beachten einen
  eigenen Host-Kopf (samt SNI).
- Benachrichtigungen: Vorübergehende Fehler werden bei allen Kanaltypen erneut zugestellt, nicht mehr an gelöschte oder
  geänderte Kanäle; Fehlertexte gekürzt.
- Docker über unix-Socket: keine liegen gebliebenen Verbindungen mehr.

## 2.38.1 – 2026-10-27

### Behoben
- Docker- und Proxmox-Checks liefen nach dem Entfernen ihrer Node im Portal online bei ipv64 (Nürnberg, Falkenstein).
  Das Portal stellte beim Entfernen alle Checks ohne privates Ziel auf „online“ um. Ein Container- oder Gastname zählt
  aber nicht als privates Ziel.
  - Jetzt misst der hub Docker- und Proxmox-Checks nie online, auch wenn sie so in der Datenbank stehen.
  - Das Portal stellt sie nie auf online um und löscht sie stattdessen mit der Node. Proxmox gilt dort jetzt wie
    Docker als „nur auf der Node“.
  - Ein Job im Portal (alle 10 Minuten) holt solche Checks auf die Node zurück, die sie zuletzt gemessen hat.
- Im Portal lässt sich ein Docker- oder Proxmox-Check mit mehreren messenden Nodes aus dem Cluster wieder bearbeiten.

## 2.38.0 – 2026-10-27

### Neu
- Proxmox VE und Docker im Cluster: Unter Cluster → Healthchecks gibt es die Bereiche „Proxmox VE“ und „Docker“
  (ohne Einstellung aus).
  - Ist ein Bereich auf zwei Nodes an, gehen die Systeme samt API-Token bzw. Zugangsdaten an die andere Node. Dort
    werden sie mit deren Schlüssel verschlüsselt gespeichert und ebenfalls abgefragt. Anlegen, Ändern und Löschen
    werden abgeglichen.
  - Docker nur für Hosts über das Netz (`tcp://`, `http(s)://`, `ssh://`); der lokale Socket bleibt bei seiner Node.
  - Docker- und Proxmox-Checks können dann mehrere messende Nodes haben: Im Formular sind die Nodes wählbar, die den
    Bereich (und die Checks) ebenfalls abgleichen. Abgleich, Bewertung und Benachrichtigung wie bei allen Checks des
    Clusters; die Node, die den Check angelegt hat, bleibt vorn.
  - Meldungen der Überwachung selbst (Gast gestoppt, Schwellen, System nicht erreichbar) schickt nur die Node, die das
    System angelegt hat; ist sie nicht erreichbar, die erreichbare Node mit der kleinsten Kennung. Nichts kommt doppelt.
  - Jedes System hat dafür eine Kennung im Cluster (`uid`), Proxmox-Checks tragen sie als `params.system_uid`; ältere
    Checks bekommen sie beim Start.
- hub: Docker- und Proxmox-Checks behalten die messenden Nodes, die die Node schickt (bisher immer nur die
  Besitzer-Node). Nicht umhängbar und nie online bleiben sie.

## 2.37.3 – 2026-10-27

### Geändert
- Dashboard: Die Kacheln von Healthchecks, Proxmox VE und Docker sind kompakter. Zahl und Bezeichnung stehen in einer
  Zeile, kleineres Symbol, weniger Abstand. Die Karte braucht etwa halb so viel Höhe.

## 2.37.2 – 2026-10-26

### Geändert
- Dashboard: Unter den Healthchecks-Kacheln stehen jetzt eigene Kachelzeilen für Proxmox VE (Systeme ok/gestört,
  Gäste laufend/gestört) und Docker (Hosts ok/gestört, Container laufend/gestört), jeweils mit Link, Hinweis bei
  nicht erreichbaren Systemen und letzter Störung. Die bisherige einzelne Proxmox-Karte entfällt; Docker hatte bisher
  keine.

## 2.37.1 – 2026-10-26

### Geändert
- Kanäle eindeutig: Bei Checks „als Check“ (Docker-Container, Proxmox-VMs) legst du die Kanäle nur noch am Host bzw.
  Container fest. „Check bearbeiten“ zeigt sie dort nur an, mit Link und den wirksamen Kanälen. Bisher ließen sie sich
  auch am Check ändern, und das nächste Speichern der Regeln überschrieb sie wieder.
- Ohne Haken nennt das Check-Formular jetzt die Standardkanäle, die dann gelten (wie die Detailseite). Bei Host,
  Node und Container steht bei „geerbt: Standardkanäle“ ebenfalls, welche das sind.


## 2.37.0 – 2026-10-26

### Neu
- Statusseiten: Schalter „Nach Gruppen der Healthchecks gliedern“ (Standard an). Aus zeigt die Seite eine Liste ohne
  Überschriften – Gruppennamen und Namen von Proxmox-VE- und Docker-Systemen bleiben dann intern.

### Behoben
- Checks, die eine neuere Node oder ipv64.net mit zusätzlichen Parametern schreibt (z. B. den Systemnamen), werden
  übernommen statt abgelehnt; unbekannte Felder fallen dabei weg.
- Docker „als Check“: Der Name des Docker-Hosts (Gruppierung) bleibt beim Bearbeiten und beim Ändern der Adresse des
  Hosts erhalten, auch wenn der Host gerade nicht erreichbar ist.
- Neuer Check aus System: Nach einem Eingabefehler bleibt die gewählte VM bzw. der Container ausgewählt, auch wenn ein
  anderes System einen Eintrag mit derselben Kennung hat.


## 2.36.2 – 2026-10-26

### Geändert
- Docker wie Proxmox VE: Wird die Überwachung eines Docker-Hosts ausgeschaltet (Pause), sind seine Container „als
  Check“ pausiert und erscheinen so in der Check-Liste; beim Einschalten laufen sie wieder. Bisher prüften sie (außer
  bei SSH/TLS) weiter selbst und blieben „in Ordnung“.

## 2.36.1 – 2026-10-26

### Geändert
- Statusseite bearbeiten: „Einträge“ und „Checks hinzufügen“ stehen auf breiten Bildschirmen nebeneinander (darunter
  untereinander).

## 2.36.0 – 2026-10-26

### Geändert
- Statusseiten: Eigene Gruppen der Seite entfallen. Die Seite gruppiert immer nach den Gruppen der Healthchecks, in
  „Proxmox VE“ und „Docker“ mit dem Namen des Systems („Proxmox VE · Cluster“). Alte Seiten zeigen damit sofort diese
  Gruppen; Auswahl, Reihenfolge und Anzeigenamen der Einträge bleiben.
- Bearbeiten: „Einträge der Seite“ ist eine einfache Liste (Name, Gruppe, Anzeigename, Entfernen). „Checks hinzufügen“
  ist eine einzige Liste für alle Checks und für Nodes, VMs, LXC und Container ohne Check – mit Suche (auch nach dem
  System), Filter nach Gruppe und Tag, „Sichtbare auswählen“ und „Ausgewählte hinzufügen“. Einträge ohne Check werden
  beim Hinzufügen wie bisher als Check angelegt. Der Schalter „Gruppen der Healthchecks übernehmen“ entfällt.

## 2.35.0 – 2026-10-26

### Neu
- Checks „als Check“ aus Proxmox VE und Docker tragen den Namen ihres Systems in den Parametern (`system`: Clustername
  bzw. Name des Systems, Name des Docker-Hosts). Die Node hält ihn bei jedem Abruf aktuell; er geht per Sync zu ipv64,
  wo das Portal die Checks genauso in Untergruppen einsortiert. Andere Nodes zeigen damit auch fremde Checks unter dem
  Namen des Systems (Docker mit der Node).

## 2.34.0 – 2026-10-26

### Neu
- Check-Liste: In den Gruppen „Proxmox VE“ und „Docker“ gibt es je Proxmox-System bzw. Docker-Host eine eigene
  aufklappbare Untergruppe mit Zählern. Der Name kommt bei jedem Aufruf aus der Überwachung: bei Proxmox der
  Clustername aus dem letzten Abruf (sonst der Name des Systems), bei Docker der Name des Hosts. Checks einer anderen
  Node stehen unter deren Namen. Der Auf-/Zu-Zustand wird im Browser gemerkt.

### Behoben (ipv64)
- Proxmox- und WHOIS-Checks wurden beim Healthchecks-Sync abgelehnt („database error“): Der Datenbank bei ipv64
  fehlten die Typen. SQL `hc2_check_types_proxmox_whois.sql` – danach im Healthchecks-Sync „Erneut senden“.

## 2.33.0 – 2026-10-26

### Neu
- Neuer Check aus einem überwachten System: Beim Typ stehen „Proxmox VE (VM, Container, Node)“ und
  „Docker-Container“. Danach wählt man das Proxmox-System bzw. den Docker-Host und die Maschine bzw. den Container aus
  dem letzten Abruf. Angelegt wird wie mit „Als Check führen“ (Intervall, Gruppe und Kanäle aus den Regeln, keine
  doppelte Meldung); der Name ist optional (leer = „System – Name“). Schon geführte Einträge sind markiert und
  gesperrt. „Container überwachen“ auf der Seite eines Docker-Hosts wählt den Host gleich vor.

### Geändert
- Der rohe Typ „Docker-Container“ (Containername von Hand) steht bei neuen Checks nicht mehr zur Wahl. Vorhandene
  Docker-Checks bleiben und lassen sich weiter bearbeiten; API und Import unverändert.

## 2.32.0 – 2026-10-26

### Geändert
- Docker wie Proxmox VE: Die Seite beginnt immer mit der Übersicht der überwachten Docker-Hosts (Kacheln, Tabelle mit
  Zustand, Containern, CPU/RAM, Bearbeiten, Aus, Löschen), auch mit nur einem Host; erst ein Klick führt zum Host.
- Der lokale Docker-Socket wird nicht mehr automatisch überwacht. Er kommt erst dazu, wenn er hinzugefügt wird
  (Formular „Docker-Host hinzufügen“ oder Knopf „Diese Maschine hinzufügen“ in der Übersicht). Ohne Host zeigt die
  Übersicht einen Einstieg wie Proxmox VE und verweist auf vorhandene Docker-Checks in der Check-Liste. Bestehende
  Hosts bleiben eingerichtet.
- Die Host-Seite zeigt den Namen des Hosts und hat einen Knopf zum Löschen; danach geht es zurück zur Übersicht.
- Zustand eines Systems (Docker und Proxmox VE): „Hinweis“ heißt jetzt „teilweise gestört“ (einzelne Container, Gäste
  oder Nodes gestört), daneben „in Ordnung“ und „nicht erreichbar“.

## 2.31.0 – 2026-10-26

### Neu
- Check-Typ **WHOIS / RDAP**: Registrierungsdaten einer Domain, einer IP-Adresse bzw. eines Netzes oder eines AS
  (AS3320). Zuerst per RDAP (zuständiger Server über den IANA-Bootstrap), sonst per klassischem WHOIS über Port 43
  (Kette whois.iana.org → Registry, z. B. für .de). Die gefundenen Angaben stehen unter „Letzte Messung“: bei Domains
  Registrar, Status, Nameserver, Registrierung, letzte Änderung und Ablauf; bei Netzen und AS Name (netname), Bereich,
  CIDR bzw. Route, Ursprungs-AS, Organisation, Land, Stadt/Adresse und Abuse-Kontakt.
- Gestört, wenn die Abfrage scheitert, die Domain nicht (mehr) registriert ist, sie in weniger als „Warnen vor Ablauf“
  Tagen abläuft (Standard 14) oder eine erwartete Angabe fehlt (z. B. „nameserver: ns1.ipv64.net“, „country: DE“).
- Rücksicht auf die Server: höchstens stündlich, im gestörten Zustand alle 10 Minuten; begrenzte Antwortgröße.
  Läuft lokal und online bei ipv64.

## 2.30.0 – 2026-10-26

### Behoben
- Healthchecks-Sync, Konflikte: Ein Konflikt entsteht, wenn ipv64 eine Änderung dieser Node ablehnt. Bisher fehlte der
  Grund, jede Karte zeigte „vom Server gelöscht“, und „Server-Version behalten“ löschte den Eintrag hier – auch einen
  Check, den ipv64 längst hat (z. B. einen Proxmox- oder Docker-Check). „Meine Version senden“ führte zur selben
  Ablehnung. Jetzt:
  - Die Karte nennt den Grund der Ablehnung und zeigt den aktuellen Stand bei ipv64 (der hub schickt ihn mit).
  - „ipv64-Stand übernehmen“ stellt diesen Stand hier wieder her; „Hier löschen“ gibt es nur, wenn ipv64 den Eintrag
    wirklich nicht hat.
  - „Erneut senden“ schickt die eigene Fassung noch einmal (z. B. nachdem das Limit erhöht wurde).
  - Neu: „Nur hier behalten“ – die Änderung bleibt auf der Node und geht nicht mehr an ipv64.
  - Ältere Konflikte ohne gespeicherten Grund werden nie gelöscht; „Erneut senden“ holt Grund und Stand nach.
- „{count} Konflikte“ zeigte den Platzhalter statt der Zahl.

## 2.29.1 – 2026-10-25

### Geändert
- Check-Formular, „Messstellen und Bewertung“: Bei „lokal auf Nodes“ sind die Online-Standorte (Nürnberg, Falkenstein) und der Test bei ipv64 ausgeblendet; sie erscheinen nur bei „online“ oder „beides“.
- Online-Messung bei ipv64: Ziele müssen öffentlich erreichbar sein – auch ein Hostname, eine Weiterleitung oder ein DNS-Server darf nicht auf eine interne Adresse zeigen. Timeouts höchstens 30 s (Verbindung) bzw. 60 s (gesamt), Wiederholung bei Störung frühestens nach 20 s.

## 2.29.0 – 2026-10-25

### Neu
- Benachrichtigungen über SecNtfy (secntfy.app): Push-Nachrichten Ende-zu-Ende verschlüsselt – Titel und Text werden mit dem öffentlichen RSA-Schlüssel des Geräts verschlüsselt, nur das Gerät kann sie lesen. Geräte-Token (NTFY-DEVICE-…) eintragen, Server änderbar (Vorgabe api.secntfy.app), Störungen auf Wunsch als kritischer Alarm. In der Node und im Portal (Versand über die hubs).
- Ein verschlüsselter Block fasst wenig: Nur bei SecNtfy werden lange Meldungen gekürzt (Text höchstens 150 Zeichen, Titel passend zum Schlüssel), alle anderen Kanäle bekommen sie vollständig.

## 2.28.1 – 2026-10-25

### Behoben
- Proxmox VE, Systemseite: Die Kacheln „Gäste“ und „Gäste laufend“ zeigten statt der Anzahl die rohe Gästeliste (`[{qemu …`). Jetzt steht dort die Zahl.

## 2.28.0 – 2026-10-24

### Neu
- E-Mail und SMS über ipv64 sind mit dem API-Key in der normalen Kanaltabelle der Benachrichtigungen verwaltbar wie
  alle anderen Kanäle: anlegen, bearbeiten, an/aus, Standard, Test, löschen und die Bestätigung per Code direkt in der
  Node (Badge „ipv64“, unbestätigte mit Badge und Link zum Bestätigen). Gespeichert sind sie bei ipv64 und gelten für
  den ganzen Account. Die eigene Karte dafür entfällt.

### Geändert
- Die Karte „Browser-Benachrichtigungen“ steht halb breit unter der Kanaltabelle.

## 2.27.1 – 2026-10-24

### Geändert
- Benachrichtigungen mit API-Key (ohne Verknüpfung): Statt „SMS/E-Mail über ipv64 – nach Verknüpfung“ zeigt die Seite
  die bestätigten E-Mail- und SMS-Kanäle des Accounts (nur lesen) und einen Link zum Anlegen auf ipv64.net; die Node
  nutzt sie über den API-Key.
- iGotify ist kein eigener Kanaltyp mehr (es ist ein normaler Gotify-Server); vorhandene iGotify-Kanäle werden zu Gotify.
  Der Gotify-Kanal nennt iGotify fürs iPhone im Hinweis.
- Ohne Verknüpfung mit dem Healthchecks-Sync gehen jetzt auch die Meldungen der Healthchecks (nicht nur die der
  Module) über den API-Key an E-Mail, SMS und App des Accounts; die ipv64-App ist dabei als Kanal mit dabei.

### Behoben
- SMS-Kontingent 0 bedeutet bei ipv64 „unbegrenzt“ (Business, Company) – Node und Portal zeigten dafür „SMS nicht in
  deiner Klasse“ und das Portal ließ keinen SMS-Kanal anlegen.

## 2.27.0 – 2026-10-23

### Neu
- Benachrichtigungen an Slack (Incoming Webhook), Microsoft Teams (Workflows-Webhook mit Adaptive Card; die alten
  Office-365-Connectoren funktionieren seit Mai 2026 nicht mehr) und Matrix (Bot-Konto mit Zugriffstoken, Raum-ID oder
  Alias) – lokal in der Node und als Server-Kanal auf ipv64.net. Farbe wie der Statusbalken der Mails, Link „Details“.

## 2.26.0 – 2026-10-23

### Neu
- Statusseiten: Beim Hinzufügen gibt es neben den Checks eigene Karten für Proxmox VE (Nodes, VMs, Container je System)
  und Docker (Container je Host) – nur, wenn es Proxmox-Systeme bzw. Docker-Hosts gibt. Hat ein Eintrag noch keinen
  Check, wird er beim Hinzufügen angelegt wie mit „auch als Check führen“ (Benachrichtigungen der Regeln, keine doppelten
  Meldungen). Checks von Nodes, Gästen und Containern stehen nur noch in ihrer Karte.

### Behoben
- Wird ein Check gelöscht (auch über eine andere Node, ipv64 oder „als Check“ aus), verschwindet er von allen
  Statusseiten; Einträge bereits gelöschter Checks werden beim Update entfernt.

## 2.25.0 – 2026-10-23

### Neu
- Unter der Check-Tabelle eine Karte zum Tageskontingent der Online-Messungen (nur bei Klassen mit Kontingent, z. B.
  Free und Home/Supporter): Verbrauch heute als Balken, Hochrechnung bis Mitternacht aus den aktiven Online- und
  Hybrid-Checks, voraussichtlicher Zeitpunkt, wann das Kontingent erreicht ist, und Hinweis, wenn ein ganzer Tag mehr
  braucht als das Kontingent.
- Lokale Checks dürfen ab 5 Sekunden prüfen; online und hybrid bleibt es bei mindestens 20 Sekunden (Node, hub und
  Portal). Die Wiederholung bei Fehler wird höchstens so lang wie das Intervall.

## 2.24.3 – 2026-10-23

### Neu
- Proxmox VE: Die Seite eines Systems hat oben Kennzahl-Kacheln wie die Übersicht – Nodes online (mit Clustername und
  Quorum), Gäste, laufend, gestört (anklickbar als Filter) und Auslastung (CPU, RAM, Kerne).

### Geändert
- Rechte-Hinweis: Bei einem Token mit „Privilege Separation“ zählt nur, was Benutzer und Token beide dürfen – der
  Hinweis zeigt jetzt die Befehle für beide.

## 2.24.2 – 2026-10-23

### Behoben
- Proxmox VE: Ein Cluster, dessen Token `cluster/status` nicht lesen darf (Sys.Audit auf „/“ fehlt), erscheint als
  „Cluster – Quorum unbekannt“ statt „Einzel-Node“; der Hinweis nennt das fehlende Recht genau und zeigt die
  pveum-Befehle zum Prüfen und Setzen mit der Token-ID.
- Benachrichtigungen nennen den Grund als Text in der Sprache des Kanals („Grund: Zeitüberschreitung“ bzw. „Reason:
  Timeout“) statt als internen Code („timeout“).
- Meldungen eines Docker-Hosts heißen jetzt „Docker: … gestört“ statt „Proxmox: … gestört“ (ein nicht erreichbarer
  Docker-Host mit hoher Priorität wie bei Proxmox).
- Docker-Formular: Die Einrichtung am Host ist für SSH eine Schritt-für-Schritt-Anleitung mit dem Knopf „Schlüssel
  erzeugen“ und fertigen Befehlen zum Kopieren (Benutzer anlegen, Schlüssel samt Rechten eintragen, Host-Key vergleichen).

## 2.24.1 – 2026-10-23

### Behoben
- Docker-Hosts aus der Ferne (Review): Container „als Check“ eines SSH-/TLS-Hosts werden pausiert, solange der Host
  ausgeschaltet ist (keine Fehlalarme); eine neue Adresse nehmen seine Checks mit, eine andere Maschine beginnt ohne
  Verlauf und „laufend gesehen“ der alten; Wechsel der Verbindungsart bzw. CA/Zertifikat entfernen behält keine alten
  Zugangsdaten und keinen alten Fingerabdruck mehr; SSH-Host-Key: Ed25519 zuerst (wie `ssh-keygen -lf …ed25519_key.pub`),
  Host-Zertifikate nach ihrem Schlüssel; der Rückfall auf `docker system dial-stdio` gilt nicht mehr für immer;
  Bearbeiten lässt Adressen unverändert (Port, Pfad, http://); „Verbindung testen“ ohne Host prüft nicht mehr den
  lokalen Socket; Löschen eines Hosts behält Docker-Checks, die selbst fragen (nur SSH/TLS-Checks gehen mit); Anlegen
  eines Fern-Hosts per API holt den entfernten lokalen Host nicht zurück; ein geänderter `NODE64_DOCKER_HOST` legt
  keinen zweiten lokalen Host an; Import: Eintrag ohne Adresse bricht nicht mehr ab, TLS-Host ohne Zugangsdaten kommt
  abgeschaltet mit Hinweis; Host-Seiten zeigen nur ihre eigenen Checks, die Übersicht zählt wie die Host-Seite;
  Docker-Checks auf den lokalen Socket nutzen ihre Verbindung wieder; Container-Vorschläge im Check-Formular auch
  für SSH-/TLS-Hosts.

## 2.24.0 – 2026-10-22

### Neu
- Docker-Hosts aus der Ferne, ohne Agent: Unter Healthchecks → Docker lassen sich weitere Hosts hinzufügen – per SSH
  (empfohlen; Node64 erzeugt den Schlüssel, der Host-Key wird beim Test bestätigt, geht über Socket-Weiterleitung oder
  `docker system dial-stdio`, also auch mit `restrict,command="docker system dial-stdio"` im authorized_keys), über die
  Docker-API mit TLS (Port 2376, Client-Zertifikat, CA oder bestätigter Fingerabdruck) oder über docker-socket-proxy
  (TCP 2375). Zugangsdaten werden verschlüsselt gespeichert. Ab zwei Hosts gibt es eine Übersicht mit Kacheln über
  alle Hosts; „Als Check führen“ nutzt bei SSH/TLS dieselbe Verbindung.
- Proxmox VE: Die Übersicht hat Kacheln über alle Systeme und Cluster – Systeme, Nodes online, Gäste laufend und
  gestört, Auslastung (CPU, RAM) mit der letzten Störung.

## 2.23.0 – 2026-10-22

### Neu
- Docker-Überwachung wie Proxmox VE: Mit erreichbarem Docker-Socket wird der Host automatisch eingerichtet und alle
  Container überwacht – Zustand, Health, Neustarts, Exit-Code/OOM, CPU und RAM (bezogen auf das Limit, wie docker
  stats), Netz und Block-I/O mit Verlauf von 1 h bis 30 Tage. Regeln mit Vererbung Host → Container, Kanäle, Ruhezeiten
  und Wartung; Störung bei unhealthy, Neustart-Schleife, beendet mit Fehler, OOM oder dead. Containerseite mit Graphen
  und Labels, „Als Check führen“ (vorhandene Docker-Checks werden zugeordnet), Label `node64.nomonitor=true`,
  Ein/Aus-Schalter, API `/api/healthchecks/docker/systems/…`, Prometheus `node64_docker_*`, Export/Import.
- Benachrichtigungen: Neuer Kanal „iGotify (iPhone)“ – Versand an einen Gotify-Server, den der iGotify-Assistent per
  Push aufs iPhone bringt.

## 2.22.0 – 2026-10-22

### Neu
- Docker-Container haben einen eigenen Menüpunkt unter Healthchecks (wie Proxmox VE): alle Container des Hosts mit
  Image, Zustand/Health, Erstellzeit und Ports samt ihren Checks, Kennzahlen, Filter und Suche; nicht überwachte per
  Klick überwachen, Checks ohne Container als „Container fehlt“. Docker-Checks stehen jetzt als normale Zeilen in der
  Liste, die den Docker-Socket nicht mehr abfragt (schneller). Neu: `GET /api/healthchecks/docker/containers`.
- Benachrichtigungen: Neuer Kanal „Home Assistant“. Er löst eine Automation über ihren Webhook aus
  (`POST /api/webhook/<ID>`, JSON mit `state`, `kind`, `title`, `message`, `check`, `node`, `url` und `time`). Die
  Webhook-ID wird verschlüsselt gespeichert und erscheint in keinem Fehlertext. Die Zertifikatsprüfung lässt sich für
  selbst signierte Zertifikate im LAN abschalten. Gesendet wird nur von der Node, „Nur lokal“ in Home Assistant geht.

### Behoben
- Kanal-Formular: Angehakte Optionen bleiben nach einem Eingabefehler angehakt.
- Der Menüpunkt „Healthchecks-Sync“ erscheint nur noch, wenn Healthchecks eingeschaltet ist.

## 2.21.1 – 2026-10-22

### Geändert
- Kennzahl-Kacheln (Verfügbarkeit, Proxmox) im einheitlichen Stil.

### Behoben
- Die Übersicht lädt deutlich schneller: Für die Status-Pillen werden nur noch die letzten Messungen je Check gelesen
  statt der ganzen Messtabelle (wurde mit wachsender Aufbewahrung immer langsamer).

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
