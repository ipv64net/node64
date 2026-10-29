# Cluster (Node64) – technische Referenz

Stand 2026-10-28 (Healthchecks 2.41.0, DynDNS 1.5.0; Bereiche Statusseiten, Kanäle, DynDNS, Zusammenführen exakter Doppel). Beschreibt, wie die Nodes eines Clusters miteinander
sprechen: Ports, Ablauf, Zeiten, Grenzen und was passiert, wenn eine Node weg ist. Bedienung und Hintergrund für
Anwender: node64.de unter `/docs/cluster/`. Entscheidungen und Commits: [PLAN-NODE64-CLUSTER.md](PLAN-NODE64-CLUSTER.md),
Healthchecks-Ablauf im Detail: [LOKALE-GRUPPE.md](LOKALE-GRUPPE.md). Code: `internal/peer`.

## Port und Verbindung

| Was | Wert |
|---|---|
| Port | normaler Web-Port `NODE64_HTTP_PORT` (Standard 8080, spricht per Dualport auch TLS); ist `NODE64_HTTPS_PORT` gesetzt, dieser |
| Protokoll | nur HTTPS (TLS 1.2+); Klartext-HTTP an `/peer/*` → `426 Upgrade Required` |
| Zertifikat | wird nicht geprüft (selbst signiert genügt), kein Pinning – ein Zertifikatswechsel ändert nichts |
| Richtung | jede Node fragt die anderen ab (Pull); beide Seiten müssen die jeweils andere unter ihrer Mitglieds-Adresse erreichen |
| Proxy dazwischen | nur ohne TLS-Aufbruch (TCP-Weiterleitung, Portfreigabe, VPN); ein TLS-terminierender Proxy bricht die Bindung → `tls_binding` |
| Uhrzeit | Hosts per NTP; erlaubte Abweichung ±5 min |
| Andere Ports | keine; ausgehend zu ipv64 nur, wenn eine Node verknüpft ist (unabhängig vom Cluster) |

## Endpunkte (auf dem Web-Port, ohne Sitzung/CSRF)

| Methode | Pfad | Zweck |
|---|---|---|
| POST | `/peer/v1/pair` | Beitritt mit Code (HMAC über Code und TLS-Bindung, Code geht nie im Klartext) |
| GET | `/peer/v1/ping` | Erreichbarkeit, Version, Account, eingeschaltete Bereiche (`sync`) |
| POST | `/peer/v1/members` | Mitglieder weitergeben (Beitritt, Entfernen, Austritt) |
| GET | `/peer/v1/changes?since=&items=` | Protokoll Healthchecks/Benachrichtigungen (checks, maintenance, settings) |
| POST | `/peer/v1/poke` | „bei mir gibt es Neues“ → sofort abholen |
| GET | `/peer/v1/measurements` | Messwerte der anderen Node (Healthchecks) |
| GET | `/peer/v1/relay` | hub-Daten einer verknüpften Node für nicht verknüpfte |
| GET | `/peer/v2/sync?since=&items=` | allgemeiner Abgleich der übrigen Module und Bereiche (Zertifikate, DNS64, Proxmox VE/Docker, Statusseiten, Kanäle) |

## Sicherheit

- Jede Node hat ein Ed25519-Schlüsselpaar (privater Schlüssel verschlüsselt in der DB, Einstellung `peer.key`).
- **Anfrage** signiert über: Methode, Pfad, Zeit, Account, Nonce, TLS-Exporter (RFC 5705/8446, Label
  `EXPORTER-node64-cluster`, 32 Byte) und SHA-256 des Bodys. **Antwort** ebenso signiert (Status, Nonce, Node,
  Exporter, Body). Ein Mittelsmann hat zu beiden Seiten andere Exporter → Ablehnung, bevor Daten fließen.
- Anfragen mit Body gehen erst nach einem signierten Ping über dieselbe Verbindung raus.
- Wiederholungsschutz: jede Nonce wird im Zeitfenster gemerkt, eine Wiederholung → `401 replayed request`.
- Größe: Body höchstens 8 MiB, Beitritt 1 MiB.
- Beitrittscode: 8 Zeichen, 10 min gültig, einmal verwendbar, nach 5 Fehlversuchen verworfen.
- Account: alle Mitglieder gleicher ipv64-Account oder ohne (0); zwei verschiedene Accounts nie. Zwei Accounts passen,
  wenn sie gleich sind oder einer 0 ist; geprüft wird gegen den Account des Clusters (der eigene, sonst der eines
  aktiven Mitglieds). Er steht in jeder Signatur (geprüft wie oben, nie ein anderer Account angenommen).
- Beitritt: Beide Seiten senden den Account ihres Clusters (nicht nur den eigenen), damit eine Node ohne Account nie
  zwei Accounts verbindet: X tritt zu Nodes ohne Account bei, Y nicht zu einem Cluster mit X – auch nicht über eine
  Node ohne Account.
- Eigener Account ändert sich: 0→X (X wie im Cluster oder dort noch keiner) und X→0 (Key entfernt, Verknüpfung
  gelöst) werden nur vermerkt; X→Y setzt alle Mitglieder aus (`account_changed`). Meldet ein Mitglied einen anderen
  Account als den des Clusters, wird es ausgesetzt (`account_mismatch`); passend geänderte Accounts (z. B. 0→X)
  werden beim Ping bzw. mit der nächsten Anfrage nachgeführt.

## Zeiten und Grenzen

| Was | Wert |
|---|---|
| Ping an jedes Mitglied | alle 30 s |
| Mitglied gilt als offline | nach 2 min ohne Antwort |
| Abholen (Pull) | alle 15 s, bei Änderungen sofort (Anstoß gebündelt, höchstens alle 0,5 s) |
| Zeitlimit je Anfrage | 10 s (Ping, Anstoß 5 s), Protokoll-Seite 20 s, Messwerte/hub-Daten/v2 30 s |
| Seitengröße | Protokoll 200 Einträge (bis 100 Seiten je Lauf; v2 zusätzlich höchstens ~4 MiB Daten je Seite), Messwerte 1000 (bis 50 Seiten) |
| Erstes Abholen der Messwerte | die letzten 24 h |
| Healthchecks bei der anderen Node aus | 5 min Ruhe statt alle 15 s (ein Anstoß holt trotzdem sofort) |
| Konflikte | jüngere Änderung gewinnt (ms), Gleichstand: größere Node-Kennung der Urheberin |
| Löschvermerke (v2) | 30 Tage |
| Abgelehnter Eintrag (v2, „cluster change not applied“) | alle 5 min erneut abgeholt, bis er angenommen wird (Warnung einmal je Stand, danach Debug); der Stand der Abholung läuft trotzdem weiter, die Stelle bleibt über Neustarts gemerkt (`peer_members.retry2`); mit dem Update auf diesen Stand holt jede Node einmal alles neu ab |
| Bereich neu eingeschaltet | Abholen ab Anfang (doppelt schadet nicht, die jüngere Änderung gewinnt); genau gleiche Einträge werden dabei zusammengeführt (siehe unten) |

## Was abgeglichen wird

Je Node und je Modul/Bereich schaltbar (`PUT /api/group/sync`, Einstellung `peer.sync`). Ausgetauscht wird ein
Bereich nur, wenn er auf **beiden** Nodes an ist (die abholende Node nennt ihre Bereiche, die liefernde prüft ihre).

| Modul | Bereiche | Standard | Weg |
|---|---|---|---|
| `healthchecks` | `checks` (mit Messwerten), `maintenance` | an | `/peer/v1/changes`, `/measurements`, `/relay` |
| `healthchecks` | `proxmox`, `docker` (Systeme samt Zugang), `statuspages` | aus | `/peer/v2/sync` |
| `notifications` | `settings` (Ruhezeiten, Drossel, Bündeln) | an | `/peer/v1/changes` |
| `notifications` | `channels` (eigene Kanäle der Node samt Zugangsdaten) | aus | `/peer/v2/sync`, Zuordnung Check → Kanal mit den Checks |
| `certs` | `certificates`, `acme`, `dns_accounts`, `cas` | aus | `/peer/v2/sync` |
| `dns64` | `settings`, `lists`, `allowlist`, `records` (mit Zonen), `forwards` (mit Umschreiben), `groups`, `group_members` | aus | `/peer/v2/sync` |
| `node` | `apikey` (zentraler ipv64-API-Key), `settings` (allgemeine Einstellungen der Node) | aus | `/peer/v2/sync` |

| `users` | `accounts` (Benutzer samt Passwort-Hash, App-2FA, SSO-Verknüpfungen), `sso` (OIDC-Einrichtung samt Client-Secret) | aus | `/peer/v2/sync` |

| `dyndns` | `config` (Namen samt Token, Einstellungen, bevorzugte und zuständige Node) | aus | `/peer/v2/sync`; nur eine Node aktualisiert (siehe „DynDNS: zuständige Node“) |

**Statusseiten** (`healthchecks/statuspages`): Kennung je Seite (`hc_status_pages.uid`, gleich auf allen Nodes; die
lokale Nummer bleibt, PROXY64-Hosts verweisen weiter auf sie und gehören zu ihrer Node). Mit geht alles, was die Seite
ausmacht: Slug, Titel, Texte, Layout/Design/Sprache/Farbe, Tage, Anzeige-Schalter, an/aus, Node-Port, noindex,
Passwort (bcrypt-Hash), Gruppen mit den Checks in ihrer Reihenfolge und Anzeigenamen, Logo und Ankündigungen. Checks
stehen über ihr Token auf der Seite – das ist auf allen Nodes gleich (Checks gleichen sich über das Token ab); ein Check,
den es auf einer Node nicht gibt (Checks dort aus), fällt beim Anzeigen weg. Gleicher Slug mit anderem Inhalt unter
anderer Kennung wird nicht übernommen (Warnung „cluster change not applied“ im Log), bis der Slug auf einer Node
geändert ist (spätestens 5 min danach kommt die Seite an, siehe „Zeiten und Grenzen“).

**Kanäle** (`notifications/channels`): Kennung je Kanal (`nf_channels.uid`). Nur die eigenen Kanäle der Node
(`execution node`): nie die Kanäle des Portals (Platzhalter `execution server`, ipv64-Mail/-SMS/App), nicht der
Browser-Kanal (gehört zur Oberfläche seiner Node) und keine mit „Geheimnis nur lokal“ (wird das eingeschaltet, gilt der
Kanal im Cluster als gelöscht). Die Geheimnisse gehen im Klartext über die Cluster-Verbindung (HTTPS, an die Kopplung
gebunden) und werden auf der empfangenden Node mit ihrem Schlüssel gespeichert. Je Node bleiben Server-ID/Revision
(ipv64), letzter Versand und Fehler. Ein Kanal, dessen Geheimnisse sich hier nicht entschlüsseln lassen, geht mit dem
Vermerk `incomplete` hinaus und wird drüben nicht übernommen. **Zuordnung Check → Kanal:** Checks verweisen lokal über
die Kanal-Nummer (je Node verschieden); ist der Bereich auf beiden Seiten an, schickt `/peer/v1/changes` je Check die
Kennungen seiner geteilten Kanäle mit (`channel_uids`, die abholende Node nennt dafür `channels` in `?items=`; beim
Einschalten kommen die Checks von vorn). Die Empfängerin setzt die Kanäle aus diesen Kennungen und behält ihre Kanäle
außerhalb des Clusters (z. B. die des Portals). Bei gleichem Stand des Checks (z. B. Bereich gerade eingeschaltet)
werden die Kanäle beider Seiten vereint, ohne neue Änderung – beide landen beim selben Ergebnis. Ohne den Bereich
bleiben die Kanäle je Node wie bisher. Gedacht vor allem für Nodes **ohne** Verbindung zu ipv64.net; verknüpfte Nodes
bekommen die Kanäle des Portals über ipv64.net (Hinweis am Schalter).

### Benutzer & Anmeldung (`users`)

Code: `internal/usercluster` (Provider), Hook in `internal/store` (`SetLoginCluster`), Wahl in
`internal/web/cluster_users.go`. Node64 kennt **keine Rollen und kein Sperren**: jeder lokale Benutzer ist
Administrator, „letzter Administrator“ heißt also „letzter Benutzer der Node“.

| Was | Abgeglichen | Bleibt je Node |
|---|---|---|
| Benutzer (`accounts`, Kennung `users.uid`) | Name, Passwort-Hash, App-2FA-Geheimnis, gehashte Wiederherstellungscodes (ein verbrauchter Code gilt danach überall nicht mehr), Sprache, Zeitzone, Anlagedatum, verknüpfte SSO-Konten (Anbieter, Subject, Anzeige) | lokale Nummer, Passkeys (an Hostnamen/RP-ID gebunden), Sitzungen, letzte Anmeldung, API- und MCP-Keys, Sperren nach Fehlversuchen |
| SSO (`sso`, ein Eintrag `oidc`) | Issuer, Client-ID, Client-Secret, Beschriftung, Scopes; „SSO entfernen“ entfernt es überall | feste Rückleit-Adresse (`auth.oidc.base_url`, enthält den eigenen Hostnamen) |
| Forward-Auth | – | komplett (Proxy-Adressen und Kopf gehören zum Netz der Node) |
| Zeitzone der Node (`node.timezone`) | – | ja (nur die Zeitzone des Benutzers geht mit) |

Geheimes geht im Klartext über die Cluster-Verbindung (HTTPS, an die Kopplung gebunden) und wird gespeichert wie
lokal: Passwort-Hash und 2FA-Geheimnis wie bisher in `users`, das Client-Secret mit dem Schlüssel der empfangenden
Node verschlüsselt. Ein Secret, das sich hier nicht entschlüsseln lässt, geht als `incomplete` hinaus und wird drüben
nicht übernommen.

**Identität und Konflikte:**

- Dieselbe Kennung auf beiden Seiten (der Benutzer kam schon über den Cluster): die jüngere Änderung gewinnt, als Ganzes.
- Gleicher Name, andere Kennung, **exakt gleich** (Name ohne Groß/klein, Hash, 2FA-Geheimnis, Codes, Sprache, Zeitzone,
  SSO-Konten): es gilt die kleinere Kennung; die Node mit der größeren übernimmt sie an Ort und Stelle (lokale Nummer,
  Passkeys, Keys und Sitzungen bleiben). Anders als bei den übrigen Bereichen geht dabei **kein** Löschvermerk für die
  alte Kennung hinaus (ein Löschvermerk könnte auf einer dritten Node einen Benutzer samt Passkeys löschen).
- Gleicher Name, anderer Inhalt (z. B. anderes Passwort – bei zwei Erstinstallationen der Normalfall): **nichts wird
  überschrieben**, jede Node behält ihren Benutzer. Die Abweichung steht in `users.cluster_conflicts` (Daten
  verschlüsselt), im Audit (`user.cluster.conflict`) und auf `/cluster` in der Karte „Benutzer im Cluster: bitte
  wählen“ (Node, 2FA, Zahl der SSO-Verknüpfungen, Anlagedatum, Kennung). API: `GET /api/group` → `user_conflicts`,
  Wahl mit `POST /api/group/users` Body `{"uid":"…"}`; Audit `user.cluster.choose` mit den verworfenen Versionen.
- Die Wahl ersetzt den Benutzer hier **an Ort und Stelle** (gleiche lokale Nummer, die eigene Sitzung bleibt) und geht
  mit den abgelösten Kennungen (`users.cluster_replaces`) und dem Zeitpunkt (`cluster_chosen_at`) an die anderen
  Nodes; wessen Benutzer darin abgelöst ist, ersetzt ihn ebenso an Ort und Stelle. Eine später eintreffende abgelöste
  Version wird abgewiesen. Bei zwei verschiedenen Wahlen gilt die jüngere.
- Wird ein Benutzer über den Cluster umbenannt und gibt es den neuen Namen hier schon unter anderer Kennung, gilt das
  ebenfalls als Abweichung zur Wahl.

**Schutzregeln:**

1. Ein Löschen aus dem Cluster entfernt **nie den letzten Benutzer** einer Node (Audit `user.cluster.keep_last`,
   Warnung im Log). Der Benutzer bleibt dann nur dort; ändert ihn dort später jemand, kommt er überall zurück.
2. Weder Abgleich noch Wahl löschen einen Benutzer, um einen anderen einzusetzen: die Wahl ersetzt den Inhalt an Ort
   und Stelle, die Sitzung der Person, die wählt, bleibt.
3. Den eigenen Benutzer kann man auf der Seite Anmeldung nicht löschen (die Liste „Benutzer dieser Node“ erscheint ab
   zwei Benutzern, Audit `user.delete`).
4. Ändert eine Übernahme Passwort oder 2FA-Geheimnis, enden die Sitzungen dieses Benutzers auf der Node (wie beim
   Ändern auf der Node selbst); er meldet sich mit dem neuen Passwort an.
5. Gleiche SSO-Identität hier bei einem anderen Benutzer: diese Verknüpfung wird nicht übernommen (Warnung im Log).
6. Aus dem Cluster übernommene Änderungen stehen im Audit-Log mit Herkunft `cluster` und Urheber `node:<Name>`
   (`user.cluster.create|update|delete|merge|choice|keep_last`, `sso.cluster.update|delete`; Bereich „Anmeldung“).

`reset-password` per Kommandozeile wirkt nur auf der eigenen Node (der Befehl läuft ohne Cluster); es gilt im Cluster
erst, wenn das Passwort danach in der Oberfläche geändert wird. Bis dahin kann eine Änderung desselben Benutzers auf
einer anderen Node es wieder überschreiben.

Neue Module hängen sich als Provider an `/peer/v2/sync`
(`internal/peer/cluster.go`); eine ältere Node bekommt nie Eintragsarten, die sie nicht kennt.
PROXY64 ist als Bereich geplant, aber zurückgestellt, bis die Nachfrage da ist:
[PLAN-NODE64-CLUSTER-MODULE.md](PLAN-NODE64-CLUSTER-MODULE.md). DNS64: [PLAN-NODE64-DNS64-LOKAL.md](PLAN-NODE64-DNS64-LOKAL.md)
(Einträge und Weiterleitungen mit „nur diese Node“ werden nie abgeglichen).

### DynDNS: zuständige Node

**Abgeglichen** (`dyndns/config`, Kennung je Name `dyn_targets.uid`): Domain, Host, Record-ID, Token-Art und Token
(Klartext über die Cluster-Verbindung, auf der Empfängerin mit ihrem Schlüssel gespeichert), Modi IPv4/IPv6, feste
Adressen, Interface-ID, Interface, an/aus; die Einstellungen (Prüfabstand, Prüf-URLs, Aufbewahrung, Benachrichtigungen,
bevorzugte Node; eine Node ohne gespeicherte Einstellungen schickt keine Vorgaben hinaus) und die zuständige Node
(Eintrag `leader`). **Je Node** bleiben: ermittelte Adressen, Anschluss-Analyse, je Name zuletzt gemeldete Adressen,
Fehler, automatische Pause und DNS-Stand, Verlauf (Prüfungen, Aufrufe), Tageslimit-Zählung. Ein Token, das sich hier
nicht entschlüsseln lässt, geht als `incomplete` hinaus und wird drüben nicht übernommen. Derselbe Name mit anderer
Einstellung unter anderer Kennung wird nicht übernommen (Warnung „cluster change not applied“), jede Node behält ihren
Stand, bis er auf einer Seite angeglichen oder gelöscht ist; exakt gleiche Namen werden zusammengeführt (unten).

**Nur eine Node aktualisiert** die Namen (alle Namen gemeinsam), sonst überschreiben sich Nodes gegenseitig. Die
anderen ermitteln weiter ihre Adressen (Anzeige, Meldung „Adresse gewechselt“), rufen aber `update.php` nicht auf;
„Jetzt aktualisieren“ lehnen sie ab (API 409). Regeln (`internal/dyndns/cluster.go`):

| Was | Regel |
|---|---|
| Kandidaten | diese Node und die Mitglieder mit dem Bereich hier und dort an, nicht ausgesetzt, DynDNS-Modul läuft (sonst meldet die Node den Bereich nicht im Ping) |
| gewünschte Node | die **bevorzugte** (Seite DynDNS, Einstellung `dyndns.preferred_node`, geht mit), sonst die **kleinste Kennung** – jeweils nur unter Mitgliedern, die seit **5 min** ununterbrochen erreichbar sind (beim ersten Blick nach dem Start Erreichbare gelten als stabil) |
| zuständige Node | steht im Eintrag `leader` (Einstellung `dyndns.cluster_leader`); sie bleibt es, solange die anderen sie erreichen |
| Ausfall | zuständige Node **2 min** ohne Antwort (Karenz des Clusters, 4 Pings), ausgesetzt, Bereich oder Modul dort aus → die gewünschte Node trägt sich ein und meldet sofort alle Namen (Blick auf die Mitglieder alle 30 s) |
| Rückkehr | die zuständige Node gibt erst ab, wenn die gewünschte **5 min** erreichbar ist (kein Hin und Her); nur die zuständige gibt ab, nur die gewünschte übernimmt |
| Start | eine Node mit Mitgliedern im Bereich aktualisiert die erste **1 min** nicht (erst den Stand der anderen abholen) |
| Übernahme | die neue Node vergisst die zuletzt gemeldeten Adressen und meldet jeden Namen einmal (die Namen zeigen evtl. noch auf die alte Node) |
| Bereich aus / allein | jede Node aktualisiert ihre Namen selbst wie ohne Cluster |

**Verschiedene Netze** (verschiedene öffentliche IPs): Nach einer Übernahme zeigen die Namen auf den Anschluss der neuen
Node – das ist der Zweck (Ausfallsicherheit über Standorte); Namen, die immer auf einen Standort zeigen sollen, nicht
über den Cluster führen oder die Node dort bevorzugen. **Getrennte Teile** (Split-Brain): Jeder Teil hält seine
zuständige Node, beide aktualisieren – in verschiedenen Netzen wechseln die Namen dann hin und her (die Erkennung
„von außen geändert“ pausiert sie nach mehreren Wechseln). Nach der Wiederverbindung gilt der jüngere `leader`-Eintrag,
danach greift wieder die Regel oben. Seite DynDNS: Karte der Namen zeigt, welche Node aktualisiert, und die Wahl der
bevorzugten Node (`POST /dyndns/cluster`); `GET /api/dyndns/status` → `cluster`.

### Zertifikate: gleiche Einträge und ACME-Konto

**Zusammenführen:** Haben zwei Nodes beim Beitritt oder beim Einschalten eines Bereichs denselben Eintrag unter
verschiedener uid, bleibt er einmal – auf allen Nodes mit der kleineren uid (die Node mit der größeren übernimmt sie,
sobald sie die andere bekommt). Verweise der Zertifikate (ACME-Stelle, DNS-Zugang, CA) zeigen danach auf den
verbliebenen Eintrag; eine zusammengeführte uid merkt sich die Node (`certs.cluster_alias`), damit Verweise anderer
Nodes auf die alte uid weiter passen (Löschen geht nie über einen Alias). Zusammengeführt wird nur genau Gleiches:

| Bereich | gleich, wenn |
|---|---|
| `certificates` | dasselbe Zertifikat (SHA-256 des ersten Zertifikats) **und** derselbe private Schlüssel |
| `acme` (Stellen) | dieselbe Verzeichnis-URL **und** dasselbe EAB (KID und HMAC) oder beide ohne |
| `dns_accounts` | derselbe Anbieter **und** dieselben Zugangsdaten (der Name zählt nicht) |
| `cas` | dasselbe CA-Zertifikat **und** derselbe Schlüssel |

Alles andere bleibt getrennt, auch bei gleichem Namen. Sonderfall: dieselbe ACME-Verzeichnis-URL mit anderem EAB
kann es je Node nur einmal geben – sie wird nicht übernommen (Warnung „cluster change not applied“), Zertifikate mit
dieser Stelle erneuert dann nur ihre Node.

**ACME-Konto** (Eintrag `account` im Bereich `acme`): Hat die andere Node keins oder dasselbe (gleicher Schlüssel),
gilt es überall (Mail und Annahme der Bedingungen gehen mit). Sind es verschiedene Konten, wird **nichts
überschrieben**: Jede Node nutzt weiter ihr eigenes, die abweichenden stehen in `certs.acme_conflicts`, und die Seite
`/cluster` zeigt unter den Abgleich-Einstellungen die Karte „ACME-Konto im Cluster“ mit Node, Stelle, Mail und
Anlagedatum je Konto und „Dieses verwenden“ (API: `GET /api/group` → `acme_accounts`, Wahl mit
`POST /api/group/acme` Body `{"thumbprint":"…"}`; Audit `cert.account.choose` mit den verworfenen Konten). Die Wahl
(Zeitpunkt und die abgelösten Konten als Fingerabdruck des Schlüssels, `certs.acme_choice`) geht mit dem Konto an die
anderen Nodes; wessen Konto abgelöst ist, übernimmt das gewählte, ein später eintreffendes altes Konto ändert nichts
mehr. Bei zwei verschiedenen Wahlen gilt die jüngere. Ausgestellte Zertifikate bleiben gültig, erneuert wird mit dem
gewählten Konto. Kommt später eine Node mit einem dritten Konto dazu, erscheint die Wahl erneut.

## Exakte Doppel beim Beitreten oder Einschalten

Was auf zwei Nodes schon **vor** dem Abgleich exakt gleich angelegt war (verschiedene Kennungen, gleicher Inhalt),
wird beim ersten Eintreffen zu einem Eintrag zusammengeführt. Regel auf jeder Node gleich, daher landen alle beim
selben Ergebnis: **es gilt die kleinere Kennung**. Kommt ein Eintrag mit kleinerer Kennung, übernimmt der Eintrag hier
sie (die lokale Nummer bleibt, Verweise bleiben gültig) und meldet die alte Kennung als gelöscht (neuer Zeitpunkt, so
verschwindet sie auf allen Nodes); kommt einer mit größerer, bleibt alles und die andere Node übernimmt unsere.
Zusammengeführt wird nur bei exakt gleichem Inhalt, nie bei bloß ähnlichen Einträgen:

| Bereich | Exakt gleich heißt |
|---|---|
| Statusseiten | gleicher Slug und alles oben Genannte gleich (Logo-Inhalt ja, Zeitpunkt des Logos nein; Passwort-Hashes sind gesalzen, mit Passwort also praktisch nie gleich) |
| Kanäle | Typ, Name, Konfiguration samt Geheimnissen (leer = nicht gesetzt), an/aus, Standard, Sprache, Ausfall/Entwarnung |
| DynDNS-Namen | Domain, Host, Record-ID, Token-Art, Token, Modi, feste Adressen, Interface-ID, Interface, an/aus (Laufzeitstand und Verlauf zählen nicht und bleiben) |
| Proxmox VE, Docker | Art, Name, Adressen, Token-ID, Secret, Pin, Intervall, an/aus (Heim-Node zählt nicht); Proxmox-Checks mit der alten Kennung bekommen die neue (als Änderung) |
| Wartungsfenster | nur lokale Fenster (ohne Server-ID): Name, Beginn, Ende, Wiederholung, Ende der Wiederholung, Checks, an/aus; das Fenster mit der größeren Kennung wird mit Löschvermerk entfernt |
| Checks | **nie** – derselbe Check auf zwei Nodes sind zwei Messstellen (eigene Tokens, Verlauf und messende Node, beim hub eigene Checks) |
| Zertifikate | eigene Regel, siehe „Zertifikate: gleiche Einträge und ACME-Konto“ |
| Benutzer | eigene Regel ohne Löschvermerk, siehe „Benutzer & Anmeldung“ (Abweichungen zur Wahl) |

Grenzen: Doppel, die schon vor dieser Version über den Cluster auf beiden Nodes gelandet sind, werden nicht nachträglich
zusammengeführt (einmal von Hand löschen). Bei drei und mehr Nodes kann eine Node, die das Doppel mit der größeren
Kennung schon übernommen hatte, beim Löschvermerk die zugehörigen Checks eines Proxmox-Systems „als Check“ mit
entfernen (wie bei jedem gelöschten System).

### Modul `node` (API-Key und allgemeine Einstellungen)

Code: `internal/nodecfg` (Provider, Hülle `nodecfg/nodecluster`). Jeder Eintrag hat seinen eigenen Zeitpunkt, die
jüngere Änderung gewinnt.

**`apikey`** – Kennung `key`, Inhalt Key im Klartext plus Konto (`ipv64.account`).

- **Achtung:** Der Key gibt Vollzugriff auf den ipv64-Account (Hinweis am Schalter). Er geht im Klartext über die
  Cluster-Verbindung (HTTPS, an die Kopplung gebunden) und wird auf der empfangenden Node mit deren Schlüssel
  verschlüsselt. Eingeschaltet ersetzt ein neuer Key auf einer Node den Key der anderen.
- Angenommen wird er nur bei gleichem Account oder wenn die Node noch keinen hat; nie ein anderer Account. Genau:
  Account-ID des Keys gleich dem Account der empfangenden Node (wie ihn der Cluster prüft: Healthchecks-Verknüpfung,
  sonst Key), oder die Node hat keinen (0) und der Account des Clusters ist derselbe bzw. es gibt dort noch keinen.
  Sonst wird der Key abgelehnt („cluster change not applied“ im Log), ebenso ein Key ohne Account-ID. Eine Node ohne
  Account gehört nach der Übernahme zum Account des Keys; das setzt niemanden aus (0→X passt, siehe Sicherheit).
- Übernommen wird über denselben Weg wie eine Eingabe in den Einstellungen (`ipv64api.Key`, Konto, Merker „entfernt“
  zurück); alles, was den Key nutzt (DynDNS, Healthchecks über die API, Meldungen …), liest ihn ohnehin frisch.
  Jede Übernahme steht im Audit-Log (`peer.ipv64_key`, `peer.ipv64_key_removed`, Bereich `sync`).
- Entfernen in den Einstellungen entfernt ihn auf allen Nodes mit eingeschaltetem Bereich. Entfernt ipv64.net die
  Node (Node-Übersicht), gilt das nur für sie: kein Löschen für die anderen, und sie nimmt keinen Key aus dem Cluster
  an, bis er auf ihr selbst eingetragen wird.
- Hängt der Account einer Node nur am Key (keine Healthchecks-Verknüpfung), ändern Eintragen und Entfernen ihren
  Account (0→X, X→0) – das passt und setzt nichts aus. Nur ein Key eines anderen Accounts (X→Y, von Hand eingetragen)
  setzt die anderen Nodes aus (`account_changed`).

**`settings`** – Kennung = Einstellungsschlüssel, feste Liste (Whitelist in `nodecfg.go`, je Schlüssel mit Merker
„geheim“: dann im Klartext übertragen und auf der empfangenden Node neu verschlüsselt):

| Schlüssel | Prüfung | Nebenwirkung wie die Einstellungsseite |
|---|---|---|
| `node.timezone` | gültige Zeitzone | – |
| `updates.mode` | `off`/`notify`/`auto` | `selfupdate.SaveMode`: `updates.check` mit, bei `off` `updates.latest` leeren |
| `updates.channel` | `stable`/`preview` | – |
| `updates.window` | `HH:MM-HH:MM` | – |
| `mcp.enabled` | `0`/`1` | – |

Erkannt wird eine Änderung beim Schreiben (Hook des Stores) am Inhalt (Prüfsumme in `nodecfg.seen`), ein
unverändert gespeicherter Wert zählt nicht; beim Start gilt für neue bzw. geänderte Werte der Zeitpunkt aus der
Datenbank. Gelöschte Einstellungen werden nicht übertragen. **Nie abgeglichen:** Name und Kennung der Node, Ports,
Adressen, HTTPS/Zertifikate der Oberfläche, Datenverzeichnis, Cluster-Einstellungen, Netz-Einstellungen
(Proxy-Netze, Forward-Auth …), Stand des Selbst-Updates. Prometheus hat keine Einstellungen (Zugriff über API-Keys),
MCP-Schlüssel gehören zu den Benutzern (nur als Hash gespeichert), die Sprache ist je Benutzer.

## Wenn eine Node weg ist

1. Die anderen pingen sie weiter alle 30 s; nach **2 min** gilt sie als **offline** (Liste: offline, letzter Fehler).
   Sie wird **nicht** ausgesetzt und nicht entfernt – offline ist kein Grund zum Aussetzen.
2. Die übrigen Nodes arbeiten normal weiter und gleichen untereinander ab.
3. **Benachrichtigen:** Misst sie einen Check mit anderen zusammen, übernimmt die nächste erreichbare messende Node
   die Meldungen (ohne Doppelmeldung). Misst nur sie einen Check, meldet nach 3 Intervallen (mind. 5 min) ohne
   Messung „nicht überwacht“ (`unchecked`).
4. **Weiterreichen an ipv64:** War sie die weiterreichende Node, übernimmt die nächste verknüpfte erreichbare Node.
5. **Kommt sie zurück:** Beide Seiten holen ab ihrem letzten Stand alles nach, was in der Zwischenzeit geändert
   wurde (auch Änderungen, die auf ihr selbst gemacht wurden); Messwerte ab dem letzten Stand. Dauerhaft
   entfernen nur mit „Aus dem Cluster nehmen“.

**Meldung:** Ist eine Node länger als **5 min** nicht erreichbar oder ausgesetzt, kommt die Benachrichtigung
„🔴 Cluster: Node … nicht erreichbar“ (Grund: letzter Fehler bzw. `suspended: <grund>`), bei Rückkehr „🟢 … wieder
erreichbar“ (Kanäle unter Benachrichtigungen, Link auf `/cluster`). Es meldet genau eine Node: die mit der
kleinsten Kennung unter den erreichbaren; die Entwarnung schickt, wer gemeldet hat. Das Dashboard zeigt dann oben
einen Hinweis und in der Kachel **Cluster** (nur mit Mitgliedern) den Zustand jeder Node.

## Split-Brain (Verbindung zwischen Teilen des Clusters länger weg)

Es gibt **keinen Anführer und keine Mehrheitsregel**: Jeder Teil arbeitet allein weiter, nichts wird gesperrt.
Nach der Wiederverbindung holt jede Node ab ihrem letzten Stand alles nach (das Protokoll hält je Eintrag nur den
letzten Stand, es läuft also nicht über), und alle landen beim selben Ergebnis:

| Was | Während der Trennung | Nach der Wiederverbindung |
|---|---|---|
| Eintrag nur auf einer Seite geändert/neu | normal | kommt überall an |
| derselbe Eintrag auf beiden Seiten geändert | jede Seite hat ihren Stand | **jüngere Änderung gewinnt, als Ganzes** (kein Zusammenführen einzelner Felder); die ältere geht verloren |
| auf einer Seite gelöscht, auf der anderen geändert | – | jüngere gewinnt: Änderung nach dem Löschen holt den Eintrag zurück, sonst bleibt er gelöscht |
| Löschvermerke | Checks/Wartungsfenster dauerhaft; Module über v2 (Zertifikate) 30 Tage | Trennung > 30 Tage: ein gelöschtes Zertifikat kann von der anderen Seite zurückkommen |
| Messwerte | jede Node misst selbst | werden nachgeholt (Messwerte gehören je einer Node, kein Konflikt) |
| Benachrichtigungen | **jede Seite meldet für sich** – Checks, die auf beiden Seiten gemessen werden, können doppelt gemeldet werden (verknüpft mit ipv64 bewertet und meldet der hub, dann nicht) | wieder genau eine Node |
| Meldung „Node nicht erreichbar“ | jede Seite meldet die Nodes der anderen | Entwarnung von denselben Nodes |
| Zertifikate | ist die zuständige Node auf der anderen Seite, erneuert diese Seite ab einem Drittel der Frist selbst | jüngeres Zertifikat gewinnt überall (höchstens einmal doppelt bestellt) |
| DynDNS | jede Seite hat eine zuständige Node und aktualisiert (verschiedene Netze: die Namen wechseln) | jüngerer `leader`-Eintrag gilt, wieder genau eine Node |
| Mitglieder entfernen/aufnehmen | erreicht nur die eigene Seite | nicht automatisch nachgeholt: entfernte Node auf der anderen Seite ggf. dort auch entfernen |

**Beispiel drei Nodes, A+B getrennt von C:** A und B gleichen weiter untereinander ab und melden als Paar
(A meldet „C nicht erreichbar“); C arbeitet allein und meldet „A“ und „B nicht erreichbar“. Checks, die nur C misst,
meldet C; Checks, die A/B und C messen, melden beide Seiten. Nach der Wiederverbindung bekommt C alles von A und B,
A und B alles von C; bei Änderungen am selben Eintrag gewinnt die jüngere – **auch wenn sie von C (der Minderheit)
kommt**. Die Uhrzeit entscheidet, daher NTP auf allen Hosts (bei mehr als 5 min Abweichung sprechen die Nodes ohnehin
nicht miteinander).

## Ausgesetzte Nodes

Grundlegende Änderung → ausgesetzt: keine Anfragen mehr an sie, ihre Anfragen werden mit 403 abgelehnt; die anderen
arbeiten weiter. Gründe: `account_changed` (eigener Account auf einen anderen als den des Clusters, X→Y),
`account_mismatch` (Mitglied meldet einen anderen Account als den des Clusters), `identity_changed`, `tls_binding`,
`version_too_old`. Zurück nur mit „Wieder aufnehmen“ (prüft erneut) – außer `version_too_old`: wird beim nächsten
Ping nach dem Update der anderen Node von selbst wieder aktiv (gestaffeltes Update).

## Beobachten

- Oberfläche `/cluster`, API `GET /api/group` (je Mitglied `online`, `state`, `reason`, `sync`, `last_seen`,
  `last_error`).
- Prometheus: `node64_group_members`, `node64_group_members_online`, `node64_group_member_up{node_id,node_name}`.
- Log (Modul `peer`): „cluster member suspended/resumed“, „peer request rejected“, „cluster entries updated“;
  Abholfehler auf Debug. Audit-Bereich `sync` (Aktionen `peer.*`).
