# Plan: Environment (weitere Node64 an einer Stelle öffnen)

Stand 2026-11-14, Wunsch Dennis: ein Menüpunkt **Environment**, der alle Node64-Container zeigt, die ich verwalte –
die Mitglieder des Clusters automatisch und weitere Nodes, die ich per Adresse hinzufüge. Ein Klick öffnet die
Node, am besten gleich angemeldet mit meinem Benutzer. **Nur Node64**, keine fremden Systeme. **Leichtgewichtig**:
eine Liste, ein Klick, kein Fernsteuern. **Nur Planung**, nichts gebaut.

## Ausgangslage (Stand Code)

- **Cluster** (`internal/peer`): Mitglieder mit Name, Adresse (`https://host:port`), Version, Online, Zustand
  (aktiv/ausgesetzt). Vertrauen über Ed25519 und an TLS gebundene Anfragen. Module können über
  `/peer/v2/call/{modul}/{name}` live bei einer anderen Node fragen, sofern ein Bereich des Moduls auf beiden
  Seiten an ist.
- **Benutzer im Cluster** (`internal/usercluster`, Bereich `users/accounts`, Schalter): gleiche Benutzer mit gleicher
  `uid` auf allen Nodes. Die Benutzerverwaltung ([PLAN-NODE64-BENUTZER.md](PLAN-NODE64-BENUTZER.md)) bringt Rollen
  (Administrator, Nur lesen) und Sperre dazu.
- **Anmeldung** je Node mit eigener Sitzung (Cookie `SameSite=Lax`); `startSession` legt sie an.
- `/api/health` ohne Anmeldung liefert Status und Version.

## Ziel in einem Satz

Menü → **Environment**: eine Liste aller Nodes (diese, Cluster, manuell hinzugefügte) mit Status und Version;
**Öffnen** springt zur Node und meldet mich dort an, wenn die Node mir vertraut, sonst landet man auf ihrer
Anmeldeseite.

## Entwurf

### Die Liste

| Spalte | Inhalt |
|---|---|
| Node | Name, darunter die Adresse; „diese Node“ markiert |
| Herkunft | Abzeichen **Cluster** oder **Hinzugefügt** |
| Status | online/offline (Cluster: letzter Ping; Hinzugefügt: Abfrage beim Öffnen der Seite), Version, „Update verfügbar“ |
| Anmeldung | „mit meinem Benutzer“ / „Anmeldeseite“ (zeigt vorab, was der Klick tut) |
| Aktion | **Öffnen**; bei hinzugefügten zusätzlich Bearbeiten/Entfernen |

- Kein Hintergrund-Job: hinzugefügte Nodes werden beim Öffnen der Seite parallel abgefragt (Zeitlimit 3 s je Node).
  Cluster-Mitglieder kommen ohnehin aus dem Ping.
- Optionales Feld **Beschreibung** (z. B. „Büro Hamburg“), sonst nichts. Keine Ordner, keine Tags.
- Ausgesetzte Cluster-Mitglieder stehen grau mit Grund, Öffnen führt zur Anmeldeseite.

### Öffnen mit Anmeldung (Anmelde-Ticket)

Ablauf, gleich für Cluster und hinzugefügte Nodes:

1. Klick auf **Öffnen** → `POST /environment/open/{id}` auf Node A (mit CSRF, angemeldet).
2. A fragt **serverseitig** bei Node B ein Ticket an (Cluster: `peer.Call(..., "environment", "ticket")`;
   hinzugefügt: über den Zugangsschlüssel, siehe unten). Mit dabei: wer (`uid` bzw. Schlüssel), wirksame Rolle des
   Benutzers auf A, Name von A und Rücksprung-Adresse.
3. B prüft und gibt ein **Ticket** zurück: 32 Byte Zufall, 60 s gültig, einmal verwendbar, nur im Speicher.
4. A liefert eine kleine Seite, die das Ticket per **POST-Formular** an `https://B/environment/enter` schickt
   (kein Ticket in URL, Verlauf oder Logs).
5. B löst das Ticket ein, legt eine normale Sitzung an (`startSession`), Audit `login.environment` (von Node A,
   Benutzer), Weiterleitung auf `/`.

Regeln:

- **Rolle wird nie größer:** B gibt höchstens die Rolle, die der Benutzer auf B hat, und höchstens die, die A
  mitschickt. Ein „Nur lesen“-Benutzer auf A wird auf B nie Administrator.
- **2FA:** gilt als erledigt, weil die Anmeldung auf A schon damit erfolgt ist. Verlangt B „2FA für alle“ und hat
  der Benutzer keine, greift B's normale Einrichtung.
- Gesperrter Benutzer auf B, unbekannte `uid`, Ticket abgelaufen → B's Anmeldeseite mit kurzem Hinweis.
- **Kein Login-CSRF:** B löst ein Ticket nur ein, wenn das Formular von A kommt (Host aus `Origin`, ersatzweise
  `Referer`, gleich dem Host der Rücksprung-Adresse im Ticket; die Seite in Schritt 4 setzt dafür
  `Referrer-Policy: origin`). Ist auf B schon ein anderer Benutzer angemeldet, bleibt diese Sitzung, B zeigt einen
  Hinweis (Abmelden zum Wechseln) und vermerkt `login.environment_failed`. Hinzugefügte Nodes (E2) brauchen dafür
  ebenfalls eine passende Rücksprung-Adresse.
- **Rückweg:** B merkt sich in der Sitzung „gekommen von A“ und zeigt oben einen kleinen Hinweis
  „Geöffnet über Environment von *A*“ mit Link zurück. Damit ist immer klar, auf welcher Node man gerade arbeitet.
- **Browser-Adresse:** standardmäßig die Adresse der Node. Je Eintrag optional eine eigene Adresse für den Browser
  (z. B. ein Name über PROXY64), wenn die Node intern anders erreicht wird. Bei `https://IP:Port` zeigt der Browser
  beim ersten Mal die Zertifikatswarnung – Hinweis auf der Seite, kein eigener Weg drumherum.

### Cluster-Mitglieder

- Erscheinen automatisch.
- **Anmeldung „mit meinem Benutzer“** nur, wenn der Benutzer-Abgleich im Cluster an ist (gleiche `uid` auf B) und
  der neue Bereich **`environment/login`** auf beiden Seiten an ist (Standard an). Sonst: Anmeldeseite.
- Kein neues Protokoll: Ticket-Anfrage über das vorhandene `/peer/v2/call` (Modul `environment`, Name `ticket`).

### Hinzugefügte Nodes (nicht im Cluster)

Adresse allein reicht für „Öffnen = Anmeldeseite“ und den Status (`/api/health`). Für Anmeldung mit Ticket braucht
es Vertrauen in beide Richtungen – dafür ein **Zugangsschlüssel**:

- Auf Node B (Administrator): Einstellungen → Environment → **„Zugang für eine andere Node erstellen“**: Name
  (z. B. „von Node Büro“), Benutzer auf B, als den man ankommt (Standard: ich selbst). B zeigt den Schlüssel
  **einmal**: `n64env1.<NodeID>.<öffentlicher Schlüssel von B>.<Geheimnis>`. B speichert nur einen Hash.
- Auf Node A: **„Node hinzufügen“** → Adresse (`https://host:port`, ohne Schema wird es ergänzt), Schlüssel (leer
  lassen = nur Link + Status), Beschreibung. A speichert den Schlüssel verschlüsselt (`secret.key`).
- A spricht B über den Cluster-Transport an (`internal/peer/transport.go` wiederverwenden): TLS ohne
  Zertifikatsprüfung, B signiert die Antwort mit seinem Ed25519-Schlüssel und bindet sie an die TLS-Verbindung
  (Exporter); A prüft gegen den öffentlichen Schlüssel aus dem Zugangsschlüssel. A beweist sich mit
  HMAC(Geheimnis, Exporter, Nonce). Ein Mittelsmann bekommt so weder Schlüssel noch Ticket; ein Zertifikatswechsel
  stört nicht.
- Endpunkte auf B (ohne Sitzung, wie `/peer/*`): `POST /peer/v2/env/status` (Name, Version, Update verfügbar) und
  `POST /peer/v2/env/ticket`.
- B: Liste der Zugänge (Name, Benutzer, zuletzt benutzt, von welcher Node), **Widerrufen**. Gesperrter oder
  gelöschter Benutzer → Zugang wirkt nicht mehr. Fehlversuche begrenzt wie die Anmeldung.

### Schnellwechsel (klein, optional in E1)

Neben dem Node-Namen in der Kopfzeile ein Aufklappmenü mit denselben Einträgen (Öffnen wie oben). Nur, wenn es
mehr als eine Node gibt.

## Bewusst nicht

- Kein Fernsteuern (Updates, Neustart, Einstellungen anderer Nodes aus dieser Oberfläche), keine zusammengefassten
  Dashboards über alle Nodes – dafür gibt es Cluster und Healthchecks.
- Keine fremden Systeme (Proxmox, Router …) – die bleiben in Healthchecks/Monitor64.
- Keine Weiterleitung des Browsers durch Node A (kein Proxy): der Browser spricht immer direkt mit Node B.

## Cluster

| Bereich | Inhalt |
|---|---|
| `environment/login` (neu, Standard **an**) | Ticket-Anfragen anderer Mitglieder beantworten |
| `environment/nodes` (neu, Standard **an**) | hinzugefügte Nodes clusterweit (Zugangsschlüssel beim Empfänger mit eigenem `secret.key` neu verschlüsselt, wie das SSO-Secret) |
| bleibt je Node | ausgestellte Zugänge (Hashes), Tickets |

## API und Audit

- `GET /api/environment` (Liste mit Status), `POST/PUT/DELETE /api/environment/nodes[/{id}]` (nur Administrator),
  `GET/POST/DELETE /api/environment/access[/{id}]` (Zugänge auf dieser Node, nur Administrator; Schlüssel nur in der
  Antwort beim Anlegen).
- Audit: `environment.node_add|node_update|node_remove`, `environment.access_create|access_revoke`,
  `environment.open` (auf A), `login.environment` (auf B, mit Herkunfts-Node), abgelehnte Tickets als Warnung.
- Benutzerverwaltung: Zugänge anlegen/widerrufen auf die Liste „nur Administrator“; Öffnen dürfen alle (Rolle wird ja
  begrenzt).

## Phasen

| Phase | Inhalt | Aufwand grob |
|---|---|---|
| **E1 Liste + Cluster** | Modul/Paket `internal/environment` (klein), Menüpunkt, Seite mit dieser Node und den Cluster-Mitgliedern, Ticket über `/peer/v2/call`, `/environment/enter`, Rückweg-Hinweis, Bereich `environment/login`, i18n `environment.*`, `nav.environment`, Tests (zwei Nodes: mit/ohne Benutzer-Abgleich, Rolle begrenzt, Ticket einmalig/abgelaufen) | ca. 3–4 Tage |
| **E2 Hinzugefügte Nodes** | Tabelle `env_nodes` und `env_access`, Hinzufügen ohne/mit Zugangsschlüssel, Status beim Seitenaufruf, `/peer/v2/env/*` mit Bindung (Transport wiederverwenden), Zugänge erstellen/widerrufen, Bereich `environment/nodes` im Cluster, API, openapi, Tests (Mittelsmann, widerrufener Schlüssel, gesperrter Benutzer, Liste auf zwei Cluster-Nodes), Doku node64.de | ca. 4–5 Tage |
| **E3 Feinschliff** (optional) | Schnellwechsel in der Kopfzeile | ca. 1 Tag |

E1 hängt an der Benutzerverwaltung B1 (Rollen); ohne B1 ginge E1 auch, alle Benutzer wären dann Administrator.

**Stand E1 (gebaut 2026-11-14):** Paket `internal/environment` (Tickets im Speicher, Provider `environment/login`
mit Modul-Vorgabe an über `peer.ModuleInfo.Default`, Tabelle `env_sessions` im eigenen Scope `environment`),
Seite und Handler in `internal/web/environment.go`. Die Rolle einer über Environment entstandenen Sitzung steht in
`env_sessions.max_role`; die Sitzungs-Middleware begrenzt damit die Rolle im Kontext (`envCap`), sodass die zentrale
Rechteprüfung der Benutzerverwaltung (`roles.go`) nur die begrenzte Rolle sieht (auch Admin-Bereiche beim Lesen).

E2 ist unabhängig von B1/B2.

**Risiken:** Ein Zugangsschlüssel ist so viel wert wie eine Anmeldung als dieser Benutzer → nur einmal angezeigt,
nur als Hash gespeichert, widerrufbar, Rolle begrenzt. Browser-Zertifikatswarnung bei IP-Adressen ist unschön, aber
ehrlich (eigene Browser-Adresse je Eintrag als Ausweg).

## Entscheidungen (Dennis, 2026-11-14)

1. Name **Environment** in beiden Sprachen.
2. Menüpunkt unter **System** neben Cluster.
3. Gibt es den Benutzer auf der anderen Node nicht (oder ist der Benutzer-Abgleich aus), meldet man sich dort
   **neu an** (Anmeldeseite). Keine Anmeldung über gleichen Benutzernamen.
4. Nodes außerhalb des Clusters werden über einen **Zugangsschlüssel** hinzugefügt; damit klappen Anmeldung und
   Verbindung.
5. Hinzugefügte Nodes stehen auf der Node, auf der sie hinzugefügt wurden, und im Cluster zusätzlich auf den anderen
   Mitgliedern (Bereich `environment/nodes`, Standard an). Ohne Cluster nur dort.
