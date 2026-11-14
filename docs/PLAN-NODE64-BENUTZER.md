# Plan: Benutzerverwaltung (mehrere Benutzer, Gruppen, LDAP/AD, Cluster)

Stand 2026-11-14, Wunsch Dennis: Eine Node soll von mehreren Personen verwaltet werden (Büro mit mehreren Leuten).
Neuer Menüpunkt unter Einstellungen für die Benutzerverwaltung: mehrere lokale Benutzer, Gruppen, 2FA je Benutzer,
SSO (Authentik usw.) und eine AD/LDAP-Anbindung an einer Stelle. **Klein halten**, aber clusterweit sauber
abgeglichen.

**Stand 2026-11-14: B1 und B2 gebaut** (Fundament 00fee2ef, Cluster 880bcee1, AD/LDAP fe1bd034, Rechte und
Oberfläche b688dee3). Bedienung: [ANMELDUNG.md](ANMELDUNG.md); Cluster: [CLUSTER.md](CLUSTER.md). Offen: Test gegen
echtes Samba-AD/OpenLDAP auf der Box, eigene Request-Header in PROXY64 für „Nur lesen“ ausblenden.

Abgrenzung: [PLAN-NODE64-LDAP.md](PLAN-NODE64-LDAP.md) beschreibt Node64 als LDAP-**Server** (LDAP64). Hier geht es um
das Gegenstück: Node64 meldet Benutzer **gegen** ein vorhandenes AD/LDAP an (LDAP-**Client**). Beides schließt sich
nicht aus; LDAP64 könnte später einfach als Verzeichnis für diese Anbindung dienen.

## Ausgangslage (Stand Code)

- Tabelle `users` mit Name, argon2id-Hash, TOTP (freiwillig, je Benutzer), Wiederherstellungscodes, Sprache,
  Zeitzone, Cluster-Kennung `uid`. Daran hängen Sitzungen, API-Keys, MCP-Keys, Passkeys, SSO-Verknüpfungen.
- **Keine Rollen, keine Gruppen, kein Sperren:** jeder Benutzer und jeder API-Key hat volle Rechte (`s.auth` prüft
  nur „angemeldet“).
- **Kein Weg, weitere Benutzer anzulegen:** nur Setup, `NODE64_ADMIN_USER` und der Cluster. Die Seite
  `/settings/login` (OIDC, Forward-Auth, Passkeys, „Benutzer dieser Node“ nur zum Löschen) ist nur über einen Link
  aus der 2FA-Karte erreichbar.
- **SSO:** genau ein OIDC-Anbieter (Authentik, Authelia, Keycloak, Pocket ID, Zitadel …), nur bereits verknüpfte
  lokale Konten, Gruppen-Claims werden nicht ausgewertet. Forward-Auth je Node.
- **Cluster:** `internal/usercluster` gleicht schon Benutzer (`users/accounts`) und SSO (`users/sso`) ab, mit
  sauberer Konfliktregel (gleicher Name, anderer Inhalt → zur Wahl auf `/cluster`), Schutz des letzten Benutzers,
  Sitzungsende bei Passwort-/2FA-Änderung. Darauf bauen wir auf – kein neues Protokoll.
- Schwachstelle nebenbei: das TOTP-Geheimnis liegt unverschlüsselt in `users.totp_secret`.

## Ziel in einem Satz

Einstellungen → **Benutzer** mit drei Reitern **Benutzer · Gruppen · Anmeldung**; zwei Rollen (Administrator,
Nur lesen); Gruppen bündeln Benutzer und geben ihnen eine Rolle; AD/LDAP und SSO legen Benutzer beim ersten Anmelden
an, wenn sie in einer zugeordneten Gruppe sind; alles über den vorhandenen Bereich `users` im Cluster.

## Entwurf

### Rollen (bewusst nur zwei)

| Rolle | Darf |
|---|---|
| **Administrator** | alles wie heute |
| **Nur lesen** | alle Seiten und GET-APIs ansehen; nichts ändern; eigenes Profil, Passwort, 2FA, Passkeys und eigene (dann ebenfalls nur lesende) API-Keys pflegen. Kein Zugriff auf Geheimnisse und Downloads mit Schlüsseln: Backup/Export, Zertifikats-Schlüssel und -Bundles/PKCS#12, Benutzerverwaltung, Cluster-Kopplung |

- Wirksame Rolle = höchste Rolle aus eigener Rolle und allen Gruppen.
- **Prüfung zentral, nicht je Handler:** in `s.auth` und `Guards.Auth` der Module: Rolle „Nur lesen“ → jede
  ändernde Anfrage (`POST/PUT/PATCH/DELETE`) 403, außer einer kleinen Liste für das eigene Konto
  (`/logout`, `/settings/user`, `/settings/password`, 2FA, Passkeys, eigene API-Keys). Dazu eine Liste
  „nur Administrator, auch beim Lesen“ (Backup, Export, Schlüssel-Downloads, Benutzerverwaltung, Kopplungscode).
  Module brauchen dafür keine Änderung; wo ein Modul einen GET mit Geheimnis hat, bekommt es `Guards.Admin`.
- Oberfläche: Knöpfe zum Ändern sind für „Nur lesen“ ausgegraut (Hinweis „nur lesen“ oben); sicher ist es auch ohne,
  weil der Server prüft.
- MCP bleibt wie es ist (ohnehin nur lesend).

### Benutzer

- Felder neu: `role` (admin/read), `disabled`, `source` (`local`, `ldap`, `oidc`), `email` (optional, nur Anzeige
  und Zuordnung), `groups` (Liste von Gruppen-Kennungen).
- Admins können: anlegen (Name, Passwort oder „Passwort beim ersten Anmelden setzen“), Rolle und Gruppen ändern,
  sperren/entsperren, Passwort setzen, **2FA zurücksetzen**, Sitzungen beenden, löschen.
- **2FA:** bleibt je Benutzer (App-TOTP, Passkeys). Neu: Schalter **„2FA für alle Pflicht“** (gilt für lokale und
  LDAP-Benutzer; SSO-Benutzer erledigen 2FA beim Anbieter). Wer keine 2FA hat, landet nach der Anmeldung auf der
  Einrichtung und kommt sonst nirgends hin. TOTP-Geheimnis künftig mit `secret.key` verschlüsselt (Cluster: im
  Klartext über die gebundene Verbindung, beim Empfänger neu verschlüsselt – wie das SSO-Secret).
- **Schutz:** nie den letzten aktiven **lokalen** Administrator sperren, herabstufen oder löschen (LDAP/SSO können
  ausfallen). Gesperrt oder herabgestuft → Sitzungen enden sofort, API-Keys folgen der neuen Rolle bzw. gelten nicht
  mehr. Notfall bleibt `node64 reset-password` (setzt zusätzlich `role=admin`, `disabled=0`).

### Gruppen

- Name, Rolle, Beschreibung, **Zuordnungen nach außen**: LDAP-Gruppen-DN(s) und/oder OIDC-Gruppenname(n).
- Mitglieder: lokal zugeordnete Benutzer plus automatisch alle, deren LDAP-/OIDC-Gruppen passen (bei jeder Anmeldung
  neu ermittelt).
- Keine verschachtelten Gruppen, keine Rechte je Modul (bewusst – „klein halten“). Später möglich, ohne das Modell
  zu brechen.

### Anmeldung (Reiter „Anmeldung“)

Die bisherige Seite `/settings/login` zieht hierher: SSO/OIDC, Forward-Auth, Passkeys, 2FA-Pflicht, dazu neu
**AD/LDAP**.

- **AD/LDAP (Client):** Server (mehrere, `ldaps://` oder StartTLS; Klartext nur mit Schalter), Profil
  „Active Directory“ oder „LDAP (OpenLDAP, LDAP64, lldap …)“, Bind-DN + Passwort (Dienstkonto, verschlüsselt), Base-DN,
  Benutzerfilter (Vorbelegung je Profil: `sAMAccountName`/`userPrincipalName` bzw. `uid`), Gruppen über `memberOf`
  (AD auch verschachtelt per `1.2.840.113556.1.4.1941`). Knopf **„Verbindung testen“** (Bind + Suche nach einem
  Namen, zeigt gefundene Gruppen).
- **Ablauf:** Anmeldeformular bleibt eines. Lokaler Benutzer mit `source=local` → wie heute. Sonst, wenn LDAP an:
  Benutzer suchen, mit seinem Passwort binden, Gruppen lesen → passt mindestens eine Node64-Gruppe, wird der Benutzer
  **beim ersten Mal angelegt** (`source=ldap`, kein lokales Passwort) bzw. Rolle/Gruppen aktualisiert; passt keine,
  wird abgelehnt. Gesperrt im AD → abgelehnt. Danach 2FA wie bei lokalen Benutzern (falls Pflicht oder eingerichtet).
- **SSO/OIDC:** wie heute „nur verknüpfte Konten“ als Standard; neu als Schalter **„Benutzer über Gruppen anlegen“**:
  Gruppen-Claim (Name einstellbar, Standard `groups`) gegen die Gruppen-Zuordnungen, sonst gleicher Ablauf wie LDAP
  (`source=oidc`).
- Passwort ändern/zurücksetzen für LDAP-/SSO-Benutzer gibt es in Node64 nicht (Hinweis „wird im Verzeichnis
  verwaltet“).
- Fehlversuche, Rate-Limit und Audit wie heute; LDAP-Anfragen mit Zeitlimit, Verbindungen begrenzt.

### Cluster (Bereich `users`, vorhanden)

| Bereich | Neu darin |
|---|---|
| `accounts` (vorhanden) | `role`, `disabled`, `source`, `email`, `groups`; TOTP-Geheimnis neu verschlüsselt beim Empfänger |
| `groups` (neu) | Gruppen mit Rolle und Zuordnungen |
| `sso` (vorhanden) | zusätzlich „Benutzer über Gruppen anlegen“ und Claim-Name |
| `directory` (neu) | LDAP-Einstellungen und der Schalter „2FA für alle Pflicht“ (sonst hätte jede Node eine andere Regel); Bind-Passwort wie das SSO-Secret (beim Empfänger mit eigenem `secret.key`) |
| bleibt je Node | Forward-Auth, Passkeys, Sitzungen, API-/MCP-Keys, Fehlversuche |

Regeln, die neu dazukommen:

- **Gleiche Kennung bei automatisch angelegten Benutzern:** `uid` wird aus der Quelle abgeleitet
  (LDAP: `objectGUID`/`entryUUID`, OIDC: Issuer+Subject → Hash). Melden sich dieselben Leute gleichzeitig an zwei
  Nodes zum ersten Mal an, entsteht derselbe Benutzer – kein Konflikt zur Wahl.
- Mitgliedschaften stehen am **Benutzer** (Ganzes gewinnt, jüngere Änderung) – reicht für die kleine Gruppenzahl;
  eine gelöschte Gruppe wird bei Benutzern einfach übergangen.
- „Letzter lokaler Admin“ prüft jede Node bei sich: eine Übernahme, die ihn sperren/löschen würde, wird für ihn
  nicht übernommen (wie heute „letzter Benutzer“, Audit `user.cluster.keep_last`).
- Sperren, Rollenwechsel und Löschen enden die Sitzungen auf **jeder** Node beim Übernehmen.
- Bestehende Konfliktregel (gleicher Name, anderer Inhalt → zur Wahl) bleibt unverändert; Rolle/Sperre zählen zum
  Inhalt.

### API und Audit

- `/api/users`: anlegen, ändern (Rolle, Gruppen, Sperre, E-Mail), Passwort setzen, 2FA zurücksetzen, Sitzungen
  beenden, löschen – nur Administrator. `/api/groups` (CRUD), `/api/auth/ldap` (lesen/ändern/testen, Passwort nie
  zurück). Eigenes Passwort/2FA bleiben bewusst ohne API.
- `GET /api/users/me` liefert die wirksame Rolle (für Skripte und die Oberfläche).
- Audit: Akteur zusätzlich mit `uid` (Name kann sich ändern); neue Aktionen `user.create|update|disable|enable|
  role|2fa_reset|sessions_end|delete`, `group.*`, `auth.ldap.*`, `login.ldap`; 403 durch Rolle als Warnung im Log.

## Phasen (so wenige wie möglich)

| Phase | Inhalt | Aufwand grob |
|---|---|---|
| **B1 Benutzer, Rollen, Gruppen** | Schema (`role`, `disabled`, `source`, `email`, Gruppen-Tabelle); zentrale Rechteprüfung + Admin-Liste; Menüpunkt Einstellungen → Benutzer mit Reitern Benutzer/Gruppen/Anmeldung (Login-Seite zieht um); Anlegen/Bearbeiten/Sperren/2FA-Reset; 2FA-Pflicht; TOTP verschlüsselt; Cluster: `accounts` erweitert + `groups`; API, i18n, openapi, Tests (Rechte-Matrix je Route, Cluster mit zwei Nodes), Doku | ca. 1,5–2 Wochen |
| **B2 AD/LDAP und SSO-Gruppen** | LDAP-Client (`github.com/go-ldap/ldap/v3`, MIT), Einstellungen + „Verbindung testen“, Anmeldung mit Anlage beim ersten Mal, Gruppen-Zuordnung, OIDC-Gruppen-Claim; Cluster `directory` (LDAP + 2FA-Pflicht, in B1 zunächst nur die 2FA-Pflicht); stabile `uid` aus der Quelle; Tests gegen Samba-AD und OpenLDAP (Container auf der Box), Doku | ca. 1 Woche |

Nach B1 ist die Node mehrbenutzerfähig (lokale Konten + vorhandenes SSO); B2 bringt das Büro-AD dazu. B1 und B2
lassen sich nicht sinnvoll parallel bauen (B2 braucht Gruppen und Rollen aus B1).

**Risiken:** vergessene Routen in der Rechteprüfung → deshalb „ändernd = verboten“ als Grundregel und ein Test, der
alle registrierten Routen mit einem Nur-lesen-Benutzer abklopft; Aussperren durch LDAP-Ausfall → lokaler Admin
bleibt Pflicht; Altgeräte ohne TLS beim LDAP → Klartext nur per Schalter.

## Entscheidungen (Dennis, 2026-11-14)

1. Rollen: nur **Administrator** und **Nur lesen**.
2. AD/LDAP: Benutzer werden beim ersten Anmelden angelegt, wenn sie in einer zugeordneten Gruppe sind.
3. SSO: Anlage über den Gruppen-Claim als Schalter, **Standard aus**.
4. 2FA-Pflicht: **ein** Schalter für alle.
5. Cluster: Benutzer-Abgleich bleibt ein Schalter (wie heute, Standard aus).
6. Menüname: **Benutzerverwaltung**.
7. Die Benutzerverwaltung ist **nur lokal für Node64** und hat mit ipv64.net nichts zu tun (keine Portal-, hub- oder
   API-v2-Änderung).
8. B1 und B2 parallel bauen; an **allen** Stellen prüfen, dass „Nur lesen“ greift.

## Gemeinsamer Vertrag (Fundament, vor dem parallelen Bau)

- **Schema** `internal/store/migrations/0008_user_admin.sql`: `users.role|disabled|source|email|group_uids|
  ext_group_uids|must_change`, Tabelle `user_groups` (uid, name, role, description, ldap_groups, oidc_groups).
- **Store** `internal/store/users.go`: `RoleAdmin/RoleRead`, `SourceLocal/LDAP/OIDC`, `CreateUserWith(NewUser)`,
  `UserByUID`, `UpdateUserAdmin(UserAdmin)`, `SetUserExtGroups`, `SetUserMustChange`, `EffectiveRole`,
  `ActiveLocalAdmins(exclude)`, Gruppen `Groups/GroupByUID/SaveGroup/DeleteGroup` (meldet `LoginChanged("groups")`).
- **Einstellungen** `internal/authcfg`: `LDAPConfig` (`auth.ldap`, Bind-Passwort mit `secret.key` verschlüsselt),
  `auth.2fa_required`, `auth.oidc.jit`, `auth.oidc.group_claim`; Speichern meldet `LoginChanged("directory","auth")`.

## Aufteilung (parallel, je ein Worktree)

| Teil | Inhalt | Dateien (Besitz) |
|---|---|---|
| A Oberfläche + Rechte | zentrale Rechteprüfung (`s.auth`, `Guards`, Admin-Liste), Test über alle Routen; Einstellungen → Benutzerverwaltung (Benutzer, Gruppen, Anmeldung; Login-Seite zieht um); 2FA-Pflicht und „Passwort beim ersten Anmelden setzen“ im Anmeldeablauf; Sperre wirkt auf Sitzungen/API-Keys; `/api/users`, `/api/groups`; „Nur lesen“-Hinweis in der Oberfläche; i18n `useradmin.*`, `nav.useradmin`; openapi | `internal/web/**` (ohne LDAP-Dateien), `internal/module` (Guards), Module nur wo GETs Geheimnisse liefern |
| B Cluster | `usercluster`: `accounts` um Rolle/Sperre/Herkunft/E-Mail/Gruppen/MustChange; neue Bereiche `groups` und `directory` (LDAP + 2FA-Pflicht, Bind-Passwort neu verschlüsselt); `sso` um JIT/Claim; Sitzungsende bei Sperre/Rolle; letzter lokaler Admin; TOTP-Geheimnis verschlüsselt speichern (Store-Hook); Tests mit zwei Nodes | `internal/usercluster/**`, `internal/store` (nur TOTP-Hook), Verdrahtung `cmd/node64/main.go` (Zeilen) |
| C AD/LDAP + SSO-Gruppen | Paket `internal/ldapauth` (go-ldap/v3: Verbindung, Test, Anmelden, Gruppen); Anmeldung lokal→LDAP mit Anlage beim ersten Mal (stabile UID aus `objectGUID`/`entryUUID`); OIDC-Gruppen-Claim mit Anlage; Karte „AD/LDAP“ als eigenes Template-Teil für den Reiter Anmeldung; API `/api/auth/ldap`; i18n `ldap.*`; Tests gegen einen Test-LDAP-Server | `internal/ldapauth/**`, `internal/web/auth_ldap*.go`, `internal/web/templates/partials/ldap_card.html` |

## Offene Fragen an Dennis (beantwortet, siehe Entscheidungen)

1. **Rollen:** reichen „Administrator“ und „Nur lesen“? (Empfehlung: ja; eine dritte Rolle wie „Bediener“ – z. B.
   Checks pausieren, quittieren – erst bei Bedarf.)
2. **LDAP/AD:** Benutzer beim ersten Anmelden automatisch anlegen, wenn sie in einer zugeordneten Gruppe sind?
   (Empfehlung: ja, das ist der übliche Büro-Fall; Alternative wäre „nur vorher angelegte/verknüpfte“.)
3. **SSO:** dasselbe auch für OIDC über den Gruppen-Claim anbieten (Schalter, Standard aus)? (Empfehlung: ja.)
4. **2FA-Pflicht:** ein Schalter für alle (Empfehlung) oder je Gruppe?
5. **Cluster:** Benutzer-Abgleich bleibt wie heute ein Schalter (Standard aus) – oder bei neuen Clustern
   standardmäßig an?
6. **Menüname:** „Benutzer“ (Empfehlung) oder „Benutzerverwaltung“?
