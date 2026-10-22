# Plan: LDAP/LDAPS-Verzeichnis (und AD) in Node64

Stand 2026-10-22, Frage Dennis: „Wie schwer wäre es, in den Node64-Container einen LDAP-, LDAPS-, AD-Server
anzubieten? Der hostet die Domain als Cluster.“ **Nur Planung**, nichts gebaut. Grundlagen: [CLUSTER.md](CLUSTER.md),
[PLAN-NODE64-CLUSTER-MODULE.md](PLAN-NODE64-CLUSTER-MODULE.md), [ZERTIFIKATE.md](ZERTIFIKATE.md),
[ANMELDUNG.md](ANMELDUNG.md). Arbeitsname des Moduls: **LDAP64** (technische Kennung `ldap64`).

## Kurzantwort

| Variante | Was es kann | Schwierigkeit | Passt zu Node64? |
|---|---|---|---|
| (a) LDAP/LDAPS-Verzeichnis in Go | Benutzer/Gruppen für Apps (Bind + Suche), LDAPS/StartTLS | mittel | ja: ein Modul im Binary, Cluster über `/peer/v2/sync` |
| (c) wie (a) + „AD-kompatibles LDAP“ | Apps, die nur „Active Directory“ anbieten (UPN-Bind, `sAMAccountName`, `memberOf`, verschachtelte Gruppen) | mittel (+1 Phase) | ja, Erweiterung von (a) |
| (c') + eigenes Kerberos | Single Sign-On per Ticket | sehr hoch | nein: kein Go-KDC, Sicherheitsrisiko |
| (b) echter AD-DC (Samba) im Node64-Image | Windows-Domänenbeitritt, GPOs, SMB/Netlogon | sehr hoch | nein: bricht `scratch`/ein Binary, braucht `CAP_SYS_ADMIN`, Port 53 kollidiert mit DNS64 |
| (b') Samba als Begleit-Container, von Node64 verwaltet | wie (b) | hoch + Dauerpflege | nur als spätere, eigene Option |

**Empfehlung:** (a)+(c) als Modul LDAP64 bauen; echtes AD (b) nicht in den Node64-Container, höchstens später als
eigener Begleit-Container (b'), wenn Windows-Domänenbeitritt wirklich gefragt ist. Begründung unten.

## Bausteine (Stand Oktober 2026)

| Baustein | Lizenz | Zustand | Rolle |
|---|---|---|---|
| `github.com/jimlambrt/gldap` | MIT | v0.1.14 (08/2024), seitdem keine Commits; genutzt von HashiCorp (Boundary/Vault-Tests) | LDAP-Server-Gerüst: Bind, Search, Add, Modify, Delete, LDAPS, StartTLS, mTLS; Controls u. a. Paging, Password-Policy, MS-Controls |
| `github.com/vjeantet/ldapserver` | MIT | älter, wenig Bewegung | alle Grundoperationen + Extended Ops; Alternative zu gldap |
| `github.com/go-asn1-ber/asn1-ber`, `github.com/go-ldap/ldap/v3` | MIT | aktiv (go-ldap-Projekt) | BER-Kodierung, Filter-Parser; go-ldap als Client für Tests |
| GLAuth | MIT | aktiv, v2.5.4 (09/2026, Sicherheitsrelease); v2.5.0 brachte StartTLS/LDAPS-Gleichstand, Paging | Vorbild (Rechte je Konto, POSIX-Attribute); eigenständige App, keine Bibliothek |
| lldap | **GPLv3**, Rust | aktiv, v0.6.3 (05/2026) | Vorbild für Umfang und Oberfläche (Benutzer, Gruppen, eigene Attribute, Paging, `memberOf`); **keinen Code übernehmen** |
| Samba AD DC | **GPLv3**, C + Python | aktiv, 4.25.0 (09/2026), 4.23/4.24 mit Sicherheitsupdates; 2026 mehrere CVEs (bis CVSS 8.8) | einziger realistischer Weg zu echtem AD |
| `github.com/jcmturner/gokrb5` | Apache-2.0 | (schon indirekt im Modul-Graph über lego) | nur Kerberos-**Client**/Dienst, **kein KDC** |

Folgerung: Für (a)/(c) gibt es keinen fertigen, gepflegten Go-Server, den man „einfach einbindet“. Realistisch ist
gldap als Gerüst (MIT, klein, Ops und Controls reichen) hinter einer eigenen Schnittstelle in `internal/ldap64`; stockt
gldap (Bugs, fehlende Extended Ops), wird es nach `internal/` übernommen (MIT erlaubt das, Lizenzhinweis behalten) oder
eine dünne eigene Schicht auf asn1-ber gebaut. Das LDAP-Protokoll selbst ist überschaubar, der Aufwand steckt in
Filtern, Schema-Verhalten und App-Kompatibilität.

## Variante (a)/(c): LDAP64 im Binary

### Umfang

- **Protokoll:** LDAPv3; Bind (simple: DN, `uid`, UPN `name@domain`, `DOMAIN\name`), Search (alle Filter inkl.
  Teilstring, `present`, `approx` als `equal`), RootDSE (`namingContexts`, `supportedControl`, `supportedExtension`),
  Subschema (minimal), Paging (RFC 2696), WhoAmI, Password-Modify (RFC 3062), Unbind/Abandon. Schreiben (Add/Modify/
  Delete) nur für Admin-Dienstkonten und erst in L3.
- **Schema:** `inetOrgPerson` + `posixAccount`/`shadowAccount` für Benutzer, `groupOfNames`/`groupOfUniqueNames` +
  `posixGroup` für Gruppen, `memberOf` am Benutzer, `entryUUID`. Base-DN aus der Domain (`home.lan` →
  `dc=home,dc=lan`), Zweige `ou=people`, `ou=groups`, `ou=services`.
- **AD-Profil (c):** zusätzlich `sAMAccountName`, `userPrincipalName`, `objectGUID`, `objectSid` (eigene Domänen-SID),
  `userAccountControl` (deaktiviert/gesperrt), `primaryGroupID`, `memberOf` und Abfragen mit
  `LDAP_MATCHING_RULE_IN_CHAIN` (1.2.840.113556.1.4.1941) für verschachtelte Gruppen, Passwortänderung über
  `unicodePwd` (nur über TLS). Damit funktionieren die „Active Directory“-Voreinstellungen von Nextcloud, Grafana,
  Gitea/Forgejo, Proxmox (Realm „Active Directory“), Jellyfin-Plugin, Portainer u. a.
- **Ausdrücklich nicht:** Windows-Domänenbeitritt, Kerberos, NTLM/SMB-Anmeldung, GPOs, Replikation zu fremden
  LDAP-Servern, beliebige Schema-Erweiterungen (nur eigene Attribute je Benutzer wie bei lldap, später).
- **NAS/SMB-Grenze:** Synology/TrueNAS/QNAP prüfen SMB-Anmeldungen per NTLM und brauchen dafür den NT-Hash
  (`sambaNTPassword`). Das ist ein passwortgleiches MD4-Geheimnis. Nur als Schalter „NT-Hash speichern“ (Standard aus,
  verschlüsselt mit `secret.key`) – offene Frage 3.

### Integration in Node64

| Thema | Plan |
|---|---|
| Modul | `internal/ldap64` nach `module.Module` (Info, Migrations, Routes, Start/Stop), aus = keine Ports, keine Goroutinen; `Exporter`, `CardProvider` (Benutzer, Binds/min, Fehlversuche), Version + CHANGELOG wie die anderen Module |
| Speicher | eigene Tabellen in `node64.db` (Benutzer, Gruppen, Mitgliedschaften, Dienstkonten, Einstellungen, Sperren); jede Zeile mit Cluster-Kennung (UUID) |
| Oberfläche | Menüpunkt LDAP64: Benutzer (anlegen, sperren, Passwort setzen, Gruppen), Gruppen, Dienstkonten (Bind-Konten je App, nur lesen, Sicht auf Zweige beschränkbar), Einstellungen (Domain, Ports, TLS, Profil Standard/AD); Seite „Apps verbinden“ mit fertigen Werten (Server, Base-DN, Bind-DN, Filter) für Nextcloud, Gitea, Proxmox, Grafana, Jellyfin, Synology; „Testsuche“ |
| Ports | 389 (LDAP + StartTLS) und 636 (LDAPS), frei wählbar; Anmeldung in `internal/ports` gegen Überschneidung; `cap_net_bind_service` hat das Binary schon (+p). Dockerfile: `EXPOSE 389 636` ergänzen |
| Zertifikate | Abnehmer der Zentrale wie DNS64: `certs.SetUsers("ldap64", …)` („benutzt von LDAP64“), `ForName`/fest gewählte Kennung, `OnChange` tauscht ohne Neustart. Für LAN-Namen die eigene CA empfehlen (Download für Clients vorhanden) |
| TLS-Regeln | Simple Bind ohne TLS standardmäßig **abgelehnt** (`confidentialityRequired`); Schalter „Klartext erlauben“ nur für Altgeräte; TLS 1.2+ |
| DNS | optional `_ldap._tcp.<domain>`/`_ldaps._tcp.<domain>` (SRV) und A-Einträge je Node in DNS64 anlegen (DNS64 kann SRV und lokale Zonen) – als Vorschlag mit Knopf, nicht still |
| Anmeldung Node64 | später (L6): „Mit Verzeichnis-Konto anmelden“ nur für Benutzer, die ihr lokales Konto verknüpft haben (gleiche Regel wie OIDC), sonst getrennt |
| MCP | höchstens lesend (`ldap_users` ohne Hashes/Attribute mit Geheimnissen); keine Änderungen über MCP |

### Sicherheit

- **Erreichbarkeit:** standardmäßig nur private Netze (wie MCP); öffentliche Quelladressen bekommen keinen Bind.
  Kein Weg über PROXY64/CDN64 in der ersten Version.
- **Anonymer Bind** aus; RootDSE ohne Anmeldung lesbar (das erwarten Clients), sonst nichts.
- **Rechte:** Dienstkonten lesen nur, Sicht auf Zweige/Gruppen beschränkbar; `userPassword`, NT-Hash und
  Sperrdaten werden nie ausgeliefert; Schreiben nur Admin-Dienstkonto (L3).
- **Passwörter:** argon2id wie die Node64-Anmeldung (`internal/web/auth.go`). Bei 64 MiB je Prüfung braucht es eine
  Grenze gleichzeitiger Prüfungen und einen kurzen Erfolgs-Cache (wie PROXY64 bei bcrypt, 5 min), sonst ist ein
  Bind-Sturm ein Speicher-DoS. Import fremder Hashes (`{SSHA}`, `{CRYPT}`, bcrypt) erlaubt, beim nächsten Bind auf
  argon2id umgestellt.
- **Rate-Limit und Sperre:** je Quell-IP und je Konto (z. B. 10 Fehlversuche → 15 min gesperrt, Meldung über die
  Standardkanäle); Fehlversuche ins Audit (Bereich `ldap64`), Prometheus-Zähler; Grenzen für Verbindungen je IP,
  Leerlauf-Timeout, Größe/Tiefe von Filtern, Ergebnisgröße (Paging erzwingen ab z. B. 1000 Treffern).
- **Optional:** wiederholte Fehlversuche einer IP an die vorhandene Sofortsperre/Firewall geben (nur LAN, Standard aus).

### Cluster: „die Domain als Cluster hosten“

Jede Node mit LDAP64 hat die **vollständige Kopie** und beantwortet Binds und Suchen selbst. Apps tragen mehrere
Server ein (Nextcloud, Proxmox, Gitea können das) oder einen Namen mit mehreren A-Einträgen/SRV. Geschrieben werden
darf auf **jeder** Node (Multi-Master wie im übrigen Cluster: kein Anführer, jüngere Änderung gewinnt, je Eintrag als
Ganzes). Das passt ohne neues Protokoll auf `/peer/v2/sync` (Provider über ein kleines Paket `ldap64/ldapcluster`,
damit `ldap64` nicht von `peer` abhängt – wie `dns64cluster`).

| Bereich | Standard | Inhalt / Regel |
|---|---|---|
| `settings` | aus | Domain, Base-DN, Profil, Passwortregeln, Sperr-Grenzen; **nicht**: Ports, Schnittstellen, Zertifikat, Netze |
| `users` | aus | Benutzer samt argon2id-Hash (PHC-Text; ist ein Hash, wird trotzdem wie ein Geheimnis behandelt); NT-Hash nur mit Schalter, über die gebundene HTTPS-Verbindung entschlüsselt, hier mit dem eigenen `secret.key` neu verschlüsselt (wie Zertifikatsschlüssel) |
| `groups` | aus | Gruppen |
| `memberships` | aus | je Mitgliedschaft ein Eintrag (Gruppe+Mitglied) – so gehen bei gleichzeitigen Änderungen auf zwei Nodes keine Mitgliedschaften verloren |
| `services` | aus | Dienstkonten mit Rechten |
| nie | – | Fehlversuchszähler und automatische Sperren (je Node), Statistik (live abgefragt), Ports, TLS |

**Besonderheiten:**
- **Sperren:** Fehlversuche zählt jede Node für sich (ein Angreifer hat also N Versuche je Node); eine von Hand
  gesetzte Sperre/Deaktivierung ist Teil des Benutzers und wird abgeglichen.
- **`uidNumber`/`gidNumber`:** zwei Nodes könnten im Split-Brain dieselbe Nummer vergeben. Vorschlag: Nummer aus
  einem Block je Node (Block aus der Node-Kennung abgeleitet) oder höchste+1 mit Konfliktprüfung beim Übernehmen
  (jüngerer Eintrag bekommt neue Nummer, Hinweis in der Oberfläche). Entscheidung in L0.
- **Split-Brain:** Passwort auf A geändert → auf B gilt bis zur Wiederverbindung das alte; ein auf A gelöschter
  Benutzer kann sich auf B weiter anmelden. Für Heimnetz/kleine Firma tragbar, in der Doku nennen.
  Löschvermerke 30 Tage wie bei v2 (Trennung > 30 Tage: Gelöschtes kann zurückkommen).
- **Erstes Einschalten:** vorhandene Einträge über `uid`/Gruppenname zusammenführen, sonst Duplikate.
- **Uhrzeit:** schon Cluster-Voraussetzung (NTP, ±5 min).

### Backup/Export

- Backup-Archiv (mit Passwort) enthält die DB ohnehin; nichts Neues nötig.
- `Exporter`: Benutzer, Gruppen, Dienstkonten; Hashes nur „mit Passwort“ (`SecretSealer`), sonst ohne.
- LDIF-Export/-Import (Umzug von/zu OpenLDAP, GLAuth, lldap). Aus lldap kommen keine Hashes (OPAQUE) → Benutzer
  brauchen neue Passwörter; aus OpenLDAP/GLAuth lassen sich `{SSHA}`/bcrypt übernehmen.

## Variante (b): echter Active-Directory-DC mit Samba

Was ein Windows-Domänenbeitritt verlangt: DNS mit AD-Zonen (`_msdcs`, SRV), CLDAP (UDP 389) für den DC-Locator,
Kerberos (88, 464), LDAP/LDAPS (389/636), Global Catalog (3268/3269), SMB (445) mit Netlogon/SYSVOL, RPC (135 +
dynamische Ports 49152–65535), signiertes NTP. Das in Go nachzubauen ist kein realistisches Projekt – es bleibt Samba.

### Samba im Node64-Image – nicht empfohlen

- Node64 ist `FROM scratch` mit einem statischen Binary als Benutzer 65532. Samba braucht libc, Python
  (`samba-tool`), dutzende Bibliotheken, einen Prozess-Wächter → Basis-Image, Prozessverwaltung, Root.
- Der DC braucht `security.NTACL`-xattrs → `CAP_SYS_ADMIN` bzw. `--privileged`. Das gälte dann für den ganzen
  Node64-Container (Tunnel, Honeypot-Profil, DNS64 …) – deutlich mehr Angriffsfläche.
- **Port 53:** Samba-DNS hört fest auf 53 (eigener Port wurde upstream abgelehnt, Bug 14599). DNS64 belegt 53 →
  Samba braucht eine eigene IP (macvlan) oder DNS64 muss weichen.
- Image wächst um ein Vielfaches (Samba-DC mit Python und Abhängigkeiten: grob 150–350 MB statt eines Binarys);
  Samba-Sicherheitsupdates (2026 mehrfach, bis CVSS 8.8) erzwingen dann Node64-Releases.
- **GPLv3:** Samba als eigenes Programm im selben Image ist eine „Zusammenstellung“ (GPLv3 §5) – der Node64-Code
  bleibt unberührt und darf privat bleiben. Aber wer das Image verteilt (GHCR öffentlich), muss den **vollständigen
  Quellcode der enthaltenen GPL-Teile** in genau dieser Version anbieten (beilegen oder schriftliches Angebot, 3 Jahre)
  plus Lizenztexte; das gilt dann auch für alle weiteren GPL/LGPL-Pakete des Basis-Images. Machbar, aber Pflicht
  bei jedem Release.

### Samba als Begleit-Container (b') – möglich, aber teuer

Eigenes Image `node64-ad` (z. B. Alpine `samba-dc` oder Grundlage `samba-in-kubernetes/samba-container`), eigene
IP (macvlan/Host-Netz auf zweiter IP), `--cap-add SYS_ADMIN`. Node64 verwaltet es:

- Bereitstellen bzw. Beitritt über einen kleinen Agenten im Begleit-Container (HTTPS, an die Node gebunden) oder
  Startparameter; Benutzer/Gruppen danach über **LDAPS mit Admin-Bind** aus der LDAP64-Oberfläche (Samba kann
  `unicodePwd` über LDAPS) – die Oberfläche aus (a) wäre also wiederverwendbar.
- DNS64 leitet die AD-Domain und `_msdcs.<domain>` an die DC-IPs weiter (Weiterleitungen gibt es schon).
- Zertifikat für LDAPS aus der Zentrale per Datei-Übergabe oder API (`/api/certs/{id}/bundle`).

**Cluster bei Samba:** Hier repliziert **Samba selbst** (DRS, Multi-Master zwischen DCs) – Node64 darf Benutzer
nicht zusätzlich über `/peer/v2/sync` abgleichen, sonst gibt es zwei Wahrheiten. Node64 koordiniert nur:
weitere Node = `samba-tool domain join … DC`, FSMO-Rollen-Anzeige. Offene Baustellen: **SYSVOL** (GPOs,
Anmeldeskripte) repliziert Samba nicht (kein DFS-R/FRS) → nur Einweg-Abgleich vom DC mit der PDC-Emulator-Rolle,
Änderungen nur dort; `idmap.ldb` ebenso. **Backup:** nie einen alten DC-Stand zurückspielen, wenn andere DCs
weiterlaufen (USN-Rollback zerstört die Replikation) → eigener Weg über `samba-tool domain backup` und
„Wiederherstellen = neu beitreten“; das Node64-Backup/Reset muss das kennen. Kerberos verlangt Zeitgleichheit
(±5 min, deckt sich mit dem Cluster).

## Phasen

### Empfohlen: LDAP64 (a)+(c)

| Phase | Inhalt | Aufwand grob |
|---|---|---|
| L0 | Vertrag: Schema, DN-Aufbau, Profil Standard/AD, Nummernvergabe, Bibliothek (gldap vs. eigene Schicht) mit kleinem Spike gegen `ldapsearch` und Nextcloud | 1–2 Tage |
| L1 | Kern: Modul, Tabellen, Server 389/636/StartTLS, Bind (DN/uid/UPN), Search mit Filtern, Paging, RootDSE, nur lesen; argon2id mit Grenze + Cache; Zertifikat aus der Zentrale; Ports-Registry; nur LAN; Rate-Limit/Sperre; Audit, Metriken; Tests mit go-ldap-Client | 1,5–2 Wochen |
| L2 | Oberfläche: Benutzer, Gruppen, Dienstkonten, Passwort setzen, Einstellungen, „Apps verbinden“ mit Werten je App, Testsuche, Dashboard-Karte; i18n de/en; openapi | ca. 1 Woche |
| L3 | AD-Profil (c): `sAMAccountName`, UPN, `objectSid/GUID`, `userAccountControl`, `memberOf`, IN_CHAIN, Password-Modify/`unicodePwd`; Schreiben für Admin-Dienstkonto; Kompatibilitätstests (Nextcloud, Gitea/Forgejo, Proxmox, Grafana, Jellyfin, Synology ohne SMB) | ca. 1 Woche |
| L4 | Cluster: Provider (`settings`, `users`, `groups`, `memberships`, `services`), Zusammenführen beim ersten Einschalten, Nummernkonflikte, Live-Test mit zwei Nodes; SRV/A-Vorschlag in DNS64 | 3–5 Tage |
| L5 | Export/Import (JSON + LDIF), Doku `docs/LDAP64.md` + node64.de, Lasttest (Binds/s, 5000 Benutzer), CHANGELOG | 3–4 Tage |
| L6 (optional) | Node64-Anmeldung mit Verzeichnis-Konto (nur verknüpfte), NT-Hash-Schalter für NAS/SMB, eigene Attribute | je 2–4 Tage |

Summe L0–L5: **grob 4–6 Wochen** Entwicklungszeit; L1 und L2 lassen sich nach L0 parallel in zwei Sitzungen bauen.
Neue Abhängigkeiten: gldap (oder nur asn1-ber), go-ldap (Tests/Filter) – alle MIT, Binary wächst nur wenig.

**Risiken:** App-Eigenheiten (jede App fragt anders: Filter, Attributnamen, Groß-/Kleinschreibung von DNs) –
dagegen L3 mit echten Apps testen; gldap ungepflegt seit 08/2024 → früh entscheiden, ob übernehmen; argon2id-Kosten
bei vielen Binds; Erwartung „AD“ bei Nutzern, die Windows-Beitritt meinen → klar benennen „AD-kompatibles LDAP“.

### Nicht empfohlen / später: Samba-Begleit-Container (b')

| Phase | Inhalt | Aufwand grob |
|---|---|---|
| B0 | Spike: Samba-DC in Container mit eigener IP, Windows 11 tritt bei, DNS64-Weiterleitung | 3–5 Tage |
| B1 | Begleit-Image + Agent, Bereitstellen/Beitritt aus Node64, Zertifikatsübergabe | 1–2 Wochen |
| B2 | Verwaltung über LDAPS (Oberfläche aus L2/L3 wiederverwenden) | 1 Woche |
| B3 | Zweiter DC je Node (DRS), SYSVOL-Einweg-Abgleich, FSMO-Anzeige | 1–2 Wochen |
| B4 | Backup/Restore ohne USN-Rollback, Reset, Updates des Samba-Images, GPL-Quellangebot | 1 Woche |
| B5 | Doku (Netz: macvlan, Ports, Windows-Beitritt, GPO-Grenzen) | 3–5 Tage |

Summe **grob 6–10 Wochen** plus dauerhafte Pflege (Samba-Updates, Windows-Supportfälle). Risiko hoch: privilegierter
Container, Netzaufbau beim Nutzer (zweite IP), DNS-Fehler machen Domänenbeitritt kaputt, SYSVOL ohne echte
Replikation.

## Empfehlung

1. **LDAP64 (a)+(c) im Binary bauen.** Deckt den typischen Heimnetz-/Kleinfirmen-Fall (zentrale Konten für
   Nextcloud, Gitea, Proxmox, Grafana, Jellyfin, NAS-Weboberfläche) vollständig ab, bleibt ein statisches Binary im
   `scratch`-Image, nutzt Zertifikate-Zentrale, DNS64 und Cluster ohne neues Protokoll, keine GPL-Pflichten.
2. **Kein Samba im Node64-Image.** Privilegien, Port-53-Konflikt mit DNS64, Größe, GPL-Quellpflicht und
   Samba-Sicherheitsupdates widersprechen dem Aufbau von Node64.
3. **Echtes AD nur, wenn Windows-Domänenbeitritt ausdrücklich gebraucht wird** – dann als eigener Begleit-Container
   (b') nach LDAP64, die Verwaltungsoberfläche wird wiederverwendet. Bis dahin in der Doku auf ein separates Samba
   oder Windows Server verweisen.

## Offene Fragen an Dennis

1. **Ziel:** Reicht „AD-kompatibles LDAP“ für Apps, oder sollen Windows-PCs der Domäne beitreten (dann später b')?
2. **Schreiben im Cluster:** auf jeder Node (wie bisher, jüngere Änderung gewinnt) oder nur auf einer festen
   Schreib-Node mit Lesekopien?
3. **NAS/SMB:** NT-Hash als Schalter anbieten (nötig für SMB-Anmeldung an Synology/TrueNAS, passwortgleich), Standard
   aus – ja oder ganz weglassen?
4. **Node64-Anmeldung** mit Verzeichnis-Konten (nur verknüpfte Benutzer, wie OIDC) – gewünscht oder getrennt lassen?
5. **Name und Reichweite:** „LDAP64“ ok? Und fest nur private Netze (wie MCP), oder später LDAPS nach außen über
   PROXY64-Stream?

## Quellen

- gldap: <https://github.com/jimlambrt/gldap> (Tags/Commits bis 2024-08-30)
- GLAuth Releases: <https://github.com/glauth/glauth/releases>
- lldap: <https://github.com/lldap/lldap>, Releases: <https://github.com/lldap/lldap/releases>
- ldapserver: <https://github.com/vjeantet/ldapserver>
- Samba-Versionen: <https://endoflife.date/samba>, Samba 4.23.13/4.25.0: <https://www.warp2search.net/story/samba-42313-release-7-bug-fixes-as-422-series-hits-endoflife/>
- Samba-DNS-Port nicht änderbar: <https://bugzilla.samba.org/show_bug.cgi?id=14599>, <https://wiki.samba.org/index.php/Samba_Internal_DNS>
- SYSVOL-Replikation: <https://wiki.samba.org/index.php/SysVol_replication_(DFS-R)>, <https://wiki.samba.org/index.php/SysVol_Replication>
- Samba-DC im Container (`CAP_SYS_ADMIN`, xattr): <https://lists.samba.org/archive/samba/2019-July/224203.html>,
  <https://github.com/samba-in-kubernetes/samba-container/>, <https://helgeklein.com/blog/samba-active-directory-in-a-docker-container-installation-guide/>
