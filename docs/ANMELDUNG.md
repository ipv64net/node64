# Anmeldung: Benutzerverwaltung, Rollen, SSO, AD/LDAP, Forward-Auth, Passkeys

Lokale Benutzer mit Passwort (optional mit App-2FA) bleiben immer die Grundlage; mindestens ein aktiver lokaler
Administrator bleibt immer erhalten. Benutzer, Gruppen und die Anmeldewege verwaltest du unter **Einstellungen →
Benutzerverwaltung** (`/settings/users`, Reiter Benutzer, Gruppen, Anmeldung; nur für Administratoren). Jede Anmeldung
steht im Audit-Log, mit dem Weg (`sso …`, `ldap`, `passkey`, `forward-auth …`). Die Benutzerverwaltung gilt nur für
diese Node bzw. den Cluster – mit ipv64.net hat sie nichts zu tun.

Eigenes Passwort, eigene 2FA, Passkeys und verknüpfte SSO-Konten pflegt jeder Benutzer selbst unter **Einstellungen →
Allgemein**; diese gibt es bewusst nur in der Oberfläche. Administratoren können Benutzer, Gruppen, die 2FA-Pflicht und
die AD/LDAP- bzw. SSO-Gruppen-Einstellungen auch per API ändern (`/api/users`, `/api/groups`, `/api/auth/*`).

## Benutzerverwaltung und Rollen

| Rolle | Darf |
|---|---|
| **Administrator** | alles |
| **Nur lesen** | alle Seiten und GET-APIs ansehen, nur das eigene Konto ändern (Profil, Passwort, 2FA, Passkeys, eigene API-/MCP-Keys, Dashboard-Anordnung). Backups, Exporte, private Schlüssel, Passwörter und Tokens (z. B. Basic-Auth von Checks, TSIG, Push-Token, Werte eigener Request-Header in PROXY64) sowie die Benutzerverwaltung bleiben Administratoren vorbehalten. |

- Die **wirksame Rolle** ist die höchste aus der eigenen Rolle und allen Gruppen des Benutzers. Geprüft wird bei jeder
  Anfrage auf dem Server; oben in der Oberfläche steht für „Nur lesen“ ein Hinweis.
- Ein **API-Key** hat die Rolle seines Benutzers (der Key eines Nur-lesen-Benutzers ist nur lesend). Gesperrte Benutzer
  können sich nicht anmelden; ihre Sitzungen und API-Keys gelten nicht mehr.
- Administratoren legen Benutzer an (mit Passwort oder Einmal-Passwort „beim ersten Anmelden setzen“), ändern Rolle,
  Gruppen und E-Mail, sperren, setzen Passwort und 2FA zurück und beenden Sitzungen. „2FA zurücksetzen“ entfernt App-2FA
  und die Passkeys des Benutzers auf dieser Node. Sperren oder eine geänderte Rolle
  beenden die Sitzungen sofort.
- **Gruppen** haben einen Namen und eine Rolle und ordnen optional AD/LDAP-Gruppen (DN oder Name) und SSO-Gruppen zu.
- **„2FA für alle Pflicht“** (Reiter Anmeldung): lokale und AD/LDAP-Benutzer ohne App-2FA und ohne Passkey kommen nach
  der Anmeldung nur noch zur 2FA-Einrichtung. SSO-Benutzer sind ausgenommen (2FA beim Anbieter), ebenso Anmeldungen über
  Forward-Auth (siehe dort).

## AD/LDAP

Node64 meldet Benutzer gegen ein vorhandenes Active Directory oder LDAP (OpenLDAP, LDAP64, lldap …) an.

1. Reiter **Anmeldung → AD/LDAP**: Server (`ldaps://dc.firma.lan:636` oder `ldap://…` mit StartTLS; mehrere möglich),
   Profil Active Directory oder LDAP, Dienstkonto (Bind-DN und Passwort, verschlüsselt gespeichert), Base-DN,
   optional eigener Benutzerfilter. „Verbindung testen“ zeigt für einen Testnamen den DN, die Gruppen und welche
   Node64-Gruppe passt.
2. Unter **Gruppen** eine Gruppe mit Rolle anlegen und die AD-Gruppe zuordnen (z. B.
   `CN=Node64-Admins,OU=Gruppen,DC=firma,DC=lan`).
3. Wer in einer zugeordneten Gruppe ist, meldet sich mit seinem AD-Namen und Passwort an; beim ersten Mal wird der
   Benutzer angelegt (Herkunft „LDAP“, kein Passwort in Node64). Ohne passende Gruppe, im AD deaktiviert oder in Node64
   gesperrt: keine Anmeldung. Ein lokaler Benutzer gleichen Namens wird nie übernommen.

Klartext-LDAP ohne TLS geht nur mit dem Schalter „Klartext erlauben“; ein leeres Passwort wird immer abgelehnt.

## SSO über OpenID Connect

Das geht mit jedem OIDC-Anbieter, etwa Authelia, Authentik, Keycloak, Pocket ID, Zitadel oder Kanidm.

1. Beim Anbieter einen **vertraulichen Client** anlegen: Authorization Code mit PKCE, Scopes `openid profile email`.
   Als Redirect URI die Adresse eintragen, die Node64 auf der Seite anzeigt (`https://<node>/login/oidc/callback`).
2. In Node64 Issuer-URL, Client-ID und Client-Secret eintragen. Das Secret wird verschlüsselt gespeichert.
3. Im eigenen Benutzer unter **Verknüpfte Konten** auf „Mit … verknüpfen“ klicken und beim Anbieter anmelden.
4. Ab dann steht auf der Login-Seite „Mit … anmelden“. Den zweiten Faktor prüft der Anbieter.

Standardmäßig kommt **nur hinein, wer sein Konto verknüpft hat**. Optional (Reiter Anmeldung → „SSO: Benutzer über
Gruppen anlegen“, Standard aus) legt Node64 Benutzer beim ersten Anmelden an, wenn der Gruppen-Claim (Standard
`groups`; beim Anbieter den Scope/Claim freigeben) eine zugeordnete Node64-Gruppe enthält.

### Beispiel Authelia (`configuration.yml`)

```yaml
identity_providers:
  oidc:
    clients:
      - client_id: node64
        client_name: Node64
        client_secret: '$pbkdf2-sha512$...'   # Hash des Secrets, das du in Node64 einträgst
        public: false
        authorization_policy: two_factor
        require_pkce: true
        pkce_challenge_method: S256
        redirect_uris: ['https://node64.example.com/login/oidc/callback']
        scopes: [openid, profile, email]
        token_endpoint_auth_method: client_secret_basic
```

Die Issuer-URL in Node64 ist dann die Adresse von Authelia, z. B. `https://auth.example.com`.

### Beispiel Authentik

1. Einen OAuth2/OpenID-Provider vom Typ „Confidential“ anlegen und die Redirect URI eintragen.
2. Eine Anwendung mit dem Slug `node64` anlegen.
3. Issuer-URL in Node64: `https://authentik.example.com/application/o/node64/`

## Forward-Auth (Remote-User vom Reverse-Proxy)

Steht Node64 hinter Traefik, Caddy oder Nginx mit Authelia oder Authentik als Forward-Auth, meldet der Proxy den
Benutzer im Kopf `Remote-User`.

- Standardmäßig aus. Eingeschaltet gilt der Kopf nur für Verbindungen aus den **eingetragenen Proxy-Adressen**.
  Geprüft wird die Adresse der Verbindung selbst, nie `X-Forwarded-For`. „Alle Adressen“ (`0.0.0.0/0`) ist gesperrt.
- Der Name im Kopf muss **genau einem lokalen Benutzer** entsprechen.
- Geprüft wird bei jeder Anfrage. Wer sich beim Proxy abmeldet, ist auch in Node64 abgemeldet.
- Der Proxy muss den Kopf selbst setzen und einen vom Browser mitgeschickten überschreiben. Das ist bei
  Authelia/Authentik-Forward-Auth der Fall.
- Ist die Node auch direkt (ohne Proxy) erreichbar, schadet das nicht: Direkte Anfragen kommen nicht von der
  Proxy-Adresse.
- Anmeldung und 2FA erledigt der vorgeschaltete Dienst; Node64 sieht dabei weder Passwort noch zweiten Faktor. Die
  2FA-Pflicht und „Passwort beim ersten Anmelden setzen“ gelten für Forward-Auth deshalb nicht (2FA in Authelia bzw.
  Authentik einschalten). Bei der Anmeldung mit Passwort direkt an der Node greifen beide weiter.

## Passkeys

Passkeys sind eine Anmeldung ohne Passwort per Fingerabdruck, Face ID, Geräte-PIN oder Sicherheitsschlüssel. Auf der
Login-Seite steht dann „Mit Passkey anmelden“, ohne Benutzernamen.

- Passkeys brauchen **HTTPS mit einem Hostnamen**, z. B. `https://node64.example.com`. Unter einer IP-Adresse wie
  `https://192.168.10.30` lassen die Browser sie nicht zu.
- Ein Passkey gilt nur für den Hostnamen, unter dem er angelegt wurde.
- Anlegen unter **Einstellungen → Allgemein → Passkeys**. Mehrere Passkeys je Benutzer sind möglich, z. B. Handy und
  YubiKey.
- Passwort und App-2FA bleiben daneben bestehen. Der Passkey ersetzt sie nicht.

## Im Cluster (Bereich „Benutzer & Anmeldung“)

Standardmäßig aus; einschalten auf der Seite **Cluster** (auf einer Node, der Schalter gilt für den ganzen Cluster). Dann gelten die Benutzer (Passwort, App-2FA,
Wiederherstellungscodes, Sprache, Zeitzone, verknüpfte SSO-Konten) und die SSO-Einrichtung (Issuer, Client-ID,
Client-Secret, Beschriftung, Scopes) auf allen Nodes. **Je Node bleiben** Passkeys (an den Hostnamen gebunden),
Sitzungen, API-Keys, die feste Rückleit-Adresse für SSO und Forward-Auth.

- Gleichnamige Benutzer mit anderem Inhalt (z. B. zwei Erstinstallationen mit `admin` und verschiedenem Passwort)
  werden nie überschrieben: Die Seite **Cluster** zeigt „Benutzer im Cluster: bitte wählen“, die gewählte Version gilt
  danach überall. Die eigene Sitzung bleibt dabei bestehen.
- Mit dem Benutzer gehen Rolle, Sperre, Herkunft, E-Mail und Gruppen mit; eigene Bereiche gibt es für die
  **Benutzergruppen** und für **AD/LDAP** (samt Schalter „2FA für alle Pflicht“; das Bind-Passwort wird auf jeder Node
  mit ihrem eigenen Schlüssel gespeichert).
- Löschen (Benutzerverwaltung) gilt auf allen Nodes – den letzten Benutzer und den letzten aktiven lokalen
  Administrator einer Node entfernt, sperrt oder stuft der Cluster aber nie herab.
- Ändern sich Passwort, 2FA, Rolle, Sperre oder Gruppen über den Cluster, enden die Sitzungen dieses Benutzers auf den
  anderen Nodes.

Technische Einzelheiten: [CLUSTER.md](CLUSTER.md#benutzer--anmeldung-users).

## Passwort vergessen (Notfallzugang)

Es gibt keinen Weg über die Oberfläche oder per E-Mail. Wer Zugriff auf den Docker-Host hat, setzt das Passwort per
Befehl im laufenden Container neu (der Node muss nicht angehalten werden):

```bash
docker exec node64 /node64 reset-password
```

- Ohne Angaben erzeugt der Befehl ein zufälliges Passwort (20 Zeichen) und gibt es einmal aus. Eigenes Passwort:
  `-password 'NEUES-PASSWORT'` (mindestens 10 Zeichen; landet dann aber in der Shell-History).
- Mehrere Benutzer: `-user NAME`.
- Authenticator-App und Wiederherstellungscodes verloren: `-disable-2fa` schaltet die Zwei-Faktor-Anmeldung ab.
- Der Benutzer ist danach wieder aktiver lokaler Administrator (Rolle Administrator, entsperrt).
- Alle Sitzungen des Benutzers werden beendet; der Vorgang steht im Audit-Log (`settings.password`,
  „reset-password (Kommandozeile)“).
- Mit docker compose: `docker compose exec node /node64 reset-password` (Dienstname wie in der compose-Datei).
- Im Cluster gilt das neue Passwort nur auf dieser Node; damit es überall gilt, danach in der Oberfläche einmal das
  Passwort ändern.
