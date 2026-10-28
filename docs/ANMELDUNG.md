# Anmeldung: lokale Benutzer, SSO, Forward-Auth, Passkeys

Lokale Benutzer mit Passwort (optional mit App-2FA) bleiben immer die Grundlage. Ein Benutzer reicht. Die weiteren
Wege richtest du unter **Einstellungen → Anmeldung** (`/settings/login`) ein. Jede Anmeldung steht im Audit-Log, mit
dem Weg (`sso …`, `passkey`, `forward-auth …`).

## SSO über OpenID Connect

Das geht mit jedem OIDC-Anbieter, etwa Authelia, Authentik, Keycloak, Pocket ID, Zitadel oder Kanidm.

1. Beim Anbieter einen **vertraulichen Client** anlegen: Authorization Code mit PKCE, Scopes `openid profile email`.
   Als Redirect URI die Adresse eintragen, die Node64 auf der Seite anzeigt (`https://<node>/login/oidc/callback`).
2. In Node64 Issuer-URL, Client-ID und Client-Secret eintragen. Das Secret wird verschlüsselt gespeichert.
3. Im eigenen Benutzer unter **Verknüpfte Konten** auf „Mit … verknüpfen“ klicken und beim Anbieter anmelden.
4. Ab dann steht auf der Login-Seite „Mit … anmelden“. Den zweiten Faktor prüft der Anbieter.

Es kommt **nur hinein, wer sein Konto verknüpft hat**. Beim Anbieter vorhandene Benutzer bekommen kein automatisches
Konto.

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

## Passkeys

Passkeys sind eine Anmeldung ohne Passwort per Fingerabdruck, Face ID, Geräte-PIN oder Sicherheitsschlüssel. Auf der
Login-Seite steht dann „Mit Passkey anmelden“, ohne Benutzernamen.

- Passkeys brauchen **HTTPS mit einem Hostnamen**, z. B. `https://node64.example.com`. Unter einer IP-Adresse wie
  `https://192.168.10.30` lassen die Browser sie nicht zu.
- Ein Passkey gilt nur für den Hostnamen, unter dem er angelegt wurde.
- Anlegen unter **Einstellungen → Anmeldung → Passkeys**. Mehrere Passkeys je Benutzer sind möglich, z. B. Handy und
  YubiKey.
- Passwort und App-2FA bleiben daneben bestehen. Der Passkey ersetzt sie nicht.

## Im Cluster (Bereich „Benutzer & Anmeldung“)

Standardmäßig aus; einschalten auf der Seite **Cluster** auf beiden Nodes. Dann gelten die Benutzer (Passwort, App-2FA,
Wiederherstellungscodes, Sprache, Zeitzone, verknüpfte SSO-Konten) und die SSO-Einrichtung (Issuer, Client-ID,
Client-Secret, Beschriftung, Scopes) auf allen Nodes. **Je Node bleiben** Passkeys (an den Hostnamen gebunden),
Sitzungen, API-Keys, die feste Rückleit-Adresse für SSO und Forward-Auth.

- Gleichnamige Benutzer mit anderem Inhalt (z. B. zwei Erstinstallationen mit `admin` und verschiedenem Passwort)
  werden nie überschrieben: Die Seite **Cluster** zeigt „Benutzer im Cluster: bitte wählen“, die gewählte Version gilt
  danach überall. Die eigene Sitzung bleibt dabei bestehen.
- Löschen (Liste „Benutzer dieser Node“ unter Anmeldung, ab zwei Benutzern) gilt auf allen Nodes – den letzten
  Benutzer einer Node löscht der Cluster aber nie.
- Ändert sich Passwort oder 2FA über den Cluster, enden die Sitzungen dieses Benutzers auf den anderen Nodes.

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
- Alle Sitzungen des Benutzers werden beendet; der Vorgang steht im Audit-Log (`settings.password`,
  „reset-password (Kommandozeile)“).
- Mit docker compose: `docker compose exec node /node64 reset-password` (Dienstname wie in der compose-Datei).
- Im Cluster gilt das neue Passwort nur auf dieser Node; damit es überall gilt, danach in der Oberfläche einmal das
  Passwort ändern.
