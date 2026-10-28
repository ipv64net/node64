# Plan: PROXY64 Forward-Auth, API-Keys und Benutzer ans Ziel

Stand 2026-10-28. Entscheidungen von Dennis:
- Forward-Auth kommt in die **Zugriffslisten** (gelten je Host und je Custom Location).
- **API-Keys** für Apps und Skripte, **Benutzername ans Ziel weiterreichen**, **authentik** als Vorlage.
- Umsteiger von Traefik sollen kaum Arbeit haben.
- Einfach, schlüssig, dokumentiert; in der Oberfläche wenig Text. Hauptsache, die Funktion ist da.
- Node64 selbst als Anmeldedienst („mit Node64-Konto anmelden“) erst später.

Beginn, wenn die Docker-Labels (PLAN-PROXY64-DOCKER.md, D1–D3) committet sind: beide Arbeiten ändern dieselben
Dateien (Zugriff, Formulare, Texte, Changelog).

## 1. Verhalten je Anfrage

Reihenfolge auf einem Host mit Zugriffsliste:

1. **Header-Schutz:** Header, die PROXY64 selbst ans Ziel setzt (`Remote-User`, `Remote-Email`, `Remote-Groups`,
   `Remote-Name` und die Antwort-Header des Anmeldedienstes, z. B. `X-authentik-*`), werden aus der Anfrage des
   Besuchers immer entfernt. Sonst könnte sich jeder als Admin ausgeben.
2. **Rückweg des Anmeldedienstes:** Pfad wie `/outpost.goauthentik.io/` (authentik) bzw. `/oauth2/` (oauth2-proxy) geht
   ohne Prüfung direkt an den Anmeldedienst.
3. **IP-Regeln** wie bisher (deny → 403; allow + „eine Bedingung reicht“ → durch).
4. **API-Key** gültig → durch, Benutzer = Name des Keys.
5. **Lokale Benutzer** wie bisher (Basic Auth bzw. Login-Seite). Mit Forward-Auth nur noch Basic Auth als Rückfall für
   Programme, die Login-Seite entfällt.
6. **Forward-Auth:** Unteranfrage an die Adresse des Dienstes, wie Traefik `forwardAuth`:
   - mitgeschickt: Methode GET, alle Header des Besuchers (Cookie, Authorization …), dazu `X-Forwarded-Method`,
     `-Proto`, `-Host`, `-Uri`, `-For` (echte Client-IP);
   - 2xx → Anfrage geht ans Ziel, die eingestellten Antwort-Header werden übernommen;
   - sonst geht die Antwort des Dienstes unverändert an den Besucher (Status, `Location`, `Set-Cookie`, Body bis
     64 KB) – damit landet er auf der Anmeldeseite;
   - Dienst nicht erreichbar (Zeitlimit 5 s) → 502-Seite „Anmeldedienst nicht erreichbar“, Warnung im Log höchstens
     einmal je Minute.
   - kein Zwischenspeichern (wie Traefik); die Dienste sind dafür gebaut.

Der Header mit dem API-Key und die Basic-Auth-Daten gehen nicht ans Ziel (außer „Zugangsdaten weiterreichen“, wie
bisher `PassAuth`).

## 2. Vorlagen

| Vorlage | Adresse (Beispiel) | Antwort-Header | Rückweg |
|---|---|---|---|
| authentik | `http://authentik-server:9000/outpost.goauthentik.io/auth/traefik` | `X-authentik-username`, `-groups`, `-email`, `-name`, `-uid` | `/outpost.goauthentik.io/` |
| Authelia | `http://authelia:9091/api/authz/forward-auth` | `Remote-User`, `Remote-Groups`, `Remote-Email`, `Remote-Name` | – |
| oauth2-proxy | `http://oauth2-proxy:4180/oauth2/auth` | `X-Auth-Request-User`, `-Email`, `-Groups` | `/oauth2/`; bei 401 Weiterleitung auf `/oauth2/start?rd=<url>` |
| Eigener Dienst | frei | frei | frei |

Endpunkte und Header beim Umsetzen gegen die aktuelle Doku der Dienste prüfen und mit echten Containern auf der Box
testen (authentik und Authelia).

## 3. Benutzer ans Ziel melden

Schalter in der Zugriffsliste. PROXY64 setzt dann einheitlich `Remote-User`, `Remote-Email`, `Remote-Groups`,
`Remote-Name` – aus dem Anmeldedienst (Vorlagen bilden ihre Header darauf ab), aus der lokalen Anmeldung oder aus dem
Namen des API-Keys. Für Dienste mit „Trusted Header SSO“ (Grafana, Paperless-ngx, Audiobookshelf, Nextcloud mit
Erweiterung …).

## 4. API-Keys

- Je Zugriffsliste beliebig viele, mit Namen. PROXY64 erzeugt sie (`p64k_` + Zufall), zeigt sie **einmal** an, speichert
  nur den SHA-256-Hash; Liste zeigt Name, Anfang des Keys, angelegt, zuletzt benutzt; Löschen = sofort ungültig.
- Angenommen als `Authorization: Bearer <key>`, im Header `X-API-Key` oder als Basic-Auth-Passwort (beliebiger
  Benutzername, für Apps, die nur Basic Auth können).
- Fehlversuche zählen wie falsche Passwörter (Sperre, Honeypot-Meldung).
- Gilt mit und ohne Forward-Auth.

## 5. Umstieg von Traefik

- Docker-Labels: `traefik.http.routers.<r>.middlewares=<m>@docker` mit `traefik.http.middlewares.<m>.forwardauth.address`
  und `.authResponseHeaders` → Zugriffsliste „Traefik: <m>“ anlegen bzw. wiederverwenden und dem Host zuweisen;
  erkennt PROXY64 die authentik- oder Authelia-Adresse, wird die Vorlage gesetzt.
- Middlewares aus einer Datei (`authentik@file`): nicht lesbar → Hinweis am Host „Zugriffsliste wählen“.
- Doku-Abschnitt „Umstieg von Traefik“ mit Gegenüberstellung Label → Einstellung.

## 6. Oberfläche (knapp)

Formular der Zugriffsliste:
- **Anmeldung:** Benutzer (wie bisher) · authentik · Authelia · oauth2-proxy · Eigener Dienst.
- Bei einem Dienst: Feld **Adresse**, darunter eingeklappt „Erweitert“ (Antwort-Header, Rückweg).
- Schalter **Benutzer an das Ziel melden**.
- Bereich **API-Keys:** Name + „Anlegen“, Liste mit Löschen. Der neue Key erscheint einmal mit Kopierknopf.
- Je Feld höchstens ein kurzer Hinweis, Rest in der Doku (Fragezeichen-Link).

Liste der Zugriffslisten: Abzeichen „authentik“ / „Authelia“ / „Forward-Auth“ und „n API-Keys“.

## 7. Phasen

- **F1** Forward-Auth mit Vorlagen, Rückweg, Header-Schutz, Fehlerseite; Tests mit Test-Anmeldedienst.
- **F2** API-Keys (Speicher, Prüfung, Oberfläche, Fehlversuche).
- **F3** Benutzer ans Ziel melden.
- **F4** Traefik-Labels → Zugriffsliste (zusammen mit der Docker-Sitzung).
- **F5** Doku node64.de (Zugriffslisten, Umstieg von Traefik), öffentlicher Changelog, Modul-Changelogs.
- Echttest auf der Box mit authentik und Authelia vor dem Ausrollen.

Später: Node64 als Anmeldedienst (Benutzer, Passkeys, OIDC der Node).
