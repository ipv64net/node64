# Plan: PROXY64 – Proxy-Hosts über Docker-Labels

Stand 2026-10-28, erste Fassung mit Dennis' Entscheidungen. Noch nichts umgesetzt.

**Idee:** Wie bei Traefik liest PROXY64 über den Docker-Socket die Container mit Labels und legt daraus von selbst
Proxy-Hosts an – ohne Formular. Der Proxy-Host ist danach ein ganz normaler Host: Blocklisten, Zugriffslisten,
WAF/JA4, Länder- und Ratensperren, Honeypot64, Zertifikate, CDN64 online (Modus 1–3) und die CDN64-Statistik
greifen unverändert.

**Entscheidungen (Dennis, 2026-10-28):**
- Priorität 1 sind eigene Labels `node64.proxy.*` (Host, Port, Schema), sauber dokumentiert.
- Traefik-Labels werden mitgelesen (Umsteiger) – Phase 2.
- Container entfernt → Proxy-Host in Node64 komplett gelöscht, Name bei CDN64 online abgemeldet.
- Entfernte Docker-Hosts (SSH/TCP) erst einmal nicht – nur der Docker-Host, auf dem Node64 läuft.
- Abzeichen „Docker“ an jedem so angelegten Host ist Pflicht.

## 1. Labels (Phase 1)

| Label | Pflicht | Bedeutung |
|---|---|---|
| `node64.proxy.host` | ja | Namen, durch Komma getrennt (`app.example.de,www.example.de`) |
| `node64.proxy.port` | nein | Port im Container; fehlt er, gilt der einzige freigegebene (`EXPOSE`) Port, sonst Fehler „Port fehlt“ |
| `node64.proxy.scheme` | nein | `http` (Standard) oder `https` |
| `node64.proxy.network` | nein | Docker-Netz, über das PROXY64 den Container erreicht (bei mehreren Netzen) |

- Ein Container = ein Proxy-Host (mehrere Namen möglich). Mehrere Dienste je Container erst mit Phase 2.
- Kennung des Hosts ist der **Container-Name** (bleibt bei `docker compose up` gleich, die ID nicht) – wie bei der
  Docker-Überwachung.
- Ungültige Labels (Name, Port, Schema) → kein Host, Fehler in der Docker-Übersicht (Abschnitt 5).

## 2. Was die Labels festlegen – und was nicht

- **Aus den Labels, in der Oberfläche fest (nur lesen):** Namen, Schema, Ziel (Adresse, Port).
- **In der Oberfläche einstellbar und bleibt erhalten** (Neustart, Neuanlegen des Containers): CDN64 online samt
  Modus, Zugriffsliste, Schutz/WAF, Länder, Locations, Erweitert, Zertifikat, HTTP/2/3, HSTS usw.
- **Neue Docker-Hosts** bekommen die üblichen Standardwerte (Blocklisten wie eingestellt, WAF an). CDN64 online wird
  in der Oberfläche eingeschaltet (ein Klick), nicht per Label – sonst könnte jeder, der Container starten darf,
  Dienste ins Internet stellen. (Ein Label `node64.proxy.cdn64=1` hinter einem eigenen Schalter wäre später möglich,
  ist aber nicht Teil dieses Plans.)

## 3. Ziel-Adresse

PROXY64 verbindet sich direkt mit dem Container, nicht über freigegebene Ports. Reihenfolge:

1. `node64.proxy.network` gesetzt → IP des Containers in diesem Netz.
2. Gemeinsames Docker-Netz mit dem Node64-Container (eigener Container über den Hostnamen per inspect) → IP dort.
3. Node64 mit `network_mode: host` → IP des Containers in seinem (ersten) Bridge-Netz; vom Host aus erreichbar.
4. Sonst: freigegebener Port des Containers auf dem Host (Docker-Gateway wie in Punkt 3 der PROXY64-1.27-Prüfung).
5. Nichts davon → Host wird angelegt, Ziel-Status „nicht erreichbar“ mit Hinweis („Container in ein gemeinsames
   Netz mit Node64 aufnehmen oder `node64.proxy.network` setzen“).

Die IP wird bei jedem Start des Containers neu gelesen (Docker vergibt sie neu).

## 4. Ablauf (Abgleich)

- **Quelle:** Docker-API über den vorhandenen Client der Docker-Überwachung (`internal/proxmox/docker.go`:
  `unix://`, `tcp://` bzw. docker-socket-proxy), Standard `NODE64_DOCKER_HOST` bzw. `/var/run/docker.sock`.
  Nur GET: `/containers/json?all=1`, `/containers/{id}/json`, `/events` (Filter `type=container`).
  docker-socket-proxy braucht `CONTAINERS=1` und `EVENTS=1`.
- **Start und alle 5 Minuten:** volle Liste, Abgleich mit den Docker-Hosts. **Dazwischen:** Ereignisse `start`,
  `die`, `destroy`, `rename` lösen einen Abgleich aus (entprellt, 2 s).
- **Container gestoppt:** Host bleibt, Besucher sehen „Dienst nicht erreichbar“ (502), wie bei jedem Ziel.
- **Container entfernt:** Host wird **nach 2 Minuten Wartezeit** gelöscht, samt Abmelden bei CDN64 online
  (`deleteHost` → `onlineKick`). Die Wartezeit fängt `docker compose up` ab (Container wird gelöscht und sofort mit
  gleichem Namen neu angelegt) – sonst gingen CDN64-Anmeldung und Einstellungen bei jedem Update verloren.
- **Socket nicht erreichbar oder Liste fehlerhaft:** nichts löschen, nur Fehler anzeigen. Gelöscht wird nur, wenn die
  Liste erfolgreich gelesen wurde und der Container fehlt.
- **Node64 war aus, als der Container entfernt wurde:** der Abgleich beim nächsten Start holt das Löschen nach.
- **Konflikte:** Name gehört schon zu einem von Hand angelegten Host → der Hand-Host gewinnt, Docker-Container wird
  nicht übernommen (Hinweis). Zwei Container mit demselben Namen → der zuerst gesehene gewinnt (Hinweis).
- **Label entfernt** (Container neu angelegt ohne `node64.proxy.host`) → wie Container entfernt.
- **Audit:** `cdn64.host.docker.create` / `.update` / `.delete` mit Container-Name.

## 5. Oberfläche

- **Abzeichen „Docker“** in der Host-Liste (Tooltip: Container-Name, Zustand) und im Host-Formular; die Felder aus den
  Labels sind gesperrt mit Hinweis „Kommt aus den Docker-Labels von Container X“. Löschen in der Oberfläche nicht
  möglich (Hinweis: Label entfernen bzw. Container entfernen); ausschalten geht.
- **PROXY64 → Einstellungen → Docker:**
  - Schalter „Docker-Labels auswerten“ – **standardmäßig aus**.
  - Docker-Host (vorbelegt wie die Docker-Überwachung), Zustand (verbunden / Fehler mit Hinweis wie bei der
    Überwachung, z. B. Rechte am Socket).
  - Zertifikate: „Für Docker-Hosts automatisch ein Zertifikat anfordern“ mit Weg (wie im Host-Formular) und dem Haken
    für die Nutzungsbedingungen (einmal hier, nicht per Label). Ohne Haken: passendes vorhandenes Zertifikat
    (z. B. Wildcard), sonst nur HTTP.
  - Liste der Container mit `node64.proxy.*`: übernommen / Konflikt / Fehler (Label, Ziel).
- Texte DE und EN (`internal/i18n/locales`).

## 6. Cluster

Docker-Hosts sind **nur lokal**: Sie gehören zu dem Docker-Host, auf dem die Node läuft, und werden nicht an andere
Nodes verteilt (Kennzeichen am Host, beim Cluster-Abgleich ausgelassen).

## 7. Phase 2 – Traefik-Labels mitlesen

- Schalter „Traefik-Labels mitlesen“ unter Einstellungen → Docker (an, wenn Docker-Labels an).
- Ausgewertet werden nur:
  - `traefik.enable` (`false` → ignorieren),
  - `traefik.http.routers.<r>.rule` – nur `Host(...)`, auch mehrere mit `||` bzw. `Host(\`a\`, \`b\`)`;
    andere Regeln (`PathPrefix`, `Headers` …) → Router übersprungen, Hinweis „Regel nicht unterstützt“,
  - `traefik.http.routers.<r>.service` bzw. der einzige Service,
  - `traefik.http.services.<s>.loadbalancer.server.port` und `.scheme`,
  - `traefik.docker.network` (wie `node64.proxy.network`).
- Ignoriert: Middlewares, Entrypoints, `tls.certresolver` (Zertifikate macht PROXY64), TCP/UDP-Router.
- Je Router ein Host (Kennung Container + Router). Stehen eigene und Traefik-Labels am selben Container, gelten die
  eigenen.

## 8. Phasen und Aufwand

| Phase | Inhalt | Aufwand |
|---|---|---|
| D1 | Labels lesen, Abgleich mit Ereignissen und Wartezeit, Ziel-Adresse, Speicherung (Migration: Quelle `docker`, Container-Name), Löschen samt CDN64-Abmeldung, Tests mit nachgebauter Docker-API | ~1 Tag |
| D2 | Oberfläche: Abzeichen, gesperrte Felder, Einstellungen → Docker, Container-Liste, Zertifikate; Changelogs, README (Compose-Beispiel, socket-proxy), `docs/CDN64.md`; node64.de über die Webseiten-Sitzung | ~0,5 Tag |
| D3 | Traefik-Labels (Abschnitt 7) mit Tests | ~0,5 Tag |

D1 und D2 laufen parallel (Agenten), D3 danach. Portal und Server (srv07/srv08) sind nicht betroffen – kein Upload,
keine Doku in `ipv64_docs`.

## 9. Sicherheit

- Wer den Docker-Socket hat, kann den Host steuern; PROXY64 sendet nur GET. Empfehlung in der Doku:
  docker-socket-proxy mit `CONTAINERS=1`, `EVENTS=1`, alles andere aus.
- Wer auf dem Docker-Host Container starten darf, kann damit nur **lokale** Proxy-Hosts anlegen – nichts ins
  Internet stellen (CDN64 online nur über die Oberfläche) und keine Hand-Hosts überschreiben.
- Hosts über Labels gehen nur an Ziele auf diesem Docker-Host (Container-IP bzw. Gateway), nie an beliebige
  Adressen aus einem Label.
