# Plan (Merkzettel): CDN64 online über die ipv64-CDN-Server

> Seit 2026-10-19 heißt diese Funktion nur noch **CDN64** (ohne „online“); der lokale Reverse-Proxy heißt **PROXY64**.
> Der Merkzettel unten ist der Stand von damals.

Stand 2026-10-15. **Noch kein Phasenplan.** Das hier ist nur festgehalten, damit nichts verloren geht. Dafür kommt
später ein eigener Phasenplan, weil auch bei ipv64 (CDN-Server, API v2, Portal) einiges neu gebaut werden muss.
Grundlage ist der lokale Reverse-Proxy aus [PLAN-NODE64-CDN64.md](PLAN-NODE64-CDN64.md), der zuerst fertig wird.

Wichtig laut Dennis: Den Kunden geht es weniger darum, ihre IP zu verschleiern. Es geht vor allem um das
**CGNAT-Problem**. Ihre selbst gehosteten Dienste sind über IPv6 gut erreichbar, über IPv4 aber nicht. Die
ipv64-CDN-Server lösen das, und das kommt sehr gut an.

ipv64 betreibt schon CDN-Server: nginx mit IPv4 und IPv6, gesteuert über `bots/cdn_bot.php` und API v2 `/cdn`
(Proxy, Portmapper, Zugriffsliste, Caching, Let's Encrypt). Zielgruppe sind Anschlüsse **ohne eigene öffentliche
IPv4**, z. B. DS-Lite oder CGNAT. Besucher kommen über IPv4 oder IPv6 zum CDN-Server, und der CDN-Server erreicht
die Node über IPv6.

CDN64 soll diese Server später aus der Oberfläche heraus verknüpfen, **je Host wählbar**:

| Veröffentlichung | Weg | TLS | Was das CDN sieht |
|---|---|---|---|
| **Direkt** (Standard) | Besucher → Router → Node64 | auf der Node | – |
| **ipv64-CDN mit TLS-Terminierung** (wie Cloudflare) | Besucher → CDN-Server (TLS endet dort) → neu verschlüsselt → Node64 | zweimal: am CDN mit eigenem Zertifikat, zur Node mit dem Zertifikat der Node | Inhalte; dafür Caching, Zugriffsliste, Schutz vor Angriffen am CDN |
| **ipv64-CDN ohne TLS-Terminierung** (Durchreichen) | Besucher → CDN-Server (liest nur den Namen, SNI) → rohe TCP-Verbindung → Node64 | Ende-zu-Ende nur auf der Node | nur Name, IPs, Datenmenge; kein Caching am CDN |

**Was die Node dafür mitbringt:**

- **Verknüpfen über API v2** mit dem zentralen API-Key, wie bei allen Diensten (Entscheidung „API zuerst“).
  - CDN64 legt die CDN-Domain bzw. den Eintrag an, wählt den Modus und setzt die DNS-Einträge.
  - Es zeigt den Zustand an (zugewiesener Server, Zertifikat am CDN, Datenmenge, Limit der Klasse).
- **Ein Herkunfts-Port für alle Hosts:** Das CDN verbindet sich immer mit Edge auf 443, und Edge verteilt nach dem
  Namen. Mit TLS-Terminierung muss das CDN dafür den Namen weitergeben (nginx `proxy_ssl_server_name on`). Die Node
  braucht so keine zweite Freigabe im Router.
- **Echte Client-IP:**
  - Mit TLS-Terminierung über `X-Forwarded-For`.
  - Beim Durchreichen über das PROXY-Protokoll.
  - Beides gilt nur, wenn die Verbindung von einem ipv64-CDN-Server kommt; die Liste kommt per API.
- **Herkunftsschutz:**
  - Option „nur über das CDN“.
  - Später gegenseitige Zertifikatsprüfung (mTLS) zwischen CDN und Node. Im cdn_bot ist `ssl_verify_client`
    dafür schon angedacht.
- **Zertifikate:**
  - Mit TLS-Terminierung: am CDN das Zertifikat von ipv64 (wie heute) und auf der Node ein eigenes. Das CDN prüft
    das Zertifikat der Node; sie bekommt es per ipv64 DNS-01, ohne dass Port 80 offen sein muss.
  - Beim Durchreichen gibt es nur das Zertifikat auf der Node.
- **HTTP/3:**
  - Mit TLS-Terminierung spricht das CDN mit dem Besucher, was nginx dort kann.
  - Beim Durchreichen läuft zunächst HTTP/1.1 und HTTP/2 über TCP. QUIC durchzureichen braucht am CDN ein Programm,
    das den Namen aus dem QUIC-Paket liest; nginx kann das nicht. Edge kündigt HTTP/3 (`Alt-Svc`) daher nur an, wo
    es auch ankommt.
- **Erreichbarkeit:** In der Liste steht zusätzlich „CDN → Node erreichbar“, geprüft vom CDN-Server, per API
  abgefragt.

**Was auf der ipv64-Seite dazukommt (nicht in diesem Repo, eigene Abstimmung):**

- **Für das Durchreichen:**
  - Auf den CDN-Servern kommt vor 443 ein nginx-`stream` mit `ssl_preread`. Namen im Durchreich-Modus gehen roh
    (mit `proxy_protocol`) zur Node, alle anderen an den bestehenden HTTP-Teil auf dem Server selbst.
  - Port 80 leitet für diese Namen nur auf HTTPS um.
- API v2 `/cdn`:
  - Modus je Eintrag (terminieren/durchreichen);
  - Herkunfts-Port und -Schema, mehrere Namen je Domain;
  - Liste der CDN-Server-IPs;
  - Prüfung „CDN → Node“.
- Später, falls gewünscht: mTLS zur Node.

**Tunnel über QUIC (von Dennis gewünscht, optional):** Wer auch per IPv6 nicht von außen erreichbar ist (doppeltes
CGNAT, Mobilfunk, strenge Firewall), dem hilft nur eine ausgehende Verbindung von der Node zum CDN-Server (wie
Cloudflare Tunnel). Dennis' Idee: Der lokale Reverse-Proxy baut selbst eine **QUIC-Verbindung zu einem ipv64-CDN-Server** auf. Welcher Server
das ist, steuert ipv64. Über diese Verbindung kommen dann die Anfragen der Besucher; beide Modi (mit und ohne
TLS-Terminierung) können darüber laufen. Von außen muss die Node dafür gar nicht erreichbar sein.

**Datenmodell (wenn es so weit ist):**

- Jeder Host hat `publish` = `direct` | `ipv64_cdn_tls` | `ipv64_cdn_passthrough` (später ggf. `…_tunnel`) und
  `origin_only_cdn`.
- Kommt mit diesem Plan per Migration dazu; der lokale Plan baut es nicht vorab ein.

## Offen für den eigenen Plan

- Beim Durchreichen HTTP/3: Reicht HTTP/2 über TCP, oder soll ein eigenes Programm auf den CDN-Servern auch QUIC
  nach dem Namen durchreichen (nginx kann das nicht)?
- Tunnel über QUIC: Steuerung (welcher CDN-Server, Ausfall, Wechsel), Authentisierung der Node (API-Key oder
  eigenes Token), Limits je Klasse.
