# CDN64 online – dein Dienst im Internet, ohne offene Ports

CDN64 online macht einen Dienst, der in deinem Heimnetz hinter Node64 läuft, über die Server **srv07.cdn64.de**
(Nürnberg) und **srv08.cdn64.de** (Falkenstein) aus dem Internet erreichbar – per IPv4 und IPv6, auch wenn dein
Anschluss nur IPv6 hat (DS-Lite) oder du keine Ports freigeben kannst oder willst.

## So funktioniert es

Node64 baut einen verschlüsselten Tunnel zu beiden Servern auf (QUIC, sonst TCP; Port 7844, sonst 443). Besucher
rufen deinen Namen auf, das DNS zeigt auf die Server, die Server reichen die Verbindung durch den Tunnel zu deiner
Node. Fällt ein Server aus, nimmt ipv64 ihn nach rund einer Minute aus dem DNS; der andere übernimmt.

## Voraussetzungen

- Node64 ab Version 0.11.98 mit dem Modul CDN64 und einem Proxy-Host für den Namen.
- Ein verbundener ipv64-Account (*Einstellungen › ipv64*) mit einer Account-Klasse, die CDN-Domains enthält.
- Der Name liegt in einer Domain deines ipv64-Accounts, ohne CNAME und ohne DNS-Failover.

## Einschalten

1. In Node64 unter *CDN64 › Proxy-Hosts* beim Host auf **Einschalten** (Spalte *CDN64 online*).
2. Modus wählen:
   - **Modus 1 – durchreichen (Standard):** TLS endet in deiner Node, dein Zertifikat bleibt bei dir, die Server
     sehen keine Inhalte. Für fast alle Fälle die richtige Wahl.
   - **Modus 2 – auf den Servern beenden:** Die Server holen ein eigenes Zertifikat (Name und `*.Name`) und
     beenden TLS; dafür filtern sie schon dort (Blocklisten, Limits) und sprechen HTTP/3. Nicht für Hosts mit
     „TLS durchreichen“.
3. Die Node prüft den Account, baut den Tunnel auf, schaltet den Namen bei ipv64 ein und testet den Weg über das
   Internet. Fertig, wenn alle Schritte grün sind.

Ausschalten stellt den DNS-Eintrag wieder auf die bisherige Adresse zurück.

## Gut zu wissen

- **Echte Besucher-IP:** Deine Node sieht die echte Adresse der Besucher (Zugriffslisten, Limits, Log).
- **Im Heimnetz** beantwortet DNS64 deiner Node den Namen mit ihrer lokalen Adresse – Aufrufe von zu Hause gehen
  nicht über das Internet.
- **Kontingent:** Jeder Name zählt als CDN-Domain, Traffic zählt gegen den CDN-Traffic deiner Klasse (gemeinsam mit
  dem bisherigen CDN). Ist der Traffic des Monats aufgebraucht, sind deine Namen bis zum Monatswechsel gesperrt.
  Supporter-Accounts haben zusätzlich eine Bandbreitengrenze.
- **Meldungen:** Steht der Tunnel länger als 3 Minuten zu keinem Server oder sperrt ipv64 einen Namen, meldet
  Node64 das über deine Benachrichtigungskanäle.
- **Langsam?** Zeigt die Node „UDP gesperrt“, läuft der Tunnel über TCP. Ein Hinweis auf einen kleinen UDP-Puffer
  nennt den Befehl für den Docker-Host.

## Häufige Meldungen

| Meldung | Abhilfe |
|---|---|
| Kein ipv64-Account verbunden | *Einstellungen › ipv64* API-Key eintragen |
| Name nicht im Account | Domain zuerst bei ipv64 anlegen |
| CNAME vorhanden / DNS-Failover aktiv | CNAME entfernen bzw. Failover ausschalten |
| Kontingent voll | Namen ausschalten oder höhere Account-Klasse |
| Node erreicht srv07/srv08 nicht | Ausgehend UDP/TCP 7844 oder 443 erlauben |
| Antwort über eine andere Node | Der Name ist auf einer anderen Node eingeschaltet – dort ausschalten |
