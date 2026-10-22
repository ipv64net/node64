# Plan: PROXY64 und DNS64 im Cluster (zurückgestellt)

Stand 2026-10-20. **Zurückgestellt** (Entscheidung Dennis): wird umgesetzt, wenn die Nachfrage hoch genug ist. Der
Cluster ist dafür vorbereitet: Neue Module hängen sich als Provider an `/peer/v2/sync` (`internal/peer/cluster.go`),
ein neues Protokoll ist nicht nötig. Grundlagen: [CLUSTER.md](CLUSTER.md), [PLAN-NODE64-CLUSTER.md](PLAN-NODE64-CLUSTER.md).

## Grundregel: jede Angabe ist eins von dreien

| Art | Bedeutung | Beispiele |
|---|---|---|
| gemeinsam | wird abgeglichen, je Bereich schaltbar | Proxy-Hosts, Zugriffslisten, DNS-Einträge |
| je Node abweichend | gemeinsamer Wert, eine Node darf ihn lokal überschreiben; die Abweichung wird nie abgeglichen | Ziel eines Hosts, Host auf dieser Node aus |
| nur lokal | gehört zur Node, wird nie abgeglichen | Ports, Anmeldung, Tunnel, DynDNS |

**Statistiken** werden nicht kopiert: Die Cluster-Ansicht fragt sie live bei jeder Node ab (neuer, nur lesender
Endpunkt `/peer/v2/stats` mit der bestehenden Signatur) und zeigt sie mit Node-Namen und als Summe. Offline-Nodes
erscheinen als „nicht erreichbar“.

## PROXY64

| Bereich | Art | Anmerkung |
|---|---|---|
| Hosts samt Locations, Erweitert, Ländersperre | gemeinsam | Zertifikat über den Namen zugeordnet (lokale IDs unterscheiden sich) |
| Ziel des Hosts (Schema, Host, Port, auch je Location) | je Node abweichend | ohne Eintrag gilt das gemeinsame Ziel |
| Host auf dieser Node aus | je Node abweichend | Dienst nur an einem Standort |
| Streams | gemeinsam, Ziel je Node abweichend | Port gleich; belegt → Fehler nur auf dieser Node |
| Zugriffslisten (Benutzer mit Hash, IP-Regeln) | gemeinsam | Verweis über Cluster-Kennung |
| Einstellungen: Blocklisten, Ausnahmen, Limits, Standardseite, Log-Aufbewahrung | gemeinsam | eigener Bereich |
| CDN64 (Name bei ipv64 eingeschaltet) | eigener Bereich, aus | jede Node meldet ihren Tunnel für denselben Namen; Modus je Name, Priorität je Node; der Server kann mehrere Tunnel je Host mit Priorität schon (`cdn64o_host_tunnels.priority`) |
| Statistik, Zugriffs-Log | live abgefragt | |
| Tunnel-Token, Ports des Eingangs, Erreichbarkeit | nur lokal | |

## DNS64

**Umgesetzt** in DNS64 1.26.0 (Plan [PLAN-NODE64-DNS64-LOKAL.md](PLAN-NODE64-DNS64-LOKAL.md), Phase L4); abweichend
von dieser Tabelle sind alle Bereiche ohne Einstellung **aus** (Entscheidung Dennis 2026-10-22).

| Bereich | Standard | Anmerkung |
|---|---|---|
| Einstellungen (Upstreams, Blockier-Art, Cache, Firefox-Schalter) | an | nicht: Ports, Schnittstellen, DoT/DoH-Zertifikat |
| Blocklisten-Auswahl und eigene Listen | an | jede Node lädt selbst |
| Freigaben und eigene Sperren | an | |
| Eigene Einträge (A/AAAA/CNAME) | an | je Eintrag „nur diese Node“ (z. B. `nas.home.lan` je Standort) |
| Gruppen (Regeln, Kategorien, SafeSearch, Zeitpläne, Internet aus/frei) | an | „Internet aus“ wirkt sofort überall |
| Gruppen-Mitglieder (MAC/IP) | aus | gehören zum Standort; im selben LAN einschalten |
| Abfrage-Log, Statistik | live abgefragt | |

## Bewusst nicht abgeglichen

- DynDNS: zwei Nodes würden dieselbe Domain abwechselnd überschreiben.
- Anmeldung, 2FA, Passkeys, SSO, API-Keys: Sicherheit; Passkeys hängen an der Adresse der Node.
- Benachrichtigungskanäle (Tokens, Passwörter): ggf. später als eigener Bereich (aus), beim Abgleich neu verschlüsselt.
- Ports, Logging, Backup, Updates.

## Technik

- Jeder abgeglichene Eintrag bekommt eine Cluster-Kennung (UUID); Verweise (Zertifikat, Zugriffsliste) laufen darüber.
- Abweichungen je Node in einer eigenen lokalen Tabelle, die der Abgleich nie sieht.
- Erstes Einschalten: vorhandene Einträge über den natürlichen Schlüssel zusammenführen (Hostname, Stream-Port,
  Listenname, Name+Typ), sonst Duplikate; Gleichstand: jüngere Änderung gewinnt.

## Reihenfolge (wenn es losgeht)

1. PROXY64: Hosts, Zugriffslisten, Einstellungen, Abweichungen je Node (Ziel, aus).
2. PROXY64: Streams.
3. CDN64 über mehrere Nodes (Priorität, Anzeige „über Node X“).
4. DNS64-Bereiche.
5. Statistik über alle Nodes.

## Offene Fragen (bei Wiederaufnahme klären)

1. CDN64 mit mehreren Nodes: Ausfallsicherheit über Priorität (Server kann es) oder Lastverteilung (Serverarbeit)?
2. DNS64-Gruppenmitglieder: Standard aus oder an?
3. Abweichungen je Node: reichen Ziel und „aus“, oder auch Zertifikat je Node?
4. Benachrichtigungskanäle: optionaler Bereich oder dauerhaft lokal?
