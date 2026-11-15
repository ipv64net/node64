# IPAM64 – IP-Adressverwaltung

IPAM64 ist das Node64-Modul für Netze und feste Adressen (IPv4 und IPv6). Es arbeitet mit DNS64 zusammen: Was in
IPAM64 steht, vergibt der DHCP-Server von DNS64 und beantwortet der lokale DNS. Grundlage war ein Entwurf aus der
Community (UlrichSchwarz); Plan und Entscheidungen: [PLAN-NODE64-IPAM64.md](PLAN-NODE64-IPAM64.md).

## Einschalten und einrichten

1. *Einstellungen → Module → IPAM64* einschalten (Standard aus; aus heißt: kein Menüpunkt, keine Hintergrundarbeit).
2. *IPAM64 → Einrichten*: Der Assistent schlägt Präfixe aus den DHCP-Netzen von DNS64 und den Netzen der Node vor und
   übernimmt feste Adressen und A/AAAA-Einträge, die in DNS64 von Hand stehen. Sie werden in DNS64 gekennzeichnet, nicht
   doppelt angelegt. Was nicht passt (zweiter Name für dieselbe IP, Name ist kein einfaches DNS-Label), bleibt von Hand.

## Präfixe, Adressbereiche, Adressen

- **Präfix**: IPv4 ab /8, IPv6 ab /16. Präfixe dürfen ineinander liegen; der Baum ergibt sich daraus. Status
  *Container* (nur Gliederung), *Aktiv*, *Reserviert*, *Veraltet*. VLAN, Rolle, Tags, DNS-Zone, „gilt als voll“, Scan.
- **Adressbereich**: *Feste Adressen* (dort sucht „nächste freie Adresse“) oder *Frei halten*. Der DHCP-Adressbereich
  kommt aus DNS64.
- **Adresse**: Status, Rechnername (ein DNS-Label), Rolle (Gateway, DNS-Server, VIP, Anycast), MAC, Beschreibung, Tags.
  Jede Adresse gehört zum kleinsten Präfix, in dem sie liegt.

## DHCP und DNS

An der Adresse:

- **Lokaler DNS-Eintrag**: `<Rechnername>.<Zone>` als A bzw. AAAA, PTR wahlweise. Zone an der Adresse, sonst die des
  Präfixes (bzw. die Domain des DHCP-Netzes); ein Kind-Präfix ohne eigene Zone nimmt die des Eltern-Präfixes bzw.
  DHCP-Netzes.
- **Feste Zuweisung**: Reservierung der MAC im DHCP-Netz, in dem die Adresse liegt (nur IPv4; DHCPv6 gibt es nicht).
- Eine feste Adresse **im DHCP-Adressbereich ohne Reservierung** nimmt DNS64 automatisch aus der Vergabe aus – auch
  in einem Kind-Präfix, das im DHCP-Netz liegt.

Die Karte *Wirkung in DNS64* zeigt, was entsteht bzw. vorhanden ist. DNS64 prüft die ganze Adresse vor dem Schreiben;
lehnt es ab (MAC schon vergeben, CNAME auf dem Namen …), bleibt alles beim alten Stand. Ein gleicher Eintrag von Hand
wird übernommen (gekennzeichnet) und bei einem Fehler wieder freigegeben, nicht gelöscht. In DNS64 tragen diese Einträge das Kennzeichen „IPAM64“ und lassen sich dort
nur über IPAM64 ändern, solange IPAM64 läuft. Ein Abgleich alle 10 Minuten repariert Abweichungen.

**Vor dem Abschalten**: *IPAM64 → An DNS64 übergeben* nimmt die Kennzeichen weg; die Einträge bleiben in DNS64 und sind
dort wieder frei bearbeitbar. Im Cluster geben die anderen Nodes ihre Einträge beim nächsten Abgleich ebenfalls frei.
Für übergebene Adressen schreibt IPAM64 nichts mehr nach DNS64, bis DNS oder DHCP an der Adresse wieder eingeschaltet
wird. Auch ohne Übergabe laufen DHCP und DNS weiter (die Einträge liegen in DNS64).

## IPv6 vom Provider

Ein globales IPv6-Präfix (z. B. das /56 vom Provider) lässt sich als *dynamisch* markieren. Präfixe darin merken sich
ihre Präfix-ID. Wechselt der Provider das Präfix, erkennt IPAM64 das an den Adressen der Node (alle 2 Minuten oder auf
Knopfdruck) und zieht Präfixe, Adressbereiche, Adressen und ihre AAAA-Einträge nach – am Stück; scheitert es, bleibt
der alte Stand. Als neue Adresse zählen nur Adressen auf der Schnittstelle, auf der die Node zuletzt im Präfix lag
(eine globale Adresse von WireGuard, Docker oder einem zweiten Anschluss stört nicht). Ziele in PROXY64, Monitor64 und
Healthchecks, die noch auf das alte Präfix zeigen, nennt die Übersicht – besser sind dort DNS-Namen.

## Scan & Konflikte

- **Nachbartabelle** (ARP und NDP) der Node: alle 2 Minuten, nur in Netzen, an denen die Node hängt. Im Cluster sieht
  jede Node ihre eigenen Netze.
- **Netz-Scan** (optional, je Präfix *aktiv*): ein kleines UDP-Paket je Adresse, danach die Nachbartabelle; nur private
  IPv4-Netze bis /22, im Hintergrund, automatisch alle 15 oder 60 Minuten oder von Hand.
- **Konflikte**: zwei Geräte antworten abwechselnd auf dieselbe IP (Sichtungen überschneiden sich über 5 Minuten; ein
  Gerätetausch zählt nicht); eine fremde MAC an einer festen Adresse (ab 5 Minuten); der DHCP-Server hat eine feste
  Adresse vergeben; dieselbe Adresse wurde auf zwei Nodes gleichzeitig vergeben (24 Stunden). **Hinweise**: fest eingestelltes Gerät im DHCP-
  Adressbereich, feste Adresse mit DNS-Eintrag seit 7 Tagen nicht gesehen, fremder DHCP-Server.
- **Unbekannte Geräte** (nur Nachbartabelle) lassen sich übernehmen oder ignorieren. Der Hersteller kommt aus der
  eingebauten IEEE-Liste; zufällige MACs (z. B. Smartphones) werden erkannt.
- **Benachrichtigungen** über die Standardkanäle: neue Konflikte (Standard an), neue Geräte (Standard aus).

## Import, Export, API

- **CSV-Export** (Übersicht oder je Präfix) und **CSV-Import** mit Vorschau. Spalten Adressen: `ip, name, mac, status,
  role, description, tags, dns, dns_zone, ptr, dhcp`; Präfixe (ohne `ip`): `prefix, name, status, vlan, role,
  description, tags, dns_zone, scan, dynamic`. Komma oder Semikolon; der eigene Export lässt sich wieder einlesen.
  Höchstens 10.000 Zeilen (2 MB) je Datei; 10.000 Adressen mit DNS-Eintrag dauern etwa eine halbe Minute. Eine
  kaputte Zeile erscheint in der Vorschau als Fehler, der Rest wird gelesen.
- **API** `/api/ipam64/…`: Präfixe, Adressbereiche, Adressen (seitenweise), freie Adressen und Vergabe am Stück
  (`POST /api/ipam64/available`, je Node – im Cluster auf einer Node vergeben), Konflikte, Scan. Beschreibung unter
  *API* in der Node.
- **Prometheus** `/api/metrics`: `node64_ipam64_*` (Belegung und Auslastung je Präfix, Konflikte, unbekannte Geräte).
- **MCP** (lesend): Bereich *IPAM64* mit `ipam64_overview`, `ipam64_addresses`, `ipam64_conflicts`, `ipam64_available`.

## Cluster

Präfixe, Adressbereiche und feste Adressen werden abgeglichen (Bereiche unter *Cluster*, Standard an). Sichtungen,
Scan und ignorierte Geräte bleiben je Node. Die Einträge in DNS64 kommen über den Abgleich von DNS64; so haben auch die
Reserve-Node des DHCP und Nodes ohne IPAM64 alle Reservierungen und Einträge.

„Nächste freie Adresse“ vergibt nur je Node am Stück. Vergeben zwei Nodes gleichzeitig dieselbe Adresse, gilt der
Eintrag mit der kleineren Kennung; die andere Node ersetzt ihren und zeigt das 24 Stunden als Konflikt (mit
Benachrichtigung). Automatische Vergabe (API, Skripte) daher über eine Node. Gleicht eine Node DNS64 mit dieser ab,
aber nicht die Adressen von IPAM64, lässt der Abgleich ihre gekennzeichneten Einträge in Ruhe.
