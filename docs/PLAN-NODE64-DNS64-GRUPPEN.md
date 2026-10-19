# Plan: Gerätegruppen und Kinderschutz in DNS64

Stand 2026-10-19. Entschieden: Erkennung per MAC zuerst, IP/Netz als Ausweichweg. **Umgesetzt: G1 (DNS64 1.16.0), G2 (1.17.0), G3 (1.18.0).** Entschieden: Kategorien als eigene kleine Listen,
Kinderschutz-Listen global und je Gruppe, YouTube standardmäßig streng, SafeSearch als ein Schalter,
Firefox-Canary global standardmäßig an, „Internet aus“ mit Hinweisseite der Node, keine Benachrichtigungen bei Sperrversuchen.
Grundlage ist DNS64 1.15.0. Heute gelten
Blocklisten, Freigaben und die Pause für **alle** Geräte gleich. Ziel ist, einzelne Geräte zu Gruppen
zusammenzufassen, etwa „Kinder“, „Gäste“ oder „Smart-TV“. Jede Gruppe bekommt eigene Regeln:

- Listen und Freigaben;
- SafeSearch;
- Schutz gegen Umgehen;
- Zeitpläne;
- eine eigene Pause bzw. Sperre.

Geräte ohne Gruppe verhalten sich wie heute.

## Was heute schon da ist (und genutzt wird)

| Baustein | Stand | Nutzen für Gruppen |
|---|---|---|
| Blocklisten | 28 Vorlagen mit Kategorien, eigene Listen, Matcher als Hash-Tabelle | Kinderschutz-Listen gibt es schon, gelten aber für alle |
| Freigaben | eine Liste für alle | pro Gruppe zusätzlich |
| Pause | global, 10 min oder bis zum Wiedereinschalten | gleiches Bedienkonzept pro Gruppe, auch umgekehrt („sperren“) |
| Abfrage-Log | Client-IP, Gerätename per PTR vom Router, Protokoll | Spalte Gruppe, Filter nach Gruppe, Auswahl von Geräten |
| Client-Netze | Freigabeliste je IP/Netz | gleiche Logik für die Zuordnung zu Gruppen |

## Grundsätze

- **Ohne Gruppe ändert sich nichts.** Keine Gruppe angelegt heißt gleiches Verhalten und gleiche Geschwindigkeit
  wie heute.
- **Ein Gerät, eine Gruppe.** Passt ein Gerät auf mehrere Gruppen, gilt die erste in der eingestellten Reihenfolge.
- **Erkennung per MAC-Adresse, sonst IP/Netz.** IPv6-Geräte wechseln ihre Adresse ständig (Privacy Extensions),
  und auch per DHCP vergebene IPv4-Adressen wechseln. Im Host-Netzwerk sieht DNS64 die Nachbartabelle des Hosts
  (ARP für IPv4, NDP für IPv6, per Netlink). Damit lässt sich jede Anfrage einer MAC-Adresse zuordnen, egal welche
  Adresse das Gerät gerade hat.
  - Ausweichweg: IPv4/IPv6-Adresse oder Netz, z. B. ein eigenes Kinder-VLAN `192.168.30.0/24`.
  - Grenze: Die MAC-Adresse sieht DNS64 nur im selben Netzsegment und nur im Host-Netzwerk. Hinter einem Router,
    in einem anderen VLAN oder im Bridge-Modus geht nur IP/Netz.
  - Grenze: Manche Handys nutzen je WLAN eine zufällige MAC-Adresse. Die bleibt pro WLAN aber fest und funktioniert.
- **Schnell bleiben.** Die Zuordnung von Client zu Gruppe wird gecacht (MAC-Tabelle alle 30 s neu). Pro Anfrage
  kommt eine Map-Abfrage dazu.
- **Ehrlich in der Doku.** Über mobile Daten, ein fremdes DNS oder ein VPN, das der Schutz gegen Umgehen nicht
  kennt, kommt jedes Gerät an DNS64 vorbei. DNS-Sperren sind Hürden, kein Ersatz für Gespräche und Elternfunktionen
  am Gerät.

## Funktionen je Gruppe

### 1. Listen und Freigaben
- Auswahl der Blocklisten pro Gruppe, standardmäßig die globale Auswahl. Dazu kommen beliebige weitere Listen,
  z. B. die Kinderschutz-Listen nur für „Kinder“, und auf Wunsch einzelne globale Listen aus („Smart-TV“ ohne
  Native Tracker).
- Eigene Freigaben pro Gruppe, z. B. die Schulplattform, zusätzlich zu den globalen.
- Eigene Sperren pro Gruppe, einzelne Domains wie `tiktok.com`, mit Subdomains.
- **Kategorien-Schalter** als Abkürzung: „Soziale Netzwerke“, „Spiele“, „Streaming“, „Glücksspiel“,
  „Erwachseneninhalte“. Jeder Schalter steht für eine kleine, von uns gepflegte Domainliste, dazu Glücksspiel
  und NSFW aus HaGeZi/OISD.

### 2. Kinderfreundliche Antworten (SafeSearch)
- **Google:** `google.<tld>` und `www.google.<tld>` antworten als CNAME auf `forcesafesearch.google.com`, alle
  Länderendungen.
- **YouTube:** `www.youtube.com`, `m.youtube.com`, `youtubei.googleapis.com`, `youtube.googleapis.com` und
  `www.youtube-nocookie.com` auf `restrict.youtube.com` (streng) bzw. `restrictmoderate.youtube.com` (mittel).
- **Bing:** `www.bing.com` auf `strict.bing.com`.
- **DuckDuckGo:** `duckduckgo.com` auf `safe.duckduckgo.com`.
- **Umsetzung:** DNS64 antwortet mit CNAME und den aufgelösten Adressen des Ziels. Das Ziel geht wie jede
  Anfrage über den Cache und die Upstreams. HTTPS bleibt unberührt, keine Zertifikate nötig.
- Ist ein Gerät im Browser angemeldet, kann es SafeSearch nicht abschalten. Die Umleitung liegt im DNS.

### 3. Schutz gegen Umgehen
- Die Liste „HaGeZi DoH/VPN/Proxy Bypass“ (seit 1.15.0) pro Gruppe einschalten.
- `use-application-dns.net` mit NXDOMAIN beantworten. Firefox schaltet sein eingebautes DoH dann ab. Sinnvoll
  auch global, als eigener Schalter in den Einstellungen.
- `mask.icloud.com` und `mask-h2.icloud.com` mit NXDOMAIN beantworten. iCloud Private Relay ist auf diesen Geräten
  dann aus.
- Hinweis auf der Seite: DoH/DoT von DNS64 selbst gilt mit, die Gruppe erkennt DNS64 auch dort.

### 4. Zeitpläne
- Pro Gruppe Regeln aus Wochentagen und Uhrzeit, z. B. „Mo–Fr 21:00–07:00“. Es gilt die Zeitzone der Node aus
  den Einstellungen des Kerns.
- Was in der Zeit passiert, ist je Regel einstellbar:
  - **„Internet aus“:** Es antworten nur lokale Namen, eigene Einträge und die Freigaben der Gruppe.
    Alles andere bekommt NXDOMAIN bzw. 0.0.0.0, wie beim Blockieren.
  - **Kategorien sperren:** z. B. „Spiele“ und „Soziale Netzwerke“ nur am Wochenende frei.
- Regeln, die über Mitternacht gehen, sind erlaubt. Mehrere Regeln pro Gruppe sind möglich.
- Im Abfrage-Log steht der Grund, z. B. „Zeitplan: Schlafenszeit“.

### 5. Sofort-Knöpfe
- **„Sperren“** pro Gruppe, wie die heutige Pause, nur umgekehrt: 30 min, 1 h, bis morgen früh oder bis zum
  Aufheben. Wirkt wie „Internet aus“.
- **„Frei“** (Bonuszeit) pro Gruppe: Zeitpläne und Kategorien für 30 min / 1 h aussetzen. Die Blocklisten
  gelten weiter.
- Die Knöpfe stehen oben auf der Gruppen-Seite und auf der Dashboard-Karte von DNS64.

### 6. Übersicht und Log
- Neue Seite **„Gruppen“** (Reiter in DNS64). Jede Gruppe zeigt:
  - ihre Geräte mit Name, MAC, letzter IP und „zuletzt gesehen“;
  - die Anfragen heute, davon geblockt;
  - den aktiven Zeitplan;
  - die Knöpfe.
- **Gerät hinzufügen:** aus den Geräten der letzten 24 h im Abfrage-Log wählen (Name vom Router, MAC aus der
  Nachbartabelle) oder MAC/IP/Netz von Hand eintragen.
- Abfrage-Log: neue Spalte „Gruppe“, Filter nach Gruppe. Die Top-Listen der Übersicht sind pro Gruppe filterbar.
- Datenschutz: Die heutige Kürzung der Client-Adressen gilt weiter. Bei „gekürzt“/„keine“ speichert das Log den
  Gruppennamen statt der Adresse, damit die Auswertung pro Gruppe trotzdem geht.

## Technik

- **Matcher:** Heute steht je Regel nur die erste Liste (`uint8`). Neu wird daraus eine Bitmaske der Listen
  (`uint64`, höchstens 64 Listen: 28 Vorlagen plus eigene).
  - Eine Anfrage ist geblockt, wenn die Maske der Regel und die Listenmaske der Gruppe sich überschneiden.
  - Geladen wird die Vereinigung aller Listen, die irgendeine Gruppe nutzt. Nicht genutzte Listen werden gar nicht
    geladen.
  - Speicher: etwa +7 MB je 1 Mio. Regeln.
- **Zuordnung:** `groups.Resolver` mit Nachbartabelle (Netlink `RTM_GETNEIGH`, IPv4 und IPv6, alle 30 s) und den
  Netz-Regeln. Ergebnis wird je Client-IP 60 s gecacht.
- **Reihenfolge im Server** (heute: eigene Einträge, lokale Namen, Blocklisten, Cache, Upstream):
  1. Zeitplan/Sperre der Gruppe („Internet aus“: nur eigene Einträge, lokale Namen, Freigaben);
  2. SafeSearch/Bypass-Regeln;
  3. eigene Einträge;
  4. lokale Namen;
  5. Freigaben der Gruppe und global;
  6. Sperren der Gruppe;
  7. Blocklisten mit der Maske der Gruppe;
  8. Cache;
  9. Upstream.

  Die globale Pause setzt wie heute nur Blocklisten aus, nicht Zeitpläne und Sperren der Gruppen.
- **Daten:** Tabellen `dns64_groups` (Name, Reihenfolge, Listenmaske, SafeSearch, Bypass, Kategorien) und
  `dns64_group_members` (Typ mac/ip/net, Wert, Name). Dazu `dns64_group_rules` (Tage, von, bis, Aktion) und
  `dns64_group_domains` (Freigabe/Sperre). Alles in `node64.db`, damit es in Export, Import und Backup ist.
  Der Zustand der Sofort-Knöpfe liegt in den Einstellungen wie die heutige Pause.
- **API:** `GET|POST /api/dns64/groups`, `GET|PUT|DELETE /api/dns64/groups/{id}` und
  `POST /api/dns64/groups/{id}/block|free|resume`. Dazu `GET /api/dns64/devices` (zuletzt gesehen, MAC, Name,
  Gruppe) sowie Audit für jede Änderung, OpenAPI und Hilfe-Links.
- **Prometheus:** Anfragen und Blockierungen je Gruppe.

## Phasen

| Phase | Inhalt |
|---|---|
| G1 | Gruppen anlegen, Geräte per IP/Netz und MAC (Nachbartabelle) zuordnen, Seite „Gruppen“, Spalte und Filter im Log, Geräteauswahl aus dem Log |
| G2 | Listen und Freigaben/Sperren je Gruppe (Matcher mit Bitmaske), Kategorien-Schalter |
| G3 | SafeSearch (Google, YouTube, Bing, DuckDuckGo) und Schutz gegen Umgehen (Bypass-Liste, Firefox-Canary, iCloud Private Relay) |
| G4 | Zeitpläne und Sofort-Knöpfe (Sperren/Frei), Dashboard-Karte |
| G5 | API vollständig, Prometheus je Gruppe, Doku (node64.de), Export/Import, Tests mit -race, Box-Test |

Jede Phase ist für sich nutzbar und wird einzeln ausgerollt.

## Offene Fragen an Dennis

1. **Erkennung:** MAC zuerst und IP/Netz als Ausweichweg, einverstanden? Oder nur IP/Netz?
2. **Kategorien-Schalter** („Soziale Netzwerke“, „Spiele“, „Streaming“): Sollen wir die Domainlisten selbst
   pflegen (klein, im Image), oder nur fertige Listen nutzen (Glücksspiel, NSFW) und den Rest als eigene Sperren?
3. **YouTube:** standardmäßig „streng“ oder „mittel“?
4. **„Internet aus“:** NXDOMAIN wie beim Blockieren, oder eine Antwort auf eine Hinweis-IP der Node? Eine
   HTTPS-Seite „gesperrt“ geht ohne Zertifikat für die fremde Domain nicht. Es ginge nur für HTTP und im Browser
   als Fehlerseite.
5. **Benachrichtigung**, wenn ein Gerät der Gruppe „Kinder“ etwas Gesperrtes versucht (z. B. einmal pro Tag als
   Zusammenfassung)? Oder bewusst nicht?
6. Bleiben die **Kinderschutz-Listen** zusätzlich global wählbar, wie seit 1.15.0, oder sind sie mit Gruppen nur
   noch pro Gruppe wählbar?
