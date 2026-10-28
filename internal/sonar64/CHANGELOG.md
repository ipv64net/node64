# Änderungen – Sonar64

## 0.1.1 – 2026-10-28

### Behoben
- Knoten mit IPv4 und IPv6 sprechen ipv64.net abwechselnd über beide Familien an. Bisher kannte ipv64.net oft nur die
  IPv6-Adresse, und der Knoten wurde nie über IPv4 gemessen.
- Scheitert der Abgleich von Rolle oder Budget, erscheint der Hinweis gleich zusammen mit dem Knoten.

## 0.1.0 – 2026-10-28

Erste Fassung des Community-Messnetzes Sonar64 als optionales Modul (standardmäßig aus).

### Neu
- Teilnahme per Opt-in mit dem zentralen ipv64-API-Key: Node64 legt dafür ein eigenes Sonar-Token an (verschlüsselt
  gespeichert) und misst nach dem signierten Plan von ipv64.net, innerhalb fester Grenzen.
- Rolle „nur ausgehend“ (Standard) oder „auch gemessen“ (UDP 6464, über die Port-Verwaltung), Budget sparsam/normal/
  großzügig, Ruhezeit.
- Profil bei ipv64: Anzeigename, Standort (öffentlich auf etwa 1 km verschleiert), Anschlussart, Gerät.
- Vertrauensstufe als farbiges Abzeichen mit Fortschritt zur nächsten Stufe, Link zur öffentlichen Knotenseite.
- Live-Tabellen „Pings von mir“ (alle 5 Sekunden) und „Pings gegen mich“ (UDP 6464 sofort, sonst aus den Ergebnissen
  bei ipv64).
- Schnelle Aufnahme: Plan alle 2 Minuten (unverändert nur eine kurze Antwort), Meldung alle 5 Minuten.
- „Austreten“ meldet den Knoten bei ipv64.net ab und löscht Token, Schlüssel und Node-ID; ist ipv64.net nicht
  erreichbar, wird lokal trotzdem ausgetreten (ipv64.net meldet den Knoten nach 30 Tagen ohne Meldung selbst ab).
  „Node zurücksetzen“ tritt ebenfalls aus.
- Von ipv64.net abgemeldet (Token zurückgezogen, gesperrt, 30 Tage ohne Meldung): die Node misst nicht mehr, schließt
  UDP 6464 und prüft stündlich; die Seite zeigt „Von ipv64.net abgemeldet“ mit „Neu teilnehmen“ (neues Token).
- Lokale API `/api/sonar64/status`, `recent`, `inbound`, `settings`.
