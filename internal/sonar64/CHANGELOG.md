# Änderungen – Sonar64

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
- Lokale API `/api/sonar64/status`, `recent`, `inbound`, `settings`.
