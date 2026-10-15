# Änderungen – CDN64

## 1.1.0 – 2026-10-15

Reiter SSL-Zertifikate.

### Neu
- Liste aller Zertifikate:
  - Namen, Weg, Aussteller;
  - Ablauf als Pille (grün, ab 30 Tagen vor Ablauf gelb, ab 7 Tagen rot) mit Datum;
  - benutzt von welchen Hosts, automatische Erneuerung an/aus;
  - Erneuern, Herunterladen (ohne Schlüssel), Löschen (benutzte nur nach Rückfrage);
  - der laufende Schritt beim Abruf, die Seite lädt dabei selbst neu.
- Zertifikat anfordern bei Let's Encrypt:
  - automatisch (ipv64, wenn alle Namen im Account liegen, sonst HTTP-01) oder gezielt per ipv64 DNS-01 (auch Wildcards);
  - Alias über ipv64 für fremde Domains, mit Vorschau der nötigen CNAME-Einträge;
  - per HTTP-01;
  - Testumgebung wählbar.
- Eigenes Zertifikat hochladen (Datei oder hineinkopieren).
- Let's-Encrypt-Konto: Mail und Zustimmung zu den Nutzungsbedingungen.
- Host-Formular: „Neues Zertifikat gleich mit anfordern“; in der API über `request_certificate` beim Anlegen oder Ändern eines Hosts.

## 1.0.0 – 2026-10-15

Erste Version des Reverse-Proxys, angelehnt an den Nginx Proxy Manager.

### Neu
- Proxy-Hosts mit mehreren Domains (auch Wildcards) und Ziel per http oder https, Name oder IP, Port.
- Optionen je Host:
  - WebSockets;
  - Block Common Exploits (Regeln wie beim NPM, dazu Sperre für .git und .env);
  - Cache Assets: statische Dateien im Speicher, höchstens 64 MB.
- SSL je Host:
  - Zertifikat aus der Zertifikatsverwaltung (passend nach Namen oder fest gewählt) oder nur HTTP.
  - HTTPS erzwingen, HSTS (auch für Subdomains), HTTP/2, HTTP/3 (QUIC), mindestens TLS 1.2 oder 1.3.
- Erreichbarkeit der Ziele: jede Minute geprüft, in der Liste mit Antwortzeit bzw. „nicht erreichbar seit …“.
- Ein nicht erreichbares Ziel bekommt eine neutrale Seite „502“. Schleifen (Ziel zeigt auf den Proxy selbst) werden erkannt.
- Zähler je Host seit dem Start: Anfragen, Fehler, gesperrte Anfragen.
- Dashboard-Karte, Audit für alle Änderungen, lokale API unter `/api/cdn64/…`.
- Export und Import der Hosts.
- Ausgeschaltet läuft nichts: keine Routen, keine Prüfung, kein Cache, und der gemeinsame Eingang schließt seine Ports.
