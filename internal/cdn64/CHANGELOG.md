# Änderungen – CDN64

## 1.3.0 – 2026-10-15

Custom Locations, Zugriffslisten, erweiterte Optionen, Statistik und Zugriffs-Log.

### Neu
- Custom Locations: Pfade eines Proxy-Hosts mit eigenem Ziel (z. B. /api auf einen anderen Dienst).
  - Optional mit anderem Pfad beim Ziel, eigener WebSocket-Einstellung und eigener Zugriffsliste.
  - Der längste passende Pfad gewinnt.
- Zugriffslisten:
  - Benutzer mit Passwort (nur als bcrypt-Hash gespeichert) und IP-Regeln (allow/deny, erster Treffer gilt, sonst gesperrt).
  - „Beides nötig“ oder „eine Bedingung genügt“; die Anmeldung lässt sich an das Ziel weiterreichen.
  - Nach 10 falschen Anmeldungen in 5 Minuten ist die IP 15 Minuten gesperrt; die Sperre steht im Audit.
  - Gilt für Proxy-Hosts, Locations und Weiterleitungen.
- Erweitert:
  - Kopfzeilen zum Ziel und zum Besucher setzen bzw. entfernen;
  - Host-Kopf (Name des Besuchers, des Ziels oder fester Wert);
  - Timeout zum Ziel, Upload-Grenze (413), nicht puffern, gzip für Text-Antworten;
  - vertrauenswürdige Proxys mit Cloudflare-Vorlage für die echte Client-IP.
- Statistik: Anfragen je Host und Stunde (2xx–5xx, Datenmenge) über 90 Tage. Die Liste zeigt die Anfragen der letzten 24 Stunden.
- Zugriffs-Log je Host einschaltbar:
  - Reiter „Zugriffe“ mit Filter nach Host, Status und Suche;
  - Aufbewahrung 1–90 Tage, Client-IPs auf Wunsch gekürzt;
  - eigene Datei cdn64.db.
- „Healthcheck für dieses Ziel anlegen“ bei Proxy-Hosts, TLS durchreichen und TCP-Streams (braucht das Modul Healthchecks).
- API: Zugriffslisten, Zugriffs-Log, Statistik, Einstellungen, Healthcheck anlegen.

## 1.2.0 – 2026-10-15

Weiterleitungen, 404-Hosts, Streams, TLS durchreichen und die Standardseite.

### Neu
- Weiterleitungen (Redirection Hosts):
  - Domains auf eine andere Domain, optional mit Port und Pfad;
  - Code 301, 302, 303, 307, 308 oder 300;
  - Schema wie die Anfrage oder fest;
  - Pfad und Abfrage mitnehmen;
  - SSL-Optionen wie bei Proxy-Hosts.
- 404-Hosts: Domains, die bewusst mit „nicht gefunden“ antworten, auch per HTTPS.
- Streams:
  - ein Port (TCP und/oder UDP) wird roh an ein Ziel weitergereicht;
  - bei TCP optional mit TLS-Abschluss über ein Zertifikat der Verwaltung;
  - Ports werden gegen die anderen Teile geprüft; ist einer belegt, steht der Grund am Stream;
  - Zähler für Verbindungen und Datenmenge, Erreichbarkeit des Ziels.
- TLS durchreichen: Ein Name auf Port 443 geht roh an einen Dienst mit eigenem Zertifikat, ohne Entschlüsselung hier. Alle anderen Namen auf 443 bleiben bei Node64.
- Standardseite für unbekannte Namen: 404, Verbindung schließen, Weiterleitung oder eigene HTML-Seite.
- Export/Import enthält jetzt auch die Streams.

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
