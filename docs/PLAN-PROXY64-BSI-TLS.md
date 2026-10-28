# Plan: PROXY64 TLS nach BSI TR-02102-2

Stand 2026-10-28. Dennis: Wenn es für uns einfach ist, TLS nach BSI TR-02102-2 anbieten und damit werben. Kein
FIPS-Schalter.

## Ziel

Je Proxy-Host (und als Standard für neue Hosts) eine TLS-Vorgabe **„BSI TR-02102-2“**: PROXY64 bietet dann nur
Protokolle, Verfahren und Kurven an, die die Technische Richtlinie des BSI empfiehlt. Werbeaussage danach (ehrlich, ohne
Zertifikat): „TLS-Einstellungen nach BSI TR-02102-2 wählbar“.

## Heute

- TLS 1.2 und 1.3 (Feld „Mindestens TLS“ 1.2/1.3 je Host), sonst die Standards von Go.
- Go bietet bei TLS 1.2 auch ECDHE mit AES-CBC und SHA-1 sowie ChaCha20-Poly1305 an; Kurven X25519 (auch hybrid mit
  ML-KEM), P-256, P-384.

## Umsetzung (klein)

1. Feld `MinTLS` bekommt einen dritten Wert `bsi` (Auswahl „TLS nach BSI TR-02102-2“); kein neues Formularfeld.
2. Edge (`internal/edge`, `tcpConfig`): bei `bsi`
   - TLS 1.2 nur ECDHE mit AES-GCM (ECDSA und RSA), keine CBC- und SHA-1-Suites, kein ChaCha20;
   - TLS 1.3 nur `TLS_AES_128_GCM_SHA256` und `TLS_AES_256_GCM_SHA384` (Go wählt 1.3-Suites selbst – prüfen, wie
     sich ChaCha20 dort abschalten lässt; sonst Hinweis in der Doku);
   - Kurven P-256, P-384 (und P-521, falls Go sie anbietet); X25519 und Hybrid-Verfahren nur, wenn die aktuelle Fassung
     der TR sie nennt.
   - HTTP/3 (QUIC) ist TLS 1.3: gleiche Einschränkung soweit Go es zulässt.
3. Standard für neue Hosts in den PROXY64-Einstellungen wählbar („TLS-Vorgabe für neue Hosts“).
4. Zertifikate: RSA ab 3000 Bit bzw. ECDSA P-256/P-384 – bei Let's Encrypt ECDSA P-256 (Standard) passt; bei eigenen
   Zertifikaten Hinweis, wenn RSA < 3000 Bit.
5. Tests: Handshake mit erlaubten und verbotenen Suites/Kurven; Render-Test der Auswahl.
6. Doku (node64.de): Abschnitt „TLS nach BSI TR-02102-2“ mit Liste der Verfahren und dem Hinweis, dass ältere Clients
   (z. B. ohne AES-GCM) dann nicht mehr verbinden.

## Vor dem Umsetzen

Die aktuelle Fassung der TR-02102-2 (Jahr der Veröffentlichung) lesen und die Listen oben abgleichen
(insbesondere X25519, ChaCha20, hybride Verfahren mit ML-KEM, Brainpool-Kurven). Die Werbeaussage nennt die Fassung.
