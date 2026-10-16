-- Selbst signierte Zertifikate: Art des Schluessels (ecdsa = P-256, rsa = 2048 Bit; leer = ecdsa).
ALTER TABLE certs ADD COLUMN key_type TEXT NOT NULL DEFAULT '';
