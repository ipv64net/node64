-- iGotify ist kein eigener Kanaltyp mehr: es ist ein normaler Gotify-Server (die iPhone-App haengt am Gotify-Server).
UPDATE nf_channels SET type = 'gotify' WHERE type = 'igotify';
