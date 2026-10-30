-- SecNtfy heisst jetzt IPv64 App und hat wieder den Typ app (Server fest api.secntfy.app, Geraete-Token und
-- kritischer Alarm bleiben). Der fruehere Firebase-Weg der App ist ersetzt.
UPDATE nf_channels SET type = 'app' WHERE type = 'secntfy';
