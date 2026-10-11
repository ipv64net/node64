-- Umbenennung Agent -> Node64: Einstellungsschluessel agent.* heissen jetzt node.*
UPDATE settings SET key = 'node.' || substr(key, 7) WHERE key LIKE 'agent.%';
