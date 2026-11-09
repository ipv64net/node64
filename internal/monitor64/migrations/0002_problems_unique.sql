-- Hoechstens ein offenes Problem je Host und Dienst (Review: doppelte offene Probleme blieben fuer immer offen).
-- Vorhandene Doppel vorher schliessen (das juengste bleibt offen).
UPDATE m64_problems SET closed_at = updated_at, closed_how = 'auto', state = 'ok'
WHERE closed_at = '' AND deleted = 0 AND id NOT IN (
	SELECT MAX(id) FROM m64_problems WHERE closed_at = '' AND deleted = 0 GROUP BY host_uid, service_key
);
CREATE UNIQUE INDEX IF NOT EXISTS m64_problems_one_open ON m64_problems (host_uid, service_key) WHERE closed_at = '' AND deleted = 0;
