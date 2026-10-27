#!/bin/bash
# Honeypot64 H5 (Fruehwarnung fuer eigene Netze, Limits je Klasse): Pruefung in einer abgeschotteten Umgebung auf der
# Testbox (ssh agentbox). Eigene Container/Netz/Image mit Praefix hp5w-, Test-DB mit Test-Passwort; am Ende wird alles
# entfernt. Andere Container auf der Box werden nicht angefasst.
#   bash run_agentbox.sh <pfad/zu/ipv64net_webseite/api_v2.php>
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
HP="$(cd "$HERE/../.." && pwd)"            # deploy/web/honeypot
WEB="$(cd "$HP/.." && pwd)"                # deploy/web
SQL="$(cd "$WEB/../sql" && pwd)"           # deploy/sql
API="${1:?Pfad zu api_v2.php}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# Webroot zusammenstellen: echte api_v2.php mit den require-Zeilen vor dem Start-Block (wie in der Einspiel-Anleitung),
# Stubs fuer dbconnect/header/footer
mkdir -p "$STAGE/hp5w/web/honeypot" "$STAGE/hp5w/web/bots" "$STAGE/hp5w/tests" "$STAGE/hp5w/sql"
cat > "$STAGE/patch.py" <<'PY'
import sys
s = open(sys.argv[1], encoding="utf-8").read().replace("\r\n", "\n")
n = "// ===================================================================\n//  Start\n"
p = s.rfind(n)
assert p >= 0, "Start-Block nicht gefunden"
sys.stdout.write(s[:p] + "require __DIR__ . '/api_v2_honeypot.php';\nrequire __DIR__ . '/api_v2_threat.php';\nrequire __DIR__ . '/api_v2_threat_watch.php';\n\n" + s[p:])
PY
python "$STAGE/patch.py" "$API" > "$STAGE/hp5w/web/api_v2.php"
grep -q "api_v2_threat_watch.php" "$STAGE/hp5w/web/api_v2.php"
cp "$WEB/api_v2_honeypot.php" "$WEB/api_v2_threat.php" "$WEB/api_v2_threat_watch.php" "$WEB/api_v2_openapi.json" "$STAGE/hp5w/web/"
cp "$HP/watch.php" "$HP/hp_limits_lib.php" "$HP/hp_release_lib.php" "$STAGE/hp5w/web/honeypot/"
cp "$WEB/bots/honeypot_watch.php" "$STAGE/hp5w/web/bots/"
cp "$HERE/dbconnect_stub.php" "$STAGE/hp5w/web/dbconnect.php"
cp "$HERE/header_stub.php" "$STAGE/hp5w/web/header.php"
cp "$HP/tests/footer_stub.php" "$STAGE/hp5w/web/footer.php"
cp "$HERE/run_tests.php" "$HERE/setup.sql" "$STAGE/hp5w/tests/"
cp "$SQL/honeypot.sql" "$SQL/honeypot_h3_scoring.sql" "$SQL/honeypot_h5.sql" "$SQL/honeypot_watch_details.sql" "$SQL/honeypot_sensor_country.sql" "$STAGE/hp5w/sql/"

ssh agentbox 'rm -rf /tmp/hp5w'
scp -q -r "$STAGE/hp5w" agentbox:/tmp/

ssh agentbox 'bash -s' <<'REMOTE'
set -u
cleanup() {
  docker rm -f -v hp5w-php hp5w-db >/dev/null 2>&1 || true
  docker network rm hp5w-net >/dev/null 2>&1 || true
  docker rmi hp5w-php:latest >/dev/null 2>&1 || true
  rm -rf /tmp/hp5w
}
trap cleanup EXIT
docker network create hp5w-net >/dev/null
docker run -d --name hp5w-db --network hp5w-net -e MARIADB_ROOT_PASSWORD=hp5wtest -e MARIADB_DATABASE=ipv64 mariadb:10.5 >/dev/null
printf 'FROM php:8.3-cli\nRUN docker-php-ext-install pdo_mysql >/dev/null\n' | docker build -q -t hp5w-php:latest - >/dev/null
for i in $(seq 1 60); do docker exec hp5w-db mysql -uroot -php5wtest -e 'SELECT 1' ipv64 >/dev/null 2>&1 && break; sleep 1; done
M="docker exec -i hp5w-db mysql -uroot -php5wtest ipv64"
$M < /tmp/hp5w/tests/setup.sql
$M < /tmp/hp5w/sql/honeypot.sql
$M < /tmp/hp5w/sql/honeypot_h3_scoring.sql
$M < /tmp/hp5w/sql/honeypot_h5.sql
$M < /tmp/hp5w/sql/honeypot_h5.sql   # mehrfach ausfuehrbar
$M < /tmp/hp5w/sql/honeypot_watch_details.sql
$M < /tmp/hp5w/sql/honeypot_watch_details.sql   # mehrfach ausfuehrbar
$M < /tmp/hp5w/sql/honeypot_sensor_country.sql   # Standort des Sensors (api_v2_honeypot.php schreibt hp_sensors.country)
echo "--- Tabellen"; docker exec hp5w-db mysql -uroot -php5wtest ipv64 -N -e "SHOW TABLES LIKE 'hp\_%'" | tr '\n' ' '; echo
docker run -d --name hp5w-php --network hp5w-net -e HP5WTEST=1 -v /tmp/hp5w:/w -w /w/web hp5w-php:latest php -S 0.0.0.0:8080 -t /w/web >/dev/null
sleep 1
for f in /w/web/api_v2.php /w/web/api_v2_honeypot.php /w/web/api_v2_threat_watch.php /w/web/honeypot/watch.php /w/web/honeypot/hp_limits_lib.php /w/web/bots/honeypot_watch.php /w/tests/run_tests.php; do
  docker exec hp5w-php php -l "$f" | grep -v '^No syntax errors' || true
done
docker exec -e HP5WTEST=1 hp5w-php php /w/tests/run_tests.php http://127.0.0.1:8080 /w/web; rc=$?
echo "--- Server-Log (Warnungen/Fehler)"; docker logs hp5w-php 2>&1 | grep -iE 'error|warning|notice|deprecated' | head -30 || true
exit $rc
REMOTE
