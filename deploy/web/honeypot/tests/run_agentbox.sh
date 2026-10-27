#!/bin/bash
# Honeypot64 H2: Pruefung in einer abgeschotteten Umgebung auf der Testbox (ssh agentbox).
# Eigene Container/Netz/Image mit Praefix hp2test-, Test-DB mit Test-Passwort; am Ende wird alles entfernt.
# Andere Container auf der Box werden nicht angefasst.
#   bash run_agentbox.sh <pfad/zu/ipv64net_webseite/api_v2.php>
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WEB="$(cd "$HERE/../.." && pwd)"          # deploy/web
SQL="$(cd "$WEB/../sql" && pwd)"          # deploy/sql
API="${1:?Pfad zu api_v2.php}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# Webroot zusammenstellen: echte api_v2.php mit require-Zeile vor dem Start-Block (wie in der Einspiel-Anleitung),
# Stubs fuer dbconnect/header/footer
mkdir -p "$STAGE/hp2test/web/honeypot" "$STAGE/hp2test/web/bots" "$STAGE/hp2test/tests" "$STAGE/hp2test/sql"
cat > "$STAGE/patch.py" <<'PY'
import sys
s = open(sys.argv[1], encoding="utf-8").read().replace("\r\n", "\n")
n = "// ===================================================================\n//  Start\n"
p = s.rfind(n)
assert p >= 0, "Start-Block nicht gefunden"
sys.stdout.write(s[:p] + "require __DIR__ . '/api_v2_honeypot.php';\n\n" + s[p:])
PY
python "$STAGE/patch.py" "$API" > "$STAGE/hp2test/web/api_v2.php"
grep -q "api_v2_honeypot.php" "$STAGE/hp2test/web/api_v2.php"
cp "$WEB/api_v2_honeypot.php" "$STAGE/hp2test/web/"
cp "$WEB/honeypot/index.php" "$STAGE/hp2test/web/honeypot/"
cp "$WEB/bots/honeypot_cleanup.php" "$STAGE/hp2test/web/bots/"
cp "$HERE/dbconnect_stub.php" "$STAGE/hp2test/web/dbconnect.php"
cp "$HERE/header_stub.php" "$STAGE/hp2test/web/header.php"
cp "$HERE/footer_stub.php" "$STAGE/hp2test/web/footer.php"
cp "$HERE/run_tests.php" "$HERE/fresh_report.php" "$HERE/sample_report.json" "$HERE/setup.sql" "$STAGE/hp2test/tests/"
cp "$SQL/honeypot.sql" "$STAGE/hp2test/sql/"
cp "$SQL/honeypot_h4_stats.sql" "$STAGE/hp2test/sql/"   # Zaehlung je Account (seit H4 Teil der Annahme)
cp "$SQL/honeypot_sensor_country.sql" "$STAGE/hp2test/sql/"   # Standort des Sensors (Live-Karte)
cp "$SQL/honeypot_h3_scoring.sql" "$STAGE/hp2test/sql/"   # hp_list_tokens (GET /honeypot/list-token)

ssh agentbox 'rm -rf /tmp/hp2test'
scp -q -r "$STAGE/hp2test" agentbox:/tmp/

ssh agentbox 'bash -s' <<'REMOTE'
set -u
cleanup() {
  docker rm -f -v hp2test-php hp2test-db >/dev/null 2>&1 || true
  docker network rm hp2test-net >/dev/null 2>&1 || true
  docker rmi hp2test-php:latest >/dev/null 2>&1 || true
  rm -rf /tmp/hp2test
}
trap cleanup EXIT
docker network create hp2test-net >/dev/null
docker run -d --name hp2test-db --network hp2test-net -e MARIADB_ROOT_PASSWORD=hp2test -e MARIADB_DATABASE=ipv64 mariadb:10.5 >/dev/null
printf 'FROM php:8.3-cli\nRUN docker-php-ext-install pdo_mysql >/dev/null\n' | docker build -q -t hp2test-php:latest - >/dev/null
for i in $(seq 1 60); do docker exec hp2test-db mysql -uroot -php2test -e 'SELECT 1' ipv64 >/dev/null 2>&1 && break; sleep 1; done
docker exec -i hp2test-db mysql -uroot -php2test ipv64 < /tmp/hp2test/tests/setup.sql
docker exec -i hp2test-db mysql -uroot -php2test ipv64 < /tmp/hp2test/sql/honeypot.sql
docker exec -i hp2test-db mysql -uroot -php2test ipv64 < /tmp/hp2test/sql/honeypot.sql   # mehrfach ausfuehrbar
docker exec -i hp2test-db mysql -uroot -php2test ipv64 < /tmp/hp2test/sql/honeypot_h4_stats.sql
docker exec -i hp2test-db mysql -uroot -php2test ipv64 < /tmp/hp2test/sql/honeypot_sensor_country.sql
docker exec -i hp2test-db mysql -uroot -php2test ipv64 < /tmp/hp2test/sql/honeypot_h3_scoring.sql
echo "--- Tabellen"; docker exec hp2test-db mysql -uroot -php2test ipv64 -N -e "SHOW TABLES LIKE 'hp\_%'" | tr '\n' ' '; echo
docker run -d --name hp2test-php --network hp2test-net -e HP2TEST=1 -v /tmp/hp2test:/w -w /w/web hp2test-php:latest php -S 0.0.0.0:8080 -t /w/web >/dev/null
sleep 1
for f in /w/web/api_v2_honeypot.php /w/web/honeypot/index.php /w/web/bots/honeypot_cleanup.php /w/tests/run_tests.php /w/tests/fresh_report.php; do
  docker exec hp2test-php php -l "$f" | grep -v '^No syntax errors' || true
done
docker exec -e HP2TEST=1 hp2test-php php /w/tests/run_tests.php http://127.0.0.1:8080 /w/web; rc=$?
echo "--- Server-Log (Warnungen/Fehler)"; docker logs hp2test-php 2>&1 | grep -iE 'error|warning|notice|deprecated' | head -20 || true
exit $rc
REMOTE
