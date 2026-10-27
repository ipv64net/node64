#!/bin/bash
# Honeypot64 H4 (Statistik + Listen): Pruefung in einer abgeschotteten Umgebung auf der Testbox (ssh agentbox).
# Eigene Container/Netz/Image mit Praefix hp4a-, Test-DB mit Test-Passwort; am Ende wird alles entfernt.
# Andere Container auf der Box werden nicht angefasst. Das nginx-Image wird nur entfernt, wenn es vorher fehlte.
#   bash run_agentbox.sh <pfad/zu/ipv64net_webseite/api_v2.php>
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
HP="$(cd "$HERE/../.." && pwd)"            # deploy/web/honeypot
WEB="$(cd "$HP/.." && pwd)"                # deploy/web
BL="$WEB/blocklists"
SQL="$(cd "$WEB/../sql" && pwd)"           # deploy/sql
API="${1:?Pfad zu api_v2.php}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# Webroot wie auf ipv64 (/var/www/clients/client1/web58/web), echte api_v2.php mit den require-Zeilen vor dem Start-Block
R="$STAGE/hp4a"; W="$R/web58/web"
mkdir -p "$W/honeypot" "$W/bots/blocklist" "$W/blocklists/countries" "$R/web58/private" "$R/tests" "$R/sql" "$R/nginx"
cat > "$STAGE/patch.py" <<'PY'
import sys
s = open(sys.argv[1], encoding="utf-8").read().replace("\r\n", "\n")
n = "// ===================================================================\n//  Start\n"
p = s.rfind(n)
assert p >= 0, "Start-Block nicht gefunden"
sys.stdout.write(s[:p] + "require __DIR__ . '/api_v2_honeypot.php';\nrequire __DIR__ . '/api_v2_threat.php';\nrequire __DIR__ . '/api_v2_honeypot_stats.php';\n\n" + s[p:])
PY
python "$STAGE/patch.py" "$API" > "$W/api_v2.php"
grep -q "api_v2_honeypot_stats.php" "$W/api_v2.php"
cp "$WEB/api_v2_honeypot.php" "$WEB/api_v2_threat.php" "$WEB/api_v2_honeypot_stats.php" "$W/"
cp "$HP/stats.php" "$HP/hp_stats_lib.php" "$HP/hp_release_lib.php" "$W/honeypot/"
cp "$WEB/bots/honeypot_lists.php" "$WEB/bots/honeypot_lists_index.php" "$W/bots/"
cp "$BL/site/bots/blocklist/create_blocklists_v2.php" "$W/bots/blocklist/"
cp "$HERE/dbconnect_stub.php" "$W/dbconnect.php"
cp "$HERE/header_stub.php" "$W/header.php"
cp "$HERE/footer_stub.php" "$W/footer.php"
cp "$HERE/run_tests.php" "$HERE/setup.sql" "$HERE/legacy.sql" "$R/tests/"
cp "$HERE/nginx.conf" "$R/nginx.conf"
cp "$SQL/honeypot.sql" "$SQL/honeypot_h3_scoring.sql" "$SQL/honeypot_h4_stats.sql" "$SQL/honeypot_h6.sql" "$SQL/honeypot_sensor_country.sql" "$R/sql/"

ssh agentbox 'rm -rf /tmp/hp4a'
scp -q -r "$R" agentbox:/tmp/

ssh agentbox 'bash -s' <<'REMOTE'
set -u
NGX=nginx:1.27-alpine
HAD_NGX=0; docker image inspect $NGX >/dev/null 2>&1 && HAD_NGX=1
cleanup() {
  docker rm -f -v hp4a-php hp4a-db hp4a-nginx >/dev/null 2>&1 || true
  docker network rm hp4a-net >/dev/null 2>&1 || true
  docker rmi hp4a-php:latest >/dev/null 2>&1 || true
  [ "$HAD_NGX" = 0 ] && docker rmi $NGX >/dev/null 2>&1 || true
  rm -rf /tmp/hp4a
}
trap cleanup EXIT
docker network create hp4a-net >/dev/null
docker run -d --name hp4a-db --network hp4a-net -e MARIADB_ROOT_PASSWORD=hp4atest -e MARIADB_DATABASE=ipv64 mariadb:10.5 >/dev/null
printf 'FROM php:8.3-cli\nRUN docker-php-ext-install pdo_mysql >/dev/null\n' | docker build -q -t hp4a-php:latest - >/dev/null
for i in $(seq 1 60); do docker exec hp4a-db mysql -uroot -php4atest -e 'SELECT 1' ipv64 >/dev/null 2>&1 && break; sleep 1; done
M="docker exec -i hp4a-db mysql -uroot -php4atest ipv64"
$M < /tmp/hp4a/tests/setup.sql
$M < /tmp/hp4a/sql/honeypot.sql
$M < /tmp/hp4a/sql/honeypot_h3_scoring.sql
$M < /tmp/hp4a/tests/legacy.sql
$M < /tmp/hp4a/sql/honeypot_h4_stats.sql
$M < /tmp/hp4a/sql/honeypot_h4_stats.sql   # mehrfach ausfuehrbar
$M < /tmp/hp4a/sql/honeypot_h6.sql   # Fingerabdruecke (hp_samples_fps), seit H6 Teil der Annahme und der Listen
$M < /tmp/hp4a/sql/honeypot_sensor_country.sql   # Standort des Sensors (api_v2_honeypot.php schreibt hp_sensors.country)
echo "--- Tabellen"; docker exec hp4a-db mysql -uroot -php4atest ipv64 -N -e "SHOW TABLES LIKE 'hp\_%'" | tr '\n' ' '; echo
D=/var/www/clients/client1/web58
docker run -d --name hp4a-php --network hp4a-net -e HP4ATEST=1 -v /tmp/hp4a/web58:$D -v /tmp/hp4a/tests:/w/tests -v /tmp/hp4a/nginx:/w/nginx -w $D/web hp4a-php:latest \
  php -S 0.0.0.0:8080 -t $D/web >/dev/null
sleep 1
for f in $D/web/api_v2_honeypot.php $D/web/api_v2_honeypot_stats.php $D/web/honeypot/stats.php $D/web/honeypot/hp_stats_lib.php $D/web/bots/honeypot_lists.php \
  $D/web/bots/honeypot_lists_index.php $D/web/bots/blocklist/create_blocklists_v2.php /w/tests/run_tests.php; do
  docker exec hp4a-php php -l "$f" | grep -v '^No syntax errors' || true
done
docker exec -e HP4ATEST=1 hp4a-php php /w/tests/run_tests.php http://127.0.0.1:8080 $D/web; rc=$?

echo "nginx (erzeugte map und location-Snippet, Stand vor dem Schwellen-Wechsel)"
docker run -d --name hp4a-nginx --network hp4a-net -v /tmp/hp4a/nginx.conf:/etc/nginx/nginx.conf:ro -v /tmp/hp4a/nginx:/etc/nginx/ipv64:ro $NGX >/dev/null
sleep 1
if docker exec hp4a-nginx nginx -t 2>&1 | grep -q 'test is successful'; then echo "  ok    nginx -t"; else echo "  FEHLER nginx -t"; docker exec hp4a-nginx nginx -t 2>&1 | tail -5; rc=1; fi
docker exec -e HP4ATEST=1 hp4a-php php /w/tests/run_tests.php --nginx http://hp4a-nginx || rc=1

echo "--- Server-Log (Warnungen/Fehler)"; docker logs hp4a-php 2>&1 | grep -iE 'error|warning|notice|deprecated' | head -30 || true
exit $rc
REMOTE
