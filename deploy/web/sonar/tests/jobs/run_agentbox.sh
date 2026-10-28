#!/bin/bash
# Sonar64 Teil J: Pruefung der Jobs (bots/sonar_*.php) auf der Testbox (ssh agentbox) gegen c64o-db.
# Eigene Datenbank s64jobs_test (nur sonar_*-Tabellen aus deploy/sql/sonar64.sql), damit parallele Tests in "ipv64"
# nicht gestoert werden; am Ende werden Datenbank und Dateien entfernt. Der Zugang bleibt in der Umgebung.
#   bash run_agentbox.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WEB="$(cd "$HERE/../../.." && pwd)"     # deploy/web
SQL="$(cd "$WEB/../sql" && pwd)"        # deploy/sql
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
R="/tmp/s64-j-$(date +%s)-$RANDOM"

mkdir -p "$STAGE/s/web/bots" "$STAGE/s/web/sonar" "$STAGE/s/tests" "$STAGE/s/sql"
for f in sonar_plan sonar_rollup sonar_trust sonar_outages sonar_cleanup honeypot_cron; do cp "$WEB/bots/$f.php" "$STAGE/s/web/bots/"; done
cp "$WEB/sonar/s64_lib.php" "$STAGE/s/web/sonar/"
cp "$HERE/dbconnect_stub.php" "$STAGE/s/web/dbconnect.php"
cp "$HERE/run_tests.php" "$STAGE/s/tests/"
cp "$SQL/sonar64.sql" "$STAGE/s/sql/"

scp -q -r "$STAGE/s" "agentbox:$R"
ssh agentbox "R=$R bash -s" <<'REMOTE'
set -u
# -i nur mit Datei auf stdin (sonst liest docker den Rest dieses Skripts)
DBX() { docker exec c64o-db sh -c 'mysql -uroot -p"$MARIADB_ROOT_PASSWORD" "$@"' sh "$@" </dev/null; }
DBF() { docker exec -i c64o-db sh -c 'mysql -uroot -p"$MARIADB_ROOT_PASSWORD" "$@"' sh "$@"; }
cleanup() { DBX -e 'DROP DATABASE IF EXISTS s64jobs_test' >/dev/null 2>&1 || true; rm -rf "$R"; }
trap cleanup EXIT
DBX -e 'DROP DATABASE IF EXISTS s64jobs_test; CREATE DATABASE s64jobs_test CHARACTER SET utf8mb4'
DBF s64jobs_test < "$R/sql/sonar64.sql"
DBF s64jobs_test < "$R/sql/sonar64.sql"   # mehrfach ausfuehrbar
echo "--- Tabellen: $(DBX -N s64jobs_test -e "SHOW TABLES" | tr '\n' ' ')"
for f in "$R"/web/bots/*.php "$R"/web/sonar/s64_lib.php "$R"/tests/run_tests.php; do
  docker run --rm -v "$R:/w" c64o-php php -l "/w/${f#$R/}" </dev/null | grep -v '^No syntax errors' || true
done
S64J_DBPW="$(docker exec c64o-db printenv MARIADB_ROOT_PASSWORD)" docker run --rm --network c64o -e S64J=1 -e S64J_DBHOST=c64o-db -e S64J_DBPW \
  -v "$R:/w" -w /w/web/bots c64o-php php -d memory_limit=512M /w/tests/run_tests.php "$@" </dev/null
REMOTE
