#!/bin/bash
# Sonar64 Teil A (API ipv64): Pruefung in einer abgeschotteten Umgebung auf der Testbox (ssh agentbox).
# Eigene Container/Netz mit Praefix s64a<zufall>, Test-DB mit Test-Passwort, Ordner /tmp/s64-A-<zufall>; am Ende wird
# alles entfernt. Andere Container auf der Box werden nicht angefasst (c64o-php nur fuer php -l ueber stdin).
# Webroot wie live unter /var/www/clients/client1/web58/web (Plan-Schluessel liegt darueber in private/sonar64).
#   bash run_agentbox.sh <pfad/zu/ipv64net_webseite/api_v2.php>
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WEB="$(cd "$HERE/../../.." && pwd)"         # deploy/web
SQL="$(cd "$WEB/../sql" && pwd)"            # deploy/sql
API="${1:?Pfad zu api_v2.php}"
RID="$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

R="$STAGE/s64-A-$RID"; W="$R/web58/web"
mkdir -p "$W/sonar" "$W/bots" "$R/web58/private" "$R/tests" "$R/sql"
# echte api_v2.php mit der live vorhandenen require-Zeile (api_v2_honeypot.php bindet api_v2_sonar.php ein)
cat > "$STAGE/patch.py" <<'PY'
import sys
s = open(sys.argv[1], encoding="utf-8").read().replace("\r\n", "\n")
n = "// ===================================================================\n//  Start\n"
p = s.rfind(n)
assert p >= 0, "Start-Block nicht gefunden"
sys.stdout.write(s[:p] + "require __DIR__ . '/api_v2_honeypot.php';\n\n" + s[p:])
PY
python "$STAGE/patch.py" "$API" > "$W/api_v2.php"
cp "$WEB/api_v2_honeypot.php" "$WEB/api_v2_sonar.php" "$W/"
cp "$WEB/sonar/s64_lib.php" "$W/sonar/"
cp "$WEB/bots/sonar_keygen.php" "$WEB/bots/sonar_anchor_token.php" "$WEB/bots/sonar_node.php" "$W/bots/"
cp "$HERE/dbconnect_stub.php" "$W/dbconnect.php"
cp "$HERE/run_tests.php" "$HERE/setup.sql" "$R/tests/"
cp "$SQL/sonar64.sql" "$R/sql/"

ssh agentbox "rm -rf /tmp/s64-A-$RID"
scp -q -r "$R" agentbox:/tmp/

ssh agentbox "RID=$RID bash -s" <<'REMOTE'
set -u
P="s64a$RID"; T="/tmp/s64-A-$RID"
cleanup() {
  docker rm -f -v $P-php $P-db >/dev/null 2>&1 || true
  docker network rm $P-net >/dev/null 2>&1 || true
  rm -rf "$T"
}
trap cleanup EXIT
echo "--- php -l (c64o-php)"
if docker inspect c64o-php >/dev/null 2>&1; then
  for f in $(cd $T && find . -name '*.php' | sort); do
    out=$(docker exec -i c64o-php php -l < "$T/$f" 2>&1) || echo "FEHLER $f: $out"
  done
fi
docker network create $P-net >/dev/null
docker run -d --name $P-db --network $P-net -e MARIADB_ROOT_PASSWORD=s64atest -e MARIADB_DATABASE=ipv64 mariadb:10.5 >/dev/null
printf 'FROM php:8.3-cli\nRUN docker-php-ext-install pdo_mysql >/dev/null\n' | docker build -q -t s64a-php:latest - >/dev/null
for i in $(seq 1 60); do docker exec $P-db mysql -uroot -ps64atest -e 'SELECT 1' ipv64 >/dev/null 2>&1 && break; sleep 1; done
M="docker exec -i $P-db mysql -uroot -ps64atest ipv64"
$M < $T/tests/setup.sql
$M < $T/sql/sonar64.sql
$M < $T/sql/sonar64.sql   # mehrfach ausfuehrbar
echo "--- Tabellen"; docker exec $P-db mysql -uroot -ps64atest ipv64 -N -e "SHOW TABLES LIKE 'sonar\_%'" | tr '\n' ' '; echo
chmod -R a+rwX $T
D=/var/www/clients/client1/web58
docker run -d --name $P-php --network $P-net -e S64ATEST=1 -e S64ADB=$P-db -v $T/web58:$D -v $T/tests:/w/tests -w $D/web s64a-php:latest \
  php -S 0.0.0.0:8080 -t $D/web >/dev/null
sleep 1
docker exec -e S64ATEST=1 -e S64ADB=$P-db $P-php php /w/tests/run_tests.php http://127.0.0.1:8080 $D/web; rc=$?
echo "--- Server-Log (Warnungen/Fehler)"; docker logs $P-php 2>&1 | grep -iE 'error|warning|notice|deprecated' | head -30 || true
exit $rc
REMOTE
