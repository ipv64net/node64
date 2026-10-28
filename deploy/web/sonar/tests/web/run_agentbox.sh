#!/bin/bash
# Sonar64 Teil W (Seiten unter /sonar): Pruefung in einer abgeschotteten Umgebung auf der Testbox (ssh agentbox).
# Eigene Container/Netz mit Praefix s64w<zufall>, Test-DB mit Test-Passwort, Ordner /tmp/s64-W-<zufall>; am Ende wird
# alles entfernt. Andere Container werden nicht angefasst (c64o-php nur fuer php -l ueber stdin).
#   bash run_agentbox.sh [<pfad/zu/ipv64net_webseite/api_v2.php>]   mit api_v2.php auch die oeffentlichen JSON-Antworten
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SON="$(cd "$HERE/../.." && pwd)"            # deploy/web/sonar
WEB="$(cd "$SON/.." && pwd)"                # deploy/web
SQL="$(cd "$WEB/../sql" && pwd)"            # deploy/sql
API="${1:-}"
RID="$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

R="$STAGE/s64-W-$RID"; W="$R/web58/web"
mkdir -p "$W/sonar/tests/web" "$R/web58/private" "$R/tests/out" "$R/sql"
cp "$SON"/*.php "$SON/sonar.js" "$SON/sonar.css" "$SON/de_map.json" "$W/sonar/"
cp "$HERE/sonar_test.js" "$W/sonar/tests/web/"
cp "$HERE/dbconnect_stub.php" "$W/dbconnect.php"
cp "$HERE/header_stub.php" "$W/header.php"
cp "$HERE/footer_stub.php" "$W/footer.php"
cp "$HERE/run_tests.php" "$HERE/setup.sql" "$R/tests/"
cp "$SQL/sonar64.sql" "$R/sql/"
if [ -n "$API" ] && [ -f "$WEB/api_v2_sonar.php" ]; then
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
fi

ssh agentbox "rm -rf /tmp/s64-W-$RID"
scp -q -r "$R" agentbox:/tmp/

ssh agentbox "RID=$RID bash -s" <<'REMOTE'
set -u
P="s64w$RID"; T="/tmp/s64-W-$RID"; rc=0
cleanup() {
  docker rm -f -v $P-php $P-db >/dev/null 2>&1 || true
  docker network rm $P-net >/dev/null 2>&1 || true
  docker rmi $P-php:latest >/dev/null 2>&1 || true
  rm -rf "$T"
}
trap cleanup EXIT
echo "--- php -l (c64o-php)"
for f in $(cd $T && find web58/web/sonar tests -name '*.php' | sort); do
  out=$(docker exec -i c64o-php php -l < "$T/$f" 2>&1) || { echo "FEHLER $f: $out"; rc=1; }
done
echo "--- node --check und sonar.js-Pruefung ohne API (node:22-alpine)"
docker run --rm -v $T/web58/web/sonar:/s:ro node:22-alpine sh -c 'node --check /s/sonar.js && node --check /s/tests/web/sonar_test.js && node /s/tests/web/sonar_test.js' || rc=1
docker network create $P-net >/dev/null
docker run -d --name $P-db --network $P-net -e MARIADB_ROOT_PASSWORD=s64wtest -e MARIADB_DATABASE=ipv64 mariadb:10.5 >/dev/null
printf 'FROM php:8.3-cli\nRUN docker-php-ext-install pdo_mysql >/dev/null\n' | docker build -q -t $P-php:latest - >/dev/null
for i in $(seq 1 60); do docker exec $P-db mysql -uroot -ps64wtest -e 'SELECT 1' ipv64 >/dev/null 2>&1 && break; sleep 1; done
M="docker exec -i $P-db mysql -uroot -ps64wtest ipv64"
$M < $T/tests/setup.sql
$M < $T/sql/sonar64.sql
chmod -R a+rwX $T
D=/var/www/clients/client1/web58
docker run -d --name $P-php --network $P-net -e S64WTEST=1 -e S64WDB=$P-db -e S64ATEST=1 -e S64ADB=$P-db -v $T/web58:$D -v $T/tests:/w/tests -w $D/web $P-php:latest \
  php -S 0.0.0.0:8080 -t $D/web >/dev/null
sleep 1
docker exec -e S64WTEST=1 -e S64WDB=$P-db $P-php php /w/tests/run_tests.php http://127.0.0.1:8080 $D/web /w/tests/out || rc=1
if ls $T/tests/out/*.json >/dev/null 2>&1; then
  echo "--- sonar.js gegen die echten oeffentlichen Antworten"
  docker run --rm -v $T/web58/web/sonar:/s:ro -v $T/tests/out:/o:ro node:22-alpine node /s/tests/web/sonar_test.js /o || rc=1
fi
echo "--- Server-Log (Warnungen/Fehler)"; docker logs $P-php 2>&1 | grep -iE 'error|warning|notice|deprecated' | head -30 || true
exit $rc
REMOTE
