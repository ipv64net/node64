#!/bin/bash
# Sonar64 Ende-zu-Ende (Integration aller Teile) auf der Testbox (ssh agentbox), etwa 35-45 min:
#   echte sonar64-Binaries (Anker, Knoten n1 "auch gemessen", Knoten n2 "nur ausgehend") als Container gegen die
#   API (api_v2_sonar.php im PHP-Builtin-Server), Planer und Jobs; dazu ein gefaelschter Knoten (PHP), der
#   manipulierte Werte meldet. Vertrag 10: ein spaeter gestarteter Knoten n3 ("auch gemessen") misst die Zeit bis zur
#   ersten Messung durch andere (schnelle Aufnahme), tritt dann mit "sonar64 leave" aus; ipv64 meldet n1 ab
#   (bots/sonar_node.php --revoke); zuletzt raeumt sonar_cleanup.php in 31 bzw. 121 Tagen auf.
# Abgeschottet: eigenes internes Docker-Netz s64e<zufall>-net ohne Weg nach aussen. Weil Knoten nur oeffentliche Ziele
# messen und ipv64 nur oeffentliche IPs plant, liegt es in 11.64.64.0/24 (oeffentlicher Bereich, im internen Netz nur
# auf dieser Box sichtbar). Eigene Test-DB (mariadb, Test-Passwort), Ordner /tmp/s64-e2e-<zufall>; am Ende wird alles
# entfernt. Andere Container werden nicht angefasst (c64o-php nur fuer php -l ueber stdin und als PHP-Image).
# Die Knoten sprechen die API ueber eine kleine Weiterleitung auf 127.0.0.1:8080 in ihrem eigenen Netz an (sonar64
# erlaubt http nur zu Loopback); die API sieht so die IP des Knotens.
#   bash run_agentbox.sh <pfad/zu/ipv64net_webseite/api_v2.php>
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WEB="$(cd "$HERE/../../.." && pwd)"         # deploy/web
REPO="$(cd "$WEB/../.." && pwd)"            # ipv64_container
API="${1:?Pfad zu api_v2.php}"
RID="$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

R="$STAGE/s64-e2e-$RID"; W="$R/web58/web"
mkdir -p "$W/sonar" "$W/bots" "$R/web58/private" "$R/tests" "$R/sql" "$R/sec" "$R/src"
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
for f in sonar_keygen sonar_anchor_token sonar_plan sonar_rollup sonar_trust sonar_outages sonar_cleanup sonar_node; do cp "$WEB/bots/$f.php" "$W/bots/"; done
cp "$HERE/dbconnect_stub.php" "$W/dbconnect.php"
cp "$HERE/e2e.php" "$R/tests/"
cp "$HERE/../api/setup.sql" "$R/tests/setup.sql"
cp "$WEB/../sql/sonar64.sql" "$R/sql/"
# Go-Quellen aus dem Arbeitsbaum (Kern + Programm), damit auch noch nicht committete Korrekturen mitlaufen
(cd "$REPO" && tar -cf - go.mod go.sum internal/sonar cmd/sonar64) | tar -xf - -C "$R/src"

ssh agentbox "rm -rf /tmp/s64-e2e-$RID"
scp -q -r "$R" agentbox:/tmp/

ssh agentbox "RID=$RID bash -s" <<'REMOTE'
set -u
P="s64e$RID"; T="/tmp/s64-e2e-$RID"; D=/var/www/clients/client1/web58; NET="$P-net"; FAIL=0; OKS=0; T0=$(date +%s)
cleanup() {
  [ -n "${PLANLOOP:-}" ] && kill $PLANLOOP 2>/dev/null
  docker rm -f -v $P-a_fsn $P-n1 $P-n2 $P-n3 $P-n3l $P-evil $P-api $P-db >/dev/null 2>&1 || true
  docker network rm $NET >/dev/null 2>&1 || true
  rm -rf "$T"
}
trap cleanup EXIT
# Ausgabe zeigen, FEHLER zaehlen
run() { local out; out=$("$@" 2>&1); echo "$out"; case "$out" in *FEHLER*|*"PHP Fatal"*|*"PHP Warning"*|*"PHP Notice"*) FAIL=$((FAIL+1));; esac
  OKS=$((OKS + $(printf '%s\n' "$out" | grep -c '^  ok ' || true))); }
# eigene Pruefungen der Shell (gleiches Format wie e2e.php)
ok() { echo "  ok    $1"; OKS=$((OKS+1)); }
bad() { echo "  FEHLER $1"; FAIL=$((FAIL+1)); }
echo "--- php -l (c64o-php)"
for f in $(cd $T && find . -name '*.php' | sort); do
  out=$(docker exec -i c64o-php php -l < "$T/$f" 2>&1) || { echo "FEHLER $f: $out"; FAIL=$((FAIL+1)); }
done

echo "--- Bauen (sonar64 + Weiterleitung)"
mkdir -p $T/bin $T/fwd
cat > $T/fwd/fwd.go <<'GO'
// Weiterleitung 127.0.0.1:8080 -> API (nur Test): die Verbindung zur API kommt von der IP des Knotens.
package main

import (
	"io"
	"log"
	"net"
	"os"
)

func main() {
	l, err := net.Listen("tcp", os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	for {
		c, err := l.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			u, err := net.Dial("tcp", os.Args[2])
			if err != nil {
				return
			}
			defer u.Close()
			go func() { io.Copy(u, c); u.(*net.TCPConn).CloseWrite() }()
			io.Copy(c, u)
		}(c)
	}
}
GO
docker volume create s64e-gocache >/dev/null
docker run --rm -v $T/src:/src -v $T/bin:/out -v $T/fwd:/fwd -v s64e-gocache:/root/.cache -v s64e-gocache:/go/pkg -w /src -e CGO_ENABLED=0 golang:1.27 \
  sh -c 'go build -trimpath -ldflags "-s -w -X main.Version=0.1.0" -o /out/sonar64 ./cmd/sonar64 && cd /fwd && go build -o /out/fwd fwd.go' || { echo "FEHLER Bauen"; exit 1; }
ls -l $T/bin

echo "--- Netz, Datenbank, API"
docker network create --internal --subnet 11.64.64.0/24 --gateway 11.64.64.1 $NET >/dev/null
docker run -d --name $P-db --network $NET --ip 11.64.64.3 -e MARIADB_ROOT_PASSWORD=s64etest -e MARIADB_DATABASE=ipv64 mariadb:10.5 >/dev/null
for i in $(seq 1 60); do docker exec $P-db mysql -uroot -ps64etest -e 'SELECT 1' ipv64 >/dev/null 2>&1 && break; sleep 1; done
M="docker exec -i $P-db mysql -uroot -ps64etest ipv64"
$M < $T/tests/setup.sql
$M < $T/sql/sonar64.sql
chmod -R a+rwX $T/web58 $T/tests; chmod 700 $T/sec
docker run -d --name $P-api --network $NET --ip 11.64.64.2 -e S64E=1 -e S64E_DB=11.64.64.3 -e PHP_CLI_SERVER_WORKERS=6 \
  -v $T/web58:$D -v $T/tests:/w/tests -v $T/sec:/w/sec -w $D/web c64o-php php -S 0.0.0.0:8080 -t $D/web >/dev/null
sleep 2
PX="docker exec -e S64E=1 -e S64E_DB=11.64.64.3 $P-api php"
E2E="$PX /w/tests/e2e.php"
PLAN="$PX $D/web/bots/sonar_plan.php"
echo "--- setup"; run $E2E setup
PUB="$(cat $T/sec/plan.pub)"
node() { # name ip [docker-Optionen]
  local n=$1 ip=$2; shift 2
  mkdir -p $T/data/$n; chown 65532:65532 $T/data/$n; chmod 700 $T/data/$n
  docker run -d --name $P-$n --network $NET --ip $ip --user 65532:65532 --cap-drop ALL --read-only --security-opt no-new-privileges \
    --sysctl net.ipv4.ping_group_range="0 2147483647" --memory 64m \
    --env-file $T/sec/$n.env -e SONAR64_API=http://127.0.0.1:8080/api_v2.php -e SONAR64_PLAN_KEY="$PUB" -e SONAR64_DATA=/data -e SONAR64_LOG_LEVEL=debug "$@" \
    -v $T/data/$n:/data -v $T/bin:/b:ro alpine:3.22 sh -c '/b/fwd 127.0.0.1:8080 11.64.64.2:8080 & exec /b/sonar64' >/dev/null
}
node a_fsn 11.64.64.10 -e SONAR64_MODE=anchor
node n1 11.64.64.11 -e SONAR64_MEASURED=1 -e SONAR64_STATUS=:8064
node n2 11.64.64.12 -e SONAR64_STATUS=:8064
echo "--- Anmeldung"; run $E2E registered
docker run -d --name $P-evil --network $NET --ip 11.64.64.20 -e S64E=1 -v $T/tests:/w/tests -v $T/sec:/w/sec c64o-php sleep 7200 >/dev/null
echo "--- Faelscher anmelden"; run docker exec -e S64E=1 $P-evil php /w/tests/e2e.php evil1
run $E2E evil-coords
echo "--- Planer 1"; run $PLAN
# danach wie im Betrieb (HPC_JOBS) alle 5 min, solange der Test laeuft
( while sleep 300; do $PLAN >/dev/null 2>&1 || echo "FEHLER Planer im Hintergrund"; done ) &
PLANLOOP=$!
# Plan alle 2 min (Anker jede Minute, Vertrag 10.1): kein Neustart der Knoten mehr noetig
echo "--- Faelscher meldet Manipulation"; run docker exec -e S64E=1 $P-evil php /w/tests/e2e.php evil2
echo "--- warten: Knoten <-> Anker"; run $E2E wait anchors
echo "--- Planer 2"; run $PLAN
docker exec $P-db mysql -uroot -ps64etest ipv64 -e "SELECT node_id, role, measured, reach4, trust FROM sonar_nodes" 2>/dev/null
# schnelle Aufnahme: n3 kommt in das laufende Netz (Planer nur noch im Hintergrund), gemessen ab dem Start
echo "--- n3 starten (schnelle Aufnahme)"; run $E2E mark
node n3 11.64.64.13 -e SONAR64_MEASURED=1
echo "--- warten: n2 -> n1 (udp)"; run $E2E wait pair
echo "--- warten: n3 gemessen"; run $E2E admit
kill $PLANLOOP 2>/dev/null; wait $PLANLOOP 2>/dev/null
echo "--- Planer 3"; run $PLAN
echo "--- Gesamtpruefung"; run $E2E final

echo "--- Abmelden: sonar64 leave (n3), dann ipv64 meldet n1 ab"
run $E2E snap
# wie install.sh --uninstall: Dienst stoppen, dann "sonar64 leave" mit Token und Datenordner
docker stop -t 15 $P-n3 >/dev/null
lout=$(docker run --rm --name $P-n3l --network $NET --ip 11.64.64.14 --user 65532:65532 --cap-drop ALL --read-only --security-opt no-new-privileges \
  --env-file $T/sec/n3.env -e SONAR64_API=http://127.0.0.1:8080/api_v2.php -e SONAR64_PLAN_KEY="$PUB" -e SONAR64_DATA=/data \
  -v $T/data/n3:/data -v $T/bin:/b:ro alpine:3.22 sh -c '/b/fwd 127.0.0.1:8080 11.64.64.2:8080 & sleep 1; /b/sonar64 leave' 2>&1); lrc=$?
echo "$lout" | sed 's/s64_[A-Za-z0-9]*/s64_***/g'
[ $lrc -eq 0 ] && ok "sonar64 leave: Exit 0" || bad "sonar64 leave: Exit $lrc"
case "$lout" in *s64_*) bad "sonar64 leave: Ausgabe enthaelt ein Token";; *) ok "sonar64 leave: kein Token in der Ausgabe";; esac
[ ! -e $T/data/n3/sonar64.key ] && [ ! -e $T/data/n3/sonar64.json ] && ok "sonar64 leave: sonar64.key und sonar64.json geloescht" || bad "sonar64 leave: Dateien noch da: $(ls -A $T/data/n3)"
run $E2E left
run $E2E revoke
run $E2E revoked
[ "$(docker inspect -f '{{.State.Running}} {{.RestartCount}}' $P-n1)" = "true 0" ] && ok "n1: Container laeuft weiter (kein Neustart)" || bad "n1: Container $(docker inspect -f '{{.State.Status}} {{.RestartCount}}' $P-n1)"
echo "--- nach einer Meldungsrunde"; run $E2E after
for n in a_fsn n2; do echo "  $n: $(docker logs $P-$n 2>&1 | grep -c 'not_allowed') Meldungen mit not_allowed"; done
docker logs $P-n1 2>&1 | grep -q 'signed off by ipv64' && ok "n1: Log meldet die Abmeldung" || bad "n1: keine Abmeldung im Log"

echo "--- Aufraeumen (sonar_cleanup.php in 31 / 121 Tagen)"; run $E2E cleanup

echo "--- Knoten-Logs (Warnungen/Fehler)"
for n in a_fsn n1 n2 n3; do
  l=$(docker logs $P-$n 2>&1 | grep -E 'level=(WARN|ERROR)' | grep -v 'only for tests\|SONAR64_API is set\|plan key from SONAR64_PLAN_KEY' | head -10)
  [ -n "$l" ] && echo "$n: $l"
  docker logs $P-$n 2>&1 | grep -q 'plan rejected' && { echo "FEHLER $n: plan rejected"; FAIL=$((FAIL+1)); }
done
docker stats --no-stream --format '{{.Name}} {{.MemUsage}} {{.CPUPerc}}' $P-a_fsn $P-n1 $P-n2
echo "--- Server-Log (Warnungen/Fehler)"; docker logs $P-api 2>&1 | grep -iE 'error|warning|notice|deprecated' | head -30 || true
echo "=== Ende-zu-Ende: $OKS Pruefungen ok, $FAIL Abschnitte mit Fehlern, Laufzeit $(( ($(date +%s) - T0) / 60 )) min"
docker volume rm s64e-gocache >/dev/null 2>&1 || true
exit $FAIL
REMOTE
