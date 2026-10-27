#!/bin/bash
# Honeypot64 H4 (DNSBL bl.ipv64.net): Pruefung in einer abgeschotteten Umgebung auf der Testbox (ssh agentbox).
# Eigene Container/Netz mit Praefix hp4b-, Test-Key zufaellig je Lauf; am Ende wird alles entfernt.
# Andere Container auf der Box werden nicht angefasst. Kein Zugriff auf echte Nameserver oder Datenbanken.
#   1. Logik: run_tests.php (SQLite im Speicher, zone_update als Stub) in php:8.3-cli
#   2. echter Abgleich gegen lokalen PowerDNS (powerdns/pdns-auth-49, gsqlite3), Abfragen per sdig
#   bash run_agentbox.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WEB="$(cd "$HERE/../../.." && pwd)"          # deploy/web
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

mkdir -p "$STAGE/hp4b/bots" "$STAGE/hp4b/tests"
cp "$WEB/bots/honeypot_dnsbl.php" "$STAGE/hp4b/bots/"
cp "$HERE/run_tests.php" "$HERE/pdns_test.php" "$STAGE/hp4b/tests/"
ssh agentbox 'rm -rf /tmp/hp4b'
scp -q -r "$STAGE/hp4b" agentbox:/tmp/

ssh agentbox 'bash -s' <<'REMOTE'
set -u
cleanup() {
  docker rm -f -v hp4b-php hp4b-pdns >/dev/null 2>&1 || true
  docker network rm hp4b-net >/dev/null 2>&1 || true
  rm -rf /tmp/hp4b
}
trap cleanup EXIT
FAILS=0
chmod -R a+rwX /tmp/hp4b

echo "=== 1. Logik (Stub, SQLite)"
docker run --rm --name hp4b-php -v /tmp/hp4b:/w -w /w/tests php:8.3-cli sh -c 'php -l /w/bots/honeypot_dnsbl.php && php -l run_tests.php && php -l pdns_test.php && php run_tests.php /w/bots/honeypot_dnsbl.php' || FAILS=$((FAILS+1))

echo "=== 2. Lokaler PowerDNS"
KEY="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
docker network create hp4b-net >/dev/null
docker run -d --name hp4b-pdns --network hp4b-net -e PDNS_AUTH_API_KEY="$KEY" powerdns/pdns-auth-49:latest >/dev/null
docker run -d --name hp4b-php --network hp4b-net -e PDNS_URL=http://hp4b-pdns:8081 -e PDNS_KEY="$KEY" -v /tmp/hp4b:/w -w /w/tests php:8.3-cli sleep 600 >/dev/null
for i in $(seq 1 30); do docker exec hp4b-pdns sdig 127.0.0.1 53 example A >/dev/null 2>&1 && break; sleep 1; done
P() { docker exec hp4b-php php pdns_test.php /w/bots/honeypot_dnsbl.php "$1"; }
Q() { docker exec hp4b-pdns sdig 127.0.0.1 53 "$1" "$2" 2>&1; }
check() { # check <beschreibung> <name> <typ> <grep-muster> [nicht]
  local out; out="$(Q "$2" "$3")"
  if [ "${5:-}" = "nicht" ]; then
    if echo "$out" | grep -Eq "$4"; then echo "  FAIL $1"; echo "$out" | sed 's/^/       /'; FAILS=$((FAILS+1)); else echo "  ok   $1"; fi
  else
    if echo "$out" | grep -Eq "$4"; then echo "  ok   $1"; else echo "  FAIL $1"; echo "$out" | sed 's/^/       /'; FAILS=$((FAILS+1)); fi
  fi
}
names() { docker exec hp4b-pdns pdnsutil list-zone bl.ipv64.net 2>/dev/null | awk '$3=="IN" && $4=="A"{print $1}' | sort -u | wc -l; }
V6=$(printf '%s' "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.f.4.0.1.0.a.2")
T6="2.0.0.0.0.0.f.7.f.f.f.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0"

P create || FAILS=$((FAILS+1))
check "SOA mit kurzen Zeiten" bl.ipv64.net SOA "hostmaster.ipv64.net. [0-9]+ 900 300 604800 300"
echo "--- Lauf 1 (1203 IPs, 3 Bloecke)"
P sync1 || FAILS=$((FAILS+1))
check "Testeintrag 2.0.0.127 -> 127.0.0.2, TTL 300" 2.0.0.127.bl.ipv64.net A "300	IN	A	127.0.0.2"
check "Testeintrag TXT" 2.0.0.127.bl.ipv64.net TXT "RFC 5782"
check "1.0.0.127 nicht gelistet (NXDOMAIN)" 1.0.0.127.bl.ipv64.net A "Rcode: 3"
check "IPv6-Testeintrag ::ffff:7f00:2" "$T6.bl.ipv64.net" A "127.0.0.2"
check "1.2.3.4 -> 127.0.0.2" 4.3.2.1.bl.ipv64.net A "127.0.0.2"
check "1.2.3.4 ohne fruehere Teillisten-Codes (127.0.0.3)" 4.3.2.1.bl.ipv64.net A "127.0.0.3" nicht
check "1.2.3.4 TXT mit Link" 4.3.2.1.bl.ipv64.net TXT "ip.php\?ip=1.2.3.4"
check "5.6.7.8 -> 127.0.0.2" 8.7.6.5.bl.ipv64.net A "127.0.0.2"
check "2a01:4f8::1 -> 127.0.0.2" "$V6.bl.ipv64.net" A "127.0.0.2"
check "9.9.9.9 (nur research) NXDOMAIN" 9.9.9.9.bl.ipv64.net A "Rcode: 3"
check "11.0.4.200 (letzter Block) -> 127.0.0.2" 200.4.0.11.bl.ipv64.net A "127.0.0.2"
N=$(names); if [ "$N" = "1205" ]; then echo "  ok   1205 Namen in der Zone"; else echo "  FAIL Namen in der Zone: $N"; FAILS=$((FAILS+1)); fi
echo "--- Lauf 2 (Differenz: 1 neu, 1 entfernt; nur noch ein Code, darum nichts geaendert)"
OUT="$(P sync2)"; echo "$OUT"
echo "$OUT" | grep -q "neu 1, geaendert 0, entfernt 1" && echo "  ok   Lauf 2: nur die Differenz" || { echo "  FAIL Lauf 2"; FAILS=$((FAILS+1)); }
echo "--- Lauf 3 ohne Aenderung"
OUT="$(P sync2)"; echo "$OUT"
echo "$OUT" | grep -q "neu 0, geaendert 0, entfernt 0" && echo "  ok   Lauf 3: keine Unterschiede" || { echo "  FAIL Lauf 3 schreibt noch"; FAILS=$((FAILS+1)); }
check "5.6.7.8 entfernt (NXDOMAIN)" 8.7.6.5.bl.ipv64.net A "Rcode: 3"
check "5.6.7.8 TXT entfernt" 8.7.6.5.bl.ipv64.net TXT "Rcode: 3"
check "4.4.4.4 neu" 4.4.4.4.bl.ipv64.net A "127.0.0.2"
check "1.2.3.4 weiter 127.0.0.2" 4.3.2.1.bl.ipv64.net A "127.0.0.2"
check "Testeintrag weiter da" 2.0.0.127.bl.ipv64.net A "127.0.0.2"
N=$(names); if [ "$N" = "1205" ]; then echo "  ok   1205 Namen in der Zone"; else echo "  FAIL Namen in der Zone: $N"; FAILS=$((FAILS+1)); fi

echo
if [ "$FAILS" -eq 0 ]; then echo "GESAMT: alles gruen"; else echo "GESAMT: $FAILS Fehler"; fi
exit $FAILS
REMOTE
