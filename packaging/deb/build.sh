#!/bin/sh
# Debian-Paket fuer Node64 mit dpkg-deb bauen (keine weiteren Werkzeuge noetig).
#   sh packaging/deb/build.sh <version> <deb-arch> <programm> <ausgabe-ordner>
#   z. B. sh packaging/deb/build.sh 1.7.5 amd64 dist/1.7.5/node64-linux-amd64 dist/deb
# deb-arch: amd64, arm64, armhf (Programm node64-linux-armv7). Ergebnis: <ausgabe>/node64_<version>_<arch>.deb
set -eu

VERSION=$1
ARCH=$2
BIN=$3
OUT=$4
HERE=$(cd "$(dirname "$0")" && pwd)

case "$ARCH" in amd64 | arm64 | armhf) ;; *) echo "unknown arch: $ARCH" >&2; exit 1 ;; esac
[ -f "$BIN" ] || { echo "missing binary: $BIN" >&2; exit 1; }

ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT
chmod 0755 "$ROOT" # mktemp legt 0700 an - das waere sonst die Wurzel im Paket
install -d -m 0755 "$ROOT/DEBIAN" "$ROOT/usr/bin" "$ROOT/lib/systemd/system" "$ROOT/etc/default" "$ROOT/usr/share/doc/node64"
install -m 0755 "$BIN" "$ROOT/usr/bin/node64"
install -m 0644 "$HERE/node64.service" "$ROOT/lib/systemd/system/node64.service"
install -m 0644 "$HERE/node64.default" "$ROOT/etc/default/node64"
install -m 0755 "$HERE/postinst.sh" "$ROOT/DEBIAN/postinst"
install -m 0755 "$HERE/prerm.sh" "$ROOT/DEBIAN/prerm"
install -m 0755 "$HERE/postrm.sh" "$ROOT/DEBIAN/postrm"
printf '/etc/default/node64\n' >"$ROOT/DEBIAN/conffiles"
printf 'Node64 von ipv64.net - https://node64.de\nLizenz: Apache-2.0, siehe https://github.com/ipv64net/node64/blob/main/LICENSE\n' >"$ROOT/usr/share/doc/node64/copyright"

SIZE=$(du -sk "$ROOT" | cut -f1)
cat >"$ROOT/DEBIAN/control" <<EOF
Package: node64
Version: $VERSION
Architecture: $ARCH
Maintainer: ipv64.net <info@ipv64.net>
Installed-Size: $SIZE
Depends: adduser, ca-certificates
Recommends: systemd
Section: net
Priority: optional
Homepage: https://node64.de
Description: Node64 von ipv64.net fuer das Heimnetz
 Healthchecks, DNS64 (DNS-Filter, DHCP, lokaler DNS), PROXY64 (Reverse Proxy mit
 CDN64), Monitor64, IPAM64, DynDNS, Zertifikate und Honeypot64 in einem Programm,
 mit Weboberflaeche auf Port 8080. Laeuft als Dienst "node64" unter einem eigenen
 Systembenutzer; Daten in /var/lib/node64, Einstellungen in /etc/default/node64.
EOF

mkdir -p "$OUT"
dpkg-deb --root-owner-group -Zxz --build "$ROOT" "$OUT/node64_${VERSION}_${ARCH}.deb" >/dev/null
echo "$OUT/node64_${VERSION}_${ARCH}.deb"
