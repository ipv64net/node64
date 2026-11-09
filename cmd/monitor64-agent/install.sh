#!/bin/sh
# Monitor64-Agent installieren (Linux amd64/arm64/armv7). Den Befehl mit dem Schluessel der Node zeigt Node64 im
# Assistenten "Host hinzufuegen", z. B.:
#
#   curl -fsSL https://node64.de/agent/install.sh | sh -s -- --key "ssh-ed25519 AAAA... node64@nas"
#
# Optionen: --key "<oeffentlicher Schluessel>" (Pflicht), --port 6465, --base <URL> (Ordner mit den Dateien,
# Standard https://node64.de/agent/; z. B. die eigene Node fuer Hosts ohne Internet).
# Die Datei monitor64-agent-linux-<arch> wird gegen SHA256SUMS aus demselben Ordner geprueft und ruft dann
# "monitor64-agent install" auf (Datei, Schluessel, systemd-Dienst, Fingerabdruck des Hostschluessels).
# Entfernen: monitor64-agent uninstall
set -eu

BASE="https://node64.de/agent/"
KEY=""
PORT=""

say() { printf '%s\n' "monitor64-agent: $*"; }
die() { printf '%s\n' "monitor64-agent: ERROR: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
	case "$1" in
	--key) [ $# -ge 2 ] || die "--key needs a value"; KEY=$2; shift 2 ;;
	--key=*) KEY=${1#--key=}; shift ;;
	--port) [ $# -ge 2 ] || die "--port needs a value"; PORT=$2; shift 2 ;;
	--port=*) PORT=${1#--port=}; shift ;;
	--base) [ $# -ge 2 ] || die "--base needs a value"; BASE=$2; shift 2 ;;
	--base=*) BASE=${1#--base=}; shift ;;
	-h | --help)
		say 'usage: sh install.sh --key "ssh-ed25519 AAAA... comment" [--port 6465] [--base URL]'
		exit 0
		;;
	*) die "unknown option: $1" ;;
	esac
done

[ -n "$KEY" ] || die '--key is missing (public key of the node, shown in Node64)'
case "$PORT" in
"" | [0-9] | [0-9][0-9] | [0-9][0-9][0-9] | [0-9][0-9][0-9][0-9] | [0-9][0-9][0-9][0-9][0-9]) ;;
*) die "invalid port: $PORT" ;;
esac
[ "$(id -u)" = 0 ] || die "please run as root (sudo sh -s -- ...)"
[ "$(uname -s)" = Linux ] || die "only Linux is supported by this script"

case "$(uname -m)" in
x86_64 | amd64) ARCH=amd64 ;;
aarch64 | arm64) ARCH=arm64 ;;
armv7* | armv8l | armhf) ARCH=armv7 ;;
*) die "unsupported architecture: $(uname -m)" ;;
esac
FILE="monitor64-agent-linux-$ARCH"

case "$BASE" in
https://*) ;;
http://*) say "WARNING: downloading over plain HTTP - the checksum only protects against broken downloads, not against tampering. Use HTTPS if possible." ;;
*) die "--base must start with https:// or http://" ;;
esac
case "$BASE" in */) ;; *) BASE="$BASE/" ;; esac

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM

fetch() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --proto '=https,http' -o "$2" "$1"
	elif command -v wget >/dev/null 2>&1; then
		wget -q -O "$2" "$1"
	else
		die "curl or wget is required"
	fi
}

say "downloading $BASE$FILE"
fetch "$BASE$FILE" "$TMP/monitor64-agent" || die "download failed: $BASE$FILE"
fetch "${BASE}SHA256SUMS" "$TMP/SHA256SUMS" || die "download failed: ${BASE}SHA256SUMS"

WANT=$(awk -v f="$FILE" '$2 == f || $2 == "*" f { print $1; exit }' "$TMP/SHA256SUMS")
[ -n "$WANT" ] || die "$FILE not listed in SHA256SUMS"
if command -v sha256sum >/dev/null 2>&1; then
	GOT=$(sha256sum "$TMP/monitor64-agent" | awk '{ print $1 }')
elif command -v openssl >/dev/null 2>&1; then
	GOT=$(openssl dgst -sha256 "$TMP/monitor64-agent" | awk '{ print $NF }')
else
	die "sha256sum or openssl is required"
fi
[ "$GOT" = "$WANT" ] || die "checksum mismatch for $FILE (expected $WANT, got $GOT)"
say "checksum ok"

chmod 755 "$TMP/monitor64-agent"
if [ -n "$PORT" ]; then
	"$TMP/monitor64-agent" install --key "$KEY" --port "$PORT"
else
	"$TMP/monitor64-agent" install --key "$KEY"
fi
