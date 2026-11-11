#!/bin/sh
# Monitor64-Agent installieren (Linux amd64/arm64/armv6/armv7 - eine Datei fuer 32-Bit-ARM, auch Raspberry Pi Zero/1; FreeBSD, OPNsense, pfSense und TrueNAS CORE amd64/arm64).
# Den Befehl mit dem Schluessel der Node zeigt Node64 im Assistenten "Host hinzufuegen", z. B.:
#
#   curl -fsSL https://node64.de/agent/install.sh | sh -s -- --key "ssh-ed25519 AAAA... node64@nas"
#   fetch -o /tmp/install.sh https://node64.de/agent/install.sh && sh /tmp/install.sh --key "ssh-ed25519 AAAA..."
#
# Optionen: --key "<oeffentlicher Schluessel>" (Pflicht), --port 6465, --base <URL> (Ordner mit den Dateien,
# Standard https://node64.de/agent/; z. B. die eigene Node fuer Hosts ohne Internet).
# Push-Betrieb (Host hinter NAT, VPS): --connect token@node[:6466] (auch mehrfach, z. B. Cluster) baut die Verbindung
# zur Node selbst auf; --no-listen zusaetzlich, wenn der Agent nicht lauschen soll. Die Ziele landen in
# /etc/monitor64-agent/connect (FreeBSD: /usr/local/etc/monitor64-agent/connect; nur fuer root lesbar), nicht in der
# Befehlszeile des Dienstes.
# Die Datei monitor64-agent-<linux|freebsd>-<arch> wird gegen SHA256SUMS aus demselben Ordner geprueft und ruft dann
# "monitor64-agent install" auf (Datei, Schluessel, Dienst - systemd bzw. rc.d -, Fingerabdruck des Hostschluessels).
# Laeuft mit jeder POSIX-Shell (dash, busybox ash, /bin/sh von FreeBSD).
# Entfernen: monitor64-agent uninstall
set -eu

BASE="https://node64.de/agent/"
KEY=""
PORT=""
CONNECT=""
NOLISTEN=""

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
	--connect) [ $# -ge 2 ] || die "--connect needs a value"; CONNECT="$CONNECT $2"; shift 2 ;;
	--connect=*) CONNECT="$CONNECT ${1#--connect=}"; shift ;;
	--no-listen) NOLISTEN=1; shift ;;
	-h | --help)
		say 'usage: sh install.sh --key "ssh-ed25519 AAAA... comment" [--port 6465] [--base URL] [--connect token@node[:6466]] [--no-listen]'
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
# --connect: nur Zeichen aus token@host:port (IPv6 in Klammern); genaue Pruefung macht "monitor64-agent install".
for c in $CONNECT; do
	case "$c" in
	*@*) ;;
	*) die "--connect expects token@host[:port]: $c" ;;
	esac
	case "$c" in
	*[!]a-z0-9A-Z@.:_[-]*) die "invalid --connect value: $c" ;;
	esac
done
[ -z "$NOLISTEN" ] || [ -n "$CONNECT" ] || die "--no-listen needs --connect token@node[:port]"
[ "$(id -u)" = 0 ] || die "please run as root (sudo sh -s -- ...)"
# LIB ist der Programmordner, den "monitor64-agent install" anlegt (Download dorthin, siehe unten).
case "$(uname -s)" in
Linux)
	OS=linux
	LIB=/usr/local/lib/monitor64-agent
	;;
FreeBSD)
	OS=freebsd
	LIB=/usr/local/libexec/monitor64-agent
	;;
*) die "only Linux and FreeBSD are supported by this script (Windows: install.ps1)" ;;
esac

case "$(uname -m)" in
x86_64 | amd64) ARCH=amd64 ;;
aarch64 | arm64) ARCH=arm64 ;;
armv6* | armv7* | armv8l | armhf) ARCH=armv7 ;; # die armv7-Datei ist fuer ARMv6 gebaut und laeuft auf beiden
*) die "unsupported architecture: $(uname -m)" ;;
esac
[ "$OS-$ARCH" != freebsd-armv7 ] || die "unsupported architecture on FreeBSD: $(uname -m)"
FILE="monitor64-agent-$OS-$ARCH"

# Bei HTTPS keine Umleitung auf HTTP (sonst koennte jemand Datei und SHA256SUMS gemeinsam austauschen).
case "$BASE" in
https://*) PROTO='=https' ;;
http://*)
	PROTO='=http,https'
	say "WARNING: downloading over plain HTTP - the checksum only protects against broken downloads, not against tampering. Use HTTPS if possible."
	;;
*) die "--base must start with https:// or http://" ;;
esac
case "$BASE" in */) ;; *) BASE="$BASE/" ;; esac

# Nicht unter /tmp ablegen (oft noexec): Download in den Programmordner, sonst /var/tmp.
TMP=""
if mkdir -p "$LIB" 2>/dev/null && chmod 755 "$LIB"; then
	TMP=$(mktemp -d "$LIB/.download.XXXXXX" 2>/dev/null) || TMP=""
fi
[ -n "$TMP" ] || TMP=$(mktemp -d /var/tmp/monitor64-agent.XXXXXX) || die "no directory for the download"
trap 'rm -rf "$TMP"' EXIT
trap 'exit 1' INT TERM

# download URL DATEI: Zeitlimits (curl: Verbindung 10 s, gesamt 300 s; wget und fetch: 10 s ohne Daten), bei HTTPS
# keine Umleitung auf HTTP. FreeBSD hat ohne Pakete nur fetch(1).
download() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --connect-timeout 10 --max-time 300 --proto "$PROTO" --proto-redir "$PROTO" -o "$2" "$1"
	elif command -v wget >/dev/null 2>&1; then
		# wget kennt keine Sperre fuer Umleitungen: Kopfzeilen mitlesen und Umleitung auf http:// ablehnen.
		wget -S -T 10 -t 2 -O "$2" "$1" 2>"$TMP/wget.log" || return 1
		if [ "$PROTO" = '=https' ] && grep -qi '^ *location: *http:' "$TMP/wget.log"; then
			say "redirect to plain HTTP refused"
			return 1
		fi
	elif command -v fetch >/dev/null 2>&1; then
		# fetch folgt jeder Umleitung: mit -v mitlesen ("301 redirect to http://...") und http:// ablehnen.
		fetch -v -T 10 -o "$2" "$1" 2>"$TMP/fetch.log" || return 1
		if [ "$PROTO" = '=https' ] && grep -qi 'redirect to http:' "$TMP/fetch.log"; then
			say "redirect to plain HTTP refused"
			return 1
		fi
	else
		die "curl, wget or fetch is required"
	fi
}

say "downloading $BASE$FILE"
download "$BASE$FILE" "$TMP/monitor64-agent" || die "download failed: $BASE$FILE"
download "${BASE}SHA256SUMS" "$TMP/SHA256SUMS" || die "download failed: ${BASE}SHA256SUMS"

WANT=$(awk -v f="$FILE" '$2 == f || $2 == "*" f { print $1; exit }' "$TMP/SHA256SUMS")
[ -n "$WANT" ] || die "$FILE not listed in SHA256SUMS"
if command -v sha256sum >/dev/null 2>&1; then
	GOT=$(sha256sum "$TMP/monitor64-agent" | awk '{ print $1 }')
elif command -v sha256 >/dev/null 2>&1; then
	GOT=$(sha256 -q "$TMP/monitor64-agent") # FreeBSD
elif command -v openssl >/dev/null 2>&1; then
	GOT=$(openssl dgst -sha256 "$TMP/monitor64-agent" | awk '{ print $NF }')
else
	die "sha256sum, sha256 or openssl is required"
fi
[ "$GOT" = "$WANT" ] || die "checksum mismatch for $FILE (expected $WANT, got $GOT)"
say "checksum ok"

chmod 755 "$TMP/monitor64-agent"
set -f # [2001:db8::1] nicht als Dateimuster auswerten
set -- install --key "$KEY"
if [ -n "$PORT" ]; then
	set -- "$@" --port "$PORT"
fi
for c in $CONNECT; do
	set -- "$@" --connect "$c"
done
if [ -n "$NOLISTEN" ]; then
	set -- "$@" --no-listen
fi
"$TMP/monitor64-agent" "$@"
