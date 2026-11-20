#!/bin/sh
# Monitor64-Agent installieren (Linux amd64/arm64/armv6/armv7 - eine Datei fuer 32-Bit-ARM, auch Raspberry Pi Zero/1; FreeBSD, OPNsense, pfSense und TrueNAS CORE amd64/arm64).
# Den Befehl mit dem Schluessel der Node zeigt Node64 im Assistenten "Host hinzufuegen", z. B.:
#
#   curl -fsSL https://node64.de/agent/install.sh | sh -s -- --key "ssh-ed25519 AAAA... node64@nas"
#   fetch -o /tmp/install.sh https://node64.de/agent/install.sh && sh /tmp/install.sh --key "ssh-ed25519 AAAA..."
#
# Optionen: --key "<oeffentlicher Schluessel>" (Pflicht), --port 6465, --base <URL> (Ordner mit den Dateien,
# Standard https://node64.de/agent/; z. B. die eigene Node fuer Hosts ohne Internet).
# --sums-sha256 <hex>: Pruefsumme von SHA256SUMS, wie sie die Node aus ihrem signierten Verzeichnis kennt (steht im
# Befehl des Assistenten "Host hinzufuegen"). Ohne sie bzw. bei Abweichung (neues Release, das die Node noch nicht
# kennt) prueft das Skript die Signatur SHA256SUMS.sig (ed25519, Release-Schluessel wie beim automatischen Update) mit
# OpenSSL ab 3.0; ohne beides nur mit Warnung, bei Abweichung ohne gueltige Signatur Abbruch (AG-2).
# Push-Betrieb (Host hinter NAT, VPS): --connect token@node[:6466] (auch mehrfach, z. B. Cluster) baut die Verbindung
# zur Node selbst auf; --no-listen zusaetzlich, wenn der Agent nicht lauschen soll. Die Ziele landen in
# /etc/monitor64-agent/connect (FreeBSD: /usr/local/etc/monitor64-agent/connect; nur fuer root lesbar), nicht in der
# Befehlszeile des Dienstes.
# Die Datei monitor64-agent-<linux|freebsd>-<arch> wird gegen SHA256SUMS aus demselben Ordner geprueft (SHA256SUMS
# selbst gegen --sums-sha256 bzw. die Signatur) und ruft dann
# "monitor64-agent install" auf (Datei, Schluessel, Dienst - systemd bzw. rc.d -, Fingerabdruck des Hostschluessels).
# Laeuft mit jeder POSIX-Shell (dash, busybox ash, /bin/sh von FreeBSD).
# Entfernen: monitor64-agent uninstall
set -eu

BASE="https://node64.de/agent/"
KEY=""
PORT=""
CONNECT=""
NOLISTEN=""
SUMS=""

# Oeffentlicher Release-Schluessel (ed25519, wie main.ReleaseKeys des Agents) fuer SHA256SUMS.sig
RELEASE_KEY='-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEACKADRKNeeSdwpqmdt9saWJw1i92EQJdsxmQOs6m/iAw=
-----END PUBLIC KEY-----'

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
	--sums-sha256) [ $# -ge 2 ] || die "--sums-sha256 needs a value"; SUMS=$2; shift 2 ;;
	--sums-sha256=*) SUMS=${1#--sums-sha256=}; shift ;;
	-h | --help)
		say 'usage: sh install.sh --key "ssh-ed25519 AAAA... comment" [--port 6465] [--base URL] [--sums-sha256 HEX] [--connect token@node[:6466]] [--no-listen]'
		exit 0
		;;
	*) die "unknown option: $1" ;;
	esac
done

[ -n "$KEY" ] || die '--key is missing (public key of the node, shown in Node64)'
case "$SUMS" in
"") ;;
*[!0-9a-f]*) die "invalid --sums-sha256 (64 hex digits)" ;;
*) [ ${#SUMS} -eq 64 ] || die "invalid --sums-sha256 (64 hex digits)" ;;
esac
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
	[ -n "$SUMS" ] || say "WARNING: downloading over plain HTTP - without --sums-sha256 or a valid signature the checksum only protects against broken downloads, not against tampering. Use HTTPS if possible."
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

# sha256of DATEI: SHA-256 als Hex
sha256of() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{ print $1 }'
	elif command -v sha256 >/dev/null 2>&1; then
		sha256 -q "$1" # FreeBSD
	elif command -v openssl >/dev/null 2>&1; then
		openssl dgst -sha256 "$1" | awk '{ print $NF }'
	else
		die "sha256sum, sha256 or openssl is required"
	fi
}

# verify_sig: Signatur SHA256SUMS.sig pruefen (Release-Schluessel). 0 = gueltig; 1 = nicht pruefbar (keine Signatur,
# kein OpenSSL ab 3.0; Grund in SIGWHY). Eine ungueltige Signatur bricht ab.
SIGWHY=""
verify_sig() {
	if ! download "${BASE}SHA256SUMS.sig" "$TMP/SHA256SUMS.sig" >/dev/null 2>&1; then
		SIGWHY="no signature (${BASE}SHA256SUMS.sig)"
		return 1
	fi
	if ! command -v openssl >/dev/null 2>&1 || ! openssl pkeyutl -help 2>&1 | grep -q rawin; then
		SIGWHY="OpenSSL 3.0 or newer is required to check the signature"
		return 1
	fi
	printf '%s\n' "$RELEASE_KEY" >"$TMP/release.pem"
	openssl base64 -d -A -in "$TMP/SHA256SUMS.sig" -out "$TMP/SHA256SUMS.bin" 2>/dev/null || die "SHA256SUMS.sig is not readable"
	openssl pkeyutl -verify -pubin -inkey "$TMP/release.pem" -rawin -in "$TMP/SHA256SUMS" -sigfile "$TMP/SHA256SUMS.bin" >/dev/null 2>&1 ||
		die "invalid signature of SHA256SUMS - files may have been tampered with"
	return 0
}

# SHA256SUMS absichern (AG-2): mit der Pruefsumme aus dem Befehl der Node (sie kennt das signierte Verzeichnis), sonst
# ueber die Signatur SHA256SUMS.sig. Weicht SHA256SUMS von der Pruefsumme der Node ab (z. B. neues Release, das die
# Node noch nicht geladen hat), entscheidet die Signatur; ohne gueltige Signatur bricht das Skript ab. Ohne
# --sums-sha256 und nicht pruefbar (keine Signatur, kein OpenSSL ab 3.0) nur mit Warnung - dann schuetzt allein HTTPS.
if [ -n "$SUMS" ]; then
	if [ "$(sha256of "$TMP/SHA256SUMS")" = "$SUMS" ]; then
		say "SHA256SUMS confirmed by the node"
	elif verify_sig; then
		say "SHA256SUMS differs from the checksum of the node (newer release?) - signature of SHA256SUMS ok"
	else
		die "SHA256SUMS does not match the checksum from the node (--sums-sha256) and cannot be confirmed by its signature ($SIGWHY). Files may have been tampered with - or the node knows another release: reload the page in Node64 and copy the command again."
	fi
elif verify_sig; then
	say "signature of SHA256SUMS ok"
else
	say "WARNING: $SIGWHY - only the transport protects the download"
fi

WANT=$(awk -v f="$FILE" '$2 == f || $2 == "*" f { print $1; exit }' "$TMP/SHA256SUMS")
[ -n "$WANT" ] || die "$FILE not listed in SHA256SUMS"
GOT=$(sha256of "$TMP/monitor64-agent")
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
