#!/bin/sh
# Sonar64 ohne Docker installieren (Raspberry Pi Zero/1/2/3/4/5, beliebiges Linux mit systemd).
# Anleitung: docs/SONAR64.md. Aufruf als root:
#
#   sudo sh install.sh                 neueste Version installieren bzw. aktualisieren (fragt nach dem Token)
#   sudo SONAR64_TOKEN=s64_... sh install.sh
#   sudo sh install.sh --uninstall     Dienst und Programm entfernen (Einstellung und Schluessel bleiben)
#   sudo sh install.sh --purge         zusaetzlich /etc/sonar64.env und /var/lib/sonar64 loeschen
#
# Variablen: SONAR64_VERSION (z. B. 0.1.0, Standard: neueste), SONAR64_TOKEN, SONAR64_MEASURED (0/1),
# SONAR64_BUDGET (sparsam|normal|grosszuegig), SONAR64_QUIET (z. B. 23-6). Nur Tests: SONAR64_SRC_DIR (Ordner mit
# den Release-Dateien statt Download).
#
# Das Programm kommt aus den GitHub-Releases von ipv64net/node64 (Tag sonar64-v<version>) und wird gegen SHA256SUMS
# geprueft. Es laeuft als eigener Nutzer sonar64 mit nur CAP_NET_RAW (systemd-Haertung, MemoryMax=64M).
set -eu

REPO="ipv64net/node64"
BIN=/usr/local/bin/sonar64
UNIT=/etc/systemd/system/sonar64.service
ENVF=/etc/sonar64.env
DATA=/var/lib/sonar64
USR=sonar64

say() { printf '%s\n' "sonar64: $*"; }
die() { printf '%s\n' "sonar64: ERROR: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "please run as root (sudo sh install.sh)"
command -v systemctl >/dev/null 2>&1 || die "systemd is required (use the Docker image otherwise)"

# ---- entfernen
case "${1:-}" in
--uninstall | --purge)
	systemctl disable --now sonar64.service 2>/dev/null || true
	rm -f "$UNIT" "$BIN"
	systemctl daemon-reload
	if [ "$1" = --purge ]; then
		rm -f "$ENVF"
		rm -rf "$DATA" /var/lib/private/sonar64
		say "removed (including settings, key and node ID)"
	else
		say "removed (settings $ENVF and key in $DATA kept)"
	fi
	exit 0
	;;
"") ;;
*) die "unknown option $1 (--uninstall, --purge)" ;;
esac

# ---- Architektur
case "$(uname -m)" in
armv6l) ARCH=armv6 ;;
armv7l | armv8l) ARCH=armv7 ;;
aarch64 | arm64) ARCH=arm64 ;;
x86_64 | amd64) ARCH=amd64 ;;
*) die "unsupported architecture $(uname -m) (armv6l, armv7l, aarch64, x86_64)" ;;
esac
ASSET="sonar64-linux-$ARCH"

# ---- Werkzeuge
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is missing"
if command -v curl >/dev/null 2>&1; then
	fetch() { curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
	fetch() { wget -q -O "$2" "$1"; }
else
	fetch() { die "curl or wget is required"; }
fi

TMP=$(mktemp -d /var/tmp/sonar64.XXXXXX 2>/dev/null || mktemp -d)
cleanup() { rm -rf "$TMP"; [ -z "${ECHO_OFF:-}" ] || stty echo 2>/dev/null </dev/tty || true; }
trap cleanup EXIT
trap 'exit 1' INT TERM

# ---- Version
VER="${SONAR64_VERSION:-}"
if [ -n "${SONAR64_SRC_DIR:-}" ]; then
	[ -d "$SONAR64_SRC_DIR" ] || die "SONAR64_SRC_DIR is not a directory"
	VER="${VER:-local}"
elif [ -z "$VER" ]; then
	fetch "https://api.github.com/repos/$REPO/releases?per_page=50" "$TMP/releases.json" || die "cannot list releases"
	VER=$(grep -o '"tag_name": *"sonar64-v[^"]*"' "$TMP/releases.json" | head -n 1 | sed 's/.*"sonar64-v\([^"]*\)"/\1/')
	[ -n "$VER" ] || die "no sonar64 release found"
fi
VER="${VER#sonar64-v}"
VER="${VER#v}"
printf '%s' "$VER" | grep -Eq '^[0-9A-Za-z][0-9A-Za-z.+-]{0,40}$' || die "invalid version"

# ---- laden und pruefen
get() { # get <datei>
	if [ -n "${SONAR64_SRC_DIR:-}" ]; then
		cp "$SONAR64_SRC_DIR/$1" "$TMP/$1" || die "missing $1 in SONAR64_SRC_DIR"
	else
		fetch "https://github.com/$REPO/releases/download/sonar64-v$VER/$1" "$TMP/$1" || die "download of $1 failed"
	fi
}
say "installing version $VER for $ARCH"
get SHA256SUMS
get "$ASSET"
get sonar64.service
for f in "$ASSET" sonar64.service; do
	want=$(awk -v f="$f" '$2 == f || $2 == "*" f { print $1; exit }' "$TMP/SHA256SUMS")
	printf '%s' "$want" | grep -Eq '^[0-9a-f]{64}$' || die "no checksum for $f in SHA256SUMS"
	have=$(sha256sum "$TMP/$f" | awk '{ print $1 }')
	[ "$want" = "$have" ] || die "checksum mismatch for $f - not installed"
done
say "checksums ok"
chmod 0755 "$TMP/$ASSET"
"$TMP/$ASSET" version >/dev/null 2>&1 || die "the program does not start on this system (wrong architecture or $TMP mounted noexec?)"

# ---- Einstellung (/etc/sonar64.env, 0600, root)
TOKEN="${SONAR64_TOKEN:-}"
if [ -z "$TOKEN" ] && ! grep -q '^SONAR64_TOKEN=s64a\{0,1\}_' "$ENVF" 2>/dev/null; then
	if (: </dev/tty) 2>/dev/null; then
		printf 'Sonar token (s64_..., from ipv64.net "My node"; input hidden): ' >/dev/tty
		ECHO_OFF=1
		stty -echo </dev/tty
		IFS= read -r TOKEN </dev/tty || TOKEN=""
		stty echo </dev/tty
		ECHO_OFF=
		printf '\n' >/dev/tty
	else
		die "SONAR64_TOKEN is not set and there is no terminal to ask"
	fi
fi
TOKEN=$(printf '%s' "$TOKEN" | tr -d ' \r\n\t')
if [ -n "$TOKEN" ]; then
	printf '%s' "$TOKEN" | grep -Eq '^s64a?_[A-Za-z0-9]{40}$' || die "the token has an invalid format (s64_ + 40 letters/digits)"
fi
opt() { # opt <name> <muster>: Wert aus der Umgebung pruefen
	eval "v=\${$1:-}"
	[ -z "$v" ] && return 0
	printf '%s' "$v" | grep -Eq "$2" || die "$1 is invalid"
	printf '%s=%s\n' "$1" "$v"
}
NEW="$TMP/sonar64.env"
umask 077
{
	if [ -n "$TOKEN" ]; then
		printf 'SONAR64_TOKEN=%s\n' "$TOKEN"
	elif [ -f "$ENVF" ]; then
		grep '^SONAR64_TOKEN=' "$ENVF" | head -n 1
	fi
	opt SONAR64_MEASURED '^[01]$'
	opt SONAR64_BUDGET '^(sparsam|normal|grosszuegig)$'
	opt SONAR64_QUIET '^[0-9]{1,2}-[0-9]{1,2}$'
	# alle uebrigen Zeilen der alten Datei behalten, ausser den hier neu gesetzten
	if [ -f "$ENVF" ]; then
		grep -v -e '^SONAR64_TOKEN=' \
			${SONAR64_MEASURED:+-e '^SONAR64_MEASURED='} \
			${SONAR64_BUDGET:+-e '^SONAR64_BUDGET='} \
			${SONAR64_QUIET:+-e '^SONAR64_QUIET='} "$ENVF" || true
	else
		printf '%s\n' '# Sonar64 - see docs/SONAR64.md' '#SONAR64_MEASURED=0' '#SONAR64_BUDGET=sparsam' \
			'#SONAR64_QUIET=23-6' '#SONAR64_STATUS=127.0.0.1:8064' '#SONAR64_LOG_LEVEL=info'
	fi
} >"$NEW"
grep -q '^SONAR64_TOKEN=s64a\{0,1\}_' "$NEW" || die "no token in the settings"
install -m 0600 -o root -g root "$NEW" "$ENVF"

# ---- Nutzer
if ! id "$USR" >/dev/null 2>&1; then
	NOLOGIN=$(command -v nologin || echo /bin/false)
	if command -v useradd >/dev/null 2>&1; then
		useradd --system --no-create-home --home-dir "$DATA" --shell "$NOLOGIN" "$USR"
	elif command -v adduser >/dev/null 2>&1; then
		adduser -S -D -H -h "$DATA" -s "$NOLOGIN" "$USR"
	else
		die "cannot create user $USR (no useradd/adduser)"
	fi
	say "user $USR created"
fi

# ---- Programm und Dienst
if systemctl is-active --quiet sonar64.service; then
	systemctl stop sonar64.service
fi
install -m 0755 -o root -g root "$TMP/$ASSET" "$BIN"
install -m 0644 -o root -g root "$TMP/sonar64.service" "$UNIT"
systemctl daemon-reload
systemctl enable sonar64.service >/dev/null 2>&1
systemctl restart sonar64.service
say "installed: $("$BIN" version)"
say "status: systemctl status sonar64   log: journalctl -u sonar64 -f"
say "set name, location and access type on ipv64.net (\"My node\")"
