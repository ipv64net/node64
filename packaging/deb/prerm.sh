#!/bin/sh
# Paket node64: Dienst vor dem Entfernen stoppen (bei einem Update startet postinst ihn neu). Aktiviert bzw.
# deaktiviert bleibt er wie vom Admin eingestellt (gilt wieder nach erneuter Installation); "purge" raeumt das auf.
set -e

case "$1" in
remove|deconfigure)
	if [ -d /run/systemd/system ]; then
		systemctl stop node64.service >/dev/null 2>&1 || true
	fi
	;;
esac
exit 0
