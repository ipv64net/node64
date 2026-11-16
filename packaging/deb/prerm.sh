#!/bin/sh
# Paket node64: Dienst vor dem Entfernen stoppen (bei einem Update startet postinst ihn neu).
set -e

case "$1" in
remove|deconfigure)
	if [ -d /run/systemd/system ]; then
		systemctl stop node64.service >/dev/null 2>&1 || true
		systemctl disable node64.service >/dev/null 2>&1 || true
	fi
	;;
esac
exit 0
