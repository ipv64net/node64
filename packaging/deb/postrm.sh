#!/bin/sh
# Paket node64: Die Daten in /var/lib/node64 bleiben auch bei "purge" erhalten (Datenbank, Zertifikate, Schluessel) -
# wer sie nicht mehr braucht, loescht den Ordner selbst. Der Systembenutzer wird bei "purge" entfernt.
set -e

case "$1" in
remove)
	if [ -d /run/systemd/system ]; then
		systemctl daemon-reload >/dev/null 2>&1 || true
	fi
	;;
purge)
	if getent passwd node64 >/dev/null 2>&1; then
		deluser --system node64 >/dev/null 2>&1 || true
	fi
	echo "Die Daten von Node64 liegen weiter in /var/lib/node64 - bei Bedarf selbst loeschen."
	;;
esac
exit 0
