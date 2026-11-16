#!/bin/sh
# Paket node64: Systembenutzer anlegen, Dienst aktivieren und (neu) starten.
set -e

case "$1" in
configure)
	mkdir -p /var/lib/node64
	if ! getent group node64 >/dev/null 2>&1; then
		addgroup --system node64 >/dev/null
	fi
	if ! getent passwd node64 >/dev/null 2>&1; then
		adduser --system --ingroup node64 --home /var/lib/node64 --no-create-home --disabled-login \
			--gecos "Node64" node64 >/dev/null
	fi
	chown node64:node64 /var/lib/node64
	chmod 0750 /var/lib/node64
	if [ -d /run/systemd/system ]; then
		systemctl daemon-reload >/dev/null 2>&1 || true
		systemctl enable node64.service >/dev/null 2>&1 || true
		if [ -n "$2" ]; then
			systemctl restart node64.service >/dev/null 2>&1 || true
		else
			systemctl start node64.service >/dev/null 2>&1 || true
		fi
		echo "Node64 laeuft: http://$(hostname -f 2>/dev/null || hostname):8080  (Einstellungen: /etc/default/node64)"
	else
		echo "Node64 installiert. Ohne systemd bitte selbst starten: /usr/bin/node64 (Daten: /var/lib/node64)"
	fi
	;;
esac
exit 0
