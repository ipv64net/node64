#!/bin/sh
# Paket node64: Systembenutzer anlegen, Dienst bei der Erstinstallation aktivieren und starten. Bei einem Update
# (bzw. erneuter Installation nach "remove") bleibt die Entscheidung des Admins: aktiviert = neu starten,
# deaktiviert = nur neu starten, wenn er gerade laeuft.
set -e

case "$1" in
configure)
	mkdir -p /var/lib/node64
	if ! getent group node64 >/dev/null 2>&1; then
		addgroup --system node64 >/dev/null
	fi
	if ! getent passwd node64 >/dev/null 2>&1; then
		adduser --system --ingroup node64 --home /var/lib/node64 --no-create-home --disabled-login 			--gecos "Node64" node64 >/dev/null
	fi
	# nach "purge" (Benutzer geloescht, Daten geblieben) kann der neue Benutzer eine andere UID haben: dann auch den
	# Inhalt uebergeben (Datenbank, Schluessel, Selbst-Update in bin/)
	if [ "$(stat -c %U:%G /var/lib/node64)" != "node64:node64" ]; then
		chown -R node64:node64 /var/lib/node64
	fi
	chmod 0750 /var/lib/node64
	if [ -d /run/systemd/system ]; then
		systemctl daemon-reload >/dev/null 2>&1 || true
		if [ -z "$2" ]; then
			systemctl enable node64.service >/dev/null 2>&1 || true
			systemctl start node64.service >/dev/null 2>&1 || true
		elif systemctl is-enabled --quiet node64.service 2>/dev/null; then
			systemctl restart node64.service >/dev/null 2>&1 || true
		else
			systemctl try-restart node64.service >/dev/null 2>&1 || true
		fi
		if systemctl is-active --quiet node64.service 2>/dev/null; then
			echo "Node64 laeuft: http://$(hostname -f 2>/dev/null || hostname):8080  (Einstellungen: /etc/default/node64)"
		elif systemctl is-enabled --quiet node64.service 2>/dev/null; then
			echo "Node64 ist installiert, startet aber nicht - siehe: systemctl status node64 / journalctl -u node64"
		else
			echo "Node64 ist installiert, der Dienst ist deaktiviert (starten: systemctl enable --now node64)"
		fi
	else
		echo "Node64 installiert. Ohne systemd bitte selbst starten: /usr/bin/node64 (Daten: /var/lib/node64)"
	fi
	;;
esac
exit 0
