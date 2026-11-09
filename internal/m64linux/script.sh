# Monitor64: Abfrage ohne Agent (Node64). Nur lesende Befehle, laeuft mit BusyBox ash, dash und bash.
# Aufruf: sh -s -- [smart] [updates]
# Ausgabe in Abschnitten: Zeile "<<<m64:NAME>>>", danach der Inhalt. Was es nicht gibt, fehlt einfach.
#   file:PFAD   Inhalt einer Datei (/proc/...)
#   attr        Zeilen "PFAD<TAB>WERT" fuer einzeilige Dateien aus /sys (WERT 1 = vorhanden bzw. Symlink-Ziel)
#   df, df_i, zpool_list, zpool_status, systemd_failed, systemd_state, needs_restarting,
#   updates:MGR, updates_sec:MGR, smart:GERAET, note ("ABSCHNITT TEXT"), end
m64_smart=0
m64_updates=0
for m64_a in "$@"; do
	case $m64_a in
	smart) m64_smart=1 ;;
	updates) m64_updates=1 ;;
	esac
done
LC_ALL=C
LANG=C
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH
export LC_ALL LANG PATH

m64_sec() { printf '\n<<<m64:%s>>>\n' "$1"; }
m64_note() { m64_sec note; printf '%s %s\n' "$1" "$2"; }
m64_have() { command -v "$1" >/dev/null 2>&1; }
m64_cat() {
	for m64_p in "$@"; do
		[ -f "$m64_p" ] && [ -r "$m64_p" ] || continue
		m64_sec "file:$m64_p"
		cat "$m64_p" 2>/dev/null
	done
}
# read ist eingebaut: kein eigener Prozess je Datei
m64_attr() {
	for m64_p in "$@"; do
		[ -f "$m64_p" ] && [ -r "$m64_p" ] || continue
		m64_v=
		{ IFS= read -r m64_v || [ -n "$m64_v" ]; } 2>/dev/null <"$m64_p" || continue
		printf '%s\t%s\n' "$m64_p" "$m64_v"
	done
}
m64_flag() { printf '%s\t1\n' "$1"; }
m64_link() {
	[ -L "$1" ] || return 0
	m64_v=$(readlink "$1" 2>/dev/null) && printf '%s\t%s\n' "$1" "$m64_v"
}

m64_sec start
echo 1

m64_cat /proc/uptime /proc/stat /proc/meminfo /proc/loadavg /proc/mounts /proc/diskstats /proc/net/dev /proc/mdstat
for m64_p in /proc/net/bonding/*; do m64_cat "$m64_p"; done
m64_cat /var/run/reboot-required.pkgs /run/reboot-required.pkgs

# Dateisysteme: GNU df mit -l (ohne Netz-Dateisysteme), BusyBox kennt -l bzw. -T nicht immer
m64_o=$(df -PkTl 2>/dev/null)
[ -n "$m64_o" ] || m64_o=$(df -PkT 2>/dev/null)
[ -n "$m64_o" ] || m64_o=$(df -Pk 2>/dev/null)
if [ -n "$m64_o" ]; then
	m64_sec df
	printf '%s\n' "$m64_o"
fi
m64_o=$(df -Pil 2>/dev/null)
[ -n "$m64_o" ] || m64_o=$(df -Pi 2>/dev/null)
if [ -n "$m64_o" ]; then
	m64_sec df_i
	printf '%s\n' "$m64_o"
fi

m64_sec attr
m64_attr /proc/sys/kernel/osrelease
[ -e /var/run/reboot-required ] && m64_flag /var/run/reboot-required
[ -e /run/reboot-required ] && m64_flag /run/reboot-required
[ -d /run/systemd/system ] && m64_flag /run/systemd/system
for m64_d in /lib/modules/*; do
	[ -f "$m64_d/modules.dep" ] && m64_flag "$m64_d/modules.dep"
done
for m64_d in /sys/block/*; do
	case ${m64_d##*/} in
	sd* | hd* | vd* | xvd* | nvme* | mmcblk* | sata*) ;;
	*) continue ;;
	esac
	m64_attr "$m64_d/device/model" "$m64_d/device/serial" "$m64_d/device/wwid" "$m64_d/device/name" \
		"$m64_d/queue/rotational"
done
for m64_i in /sys/class/net/*; do
	[ "${m64_i##*/}" = lo ] && continue
	m64_attr "$m64_i/operstate" "$m64_i/carrier" "$m64_i/speed" "$m64_i/duplex" "$m64_i/address" \
		"$m64_i/mtu" "$m64_i/statistics/rx_crc_errors"
	[ -d "$m64_i/bonding" ] && m64_flag "$m64_i/bonding"
	[ -d "$m64_i/bridge" ] && m64_flag "$m64_i/bridge"
	[ -e "$m64_i/device" ] && m64_flag "$m64_i/device"
	m64_link "$m64_i/master"
	if [ -r "$m64_i/uevent" ]; then
		while IFS= read -r m64_l; do
			case $m64_l in DEVTYPE=*) printf '%s\t%s\n' "$m64_i/uevent" "$m64_l" ;; esac
		done <"$m64_i/uevent"
	fi
done
for m64_h in /sys/class/hwmon/hwmon*; do
	m64_n=
	{ IFS= read -r m64_n; } 2>/dev/null <"$m64_h/name"
	# drivetemp koennte schlafende Platten wecken; Plattentemperatur kommt aus SMART
	[ "$m64_n" = drivetemp ] && continue
	m64_attr "$m64_h/name" "$m64_h/device/name" "$m64_h"/temp*_input "$m64_h"/temp*_label \
		"$m64_h"/temp*_crit "$m64_h"/temp*_max
	m64_link "$m64_h/device"
done
for m64_z in /sys/class/thermal/thermal_zone*; do
	m64_attr "$m64_z/type" "$m64_z/temp" "$m64_z"/trip_point_*_type "$m64_z"/trip_point_*_temp
done

if m64_have zpool; then
	m64_sec zpool_list
	zpool list -Hp -o name,size,alloc,free,frag,health 2>/dev/null
	m64_sec zpool_status
	zpool status 2>/dev/null
fi
if [ -d /run/systemd/system ] && m64_have systemctl; then
	m64_sec systemd_failed
	systemctl --failed --no-legend --plain 2>/dev/null
	m64_sec systemd_state
	systemctl is-system-running 2>/dev/null
fi
if [ ! -e /var/run/reboot-required ] && m64_have needs-restarting; then
	needs-restarting -r >/dev/null 2>&1
	m64_rc=$?
	m64_sec needs_restarting
	echo "$m64_rc"
fi

if [ "$m64_updates" = 1 ]; then
	m64_done=0
	if [ -x /usr/lib/update-notifier/apt-check ]; then
		m64_o=$(/usr/lib/update-notifier/apt-check 2>&1 >/dev/null)
		case $m64_o in
		*[0-9]";"[0-9]*)
			m64_sec updates:aptcheck
			printf '%s\n' "$m64_o"
			m64_done=1
			;;
		esac
	fi
	if [ "$m64_done" = 1 ]; then
		:
	elif m64_have apt-get; then
		m64_sec updates:apt
		apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | grep '^Inst '
	elif m64_have dnf; then
		m64_sec updates:dnf
		dnf -q check-update 2>/dev/null
		m64_sec updates_sec:dnf
		dnf -q updateinfo list --security 2>/dev/null
	elif m64_have yum; then
		m64_sec updates:yum
		yum -q check-update 2>/dev/null
		m64_sec updates_sec:yum
		yum -q updateinfo list --security 2>/dev/null
	elif m64_have zypper; then
		m64_sec updates:zypper
		zypper -n -q list-updates 2>/dev/null
		m64_sec updates_sec:zypper
		zypper -n -q list-patches --category security 2>/dev/null
	elif m64_have checkupdates; then
		m64_sec updates:pacman
		checkupdates 2>/dev/null
	elif m64_have pacman; then
		m64_sec updates:pacman
		pacman -Qu 2>/dev/null
	elif m64_have apk; then
		m64_sec updates:apk
		apk list -u 2>/dev/null
	elif m64_have opkg; then
		m64_sec updates:opkg
		opkg list-upgradable 2>/dev/null
	else
		m64_note updates "kein Paketverwalter erkannt"
	fi
fi

# SMART: als root direkt, sonst nur ueber "sudo -n" (Zeile in sudoers); Geraetenamen werden vorher geprueft
if [ "$m64_smart" = 1 ]; then
	m64_sc=
	for m64_p in /usr/sbin/smartctl /usr/local/sbin/smartctl /sbin/smartctl /usr/bin/smartctl \
		/usr/local/bin/smartctl /bin/smartctl /opt/sbin/smartctl /opt/bin/smartctl; do
		if [ -x "$m64_p" ]; then
			m64_sc=$m64_p
			break
		fi
	done
	m64_root=0
	[ "$(id -u 2>/dev/null)" = 0 ] && m64_root=1
	m64_smartctl() {
		if [ "$m64_root" = 1 ]; then
			"$m64_sc" "$@"
		else
			sudo -n "$m64_sc" "$@"
		fi
	}
	if [ -z "$m64_sc" ]; then
		m64_note smart "smartctl fehlt"
	elif [ "$m64_root" = 0 ] && ! m64_have sudo; then
		m64_note smart "sudo fehlt"
	elif ! m64_smartctl -V >/dev/null 2>&1; then
		m64_note smart "sudo -n smartctl nicht erlaubt"
	else
		m64_list=$(m64_smartctl --scan-open 2>/dev/null)
		if [ -z "$m64_list" ]; then
			m64_note smart "keine Platten mit SMART gefunden"
		else
			m64_c=0
			printf '%s\n' "$m64_list" | while read -r m64_dev m64_dd m64_typ m64_rest; do
				case $m64_dev in /dev/?*) ;; *) continue ;; esac
				case ${m64_dev#/dev/} in *[!a-z0-9/]*) continue ;; esac
				[ "$m64_dd" = "-d" ] || m64_typ=
				case $m64_typ in *[!a-z0-9,_+-]*) m64_typ= ;; esac
				m64_c=$((m64_c + 1))
				[ "$m64_c" -gt 64 ] && break
				m64_sec "smart:$m64_dev"
				if [ -n "$m64_typ" ]; then
					m64_smartctl -j -a -n standby -d "$m64_typ" "$m64_dev" 2>/dev/null
				else
					m64_smartctl -j -a -n standby "$m64_dev" 2>/dev/null
				fi
			done
		fi
	fi
fi

m64_sec end
