# Monitor64: Abfrage ohne Agent (Node64). Nur lesende Befehle, laeuft mit BusyBox ash, dash und bash.
# Aufruf: sh -s -- [smart] [updates]
# Ausgabe in Abschnitten: Zeile "<<<m64:NAME>>>", danach der Inhalt. Was es nicht gibt, fehlt einfach.
#   file:PFAD   Inhalt einer Datei (/proc/...)
#   attr        Zeilen "PFAD<TAB>WERT" fuer einzeilige Dateien aus /sys (WERT 1 = vorhanden bzw. Symlink-Ziel);
#               "PFAD.hex<TAB>HEX" fuer Binaerdateien (vpd_pg80)
#   df, df_i, zpool_list, zpool_list_rc, zpool_status, systemd_failed, systemd_state, needs_restarting,
#   updates:MGR, updates_sec:MGR, smart:GERAET, note ("ABSCHNITT TEXT"), end
#   err:ABSCHNITT, err:smart:GERAET   nicht lesbar (Zeitlimit, Exit-Code), eine Zeile Text
# Zeilen aus Dateien und Programmen, die wie ein Abschnittskopf beginnen, bekommen ein Leerzeichen davor.
# Jedes Programm hat ein Zeitlimit (timeout aus coreutils bzw. BusyBox; fehlt es, laeuft es ohne).
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
m64_err() { m64_sec "err:$1"; printf '%s\n' "$2"; }
m64_have() { command -v "$1" >/dev/null 2>&1; }
if m64_have sed; then
	m64_mask() { sed 's/^<<<m64:/ <<<m64:/'; }
else
	m64_mask() { cat; }
fi

# timeout: GNU/neues BusyBox "timeout -s SIG SEK", altes BusyBox "timeout -s SIG -t SEK"
m64_to=0
if timeout -s KILL 5 true >/dev/null 2>&1; then
	m64_to=1
elif timeout -s KILL -t 5 true >/dev/null 2>&1; then
	m64_to=2
fi
# m64_run SIGNAL SEKUNDEN BEFEHL ...  (stdin /dev/null: das Skript selbst kommt ueber stdin)
m64_run() {
	m64_s=$1
	m64_t=$2
	shift 2
	case $m64_to in
	1) timeout -s "$m64_s" "$m64_t" "$@" </dev/null ;;
	2) timeout -s "$m64_s" -t "$m64_t" "$@" </dev/null ;;
	*) "$@" </dev/null ;;
	esac
}
# Exit-Code nach Zeitlimit: 124 (GNU), 137/143 (getoetet mit KILL/TERM)
m64_timedout() {
	[ "$m64_to" != 0 ] || return 1
	case $1 in 124 | 137 | 143) return 0 ;; esac
	return 1
}
# m64_try NAME "EXIT-CODES" SEKUNDEN BEFEHL ...: Ausgabe in m64_o; sonst Fehlertext in m64_e
m64_try() {
	m64_n=$1
	m64_ok=$2
	m64_t=$3
	shift 3
	m64_o=$(m64_run TERM "$m64_t" "$@" 2>/dev/null)
	m64_rc=$?
	if m64_timedout "$m64_rc"; then
		m64_e="$m64_n: Zeitlimit"
		return 1
	fi
	for m64_c in $m64_ok; do
		[ "$m64_rc" = "$m64_c" ] && return 0
	done
	m64_e="$m64_n: Exit-Code $m64_rc"
	return 1
}
m64_out() {
	if [ -n "$m64_o" ]; then
		printf '%s\n' "$m64_o" | m64_mask
	fi
}
m64_cat() {
	for m64_p in "$@"; do
		[ -f "$m64_p" ] && [ -r "$m64_p" ] || continue
		m64_sec "file:$m64_p"
		m64_mask <"$m64_p" 2>/dev/null
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
m64_hex=0
m64_have od && m64_have tr && m64_hex=1
m64_hexattr() {
	[ "$m64_hex" = 1 ] && [ -f "$1" ] && [ -r "$1" ] || return 0
	printf '%s.hex\t' "$1"
	od -An -tx1 -v "$1" 2>/dev/null | tr -d ' \n'
	echo
}

m64_sec start
echo 1

m64_cat /proc/uptime /proc/stat /proc/meminfo /proc/loadavg /proc/mounts /proc/diskstats /proc/net/dev /proc/mdstat
for m64_p in /proc/net/bonding/*; do m64_cat "$m64_p"; done
m64_cat /var/run/reboot-required.pkgs /run/reboot-required.pkgs

# Dateisysteme: ohne -l (GNU haelt Geraete mit ":" wie mergerfs fuer Netz), Netz-Dateisysteme per -x (df kann an
# einem toten Server haengen); BusyBox kennt -x bzw. -T nicht immer. Zeitlimit 5 s (KILL, NFS haengt sonst).
# Rueckgabe: 0 Ausgabe da, 1 keine Ausgabe, 2 Zeitlimit
m64_df() {
	m64_o=$(m64_run KILL 5 df "$@" 2>/dev/null)
	m64_rc=$?
	m64_timedout "$m64_rc" && return 2
	[ -n "$m64_o" ]
}
m64_xdf() {
	m64_df "$@" -x nfs -x nfs4 -x cifs -x smb3 -x smbfs -x ncpfs -x afs -x 9p -x ceph -x glusterfs \
		-x fuse.glusterfs -x fuse.sshfs -x fuse.rclone -x fuse.s3fs -x davfs -x fuse.davfs -x lustre -x gpfs \
		-x fuse.ceph-fuse
}
m64_xdf -PkT
m64_r=$?
if [ "$m64_r" = 1 ]; then
	m64_df -PkT
	m64_r=$?
fi
if [ "$m64_r" = 1 ]; then
	m64_df -Pk
	m64_r=$?
fi
case $m64_r in
0)
	m64_sec df
	m64_out
	m64_xdf -Pi
	m64_r=$?
	if [ "$m64_r" = 1 ]; then
		m64_df -Pi
		m64_r=$?
	fi
	case $m64_r in
	0)
		m64_sec df_i
		m64_out
		;;
	2) m64_err fs "df -i: Zeitlimit" ;;
	esac
	;;
2) m64_err fs "df: Zeitlimit" ;;
esac

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
	m64_attr "$m64_d/device/model" "$m64_d/device/serial" "$m64_d/device/wwid" "$m64_d/wwid" "$m64_d/device/name" \
		"$m64_d/queue/rotational"
	[ -f "$m64_d/device/serial" ] || m64_hexattr "$m64_d/device/vpd_pg80"
done
# Seriennummern aus udev (nur ata-/nvme-Namen ganzer Platten)
for m64_l in /dev/disk/by-id/*; do
	case ${m64_l##*/} in
	*-part[0-9]* | nvme-eui.* | nvme-nvme.*) ;;
	ata-* | nvme-*) m64_link "$m64_l" ;;
	esac
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
	m64_o=$(m64_run TERM 5 zpool list -Hp -o name,size,alloc,free,frag,health 2>/dev/null)
	m64_rc=$?
	if m64_timedout "$m64_rc"; then
		m64_err zfs "zpool: Zeitlimit"
	else
		m64_sec zpool_list
		m64_out
		if [ "$m64_rc" != 0 ]; then
			m64_sec zpool_list_rc
			echo "$m64_rc"
		fi
		if [ -n "$m64_o" ]; then
			m64_o=$(m64_run TERM 5 zpool status 2>/dev/null)
			if m64_timedout "$?"; then
				m64_err zfs "zpool: Zeitlimit"
			else
				m64_sec zpool_status
				m64_out
			fi
		fi
	fi
fi
if [ -d /run/systemd/system ] && m64_have systemctl; then
	if m64_try "systemctl --failed" 0 5 systemctl --failed --no-legend --plain; then
		m64_sec systemd_failed
		m64_out
		m64_o=$(m64_run TERM 5 systemctl is-system-running 2>/dev/null)
		m64_timedout "$?" && m64_o=
		m64_sec systemd_state
		m64_out
	else
		m64_err systemd "$m64_e"
	fi
fi

if [ "$m64_updates" = 1 ]; then
	# RHEL: Python-Aufruf, daher nur mit den Updates (hoechstens stuendlich)
	if [ ! -e /var/run/reboot-required ] && m64_have needs-restarting; then
		m64_run TERM 30 needs-restarting -r >/dev/null 2>&1
		m64_rc=$?
		if ! m64_timedout "$m64_rc"; then
			m64_sec needs_restarting
			echo "$m64_rc"
		fi
	fi
	m64_done=0
	if [ -x /usr/lib/update-notifier/apt-check ]; then
		m64_o=$(m64_run TERM 90 /usr/lib/update-notifier/apt-check 2>&1 >/dev/null)
		case $m64_o in
		*[0-9]";"[0-9]*)
			m64_sec updates:aptcheck
			m64_out
			m64_done=1
			;;
		esac
	fi
	# Fehler der Sicherheitsliste ergibt nur einen Hinweis (die Gesamtzahl gilt)
	m64_mgr=
	if [ "$m64_done" = 1 ]; then
		:
	elif m64_have apt-get; then
		# dist-upgrade (nur Simulation) zaehlt auch zurueckgehaltene Pakete
		if m64_try apt-get 0 90 apt-get -s -o Debug::NoLocking=1 dist-upgrade; then
			m64_sec updates:apt
			printf '%s\n' "$m64_o" | grep '^Inst '
		else
			m64_err updates "$m64_e"
		fi
	elif m64_have dnf || m64_have yum; then
		m64_mgr=dnf
		m64_have dnf || m64_mgr=yum
		if m64_try "$m64_mgr" "0 100" 90 "$m64_mgr" -q check-update; then
			m64_sec "updates:$m64_mgr"
			m64_out
			if m64_try "$m64_mgr" 0 90 "$m64_mgr" -q updateinfo list --security; then
				m64_sec "updates_sec:$m64_mgr"
				m64_out
			else
				m64_note updates "Sicherheitsupdates unbekannt: $m64_e"
			fi
		else
			m64_err updates "$m64_e"
		fi
	elif m64_have zypper; then
		m64_mgr=zypper
		if m64_try zypper 0 90 zypper -n -q list-updates; then
			m64_sec updates:zypper
			m64_out
			if m64_try zypper "0 100 101" 90 zypper -n -q list-patches --category security; then
				m64_sec updates_sec:zypper
				m64_out
			else
				m64_note updates "Sicherheitsupdates unbekannt: $m64_e"
			fi
		else
			m64_err updates "$m64_e"
		fi
	elif m64_have checkupdates; then
		if m64_try checkupdates "0 2" 90 checkupdates; then
			m64_sec updates:pacman
			m64_out
		else
			m64_err updates "$m64_e"
		fi
	elif m64_have pacman; then
		if m64_try pacman "0 1" 90 pacman -Qu; then
			m64_sec updates:pacman
			m64_out
		else
			m64_err updates "$m64_e"
		fi
	elif m64_have apk; then
		if m64_try apk 0 90 apk list -u; then
			m64_sec updates:apk
			m64_out
		else
			m64_err updates "$m64_e"
		fi
	elif m64_have opkg; then
		if m64_try opkg 0 90 opkg list-upgradable; then
			m64_sec updates:opkg
			m64_out
		else
			m64_err updates "$m64_e"
		fi
	else
		m64_note updates "kein Paketverwalter erkannt"
	fi
fi

# SMART: als root direkt, sonst nur ueber "sudo -n" (Zeile in sudoers); Geraetenamen werden vorher geprueft.
# Zeitlimit mit TERM: sudo gibt es an smartctl weiter (KILL wuerde nur sudo beenden).
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
	# m64_smartctl SEKUNDEN ARGUMENTE ...
	m64_smartctl() {
		m64_st=$1
		shift
		if [ "$m64_root" = 1 ]; then
			m64_run TERM "$m64_st" "$m64_sc" "$@"
		else
			m64_run TERM "$m64_st" sudo -n "$m64_sc" "$@"
		fi
	}
	if [ -z "$m64_sc" ]; then
		m64_note smart "smartctl fehlt"
	elif [ "$m64_root" = 0 ] && ! m64_have sudo; then
		m64_note smart "sudo fehlt"
	elif ! m64_smartctl 10 -V >/dev/null 2>&1; then
		m64_note smart "sudo -n smartctl nicht erlaubt"
	else
		m64_list=$(m64_smartctl 20 --scan-open 2>/dev/null)
		m64_rc=$?
		if [ -z "$m64_list" ] && m64_timedout "$m64_rc"; then
			m64_err smart "smartctl --scan-open: Zeitlimit"
		elif [ -z "$m64_list" ]; then
			m64_note smart "keine Platten mit SMART gefunden"
		else
			m64_c=0
			printf '%s\n' "$m64_list" | while read -r m64_dev m64_dd m64_typ _; do
				case $m64_dev in /dev/?*) ;; *) continue ;; esac
				case ${m64_dev#/dev/} in *[!a-z0-9/]*) continue ;; esac
				[ "$m64_dd" = "-d" ] || m64_typ=
				case $m64_typ in *[!a-z0-9,_+-]*) m64_typ= ;; esac
				m64_c=$((m64_c + 1))
				[ "$m64_c" -gt 64 ] && break
				if [ -n "$m64_typ" ]; then
					m64_o=$(m64_smartctl 20 -j -a -n standby -d "$m64_typ" "$m64_dev" 2>/dev/null)
				else
					m64_o=$(m64_smartctl 20 -j -a -n standby "$m64_dev" 2>/dev/null)
				fi
				m64_rc=$?
				m64_sec "smart:$m64_dev"
				m64_out
				# smartctl schreibt JSON erst am Ende: abgebrochen = leer (Exit-Code allein ist ein Bitfeld)
				if [ -z "$m64_o" ] && m64_timedout "$m64_rc"; then
					m64_err "smart:$m64_dev" "smartctl: Zeitlimit"
				fi
			done
		fi
	fi
fi

m64_sec end
