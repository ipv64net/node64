#!/bin/bash
# Samba-AD-DC provisionieren, Testbenutzer/-gruppen anlegen, im Vordergrund starten
set -e
. /env/pw
rm -f /etc/samba/smb.conf
samba-tool domain provision --realm=N64TEST.LAN --domain=N64TEST --server-role=dc --dns-backend=NONE \
  --adminpass="$ADMINPW" --option="tls enabled = yes" --option="tls keyfile = /certs/dc1.key" \
  --option="tls certfile = /certs/dc1.crt" --option="tls cafile = /certs/ca.crt" >/tmp/provision.log
u() { samba-tool user create "$@" >/dev/null; }
u svc-node64 "$SVCPW"
u anna "$USERPW" --given-name=Anna --surname=Alt --mail-address=anna@n64test.lan
u jürgen "$USERPW" --given-name=Jürgen --surname=Müller --mail-address=juergen@n64test.lan
u eva "$USERPW" --given-name=Eva --surname=Schmidt
samba-tool user rename eva --force-new-cn="Schmidt\, Eva" >/dev/null
u gesperrt "$USERPW"
samba-tool user disable gesperrt >/dev/null
for g in Inner Middle Outer "Node64 Admins"; do samba-tool group add "$g" >/dev/null; done
samba-tool group addmembers Inner anna,jürgen,eva,gesperrt >/dev/null
samba-tool group addmembers Middle Inner >/dev/null
samba-tool group addmembers Outer Middle >/dev/null
samba-tool group addmembers "Node64 Admins" anna >/dev/null
samba-tool user show anna --attributes=objectGUID | sed -n 's/^objectGUID: //p' > /env/anna.guid
touch /env/samba.ready
exec samba -i --debuglevel=1
