#!/usr/bin/sh

IPA_DIR="/usr/share/ipa"  #TODO find appropriate dir
DAEMON_DIR="ipadnssecd"

FILES="keydaemon.py keysyncer.py syncrepl.py odsmgr.py signer-replacement/signerd.py bindmgr.py temp.py"

mkdir -p "$IPA_DIR/$DAEMON_DIR/signer-replacement"

for file in $FILES
do
	ln -s "$(pwd)/$file" "$IPA_DIR/$DAEMON_DIR/$file"
done

ln -s "$(pwd)/ipa-dnskeysyncd.service" /lib/systemd/system/ipa-dnskeysyncd.service
ln -s "$(pwd)/signer-replacement/ipa-ods-exporter.service" /lib/systemd/system/ipa-ods-exporter.service 
ln -s "$(pwd)/signer-replacement/ipa-ods-exporter.socket" /etc/systemd/system/ipa-ods-exporter.socket 
systemctl daemon-reload
