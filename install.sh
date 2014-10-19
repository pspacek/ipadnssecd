#!/usr/bin/sh

IPA_DIR="/usr/share/ipa"  #TODO find appropriate dir
DAEMON_DIR="ipadnssecd"

FILES=*.py

mkdir -p "$IPA_DIR/$DAEMON_DIR"

for file in $FILES
do
	ln --force -s "$(pwd)/$file" "$IPA_DIR/$DAEMON_DIR/$file"
done

ln --force -s "$(pwd)/ipa-dnskeysyncd.service" /lib/systemd/system/ipa-dnskeysyncd.service
ln --force -s "$(pwd)/ipa-ods-exporter.service" /lib/systemd/system/ipa-ods-exporter.service 
ln --force -s "$(pwd)/ipa-ods-exporter.socket" /lib/systemd/system/ipa-ods-exporter.socket
systemctl daemon-reload
