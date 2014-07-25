#!/usr/bin/sh

IPA_DIR="/usr/share/ipa"  #TODO find appropriate dir
DAEMON_DIR="ipadnssecd"

FILES="keydaemon.py keysyncer.py script.py syncrepl.py odsmgr.py signer-replacement/print_all.py signer-replacement/signerd.py"

mkdir "$IPA_DIR/$DAEMON_DIR"
mkdir "$IPA_DIR/$DAEMON_DIR/signer-replacement"

for file in $FILES
do
	cp $file "$IPA_DIR/$DAEMON_DIR/$file"
done

cp ipa-dnskeysyncd.service /etc/systemd/system/ipa-dnskeysyncd.service
cp signer-replacement/ipa-ods-exporter.service /etc/systemd/system/ipa-ods-exporter.service
cp signer-replacement/ipa-ods-exporter.socket /etc/systemd/system/ipa-ods-exporter.socket