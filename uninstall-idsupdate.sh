#! /bin/bash

temp_dir="$TMP"

# Update the crontab

fcrontab -l >fcrontab_old

if grep "snort-update\|ids-update" fcrontab_old >>/dev/null; then
  sed -i "/snort-update\|ids-update\|Snort rule update/,+2d" fcrontab_old;
fi

fcrontab fcrontab_old
unlink fcrontab_old

rm -f /var/ipfire/addon-lang/ids-update.*.pl
rm -f /var/ipfire/menu.d/EX-idsupdate.menu
rm -f /usr/lib/statusmail/plugins/services_ids_update.pm
rm -f /var/ipfire/statusmail/plugins/services_ids_update.pm
rm -f /usr/share/logwatch/dist.conf/services/ids-update.conf
rm -f /usr/share/logwatch/scripts/services/ids-update
rm -f /usr/local/bin/ids-update.pl
rm -f /srv/web/ipfire/cgi-bin/idsflowbits.cgi
rm -f /srv/web/ipfire/cgi-bin/logs.cgi/idsupdate.dat
rm -f /srv/web/ipfire/cgi-bin/idsupdate.cgi
rm -f /root/install-idsupdate.sh
rm -rf /var/ipfire/idsupdate
rm -f /var/tmp/snortrules-snapshot-*.tar.gz
rm -f /var/tmp/*_classification.config
rm -f /var/tmp/*_reference.config
rm -f /var/tmp/flowbit-warnings.txt
rm -f /var/tmp/community-rules.tar.gz
rm -f /var/tmp/emerging.rules.tar.gz
rm -f /var/tmp/rule_backup.tar.gz

# Update language cache

update-lang-cache
