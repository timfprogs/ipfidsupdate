#! /bin/bash

# Locations of settings files
updatedir="/var/ipfire/snortupdate"
updatesettings="$updatedir/settings"
mailfile="/var/ipfire/dma/mail.conf"
qossettings="/var/ipfire/qos/settings"
temp_dir="$TMP"

phase2="no"

# Default update settings

RATE="DAILY"
DOWNLOAD_LIMIT=0
POLICY="BALANCED"
EMAIL="off"
LIVE_UPDATE="on"
APPLY_POLICY_CHANGE="on"
VERSION=0

if [[ ! -d $updatedir ]]; then mkdir -p $updatedir; fi

# If there's an old settings file, read it and use it as the defaults
if [[ -e $updatesettings ]]; then
  echo read old settings
  source $updatesettings
fi

while getopts ":2hH" opt; do
  case $opt in
  2) phase2="yes";;

  *) echo "Usage: $0 [-2]"; exit 1;;
  esac
done

if [[ $phase2 == "no" ]]; then
  # Check to see if there's a new version available

  echo Check for new version

  wget "https://github.com/timfprogs/ipfidsupdate/raw/master/VERSION"

  NEW_VERSION=`cat VERSION`
  rm VERSION

  # Set phase2 to yes to stop download of update

  if [[ $VERSION -eq $NEW_VERSION ]]; then
    phase2="yes"
  fi
fi

if [[ $phase2 == "no" ]]; then

  # Do some renaming

  while read -r old new || [[ -n "$old" ]]; do
    if [[ -e $old ]]; then mv $old $new; fi
  done <<-RENAME
  /usr/local/bin/snort-update.pl /usr/local/bin/ids-update.pl
  /var/ipfile/snortupdate /var/ipfire/idsupdate
RENAME

  # Change some permissions

  while read -r file owner mode || [[ -n "$file" ]]; do
    if [[ -e $file ]];
    then
      chown $file $owner
      chmod $file $perm;
    fi
  done <<-PERM
  /var/tmp/community-rules.tar.gz nobody.nobody 0644
  /var/tmp/emerging.rules.tar.gz nobody.nobody 0644
  /var/tmp/snortrules-snapshot-29111.tar.gz nobody.nobody 0644
PERM

  chown nobody.nobody /etc/snort/rules/*

  # Download the manifest

  wget "https://github.com/timfprogs/ipfidsupdate/raw/master/MANIFEST"

  # Download and move files to their destinations

  echo Downloading files

  if [[ ! -r MANIFEST ]]; then
    echo "Can't find MANIFEST file"
    exit 1
  fi

  while read -r name path owner mode || [[ -n "$name" ]]; do
    echo --
    echo Download $name
    if [[ ! -d $path ]]; then mkdir -p $path; fi
    if [[ $name != "." ]]; then wget "https://github.com/timfprogs/ipfidsupdate/raw/master/$name" -O $path/$name; fi
    chown $owner $path/$name
    chmod $mode $path/$name
  done < "MANIFEST"

  # Tidy up

  rm MANIFEST

  # Run the second phase of the new install file
  exec $0 -2

  echo Failed to exec $0
fi

# Update the crontab

start=$(($RANDOM % 30 + 5))
stop=$(($start + 10))
CRONTAB="%hourly,nice(1),random,serialonce(true) $start-$stop /usr/local/bin/snort-update.pl"

fcrontab -l >fcrontab_old

if grep snort-update fcrontab_old >>/dev/null; then
  sed -i "/snort-update.pl/c$CRONTAB" fcrontab_old;
else
  cat <<END >> fcrontab_old

# Snort rule update
$CRONTAB
END
fi

fcrontab fcrontab_old

# Update language cache

update-lang-cache
