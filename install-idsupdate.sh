#! /bin/bash

# Locations of files
updatedir="/var/ipfire/idsupdate"

temp_dir="$TMP"

# Branch to use from repository
branch=master

phase2="no"

if [[ ! -d $updatedir ]]; then mkdir -p $updatedir; fi

while getopts ":2hHb:" opt; do
  case $opt in
  2) phase2="yes";;

  b) branch=$OPTARG;;

  :) echo "No argument supplied for option -$OPTARG"; exit 1;;

  *) echo "Usage: $0 [-2] [-b branch]"; exit 1;;
  esac
done

if [[ $phase2 == "no" ]]; then

  # Do some renaming

  while read -r old new || [[ -n "$old" ]]; do
    if [[ -e $old ]]; then mv $old $new; fi
  done <<-RENAME
  /usr/local/bin/snort-update.pl /usr/local/bin/ids-update.pl
  /var/ipfire/snortupdate /var/ipfire/idsupdate
  /var/ipfire/snortupdate/settings /var/ipfire/idsupdate/settings
RENAME

  # Change some permissions

  while read -r file owner mode || [[ -n "$file" ]]; do
    if [[ -e $file ]];
    then
      chown $owner $file
      chmod $mode $file;
    fi
  done <<-PERM
  /var/tmp/community-rules.tar.gz nobody.nobody 0644
  /var/tmp/emerging.rules.tar.gz nobody.nobody 0644
  /var/tmp/snortrules-snapshot-29111.tar.gz nobody.nobody 0644
  /var/ipfire/idsupdate nobody.nobody 0755
  /var/ipfire/idsupdate/settings nobody.nobody 0644
PERM

  chown nobody.nobody /etc/snort/rules/*
  if [[ -d /var/ipfire/snortupdate ]]; then rm -R /var/ipfire/snortupdate; fi

  # Download the manifest

  wget "https://github.com/timfprogs/ipfidsupdate/raw/$branch/MANIFEST"

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
    if [[ $name != "." ]]; then wget "https://github.com/timfprogs/ipfidsupdate/raw/$branch/$name" -O $path/$name; fi
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
CRONTAB="%hourly,nice(1),random,serialonce(true) $start-$stop /usr/local/bin/ids-update.pl"

fcrontab -l >fcrontab_old

if grep "snort-update\|ids-update" fcrontab_old >>/dev/null; then
  sed -i "/snort-update.pl\|ids-update.pl/c$CRONTAB" fcrontab_old;
else
  cat <<END >> fcrontab_old

# Snort rule update
$CRONTAB
END
fi

fcrontab fcrontab_old
unlink fcrontab_old

# Update language cache

update-lang-cache
