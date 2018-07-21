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

# Check if QOS is enabled, and if so use it to set a default download speed limit

if [[ -e $qossettings ]]; then
  DOWNLOAD_LIMIT=`awk 'BEGIN{FS="="};/^INC_SPD/{print $2}' $qossettings`
  DOWNLOAD_LIMIT=$((${DOWNLOAD_LIMIT:-0}/2))
fi
 
# Function for a Yes/No setting
function yesno
{
  case $2 in
    on)  default="yes";;
    off) default="no";;
  esac

  local response

  while [[ ! ${response} =~ ^[ynYN].* ]]; do
    read -p "$1 [$default] : " response
    response=${response:-$default}
  done
 
  case $response in
    y* | Y*) eval $3="on";;
    n* | N*) eval $3="off";;
  esac
}
 
#--------------------------------------------------------------------
# Start of questions for update settings
#--------------------------------------------------------------------
 
cat <<END
 
---------------------------------------------------------------------

The system can check for an update to the rule files at a number
of different rates: Hourly, Daily or Weekly.  It will check for
the existence of an update at the specified rate, but only download
and process it if it is different from the version already on the
system.
 
END
 
unset new_rate
while [[ ! ${new_rate} =~ ^[hdwHDW].* ]]; do
  echo "How often do you want to check for an update:"
  echo "  h) hourly"
  echo "  d) daily"
  echo "  w) weekly"
  read -p "Update check rate [$RATE] : " new_rate
  new_rate=$(echo $new_rate | tr 'HDW' 'hdw')
  new_rate=${new_rate:-$RATE}
done
 
case $new_rate in
  h* | H* ) RATE=HOURLY
            CRONTAB="%hourly,nice(1),random(true),serialonce(true) 15-45 /usr/local/bin/snort-update.pl";;
  d* | D* ) RATE=DAILY
            CRONTAB="%nightly,nice(1),random(true),serialonce(true) 15-45 23-4 /usr/local/bin/snort-update.pl";;
  w* | W* ) RATE=WEEKLY
            CRONTAB="%dow,bootrun(true),nice(1),random(true),serialonce(true) 15-45 23-4 * * sat,sun /usr/local/bin/snort-update.pl";;
esac
 
cat <<END
 
---------------------------------------------------------------------

You can specify a maximum download speed for the update files.
If the update rate you have chosen can lead to an update during the
period when you are using the system it is worth considering a limit.
A value of zero disables the limit.
 
END
 
while [[ ! ${limit} =~ ^[0-9]+$ ]]; do
  read -p "Rule download speed limit (0 for no limit) [$DOWNLOAD_LIMIT] : " limit
  limit=${limit:-$DOWNLOAD_LIMIT}
done
 
DOWNLOAD_LIMIT=$limit
 
cat <<END
 
---------------------------------------------------------------------

New rules can be enabled or disabled depending on a default policy.
There are four possible policies:
 
Connectivity (over Security)
    Has the minimum impact on the system in terms of memory and
    processing power, while still detecting the most important
    threats.
   
Balanced (between Connectivity and Security)
    A good starting point, giving good detection without consuming
    too much resources.
   
Security (over Connectivity)
    Detects a lot more threats, at the cost of using more resources.
    Should be the target for a secure installation.
   
Max-Detect
    The highest level of detection.
   
Note that for the Security and Max-Detect policies  you will have to
tune the rules to your installation by enabling and disabling
individual rules, or you can expect to have a lot of log messages.
In particular max-detect will generate messages for a lot of routine
traffic.
 
END

unset newpolicy
while [[ ! ${newpolicy} =~ ^[cbsmCBAM].* ]]; do
  echo "What policy do you want to apply for new rules:"
  echo "  Connectivity"
  echo "  Balanced"
  echo "  Security"
  echo "  Max-detect"
  read -p "New rule policy [$POLICY] : " policy
  newpolicy=$(echo $newpolicy | tr 'CBSM' 'cbsw')
  newpolicy=${policy:-$POLICY}
done
 
case $policy in
  c* | C* ) POLICY=CONNECTIVITY;;
  b* | B* ) POLICY=BALANCED;;
  s* | S* ) POLICY=SECURITY;;
  m* | M* ) POLICY=MAXDETECT;;
esac
 
if [[ -e $mailfile ]]; then
  mailenabled=`awk 'BEGIN{FS="="};/USEMAIL/{print $2}' $mailfile`
  if [[ $mailenabled == "on" ]]; then
 
    cat <<-END
 
---------------------------------------------------------------------

The system can send email messages to inform you of either a
successful rule update or an update failure.  Note that anyone
intercepting one of these emails will be able to deduce a lot about
the protection of your system and hence what exploits are likely to
work on it.

You should probably only enable emails if you a confident of the
security of your email infrastructure.
 
END

    yesno "Do you want to send update notification emails" "$EMAIL" EMAIL
  else
    EMAIL=off
  fi
else
  EMAIL=off
fi
 
cat <<END
 
---------------------------------------------------------------------

Once the rules have been updated Snort can be told to use the new
rules in two different ways; either by performing a live update, or
by restarting.
 
A live update means that the system continues to be protected while
the new rule files are read and processed, but requires more memory
than stopping Snort and then re-starting it.

END
 
yesno "Do you want to perform a live update of the rules" "$LIVE_UPDATE" LIVE_UPDATE

cat <<END
 
---------------------------------------------------------------------

The policy of a rule can change over time due to changes in the
perceived level of threat.

If the policy of an existing rule changes the system can apply the
change to that rule by enabling it or disabling it depending on the
selected default policy and the new policy of the rule.

END

yesno "Do you want to apply policy changes to changed rules" "$APPLY_POLICY_CHANGE" APPLY_POLICY_CHANGE

# Write the settings file

cat <<END > $updatesettings
RATE=$RATE
DOWNLOAD_LIMIT=$DOWNLOAD_LIMIT
POLICY=$POLICY
EMAIL=$EMAIL
LIVE_UPDATE=$LIVE_UPDATE
APPLY_POLICY_CHANGE=$APPLY_POLICY_CHANGE
VERSION=$NEW_VERSION
DEBUG=0
END

# Update the crontab

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
