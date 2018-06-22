# ipfidsupdate
Automated Snort rule update for IPFire

Provides a service to update Snort rules on an IPFire appliance automatically, including preserving the state (enabled/disabled) of
existing rules.

## To install

First remove any automatic updater that you've already got running.

Download the installer:

  ```wget https://github.com/timfprogs/ipfidsupdate/raw/master/install-idsupdate.sh```
  
Make it executable:

  ```chmod +x install-idsupdate.sh```

Run the installer:

  ```./install-idsupdate.sh```

The installer will download the files and install them in the correct places.  It will then ask a number of questions.  If you want
the system to run with minimal interaction, you should probably choose the following settings:

  ```
  Policy : Balanced
  Apply policy changes to new changed rules : yes
  ```

Other settings are up to you.

## Notes
### Policy

If you choose a policy of Security you are likely to have to manually enable and disable rules every time there is an update.  If
you choose Max-Detect you will have to do this, and you will prevent access through the firewall for many users while you try
to get the enable and disable rules right.  Both these settings also run the risk of slowing down the traffic through the firewall due to the amount of processing involved.

The policy of connectivity is useful if you do not have a lot of memory or you've got a fast connection on a slow computer.

### Maximum download speed

A Talos VRT rule file is large and may take a significant time to download.  Setting a maximum download speed can prevent this from interfering too much with other users.  A limit of half your internet speed is a good start.

### Emails

If you've got emails enabled, you will be given the option of enabling emails whenever there is a successful update or a failure.
You should be aware that these emails could give useful information to an attacker if they are intercepted.  The amount of
information in the email is minimised to limit this, but you should probably only enable this is you've confident of the
security of your email infrastructure.

### Update log

A new page is added to the Log menu giving the update status.  Note that if you're in Europe this will be blank for most of the
day, since the rules are typically updated late in the day.  You can select previous day's logs.

You will occasionally get messages due to failed attempts to download a file.  These can be ignored unless the recurr frequently.

Note that only information for currently selected categories will be shown; there may be changes to rules is other categories.
This means that occasionally an update is downloaded that appears to have nothing it it; this will be due to all the changes
being in categories that you haven't got selected.

The categories are:

__New Rules__
These are enabled or disabled depending on their policy and your selected default policy.

__Deleted Rules__
These are rules that have been deleted from the ruleset.

__Updated Rules__
These are rules that have been changed from the previous version.  If the policy has changed and 'Apply policy changes to new 
changed rules' has been set to 'yes' then the rule will be enabled or disabled as appropriate. Rules that have not changed
category will be listed if you have overridden the enabled or disabled state.  You should consider whether the reason that you
overrode the state is still valid.

### Flowbits

These are used to pass information between different rules.  For example a flowbit will be set if a rule recognises that a file
is a particular type of executable.  Other rules can then use test the flowbit rather than duplicating the check.

This means that a rule that tests a flowbit cannot work if the rule that checks the flowbit is disabled.  As part of the update a 
check is made for these rule; a link will be placed on the log page if any are found.  You should either enable the rule that
sets the flowbit or disable the rule that tests it.

Most of the rules that set flowbits are found in the emerging-info, emerging-policy and file-identify categories.

### Rulesets

The community rules can be found in both the Talos VRT and Emerging Threats rulesets, as well as the Community ruleset.  To avoid 
wasting resources on these duplicate rules the updater carries out some processing to optimise the rulesets.  In particular it
switches to an alternative version of the Emerging Threats rules (no-gpl) if it detects that you are using one of the Talso VRT
rulesets.  A consequence of this is that the first time an Emerging Threats ruleset is updated there will be a large number of
deleted rules reported, as the duplcated rules are removed.

The updater will not update the Community ruleset if you've got one of the other rulesets installed, but you should manually
disable it.
