#! /usr/bin/perl

############################################################################
#                                                                          #
# Automatic updates for the IPFire Intrusion Detection System              #
#                                                                          #
# This is free software; you can redistribute it and/or modify             #
# it under the terms of the GNU General Public License as published by     #
# the Free Software Foundation; either version 2 of the License, or        #
# (at your option) any later version.                                      #
#                                                                          #
# This is distributed in the hope that it will be useful,                  #
# but WITHOUT ANY WARRANTY; without even the implied warranty of           #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the            #
# GNU General Public License for more details.                             #
#                                                                          #
# You should have received a copy of the GNU General Public License        #
# along with IPFire; if not, write to the Free Software                    #
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA #
#                                                                          #
# Copyright (C) 2018                                                       #
#                                                                          #
############################################################################

use strict;
use warnings;

use File::Copy;
use File::Basename;
use Sort::Naturally;
use Sys::Syslog qw(:standard :macros);
use HTTP::Request;
use LWP::UserAgent;
use MIME::Lite;

require "/var/ipfire/general-functions.pl";
require "${General::swroot}/lang.pl";

############################################################################
# Configuration variables
#
# These variables give the locations of various files used by this script
############################################################################

my $rule_dir        = "/etc/snort/rules";
my $oinkmaster_conf = "${General::swroot}/snort/oinkmaster.conf";
my $snort_conf      = "/etc/snort/snort.conf";
my $mail_config     = "${General::swroot}/dma/mail.conf";
my $update_settings = "${General::swroot}/idsupdate/settings";
my $update_status   = "${General::swroot}/idsupdate/status";
my $snort_settings  = "${General::swroot}/snort/settings";
my $proxy_settings  = "${General::swroot}/proxy/settings";
my $cert_file       = "/etc/ssl/certs/ca-bundle.crt";
my $tmp_dir         = "/var/tmp";
my $oinkmaster      = "sudo -u nobody /usr/local/bin/oinkmaster.pl";
my $wget            = "sudo -u nobody /usr/bin/wget";
my $snort_control   = "/etc/init.d/snort";
my $detailed_log    = "$tmp_dir/log";
my $rule_backup     = "$tmp_dir/rule_backup.tar.gz";
my $flowbit_warnings= "$tmp_dir/flowbit-warnings.txt";
my $snort           = "/usr/sbin/snort";
my $md5sum          = "/usr/bin/md5sum";
my $classtype_file  = "/etc/snort/rules/classification.config";
my $df              = "/bin/df";
my $free_space      = 300;         # MBytes of free space required to do an update
my $max_reread_wait = 120;         # Maximum number of seconds to wait for Snort to re-read rules

# Version of the Snort rule files required.
# Note that the Talos VRT version is overwritten later with the correct
# installed version

my $emerging_threats_snort_version = "2.9.0";
my $talos_vrt_snort_version        = "29111";

############################################################################
# Constants
############################################################################

use constant MESSAGE    =>  0;
use constant ENABLED    =>  1;
use constant PRIORITY   =>  2;
use constant REVISION   =>  3;
use constant CLASSTYPE  =>  4;
use constant POLICY     =>  5;
use constant RULESET    =>  6;
use constant STATUS     =>  7;
use constant CHANGE_KEY =>  8;
use constant FROM       =>  9;
use constant TO         => 10;
use constant ACTIVE     => 11;

############################################################################
# Function prototypes
############################################################################

sub get_rule( $ );
sub parse_rule_files( $$ );
sub parse_rule_file_pass_1( $ );
sub parse_rule_file_pass_2( $ );
sub print_list( $$@ );
sub generate_oinkmaster_config( );
sub get_skipped_files( $ );
sub abort( $ );
sub log_message( $$ );
sub check_for_updates( $ );
sub check_for_deleted_rules();
sub download_update( $$$$ );
sub parse_snort_config( $ );
sub parse_classification_file( $ );
sub update_rules();
sub check_running();
sub debug( $$ );
sub restart_snort();
sub email_status();
sub is_enough_disk_space( $ );
sub is_connected();
sub create_rules_backup();
sub restore_rules_backup();
sub check_flowbits();
sub expand_flowbit_groups();

############################################################################
# Variables
############################################################################

my %rules;                            # Temporary storage for information about rules
my %skipped_files;                    # Rule files that are not to be processed (From oinkmaster.conf)
my %enabled_sids;                     # Rules to be enabled for each rule set
my %disabled_sids;                    # Rules to be disabled for each rule set
my $changed_sids          = 0;        # The number of changed rules
my $rule_count            = 0;        # The total number of active rules
my %update_settings;                  # Snort Update settings
my %snort_settings;                   # Snort settings
my %mail_settings;                    # Mail settings - used to send status email
my %proxy_settings;                   # Proxy settings - used for downloading rule sets
my %update_status;                    # Update status including identifier of installed rule sets
my @updates;                          # Rules sets and URLs for which updates are available
my %enabled_rule_files;               # Rule categories that are enabled
my %classtype_priority;               # Used to map rule classtypes to priorities
my $write_update_status   = 0;        # Set to 1 to write update status at end of run
my $delete_log            = 1;        # Delete detailed download/rule update log
my $success               = 0;        # Set to 1 if some rules were successfully downloaded and updated
my $failure               = 0;        # Set to 1 if there was an error downloading and updating some rules
my $fix_community_rules   = 0;        # Set to 1 to handle duplicate community rules
my %flowbits;
my %flowgroups;


my %policies = ( 'CONNECTIVITY' => 1, # List of policies
                 'BALANCED'     => 2,
                 'SECURITY'     => 3,
                 'MAX_DETECT'   => 4 );

my @policies = ( 'None', 'Connectivity', 'Balanced', 'Security', 'Max-Detect', 'Not defined' );

############################################################################
# Set up for update
############################################################################

# Connect to the system log

openlog( "idsupdate", "nofatal", LOG_USER);

# Default settings
# Should be overwritten by reading settings files.  Not all possible fields
# are defined - only the ones that are used in this script.

%update_settings = ( 'ENABLE'              => 'off',        # Enable
                     'DEBUG'               => 0,            # Debug level
                     'POLICY'              => 'BALANCED',   # Policy to determine whether new rules are enabled
                     'RATE'                => 'HOURLY',     # How often to check for rule set updates
                     'DOWNLOAD_LIMIT'      => 5500,         # Maximum rule set download rate in kbit/s
                     'LIVE_UPDATE'         => 'on',         # Attempt to get Snort to perform a live rule update
                     'APPLY_POLICY_CHANGE' => 'on',         # Change rule state according to policy changes
                     'EMAIL'               => 'on' );       # Send a status email for a download success/failure

%mail_settings   = ( 'USEMAIL'             => 'off' );      # Email disabled

%snort_settings  = ( 'OINKCODE'            => '',           # Oinkcode for Talos VRT registered/subscribed rules
                     'ENABLE_SNORT_ORANGE' => 'off',        # Snort not enabled on Orange interface
                     'ENABLE_SNORT_BLUE'   => 'off',        # Snort not enabled on Blue interface
                     'ENABLE_SNORT_GREEN'  => 'off',        # Snort not enabled on Green interface
                     'ENABLE_SNORT'        => 'off' );      # Snort not enabled on Red interface

%proxy_settings  = ( 'UPSTREAM_PROXY'      => '' );         # No Proxy in use

%update_status   = ( 'ERROR'               => 0,            # Last run ended with error
                     'SNORT_UPDATE_STOPPED_SNORT'
                                           => 0,            # Count of times that update stopped Snort
                     'TALOS_VRT'           => '',           # MD5 for Talos VRT rules
                     'EMERGING_THREATS'    => '',           # MD5 for Emerging Threats rules
                     'COMMUNITY'           => '' );         # MD5 for Community rules

# Read the settings files

General::readhash($update_settings, \%update_settings) if (-e $update_settings);

# Check if it's time to run

exit if ($update_settings{'ENABLE'} ne 'on');

if ($update_settings{'RATE'} ne 'HOURLY' and not -t STDIN)
{
  my @timedate = localtime();

  exit if ($timedate[2] != 0);  # Only run just after midnight for hourly and weekly
  exit if ($update_settings{'RATE'} eq 'WEEKLY' and $timedate[6] != 0);  # Only run on Sundays for weekly
}

log_message LOG_INFO, "Starting Snort update check";

# Read the rest of the settings

General::readhash($snort_settings,  \%snort_settings)  if (-e $snort_settings);
General::readhash($mail_config,     \%mail_settings)   if (-e $mail_config);
General::readhash($update_status,   \%update_status)   if (-e $update_status);
General::readhash($proxy_settings,  \%proxy_settings)  if (-e $proxy_settings);

my $base_policy = $policies{$update_settings{POLICY}};

############################################################################
# Check to see if we can go ahead with an update
############################################################################

if (is_connected() and is_enough_disk_space( $tmp_dir ))
{
  debug 1, "Connection and disk space checks OK";

  # Read the Oinkmaster configuration file and work out which rule files are
  # ignored completely

  get_skipped_files( $oinkmaster_conf );

  # Read the Snort configuration to find out which rules files are in use

  parse_snort_config( $snort_conf );

  # Scan the rules files to determine which updates to look for and download
  # any available updates

  check_for_updates( $rule_dir );
}

############################################################################
# Process any available updates
############################################################################

if (@updates )
{
  create_rules_backup();

  # Parse the rule files before doing the update, to get the current state of the
  # rules

  log_message LOG_INFO, "Getting current rule state";
  parse_rule_files( \&parse_rule_file_pass_1, $rule_dir );

  # Generate the Oinkmaster configuration for each update

  generate_oinkmaster_config();

  # Update the rule files

  update_rules();

  # Re-parse the rule files and look for changes

  $rule_count = 0;
  %flowbits   = ();
  %flowgroups = ();

  log_message LOG_INFO, "Getting rule changes";
  parse_rule_files( \&parse_rule_file_pass_2, $rule_dir );

  # Iterate through the rules and check for old rules which do not exist in the
  # new rule set

  check_for_deleted_rules();

  # Update the oinkmaster configuration with the new list of enabled and
  # disabled rules.

  generate_oinkmaster_config();

  # Update the rules files a second time, with the updated enables and disables

  update_rules();

  if (($update_settings{'LIVE_UPDATE'} ne 'on') or
      ($update_status{'SNORT_UPDATE_STOPPED_SNORT'} > 10))
  {
    # Low memory - stop Snort
    # Use the Snort control program to stop snort

    log_message LOG_INFO, "Stopping Snort";

    system( $snort_control, "stop" );

    sleep 5;
  }

  # Check to see if the updated configuration has errors

  if (system( "$snort -c $snort_conf -T -q >>$detailed_log" ) > 0)
  {
    log_message LOG_ERR, "Snort rule check failed";

    $failure = 1;
    $success = 0;

    restore_rules_backup();

    if (($update_settings{'LIVE_UPDATE'} ne 'on') or
        ($update_status{'SNORT_UPDATE_STOPPED_SNORT'} > 10))
    {
      # Low memory - Use the Snort control program to start snort

      log_message LOG_INFO, "Starting Snort";

      system( $snort_control, "start" );

      sleep 5;
    }
  }
  else
  {
    # Tell the running instances of Snort to re-read the rules

    restart_snort();

    log_message LOG_INFO, "Completed update: $rule_count rules active";
  }

  # Send an email with the status, if enabled

  email_status() if ($update_settings{'EMAIL'} eq 'on' and $mail_settings{'USEMAIL'} eq 'on');

  # Check that used flowbits are set somewhere

  check_flowbits();
  expand_flowbit_groups();
}
else
{
  log_message LOG_INFO, "No updates available";
}

# Check whether all the expected instances of Snort are running and restart
# if necessary

check_running();

# Update the settings and status files if they've changed

if ($write_update_status)
{
  log_message LOG_INFO, "Writing new update status";
  General::writehash($update_status, \%update_status);
}

closelog();

exit;

#------------------------------------------------------------------------------
# sub create_rules_backup()
#
# Creates a backup of the current rule files
#------------------------------------------------------------------------------

sub create_rules_backup()
{
  system( "tar --create --absolute-names --gzip --file $rule_backup $rule_dir" );
}


#------------------------------------------------------------------------------
# sub restore_rules_backup()
#
# Restores a backup of the current rule files
#------------------------------------------------------------------------------

sub restore_rules_backup()
{
  system( "tar --extract --absolute-names --gzip --file $rule_backup $rule_dir" );
}


#------------------------------------------------------------------------------
# sub is_connected()
#
# Checks that the system is connected to the internet.
#
# This looks for a file created by IPFire when connected to the internet
#------------------------------------------------------------------------------

sub is_connected()
{
  return (-e "${General::swroot}/red/active");
}


#------------------------------------------------------------------------------
# sub is_enough_disk_space( path_to_directory )
#
# Checks that there is enough free space on the disk drive to download and
# process the update.
#
# Parameters:
#   path_to_directory  The path to a directory on the drive being checked.
#------------------------------------------------------------------------------

sub is_enough_disk_space( $ )
{
  my ($path) = @_;

  my @df = qx/$df -B M $path/;

  foreach my $line (@df)
  {
    next if $line =~ m/^Filesystem/;

    if ($line =~ m/dev/ )
    {
      $line =~ m/^.* (\d+)M.*$/;

      if ($1 < $free_space)
      {
        log_message LOG_WARNING, "$Lang::tr{'not enough disk space'} ${1}MB < ${free_space}MB";
        $failure = 1;
      }
      else
      {
        return 1;
      }
    }
  }

  return 0;
}


#------------------------------------------------------------------------------
# sub email_status()
#
# Sends an email with the status of the update.
#
# If an error occurs, further error emails are suppressed until a successful
# update occurs.
#------------------------------------------------------------------------------

sub email_status()
{
  # Create a new multipart message

  my $msg = MIME::Lite->new( From    => $mail_settings{'SENDER'},
                             To      => $mail_settings{'RECIPIENT'},
                             Subject => $Lang::tr{'idsupdate update status'},
                             Type    => 'multipart/mixed' );

  # Add parts (each "attach" has same arguments as "new"):

  if ($failure and not $success)
  {
    return if ($update_status{'ERROR'} eq 'on');

    $msg->attach( Type    => 'TEXT',
                  Data    => $Lang::tr{'idsupdate update failed'} );

    $update_status{'ERROR'} = 'on';
    $update_status          = 1;
  }
  elsif ($failure and $success)
  {
    $msg->attach( Type    => 'TEXT',
                  Data    => $Lang::tr{'idsupdate update partial'} );

    if ($update_status{'ERROR'} eq 'on')
    {
      $update_status{'ERROR'} = 'off';
      $update_status          = 1;
    }
  }
  else
  {
    $msg->attach( Type    => 'TEXT',
                  Data    => $Lang::tr{'idsupdate update success'} );

    if ($update_status{'ERROR'} eq 'on')
    {
      $update_status{'ERROR'} = 'off';
      $update_status          = 1;
    }
  }

  $msg->send_by_sendmail;
}

#------------------------------------------------------------------------------
# sub check_for_deleted_rules()
#
# Iterate through the rules and check for old rules which do not exist in the
# new rule set
#------------------------------------------------------------------------------

sub check_for_deleted_rules()
{
  foreach my $sid ( sort keys %rules )
  {
    if ($rules{$sid}[STATUS] eq 'old' and $rules{$sid}[ACTIVE])
    {
      $rules{$sid}[STATUS] = 'delete';
      log_message LOG_INFO, "Deleted rule sid:$sid $rules{$sid}[MESSAGE]" if (exists $rules{$sid}[MESSAGE]);
      $changed_sids++;
    }
  }
}


#------------------------------------------------------------------------------
# sub restart_snort()
#
# Tells Snort to re-read its rules.
#
# This can be done by means of a live update or by restarting Snort.
#
# For a live update, we have to monitor the instance of Snort to work out when
# it stopped doing the update.  This is necessary since doing the re-read of
# the rules consumes a lot of memory and therefore we need to ensure that we're
# only doing one at a time.
#
# Restarting Snort will stop all Snort processes and then restarting them one
# at a time, leaving the system partially unprotected for a while, however this
# uses less memory.
#------------------------------------------------------------------------------

sub restart_snort()
{
  if (($update_settings{'LIVE_UPDATE'} eq 'on') and
      ($update_status{'SNORT_UPDATE_STOPPED_SNORT'} <= 10))
  {
    # Perform a live update.  Send a SIGHUP to each instance of Snort in turn.
    # This causes that instance of Snort to create a new thread which will
    # parse the rule files.  When the parsing is complete, the rules in the
    # filtering part of Snort are swapped with the new rules.

    foreach my $pid ( qx/ps -C snort -o pid --no-headers/ )
    {
      my $count     = 0;
      my $cpu;
      my $last_cpu  = 0;
      my $delta_cpu = 0;
      my $max_cpu   = 0;
      my $last_mem  = 0;
      my $delta_mem = 0;
      my $mem;
      my $max_mem   = 0;

      my @fields;

      $pid =~ s/\s//g;

      next unless ($pid);

      # Get the current CPU and Memory usage

      open STAT, "<", "/proc/$pid/stat" or die "Can't open process stat: $!";

      my $line = <STAT>;

      close STAT;

      @fields    = split /\s+/, $line;

      $cpu       = $fields[13];
      $mem       = $fields[23];

      log_message LOG_INFO, "Telling Snort pid $pid to re-read rules";

      kill 'HUP', $pid;

      # Loop, monitoring the CPU and Memory usage of the process

      do
      {
        $last_cpu = $cpu;
        $last_mem = $mem;

        sleep 10;

        # Get the current CPU and Memory usage

        open STAT, "<", "/proc/$pid/stat" or die "Can't open process stat: $!";

        my $line = <STAT>;

        close STAT;

        @fields    = split /\s+/, $line;

        $cpu       = $fields[13];
        $mem       = $fields[22];

        $delta_cpu = $cpu - $last_cpu;
        $max_cpu   = $delta_cpu if ($delta_cpu > $max_cpu);
        $max_mem   = $mem       if ($mem > $max_mem);

        $count += 10;  # Because we're sleeping for 10 seconds
      }
      # Loop until the memory usage and CPU usage both drop from the maximum, or we time out
      while ((($delta_cpu > ($max_cpu * 0.9)) or ($mem >= $max_mem)) and ($count < $max_reread_wait));

      sleep 10;
    }
  }
  else
  {
    # Low memory.  Use the Snort control program to restart snort

    log_message LOG_INFO, "Starting Snort";

    system( $snort_control, "start" );

    sleep 5;
  }
}


#------------------------------------------------------------------------------
# sub check_running()
#
#
# Checks to see if Snort is running, and restarts it if necessary.
#
# Note that Snort can take a long time to start up, which is a problem if we
# catch it starting up, so if we don't have the expected snort instances
# running we wait for a while and try again, until we get a stable situation.
#
# If we're going to restart snort, we also make sure that we've shut down all
# instances, not just the ones we expect.
#------------------------------------------------------------------------------

sub check_running()
{
  my $number_not_running = 0;
  my $last_not_running   = 0;
  my $expected_running   = 0;

  log_message LOG_INFO, "Checking that Snort is running correctly";

  # Loop until the situation is stable

  do
  {
    # Check to see if the right Snort instances are running

    $last_not_running   = $number_not_running;
    $number_not_running = 0;
    $expected_running   = 0;

    if ($snort_settings{'ENABLE_SNORT_GREEN'} eq 'on')
    {
      if (not -e "/var/run/snort_green0.pid")
      {
        log_message LOG_ERR, "Snort not running on green";
        $number_not_running++;
      }

      $expected_running++;
    }

    if ($snort_settings{'ENABLE_SNORT_BLUE'} eq 'on')
    {
      if (not -e "/var/run/snort_blue0.pid")
      {
        log_message LOG_ERR, "Snort not running on blue";
        $number_not_running++;
      }

      $expected_running++;
    }

    if ($snort_settings{'ENABLE_SNORT_ORANGE'} eq 'on')
    {
      if (not -e "/var/run/snort_orange0.pid")
      {
        log_message LOG_ERR, "Snort not running on orange";
        $number_not_running++;
      }

      $expected_running++;
    }

    if ($snort_settings{'ENABLE_SNORT'} eq 'on')
    {
      if (not -e "/var/run/snort_red0.pid" and not -e "/var/run/snort_ppp0.pid")
      {
        log_message LOG_ERR, "Snort not running on red";
        $number_not_running++;
      }

      $expected_running++;
    }

    sleep 60 if ($number_not_running != 0);
  }
  while (($number_not_running != $last_not_running) and ($number_not_running > 0));

  # Also check that the right number of processes are running
  # This is because the Out-Of-Memory process killer does not delete the pid
  # file when it kills a process

  if ($number_not_running == 0)
  {
    $number_not_running = $expected_running - qx/ps -C snort -o pid --no-headers | wc -l/;
  }

  if ($number_not_running > 0)
  {
    # Need to restart.  Start by stopping Snort.

    log_message LOG_NOTICE, "Shutting down and restarting Snort";

    system( $snort_control, "stop" );

    sleep 5;

    # Check everything's shut down

    foreach my $pid ( qx/ps -C snort -o pid --no-headers/ )
    {
      $pid =~ s/\s+//g;

      next unless ($pid);

      kill 'TERM', $pid;
    }

    # Now start Snort again

    system( $snort_control, "start" );

    if (($changed_sids > 0) and ($update_status{'SNORT_UPDATE_STOPPED_SNORT'} <= 10))
    {
      # Snort not running after performing an update.
      # Maybe we haven't got enough memory - make a note and if it happens too
      # often stop using a live update.

      $update_status{'SNORT_UPDATE_STOPPED_SNORT'}++;
      $write_update_status = 1;
    }
  }
  elsif (($changed_sids > 0) and
         ($update_status{'SNORT_UPDATE_STOPPED_SNORT'} > 1) and
         ($update_settings{'LIVE_UPDATE'} eq 'on'))
  {
    # Everything's OK after an update.

    $update_status{'SNORT_UPDATE_STOPPED_SNORT'}--;
    $write_update_status = 1;
  }
}


#------------------------------------------------------------------------------
# sub update_rules()
#
# Calls Oinkmaster to update the rule files.
#
# Two configuration files are passed; the main Oinkmaster configuration, and a
# second file containing the list of rules to enable and disable.  This process
# has to be carried out once for each set of downloaded updates.
#------------------------------------------------------------------------------

sub update_rules()
{
  foreach my $update (@updates)
  {
    my ($file, $type, $name) = @{ $update };
    my $status;

    log_message LOG_INFO, "Updating $name rules";

    my $conf_file = "${General::swroot}/idsupdate/${type}_oinkmaster.conf";

    if (-e $conf_file)
    {
      $status = system( "$oinkmaster -v -s -u file://$file -C $oinkmaster_conf -C $conf_file -o $rule_dir >>$detailed_log 2>&1" );
    }
    else
    {
      $status = system( "$oinkmaster -v -s -u file://$file -C $oinkmaster_conf -o $rule_dir >>$detailed_log 2>&1" );
    }

    if ($status != 0)
    {
      log_message LOG_WARNING, "Oinkmaster failed returning $status";
      $failure = 1;
    }
    else
    {
      $success = 1;
    }
  }
}


#------------------------------------------------------------------------------
# parse_snort_config( config-file )
#
# Parses the Snort configuration file looking for rule files that are enabled.
#
# The action taken for a line depends on the command:
#
# include - If it's a rule file, remember the file otherwise parse the file for
#           further commands.
#
# var     - Remember the variable declaration.
#
# Variables referenced in include and variable commands are expanded.
#
# Parameters:
#   config-file The path to the config file
#------------------------------------------------------------------------------

sub parse_snort_config( $ )
{
  my ($path) = @_;

  my $fh;
  my %vars;

  debug 2, "Parse config file $path";

  open $fh, "<", $path or abort "Failed to open snort config file $path: $!";

  foreach my $line (<$fh>)
  {
    chomp $line;
    next unless ($line);
    next if ($line =~ m/^#/);

    if ($line =~ m/^include\s+(.*\.rules)$/)
    {
      # Include of rule file - record it

      my $file = $1;

      while ($file =~ m/\$(\w+)/)
      {
        my $var = $1;
        $file =~ s/\$$var/$vars{$var}/g;
      }

      $file =~ m#([^//]+\.rules)$#;
      $enabled_rule_files{ basename $1 } = "Enabled";
    }
    elsif ($line =~ m/^include\s+(.+)$/)
    {
      # Include of something else - process it

      my $file = $1;

      while ($file =~ m/\$(\w+)/)
      {
        $file =~ s/$1/$vars{$1}/g;
      }

      parse_snort_config( $1 );
    }
    elsif ($line =~ m/^var\s+(\S+)\s+(\S+)/)
    {
      # Variable - record it so we can substitute it

      $vars{$1} = $2;
    }
  }

  close $fh;
}


#------------------------------------------------------------------------------
# sub download_update( version-url, tarball-url, type )
#
# Downloads a version file and checks to see if the version is different from
# the one that's already on the system.  If it is different, downloads the
# update file.
#
# Parameters:
#   version-url The URL of the version file
#   tarball-url The URL of the tarball
#   type        The rule file type
#------------------------------------------------------------------------------

sub download_update( $$$$ )
{
  my ($version_url, $tarball_url, $type, $name) = @_;

  my $key = uc $type;
  my $current_md5;
  my $current_version = $update_status{$key} || "";
  my $status = 0;
  my $wget_proxy = '';

  debug 1, "Check for $name update";

  # Create a user agent for downloading the rule set's MD5 file

  my $ua = LWP::UserAgent->new( ssl_opts => { SSL_ca_file => $cert_file }, max_size => 10240 );

  # Get the Proxy settings

  if ($proxy_settings{'UPSTREAM_PROXY'})
  {
    my ($peer, $peerport) = (/^(?:[a-zA-Z ]+\:\/\/)?(?:[A-Za-z0-9\_\.\-]*?(?:\:[A-Za-z0-9\_\.\-]*?)?\@)?([a-zA-Z0-9\.\_\-]*?)(?:\:([0-9]{1,5}))?(?:\/.*?)?$/);

    if ($peer)
    {
      $wget_proxy = "--proxy=on --proxy-user=$proxy_settings{'UPSTREAM_USER'} --proxy-passwd=$proxy_settings{'UPSTREAM_PASSWORD'} -e http_proxy=http://$peer:$peerport/";

      $ua->proxy( "html", "http://$peer:$peerport/" );
    }
  }

  # Get the rule version from the internet

  my $request  = HTTP::Request->new(GET => $version_url);
  my $response = $ua->request($request);

  if (not $response->is_success)
  {
    log_message LOG_WARNING, "Failed to download $name version file $version_url: ". $response->status_line;
    $failure = 1;

    return;
  }

  my $new_version = $response->content;
  chomp $new_version;

  debug 1, "Versions: Old $current_version, new $new_version";

  if ($new_version ne $current_version)
  {
    # Need to download the new rules

    my $limit    = "";
    my ($output) = $tarball_url =~ m#([^//]+\.gz)#;

    if ($update_settings{'DOWNLOAD_LIMIT'} > 0)
    {
      my $kbytes = $update_settings{'DOWNLOAD_LIMIT'} / 8;
      $limit = "--limit-rate=${kbytes}k";
    }

    log_message LOG_INFO, "Download $name rules";

    if ($delete_log)
    {
      # Delete the old log file if this is the first time in this run

      unlink $detailed_log if ( -e $detailed_log );
      $delete_log = 0;
    }

    $status = system("$wget $wget_proxy --no-show-progress -o $detailed_log -O $tmp_dir/$output $limit $tarball_url");

    if ($status != 0)
    {
      log_message LOG_WARNING, "Failed to download $name rules $tarball_url: $status";
      $failure = 1;
    }
    else
    {
      # Check the download

      my $md5 = qx{ $md5sum $tmp_dir/$output };
      chomp $md5;

      $md5 =~ s/\s+.*$//;

      if ($md5 eq $new_version)
      {
        # The download was successful.  Record for later

        debug 1, "Download successful";

        push @updates, [ "$tmp_dir/$output", $type, $name];

        $update_status{$key} = $new_version;
        $write_update_status  = 1;

        copy $classtype_file, "$rule_dir/${key}_classification.config";

        if (not -e "$tmp_dir/snortrules.tar.gz" or (-M "$tmp_dir/snortrules.tar.gz") > (-M "$tmp_dir/$output"))
        {
          system( "touch -r $tmp_dir/$output $tmp_dir/snortrules.tar.gz" );
        }
      }
      else
      {
        log_message LOG_WARNING, "Download of $name rules failed checksum verification";
        $failure = 1;
      }
    }
  }
}


#------------------------------------------------------------------------------
# sub parse_classification_file( path )
#
# Reads a classification config file and extracts the priority for each
# classtype.
#
# Parameters:
#   path  Path to classification file
#------------------------------------------------------------------------------

sub parse_classification_file( $ )
{
  my ($path) = @_;

  open CLASS, "<", $path or abort "Can't open classification file $path: $!";

  debug 1, "Reading classification file $path";

  foreach my $line (<CLASS>)
  {
    chomp $line;
    next if ($line =~ m/^#/);
    next unless ($line);

    # Format: config classification: <classtype>,<description>,<priority>

    if ($line =~ m/^config\s+classification:/)
    {
      my (undef, $classtype, undef, $priority) = split /,\s*|:\s*/, $line;

      $classtype_priority{$classtype} = $priority;
    }
  }

  close CLASS;
}


#------------------------------------------------------------------------------
# sub check_for_updates( rule_dir )
#
# Scans the rule directory and works out which types of rule files are present.
#
# We have to do some processing to make sure that we don't download duplicate
# information:
#
# If we've got the community rules download the No-GPL version of the Emerging
# Threats rules.
#
# Parameters:
#   conf-rule_dir  The path to the directory containing the rule files
#------------------------------------------------------------------------------

sub check_for_updates( $ )
{
  my ($rule_dir) = @_;

  my $found_vrt       = 0;
  my $found_emerging  = 0;
  my $found_community = 0;

  my $et_v    = $emerging_threats_snort_version;
  my $vrt_v   = $talos_vrt_snort_version;

  my $Version = `snort -V 2>&1 | grep 'Version'`;
  my ($v) = $Version =~ m/(\d+\.[\d\.]*)/;
  $v =~ s/\.//g if ($v);
  $vrt_v = $v if ($v);

  ($v) = $Version =~ m/(\d+\.[\d\.]*)/;
  my @Version = split /\./, $v;
  $et_v       = join '.', @Version[0..1], '0';

  # Scan the rule directory and work out which types we've got

  opendir DIR, $rule_dir or abort "Can't open Snort rules dir $rule_dir: $!";

  foreach my $file (readdir DIR)
  {
    next if ($file =~ m/^\./);

    debug 2, "Rulefile $file";

    if ($file =~ m/classification\.config$/)
    {
      # The classification file maps the classtype to a default priority for
      # that classtype which we'll need later.

      parse_classification_file( "$rule_dir/$file" );
    }
    elsif ($file =~ m/^emerging-.*\.rules$/)
    {
      $found_emerging = 1;
    }
    elsif ($file eq 'community.rules')
    {
      $found_community = 1;
    }
    elsif ($file =~ /\.rules$/)
    {
      $found_vrt       = 1;
    }
  }

  # If we've found both the Talos VRT and Community rules remember it so that we can do
  # some special processing later

  $fix_community_rules = $found_community && $found_vrt && $enabled_rule_files{'community.rules'};

  # Check for updates

  if ($found_vrt and $snort_settings{OINKCODE})
  {
    # Download Talos VRT rules for either a subscription or a registered user.
    # The process is the same for each - the server sends different rules
    # depending on the Oinkcode

    download_update( "https://www.snort.org/rules/snortrules-snapshot-$vrt_v.tar.gz.md5\?oinkcode=$snort_settings{OINKCODE}",
                     "https://www.snort.org/rules/snortrules-snapshot-$vrt_v.tar.gz?oinkcode=$snort_settings{OINKCODE}",
                     "talos_vrt",
                     "Talos VRT registered or subscribed" );
  }

  if ($found_emerging and (not $found_community) and (not $found_vrt))
  {
    # No community rules, so download the Emerging Threats version that
    # includes them

    download_update( "https://rules.emergingthreats.net/open/snort-$et_v/emerging.rules.tar.gz.md5",
                     "https://rules.emergingthreats.net/open/snort-$et_v/emerging.rules.tar.gz",
                     "emerging_threats",
                     "Emerging Threats Open" );
  }

  if ($found_emerging and ($found_community or $found_vrt))
  {
    # We've got the community rules from another source, so download the
    # Emerging threats version that excludes them.

    download_update( "https://rules.emergingthreats.net/open-nogpl/snort-$et_v/emerging.rules.tar.gz.md5",
                     "https://rules.emergingthreats.net/open-nogpl/snort-$et_v/emerging.rules.tar.gz",
                     "emerging_threats",
                     "Emerging Threats Open No-GPL" );
  }

  if ($found_community)
  {
    # Download the community ruleset.

    download_update( "https://www.snort.org/downloads/community/community-rules.tar.gz.md5",
                     "https://www.snort.org/downloads/community/community-rules.tar.gz",
                     "community",
                     "Community" );
  }
}


#------------------------------------------------------------------------------
# sub get_skipped_files( conf-file )
#
# Parses the Oinkmaster configuration file and extracts the list of files that
# should not be processed.
#
# Parameters:
#   conf-file  The path to the Oinkmaster configuration file
#------------------------------------------------------------------------------

sub get_skipped_files( $ )
{
  my ($conf_file) = @_;

  debug 1, "Reading Oinkmaster configuration";

  open CONF, "<", $conf_file or abort "Can't open oinkmaster configuration file $conf_file: $!";

  foreach my $line (<CONF>)
  {
    next unless ($line =~ m/^skipfile/);

    chomp $line;

    my @files = split /[,\s]+/, $line;

    shift @files; # remove command from beginning of line

    foreach my $file (@files)
    {
      $skipped_files{$file} = 1;
    }
  }

  close CONF;
}


#------------------------------------------------------------------------------
# sub generate_oinkmaster_config
#
# Generate the oinkmaster configuration files, containing enablesid and
# disabledsid commands.
#
# We create one file for each of the downloads so that Oinkmaster doesn't
# complain about enabling non-existent SIDs for the SIDs defined in another
# download.  Note we will still get errors if rules are deleted.
#------------------------------------------------------------------------------

sub generate_oinkmaster_config( )
{
  foreach my $update (@updates)
  {
    my ($file, $type, $name) = @{ $update };
    my $status;

    my $conf_file = "${General::swroot}/idsupdate/${type}_oinkmaster.conf";

    # Create a new Oinkmaster config file.

    unlink $conf_file if ( -e $conf_file );

    open NEW_CONF, ">", $conf_file or abort "Can't open new config file $conf_file: $!";

    debug 1, "Update $name Oinkmaster configuration";

    # Write the list of enabled and disabled SIDs

    print_list( *NEW_CONF, "enablesid",  @{ $enabled_sids{$type} } );
    print_list( *NEW_CONF, "disablesid", @{ $disabled_sids{$type} } );

    close NEW_CONF;
  }
}


#------------------------------------------------------------------------------
# sub parse_rule_files( parse-function, directory )
#
# Scans the specified directory looking for rule files, skipping files
# specified in the Oinkmaster configuration file.
#
# Parameters
#   function  Function to be called to parse an individual rule file
#   directory Path to directory to be scanned
#------------------------------------------------------------------------------

sub parse_rule_files( $$ )
{
  my ($function, $directory) = @_;

  opendir RULEDIR, $directory or abort "Can't open rules directory $directory: $!";

  foreach my $name ( readdir RULEDIR )
  {
    next unless ($name =~ m/\.rules$/);
    next if (exists( $skipped_files{$name}) );

    &$function( "$directory/$name" );
  }

  closedir RULEDIR
}


#------------------------------------------------------------------------------
# sub print_line( file, command, list )
#
# Prints a list of SID commands to a file.  It will print a command followed by
# up to 10 SIDS on each line.
#
# Parameters:
#   file    - Reference to filehandle for output file
#   command - Command to be printed at the start of each line
#   list    - List of SIDS to be output
#------------------------------------------------------------------------------

sub print_list( $$@ )
{
  my ($file, $command, @list) = @_;
  my $number_on_line = 0;

  foreach my $sid (sort {$a <=> $b} @list)
  {
    if ($number_on_line == 0)
    {
      print $file "$command $sid";
      $number_on_line++;
    }
    elsif ($number_on_line < 10)
    {
      print $file ", $sid";
      $number_on_line++;
    }
    else
    {
      print $file ", $sid\n";
      $number_on_line = 0;
    }
  }

  print $file "\n" if ($number_on_line > 0);
}


#------------------------------------------------------------------------------
# sub parse_rule_file_pass_1( file-name )
#
# Parses a rule file and extracts the interesting rule options.  This is used
# generate a hash of hashes indexed by SID and option name.
#
# Parameters:
#   file-name - Path of rule file.
#------------------------------------------------------------------------------

sub parse_rule_file_pass_1( $ )
{
  my ($file) = @_;

  my $sid;
  my $options;
  my $active_rule_file = $enabled_rule_files{basename $file};

  debug 2, "Parsing rule file - Pass 1 - $file";

  open RULES, "<", $file or abort "Can't open rule file $file: $!";

  ($sid, $options) = get_rule( \*RULES );

  while ($sid)
  {
    if (exists $rules{$sid})
    {
      # Can get SIDs for community rules in more than one file

      if ($$options[ENABLED])
      {
        $rules{$sid}[ENABLED] = 1;
      }
    }
    else
    {
      $rules{$sid}         = $options;
      $rules{$sid}[STATUS] = 'old';
      $rules{$sid}[ACTIVE] = $active_rule_file;
    }

    ($sid, $options) = get_rule( \*RULES );
  }

  close RULES;
}


#------------------------------------------------------------------------------
# sub parse_rule_file_pass_2( file-name )
#
# Parses a rule file and extracts the interesting rule options.
# These are then used to decide what to do with a rule.
#
# If the rule didn't exist in the previous rule file its policy is compared
# with the base policy to decide whether the rule is to be enabled or not.
#
# If the rule is in the previous rule file it's left enabled or disabled, but
# it is examined for significant changes:
# - If it is enabled and the policy is greater than the base policy a change in
#   the classtype or revision, or an increase in policy or a decrease in priority
#   suggests the rule should be disabled.
# - If it is disabled and the policy is less than the base policy a change in
#   the classtype or policy, or a decrease in the policy or an increase in
#   priority suggests the rule should be enabled.
#
# If the rule file is active and the rule policy is changed then the rule will
# be optionally enable or disabled depending on the new policy, if the user
# option is set.
#
# Parameters:
#   file-name - Path of rule file.
#------------------------------------------------------------------------------

sub parse_rule_file_pass_2( $ )
{
  my ($file) = @_;

  my $sid;
  my $options;
  my $type;
  my $active_rule_file = $enabled_rule_files{basename $file};

  debug 2, "Parsing rule file - Pass 2 - $file";

  # What ruleset are we processing?

  if ( $file =~ m/\/community/ )
  {
    $type = "community";
  }
  elsif ( $file =~ m/\/emerging/ )
  {
    $type = "emerging_threats";
  }
  else
  {
    $type = "talos_vrt";
  }

  # Parse the file

  open RULES, "<", $file or abort "Can't open rule file $file: $!";
  ($sid, $options) = get_rule( \*RULES );

  while ($sid)
  {
    if ($type eq "talos_vrt" and $fix_community_rules and $$options[RULESET] eq 'community')
    {
      # This is a community rule in a non-community rule file and we're using the
      # community rule file.  Force this rule to disabled so that we use the community
      # version of the rule, which may be newer if this is the Talos VRT registered
      # rules.

      push @{ $disabled_sids{$type} }, $sid;
      ($sid, $options) = get_rule( \*RULES );

      next;
    }

    if (exists $rules{$sid})
    {
      my $policy_changed   = 0;
      my $revision_changed = 0;

      # Existing rule

      if ($rules{$sid}[ENABLED])
      {
        $rules{$sid}[STATUS] = 'enabled';

        if ($$options[POLICY] > $base_policy)
        {
          # Should it be disabled?
          # Look for changed fields in an order that gives the most
          # information to someone looking at the log.
          # 1 - classtype changed
          # 2 - more permissive policy
          # 3 - lower priority
          # 4 - revision changed

          if ($$options[CLASSTYPE] ne $rules{$sid}[CLASSTYPE])
          {
            $rules{$sid}[CHANGE_KEY] = 'Classtype';
            $rules{$sid}[FROM]       = $rules{$sid}[CLASSTYPE];
            $rules{$sid}[TO]         = $$options[CLASSTYPE];
          }
          elsif ($$options[POLICY] > $rules{$sid}[POLICY])
          {
            $rules{$sid}[CHANGE_KEY] = 'Policy';
            $rules{$sid}[FROM]       = $policies[$rules{$sid}[POLICY]];
            $rules{$sid}[TO]         = $policies[$$options[POLICY]];
            $policy_changed          = 1;
          }
          elsif ($$options[PRIORITY] > $rules{$sid}[PRIORITY])
          {
            $rules{$sid}[CHANGE_KEY] = 'Priority';
            $rules{$sid}[FROM]       = $rules{$sid}[PRIORITY];
            $rules{$sid}[TO]         = $$options[PRIORITY];
          }
          elsif ($$options[REVISION] != $rules{$sid}[REVISION])
          {
            $rules{$sid}[CHANGE_KEY] = 'Revision';
            $rules{$sid}[FROM]       = $rules{$sid}[REVISION];
            $rules{$sid}[TO]         = $$options[REVISION];
            $revision_changed        = 1;
          }

          if ($revision_changed)
          {
            if ($policy_changed and $update_settings{'APPLY_POLICY_CHANGE'} eq 'on')
            {
              $rules{$sid}[ENABLED] = 0;
              $rules{$sid}[STATUS]  = 'disabled';

              push @{ $disabled_sids{$type} }, $sid;

              if ($active_rule_file)
              {
                log_message LOG_INFO, "Disabled rule sid:$sid due to changed $rules{$sid}[CHANGE_KEY] from $rules{$sid}[FROM] to $rules{$sid}[TO]  $$options[MESSAGE]";
              }
            }
            else
            {
              push @{ $enabled_sids{$type} }, $sid;
              $rules{$sid}[STATUS] = 'enabled';

              if (exists $rules{$sid}[CHANGE_KEY])
              {
                if ($active_rule_file)
                {
                  log_message LOG_INFO, "Enabled rule sid:$sid changed $rules{$sid}[CHANGE_KEY] from $rules{$sid}[FROM] to $rules{$sid}[TO] $$options[MESSAGE]";
                }

                $rules{$sid}[STATUS] = 'ask-disable';
              }
            }
          }
        }
        else
        {
          push @{ $enabled_sids{$type} }, $sid;
          $rules{$sid}[STATUS] = 'enabled';
        }
      }
      else
      {
        $rules{$sid}[STATUS] = 'disabled';

        if ($$options[POLICY] < $base_policy)
        {
          # Should it be enabled?
          # Look for changed fields in an order that gives the most
          # information to someone looking at the log.
          # 1 - classtype changed
          # 2 - less permissive policy
          # 3 - higher priority
          # 4 - revision changed

          if ($$options[CLASSTYPE] ne $rules{$sid}[CLASSTYPE])
          {
            $rules{$sid}[CHANGE_KEY] = 'Classtype';
            $rules{$sid}[FROM]       = $rules{$sid}[CLASSTYPE];
            $rules{$sid}[TO]         = $$options[CLASSTYPE];
          }
          elsif ($$options[POLICY] < $rules{$sid}[POLICY])
          {
            $rules{$sid}[CHANGE_KEY] = 'Policy';
            $rules{$sid}[FROM]       = $policies[$rules{$sid}[POLICY]];
            $rules{$sid}[TO]         = $policies[$$options[POLICY]];
          }
          elsif ($$options[PRIORITY] < $rules{$sid}[PRIORITY])
          {
            $rules{$sid}[CHANGE_KEY] = 'Priority';
            $rules{$sid}[FROM]       = $rules{$sid}[PRIORITY];
            $rules{$sid}[TO]         = $$options[PRIORITY];
          }
          elsif ($$options[REVISION] != $rules{$sid}[REVISION])
          {
            $rules{$sid}[CHANGE_KEY] = 'Revision';
            $rules{$sid}[FROM]       = $rules{$sid}[REVISION];
            $rules{$sid}[TO]         = $$options[REVISION];
            $revision_changed        = 1;
          }

          if ($revision_changed)
          {
            if ($policy_changed and $update_settings{'APPLY_POLICY_CHANGE'} eq 'on')
            {
              $rules{$sid}[ENABLED] = 1;
              $rules{$sid}[STATUS]  = 'enabled';

              push @{ $enabled_sids{$type} }, $sid;

              if ($active_rule_file)
              {
                log_message LOG_INFO, "Enabled rule sid:$sid due to changed $rules{$sid}[CHANGE_KEY] from $rules{$sid}[FROM] to $rules{$sid}[TO]  $$options[MESSAGE]";
              }
            }
            else
            {
              push @{ $disabled_sids{$type} }, $sid;
              $rules{$sid}[STATUS] = 'disabled';

              if (exists $rules{$sid}[CHANGE_KEY])
              {
                if ($active_rule_file)
                {
                  log_message LOG_INFO, "Disabled rule sid:$sid changed $rules{$sid}[CHANGE_KEY] from $rules{$sid}[FROM] to $rules{$sid}[TO]  $$options[MESSAGE]";
                }

                $rules{$sid}[STATUS] = 'ask-enable';
              }
            }
          }
        }
        else
        {
          push @{ $disabled_sids{$type} }, $sid;
          $rules{$sid}[STATUS] = 'disabled';
        }
      }
    }
    else
    {
      # New rule

      $rules{$sid} = $options;
      $rules{$sid}[STATUS] = 'new';

      # Should it be enabled in the chosen policy?

      if ($$options[POLICY] <= $base_policy)
      {
        $rules{$sid}[ENABLED] = 1;
        push @{ $enabled_sids{$type} }, $sid;

        if ($active_rule_file)
        {
          log_message LOG_INFO, "Enabled new rule sid:$sid $$options[MESSAGE]";
          $changed_sids++;
        }
      }
      else
      {
        $rules{$sid}[ENABLED] = 0;
        push @{ $disabled_sids{$type} }, $sid;

        if ($active_rule_file)
        {
          log_message LOG_INFO, "Disabled new rule sid:$sid $$options[MESSAGE]";
          $changed_sids++;
        }
      }
    }

    if ( ($rules{$sid}[ENABLED] == 1) and $active_rule_file )
    {
      $rule_count++;
      $rules{$sid}[ACTIVE] = 1;
    }
    else
    {
      $rules{$sid}[ACTIVE] = 0;
    }

    ($sid, $options) = get_rule( \*RULES );
  }

  close RULES;
}


#------------------------------------------------------------------------------
# sub get_rule( file-handle )
#
# Reads a rule from the specified file and returns significant option fields.
# A rule can extend onto the next line if a line ends with a continuation
# character ('\').  In these case multiple lines are read from the file and
# concatenated to form the complete rule.
# Once the rule has been assembled, the options are extracted and then scanned
# to obtain the options we're interested in: message, priority, classtype,
# revision, policy, ruleset, sid and gid.  If no explicit priority is specified,
# it is inferred from the class type.
#
# For the policy the first item in the list connectivity, balanced, security
# and max-detect is chosen.  If no explicit policy is specified it is set to
# security if the rule is commented out or balanced otherwise (the default
# is that rules from balanced and connectivity policies are uncommented).
#
# Parameters:
#   file-handle - reference to the file handle of the rule file.
#
# Returns:
#   list containing: SID
#                    reference to a hash of (option-name, option-value) pairs.
#------------------------------------------------------------------------------

sub get_rule( $ )
{
  my ($rule_file) = @_;

  my $line;
  my $current_rule = "";
  my $enabled      = 0;
  my $message      = "";
  my $priority     = 0;
  my $classtype    = "";
  my $revision     = 0;
  my $policy       = 5;
  my $sid          = 0;
  my $gid          = 1;
  my $ruleset      = "";

  # Read lines from the file until we have a complete rule

  while ($line = <$rule_file>)
  {
    chomp $line;

    next unless ($line);

    next if (($line !~ m/#?\s*(alert|drop|log|pass|activate|dynamic|reject|sdrop)/) and not ($current_rule));

    # Line is part of a rule

    $current_rule .= $line;

    if ($line =~ m/\\$/)
    {
      # Continuation mark - go back for more
      $current_rule =~ s/\s*\\$/ /;
      next;
    }

    last if ($current_rule);
  }

  return undef unless ($current_rule);

  # A complete rule has been assembled.

  $enabled = 1 if ($current_rule !~ m/^#/);

  # Extract the options.

  $current_rule =~ s/^#\s*//;
  $current_rule =~ s/^[^(]*\(//;
  $current_rule =~ s/\)[^)]*$//;

  my @options = split /;\s+/, $current_rule;

  # Iterate through the options looking for the one's we're interested in.

  foreach my $option (@options)
  {
    $message   = $1 if ($option =~ m/^msg:\s*"(.*)"/);
    $revision  = $1 if ($option =~ m/^rev:\s*(.\d*)/);
    $priority  = $1 if ($option =~ m/^priority:\s*(\d*)/);
    $classtype = $1 if ($option =~ m/^classtype:\s*(.*)/);
    $sid       = $1 if ($option =~ m/^sid:\s*(.*)/);

    if ($option =~ m/^metadata:/)
    {
      $policy  = 4  if ($option =~ m/max-detect/   and $policy > 4);
      $policy  = 3  if ($option =~ m/security/     and $policy > 3);
      $policy  = 2  if ($option =~ m/balanced/     and $policy > 2);
      $policy  = 1  if ($option =~ m/connectivity/ and $policy > 1);
      $ruleset = $1 if ($option =~ m/ruleset\s*(\w+)/);
    }
  }

  # If no priority is specified, infer it from the class type.

  if ($priority == 0)
  {
    if (exists $classtype_priority{$classtype})
    {
      $priority = $classtype_priority{$classtype};
    }
    else
    {
      $priority = 4;
    }
  }

  # Check to see if a policy is set, and if not infer it from whether the rule
  # is commented or not.

  if ($policy == 5)
  {
    if ($enabled)
    {
      # Rule enabled, so the policy must be must be balanced or connectivity;
      # assume connectivity if the priority is 1, balanced otherwise.

      if ($priority == 1)
      {
        $policy = 1;
      }
      else
      {
        $policy = 2;
      }
    }
    else
    {
      # Rule disabled, so the policy must be max-detect or security;
      # assume max-detect if the priority is 4, security otherwise.

      if ($priority ==  4)
      {
        $policy = 4;
      }
      else
      {
        $policy = 3;
      }
    }
  }

  # Parse the flowbits for this rule

  my @flowbits = $current_rule =~ m/flowbits:\s*(.*?);/g;

  foreach my $flowbits( @flowbits)
  {
    my ($option, $bits, $group) = split /,\s*/, $flowbits;

    next if ($option eq 'noalert');
    next if ($option eq 'reset');

    $group = '' unless (defined $group);

    foreach my $flowbit (split /[&|]/, $bits)
    {
      if ($flowbit ne 'any' and $flowbit ne 'all')
      {
        # Add flowbit to group

        $flowbits{$flowbit}{':group'} = $group unless (defined $flowbits{$flowbit}{':group'} and $flowbits{$flowbit}{':group'} ne '');

        if ($option eq 'set' or $option eq 'setx' or $option eq 'toggle' or $option eq 'unset')
        {
          # Flowbit is set/unset in this rule

          $flowbits{$flowbit}{':set'}{$sid}         = $group;
          $flowgroups{$flowbits{$flowbit}{':group'}}{'flowbit'}{$flowbit} = 1;
        }

        if ($option eq 'setx')
        {
          # Group is set/unset in this rule

          $flowgroups{$flowbits{$flowbit}{':group'}}{':set'}{$sid} = 1;
        }

        if ($option eq 'isset' or $option eq 'isnotset')
        {
          # Flowbit is tested (tested) in this rule

          $flowbits{$flowbit}{':tst'}{$sid}         = $group;
          $flowgroups{$flowbits{$flowbit}{':group'}}{'flowbit'}{$flowbit} = 1;
        }
      }
      elsif ($group)
      {
        if ($option eq 'toggle')
        {
          # Group is set/unset in this rule

          $flowgroups{$group}{':set'}{$sid} = 1;
        }

        if ($option eq 'isset' or $option eq 'isnotset')
        {
          # Group is tested in this rule

          $flowgroups{$group}{':tst'}{$sid} = 1;
        }
      }
    }
  }

  debug 3, "Read rule SID $sid";

  return ( $sid, [ $message, $enabled, $priority, $revision, $classtype, $policy, $ruleset ] );
}


#------------------------------------------------------------------------------
# sub abort( message, parameters... )
#
# Aborts the update run, printing out an error message.
#
# Parameters:
#   message     Message to be printed
#------------------------------------------------------------------------------

sub abort( $ )
{
my ($message) = @_;

  log_message( LOG_ERR, $message );
  die $message;
}


#------------------------------------------------------------------------------
# sub log_message( level, message )
#
# Logs a message
#
# Parameters:
#   level   Severity of message
#   message Message to be logged
#------------------------------------------------------------------------------

sub log_message( $$ )
{
  my ($level, $message) = @_;

  print "($level) $message\n" if (-t STDIN);
  syslog( $level, $message );
}


#------------------------------------------------------------------------------
# sub debug( level, message )
#
# Optionally logs a debug message
#
# Parameters:
#   level   Debug level
#   message Message to be logged
#------------------------------------------------------------------------------

sub debug( $$ )
{
  my ($level, $message) = @_;

  if (($level <= $update_settings{'DEBUG'}) or
      ($level == 1 and -t STDIN))
  {
    log_message LOG_DEBUG, $message;
  }
}


#------------------------------------------------------------------------------
# sub expand_flowbit_groups()
#
# Iterates through the groups of flowbits, converting them into options on
# individual flowbits.
#------------------------------------------------------------------------------

sub expand_flowbit_groups()
{
  foreach my $group (keys %flowgroups)
  {
    next if ($group eq '');

    foreach my $flowbit (keys %{ $flowgroups{$group}{'flowbit'} })
    {
      foreach my $option ( ':set', ':tst' )
      {
        foreach my $sid (keys %{ $flowgroups{$group}{$option} })
        {
          $flowbits{$flowbit}{$option}{$sid} = $group;
        }
      }
    }
  }
}


#------------------------------------------------------------------------------
# sub check_flowbits()
#
# Iterates through the flowbits, looking for errors.
#
# A flowbit having an active reference without an active definition is an
# error. An active reference when not all definitions are active is a warning.
#------------------------------------------------------------------------------

sub check_flowbits()
{
  my $file_open = 0;

  unlink $flowbit_warnings if (-e $flowbit_warnings);

  foreach my $flowbit (sort keys %flowbits)
  {
    my $active  = 0;
    my $warning = 0;
    my $error   = 0;
    my $group   = $flowbits{$flowbit}{':group'};

    # Check to see if this flowbit is referenced in a test as part of an active rule

    foreach my $sid (keys %{ $flowbits{$flowbit}{':tst'} })
    {
      $active |= $rules{$sid}[ACTIVE];
    }

    if ($active)
    {
      $error = 1;

      # This flowbit is referenced in an active rule.
      # Check to see if it is defined in an active rule

      foreach my $sid (keys %{ $flowbits{$flowbit}{':set'} })
      {
        if ($rules{$sid}[ACTIVE])
        {
          $error = 0;
        }
        else
        {
          $warning = 1;
        }
      }
    }

    # Output the Warnings or Errors

    if ($error)
    {
      unless ($file_open)
      {
        open FLOW, '>', $flowbit_warnings or abort "Can't open flowbit warnings file $flowbit_warnings: $!";
        $file_open = 1;
      }

      print FLOW "[$group:$flowbit]\n";
      foreach my $sid (keys %{ $flowbits{$flowbit}{':set'} })
      {
        print FLOW "set||$sid||" . ($rules{$sid}[ACTIVE] ? 'enabled' : 'disabled') . "||$rules{$sid}[MESSAGE]\n";
      }
      foreach my $sid (keys %{ $flowbits{$flowbit}{':tst'} })
      {
        next unless ($rules{$sid}[ACTIVE]);
        print FLOW "tst||$sid||" . ($rules{$sid}[ACTIVE] ? 'enabled' : 'disabled') . "||$rules{$sid}[MESSAGE]\n";
      }
    }
  }

  close FLOW if ($file_open);
}
