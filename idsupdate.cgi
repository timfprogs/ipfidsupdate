#!/usr/bin/perl

###############################################################################
#                                                                             #
# IPFire.org - A linux based firewall                                         #
#                                                                             #
# This program is free software: you can redistribute it and/or modify        #
# it under the terms of the GNU General Public License as published by        #
# the Free Software Foundation, either version 3 of the License, or           #
# (at your option) any later version.                                         #
#                                                                             #
# This program is distributed in the hope that it will be useful,             #
# but WITHOUT ANY WARRANTY; without even the implied warranty of              #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the               #
# GNU General Public License for more details.                                #
#                                                                             #
# You should have received a copy of the GNU General Public License           #
# along with this program.  If not, see <http://www.gnu.org/licenses/>.       #
#                                                                             #
###############################################################################

#enable only the following on debugging purpose
use strict;
use warnings;
use CGI qw/:standard/;
use CGI::Carp 'fatalsToBrowser';

require '/var/ipfire/general-functions.pl';
require "${General::swroot}/lang.pl";
require "${General::swroot}/header.pl";

#Initialize variables and hashes
my $settings     = "${General::swroot}/idsupdate/settings";
my $mailsettings = "${General::swroot}/dma/mail.conf";
my $mainsettings = "${General::swroot}/main/settings";
my $qossettings  = "${General::swroot}/qos/settings";
my %checked;
my $msg;
my $infomessage;
my %mainsettings = ();
my %cgiparams=();
my $errormessage = '';
my %color;
my %settings;
my %stats;
my %mailsettings;
my $tmpdir       = '/var/tmp';

# Read all parameters for site
Header::getcgihash(\%cgiparams);
General::readhash($mainsettings, \%mainsettings);
General::readhash($mailsettings, \%mailsettings) if (-e $mailsettings);
General::readhash("/srv/web/ipfire/html/themes/".$mainsettings{'THEME'}."/include/colors.txt", \%color);

# Show Headers
Header::showhttpheaders();

if (-r $settings)
{
  General::readhash($settings, \%settings);
}
else
{
  # No settings file - set up defaults

  my %qossettings = ( 'DEF_INC_SPD' => 5000 );

  # The QOS is used to suggest a maximum download speed

  General::readhash($qossettings, \%qossettings) if (-e $qossettings);

  %settings = ( 'ENABLE'              => 'off',
                'RATE'                => 'DAILY',
                'POLICY'              => 'BALANCED',
                'DOWNLOAD_LIMIT'      => $qossettings{'DEF_INC_SPD'}/2,
                'LIVE_UPDATE'         => 'on',
                'APPLY_POLICY_CHANGE' => 'on',
                'FORCE_POLICY'        => 'off',
                'VERSION'             => 3,
                'DEBUG'               => 0 );
}

# ACTIONS

if ($cgiparams{'ACTION'} eq $Lang::tr{'save'})
{ #SaveButton on configsite

  # Check params

  if ($cgiparams{'DOWNLOAD_LIMIT'} =~ m/\D/)
  {
    $errormessage = $Lang::tr{'idsupdate invalid input for download limit'}
  }

  # These settings will be overwritten if enabled

  $settings{'ENABLE'}              = 'off';
  $settings{'LIVE_UPDATE'}         = 'off';
  $settings{'APPLY_POLICY_CHANGE'} = 'off';
  $settings{'FORCE_POLICY'}        = 'off';
  $settings{'EMAIL'}               = 'off';


  foreach my $item (keys %cgiparams)
  {
    $settings{$item} = $cgiparams{$item} if (exists $settings{$item});
  }

  $settings{'LIVE_UPDATE'} = $settings{'LIVE_UPDATE'} eq 'on' ? 'off' : 'on';

  General::writehash( "$settings", \%settings );

  if(!$errormessage)
  {
    $settings{'DOWNLOAD_LIMIT'} = 0;
  }
  else
  {
    $cgiparams{'update'} = 'on';
    configsite();
  }
}

#Show site
configsite();

#FUNCTIONS
sub configsite
{
  #find preselections
  my $enable = 'checked';

  #Open site
  Header::openpage($Lang::tr{'idsupdate ids update'}, 1, '');
  Header::openbigbox('100%', 'left');
  error();
  info();

  # ----- Configuration -----

  Header::openbox('100%', 'left', $Lang::tr{'idsupdate config'});

  #### JAVA SCRIPT ####
  print<<END;
<script>
  \$(document).ready(function()
  {
    // Show/Hide elements when ENABLE checkbox is checked.
    if (\$("#ENABLE").attr("checked")) {
      \$(".params").show();
    } else {
      \$(".params").hide();
    }

    // Toggle update elements when "ENABLE" checkbox is clicked
    \$("#ENABLE").change(function() {
      \$(".params").toggle();
    });
  });
</script>
END
;
  ##### JAVA SCRIPT END ####

  if ($settings{'ENABLE'} eq 'on')
  {
    $enable = 'checked';
  }
  else
  {
    $enable = '';
  }

  print<<END;
  <form method='post' action='$ENV{'SCRIPT_NAME'}'>
  <table style='width:100%' border='0'>
  <tr>
    <td style='width:24em'>$Lang::tr{'idsupdate enable automatic update'}</td>
    <td><label><input type='checkbox' name='ENABLE' id='ENABLE' $enable></label></td>
  </tr>
  </table><br>

END
;

  my $hourly_selected        = $settings{'RATE'} eq 'HOURLY'            ? "selected='selected'" : '';
  my $daily_selected         = $settings{'RATE'} eq 'DAILY'             ? "selected='selected'" : '';
  my $weekly_selected        = $settings{'RATE'} eq 'WEEKLY'            ? "selected='selected'" : '';

  my $connectivity_selected  = $settings{'POLICY'} eq 'CONNECTIVITY'    ? "selected='selected'" : '';
  my $balanced_selected      = $settings{'POLICY'} eq 'BALANCED'        ? "selected='selected'" : '';
  my $security_selected      = $settings{'POLICY'} eq 'SECURITY'        ? "selected='selected'" : '';
  my $maxdetect_selected     = $settings{'POLICY'} eq 'MAXDETECT'       ? "selected='selected'" : '';

  my $low_memory_selected    = $settings{'LIVE_UPDATE'} eq 'off'        ? 'checked' : '';
  my $apply_changes_selected = $settings{'APPLY_POLICY_CHANGE'} eq 'on' ? 'checked' : '';
  my $force_policy_selected  = $settings{'FORCE_POLICY'} eq 'on'        ? 'checked' : '';
  my $email_selected         = $settings{'EMAIL'} eq 'on'               ? 'checked' : '';

  print <<END
<div class='params'>
  <table width='100%' cellspacing='1'>
    <tr>
      <td>$Lang::tr{'idsupdate rate'}</td>
      <td>
        <select name='RATE' style='width:22em;'>
          <option value='HOURLY' $hourly_selected>$Lang::tr{'idsupdate hourly'}</option>
          <option value='DAILY' $daily_selected>$Lang::tr{'idsupdate daily'}</option>
          <option value='WEEKLY' $weekly_selected>$Lang::tr{'idsupdate weekly'}</option>
        </select>
      </td>
    </tr>
    <tr>
      <td>$Lang::tr{'idsupdate download limit'}</td>
      <td><input type='number' name='DOWNLOAD_LIMIT' value='$settings{'DOWNLOAD_LIMIT'}' style='width:22em;'></td>
    </tr>
    <tr>
      <td>$Lang::tr{'idsupdate default policy'}
      <td>
        <select name='POLICY' style='width:22em;'>
          <option value='CONNECTIVITY' $connectivity_selected>$Lang::tr{'idsupdate policy connectivity'}</option>
          <option value='BALANCED' $balanced_selected>$Lang::tr{'idsupdate policy balanced'}</option>
          <option value='SECURITY' $security_selected>$Lang::tr{'idsupdate policy security'}</option>
          <option value='MAX-DETECT' $maxdetect_selected>$Lang::tr{'idsupdate policy max-detect'}</option>
        </select>
      </td>
    </tr>
  <tr>
    <td style='width:24em'>$Lang::tr{'idsupdate low memory usage'}</td>
    <td><label><input type='checkbox' name='LIVE_UPDATE' id='LIVE_UPDATE' $low_memory_selected></label></td>
  </tr>
  <tr>
    <td style='width:24em'>$Lang::tr{'idsupdate apply policy change'}</td>
    <td><label><input type='checkbox' name='APPLY_POLICY_CHANGE' id='APPLY_POLICY_CHANGE' $apply_changes_selected></label></td>
  </tr>
  <tr>
    <td style='width:24em'>$Lang::tr{'idsupdate force policy change'}</td>
    <td><label><input type='checkbox' name='FORCE_POLICY' id='FORCE_POLICY' $force_policy_selected></label></td>
  </tr>
END
;

  if ($mailsettings{'USEMAIL'} eq 'on')
  {
    print <<END
  <tr>
    <td style='width:24em'>$Lang::tr{'idsupdate enable email'}</td>
    <td><label><input type='checkbox' name='EMAIL' id='EMAIL' $email_selected></label></td>
  </tr>
END
;
  }
  print <<END
  </table>
  <br><br>
  <table width='100%'>
  <tr>
    <td align='right'><input type='hidden' name='ACTION2' value='snort' /><input type='submit' name='ACTION' value='$Lang::tr{'save'}' /></td>
  </tr>
  </table>
</form>
</div>
END
;

  Header::closebox();

  # ----- Status -----

  if ($settings{'ENABLE'} eq 'on')
  {
    Header::openbox('100%', 'left', $Lang::tr{'idsupdate status'});

    print <<END
  <table>
    <tr><th style='width:24em'>$Lang::tr{'idsupdate ruleset'}</th><th>$Lang::tr{'idsupdate last updated'}</th></tr>
END
;
    opendir DIR, $tmpdir or die "Can't open temporary dir: $!";

    foreach my $file (sort readdir DIR)
    {
      my $name;

      if ($file eq 'community-rules.tar.gz')
      {
        $name = 'Community';
      }

      if ($file eq 'emerging.rules.tar.gz')
      {
        $name = 'Emerging Threats';
      }

      if ($file =~ m/snortrules-/)
      {
        $name = 'Talos VRT';
      }

      if ($name)
      {
        my @Info = stat( "$tmpdir/$file" );
        my $date = localtime( $Info[9] );

        print "<tr><td>$name</td><td>$date</td></tr>\n";
      }
    }

    closedir DIR;

    print <<END
  </table>
END
;

    Header::closebox();
  }

  Header::closebigbox();
  Header::closepage();
  exit 0;
}


sub info
{
  if ($infomessage)
  {
    Header::openbox('100%', 'left', $Lang::tr{'info messages'});
    print "<class name='base'>$infomessage\n";
    print "&nbsp;</class>\n";
    Header::closebox();
  }
}

sub error
{
  if ($errormessage)
  {
    Header::openbox('100%', 'left', $Lang::tr{'error messages'});
    print "<class name='base'>$errormessage\n";
    print "&nbsp;</class>\n";
    Header::closebox();
  }
}
