#!/usr/bin/perl
###############################################################################
#                                                                             #
# IPFire.org - A linux based firewall                                         #
# Copyright (C) 2015  IPFire Team  <alexander.marx@ipfire.org>                #
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
use warnings;
use CGI::Carp 'fatalsToBrowser';
use Sort::Naturally;

require '/var/ipfire/general-functions.pl';
require "${General::swroot}/lang.pl";
require "${General::swroot}/header.pl";

my $group;
my $flowbit;
my @sets;
my @tests;
my $row = 0;

#Read all parameters for site
&General::readhash("${General::swroot}/main/settings", \%mainsettings);
&General::readhash("/srv/web/ipfire/html/themes/".$mainsettings{'THEME'}."/include/colors.txt", \%color);

#Show Headers
&Header::showhttpheaders();
&Header::openpage($Lang::tr{'snrtupd flowbit warning list'}, 1, '');
&Header::openbigbox('100%', 'center');
&error;
&Header::openbox('100%', 'left', $Lang::tr{'snrtupd flowbit warning list'});
&info;
&Header::closebox();
&Header::closebigbox();	
&Header::closepage();
exit 0;

sub info
{
  unless (-e '/var/tmp/flowbit-warnings.txt')
  {
    print "$Lang::tr{'snrtupd flowbit file not found'}\n";
    return;
  }
  
  print "<p>$Lang::tr{'snrtupd flowbit warning explaination'}</p>\n";
  
  open IN, '<', '/var/tmp/flowbit-warnings.txt' or die "Can't open flowbit-warnings.txt: $!";
  
  print "<table class=\"tbl\">\n";

  print "<tr><th>$Lang::tr{'snrtupd group'}</th><th>Flowbit</th><th>$Lang::tr{'snrtupd type'}</th><th>SID</th><th>$Lang::tr{'snrtupd state'}</th><th>$Lang::tr{'snrtupd name'}</th></tr>\n";

  for my $line (<IN>)
  {
    chomp $line;
    next unless ($line);
    
    if ($line =~ m/\[(.*?)\:(.*)\]/)
    {
      show( $group, $flowbit, \@sets, \@tests );
      
      @sets    = ();
      @tests   = ();
      $group   = $1 ? $1 : '[default]';
      $flowbit = $2;
    }
    else
    {
      my ($type, $sid, $state, $name) = split/\|\|/, $line;
      
      push @sets,  [$sid, $state, $name ] if ($type eq 'set');
      push @tests, [$sid, $state, $name ] if ($type eq 'tst');
    }
  }

  close IN;

  show( $group, $flowbit, \@sets, \@tests );

  print "</table>\n";
  
  my @Info = stat( "/var/tmp/flowbit-warnings.txt" );
  my $update_time = localtime($Info[9]);
  print "<br /><p>$Lang::tr{'snrtupd flowbit update time'}: $update_time</p>\n";
}

sub show
{
  my ($group, $sid, $sets, $tests) = @_;
  
  my @sets  = @{ $sets };
  my @tests = @{ $tests };
  
  if (@sets + @tests)
  {
    my $lines  = @sets + @tests;
    my $first  = 1;
    my $colour = '';
    my $border = "border-top:2px solid #A0A0A0;";
    my $style  = '';
    
    print "<tr><td rowspan=$lines style=\"$border\">$group</td><td rowspan=$lines style=\"$border\">$flowbit</td>";
    print "<td rowspan=" . scalar(@sets) . " style=\"$border\">$Lang::tr{'snrtupd set'}</td>" if (@sets);
    
#    foreach my $def (sort { ncmp( $$a[0], $$b[0]) } @sets)
    foreach my $def (sort { $$a[0] <=> $$b[0] } @sets)
    {
      my ($sid, $state, $name) = @{ $def };
      my $colour = '';

      if ($sid < 1000000)
      {
        $sid = "<a href=\"https://www.snort.org/rule-docs/1-$sid\" target=\"_blank\">$sid</a>";
      }
      elsif ($sid >= 2000000 and $sid < 3000000)
      {
        $sid = "<a href=\"http:/doc.emergingthreats.net/$sid\" target=\"_blank\">$sid</a>";
      }
      
      if ($first)
      {
        $first = 0;
      }
      else
      {
        print "<tr>";
      }
      
      if ($row % 2)
      {
        $colour = "background-color:$color{'color20'};";
      }
      else
      {
        $colour = "background-color:$color{'color22'};";
      }

      
      if ($border or $colour)
      {
        $style="style=\"$colour$border\"";
      }
      else
      {
        $style = '';
      }
      
      print "<td $style>$sid</td><td $style>$state</td><td $style>$name</td></tr>\n";
      
      $row++;
      $border = '';
    }

    if (@sets)
    {
      $border = "border-top:2px dotted #A0A0A0;";
      print "<tr>";
    }
    
    print "<td rowspan=" . scalar(@tests) . " style=\"$border\">$Lang::tr{'snrtupd test'}</td>";
    $first = 1;

    foreach my $ref (sort { ncmp( $$a[0], $$b[0] ) } @tests)
    {
      my ($sid, $state, $name) = @{ $ref };
      my $colour = '';

      if ($sid < 1000000)
      {
        $sid = "<a href=\"https://www.snort.org/rule-docs/1-$sid\" target=\"_blank\">$sid</a>";
      }
      elsif ($sid >= 2000000 and $sid < 3000000)
      {
        $sid = "<a href=\"http:/doc.emergingthreats.net/$sid\" target=\"_blank\">$sid</a>";
      }

      if ($first)
      {
        $first = 0;
      }
      else
      {
        print "<tr>";
      }
      
      if ($row % 2)
      {
        $colour = "background-color:$color{'color20'};";
      }
      else
      {
        $colour = "background-color:$color{'color22'};";
      }
      
      if ($border or $colour)
      {
        $style="style=\"$colour$border\"";
      }
      else
      {
        $style = '';
      }
      
      print "<td $style>$sid</td><td $style>$state</td><td $style>$name</td></tr>\n";
      
      $row++;
      $border = '';
    }
  }
}

sub error
{
}
