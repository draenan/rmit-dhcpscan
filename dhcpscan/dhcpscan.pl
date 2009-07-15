#!/usr/pkg/bin/perl
# $Id$

##########################################################################
# dhcpscan.pl
#
# Scans log files for dhcp activity and builds a web page showing status
# per each requested subnet.  That is, how many times an IP address
# has been acknowledged, first time, last time, hostname, response to
# a test ping.
#
##########################################################################

use strict;
use warnings;
use Class::Struct;
use IO::Zlib;
use Net::DNS;
use Net::Ping;
use POSIX "strftime";
use English "-no_match_vars";

# These are the city subnets maintained on ns1.cs

# 131.170.24.0/24:      CS Servers                      (010.10)
# 131.170.25.0/25:      Research
# 131.170.25.128/25:    Former TSG                      (010.10)
# 131.170.26.0/25:      CS Staff                        (014.11)
# 131.170.26.128/25:    CS Staff                        (014.08)
# 131.170.27.0/25:      CS Staff                        (014.09)
# 131.170.27.128/25:    Unused
# 131.170.65.0/24:      CS Infrastructure
# 131.170.66.0/24:      CS Infrastructure
# 131.170.204.0/26:     Labs:   Games Studio            (014.11.037)
# 131.170.204.64/26:            Sutherland                      
# 131.170.204.128/26:           Alice
# 131.170.204.192/26:           RMIT Training
# 131.170.205.0/26:             Beard                   (014.10.032)
# 131.170.205.64/26:            Salomaa                 (010.11.023)
# 131.170.205.128/26:           Knuth                   (014.10.031)
# 131.170.205.192/26:           Lions                   (014.10.030)
# 131.170.206.0/26:             Hopper                  (014.09.015)
# 131.170.206.64/26:            Aho                     (010.11.017)
# 131.170.206.128/26:           Bolam                   (010.11.022)
# 131.170.206.192/26:           Babbage                 (014.09.023)
# 131.170.207.0/26:     CS Printers
# 131.170.207.64/26:    Roaming laptops, mobiles, Wiis
# 131.170.207.128/26:   Yoursoftware lab
# 131.170.207.192/26:   Non-CS staff                    (010.11)

# These are the subnets for which we will search for log  entries.

my @subnets = qw ( 131.170.26.0/25
                   131.170.26.128/25
                   131.170.27.0/25 );

my $cachedir     = "/home/adrianw/var/dhcpscan/";
my $cachefile    = $cachedir."cache.gz";
my $lastfile     = $cachedir."lastfile";
my $rebuild      = 0;
my $rebuildfrom  = 0;
my $logfile      = "/home/adrianw/var/log/daemon";
my $oldlogs      = "/home/adrianw/var/log/daemon.d/";
my @logdata;
my $searchstr    = "DHCPACK to";
my $numoldfiles  = 15;

my $now          = strftime("%Y%m%d-%H%M%S", localtime);
my $outputdir    = "./";
my $outputfile   = $outputdir."dhcpdscan-".$now.".html";

# Script needs root privs to read log files and ping with ICMP.

#die "Need to run as root.\n" unless ($EUID == 0);

if ( ! -e $cachefile or ! -e $lastfile ) {
    print "Could not find one or both cache files.  Rebuilding cache.\n";
    $rebuild = 1;
}

# Gather data from the log files.

opendir(DIR, $oldlogs) or die "Could not open $oldlogs: $!\n";
my @files = sort grep (!/^\.(\.)?$/, readdir(DIR));
closedir(DIR);

if ( $#files < $numoldfiles ) {
    $numoldfiles = $#files;
}

@files = @files[($#files - $numoldfiles + 1)..($#files)];

if ( ! $rebuild ) {
    open LASTFILE, "<", $lastfile;
    my $filename = <LASTFILE>;
    close LASTFILE;
    chomp $filename;
    print "The last file added to the cache was ".$filename."\n";
    foreach (@files) {
        $rebuildfrom++;
        last if ( $_ =~ /$filename/ );
    }
    if ( $rebuildfrom > $#files ) {
        print $filename." was not found in the list of files to read.\n";
        print "The cache will be rebuilt.\n";
        $rebuild = 1;
        $rebuildfrom = 0;
    }
}

print "Add to cache starting with file ".$files[$rebuildfrom]."\n";

if ( $rebuildfrom > 0 ) {
    @files = @files[$rebuildfrom..$#files];
}

foreach (@files) {
    printf $_."\n";
}

print "Last log file: ".$files[$#files]."\n";
exit;

my $fh = new IO::Zlib;

if ($#files > 0) {
    my $line;
    foreach my $file (@files) {
        $fh->open($oldlogs.$file, "rb") or
            die "Could not open $oldlogs.$file: $!\n";
        print "Scanning $file for lines containing \"$searchstr\"\n";
        while ($line = $fh->getline()) {
            next unless $line =~ /$searchstr/;
            push (@logdata, $line);
        }
    }
    print "Total of $#logdata matching lines found.\n";
}


# vi: set tabstop=4 shiftwidth=4 expandtab si ai nu:
