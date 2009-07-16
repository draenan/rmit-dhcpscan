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
# 131.17/0.207.128/26:   Yoursoftware lab
# 131.170.207.192/26:   Non-CS staff                    (010.11)


################################
# START USER CHANGEABLE CONFIG
################################

my $cachedir     = "/home/adrianw/var/dhcpscan/";
my $logfile      = "/home/adrianw/var/log/daemon";
my $oldlogs      = "/home/adrianw/var/log/daemon.d/";
my $searchstr    = "DHCPACK to";   # Search logs for this string.
my $numoldfiles  = 15;             # DELETE cache files if you change this.
my $outputdir    = "./";

# These are the subnets which we will search the logs for.

my @subnets = qw ( 131.170.26.0/25
                   131.170.26.128/25
                   131.170.27.0/25 );

################################
# END USER CHANGEABLE CONFIG
################################


my $now          = strftime("%Y%m%d-%H%M%S", localtime);
my $outputfile   = $outputdir."dhcpdscan-".$now.".html";
my $cachefile    = $cachedir."cache.gz";
my $lastfile     = $cachedir."lastfile";
my $rebuild      = 0;                     # Rebuild the cache (default NO)
my $rebuildfrom  = 0;                     # Array index: rebuild from this file


# Script needs root privs to read log files and ping with ICMP.

#die "Need to run as root.\n" unless ($EUID == 0);

# Check to see if both files necessary to the cache exist.

if ( ! -e $cachefile or ! -e $lastfile ) {
    print "Could not find one or both cache files.  Rebuilding cache.\n";
    $rebuild = 1;
}

# Gather a list of old log files.  The regex stops "." and ".." from being
# copied to the array.

opendir(DIR, $oldlogs) or die "Could not open $oldlogs: $!";
my @files = sort grep (!/^\.(\.)?$/, readdir(DIR));
closedir(DIR);

# Not much point trying to read more files than actually exist...

if ( $#files < $numoldfiles ) {
    $numoldfiles = $#files;
}

# Trim the files array of all but the files we want to check and initialize
# an array for the data and a file handle for the gzipped archived log
# files.

@files = @files[($#files - $numoldfiles + 1)..($#files)];

my @logdata;
my $fh = new IO::Zlib;

# Skip this block if we don't need to rebuild the cache.

if ( ! $rebuild ) {

# Check for the name of the last archived log file that we processed.
# Check to see if that file is among the list of files that we will be
# processing this time.  "rebuildfrom" is used as an index into the files
# array so we know where to start processing.

    open LASTFILE, "<", $lastfile or die "Could not open $lastfile: $!";
    my $filename = <LASTFILE>;
    close LASTFILE;
    chomp $filename;
    print "The last archive file added to the cache was ".$filename."\n";
    my $foundlast = 0;
    foreach (@files) {
        $rebuildfrom++;
        if ( $_ =~ /$filename/ ) {
            $foundlast++;
            last;
        }
    }

    if ( ! $foundlast ) {

# The last archive files we processed isn't in the list of files to process
# now, so the cache is old and needs to be rebuilt from scratch.

        print $filename." was not found in the list of files to read.\n";
        print "The cache will be rebuilt.\n";
        $rebuild = 1;
        $rebuildfrom = 0;
    }

    if ( ! $rebuild) {

# As we don't need to rebuild the cache, we need to trim the old data from
# the head of the cache.

        print "Reading and trimming cache file.\n";
        
# Open the first archived log file in our list to be processed and determine
# the content of the first line that matches what we are looking for.

        $fh->open($oldlogs.$files[0], "rb") or
            die "Could not open ".$oldlogs.$files[0].": $!";
        my $line;
        my $firstline;
        while ($firstline = $fh->getline()) {
            last if $firstline =~ /$searchstr/;
        }
        $fh->close;

# Once we know what we are looking for, scan through the cache file,
# discarding every line until we get to the one we want.  After that, start
# loading the data array with lines from the cache.

        $fh->open($cachefile, "rb") or
            die "Could not open $cachefile: $!";
        while ($line = $fh->getline()) {
            last if $line eq $firstline;
        }
        while ($line) {
            push (@logdata, $line);
            $line = $fh->getline();
        }
        $fh->close;
    }
}

# If there are new archive files to process (either through new additions
# to the archive directory for the cache file, or a cache rebuild,) do so.

if ($#files > 0 and $rebuildfrom <= $#files) {
    print "Add to cache starting with file ".$files[$rebuildfrom]."\n";

# Only process those files that we need to by using the rebuildfrom
# index to trim the files array.
    
    if ( $rebuildfrom > 0 ) {
        @files = @files[$rebuildfrom..$#files];
    }

# Open each archived log file that we are interested in, get a line from
# it, and add it to the logdata array if it matches what we are looking
# for.

    my $line;
    foreach my $file (@files) {
        $fh->open($oldlogs.$file, "rb") or
            die "Could not open $oldlogs.$file: $!";
        print "Scanning $file for lines containing \"$searchstr\"\n";
        while ($line = $fh->getline()) {
            next unless $line =~ /$searchstr/;
            push (@logdata, $line);
        }
    }
    print "Total of $#logdata matching lines.\n";

# Write out the collected data to the cache files.

    print "Writing out new cache file.\n";
    $fh->open($cachefile, "wb") or
        die "Could not open $cachefile: $!\n";
    foreach my $line (@logdata) {
        $fh->print($line);
    }
    $fh->close;
    open LASTFILE, ">", $lastfile or die "Could not open $lastfile: $!";
    print LASTFILE $files[$#files];
    close LASTFILE;
}

# vi: set tabstop=4 shiftwidth=4 expandtab si ai nu:
