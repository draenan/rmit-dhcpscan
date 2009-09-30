#!/usr/pkg/bin/perl
# $Id$

##########################################################################
# dhcpscan.pl
#
# Scans log files for dhcp activity and builds a web page showing status
# for each requested subnet.  That is, how many times an IP address
# has been acknowledged, first time, last time, hostname, suspected
# status (available, statically assigned, etc.)
#
# This will only work on subnets /24 or smaller, and is pretty much
# only guaranteed to run on ns1.cs (subject to the note below.)
# Virtually no input sanitizing is done.
#
# No liability, no warranty, AS IS, etc.
#
# NOTE: Due to the size of the log files, this needs a lot of memory to
#       run (approx 260-280MB).  The default limit for datasize is
#       insufficient for this.  Accordingly, it is suggested you run
#       "limit datasize 290000" prior to running this (assuming tcsh).
##########################################################################

$|++;
use strict;
use Class::Struct;
use IO::Zlib;
use Net::DNS;
use Net::Ping;
use POSIX "strftime";

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
#                               Aho                     (010.11.017)
# 131.170.206.64/26:            Bolam                   (010.11.022)
# 131.170.206.128/26:           
# 131.170.206.192/26:           Babbage                 (014.09.023)
# 131.170.207.0/26:     CS Printers
# 131.170.207.64/26:    Roaming laptops, mobiles, Wiis
# 131.170.207.128/26:   Yoursoftware lab
# 131.170.207.192/26:   Non-CS staff                    (010.11)

################################
# START USER CHANGEABLE CONFIG
################################

my $cachedir     = "/var/dhcpscan/cache/";
my $logfile      = "/var/log/daemon";
my $oldlogs      = "/var/log/daemon.d/";
my $searchstr    = "DHCPACK (to|on)";   # Search logs for this string.
my $numoldfiles  = 15;                  # DELETE cache files if you change this.
my $outputdir    = "/var/dhcpscan/";

################################
# END USER CHANGEABLE CONFIG
################################

my $now          = strftime("%Y%m%d-%H%M%S", localtime);
my $outputfile   = $outputdir."dhcpscan-".$now.".html";
my $cachefile    = $cachedir."cache.gz";
my $lastfile     = $cachedir."lastfile";
my $rebuild      = 0;                     # Rebuild the cache (default NO)
my $rebuildfrom  = 0;                     # Array index: rebuild from this file

my @subnets;

# Script needs EUID root privs to read log files and ping with ICMP.

die "Need to run as root.\n" unless ($< == 0);

# Check command line arguments for subnets to check.

if (@ARGV == 0) {
    print "Usage: dhcpscan.pl subnet [...]\n";
    print "       where subnet is a subnet in CIDR format (/24 or smaller).\n";
    print "       eg 131.170.27.0/25\n";
    exit 1;
}

foreach (@ARGV) {
    if (/\d{3}\.\d{3}\.\d{1,3}\.\d{1,3}\/\d{2}/) {
        push (@subnets, $_);
    }
    else {
        print "Invalid argument.\n";
        exit 1;
    }
}

print "**** Working on log files ****\n";

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
# Actually, the use of "$#files" instead of "@files" here and
# elsewhere seems less than ideal; can't remember why I used it
# but it works so I'm not "fixing" it.

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

if (@files > 0 and $rebuildfrom < @files) {
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

    print "Total of ".@logdata." matching lines.\n";

# Write out the collected data to the cache files.

    print "Writing out new cache file.\n";
    $fh->open($cachefile, "wb") or
        die "Could not open $cachefile: $!\n";
    foreach my $line (@logdata) {
        $fh->print($line);
    }
    $fh->close;
    open LASTFILE, ">", $lastfile or die "Could not open $lastfile: $!";
    print LASTFILE $files[$#files]."\n";
    close LASTFILE;
} 

# Get data from the active log file.

my $line;
print "Gathering  data from the active log file.\n";
open CURRENTLOG, "<", $logfile or die "Could not open $logfile: $!";
while ($line = <CURRENTLOG>) {
    next unless $line =~ /$searchstr/;
    push (@logdata, $line);
}
close CURRENTLOG;

print "Data gathering complete.\n";
print @logdata." total matching lines.\n";

# Set up array to contain the data structures for subnet address data and
# initialize a resolver.

struct ipaddr_data => { count       => '$',
                        address     => '$',
                        hostname    => '@',
                        first       => '$',
                        last        => '$',
                        notes       => '@' };
my @data;
my $res = Net::DNS::Resolver->new;
my $p   = Net::Ping->new("icmp", 1);

# Go through each line in the logdata array looking for info for each subnet
# and put it into the data array.

foreach my $subnet (@subnets) {

# Gather information about the subnet for use in building the individual
# subnet data array.

    my ($subnet_addr, $cidr_prefix) = split (/\//, $subnet);
    my ($sub_octs, $host_oct) = ($subnet_addr =~ /(.*\..*\..*)\.(.*)/);
    my $bcast_host = (2 ** (32 - $cidr_prefix)) - 1 + $host_oct;
    my $subnet_bcast_addr  = join ('.', $sub_octs, $bcast_host);
    my $subnet_router_addr = join ('.', $sub_octs, ($bcast_host - 1)); 

# Create and initialize the structs for the subnet data array.

    print "\n*** Working on subnet $subnet ***\n";
    print "Creating data structures...   ";

    my @subnet_data = map { ipaddr_data->new } 0..($bcast_host - $host_oct);

# Fill in known information (address, hostname, host role, etc)
    
    for (my $host = 0; $host < @subnet_data; $host++) {
        if ($host == 0) {
            $subnet_data[$host]->address($subnet_addr);
            $subnet_data[$host]->count(-1);
            push @{ $subnet_data[$host]->notes }, "Network address";
        }
        elsif ($host == ($#subnet_data - 1)) {
            $subnet_data[$host]->address($subnet_router_addr);
            $subnet_data[$host]->count(-1);
            push @{ $subnet_data[$host]->notes }, "Router address";
        }
        elsif ($host == $#subnet_data) {
            $subnet_data[$host]->address($subnet_bcast_addr);
            $subnet_data[$host]->count(-1);
            push @{ $subnet_data[$host]->notes }, "Broadcast address";
        }
        else {
            my $address = join ('.', $sub_octs, ($host + $host_oct));
            $subnet_data[$host]->count(0);
            $subnet_data[$host]->address($address);
        }

# Get hostname for all hosts other than the network and broadcast address.

        unless (( $host == 0 ) or ( $host == $#subnet_data )) {
            my $query = $res->query($subnet_data[$host]->address);
            if ($query) {
                foreach my $rr ($query->answer) {
                    next unless $rr->type eq "PTR";
                    push @{ $subnet_data[$host]->hostname }, $rr->rdatastr;
                }
            } else {
                push @{ $subnet_data[$host]->hostname }, "UNKNOWN";
                if ( $res->errorstring eq 'NXDOMAIN') {
                    push @{ $subnet_data[$host]->notes }, "AVAILABLE";
                }
                else {
                    push @{ $subnet_data[$host]->notes }, $res->errorstring;
                }
            }
        }
    } 
    print "done.\n";

# Search the logdata array for data relating to the current subnet.

    print "Populating data structures... ";

    foreach my $line (@logdata) {
        next unless $line =~ /$sub_octs/;

# Extract data from the log line and populate the relevant host record with
# the information.  The conditional is needed to cater for the use of subnets
# smaller than /24.  The use of "count" is slightly off, given that the
# DHCP server frequently sends more than one DHCPACK.

        my ($date, $host) = ($line =~ /^(.*:\d{2}).*DHCP.*?\d{1,3}\.\d{1,3}\.\d{1,3}\.(\d{1,3})/);
        if ( ($host > $host_oct) and ($host < $bcast_host)) {
            $host -= $host_oct;
            $subnet_data[$host]->last($date);
            $subnet_data[$host]->first($date) unless defined $subnet_data[$host]->first;
            $subnet_data[$host]->count($subnet_data[$host]->count + 1);
        }
    }
    $fh->close;
    print "done.\n";

# Push the array of subnet data onto the main array.

    push (@data, \@subnet_data);
}

# Create the output file.

print "\n**** Generating output file (may take a while - pinging some hosts)  ****\n";
print "Sending output to $outputfile ... ";

open OUTFILE, ">", $outputfile or die "Could not open $outputfile: $!";

print OUTFILE <<EOT;
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN"
"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en">
    <head>
        <meta http-equiv="Content-Type" content="text/html;charset=utf-8" /> 
        <style type="text/css">
        <!--
            body {
            	background-color: white;
                color: black;
                font-size: small;
                font-family: Arial, Helvetica, sans-serif;
            }
            table {
            	border: 2px solid black;
            	border-collapse: collapse;
            }
            th {
		        background-color: #cccccc;
            	border: 1px solid black;
            	border-bottom-width: 2px;
            	padding: 5px 5px 5px 5px;
            }
            td {
            	border: 1px solid black;
            	padding: 5px 5px 5px 5px;
            }
            a:visited {
            	color: blue;
            }
            .available {
            	background-color: #99ff99;
            }
            .unusable {
           	    background-color: #ff9999;
            }	
            .static {
           	    background-color: #ffff99;
            }	
            .footer {
            	font-size: small;
            	font-style: italic;
            }
        -->
        </style>    
        <title>dhcpscan.pl - Run on $now</title>
    </head>
    <body>
    	<h1><em>dhcpscan.pl</em></h1>
    	<p>Subnets:</p>
        <ul>
EOT

my $counter = 0;
foreach my $subnet (@subnets) {
    print OUTFILE "            <li><a href=\"#subnet-$counter\">$subnet</a></li>\n";
    $counter++;
}

print OUTFILE <<EOT;
        </ul>
        <hr />
EOT

$counter = 0;
foreach my $subnet (@subnets) {
    print OUTFILE "        <h3 id=\"subnet-$counter\">$subnet</h3>\n";

    print OUTFILE <<EOT;
        <table>
            <tr>
                <th>Count</th>
                <th>IP Address</th>
                <th>Hostname</th>
                <th>First Appearance</th>
                <th>Last Appearance</th>
                <th>Notes</th>
            </tr>
EOT

    foreach my $subnet ($data[$counter]) {
        foreach my $ipaddr (@$subnet) {

# Why the hell would I be getting a "Use of uninitialized value in string eq"
# warnings here for values of count not equal to -1 or 0?  A diagnostic print
# before the "if" and after the "else" show that $ipaddr->count *is* defined.
# Simple solution?  Disable warnings.  Grr.

            if ($ipaddr->count == -1) {
                print OUTFILE "            <tr class=\"unusable\">\n";
            }
            elsif ( ($ipaddr->count == 0) or ($ipaddr->notes(0) eq "AVAILABLE") ) {
                if ($p->ping($ipaddr->address)) {
                    print OUTFILE "            <tr class=\"static\">\n";
                    push @{ $ipaddr->notes }, "Responded to ping";
                }
                else {
                    print OUTFILE "            <tr class=\"available\">\n";
                    if ( ($ipaddr->count == 0) and ($ipaddr->hostname(0) ne "UNKNOWN") ) {
                        push @{ $ipaddr->notes }, "Available?";
                    }
                }
            }
            else {
                print OUTFILE "            <tr>\n";
            }
            print OUTFILE "                <td style=\"text-align: right\">";
            if ($ipaddr->count == -1) {
                print OUTFILE "&nbsp;</td>\n";
            }
            else {
                print OUTFILE $ipaddr->count."</td>\n";
            }
            print OUTFILE "                <td>".$ipaddr->address."</td>\n";
            print OUTFILE "                <td>";
            if ($ipaddr->hostname(0)) {
                foreach my $hostname (@{$ipaddr->hostname}) {
                    print OUTFILE $hostname."<br />";
                }
                print OUTFILE "</td>\n";
            }
            else {
                print OUTFILE "&nbsp;</td>\n";
            }
            print OUTFILE "                <td>";
            if (not defined $ipaddr->first) {
                print OUTFILE "&nbsp;</td>\n";
            }
            else {
                print OUTFILE $ipaddr->first."</td>\n";
            }
            print OUTFILE "                <td>";
            if (not defined $ipaddr->last) {
                print OUTFILE "&nbsp;</td>\n";
            }
            else {
                print OUTFILE $ipaddr->last."</td>\n";
            }
            print OUTFILE "                <td>";
            if ($ipaddr->notes(0)) {
                foreach my $note (@{$ipaddr->notes}) {
                    print OUTFILE $note."<br />";
                }
                print OUTFILE "</td>\n";
            }
            else {
                print OUTFILE "&nbsp;</td>\n";
            }
            print OUTFILE "            </tr>\n";
        }
    }

print OUTFILE <<EOT;
        </table>
        <p><a href=\"#\">^</a></p>
EOT

$counter++;
}

print OUTFILE <<EOT;
        <hr />
        <div class=\"footer\">
            <p>dhcpscan.pl run on $now</p>
            <p>Valid XHTML 1.1</p>
        </div>
    </body>
</html>
EOT

close OUTFILE;

print "done.\n";
exit 0;
    
# vi: set tabstop=4 shiftwidth=4 expandtab si ai nu:
