# dhcpscan.pl

Scans log files for DHCP activity and builds a web page showing status
for each requested subnet.  That is, how many times an IP address
has been acknowledged, first time, last time, hostname, suspected
status (available, statically assigned, etc.)

Existence of this script proves that I once used to write scripts in Perl.
Whether or not I did it *well* is up for interpretation.


## History

Back in the days when Schools at RMIT managed their own infrastructure, someone
had an idea to take the subnets allocated to the School of Computer Science and
split them up into small subnets based on building and floor.  So where most
areas of RMIT were using /24 subnets, CS tended to use /25 or /26.

This probably would have been maintainable in the long term if:

* People didn't have multiple devices (they did)
* Staff didn't want static IP addresses for their devices across multiple
  locations (they did)`
* Old records were cleaned up (they weren't)
* Staff continued to be distributed across buildings and floors (they were
  eventually moved into one building.)

By the time I started as a Unix Sysadmin at RMIT the IT Support functions had
been centralised, but there was still various legacy environments such as the
CS one to maintain, so I started off there.  It became quickly apparent that
the assignment of static IP addresses was not sustainable; this script was my
response.

Of course the fact that I was the only one to ever use it suggests that it was
ultimately a failed effort, but eventually RMIT consolidated DNS/DHCP services
into an Infoblox grid and IP address allocation stopped being something
I needed to worry about.

