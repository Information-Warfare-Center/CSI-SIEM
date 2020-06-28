##! Local site policy. Customize as appropriate.
##!
##! This file will not be overwritten when upgrading or reinstalling!

#  This file has been modified by Richard Medlin.  

# This script logs which scripts were loaded during each run.
@load misc/loaded-scripts

# Apply the default tuning scripts for common tuning settings.
@load tuning/json-logs
redef LogAscii::json_timestamps = JSON::TS_ISO8601;
redef LogAscii::use_json = T;
#  Enable the following to ignore bad checksums.  The will help when
#  Zeek stops analyzing packets with bad check sums locally.  
redef ignore_checksums = T;
# Estimate and log capture loss.
@load misc/capture-loss

# Enable logging of memory, packet and lag statistics.
@load misc/stats

# Load the scan detection script.
@load misc/scan

# Detect traceroute being run on the network. This could possibly cause
# performance trouble when there are a lot of traceroutes on your network.
# Enable cautiously.
#@load misc/detect-traceroute

# Generate notices when vulnerable versions of software are discovered.
# The default is to only monitor software found in the address space defined
# as "local".  Refer to the software framework's documentation for more
# information.
@load frameworks/software/vulnerable

# Detect software changing (e.g. attacker installing hacked SSHD).
@load frameworks/software/version-changes

# This adds signatures to detect cleartext forward and reverse windows shells.
@load-sigs frameworks/signatures/detect-windows-shells

# Load all of the scripts that detect software in various protocols.
@load protocols/ftp/software
@load protocols/smtp/software
@load protocols/ssh/software
@load protocols/http/software
@load protocols/rdp/indicate_ssl
# The detect-webapps script could possibly cause performance trouble when
# running on live traffic.  Enable it cautiously.
#@load protocols/http/detect-webapps

# This script detects DNS results pointing toward your Site::local_nets
# where the name is not part of your local DNS zone and is being hosted
# externally.  Requires that the Site::local_zones variable is defined.
@load protocols/dns/detect-external-names

# Script to detect various activity in FTP sessions.
@load protocols/ftp/detect

# Scripts that do asset tracking.
@load protocols/conn/known-hosts
@load protocols/conn/known-services
@load protocols/ssl/known-certs

# This script enables SSL/TLS certificate validation.
@load protocols/ssl/validate-certs

# This script prevents the logging of SSL CA certificates in x509.log
@load protocols/ssl/log-hostcerts-only

# Uncomment the following line to check each SSL certificate hash against the ICSI
# certificate notary service; see http://notary.icsi.berkeley.edu .
#  @load protocols/ssl/notary

# If you have GeoIP support built in, do some geographic detections and
# logging for SSH traffic.
@load protocols/ssh/geo-data
# Detect hosts doing SSH bruteforce attacks.
@load protocols/ssh/detect-bruteforcing
# Detect logins using "interesting" hostnames.
@load protocols/ssh/interesting-hostnames

# Detect SQL injection attacks.
@load protocols/http/detect-sqli

#### Network File Handling ####

# Enable MD5 and SHA1 hashing for all files.
@load frameworks/files/hash-all-files

# Detect SHA1 sums in Team Cymru's Malware Hash Registry.
@load frameworks/files/detect-MHR

# Extend email alerting to include hostnames
@load policy/frameworks/notice/extend-email/hostnames

# Uncomment the following line to enable detection of the heartbleed attack. Enabling
# this might impact performance a bit.
@load policy/protocols/ssl/heartbleed

# Added on my own to test out.
@load policy/tuning/track-all-assets
# Uncomment the following line to enable logging of connection VLANs. Enabling
# this adds two VLAN fields to the conn.log file.
@load policy/protocols/conn/vlan-logging

# Uncomment the following line to enable logging of link-layer addresses. Enabling
# this adds the link-layer address for each connection endpoint to the conn.log file.
@load policy/protocols/conn/mac-logging


# custom scripts below


@load http-basic-auth.zeek  
@load tor.zeek
@load udpscan.zeek
@load dir-mod.zeek
@load ssh-attack.zeek

#Exfiltration Monitoring after hours add the following:
@load exfil-detection-framework
#  Redefine networks monitored for exfil in your local.zeek:
#  change IP x.x.x.x/x, y.y.y.y/y to your networks that you want
#  to be monitor.
redef Exfil::watched_subnets_conn = [10.211.55.0/24, 192.168.0.0/24];
#  Redefine the business hours of your network in your local.zeek 
#  (start_time and end_time must be specified on 24 hour clock):
redef Exfil::hours = [ $start_time=2359, $end_time=0600 ];
#  Producer Consumer Ratio for detecting PCR on the network nodes to 
#  help pinpoint potential problems.

@load producer-consumer-ratio
@load cryptomining
@load dnstunnel.zeek
@load rdp
@load smtp
@load dns-zone-trans.zeek
@load creditcardcaptures
@load ftp-bruteforce.zeek
@load http-stalling.zeek
@load http-attack.zeek
@load http-pass.zeek

