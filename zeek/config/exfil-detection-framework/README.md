Exfil Framework
=====
The Exfil Framework is a suite of Zeek scripts that detect file uploads in TCP connections. The Exfil Framework can detect file uploads in most TCP sessions including sessions that have encrypted payloads (SCP,SFTP,HTTPS).  This file was originally created by reservoirlabs, but needed modification to work with Zeek 3.0.0.  This file was edited by Richard Medlin. 

Summary
---------
The Exfil framework detects file uploads by watching connections for 'bursts' in upstream traffic. A 'burst' is an event where the upstream byte rate of a connection surpasses a particular threshold (2000 bytes/sec by default). If the burst is sustained for more than a particular number of bytes (~65K by default), a Exfil::File_Transfer Notice will be issued.

### Implementation
The Exfil Framework contains four Zeek scripts:

1. **main.zeek** - The script that drives the Exfil Framework. You probably do not want to edit this file.
2. **app-exfil-conn.zeek** - The script that attaches the Exfil Framework to connections. You will want to edit the redefs exported by this script to choose which connections get monitored for file uploads. **Note:** Start small. If this script is attached to a lot of connections, it may negatively impact the amount of traffic your Zeek sensor can process.
3. **app-exfil-after-hours.zeek** - A policy script that issues a Notice if a file upload is detected after the business hours of your organization. You will want to edit the redefs exported by this file to define the appropriate business hours of your organization.
4. **__load__.zeek** - A wrapper that enables all Exfil Framework scripts with one line of configuration. You will not need to edit this file.

Quick Start
------------

```
* Enable the Exfil framework by adding the following line to your local.zeek:
```
@load exfil-detection-framework
```
* Redefine networks monitored for exfil in your local.bro:
```
redef Exfil::watched_subnets_conn = [x.x.x.x/x, y.y.y.y/y]; 
```
* Redefine the business hours of your network in your local.zeek (start_time and end_time must be specified on 24 hour clock):
```
redef Exfil::hours = [ $start_time=x, $end_time=y ];
```
