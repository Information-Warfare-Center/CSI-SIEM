##! UDP Scan detection
##!
##! ..Authors: Seth Hall
##!            Aashish Sharma

@load base/frameworks/notice
@load base/frameworks/sumstats

@load base/utils/time

module ScanUDP;

export {
	redef enum Notice::Type += {
		## Address scans detect that a host appears to be scanning some number
		## of destinations on a single port. This notice is generated when more
		## than :bro:id:`Scan::addr_scan_threshold` unique hosts are seen over
		## the previous :bro:id:`Scan::addr_scan_interval` time range.
		Address_Scan,

		## Port scans detect that an attacking host appears to be scanning a
		## single victim host on several ports.  This notice is generated when
		## an attacking host attempts to connect to
		## :bro:id:`Scan::port_scan_threshold`
		## unique ports on a single host over the previous
		## :bro:id:`Scan::port_scan_interval` time range.
		Port_Scan,
	};

	## Failed connection attempts are tracked over this time interval for the address
	## scan detection.  A higher interval will detect slower scanners, but may also
	## yield more false positives.
	const addr_scan_interval = 5min &redef;

	## The threshold of a unique number of hosts a scanning host has to have failed
	## connections with on a single port.
	const addr_scan_threshold = 25.0 &redef;

	## Failed connection attempts are tracked over this time interval for the port scan
	## detection.  A higher interval will detect slower scanners, but may also yield
	## more false positives.
	const port_scan_interval = 5min &redef;

	## The threshold of a number of unique ports a scanning host has to have failed
	## connections with on a single victim host.
	const port_scan_threshold = 15.0 &redef;
}

event zeek_init() &priority=5
	{
	local r1: SumStats::Reducer = [$stream="scanudp.addr.fail", $apply=set(SumStats::UNIQUE), $unique_max=double_to_count(addr_scan_threshold+2)];
	SumStats::create([$name="addr-scan-udp",
	                  $epoch=addr_scan_interval,
	                  $reducers=set(r1),
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	return result["scanudp.addr.fail"]$unique+0.0;
	                  	},
	                  #$threshold_func=check_addr_scan_threshold,
	                  $threshold=addr_scan_threshold,
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	local r = result["scanudp.addr.fail"];
	                  	local side = Site::is_local_addr(key$host) ? "local" : "remote";
	                  	local dur = duration_to_mins_secs(r$end-r$begin);
	                  	local message=fmt("%s scanned at least %d unique hosts on UDP port %s in %s", key$host, r$unique, key$str, dur);
	                  	NOTICE([$note=Address_Scan,
	                  	        $src=key$host,
	                  	        $p=to_port(key$str),
	                  	        $sub=side,
	                  	        $msg=message,
	                  	        $identifier=cat(key$host)]);
	                  	}]);

	# Note: port scans are tracked similar to: table[src_ip, dst_ip] of set(port);
	local r2: SumStats::Reducer = [$stream="scanudp.port.fail", $apply=set(SumStats::UNIQUE), $unique_max=double_to_count(port_scan_threshold+2)];
	SumStats::create([$name="port-scan-udp",
	                  $epoch=port_scan_interval,
	                  $reducers=set(r2),
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	return result["scanudp.port.fail"]$unique+0.0;
	                  	},
	                  $threshold=port_scan_threshold,
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	local r = result["scanudp.port.fail"];
	                  	local side = Site::is_local_addr(key$host) ? "local" : "remote";
	                  	local dur = duration_to_mins_secs(r$end-r$begin);
	                  	local message = fmt("%s scanned at least %d unique UDP ports of host %s in %s", key$host, r$unique, key$str, dur);
	                  	NOTICE([$note=Port_Scan,
	                  	        $src=key$host,
	                  	        $dst=to_addr(key$str),
	                  	        $sub=side,
	                  	        $msg=message,
	                  	        $identifier=cat(key$host)]);
	                  	}]);
	}

function add_sumstats(id: conn_id, reverse: bool)
	{
	local scanner      = id$orig_h;
	local victim       = id$resp_h;
	local scanned_port = id$resp_p;

	if ( reverse )
		{
		scanner      = id$resp_h;
		victim       = id$orig_h;
		scanned_port = id$orig_p;
		}

	SumStats::observe("scanudp.addr.fail", [$host=scanner, $str=cat(scanned_port)], [$str=cat(victim)]);
	SumStats::observe("scanudp.port.fail", [$host=scanner, $str=cat(victim)], [$str=cat(scanned_port)]);
	}

function watch_callback(c: connection, cnt: count): interval
	{
	if ( c$resp$state == UDP_INACTIVE &&
	     c$orig$state == UDP_ACTIVE &&
	     c$orig$size > 0 && c$resp$size == 0 )
		{
		#print "Add a udp sumstat " + cat(c$id);
		add_sumstats(c$id, F);
		return -1secs;
		}
	return 1sec;
	}

event new_connection(c: connection)
	{
	if ( is_udp_port(c$id$resp_p) )
		ConnPolling::watch(c, watch_callback, 0, 1sec);
	}

event icmp_unreachable(c: connection, icmp: icmp_conn, code: count, context: icmp_context)
	{
	if ( is_udp_port(context$id$resp_p) && 
	     context$id$resp_h == c$id$orig_h && # Only allow the resp of the initial packet
	     context$id$orig_h == c$id$resp_h && # to send unreachable messages.
	     ! context$bad_checksum )
		{
		#print "Add a udp sumstat from icmp " + cat(context);
		add_sumstats(context$id, F);
		}
	}
