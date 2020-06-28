@load base/protocols/rdp
@load base/protocols/rdp/consts.zeek
@load ./counttable.zeek
module HLRDP;

export {
  redef enum Log::ID += { LOG };

  const epoch_interval = 10min &redef;
  
	const failure_codes = {
		[0x01] = "SSL_REQUIRED_BY_SERVER",
		[0x02] = "SSL_NOT_ALLOWED_BY_SERVER",
		[0x03] = "SSL_CERT_NOT_ON_SERVER",
		[0x04] = "INCONSISTENT_FLAGS",
		[0x05] = "HYBRID_REQUIRED_BY_SERVER",
		[0x06] = "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER"
	} &default = function(n: count): string { return fmt("failure_code-%d", n); };
  type Info: record {
    host : addr &log;
    failed_count :count &log;
    sucess_count :count &log;
    request_count :count &log;
    };

  global log_rdp: event(rec: Info);



  }


event zeek_init()
    {
	Log::create_stream(HLRDP::LOG, [$columns=Info, $ev=log_rdp, $path="sum_ssh"]);
	local r1 = SumStats::Reducer($stream="failed.rdp", $apply=set(SumStats::COUNTTABLE));
	local r2 = SumStats::Reducer($stream="sucess.rdp", $apply=set(SumStats::COUNTTABLE));

	SumStats::create([$name="sum-rdp",
		$epoch=epoch_interval,
		$reducers=set(r1,r2),
		$epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
	{
	if ( "failed.rdp" !in result )
		return;
		local failed_counttable = result["failed.rdp"]$counttable;
		local sucesscount = result["sucess.rdp"]$counttable;
		for ( i in failed_counttable )
			for (k in sucesscount)
				Log::write(HLRDP::LOG, [$host=key$host,$failed_count=failed_counttable[i],$sucess_count=sucesscount[k]]);
		  }]);


    }

