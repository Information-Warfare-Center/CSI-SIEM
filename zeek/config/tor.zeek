@load base/frameworks/notice

module DetectTor;

export {
	redef enum Notice::Type += { 
		## Indicates that a host using Tor was discovered.
		DetectTor::Found 
	};

	## Distinct Tor-like X.509 certificates to see before deciding it's Tor.
	const tor_cert_threshold = 10.0;

	## Time period to see the :zeek:see:`tor_cert_threshold` certificates
	## before deciding it's Tor.
	const tor_cert_period = 5min;
	
	# Number of Tor certificate samples to collect.
	const tor_cert_samples = 3 &redef;
}

event zeek_init()
	{
	local r1 = SumStats::Reducer($stream="ssl.tor-looking-cert", $apply=set(SumStats::UNIQUE, SumStats::SAMPLE), $num_samples=tor_cert_samples);
	SumStats::create([$name="detect-tor",
	                  $epoch=tor_cert_period,
	                  $reducers=set(r1),
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	return result["ssl.tor-looking-cert"]$unique+0.0;
	                  	},
	                  $threshold=tor_cert_threshold,
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	local r = result["ssl.tor-looking-cert"];
	                  	local samples = r$samples;
	                  	local sub_msg = fmt("Sampled certificates: ");
	                  	for ( i in samples )
	                  		{
	                  		if ( samples[i]?$str )
	                  			sub_msg = fmt("%s%s %s", sub_msg, i==0 ? "":",", samples[i]$str);
	                  		}
	                  	NOTICE([$note=DetectTor::Found,
	                  	        $msg=fmt("%s was found using Tor by connecting to servers with at least %d unique weird certs", key$host, r$unique),
	                  	        $sub=sub_msg,
	                  	        $src=key$host,
	                  	        $identifier=cat(key$host)]);
	                  	}]);
	}

event ssl_established(c: connection )
	{
	if ( c$ssl?$subject && /^CN=www.[^=,]*$/ == c$ssl$subject && c$ssl?$issuer && /^CN=www.[^=,]*$/ == c$ssl$issuer )
		{
		SumStats::observe("ssl.tor-looking-cert", [$host=c$id$orig_h], [$str=c$ssl$subject]);
		}
	}
