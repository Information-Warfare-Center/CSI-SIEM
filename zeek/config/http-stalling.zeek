#  Written by Seth Hall, and modified by Richard Medlin.
@load base/frameworks/sumstats

module HTTPStalling;

export {
	redef enum Notice::Type += {
		## A stalling-type HTTP DoS attack against a webserver was detected. 
		Victim,
		## A stalling-type HTTP DoS attacker was detected.
		Attacker,
	};
	
	## Value representing how much time is considered too long to start and 
	## complete and HTTP request.
	const too_much_client_delay = 10secs &redef;

	## Number of suspicious requests from an attacker or to a victim to be
	## considered an attack.
	const requests_threshold: double = 40.0 &redef;
}

redef record HTTP::Info += {
	stalling_last_client_data: time &optional;
	stalling_client_done: bool &default=F;
};

event zeek_init()
	{
	local r1: SumStats::Reducer = [$stream="http.stalling.attacker", $apply=set(SumStats::SUM)];

	SumStats::create([$name="detect-http-stalling-attackers",
	                  $epoch=10min,
	                  $reducers=set(r1),
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	return result["http.stalling.attacker"]$num + 0.0;
	                  	},
	                  $threshold=requests_threshold,
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	local r = result["http.stalling.attacker"];
	                  	NOTICE([$note=Attacker,
	                  	        $msg="An HTTP stalling attacker was discovered!",
	                  	        $src=key$host,
	                  	        $identifier=cat(key$host)]);
	                  	}]);


	local r2: SumStats::Reducer = [$stream="http.stalling.victim", $apply=set(SumStats::SUM)];
	SumStats::create([$name="detect-http-stalling-victims",
	                  $epoch=10min,
	                  $reducers=set(r2),
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	return result["http.stalling.victim"]$num + 0.0;
	                  	},
	                  $threshold=requests_threshold,
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	local r = result["http.stalling.victim"];
	                  	NOTICE([$note=Victim,
	                  	        $msg="An HTTP stalling victim was discovered!",
	                  	        $src=key$host,
	                  	        $identifier=cat(key$host)]);
	                  	}]);
	}

event watch_for_request_finishing(http: HTTP::Info)
	{
	if ( ! connection_exists(http$id) )
		return;
		
	if ( http$stalling_client_done ) 
		return;
	
	# If a client body is being sent, allow for the full too_much_client_delay
	# interval between chunks of body data.
	if ( http?$stalling_last_client_data && 
	     network_time() - http$stalling_last_client_data < too_much_client_delay )
		schedule too_much_client_delay { watch_for_request_finishing(http) };

	SumStats::observe("http.stalling.attacker", [$host=http$id$orig_h], [$num=1]);
	SumStats::observe("http.stalling.victim",   [$host=http$id$resp_h], [$num=1]);
	}

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
	{
	schedule too_much_client_delay { watch_for_request_finishing(c$http) };
	}
	
event http_reply(c: connection, version: string, code: count, reason: string)
	{
	# Ignore 1xx intermediate responses.
	if ( code < 100 || code >= 200 )
		c$http$stalling_client_done=T;
	}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
	{
	if ( is_orig && c?$http )
		c$http$stalling_client_done=T;
	}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
	{
	c$http$stalling_last_client_data = network_time();
	}
