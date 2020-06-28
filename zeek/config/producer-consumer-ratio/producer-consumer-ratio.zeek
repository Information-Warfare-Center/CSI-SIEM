# Copyright 2013 Reservoir Labs, Inc.
# All rights reserved.
# 
# Contributed by Bob Rotsted
# 
# Small Business Innovation Research (SBIR) Data Rights.
# 
# These SBIR data are furnished with SBIR rights under Contract
# No. DE-SC0004400 and DE-SC0006343. For a period of 4 years
# (expiring August, 2018), unless extended in accordance with
# FAR 27.409(h), subject to Section 8 of the SBA SBIR Policy
# Directive of August 6, 2012, after acceptance of all items to
# be delivered under this contract, theGovernment will use these
# data for Government purposes only, and theyshall not be
# disclosed outside the Government (including disclosure for
# procurement purposes) during such period without permission of
# the Contractor, except that, subject to the foregoing use and
# disclosure prohibitions, these data may be disclosed for use
# by support Contractors. After the protection period, the
# Government has a paid-up license to use, and to authorize
# others to use on its behalf, these data for Government
# purposes, but is relieved of all disclosure prohibitions and
# assumes no liability for unauthorized use of these data by
# third parties. This notice shall be affixed to any
# reproductions of these data, in whole or in part.

##! Implements the Producer Consumer Ratio as described by http://resources.sei.cmu.edu/asset_files/Presentation/2014_017_001_90063.pdf

module PCR;

export {

    ## Add 'pcr' field to Conn log
    redef record Conn::Info += {
        pcr: double &log &optional;
    };

    ## Create new 'pcr' log
    redef enum Log::ID += { LOG };

    type Info: record {
        ts: time     &log;
        src: addr     &log;
        pcr: double &log;
        summary_interval: interval &log;
    };

    global log_pcr: event(rec: Info);

    ## Sets the summary interval for PCR metric
    global summary_interval = 1min &redef;

}

event connection_state_remove (c: connection) {

    if (c$id$orig_h !in Site::local_nets) {
		return;
	}

    local numerator = (c$orig$size + 0.0) - (c$resp$size + 0.0);
    local denominator = (c$orig$size + 0.0) + (c$resp$size + 0.0);

    if (numerator == 0.0 )
        return;

    local x = ( numerator / denominator );
    c$conn$pcr = x;

    SumStats::observe( "pcr", [$host=c$id$orig_h], [$dbl=x] );

}

event zeek_init() {

    ## Create PCR log stream
    Log::create_stream(PCR::LOG, [$columns=Info, $ev=log_pcr]);

    local r1 = SumStats::Reducer($stream="pcr", 
                                 $apply=set(SumStats::AVERAGE));

    SumStats::create([$name = "pcr",
                      $epoch = summary_interval,
                      $reducers = set(r1),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = {

						
                        local rec: PCR::Info = [$ts=network_time(), $src=key$host, $summary_interval=PCR::summary_interval, $pcr=result["pcr"]$average];
                        Log::write(PCR::LOG, rec);

                        }]);


}

