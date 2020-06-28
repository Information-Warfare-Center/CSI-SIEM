# Contributed by Bob Rotsted @ Reservoir Labs
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

##! A script that detects data exfiltration after business hours

module Exfil;


export {

	type business_hours: record {

    	start_time: count &default = 6;
    	end_time:   count &default = 17;

	};

	## The business hours of the network, (on a 24 hour clock)
    global hours: business_hours &redef;

    redef enum Notice::Type += {
         After_Hours_Transfer,
     };
    
}

## Converts from Epoch time to local time 
function get_hour(t: time): count {
    local the_hour: string = strftime("%H", t);
    return to_count(the_hour);
}

## Determines whether the local time is in Buisiness Hours
function in_business_hours (t: time, b: business_hours): bool {
    local h: count;
    h = get_hour(t);
     
    if ( h >= b$end_time || h < b$start_time ){
        return F;
    }

    return T;
}

## When "Exfil" activity occurs in the Exfil Framework, check to see if it is in business hours
event Exfil::log_exfil(rec: Exfil::Info) {

    if ( in_business_hours (rec$ts, hours) == F )
    {
        local tmp_msg = fmt("Sent Bytes: %s, UID: %s", rec$orig_bytes, rec$uid);
        
        NOTICE([$note=After_Hours_Transfer,
                $id=rec$id,
                $msg=tmp_msg]);
    }

}
