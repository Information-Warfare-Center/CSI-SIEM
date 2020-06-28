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

##! Watch all TCP,UDP,ICMP flows for Data Exfil

module Exfil;

export {
    ## Defines which subnets are monitored for data exfiltration
    global watched_subnets_conn: set[subnet] = [10.0.0.0/8] &redef;
    ## Defines whether connections with local destinations should be monitored for data exfiltration
    global ignore_local_dest_conn: bool = T &redef;
    ## Defines the thresholds and polling interval for the exfil framework. See main.bro for more details.
    global settings_conn: Settings &redef;
}

event connection_established (c: connection) {

    if (ignore_local_dest_conn == T && Site::is_local_addr(c$id$resp_h) == T)
        return;

    if (c$id$orig_h !in watched_subnets_conn )
        return;

    Exfil::watch_connection(c , settings_conn);

}

