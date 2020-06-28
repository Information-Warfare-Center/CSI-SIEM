# Detect DNS zone transfer queries that indicates recon

module DNS_AXFR;

@load base/frameworks/notice/main

export {
        redef enum Notice::Type += {
                Attempt
	};
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
        if ( !Site::is_local_addr(c$id$orig_h) && qtype == 252 ) {
		NOTICE([$note=DNS_AXFR::Attempt, $id=c$id, $uid=c$uid,
                        $src=c$id$orig_h,
                        $msg=fmt("DNS AXFR query type from %s", c$id$orig_h),
			$sub=fmt("queried name: %s", query)]);
	}
}
