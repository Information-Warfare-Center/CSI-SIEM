
@load base/protocols/http
@load base/frameworks/notice

module HTTPATTACKS;

redef enum Notice::Type += {
    HTTP_Smuggling,
};

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
{
    if (is_orig && c$http$method == "GET")
        NOTICE([$note=HTTP_Smuggling,
        $msg="HTTP GET request with body detected",
        $conn = c]);
}

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
{
    if (is_orig) {
        local host_h_count = 0;
        local cl_h_count = 0;
        local te_h_count = 0;

        for (i in hlist)
        {
            if (hlist[i]$name == "HOST")
                ++host_h_count;
            if (hlist[i]$name == "CONTENT-LENGTH")
                ++cl_h_count;
            if (hlist[i]$name == "TRANSFER-ENCODING")
                ++te_h_count;
        }

        if (host_h_count > 1)
            NOTICE([$note=HTTP_Smuggling,
            $msg="Multiple HTTP Host headers detected",
            $conn = c]);

        if (cl_h_count >= 1 && te_h_count >= 1)
            NOTICE([$note=HTTP_Smuggling,
            $msg="CL and TE headers detected",
            $conn = c]);

        if (cl_h_count > 1 || te_h_count > 1 )
            NOTICE([$note=HTTP_Smuggling,
            $msg="More than one CL or TE header detected",
            $conn = c]);
    }
}
