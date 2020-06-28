
module HTTP;

export {
  redef enum Notice::Type += {
    ## Generated if a site is detected using Basic Access Authentication
    HTTP::Basic_Auth_Server
  };
}

event http_header(c: connection, is_orig: bool, name: string, value: string)
    {
    if (/AUTHORIZATION/ in name && /Basic/ in value)
        {
        local parts = split_string(decode_base64(sub_bytes(value, 7, |value|)), /:/);
        if (|parts| == 2)
          NOTICE([$note=HTTP::Basic_Auth_Server,
                  $msg="Server identified on which Basic Access Authentication is in use.",
                  $sub=fmt("username: %s", parts[1]),
                  $conn=c,
                  $identifier=cat(c$id$resp_h,c$id$resp_p),
                  $suppress_for=1day]);
        }
    }
