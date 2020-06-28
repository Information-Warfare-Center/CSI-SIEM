@load base/protocols/http
@load base/frameworks/notice

module SNIFFPASS;

global username_fields = set("USERNAME", "USRNAME", "UNAME", "EMAIL", "USER", "USR", "LOGIN", "NAME", "AUTH", "LOG");
global password_fields = set("PASSWORD", "PASS", "PSW", "PWD", "SECRET");

export {
    const log_username = T &redef;
    const log_password_plaintext = F &redef;
    const log_password_md5 = F &redef;
    const log_password_sha1 = F &redef;
    const log_password_sha256 = F &redef;
    const post_body_limit = 300 &redef;
    const notice_log_enable = T &redef;
}

type SPStorage: record {
    inspect_post_data: bool &default=F &log;
    post_data: string &log &optional;
};

redef record HTTP::Info += {
    post_username: string &log &optional;
    post_password_plain: string &log &optional;
    post_password_md5: string &log &optional;
    post_password_sha1: string &log &optional;
    post_password_sha256: string &log &optional;
};

redef enum Notice::Type += {
    HTTP_POST_Password_Seen,
};

redef record connection += {
    sp: SPStorage &optional;
};

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
    if ( is_orig && c$http$method == "POST") {
        if (to_upper(name) == "CONTENT-TYPE"
            && to_upper(value) == "APPLICATION/X-WWW-FORM-URLENCODED")
        {
            if ( ! c?$sp )
                c$sp = SPStorage();

            c$sp$inspect_post_data = T;
            c$sp$post_data = "";
    }
  }
}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
  {
    if ( is_orig && c?$sp && c$sp$inspect_post_data ) {
        if ( |c$sp$post_data| >= post_body_limit )
            return;

        c$sp$post_data += data;

        if ( |c$sp$post_data| > post_body_limit )
            c$sp$post_data = c$sp$post_data[0:post_body_limit] + "~";
    }
  }

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
{
    if ( is_orig && c?$sp && c$sp$inspect_post_data )
    {
        local post_parsed = split_string(c$sp$post_data, /&/);
        local password_seen = F;

        for (p in post_parsed) {
            local kv = split_string1(post_parsed[p], /=/);
            if (to_upper(kv[0]) in username_fields) {
                c$http$post_username = kv[1];
            }
            if (to_upper(kv[0]) in password_fields) {
                password_seen = T;

                if ( log_password_plaintext )
                    c$http$post_password_plain = kv[1];
                if ( log_password_md5 )
                    c$http$post_password_md5 = md5_hash(kv[1]);
                if ( log_password_sha1 )
                    c$http$post_password_sha1 = sha1_hash(kv[1]);
                if ( log_password_sha256 )
                    c$http$post_password_sha256 = sha256_hash(kv[1]);
            }
        }

        if ( password_seen && notice_log_enable ) {
            if ( c$http?$post_username && |c$http$post_username| > 0 )
            {
               NOTICE([$note=HTTP_POST_Password_Seen,
               $msg="Password found for user " + c$http$post_username,
               $conn=c ]);
            }
            else
            {
               NOTICE([$note=HTTP_POST_Password_Seen,
               $msg="Password found",
               $conn=c ]);
            }
        }
    }
}
