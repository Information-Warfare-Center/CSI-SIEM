@load protocols/ssh/detect-bruteforcing
@load policy/frameworks/notice/actions/drop

redef SSH::password_guesses_limit=3;
redef SSH::guessing_timeout=60 mins;

event NetControl::init()
  {
  local debug_plugin = NetControl::create_debug(T);
  NetControl::activate(debug_plugin, 0);
  }

hook Notice::policy(n: Notice::Info)
  {
  if ( n$note == SSH::Password_Guessing )
    NetControl::drop_address(n$src, 60min);
    add n$actions[Notice::ACTION_DROP];
    add n$actions[Notice::ACTION_LOG];		
  }
