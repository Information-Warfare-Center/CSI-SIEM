##! This script does is primarily focused on identifying bruteforcers in FTP 
##! It generates two notices: (i) Bruteforcer (ii) BruteforceSummary.  
##! Logic to identify a bruteforcer is in function: is_ftp_bruteforcer()

module FTP; 

redef default_capture_password = T ; 
redef logged_commands += {  "USER", "PASS", } ; 

export {
	## notices once a bruteforcer is identified 
	redef enum Notice::Type += {
		Bruteforcer,
		BruteforceSummary, 
	} ; 

	## This record is to hold usernames and passwords attempted by a src
	## For example:  [user={anonymous}, pass={googlebot@google.com}, bruteforcer=F]
	type user_pass: record { 
		user: set[string]; 
		pass: set[string]; 
		bruteforcer: bool &default=F ; 
	} ; 

	## we presently flag at 5 users or 5 passwords tried
	## A bad actor can still get away trying <= 4 users or <= 4 passwords
	## 
	global fail_threshold = 4 ; 
	
	## expire function for bruteforcer_table to log BruteforceSummary
	global expire_bruteforcer_table: function(t: table[addr] of user_pass, src: addr ): interval ; 

	## data structure to store bruteforced usernames and passwords
	## using src as index and user_pass as record 
	global bruteforcer_table: table[addr] of user_pass &create_expire=1 hrs &expire_func=expire_bruteforcer_table ; 
} 

function is_ftp_bruteforcer(src: addr): bool 
	{ 
	local users_attempted = |bruteforcer_table[src]$user|  ; 
	local pass_attempted  = |bruteforcer_table[src]$pass|  ; 

	if ( (! bruteforcer_table[src]$bruteforcer) &&
		 ( users_attempted > fail_threshold || pass_attempted > fail_threshold ) || 
		   ((users_attempted + pass_attempted) > fail_threshold) 
		)
	{ 
		return T ; 
	}	
	return F ;
	} 

hook Notice::policy(n: Notice::Info)
	{
  	if ( n$note == FTP::Bruteforcer)
	add n$actions[Notice::ACTION_DROP];
	}

function expire_bruteforcer_table(t: table[addr] of user_pass, src: addr): interval
	{
	
	## we only want to log summary for a bruteforcer
	## we may have other legit ftp seessions in the table 
	if (t[src]$bruteforcer) 
	{ 
		local msg = fmt ("FTP bruteforcer : source: %s, Users tried: %s, number Password tried: %s", src, |t[src]$user|, |t[src]$pass|);
		NOTICE([$note=BruteforceSummary, $src=src, $msg=msg]);
	} 
	return 0 secs;
	} 

event ftp_request(c: connection, command: string, arg: string) &priority=5
	{ 
	local src = c$id$orig_h ; 
	local dst = c$id$resp_h ;

	if (src in Site::local_nets) 
		return ;

	if ( command == "USER" || command == "PASS" )
	{ 
		if (src !in bruteforcer_table)
		{ 	
			local u: set[string] ; 
			local p: set[string]; 
			local up: user_pass ; 
			bruteforcer_table[src]=up ; 
		} 

		if (command == "USER" ) 
			add bruteforcer_table[src]$user[arg] ; 
		else if (command == "PASS")  
			add bruteforcer_table[src]$pass[arg]; 
		
		if ( is_ftp_bruteforcer(src)) 
		{ 
			bruteforcer_table[src]$bruteforcer = T ; 	
			local msg = fmt ("FTP bruteforcer: %s, username attempted: %s, password attempted: %s", src, |bruteforcer_table[src]$user|, |bruteforcer_table[src]$pass|); 
			NOTICE([$note=Bruteforcer, $conn=c, $msg=msg]);
		} 
	} 
	}
