@load ./bin-list

module CreditCardExposure;

export {
	redef enum Log::ID += { LOG };

	redef enum Notice::Type += { 
		## An apparently valid credit card number was found.
		Found
	};

	type Info: record {
		## When the SSN was seen.
		ts:   time    &log;
		## Unique ID for the connection.
		uid:  string  &log;
		## Connection details.
		id:   conn_id &log;
		## Credit card number that was discovered.
		cc:   string  &log &optional;
		## Bank Indentification number information
		bank: Bank    &log &optional;
		## Data that was received when the credit card was discovered.
		data: string  &log;
	};
	
	## Logs are redacted by default.  If you want to see the credit card 
	## numbers in the log, redef this value to F.  
	## Notices are automatically and unchangeably redacted.
	const redact_log = F &redef;

	## The number of bytes around the discovered credit card number that is used 
	## as a summary in notices.
	const summary_length = 200 &redef;

	const cc_regex = /(^|[^0-9\-])\x00?[3-9](\x00?[0-9]){2,3}([[:blank:]\-\.]?\x00?[0-9]{4}){3}([^0-9\-]|$)/ &redef;

	## Configure this to `F` if you'd like to stop enforcing that
	## credit cards use an internal digit separator.
	const use_cc_separators = T &redef;

	const cc_separators = /\.([0-9]*\.){2}/ | 
	                      /\-([0-9]*\-){2}/ | 
	                      /[:blank:]([0-9]*[:blank:]){2}/ &redef;
}

const luhn_vector = vector(0,2,4,6,8,1,3,5,7,9);
function luhn_check(val: string): bool
	{
	local sum = 0;
	local odd = F;
	for ( char in gsub(val, /[^0-9]/, "") )
		{
		odd = !odd;
		local digit = to_count(char);
		sum += (odd ? digit : luhn_vector[digit]);
		}
	return sum % 10 == 0;
	}

event zeek_init() &priority=5
	{
	Log::create_stream(CreditCardExposure::LOG, [$columns=Info]);
	}


function check_cards(c: connection, data: string): bool
	{
	local found_cnt = 0;

	local ccps = find_all(data, cc_regex);
	for ( ccp in ccps )
		{
		# Remove non digit characters from the beginning and end of string.
		ccp = sub(ccp, /^[^0-9]*/, "");
		ccp = sub(ccp, /[^0-9]*$/, "");
		# Remove any null bytes.
		ccp = gsub(ccp, /\x00/, "");

		if ( (!use_cc_separators || cc_separators in ccp) && luhn_check(ccp) )
			{
			++found_cnt;

			# we've got a match
			local cc_parts = split_string_all(data, cc_regex);
			# take a copy to avoid modifying the vector while iterating.
			for ( i in copy(cc_parts) )
				{
				if ( i % 2 == 0 )
					{
					# Redact all matches
					local cc_match = cc_parts[i];
					cc_parts[i] = gsub(cc_parts[i], /[0-9]/, "X");
					}
				}
			local redacted_data = join_string_vec(cc_parts, "");

			# Trim the data
			local begin = 0;
			local cc_location = strstr(data, ccp);
			if ( cc_location > (summary_length/2) )
				begin = cc_location - (summary_length/2);
			
			local byte_count = summary_length;
			if ( begin + summary_length > |redacted_data| )
				byte_count = |redacted_data| - begin;

			local trimmed_redacted_data = sub_bytes(redacted_data, begin, byte_count);

			local log: Info = [$ts=network_time(), 
			                   $uid=c$uid, $id=c$id,
			                   $cc=(redact_log ? gsub(ccp, /[0-9]/, "X") : ccp),
			                   $data=(redact_log ? trimmed_redacted_data : sub_bytes(data, begin, byte_count))];

			local bin_number = to_count(sub_bytes(gsub(ccp, /[^0-9]/, ""), 1, 6));
			if ( bin_number in bin_list )
				log$bank = bin_list[bin_number];

			Log::write(CreditCardExposure::LOG, log);
			}
		
		}
	if ( found_cnt > 0 )
		{
		NOTICE([$note=CreditCardExposure::Found,
		        $conn=c,
		        $msg=fmt("Found at least %d credit card number%s", found_cnt, found_cnt > 1 ? "s" : ""),
		        $sub=trimmed_redacted_data,
		        $identifier=cat(c$id$orig_h,c$id$resp_h)]);
		return T;
		}
	else
		{
		return F;
		}
	}

event CreditCardExposure::stream_data(f: fa_file, data: string)
	{
	local c: connection;
	for ( id in f$conns )
		{
		c = f$conns[id];
		break;
		}
	if ( c$start_time > network_time()-20secs )
		check_cards(c, data);
	}

event file_new(f: fa_file)
	{
	if ( f$source == "HTTP" || f$source == "SMTP" )
		{
		Files::add_analyzer(f, Files::ANALYZER_DATA_EVENT, 
		                    [$stream_event=CreditCardExposure::stream_data]);
		}
	}
