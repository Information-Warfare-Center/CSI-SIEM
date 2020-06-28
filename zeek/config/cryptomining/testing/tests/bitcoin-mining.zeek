# @TEST-EXEC: bro -C -r $TRACES/bitcoin-mining.pcap %INPUT >out
# @TEST-EXEC: btest-diff out

@load zeek-cryptomining

redef Bitcoin::notice_miner_hosts=ALL_HOSTS;
redef Bitcoin::notice_pool_hosts=ALL_HOSTS;

hook Notice::policy(n: Notice::Info)
	{
	print "NOTICE", n$id, n$note, n$msg;
	}
