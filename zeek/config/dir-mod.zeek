@load base/utils/dir

event zeek_init()
	{
	Dir::monitor("/opt/test/", function(fname: string)
		{
		print fname;
		});
	}

