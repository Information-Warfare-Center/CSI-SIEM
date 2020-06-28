@load base/frameworks/notice
@load base/protocols/rdp

# [[https://packetstormsecurity.com/files/153133/Microsoft-Windows-Remote-Desktop-BlueKeep-Denial-Of-Service.html][Microsoft Windows Remote Desktop BlueKeep Denial Of Service ≈ Packet Storm]]
# [[https://www.cvedetails.com/cve/CVE-2019-0708/][CVE-2019-0708 : A remote code execution vulnerability exists in Remote Desktop Services formerly known as Terminal Services when an unau]]
module HLRDP;

export {
	redef enum Notice::Type += {

		Val_RDP_Channel_Name,

        Val_RDP_Head_Version,


		Val_RDP_Neg,

         Val_RDP_Build,
    };
}



event rdp_client_network_data (c: connection, channels: RDP::ClientChannelList)

{
    for ( i in c$rdp$client_channels){
        local channel_count = 0;
	++channel_count;
        if (c$rdp$client_channels[i] == "MS_T120" && channel_count < 6)
            {
                NOTICE([$note=Val_RDP_Channel_Name,
                	$msg=fmt("CVE-2019-0708 - %s - %s", c$rdp$client_channels, c$rdp$client_build),
            		    	$conn=c]);
            }
	    }
}


event rdp_client_core_data (c: connection , data: RDP::ClientCoreData ) &priority=5
{
}

##X.224
event rdp_connect_request (c: connection , cookie: string ){

}


event rdp_negotiation_response (c: connection , security_protocol: count ){


}

event rdp_client_security_data(c: connection , data: RDP::ClientSecurityData )
{

}
event rdp_gcc_server_create_response(c: connection , result: count )
    {
    }
