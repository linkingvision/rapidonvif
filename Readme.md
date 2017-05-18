# rapidonvif include onvif server and client #

![](https://github.com/veyesys/rapidonvif/blob/rapidonvif/onvif/doc/rapidonvif.png)

### Windows ###
	1. Install VS2013
	2. Build onvif\onvifagent\win32\onvifagent.sln
	3. Build onvif\prj_win32\onvifagentlib.sln
	
### Linux ###
	Change VE_PATH in the rules.mk
	$source ./rules.mk
	$make
	
### macOS ###
	Install xcode
	Change VE_PATH in the rules.mk
	$source ./rules-macos.mk
	$make 

### Get RTSP URL & Control PTZ within 10 line code
	std::string url = "http://192.168.22.100/onvif/device_service";
	std::string user = "admin";
	std::string pass =  "admin";

	OnvifAgentC agent(user, pass, url);
	OnvifAgentCProfileMap pProfiles;

	agent.Login();
	pProfiles.clear();
	agent.GetProfiles(pProfiles);
	
	agent.PTZAction(pProfiles.begin()->first,AGENT_PTZ_ZOOM_IN, 0.5);

### Features list ###
	ONVIF profile S

#### License ####
* Licensing: dual licensed as open source Affero GPL and commercial-use license (available for purchase).


# [Buy](http://veyesys.com/index.html#license) #


For more guide
[http://veyesys.com/](http://veyesys.com/)

Mail  : [xsmart@veyesys.com](xsmart@veyesys.com)

Skype : xsmart@veyesys.com

QQ    : 2104915834
