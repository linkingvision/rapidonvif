
#ifndef __ONVIF_AGENT_CLIENT__
#define __ONVIF_AGENT_CLIENT__



class  OnvifAgentC
{
public:
	OnvifAgentC(){}
	~OnvifAgentC(){}
public:
	static bool CheckOnline(astring strUser, astring strPasswd, astring strUrl);
	static bool GetProfiles(astring strUser, astring strPasswd, astring strUrl, 
			VVidOnvifProfileMap &pMap);
};


#endif /* __ONVIF_AGENT_CLIENT__ */
