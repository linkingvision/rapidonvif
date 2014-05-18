#ifndef __ONVIF_CLIENT_REPLAY__
#define __ONVIF_CLIENT_REPLAY__

#include <string>
#include <map>
#include <iostream>
#include <list>

#include "onvifclientdevice.hpp"
#include "soapStub.h"
#include "soapReplayBindingProxy.h"
#include "wsseapi.h"


using namespace std;

class OnvifClientReplay
{
public:
    OnvifClientReplay(OnvifClientDevice &device);
    ~OnvifClientReplay();
public:
	/* Add function to here */
	int GetReplayUri(_trp__GetReplayUri &req, _trp__GetReplayUriResponse &resp);
				
private:
	OnvifClientDevice &m_Device;

};

inline OnvifClientReplay::OnvifClientReplay(OnvifClientDevice &device)
: m_Device(device)
{

}

inline OnvifClientReplay::~OnvifClientReplay()
{

}

inline int OnvifClientReplay::GetReplayUri(_trp__GetReplayUri &req, 
				_trp__GetReplayUriResponse &resp)
{
	string strUrl;
	string strUser;
	string strPass;
	
	if (m_Device.GetUserPasswd(strUser, strPass) == false 
		|| m_Device.GetMediaUrl(strUrl) == false)
	{
		return SOAP_ERR;
	}
	
	ReplayBindingProxy  replayProxy(SOAP_C_UTFSTRING);
	replayProxy.soap_endpoint =  strUrl.c_str();
	
	soap_wsse_add_Security(&replayProxy);
	soap_wsse_add_UsernameTokenDigest(&replayProxy, "Id", 
		strUser.c_str() , strPass.c_str());
		
	return replayProxy.GetReplayUri( &req, &resp) ;

}


#endif 