#ifndef __ONVIF_CLIENT_MEDIA__
#define __ONVIF_CLIENT_MEDIA__

#include <string>
#include <map>
#include <iostream>
#include <list>

#include "onvifclientdevice.hpp"
#include "soapStub.h"
#include "soapMediaBindingProxy.h"
#include "wsseapi.h"


using namespace std;

class OnvifClientMedia
{
public:
    OnvifClientMedia(OnvifClientDevice &device);
    ~OnvifClientMedia();
public:
    int GetProfiles(_trt__GetProfilesResponse &profiles);
				
private:
	OnvifClientDevice &m_Device;

};

inline OnvifClientMedia::OnvifClientMedia(OnvifClientDevice &device)
: m_Device(device)
{

}

inline OnvifClientMedia::~OnvifClientMedia()
{

}

inline int OnvifClientMedia::GetProfiles(_trt__GetProfilesResponse &profiles)
{
	string strUrl;
	string strUser;
	string strPass;
	_trt__GetProfiles	profilesReq;
	
	if (m_Device.GetUserPasswd(strUser, strPass) == false 
		|| m_Device.GetMediaUrl(strUrl) == false)
	{
		return SOAP_ERR;
	}
	
	MediaBindingProxy  mediaProxy(SOAP_C_UTFSTRING);
	mediaProxy.soap_endpoint =  strUrl.c_str();
	
	soap_wsse_add_Security(&mediaProxy);
	soap_wsse_add_UsernameTokenDigest(&mediaProxy, "Id", 
		strUser.c_str() , strPass.c_str());
		
	return mediaProxy.GetProfiles( &profilesReq, &profiles) ;
}


#endif /* __ONVIF_CLIENT_MEDIA__ */