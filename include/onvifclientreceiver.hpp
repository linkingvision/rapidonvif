#ifndef __ONVIF_CLIENT_RECEIVER__
#define __ONVIF_CLIENT_RECEIVER__

#include <string>
#include <map>
#include <iostream>
#include <list>

#include "onvifclientdevice.hpp"
#include "soapStub.h"
#include "soapReceiverBindingProxy.h"
#include "wsseapi.h"


using namespace std;

class OnvifClientReceiver
{
public:
    OnvifClientReceiver(OnvifClientDevice &device);
    ~OnvifClientReceiver();
public:
	/* Add function to here */
	int GetReceivers(_trv__GetReceiversResponse & receivers);
				
private:
	OnvifClientDevice &m_Device;
	ReceiverBindingProxy  receiverProxy;

};

inline OnvifClientReceiver::OnvifClientReceiver(OnvifClientDevice &device)
: m_Device(device), receiverProxy(SOAP_C_UTFSTRING)
{

}

inline OnvifClientReceiver::~OnvifClientReceiver()
{

}

inline int OnvifClientReceiver::GetReceivers(_trv__GetReceiversResponse & receivers)
{
	_trv__GetReceivers req;
	string strUrl;
	string strUser;
	string strPass;
	
	if (m_Device.GetUserPasswd(strUser, strPass) == false 
		|| m_Device.GetReceiverUrl(strUrl) == false)
	{
		return SOAP_ERR;
	}

	receiverProxy.soap_endpoint =  strUrl.c_str();
	
	soap_wsse_add_Security(&receiverProxy);
	soap_wsse_add_UsernameTokenDigest(&receiverProxy, "Id", 
		strUser.c_str() , strPass.c_str());
		
	return receiverProxy.GetReceivers( &req, &receivers) ;
}


#endif 