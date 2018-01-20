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
	//Dealing with receivers
	int OnvifClientReceiver::GetReceivers(_trv__GetReceiversResponse & receivers);
	int OnvifClientReceiver::GetReceiver(_trv__GetReceiverResponse &receiverResponsem, string ReceiverToken);
	int OnvifClientReceiver::CreateReceiver(_trv__CreateReceiverResponse &CreateReceiverResponse, tt__ReceiverConfiguration &ReceiverConfiguration);
	int OnvifClientReceiver::DeleteReceiver(_trv__DeleteReceiverResponse &DeleteReceiverResponse, string ReceiverToken);
	//receiver status functions
	int OnvifClientReceiver::ConfigureReceiver(_trv__ConfigureReceiverResponse &ConfigureReceiverResponse, string ReceiverToken,tt__ReceiverConfiguration &ReceiverConfiguration);
	int OnvifClientReceiver::SetReceiverMode(_trv__SetReceiverModeResponse &SetReceiverModeResponse, string ReceiverToken,tt__ReceiverMode &ReceiverConfiguration);
	int OnvifClientReceiver::GetReceiverState(_trv__GetReceiverStateResponse &GetReceiverStateResponse, string ReceiverToken);
	int OnvifClientReceiver::GetServiceCapabilities(_trv__GetServiceCapabilitiesResponse &GetReceiverStateResponse);

private:
	OnvifClientDevice &m_Device;
	ReceiverBindingProxy  receiverProxy;

};

inline int OnvifClientReceiver::GetServiceCapabilities(_trv__GetServiceCapabilitiesResponse &GetServiceCapabilitiesResponse)
{
	
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

	_trv__GetServiceCapabilities GetServiceCapabilitiesReq;
	return receiverProxy.GetServiceCapabilities( &GetServiceCapabilitiesReq, &GetServiceCapabilitiesResponse) ;
}

inline int OnvifClientReceiver::GetReceiverState(_trv__GetReceiverStateResponse &GetReceiverStateResponse, string ReceiverToken)
{
	
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

	_trv__GetReceiverState GetReceiverStateReq;
	GetReceiverStateReq.ReceiverToken = ReceiverToken;
	return receiverProxy.GetReceiverState( &GetReceiverStateReq, &GetReceiverStateResponse) ;
}

inline int OnvifClientReceiver::SetReceiverMode(_trv__SetReceiverModeResponse &SetReceiverModeResponse, string ReceiverToken,tt__ReceiverMode &ReceiverConfiguration)
{
	
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

	_trv__SetReceiverMode SetReceiverModeReq;
	SetReceiverModeReq.ReceiverToken = ReceiverToken;
	SetReceiverModeReq.Mode = ReceiverConfiguration;
	return receiverProxy.SetReceiverMode( &SetReceiverModeReq, &SetReceiverModeResponse) ;
}

inline int OnvifClientReceiver::ConfigureReceiver(_trv__ConfigureReceiverResponse &ConfigureReceiverResponse, string ReceiverToken,tt__ReceiverConfiguration &ReceiverConfiguration)
{
	
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

	_trv__ConfigureReceiver ConfigureReceiverReq;
	ConfigureReceiverReq.ReceiverToken = ReceiverToken;
	ConfigureReceiverReq.Configuration = &ReceiverConfiguration;
	return receiverProxy.ConfigureReceiver( &ConfigureReceiverReq, &ConfigureReceiverResponse) ;
}

inline int OnvifClientReceiver::DeleteReceiver(_trv__DeleteReceiverResponse &DeleteReceiverResponse, string ReceiverToken)
{
	
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

	_trv__DeleteReceiver DeleteReceiverReq;
	DeleteReceiverReq.ReceiverToken = ReceiverToken;
	return receiverProxy.DeleteReceiver( &DeleteReceiverReq, &DeleteReceiverResponse) ;
}

inline int OnvifClientReceiver::CreateReceiver(_trv__CreateReceiverResponse &CreateReceiverResponse, tt__ReceiverConfiguration &ReceiverConfiguration)
{
	
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

	_trv__CreateReceiver CreateReceiverReq;
	CreateReceiverReq.Configuration = &ReceiverConfiguration;
	return receiverProxy.CreateReceiver( &CreateReceiverReq, &CreateReceiverResponse) ;
}

inline int OnvifClientReceiver::GetReceiver(_trv__GetReceiverResponse &receiverResponse, string ReceiverToken)
{
	
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

	_trv__GetReceiver ReceiverReq;
	ReceiverReq.ReceiverToken = ReceiverToken;
	return receiverProxy.GetReceiver( &ReceiverReq, &receiverResponse) ;
}

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