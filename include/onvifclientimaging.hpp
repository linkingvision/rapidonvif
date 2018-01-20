#ifndef __ONVIF_CLIENT_IMAGING__
#define __ONVIF_CLIENT_IMAGING__

#include <string>
#include <map>
#include <iostream>
#include <list>

#include "onvifclientdevice.hpp"
#include "soapStub.h"
#include "soapImagingBindingProxy.h"
#include "wsseapi.h"


using namespace std;

class OnvifClientImaging
{
public:
    OnvifClientImaging(OnvifClientDevice &device);
    ~OnvifClientImaging();
public:
	int OnvifClientImaging::GetImagingSettings(_timg__GetImagingSettingsResponse &ImagingSettingsResponse, string videoSourceToken);
	int OnvifClientImaging::GetOptions(_timg__GetOptionsResponse &GetOptionsResponse, string videoSourceToken);
	int OnvifClientImaging::GetServiceCapabilities(_timg__GetServiceCapabilitiesResponse &GetServiceCapResponse);
	int OnvifClientImaging::SetImagingSettings(_timg__SetImagingSettingsResponse &SetImagingSettingsResponse, string VideoSourceToken, tt__ImagingSettings20 &ImagingSettings,bool ForcePersistence);
	int OnvifClientImaging::GetStatus(_timg__GetStatusResponse &GetStatusResponse, string VideoSourceToken);
	//focus control functions
	int OnvifClientImaging::Move(_timg__MoveResponse &MoveResponse, tt__FocusMove &FocusMove, string VideoSourceToken);
	int OnvifClientImaging::GetMoveOptions(_timg__GetMoveOptionsResponse &MoveOptionsResponse,string VideoSourceToken);
	int OnvifClientImaging::Stop(_timg__StopResponse &StopResponse,string VideoSourceToken);

private:
	OnvifClientDevice &m_Device;
	ImagingBindingProxy ImageProxy;

};

//(focus)
inline int OnvifClientImaging::Stop(_timg__StopResponse &StopResponse,string VideoSourceToken)
{
	string strUrl;
	string strUser;
	string strPass;
	if (m_Device.GetUserPasswd(strUser, strPass) == false 
		|| m_Device.GetImagingUrl(strUrl) == false)
	{
		return SOAP_ERR;
	}
	ImageProxy.soap_endpoint =  strUrl.c_str();
	soap_wsse_add_Security(&ImageProxy);
	soap_wsse_add_UsernameTokenDigest(&ImageProxy, "Id", strUser.c_str() , strPass.c_str());

	_timg__Stop StopReq;
	StopReq.VideoSourceToken = VideoSourceToken;
	return ImageProxy.Stop(&StopReq,&StopResponse);
}

//(focus)
inline int OnvifClientImaging::GetMoveOptions(_timg__GetMoveOptionsResponse &GetMoveOptionsResponse,string VideoSourceToken)
{
	string strUrl;
	string strUser;
	string strPass;
	if (m_Device.GetUserPasswd(strUser, strPass) == false 
		|| m_Device.GetImagingUrl(strUrl) == false)
	{
		return SOAP_ERR;
	}
	ImageProxy.soap_endpoint =  strUrl.c_str();
	soap_wsse_add_Security(&ImageProxy);
	soap_wsse_add_UsernameTokenDigest(&ImageProxy, "Id", strUser.c_str() , strPass.c_str());

	_timg__GetMoveOptions GetMoveOptionsReq;
	GetMoveOptionsReq.VideoSourceToken = VideoSourceToken;
	return ImageProxy.GetMoveOptions(&GetMoveOptionsReq,&GetMoveOptionsResponse);
}

//move (focus)
inline int OnvifClientImaging::Move(_timg__MoveResponse &MoveResponse, tt__FocusMove &Focus, string VideoSourceToken)
{
	string strUrl;
	string strUser;
	string strPass;
	if (m_Device.GetUserPasswd(strUser, strPass) == false 
		|| m_Device.GetImagingUrl(strUrl) == false)
	{
		return SOAP_ERR;
	}
	ImageProxy.soap_endpoint =  strUrl.c_str();
	soap_wsse_add_Security(&ImageProxy);
	soap_wsse_add_UsernameTokenDigest(&ImageProxy, "Id", strUser.c_str() , strPass.c_str());

	_timg__Move MoveReq;
	MoveReq.Focus = &Focus;
	MoveReq.VideoSourceToken = VideoSourceToken;
	return ImageProxy.Move(&MoveReq,&MoveResponse);
}

inline int OnvifClientImaging::GetStatus(_timg__GetStatusResponse &GetImagingStatusResponse, string VideoSourceToken)
{
	string strUrl;
	string strUser;
	string strPass;
	if (m_Device.GetUserPasswd(strUser, strPass) == false 
		|| m_Device.GetImagingUrl(strUrl) == false)
	{
		return SOAP_ERR;
	}
	ImageProxy.soap_endpoint =  strUrl.c_str();
	soap_wsse_add_Security(&ImageProxy);
	soap_wsse_add_UsernameTokenDigest(&ImageProxy, "Id", strUser.c_str() , strPass.c_str());

	_timg__GetStatus GetImagingStatusReq;
	GetImagingStatusReq.VideoSourceToken = VideoSourceToken;

	return ImageProxy.GetStatus(&GetImagingStatusReq,&GetImagingStatusResponse);

}

inline int OnvifClientImaging::SetImagingSettings(_timg__SetImagingSettingsResponse &SetImagingSettingsResponse, string VideoSourceToken, tt__ImagingSettings20 &ImagingSettings,bool ForcePersistence)
{
	string strUrl;
	string strUser;
	string strPass;
	if (m_Device.GetUserPasswd(strUser, strPass) == false 
		|| m_Device.GetImagingUrl(strUrl) == false)
	{
		return SOAP_ERR;
	}
	ImageProxy.soap_endpoint =  strUrl.c_str();
	soap_wsse_add_Security(&ImageProxy);
	soap_wsse_add_UsernameTokenDigest(&ImageProxy, "Id", strUser.c_str() , strPass.c_str());

	_timg__SetImagingSettings SetImagingSettingsReq;
	SetImagingSettingsReq.VideoSourceToken = VideoSourceToken;
	SetImagingSettingsReq.ImagingSettings = &ImagingSettings;
	SetImagingSettingsReq.ForcePersistence = &ForcePersistence;
	return ImageProxy.SetImagingSettings(&SetImagingSettingsReq,&SetImagingSettingsResponse);

}

inline int OnvifClientImaging::GetServiceCapabilities(_timg__GetServiceCapabilitiesResponse &GetServiceCapResponse)
{
	string strUrl;
	string strUser;
	string strPass;
	if (m_Device.GetUserPasswd(strUser, strPass) == false 
		|| m_Device.GetImagingUrl(strUrl) == false)
	{
		return SOAP_ERR;
	}
	ImageProxy.soap_endpoint =  strUrl.c_str();
	soap_wsse_add_Security(&ImageProxy);
	soap_wsse_add_UsernameTokenDigest(&ImageProxy, "Id", strUser.c_str() , strPass.c_str());

	_timg__GetServiceCapabilities GetServiceCapReq;

	return ImageProxy.GetServiceCapabilities(&GetServiceCapReq,&GetServiceCapResponse);

}

inline int OnvifClientImaging::GetOptions(_timg__GetOptionsResponse &GetOptionsResponse, string videoSourceToken)
{
	string strUrl;
	string strUser;
	string strPass;
	if (m_Device.GetUserPasswd(strUser, strPass) == false 
		|| m_Device.GetImagingUrl(strUrl) == false)
	{
		return SOAP_ERR;
	}
	ImageProxy.soap_endpoint =  strUrl.c_str();
	soap_wsse_add_Security(&ImageProxy);
	soap_wsse_add_UsernameTokenDigest(&ImageProxy, "Id", strUser.c_str() , strPass.c_str());

	_timg__GetOptions GetOptionsReq;
	GetOptionsReq.VideoSourceToken = videoSourceToken;

	return ImageProxy.GetOptions(&GetOptionsReq,&GetOptionsResponse);


}

inline int OnvifClientImaging::GetImagingSettings(_timg__GetImagingSettingsResponse &ImagingSettingsResponse, string videoSourceToken)
{
	string strUrl;
	string strUser;
	string strPass;
	if (m_Device.GetUserPasswd(strUser, strPass) == false 
		|| m_Device.GetImagingUrl(strUrl) == false)
	{
		return SOAP_ERR;
	}
	ImageProxy.soap_endpoint =  strUrl.c_str();
	soap_wsse_add_Security(&ImageProxy);
	soap_wsse_add_UsernameTokenDigest(&ImageProxy, "Id", strUser.c_str() , strPass.c_str());

	_timg__GetImagingSettings ImagingSettingsReq;
	ImagingSettingsReq.VideoSourceToken = videoSourceToken;

	return ImageProxy.GetImagingSettings(&ImagingSettingsReq,&ImagingSettingsResponse);

}





inline OnvifClientImaging::OnvifClientImaging(OnvifClientDevice &device)
: m_Device(device)
{

}

inline OnvifClientImaging::~OnvifClientImaging()
{

}


#endif 