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
	//Profile Functions
    int OnvifClientMedia::GetProfiles(_trt__GetProfilesResponse &profiles);
	int OnvifClientMedia::GetProfile(_trt__GetProfileResponse &profileResponse,string profileToken);
	int OnvifClientMedia::CreateProfile(_trt__CreateProfileResponse &CreateProfileResponse,string Name,string token);
	//Uri and streaming functions
	int OnvifClientMedia::GetSnapshotUri(_trt__GetSnapshotUriResponse &SnapshotUriResponse,string profileToken);
	int OnvifClientMedia::GetStreamUri(_trt__GetStreamUriResponse &StreamUriResponse,tt__StreamSetup &StreamSetup, string profileToken);
	int OnvifClientMedia::GetServiceCapabilities(_trt__GetServiceCapabilitiesResponse &GetServiceCapResponse);
	int OnvifClientMedia::StartMulticastStreaming(_trt__StartMulticastStreamingResponse &StartMulticastResponse,string profileToken);
	int OnvifClientMedia::StopMulticastStreaming(_trt__StopMulticastStreamingResponse &StopMulticastResponse,string profileToken);
	//Video Source Functions
	int OnvifClientMedia::GetVideoSources(_trt__GetVideoSourcesResponse &GetVideoSourcesResponse);
	int OnvifClientMedia::GetVideoSourceConfigurations(_trt__GetVideoSourceConfigurationsResponse &GetVideoSourceConfigResponse);
	int OnvifClientMedia::SetVideoSourceConfiguration(_trt__SetVideoSourceConfigurationResponse &SetVideoSourceConfigResponse);
	int OnvifClientMedia::GetVideoSourceConfiguration(_trt__GetVideoSourceConfigurationResponse &GetVideoSourceConfigResponse,string ConfigurationToken);
	int OnvifClientMedia::GetVideoSourceConfigurationOptions(_trt__GetVideoSourceConfigurationOptionsResponse &GetVideoSourceConfigOptionsResponse, string ConfigurationToken,string profileToken);
	//Meta data functions
	int OnvifClientMedia::GetMetadataConfigurations(_trt__GetMetadataConfigurationsResponse &GetMetadataConfigurationsResponse);
	int OnvifClientMedia::GetMetadataConfiguration(_trt__GetMetadataConfigurationResponse &GetMetadataConfigurationResponse,string profileToken);
	int OnvifClientMedia::GetMetadataConfigurationOptions(_trt__GetMetadataConfigurationOptionsResponse &GetMetadataConfigurationOptionsResponse,string ConfigToken,string profileToken);

private:
	OnvifClientDevice &m_Device;
	MediaBindingProxy  mediaProxy;

};

int OnvifClientMedia::GetMetadataConfigurationOptions(_trt__GetMetadataConfigurationOptionsResponse &GetMetadataConfigurationOptionsResponse,string ConfigToken,string profileToken)
{
	string strUrl;
	string strUser;
	string strPass;
	if (m_Device.GetUserPasswd(strUser, strPass) == false 
		|| m_Device.GetMediaUrl(strUrl) == false)
	{
		return SOAP_ERR;
	}
	mediaProxy.soap_endpoint =  strUrl.c_str();
	soap_wsse_add_Security(&mediaProxy);
	soap_wsse_add_UsernameTokenDigest(&mediaProxy, "Id", strUser.c_str() , strPass.c_str());

	_trt__GetMetadataConfigurationOptions GetMetadataConfigurationOptionsReq;
	GetMetadataConfigurationOptionsReq.ConfigurationToken = &ConfigToken;
	GetMetadataConfigurationOptionsReq.ProfileToken = &profileToken;
	return mediaProxy.GetMetadataConfigurationOptions(&GetMetadataConfigurationOptionsReq,&GetMetadataConfigurationOptionsResponse);
}

int OnvifClientMedia::GetMetadataConfiguration(_trt__GetMetadataConfigurationResponse &GetMetadataConfigurationResponse,string profileToken)
{
	string strUrl;
	string strUser;
	string strPass;
	if (m_Device.GetUserPasswd(strUser, strPass) == false 
		|| m_Device.GetMediaUrl(strUrl) == false)
	{
		return SOAP_ERR;
	}
	mediaProxy.soap_endpoint =  strUrl.c_str();
	soap_wsse_add_Security(&mediaProxy);
	soap_wsse_add_UsernameTokenDigest(&mediaProxy, "Id", strUser.c_str() , strPass.c_str());

	_trt__GetMetadataConfiguration GetMetadataConfigurationReq;
	GetMetadataConfigurationReq.ConfigurationToken = profileToken;
	return mediaProxy.GetMetadataConfiguration(&GetMetadataConfigurationReq,&GetMetadataConfigurationResponse);
}

int OnvifClientMedia::GetMetadataConfigurations(_trt__GetMetadataConfigurationsResponse &GetMetadataConfigurationsResponse)
{
	string strUrl;
	string strUser;
	string strPass;
	if (m_Device.GetUserPasswd(strUser, strPass) == false 
		|| m_Device.GetMediaUrl(strUrl) == false)
	{
		return SOAP_ERR;
	}
	mediaProxy.soap_endpoint =  strUrl.c_str();
	soap_wsse_add_Security(&mediaProxy);
	soap_wsse_add_UsernameTokenDigest(&mediaProxy, "Id", strUser.c_str() , strPass.c_str());

	_trt__GetMetadataConfigurations GetMetadataConfigurationsReq;

	return mediaProxy.GetMetadataConfigurations(&GetMetadataConfigurationsReq,&GetMetadataConfigurationsResponse);
}

int OnvifClientMedia::GetVideoSourceConfigurationOptions(_trt__GetVideoSourceConfigurationOptionsResponse &GetVideoSourceConfigOptionsResponse, string ConfigurationToken,string profileToken)
{
	string strUrl;
	string strUser;
	string strPass;
	if (m_Device.GetUserPasswd(strUser, strPass) == false 
		|| m_Device.GetMediaUrl(strUrl) == false)
	{
		return SOAP_ERR;
	}
	mediaProxy.soap_endpoint =  strUrl.c_str();
	soap_wsse_add_Security(&mediaProxy);
	soap_wsse_add_UsernameTokenDigest(&mediaProxy, "Id", strUser.c_str() , strPass.c_str());

	_trt__GetVideoSourceConfigurationOptions GetVideoSourceConfigOptionsReq;
	GetVideoSourceConfigOptionsReq.ConfigurationToken = &ConfigurationToken;
	GetVideoSourceConfigOptionsReq.ProfileToken = &profileToken;

	return mediaProxy.GetVideoSourceConfigurationOptions(&GetVideoSourceConfigOptionsReq,&GetVideoSourceConfigOptionsResponse);
}

int OnvifClientMedia::SetVideoSourceConfiguration(_trt__SetVideoSourceConfigurationResponse &SetVideoSourceConfigResponse)
{
	string strUrl;
	string strUser;
	string strPass;
	if (m_Device.GetUserPasswd(strUser, strPass) == false 
		|| m_Device.GetMediaUrl(strUrl) == false)
	{
		return SOAP_ERR;
	}
	mediaProxy.soap_endpoint =  strUrl.c_str();
	soap_wsse_add_Security(&mediaProxy);
	soap_wsse_add_UsernameTokenDigest(&mediaProxy, "Id", strUser.c_str() , strPass.c_str());

	_trt__SetVideoSourceConfiguration SetVideoSourceConfigReq;

	return mediaProxy.SetVideoSourceConfiguration(&SetVideoSourceConfigReq,&SetVideoSourceConfigResponse);
}

int OnvifClientMedia::GetVideoSourceConfiguration(_trt__GetVideoSourceConfigurationResponse &GetVideoSourceConfigResponse,string ConfigurationToken)
{
	string strUrl;
	string strUser;
	string strPass;
	if (m_Device.GetUserPasswd(strUser, strPass) == false 
		|| m_Device.GetMediaUrl(strUrl) == false)
	{
		return SOAP_ERR;
	}
	mediaProxy.soap_endpoint =  strUrl.c_str();
	soap_wsse_add_Security(&mediaProxy);
	soap_wsse_add_UsernameTokenDigest(&mediaProxy, "Id", strUser.c_str() , strPass.c_str());

	_trt__GetVideoSourceConfiguration GetVideoSourceConfigReq;
	GetVideoSourceConfigReq.ConfigurationToken = ConfigurationToken;
	return mediaProxy.GetVideoSourceConfiguration(&GetVideoSourceConfigReq,&GetVideoSourceConfigResponse);
}

int OnvifClientMedia::GetVideoSourceConfigurations(_trt__GetVideoSourceConfigurationsResponse &GetVideoSourceConfigResponse)
{
	string strUrl;
	string strUser;
	string strPass;
	if (m_Device.GetUserPasswd(strUser, strPass) == false 
		|| m_Device.GetMediaUrl(strUrl) == false)
	{
		return SOAP_ERR;
	}
	mediaProxy.soap_endpoint =  strUrl.c_str();
	soap_wsse_add_Security(&mediaProxy);
	soap_wsse_add_UsernameTokenDigest(&mediaProxy, "Id", strUser.c_str() , strPass.c_str());

	_trt__GetVideoSourceConfigurations GetVideoSourceConfigReq;

	return mediaProxy.GetVideoSourceConfigurations(&GetVideoSourceConfigReq,&GetVideoSourceConfigResponse);
}

int OnvifClientMedia::GetVideoSources(_trt__GetVideoSourcesResponse &GetVideoSourcesResponse)
{
	string strUrl;
	string strUser;
	string strPass;
	if (m_Device.GetUserPasswd(strUser, strPass) == false 
		|| m_Device.GetMediaUrl(strUrl) == false)
	{
		return SOAP_ERR;
	}
	mediaProxy.soap_endpoint =  strUrl.c_str();
	soap_wsse_add_Security(&mediaProxy);
	soap_wsse_add_UsernameTokenDigest(&mediaProxy, "Id", strUser.c_str() , strPass.c_str());

	_trt__GetVideoSources GetVideoSourcesReq;

	return mediaProxy.GetVideoSources(&GetVideoSourcesReq,&GetVideoSourcesResponse);
}

int OnvifClientMedia::CreateProfile(_trt__CreateProfileResponse &CreateProfileResponse,string Name,string token)
{
	string strUrl;
	string strUser;
	string strPass;
	if (m_Device.GetUserPasswd(strUser, strPass) == false 
		|| m_Device.GetMediaUrl(strUrl) == false)
	{
		return SOAP_ERR;
	}
	mediaProxy.soap_endpoint =  strUrl.c_str();
	soap_wsse_add_Security(&mediaProxy);
	soap_wsse_add_UsernameTokenDigest(&mediaProxy, "Id", strUser.c_str() , strPass.c_str());

	_trt__CreateProfile CreateProfileReq;
	CreateProfileReq.Name = Name;
	CreateProfileReq.Token = &token;

	return mediaProxy.CreateProfile(&CreateProfileReq,&CreateProfileResponse);
}

int OnvifClientMedia::StopMulticastStreaming(_trt__StopMulticastStreamingResponse &StopMulticastResponse,string profileToken)
{
	string strUrl;
	string strUser;
	string strPass;
	if (m_Device.GetUserPasswd(strUser, strPass) == false 
		|| m_Device.GetMediaUrl(strUrl) == false)
	{
		return SOAP_ERR;
	}
	mediaProxy.soap_endpoint =  strUrl.c_str();
	soap_wsse_add_Security(&mediaProxy);
	soap_wsse_add_UsernameTokenDigest(&mediaProxy, "Id", strUser.c_str() , strPass.c_str());

	_trt__StopMulticastStreaming StopMulticastReq;
	StopMulticastReq.ProfileToken = profileToken;

	return mediaProxy.StopMulticastStreaming(&StopMulticastReq,&StopMulticastResponse);

}

int OnvifClientMedia::StartMulticastStreaming(_trt__StartMulticastStreamingResponse &StartMulticastResponse,string profileToken)
{
	string strUrl;
	string strUser;
	string strPass;
	if (m_Device.GetUserPasswd(strUser, strPass) == false 
		|| m_Device.GetMediaUrl(strUrl) == false)
	{
		return SOAP_ERR;
	}
	mediaProxy.soap_endpoint =  strUrl.c_str();
	soap_wsse_add_Security(&mediaProxy);
	soap_wsse_add_UsernameTokenDigest(&mediaProxy, "Id", strUser.c_str() , strPass.c_str());

	_trt__StartMulticastStreaming StartMulticastReq;
	StartMulticastReq.ProfileToken = profileToken;
	return mediaProxy.StartMulticastStreaming(&StartMulticastReq,&StartMulticastResponse);

}

int OnvifClientMedia::GetServiceCapabilities(_trt__GetServiceCapabilitiesResponse &GetServiceCapResponse)
{
	string strUrl;
	string strUser;
	string strPass;
	if (m_Device.GetUserPasswd(strUser, strPass) == false 
		|| m_Device.GetMediaUrl(strUrl) == false)
	{
		return SOAP_ERR;
	}
	mediaProxy.soap_endpoint =  strUrl.c_str();
	soap_wsse_add_Security(&mediaProxy);
	soap_wsse_add_UsernameTokenDigest(&mediaProxy, "Id", strUser.c_str() , strPass.c_str());

	_trt__GetServiceCapabilities GetServiceCapReq;

	return mediaProxy.GetServiceCapabilities(&GetServiceCapReq,&GetServiceCapResponse);

}

int OnvifClientMedia::GetStreamUri(_trt__GetStreamUriResponse &StreamUriResponse,tt__StreamSetup &StreamSetup, string profileToken)
{
	string strUrl;
	string strUser;
	string strPass;
	if (m_Device.GetUserPasswd(strUser, strPass) == false 
		|| m_Device.GetMediaUrl(strUrl) == false)
	{
		return SOAP_ERR;
	}

	mediaProxy.soap_endpoint =  strUrl.c_str();
	soap_wsse_add_Security(&mediaProxy);
	soap_wsse_add_UsernameTokenDigest(&mediaProxy, "Id", strUser.c_str() , strPass.c_str());


	_trt__GetStreamUri StreamUriReq;
	StreamUriReq.ProfileToken = profileToken;
	StreamUriReq.StreamSetup = &StreamSetup;

	return mediaProxy.GetStreamUri(&StreamUriReq, &StreamUriResponse);

}

OnvifClientMedia::OnvifClientMedia(OnvifClientDevice &device)
: m_Device(device), mediaProxy(SOAP_C_UTFSTRING)
{

}

OnvifClientMedia::~OnvifClientMedia()
{

}

int OnvifClientMedia::GetProfiles(_trt__GetProfilesResponse &profilesResponse)
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
	
	mediaProxy.soap_endpoint =  strUrl.c_str();
	
	soap_wsse_add_Security(&mediaProxy);
	soap_wsse_add_UsernameTokenDigest(&mediaProxy, "Id", 
		strUser.c_str() , strPass.c_str());
		
	return mediaProxy.GetProfiles( &profilesReq, &profilesResponse) ;
}

inline int OnvifClientMedia::GetProfile(_trt__GetProfileResponse &profileResponse,string profileToken)
{
	string strUrl;
	string strUser;
	string strPass;
	if (m_Device.GetUserPasswd(strUser, strPass) == false || m_Device.GetMediaUrl(strUrl) == false)
	{
		return SOAP_ERR;
	}
	mediaProxy.soap_endpoint =  strUrl.c_str();
	soap_wsse_add_Security(&mediaProxy);
	soap_wsse_add_UsernameTokenDigest(&mediaProxy, "Id", 
		strUser.c_str() , strPass.c_str());
		
	_trt__GetProfile profileReq;
	profileReq.ProfileToken = profileToken;
	return mediaProxy.GetProfile( &profileReq, &profileResponse) ;
}

inline int OnvifClientMedia::GetSnapshotUri(_trt__GetSnapshotUriResponse &SnapshotUriResponse,string profileToken)
{
	string strUrl;
	string strUser;
	string strPass;
	if (m_Device.GetUserPasswd(strUser, strPass) == false 
		|| m_Device.GetMediaUrl(strUrl) == false)
	{
		return SOAP_ERR;
	}

	mediaProxy.soap_endpoint =  strUrl.c_str();
	soap_wsse_add_Security(&mediaProxy);
	soap_wsse_add_UsernameTokenDigest(&mediaProxy, "Id", strUser.c_str() , strPass.c_str());


	_trt__GetSnapshotUri SnapshotUriReq;

	return mediaProxy.GetSnapshotUri(&SnapshotUriReq, &SnapshotUriResponse);

}



#endif /* __ONVIF_CLIENT_MEDIA__ */