#ifndef __ONVIF_CLIENT_PTZ__
#define __ONVIF_CLIENT_PTZ__

#include <string>
#include <map>
#include <iostream>
#include <list>

#include "onvifclientdevice.hpp"
#include "soapStub.h"
#include "soapPTZBindingProxy.h"
#include "wsseapi.h"
//#include "soapC.h"


using namespace std;

class OnvifClientPTZ
{
public:
    OnvifClientPTZ(OnvifClientDevice &device);
    ~OnvifClientPTZ();

	bool m_bHasRelativePTMove;
	bool m_bHasRelativeZoomMove;
	bool m_bHasAbsolutePTMove;
	bool m_bHasAbsoluteZoomMove;
	bool m_bHasContinuousPTMove;
	bool m_bHasContinuousZoomMove;

public:
	/* Add function to here */
	//Configuration functions
	int OnvifClientPTZ::GetConfiguration(_tptz__GetConfigurationResponse &configurationResp); // John 7/2
	int OnvifClientPTZ::GetConfigurations(_tptz__GetConfigurationsResponse &configurationsResp);
	int OnvifClientPTZ::GetConfigurationOptions(_tptz__GetConfigurationOptionsResponse &configOptions, string configToken); // John 7/2
	int OnvifClientPTZ::SetConfiguration(_tptz__SetConfigurationResponse &SetConfiguration, tt__PTZConfiguration &PTZConfiguration,bool ForcePersist);
	//Move Functions (includes Pan, Tilt, and Zoom Moves)
	int OnvifClientPTZ::RelativeMove(_tptz__RelativeMoveResponse &relMoveResponse, tt__PTZVector &Translation, tt__PTZSpeed &Speed, string profileToken);
	int OnvifClientPTZ::ContinuousMove(_tptz__ContinuousMoveResponse &ContMoveResponse, tt__PTZSpeed &Speed, LONG64 &Timeout, string profileToken);
	int OnvifClientPTZ::AbsoluteMove(_tptz__AbsoluteMoveResponse &AbsoluteMoveResponse, tt__PTZSpeed &Speed, tt__PTZVector &position, string profileToken);
	int OnvifClientPTZ::Stop(_tptz__StopResponse &StopResponse,bool PanTilt,bool Zoom,string profileToken);
	//Zoom Functions
	//TODO:

	//Node, status, and service capabilities
	int OnvifClientPTZ::GetNodes(_tptz__GetNodesResponse &GetNodesResponse);
	int OnvifClientPTZ::GetNode(_tptz__GetNodeResponse &GetNodeResponse, string nodeToken);
	int OnvifClientPTZ::GetStatus(_tptz__GetStatusResponse &StatusResponse,string profileToken);
	int OnvifClientPTZ::GetServiceCapabilities(_tptz__GetServiceCapabilitiesResponse &ServiceCapResponse);

	int OnvifClientPTZ::Initialize();

private:
	OnvifClientDevice &m_Device;
	PTZBindingProxy ptzProxy;

};


/* Added by John 7/2/14 */
int OnvifClientPTZ::Initialize()
{
	_tptz__GetConfigurationsResponse GetConfigsResp;
	
	if(GetConfigurations(GetConfigsResp)!=0)
		return -1;

	if(GetConfigsResp.PTZConfiguration[0]->DefaultAbsolutePantTiltPositionSpace) 
		m_bHasAbsolutePTMove = TRUE; else m_bHasAbsolutePTMove = FALSE;
	if(GetConfigsResp.PTZConfiguration[0]->DefaultAbsoluteZoomPositionSpace)
		m_bHasAbsoluteZoomMove = TRUE; else m_bHasAbsoluteZoomMove = FALSE;
	if(GetConfigsResp.PTZConfiguration[0]->DefaultRelativePanTiltTranslationSpace)
		m_bHasRelativePTMove = TRUE; else m_bHasRelativePTMove = FALSE;
	if(GetConfigsResp.PTZConfiguration[0]->DefaultRelativeZoomTranslationSpace)
		m_bHasRelativeZoomMove = TRUE; else m_bHasRelativeZoomMove = FALSE;
	if(GetConfigsResp.PTZConfiguration[0]->DefaultContinuousPanTiltVelocitySpace)
		m_bHasContinuousPTMove = TRUE; else m_bHasContinuousPTMove = FALSE;
	if(GetConfigsResp.PTZConfiguration[0]->DefaultContinuousZoomVelocitySpace)
		m_bHasContinuousZoomMove = TRUE; else m_bHasContinuousZoomMove = FALSE;
	
	return 0;

}


int OnvifClientPTZ::Stop(_tptz__StopResponse &StopResponse,bool PanTilt,bool Zoom,string profileToken)
{
	string strUrl;
	string strUser;
	string strPass;

	if (m_Device.GetUserPasswd(strUser, strPass) == false 
		|| m_Device.GetPTZUrl(strUrl) == false)
	{
		return SOAP_ERR;
	}
	ptzProxy.soap_endpoint =  strUrl.c_str();
	soap_wsse_add_Security(&ptzProxy);
	soap_wsse_add_UsernameTokenDigest(&ptzProxy, "Id", strUser.c_str() , strPass.c_str());

	_tptz__Stop StopReq;
	StopReq.PanTilt = &PanTilt;
	StopReq.ProfileToken = profileToken;
	StopReq.Zoom = &Zoom;
	return ptzProxy.Stop(&StopReq,&StopResponse);
}

	int OnvifClientPTZ::AbsoluteMove(_tptz__AbsoluteMoveResponse &AbsoluteMoveResponse, tt__PTZSpeed &Speed, tt__PTZVector &position, string profileToken)
{
	if(!m_bHasAbsolutePTMove || !m_bHasAbsoluteZoomMove) {
		cout << "Error, device does not support Absolute movement" << endl;
		//return -1;
	}
	string strUrl;
	string strUser;
	string strPass;

	if (m_Device.GetUserPasswd(strUser, strPass) == false 
		|| m_Device.GetPTZUrl(strUrl) == false)
	{
		return SOAP_ERR;
	}
	ptzProxy.soap_endpoint =  strUrl.c_str();
	soap_wsse_add_Security(&ptzProxy);
	soap_wsse_add_UsernameTokenDigest(&ptzProxy, "Id", strUser.c_str() , strPass.c_str());

	_tptz__AbsoluteMove AbsoluteMoveReq;
	AbsoluteMoveReq.ProfileToken = profileToken;
	AbsoluteMoveReq.Position = &position;
	AbsoluteMoveReq.Speed = &Speed;

	return ptzProxy.AbsoluteMove(&AbsoluteMoveReq,&AbsoluteMoveResponse);

}

int OnvifClientPTZ::RelativeMove(_tptz__RelativeMoveResponse &relMoveResponse, tt__PTZVector &Translation, tt__PTZSpeed &Speed, string profileToken)
{

	if(!m_bHasRelativePTMove || !m_bHasRelativeZoomMove) {
		cout << "Error, device does not support Relative movement" << endl;
		//return -1;
	}

	string strUrl;
	string strUser;
	string strPass;

	_tptz__RelativeMove relMoveReq;

	relMoveReq.ProfileToken = profileToken;
	relMoveReq.Translation = &Translation;
	relMoveReq.Speed = &Speed;

	if (m_Device.GetUserPasswd(strUser, strPass) == false 
		|| m_Device.GetPTZUrl(strUrl) == false)
	{
		return SOAP_ERR;
	}

	return ptzProxy.RelativeMove(&relMoveReq,&relMoveResponse);

	//_tptz__GetNodes getNodesReq;
	//_tptz__GetNodesResponse getNodesResp;

	//ptzProxy.GetNodes(&getNodesReq,&getNodesResp);
}

int OnvifClientPTZ::ContinuousMove(_tptz__ContinuousMoveResponse &ContMoveResponse, tt__PTZSpeed &Speed, LONG64 &Timeout, string profileToken)
{
	if(!m_bHasContinuousPTMove || !m_bHasContinuousZoomMove) {
		cout << "Error, device does not support Continuous movement" << endl;
		//return -1;
	}

	string strUrl;
	string strUser;
	string strPass;

	if (m_Device.GetUserPasswd(strUser, strPass) == false 
		|| m_Device.GetPTZUrl(strUrl) == false)
	{
		return SOAP_ERR;
	}
	ptzProxy.soap_endpoint =  strUrl.c_str();
	soap_wsse_add_Security(&ptzProxy);
	soap_wsse_add_UsernameTokenDigest(&ptzProxy, "Id", strUser.c_str() , strPass.c_str());

	_tptz__ContinuousMove ContMoveReq;
	ContMoveReq.ProfileToken = profileToken;
	ContMoveReq.Velocity = &Speed;
	ContMoveReq.Timeout = &Timeout;

	return ptzProxy.ContinuousMove(&ContMoveReq,&ContMoveResponse);
}

int OnvifClientPTZ::SetConfiguration(_tptz__SetConfigurationResponse &SetConfigurationResponse, tt__PTZConfiguration &PTZConfiguration,bool ForcePersist)
{
	string strUrl;
	string strUser;
	string strPass;
	if (m_Device.GetUserPasswd(strUser, strPass) == false 
		|| m_Device.GetPTZUrl(strUrl) == false)
	{
		return SOAP_ERR;
	}
	ptzProxy.soap_endpoint =  strUrl.c_str();
	soap_wsse_add_Security(&ptzProxy);
	soap_wsse_add_UsernameTokenDigest(&ptzProxy, "Id", strUser.c_str() , strPass.c_str());

	_tptz__SetConfiguration SetConfigurationReq;
	SetConfigurationReq.PTZConfiguration = &PTZConfiguration;
	SetConfigurationReq.ForcePersistence = ForcePersist;

	return ptzProxy.SetConfiguration(&SetConfigurationReq,&SetConfigurationResponse);
}

int OnvifClientPTZ::GetServiceCapabilities(_tptz__GetServiceCapabilitiesResponse &ServiceCapResponse)
{
	string strUrl;
	string strUser;
	string strPass;
	if (m_Device.GetUserPasswd(strUser, strPass) == false 
		|| m_Device.GetPTZUrl(strUrl) == false)
	{
		return SOAP_ERR;
	}
	ptzProxy.soap_endpoint =  strUrl.c_str();
	soap_wsse_add_Security(&ptzProxy);
	soap_wsse_add_UsernameTokenDigest(&ptzProxy, "Id", strUser.c_str() , strPass.c_str());

	_tptz__GetServiceCapabilities ServiceCapReq;

	return ptzProxy.GetServiceCapabilities(&ServiceCapReq,&ServiceCapResponse);

}

int OnvifClientPTZ::GetStatus(_tptz__GetStatusResponse &StatusResponse,string profileToken)
{
	string strUrl;
	string strUser;
	string strPass;
	if (m_Device.GetUserPasswd(strUser, strPass) == false 
		|| m_Device.GetPTZUrl(strUrl) == false)
	{
		return SOAP_ERR;
	}
	ptzProxy.soap_endpoint =  strUrl.c_str();
	soap_wsse_add_Security(&ptzProxy);
	soap_wsse_add_UsernameTokenDigest(&ptzProxy, "Id", strUser.c_str() , strPass.c_str());

	_tptz__GetStatus StatusReq;
	StatusReq.ProfileToken = profileToken;
	return ptzProxy.GetStatus(&StatusReq,&StatusResponse);

}

int OnvifClientPTZ::GetNode(_tptz__GetNodeResponse &GetNodeResponse, string nodeToken)
{
	string strUrl;
	string strUser;
	string strPass;

	if (m_Device.GetUserPasswd(strUser, strPass) == false 
		|| m_Device.GetPTZUrl(strUrl) == false)
	{
		return SOAP_ERR;
	}
	ptzProxy.soap_endpoint =  strUrl.c_str();
	soap_wsse_add_Security(&ptzProxy);
	soap_wsse_add_UsernameTokenDigest(&ptzProxy, "Id", strUser.c_str() , strPass.c_str());

	_tptz__GetNode GetNodeReq;
	GetNodeReq.NodeToken = nodeToken;

	return ptzProxy.GetNode(&GetNodeReq,&GetNodeResponse);
}

int OnvifClientPTZ::GetNodes(_tptz__GetNodesResponse &GetNodesResponse)
{
	string strUrl;
	string strUser;
	string strPass;

	_tptz__GetNodes GetNodesReq;

	//ptzProxy.GetNodes(&GetNodesReq, &GetNodesResponse);

	if (m_Device.GetUserPasswd(strUser, strPass) == false 
		|| m_Device.GetPTZUrl(strUrl) == false)
	{
		return SOAP_ERR;
	}

	ptzProxy.soap_endpoint =  strUrl.c_str();
	
	soap_wsse_add_Security(&ptzProxy);
	soap_wsse_add_UsernameTokenDigest(&ptzProxy, "Id", strUser.c_str() , strPass.c_str());

	return ptzProxy.GetNodes(&GetNodesReq,&GetNodesResponse);

}

int OnvifClientPTZ::GetConfigurations(_tptz__GetConfigurationsResponse &configurationsResp)
{
	string strUrl;
	string strUser;
	string strPass;
	_tptz__GetConfigurations	configurationsReq;
	
	if (m_Device.GetUserPasswd(strUser, strPass) == false 
		|| m_Device.GetPTZUrl(strUrl) == false)
	{
		return SOAP_ERR;
	}
	
	ptzProxy.soap_endpoint =  strUrl.c_str();
	
	soap_wsse_add_Security(&ptzProxy);
	soap_wsse_add_UsernameTokenDigest(&ptzProxy, "Id", 
		strUser.c_str() , strPass.c_str());
		
	return ptzProxy.GetConfigurations( &configurationsReq, &configurationsResp) ;
}

int OnvifClientPTZ::GetConfiguration(_tptz__GetConfigurationResponse &configurationResp)
{
	string strUrl;
	string strUser;
	string strPass;
	_tptz__GetConfiguration	configurationReq;
	
	if (m_Device.GetUserPasswd(strUser, strPass) == false 
		|| m_Device.GetPTZUrl(strUrl) == false)
	{
		return SOAP_ERR;
	}
	
	ptzProxy.soap_endpoint =  strUrl.c_str();
	
	soap_wsse_add_Security(&ptzProxy);
	soap_wsse_add_UsernameTokenDigest(&ptzProxy, "Id", 
		strUser.c_str() , strPass.c_str());
		
	return ptzProxy.GetConfiguration( &configurationReq, &configurationResp) ;
}

int OnvifClientPTZ::GetConfigurationOptions(_tptz__GetConfigurationOptionsResponse &configOptions, string configToken)
{
	string strUrl;
	string strUser;
	string strPass;
	_tptz__GetConfigurationOptions	configurationOptionsReq;
	configurationOptionsReq.ConfigurationToken = configToken;
	
	if (m_Device.GetUserPasswd(strUser, strPass) == false 
		|| m_Device.GetPTZUrl(strUrl) == false)
	{
		return SOAP_ERR;
	}

	ptzProxy.soap_endpoint =  strUrl.c_str();
	
	soap_wsse_add_Security(&ptzProxy);
	soap_wsse_add_UsernameTokenDigest(&ptzProxy, "Id", 
		strUser.c_str() , strPass.c_str());
		
	return ptzProxy.GetConfigurationOptions( &configurationOptionsReq, &configOptions) ;

}

/* END - Added by John 7/2/14 */

OnvifClientPTZ::OnvifClientPTZ(OnvifClientDevice &device)
: m_Device(device)
{
	if(m_Device.GetCapabilities()==SOAP_OK)
		Initialize();
}

OnvifClientPTZ::~OnvifClientPTZ()
{

}


#endif 