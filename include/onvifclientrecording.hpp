#ifndef __ONVIF_CLIENT_RECORDING__
#define __ONVIF_CLIENT_RECORDING__

#include <string>
#include <map>
#include <iostream>
#include <list>

#include "onvifclientdevice.hpp"
#include "soapStub.h"
#include "soapRecordingBindingProxy.h"
#include "wsseapi.h"


using namespace std;

class OnvifClientRecording
{
public:
    OnvifClientRecording(OnvifClientDevice &device);
    ~OnvifClientRecording();
public:
	/* Add function to here */
	int GetRecordings(_trc__GetRecordingsResponse &recordings);
				
private:
	OnvifClientDevice &m_Device;

};

inline OnvifClientRecording::OnvifClientRecording(OnvifClientDevice &device)
: m_Device(device)
{

}

inline OnvifClientRecording::~OnvifClientRecording()
{

}

inline int OnvifClientRecording::GetRecordings(_trc__GetRecordingsResponse &recordings)
{
	_trc__GetRecordings req;
	string strUrl;
	string strUser;
	string strPass;
	
	if (m_Device.GetUserPasswd(strUser, strPass) == false 
		|| m_Device.GetMediaUrl(strUrl) == false)
	{
		return SOAP_ERR;
	}
	
	RecordingBindingProxy  recordingProxy(SOAP_C_UTFSTRING);
	recordingProxy.soap_endpoint =  strUrl.c_str();
	
	soap_wsse_add_Security(&recordingProxy);
	soap_wsse_add_UsernameTokenDigest(&recordingProxy, "Id", 
		strUser.c_str() , strPass.c_str());
		
	return recordingProxy.GetRecordings( &req, &recordings);
}


#endif 