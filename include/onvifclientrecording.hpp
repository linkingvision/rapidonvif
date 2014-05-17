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


#endif 