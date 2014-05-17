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


using namespace std;

class OnvifClientPTZ
{
public:
    OnvifClientPTZ(OnvifClientDevice &device);
    ~OnvifClientPTZ();
public:
	/* Add function to here */
				
private:
	OnvifClientDevice &m_Device;

};

inline OnvifClientPTZ::OnvifClientPTZ(OnvifClientDevice &device)
: m_Device(device)
{

}

inline OnvifClientPTZ::~OnvifClientPTZ()
{

}


#endif 