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


#endif 