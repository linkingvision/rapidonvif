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
				
private:
	OnvifClientDevice &m_Device;

};

inline OnvifClientReceiver::OnvifClientReceiver(OnvifClientDevice &device)
: m_Device(device)
{

}

inline OnvifClientReceiver::~OnvifClientReceiver()
{

}


#endif 