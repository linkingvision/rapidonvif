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
	/* Add function to here */
				
private:
	OnvifClientDevice &m_Device;

};

inline OnvifClientImaging::OnvifClientImaging(OnvifClientDevice &device)
: m_Device(device)
{

}

inline OnvifClientImaging::~OnvifClientImaging()
{

}


#endif 