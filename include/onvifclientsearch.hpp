#ifndef __ONVIF_CLIENT_SEARCH__
#define __ONVIF_CLIENT_SEARCH__

#include <string>
#include <map>
#include <iostream>
#include <list>

#include "onvifclientdevice.hpp"
#include "soapStub.h"
#include "soapSearchBindingProxy.h"
#include "wsseapi.h"


using namespace std;

class OnvifClientSearch
{
public:
    OnvifClientSearch(OnvifClientDevice &device);
    ~OnvifClientSearch();
public:
	/* Add function to here */
				
private:
	OnvifClientDevice &m_Device;

};

inline OnvifClientSearch::OnvifClientSearch(OnvifClientDevice &device)
: m_Device(device)
{

}

inline OnvifClientSearch::~OnvifClientSearch()
{

}


#endif 