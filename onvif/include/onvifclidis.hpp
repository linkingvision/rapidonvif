
#ifndef __ONVIF_DIS_CLIENT__
#define __ONVIF_DIS_CLIENT__

#include <cstdlib>
#include <thread>
#include <mutex>
#include <string.h>
#include <vector>
#include <iostream>
#include <thread>
#include <mutex>
#include <chrono>
#include <map>

#if (defined(_WIN32) || defined(_WIN64))
#pragma warning(disable:4996)
#include <ObjBase.h>
#include <Iphlpapi.h>
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "WS2_32.lib")
#pragma comment(lib, "ole32.lib")
#else //linux
#include <ifaddrs.h>
#include <arpa/inet.h>
#endif // WIN32 | WIN64

class CamSearchNotify
{
public:
	virtual bool NewCam(astring strIP, astring strPort, 
			astring strModel, astring strONVIFAddr){return false;}
};


/* Each interface will have a interface,
TODO process blow case
QList<QHostAddress> DeviceSearcher::getHostAddress()
{
	QList<QHostAddress> ipAddressesList = QNetworkInterface::allAddresses();
	QList<QHostAddress> ipAddressesIPV4;
	
	// skip IPV6 address
	QList<QHostAddress>::iterator i;
	for(i=ipAddressesList.begin();i!=ipAddressesList.end();i++)
	{
		std::string ip = (*i).toString().toStdString();
		size_t p1 = ip.find("127.");
		if (p1 != std::string::npos) 
		{
			continue;
		}
		size_t p2 = ip.find(":");
		if (p2 != std::string::npos) 
		{
			continue;
		}
		ipAddressesIPV4.append(*i);
	}
	
	return ipAddressesIPV4;
}


*/
class  OnvifDisClient
{
public:
	OnvifDisClient(std::string strAddr, CamSearchNotify & pNotify)
	: m_pNotify(pNotify), m_pThread(NULL), m_bStarted(false), m_bExit(false), 
	m_strAddr(strAddr)
	{
		
	}
	~OnvifDisClient()
	{
		Stop();
	}

public:
	static std::vector<std::string> GetInterfaces()
	{
		std::vector<std::string> vecNetInterfaces;
		
#if (defined(_WIN32) || defined(_WIN64))
		ULONG ulLen = 0;
		PIP_ADAPTER_INFO lpAdapterInfo = NULL, lpNextData = NULL;

		GetAdaptersInfo(lpAdapterInfo, &ulLen);
		if (0 == ulLen)
		    return -1;

		lpAdapterInfo = (PIP_ADAPTER_INFO)(new CHAR[ulLen]);
		if (NULL == lpAdapterInfo)
		    return -1;

		memset(lpAdapterInfo, 0, ulLen);
		ULONG uRet = GetAdaptersInfo(lpAdapterInfo, &ulLen);
		if (uRet != ERROR_SUCCESS)
		{
		    delete [] lpAdapterInfo;
		    lpAdapterInfo = NULL;
		    
		    return vecNetInterfaces;
		}

		int m_lMaxAdaptersNum = 0;

		for (lpNextData = lpAdapterInfo; lpNextData != NULL; lpNextData = lpNextData->Next)
		{
		    //strncpy(m_host[m_lMaxAdaptersNum], lpNextData->IpAddressList.IpAddress.String, sizeof(m_host[m_lMaxAdaptersNum]));
		    IP_ADDR_STRING *pIpAddrString =&(lpNextData->IpAddressList);
		    int IPnumPerNetCard = 0;
		    do 
		    {
		        if (strcmp("0.0.0.0", pIpAddrString->IpAddress.String))
		        {
		            ++m_lMaxAdaptersNum; 
		            vecNetInterfaces.push_back(pIpAddrString->IpAddress.String);
		        }

		        //std::cout << lpNextData->AdapterName << ",?????IP??:"<< ++IPnumPerNetCard << std::endl;
		        //std::cout << "IP ??:"<< pIpAddrString->IpAddress.String << std::endl;
		        //std::cout << "????:"<< pIpAddrString->IpMask.String << std::endl;
		        //std::cout << "????:"<< lpNextData->GatewayList.IpAddress.String << std::endl;

		        pIpAddrString=pIpAddrString->Next;
		    } while (pIpAddrString);
		}

		delete [] lpAdapterInfo;
		lpAdapterInfo = NULL;

#else //#if (defined(WIN32) || defined(WIN64))

		struct ifaddrs *ifList  = NULL;

		int iRet = getifaddrs(&ifList);
		if (iRet < 0) 
		{
		    return vecNetInterfaces;
		}

		struct sockaddr_in *sin = NULL;
		struct ifaddrs *ifa     = NULL;

		for (ifa = ifList; ifa != NULL; ifa = ifa->ifa_next)
		{
		    if(ifa->ifa_addr->sa_family == AF_INET)
		    {
		        printf("\n>>> interfaceName: %s\n", ifa->ifa_name);
		        sin = (struct sockaddr_in *)ifa->ifa_addr;
		        printf(">>> ipAddress: %s\n", inet_ntoa(sin->sin_addr));

		        vecNetInterfaces.push_back(inet_ntoa(sin->sin_addr));
		        ++m_lMaxAdaptersNum ; 

		        //sin = (struct sockaddr_in *)ifa->ifa_dstaddr;
		        //printf(">>> broadcast: %s\n", inet_ntoa(sin->sin_addr));
		        //sin = (struct sockaddr_in *)ifa->ifa_netmask;
		        //printf(">>> subnetMask: %s\n", inet_ntoa(sin->sin_addr));
		    }
		}
		freeifaddrs(ifList);
#endif
		return vecNetInterfaces;
	}

public:
	bool Start()
	{
		if (m_bStarted == true)
		{
			return true;
		}
		/* Start Search thread */
		m_pThread = new std::thread(OnvifDisClient::DisThread, this);

		m_bStarted = true;
		return true;	
	}
	bool Stop()
	{
		if (m_bStarted == true)
		{
			m_bExit = true;
			if (m_pThread)
			{
				m_pThread->join();
				delete m_pThread;
				m_pThread = NULL;
			}
		}
		return true;
	}

	bool SendProbe(int nFd)
	{
		char *cxml = {"<?xml version=\"1.0\" encoding=\"UTF-8\"?><SOAP-ENV:Envelope x"
		    "mlns:SOAP-ENV=\"http://www.w3.org/2003/05/soap-envelope\" x"
		    "mlns:SOAP-ENC=\"http://www.w3.org/2003/05/soap-encoding\" x"
		    "mlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" x"
		    "mlns:xsd=\"http://www.w3.org/2001/XMLSchema\" x"
		    "mlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" x"
		    "mlns:wsdd=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" x"
		    "mlns:chan=\"http://schemas.microsoft.com/ws/2005/02/duplex\" x"
		    "mlns:wsa5=\"http://www.w3.org/2005/08/addressing\" x"
		    "mlns:c14n=\"http://www.w3.org/2001/10/xml-exc-c14n#\" x"
		    "mlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" x"
		    "mlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" x"
		    "mlns:wsc=\"http://schemas.xmlsoap.org/ws/2005/02/sc\" x"
		    "mlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" x"
		    "mlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" x"
		    "mlns:xmime=\"http://tempuri.org/xmime.xsd\" x"
		    "mlns:xop=\"http://www.w3.org/2004/08/xop/include\" x"
		    "mlns:tt=\"http://www.onvif.org/ver10/schema\" x"
		    "mlns:wsrfbf=\"http://docs.oasis-open.org/wsrf/bf-2\" x"
		    "mlns:wstop=\"http://docs.oasis-open.org/wsn/t-1\" x"
		    "mlns:wsrfr=\"http://docs.oasis-open.org/wsrf/r-2\" x"
		    "mlns:tad=\"http://www.onvif.org/ver10/analyticsdevice/wsdl\" x"
		    "mlns:tan=\"http://www.onvif.org/ver20/analytics/wsdl\" x"
		    "mlns:tdn=\"http://www.onvif.org/ver10/network/wsdl\" x"
		    "mlns:tds=\"http://www.onvif.org/ver10/device/wsdl\" x"
		    "mlns:tev=\"http://www.onvif.org/ver10/events/wsdl\" x"
		    "mlns:wsnt=\"http://docs.oasis-open.org/wsn/b-2\" x"
		    "mlns:timg=\"http://www.onvif.org/ver20/imaging/wsdl\" x"
		    "mlns:tls=\"http://www.onvif.org/ver10/display/wsdl\" x"
		    "mlns:tmd=\"http://www.onvif.org/ver10/deviceIO/wsdl\" x"
		    "mlns:tptz=\"http://www.onvif.org/ver20/ptz/wsdl\" x"
		    "mlns:trc=\"http://www.onvif.org/ver10/recording/wsdl\" x"
		    "mlns:trp=\"http://www.onvif.org/ver10/replay/wsdl\" x"
		    "mlns:trt=\"http://www.onvif.org/ver10/media/wsdl\" x"
		    "mlns:trv=\"http://www.onvif.org/ver10/receiver/wsdl\" x"
		    "mlns:tse=\"http://www.onvif.org/ver10/search/wsdl\">"
		    "<SOAP-ENV:Header><wsa:MessageID>urn:uuid:6fc2dc19-3785-445a-b1d1-82063b65ddd1</wsa:MessageID>"
		    "<wsa:To SOAP-ENV:mustUnderstand=\"true\">urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>"
		    "<wsa:Action SOAP-ENV:mustUnderstand=\"true\">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>"
		    "</SOAP-ENV:Header><SOAP-ENV:Body><wsdd:Probe><wsdd:Types></wsdd:Types><wsdd:Scopes></wsdd:Scopes>"
		    "</wsdd:Probe></SOAP-ENV:Body></SOAP-ENV:Envelope>" };

		struct sockaddr_in addr;

		memset(&addr, 0, sizeof(addr));

		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = inet_addr("239.255.255.250");
		addr.sin_port = htons(3702);

		int len = strlen(cxml);
		int nRet = sendto(nFd, cxml, len, 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
		if (nRet != len)
		{
			printf("SendProbe nRet = %d, len = %d\n", nRet, len);
			return false;
		}

		return true;
	}

	bool ProcessRecvMsg(std::string &strMsg)
	{
		return true;
	}
	
public:
	static void DisThread(void *user_data)
	{	
		OnvifDisClient* pThread = (OnvifDisClient*)user_data;

		if (pThread)
		{
			return pThread->WatchThread1();
		}
		return;
	}
	void DisThread1()

	{
		int fd = socket(AF_INET, SOCK_DGRAM, 0);
		if(fd < 0)
		{
			printf("socket SOCK_DGRAM error!\n");
			return ;
		}

		struct sockaddr_in addr;
		int on = 1;
		memset(&addr, 0, sizeof(addr));
		addr.sin_port = 0;
		addr.sin_family = AF_INET;

		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
		addr.sin_addr.s_addr = inet_addr(m_strAddr.c_str());
		if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)))
		{
			printf("bind error");
			return;
		}

		SendProbe(fd);

		/* loop to receive data udp data */
		while(!m_bExit)
		{
			char rbuf[65535];
			int ret;
			fd_set fdread;
			struct timeval tv = {0, 500};

			FD_ZERO(&fdread);
			FD_SET(fd, &fdread); 

			ret = select(fd+1, &fdread, NULL, NULL, &tv); 
			if (ret == 0) // Time expired 
			{ 
				continue; 
			}
			else if (!FD_ISSET(fd, &fdread))
			{
				continue;
			}

			struct sockaddr_in addr;
			int addr_len = sizeof(struct sockaddr_in);
			int rlen = recvfrom(fd, rbuf, sizeof(rbuf), 0, (struct sockaddr *)&addr, &addr_len);
			if (rlen <= 0)
			{
				printf("DisThread1 rlen = %d, fd = %d\r\n", rlen, fd);
				continue;
			}
			std::string strRecv(rbuf, rlen);
			ProcessRecvMsg(strRecv);
		}
		return;
	}	

private:
	CamSearchNotify &m_pNotify;
	std::thread *m_pThread;
	bool m_bStarted;
	bool m_bExit;
	std::string m_strAddr;
	
};


#endif /* __ONVIF_DIS_CLIENT__ */
