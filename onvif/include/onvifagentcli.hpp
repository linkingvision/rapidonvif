
#ifndef __ONVIF_AGENT_CLIENT__
#define __ONVIF_AGENT_CLIENT__

#include <string.h>
#include <vector>
#include <iostream>
#include <thread>
#include <mutex>
#include <chrono>
#include <map>
#include "wsclient.hpp"
#include "onvifcli.pb.h"
#include "onvifclidevice.pb.h"
#include <google/protobuf/util/json_util.h>

class  OnvifAgentC : public WebSocketClient
{
public:
	OnvifAgentC(std::string strUser, std::string strPasswd, std::string strUrl)
	:WebSocketClient("localhost", "10000", "/onvifagentcli"), m_bLogin(false), 
	m_strUser(strUser), m_strPasswd(strPasswd), m_strUrl(strUrl)
	{
		/* Connect to the remote server */
		Connect();
	}
	~OnvifAgentC()
	{}

public:
	virtual bool ProcessRecvMsg(char *data, size_t data_len)
	{
		/* lock guard */
		std::lock_guard<std::mutex> guard(m_lock);
		std::string strMsg(data, data_len);
		::google::protobuf::util::Status status = 
			::google::protobuf::util::JsonStringToMessage(strMsg, &m_lastCmd);
		if (!status.ok())
		{
			return false;
		}
		
		m_msgId ++;
		return true;
	}
public:
	bool Login()
	{
		if (Connected() == false)
		{
			if (Connect() == false)
			{
				return false;
			}
		}

		OnvifCli::OnvifCliCmd cmd;
		cmd.set_type(OnvifCli::CLI_CMD_DEV_LOGIN_REQ);
		OnvifCliDeviceLoginReq * req = new OnvifCliDeviceLoginReq;
		req->set_strusername(m_strUser);
		req->set_strpasswd(m_strPasswd);
		req->set_strurl(m_strUrl);
		cmd.set_allocated_loginreq(req);
		std::string strMsg;
		::google::protobuf::util::Status status = 
			::google::protobuf::util::MessageToJsonString(cmd, &strMsg);
		if (!status.ok())
		{
			return false;
		}
		long long lastMsgId = 0;
		/* only lock here */
		{
			std::lock_guard<std::mutex> guard(m_lock);
			lastMsgId = m_msgId;
		}
		
		if (SendMsg(strMsg) == false)
		{
			return false;
		}

		OnvifCli::OnvifCliCmd respCmd;

		if (GetRespMsg(lastMsgId, respCmd) == false)
		{
			return false;
		}

		if (!respCmd.has_loginresp())
		{
			return false;
		}
		const OnvifCliDeviceLoginResp& pResp =  respCmd.loginresp();
		
		printf("%s %d websocket login handle %s id %lld login %d\n", __FILE__, __LINE__, 
					pResp.strhandle().c_str(), lastMsgId, pResp.blogined());
		
		m_bLogin = true;
		return true;
		
	}
	bool GetRespMsg(long long lastId, OnvifCli::OnvifCliCmd & respCmd)
	{
		int i = 20;
		while(i --)
		{
			std::chrono::milliseconds dura(100);
			std::this_thread::sleep_for(dura);

			/* lock the guard */
			std::lock_guard<std::mutex> guard(m_lock);
			if (m_msgId > lastId)
			{
				respCmd = m_lastCmd;
				return true;
			}
			
		}
		return false;
	}
	
	bool CheckOnline()
	{
	}
		
	bool GetProfiles()
	{
	
	}

private:
	bool m_bLogin;
	std::string m_strUser;
	std::string m_strPasswd;
	std::string m_strUrl;
	OnvifCli::OnvifCliCmd m_lastCmd;
};


#endif /* __ONVIF_AGENT_CLIENT__ */
