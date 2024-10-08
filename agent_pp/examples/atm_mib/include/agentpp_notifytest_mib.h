/*_############################################################################
  _## 
  _##  AGENT++ 4.5 - agentpp_notifytest_mib.h  
  _## 
  _##  Copyright (C) 2000-2021  Frank Fock and Jochen Katz (agentpp.com)
  _##  
  _##  Licensed under the Apache License, Version 2.0 (the "License");
  _##  you may not use this file except in compliance with the License.
  _##  You may obtain a copy of the License at
  _##  
  _##      http://www.apache.org/licenses/LICENSE-2.0
  _##  
  _##  Unless required by applicable law or agreed to in writing, software
  _##  distributed under the License is distributed on an "AS IS" BASIS,
  _##  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  _##  See the License for the specific language governing permissions and
  _##  limitations under the License.
  _##  
  _##########################################################################*/



//--AgentGen BEGIN=_BEGIN
//--AgentGen END


#ifndef _agentpp_notifytest_mib_h
#define _agentpp_notifytest_mib_h


#include <agent_pp/mib.h>

#include <agent_pp/snmp_textual_conventions.h>
#include <agent_pp/notification_originator.h>
#include <snmp_pp/log.h>


#define oidAgentppNotifyTest             "1.3.6.1.4.1.4976.6.2.1.1.0"
#define oidAgentppNotifyTestAllTypes     "1.3.6.1.4.1.4976.6.2.2.0.1"



//--AgentGen BEGIN=_INCLUDE
#ifdef AGENTPP_NAMESPACE
namespace Agentpp {
#endif
//--AgentGen END


/**
 *  agentppNotifyTest
 *
 * "By setting this object to one of its enumerated
 * values generates a corresponding notification.
 * When reading this object it will return the value
 * corresponding to the last notification type sent."
 */


class agentppNotifyTest: public MibLeaf {

public:
	agentppNotifyTest();
	virtual ~agentppNotifyTest();

	static agentppNotifyTest* instance;

	virtual long       	get_state();
	virtual void       	set_state(long);
	virtual int        	set(const Vbx&);
	virtual int        	prepare_set_request(Request*, int&);
	virtual bool    	value_ok(const Vbx&);
	enum labels {
		e_agentppNotifyTestAllTypes = 1 };

//--AgentGen BEGIN=agentppNotifyTest
	void send_agentppNotifyTestAllTypes();
//--AgentGen END
};


/**
 *  agentppNotifyTestAllTypes
 *
 * "A notification with objects of all possible SNMPv2/v3 types."
 */


class agentppNotifyTestAllTypes: public NotificationOriginator {

public:
	agentppNotifyTestAllTypes();
	virtual ~agentppNotifyTestAllTypes();

	virtual void        	generate(Vbx*, int, const NS_SNMP OctetStr&);

//--AgentGen BEGIN=agentppNotifyTestAllTypes
//--AgentGen END
};


class agentpp_notifytest_mib: public MibGroup
{
  public:
	agentpp_notifytest_mib();
	virtual ~agentpp_notifytest_mib() { }

//--AgentGen BEGIN=agentpp_notifytest_mib
//--AgentGen END

};

//--AgentGen BEGIN=_END
#ifdef AGENTPP_NAMESPACE
}
#endif

//--AgentGen END


/**
 * agentpp_notifytest_mib.h generated by AgentGen 1.6.1 for AGENT++v3.4 
 * Fri Jul 06 11:45:57 GMT+02:00 2001.
 */


#endif


