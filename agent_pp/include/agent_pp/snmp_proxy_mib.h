/*_############################################################################
  _## 
  _##  AGENT++ 4.5 - snmp_proxy_mib.h  
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


#ifndef _snmp_proxy_mib_h
#define _snmp_proxy_mib_h


#include <agent_pp/mib.h>
#include <agent_pp/snmp_textual_conventions.h>


#define oidSnmpProxyTable                "1.3.6.1.6.3.14.1.2"
#define oidSnmpProxyEntry                "1.3.6.1.6.3.14.1.2.1"
#define oidSnmpProxyName                 "1.3.6.1.6.3.14.1.2.1.1"
#define oidSnmpProxyType                 "1.3.6.1.6.3.14.1.2.1.2"
#define oidSnmpProxyContextEngineID      "1.3.6.1.6.3.14.1.2.1.3"
#define oidSnmpProxyContextName          "1.3.6.1.6.3.14.1.2.1.4"
#define oidSnmpProxyTargetParamsIn       "1.3.6.1.6.3.14.1.2.1.5"
#define oidSnmpProxySingleTargetOut      "1.3.6.1.6.3.14.1.2.1.6"
#define oidSnmpProxyMultipleTargetOut    "1.3.6.1.6.3.14.1.2.1.7"
#define oidSnmpProxyStorageType          "1.3.6.1.6.3.14.1.2.1.8"
#define oidSnmpProxyRowStatus            "1.3.6.1.6.3.14.1.2.1.9"

#ifdef AGENTPP_NAMESPACE
namespace Agentpp {
    using namespace Snmp_pp;
#endif


/**
 *  snmpProxyType
 *
"The type of message that may be forwarded using
 the translation parameters defined by this entry."
 */



/**
 *  snmpProxyContextEngineID
 *
"The contextEngineID contained in messages that
 may be forwarded using the translation parameters
 defined by this entry."
 */


/**
 *  snmpProxyContextName
 *
"The contextName contained in messages that may be
 forwarded using the translation parameters defined
 by this entry.

 This object is optional, and if not supported, the
 contextName contained in a message is ignored when
 selecting an entry in the snmpProxyTable."
 */


/**
 *  snmpProxyTargetParamsIn
 *
"This object selects an entry in the snmpTargetParamsTable.
 The selected entry is used to determine which row of the
 snmpProxyTable to use for forwarding received messages."
 */



/**
 *  snmpProxySingleTargetOut
 *
"This object selects a management target defined in the
 snmpTargetAddrTable (in the SNMP-TARGET-MIB). The
 selected target is defined by an entry in the
 snmpTargetAddrTable whose index value (snmpTargetAddrName)
 is equal to this object.

 This object is only used when selection of a single
 target is required (i.e. when forwarding an incoming
 read or write request)."
 */


/**
 *  snmpProxyMultipleTargetOut
 *
"This object selects a set of management targets defined
 in the snmpTargetAddrTable (in the SNMP-TARGET-MIB).

 This object is only used when selection of multiple
 targets is required (i.e. when forwarding an incoming
 notification)."
 */


/**
 *  snmpProxyRowStatus
 *
"The status of this conceptual row.

 To create a row in this table, a manager must
 set this object to either createAndGo(4) or
 createAndWait(5).

 The following objects may not be modified while the
 value of this object is active(1):
 - snmpProxyType
 - snmpProxyContextEngineID
 - snmpProxyContextName
 - snmpProxyTargetParamsIn
 - snmpProxySingleTargetOut
 - snmpProxyMultipleTargetOut"
 */



/**
 *  snmpProxyEntry
 *
"A set of translation parameters used by a proxy forwarder
 application for forwarding SNMP messages.

 Entries in the snmpProxyTable are created and deleted
 using the snmpProxyRowStatus object."
 */


class AGENTPP_DECL snmpProxyEntry: public StorageTable {

 public:
	snmpProxyEntry();
	virtual ~snmpProxyEntry();

	static snmpProxyEntry* instance;
	virtual void       	set_row(MibTableRow* r, 
                                        int proxyType, 
                                        char* contextEngineID, 
					char* contextName, 
                                        char* targetParamsIn, 
                                        char* singleTargetParamsOut, 
					char* multipleTargetParamsOut, 
                                        int storageType, 
                                        int rowStatus);
	virtual void       	set_row(MibTableRow* r, 
                                        int proxyType, 
                                        const OctetStr& contextEngineID, 
					const OctetStr& contextName, 
                                        const OctetStr& targetParamsIn, 
                                        const OctetStr& singleTargetParamsOut, 
					const OctetStr& multipleTargetParamsOut, 
                                        int storageType, 
                                        int rowStatus);
};


class AGENTPP_DECL snmp_proxy_mib: public MibGroup
{
  public:
	snmp_proxy_mib();
	virtual ~snmp_proxy_mib() { }
        
        virtual snmpProxyEntry* get_proxy_table() 
                             { return (snmpProxyEntry*)get_content().get(); }
};

#ifdef AGENTPP_NAMESPACE
}
#endif

/**
 * snmp_proxy_mib.h generated by AgentGen 1.1.3 for AGENT++v3 
 * Sun Nov 14 22:03:51 GMT+03:30 1999.
 */


#endif


