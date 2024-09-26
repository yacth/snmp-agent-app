/*_############################################################################
  _## 
  _##  AGENT++ 4.5 - snmp_proxy_mib.cpp  
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

#include <libagent.h>

#include <agent_pp/snmp_proxy_mib.h>
#include <agent_pp/snmp_community_mib.h>

#ifdef AGENTPP_NAMESPACE
namespace Agentpp {
#endif

/**
 *  snmpProxyEntry
 *
 */

snmpProxyEntry* snmpProxyEntry::instance = 0;

snmpProxyEntry::snmpProxyEntry():
   StorageTable(oidSnmpProxyEntry, iSnmpAdminString, 1)
{
	// This table object is a singleton. In order to access it use
	// the static pointer snmpProxyEntry::instance.
	instance = this;

	add_col(new SnmpInt32MinMax("2", READCREATE, 1,  
				    VMODE_DEFAULT | VMODE_LOCKED, 1, 4));
	add_col(new SnmpEngineID("3", READCREATE, new OctetStr(""), 
				 VMODE_DEFAULT | VMODE_LOCKED));
	add_col(new SnmpAdminString("4", READCREATE, new OctetStr(""), 
				    VMODE_DEFAULT | VMODE_LOCKED));
	add_col(new SnmpAdminString("5", READCREATE, new OctetStr(""), 
				    VMODE_DEFAULT | VMODE_LOCKED));
	add_col(new SnmpAdminString("6", READCREATE, new OctetStr(""), 
				    VMODE_DEFAULT | VMODE_LOCKED));
	add_col(new SnmpTagValue("7", READCREATE, new OctetStr(""), 
				    VMODE_DEFAULT | VMODE_LOCKED));
	add_storage_col(new StorageType("8", 3));
	add_col(new snmpRowStatus("9", READCREATE));
}

snmpProxyEntry::~snmpProxyEntry()
{
	instance = 0;
}

void snmpProxyEntry::set_row(MibTableRow* r, int p0, char* p1, char* p2, 
			     char* p3, char* p4, char* p5, int p6, int p7)
{
	r->get_nth(0)->replace_value(new SnmpInt32(p0));
	r->get_nth(1)->replace_value(new OctetStr(p1));
	r->get_nth(2)->replace_value(new OctetStr(p2));
	r->get_nth(3)->replace_value(new OctetStr(p3));
	r->get_nth(4)->replace_value(new OctetStr(p4));
	r->get_nth(5)->replace_value(new OctetStr(p5));
	r->get_nth(6)->replace_value(new SnmpInt32(p6));
	r->get_nth(7)->replace_value(new SnmpInt32(p7));
}

void snmpProxyEntry::set_row(MibTableRow* r, int proxyType, 
                             const OctetStr& engineID, 
                             const OctetStr& contextName,
                             const OctetStr& targetParamsIn,
			     const OctetStr& singleTargetOut, 
                             const OctetStr& multipleTargetOut, 
                             int storageType, int rowStatus)
{
	r->get_nth(0)->replace_value(new SnmpInt32(proxyType));
	r->get_nth(1)->replace_value(new OctetStr(engineID));
	r->get_nth(2)->replace_value(new OctetStr(contextName));
	r->get_nth(3)->replace_value(new OctetStr(targetParamsIn));
	r->get_nth(4)->replace_value(new OctetStr(singleTargetOut));
	r->get_nth(5)->replace_value(new OctetStr(multipleTargetOut));
	r->get_nth(6)->replace_value(new SnmpInt32(storageType));
	r->get_nth(7)->replace_value(new SnmpInt32(rowStatus));
}



snmp_proxy_mib::snmp_proxy_mib(): MibGroup("1.3.6.1.6.3.14.1", "snmpProxyMIB")
{
	add(new snmpProxyEntry());
}

#ifdef AGENTPP_NAMESPACE
}
#endif
