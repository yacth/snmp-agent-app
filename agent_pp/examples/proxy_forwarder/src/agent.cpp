/*_############################################################################
  _## 
  _##  AGENT++ 4.5 - agent.cpp  
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

#include <stdlib.h>
#include <signal.h>

#include <agent_pp/agent++.h>

#ifndef _SNMPv3
#error "_SNMPv3 must be defined in order to use the ProxyForwarder"
#endif
#ifndef _PROXY_FORWARDER
#error "_PROXY_FORWARDER must be defined in order to use the ProxyForwarder"
#endif

#include <agent_pp/snmp_group.h>
#include <agent_pp/system_group.h>
#include <agent_pp/snmp_target_mib.h>
#include <agent_pp/snmp_notification_mib.h>
#include <agent_pp/snmp_community_mib.h>
#include <agent_pp/notification_originator.h>
#include <agent_pp/snmp_proxy_mib.h>
#include <agent_pp/vacm.h>
#include <agent_pp/v3_mib.h>

#include <snmp_pp/oid_def.h>
#include <snmp_pp/octet.h>
#include <snmp_pp/mp_v3.h>
#include <snmp_pp/log.h>


#ifdef SNMP_PP_NAMESPACE
using namespace Snmp_pp;
#endif

#ifdef AGENTPP_NAMESPACE
using namespace Agentpp;
#endif

// globals:

static const char* loggerModuleName = "agent++.proxy_forwarder";

unsigned short port;
Mib* mib;
RequestList* reqList;
bool run = TRUE;

static void sig(int signo) {
    if ((signo == SIGTERM) || (signo == SIGINT) ||
            (signo == SIGSEGV)) {

        printf("\n");

        switch (signo) {
            case SIGSEGV:
            {
                printf("Segmentation fault, aborting.\n");
                exit(1);
            }
            case SIGTERM:
            case SIGINT:
            {
                if (run) {
                    run = FALSE;
                    printf("User abort\n");
                }
            }
        }
    }
}

void init_signals() {
    signal(SIGTERM, sig);
    signal(SIGINT, sig);
    signal(SIGSEGV, sig);
}

/**
 * This sample configuration creates a proxy forwarding for GET requests
 * to the same host (using 127.0.0.1) on port 4701.
 * @param proxy_eid
 *    the engine ID of the proxy engine.
 * @return 
 *    the created and configured proxy MIB instance.
 */
snmp_proxy_mib* initProxy(const OctetStr& proxy_eid) {
    snmp_proxy_mib* proxy_mib = new snmp_proxy_mib();
    snmpProxyEntry* proxy_table = proxy_mib->get_proxy_table();
    MibTableRow* proxy_row = proxy_table->add_row(Oidx::from_string("proxy4701", false));
    proxy_table->set_row(proxy_row,
            1,
            proxy_eid,
            "",
            "proxyIn",
            "proxyOut4701",
            "",
            3,
            1);
    return proxy_mib;
}

/**
 * This sample target configuration creates a proxy address (127.0.0.1:4700)
 * and target parameters for matching the incoming SNMPv2c proxy requests 
 * (with community "proxy1") and forwarding them using SNMPv2c but with 
 * another community ("public").
 * @return 
 *    the created and pre-configured target MIB 
 */
snmp_target_mib* initTargets() {
    snmp_target_mib* target_mib = new snmp_target_mib();
    snmpTargetAddrEntry* target_addr_table = target_mib->get_target_addr_table();
    target_addr_table->add_entry("proxyOut4701",
            Oidx(oidSnmpUdpDomain),
            OctetStr::from_hex_string("7F 00 00 01 12 5D"),
            "",
            "proxyAccess");
    snmpTargetParamsEntry* target_params_table = target_mib->get_target_params_table();
    target_params_table->add_entry("proxyAccess", 1, 2, "public", 1);
    target_params_table->add_entry("proxyIn", 1, 2, "pubProxy1", 1);
    return target_mib;
}

/**
 * This sample configuration for the SNMP-COMMUNITY-MIB adds a community 
 * mapping for a proxy forwarding configuration (community "proxy1").
 * @param mib
 *    the Mib instance from which to lookup the existing snmp_community_mib
 *    instance.
 * @param proxy_eid
 *    the engine ID of the proxy engine to be configured.
 */
void initCommunities(Mib* mib, const OctetStr& proxy_eid) {
    if (!mib->get_request_list()->get_v3mp()) {
        LOG_BEGIN(loggerModuleName, ERROR_LOG | 0);
        LOG("v3MP must be initialized before snmpCommunityTable");
        LOG_END;
        return;
    }

    snmpCommunityEntry* snmpCommunityEntry =
            snmpCommunityEntry::get_instance(mib);
    if (!snmpCommunityEntry) {
        LOG_BEGIN(loggerModuleName, ERROR_LOG | 0);
        LOG("snmpCommunityEntry must be initialized before initCommunities is called");
        LOG_END;
        return;
    }
    Oidx ind = Oidx::from_string("proxy1", FALSE);
    MibTableRow* r = snmpCommunityEntry->find_index(ind);
    if (!r) r = snmpCommunityEntry->add_row(ind);
    snmpCommunityEntry->set_row(r,
            OctetStr("proxy1"),
            OctetStr("pubProxy1"),
            proxy_eid,
            OctetStr(""),
            OctetStr("access"),
            3, 1);
}

void init(Mib& mib, const NS_SNMP OctetStr& engineID) {
    OctetStr proxy_eid(SnmpEngineID::create_engine_id(4701));
    OctetStr descr;
    descr += "AGENT++v";
    descr += AGENTPP_VERSION_STRING;
    descr += " Proxy Forwarder - Use 'MD5' as SNMPv3 user and 'MD5UserAuthPassword' as authentication";
    mib.add(new sysGroup(descr.get_printable(),
            "1.3.6.1.4.1.4976", 10));
    mib.add(new snmpGroup());
    mib.add(new TestAndIncr(oidSnmpSetSerialNo));
    mib.add(initTargets());
    mib.add(initProxy(proxy_eid));
    mib.add(new snmp_community_mib());
    initCommunities(&mib, proxy_eid);
    mib.add(new snmp_notification_mib());

    UsmUserTable *uut = new UsmUserTable();

    uut->addNewRow("unsecureUser",
            SNMP_AUTHPROTOCOL_NONE,
            SNMP_PRIVPROTOCOL_NONE, "", "", engineID, false);

    uut->addNewRow("MD5",
            SNMP_AUTHPROTOCOL_HMACMD5,
            SNMP_PRIVPROTOCOL_NONE,
            "MD5UserAuthPassword", "", engineID, false);

    uut->addNewRow("SHA",
            SNMP_AUTHPROTOCOL_HMACSHA,
            SNMP_PRIVPROTOCOL_NONE,
            "SHAUserAuthPassword", "", engineID, false);

    uut->addNewRow("MD5DES",
            SNMP_AUTHPROTOCOL_HMACMD5,
            SNMP_PRIVPROTOCOL_DES,
            "MD5DESUserAuthPassword",
            "MD5DESUserPrivPassword", engineID, false);

    uut->addNewRow("SHADES",
            SNMP_AUTHPROTOCOL_HMACSHA,
            SNMP_PRIVPROTOCOL_DES,
            "SHADESUserAuthPassword",
            "SHADESUserPrivPassword", engineID, false);

    uut->addNewRow("MD5IDEA",
            SNMP_AUTHPROTOCOL_HMACMD5,
            SNMP_PRIVPROTOCOL_IDEA,
            "MD5IDEAUserAuthPassword",
            "MD5IDEAUserPrivPassword", engineID, false);

    uut->addNewRow("SHAIDEA",
            SNMP_AUTHPROTOCOL_HMACSHA,
            SNMP_PRIVPROTOCOL_IDEA,
            "SHAIDEAUserAuthPassword",
            "SHAIDEAUserPrivPassword", engineID, false);

    uut->addNewRow("MD5AES128",
            SNMP_AUTHPROTOCOL_HMACMD5,
            SNMP_PRIVPROTOCOL_AES128,
            "MD5AES128UserAuthPassword",
            "MD5AES128UserPrivPassword", engineID, false);

    uut->addNewRow("SHAAES128",
            SNMP_AUTHPROTOCOL_HMACSHA,
            SNMP_PRIVPROTOCOL_AES128,
            "SHAAES128UserAuthPassword",
            "SHAAES128UserPrivPassword", engineID, false);

    uut->addNewRow("MD5AES192",
            SNMP_AUTHPROTOCOL_HMACMD5,
            SNMP_PRIVPROTOCOL_AES192,
            "MD5AES192UserAuthPassword",
            "MD5AES192UserPrivPassword", engineID, false);

    uut->addNewRow("SHAAES192",
            SNMP_AUTHPROTOCOL_HMACSHA,
            SNMP_PRIVPROTOCOL_AES192,
            "SHAAES192UserAuthPassword",
            "SHAAES192UserPrivPassword", engineID, false);

    uut->addNewRow("MD5AES256",
            SNMP_AUTHPROTOCOL_HMACMD5,
            SNMP_PRIVPROTOCOL_AES256,
            "MD5AES256UserAuthPassword",
            "MD5AES256UserPrivPassword", engineID, false);

    uut->addNewRow("SHAAES256",
            SNMP_AUTHPROTOCOL_HMACSHA,
            SNMP_PRIVPROTOCOL_AES256,
            "SHAAES256UserAuthPassword",
            "SHAAES256UserPrivPassword", engineID, false);

    // add non persistent USM statistics
    mib.add(new UsmStats());
    // add the USM MIB - usm_mib MibGroup is used to
    // make user added entries persistent
    mib.add(new usm_mib(uut));
    // add non persistent SNMPv3 engine object
    mib.add(new V3SnmpEngine());
    mib.add(new MPDGroup());
}

int main(int argc, char* argv[]) {
    if (argc > 1)
        port = atoi(argv[1]);
    else
        port = 4700;

#ifndef _NO_LOGGING
    DefaultLog::log()->set_filter(ERROR_LOG, 5);
    DefaultLog::log()->set_filter(WARNING_LOG, 5);
    DefaultLog::log()->set_filter(EVENT_LOG, 5);
    DefaultLog::log()->set_filter(INFO_LOG, 5);
    DefaultLog::log()->set_filter(DEBUG_LOG, 8);
#endif
    int status;
    Snmp::socket_startup(); // Initialize socket subsystem
    Snmpx snmp(status, port);

    if (status == SNMP_CLASS_SUCCESS) {

        LOG_BEGIN(loggerModuleName, EVENT_LOG | 1);
        LOG("main: SNMP listen port");
        LOG(port);
        LOG_END;
    } else {
        LOG_BEGIN(loggerModuleName, ERROR_LOG | 0);
        LOG("main: SNMP port init failed");
        LOG(status);
        LOG_END;
        exit(1);
    }

    mib = new Mib();
    reqList = new RequestList(mib);

#ifdef _SNMPv3
    unsigned int snmpEngineBoots = 0;
    OctetStr engineId(SnmpEngineID::create_engine_id(port));

    // you may use your own methods to load/store this counter
    status = mib->get_boot_counter(engineId, snmpEngineBoots);
    if ((status != SNMPv3_OK) && (status < SNMPv3_FILEOPEN_ERROR)) {
        LOG_BEGIN(loggerModuleName, ERROR_LOG | 0);
        LOG("main: Error loading snmpEngineBoots counter (status)");
        LOG(status);
        LOG_END;
        exit(1);
    }

    snmpEngineBoots++;
    status = mib->set_boot_counter(engineId, snmpEngineBoots);
    if (status != SNMPv3_OK) {
        LOG_BEGIN(loggerModuleName, ERROR_LOG | 0);
        LOG("main: Error saving snmpEngineBoots counter (status)");
        LOG(status);
        LOG_END;
        exit(1);
    }

    int stat;
    v3MP *v3mp = new v3MP(engineId, snmpEngineBoots, stat);

    // register v3MP
    reqList->set_v3mp(v3mp);
    snmp.set_mpv3(v3mp);
#else
        OctetStr engineId; // not used without SNMPv3
#endif
    reqList->set_snmp(&snmp);

    // register requestList for outgoing requests
    mib->set_request_list(reqList);

    init_signals();

    // add supported objects
    init(*mib, engineId);
    snmp_community_mib::add_public();

    ProxyForwarder* proxy = new ProxyForwarder(mib, "", ProxyForwarder::ALL);
    mib->register_proxy(proxy);

#ifdef _SNMPv3
    // register VACM
    Vacm* vacm = new Vacm(*mib);
    reqList->set_vacm(vacm);

    // initialize security information
    vacm->addNewContext("");
    vacm->addNewContext("other");

    // Add new entries to the SecurityToGroupTable.
    // Used to determine the group a given SecurityName belongs to. 
    // User "new" of the USM belongs to newGroup

    vacm->addNewGroup(SNMP_SECURITY_MODEL_USM, "new",
            "newGroup", storageType_nonVolatile);

    vacm->addNewGroup(SNMP_SECURITY_MODEL_USM, "test",
            "testGroup", storageType_nonVolatile);
    vacm->addNewGroup(SNMP_SECURITY_MODEL_V2, "public",
            "v1v2group", storageType_nonVolatile);
    vacm->addNewGroup(SNMP_SECURITY_MODEL_V1, "public",
            "v1v2group", storageType_nonVolatile);
    vacm->addNewGroup(SNMP_SECURITY_MODEL_USM, "initial",
            "initial", storageType_nonVolatile);
    vacm->addNewGroup(SNMP_SECURITY_MODEL_USM, "unsecureUser",
            "newGroup", storageType_nonVolatile);
    vacm->addNewGroup(SNMP_SECURITY_MODEL_USM, "MD5",
            "testNoPrivGroup", storageType_nonVolatile);
    vacm->addNewGroup(SNMP_SECURITY_MODEL_USM, "SHA",
            "testNoPrivGroup", storageType_nonVolatile);
    vacm->addNewGroup(SNMP_SECURITY_MODEL_USM, "MD5DES",
            "testGroup", storageType_nonVolatile);
    vacm->addNewGroup(SNMP_SECURITY_MODEL_USM, "SHADES",
            "testGroup", storageType_nonVolatile);
    vacm->addNewGroup(SNMP_SECURITY_MODEL_USM, "MD5IDEA",
            "testGroup", storageType_nonVolatile);
    vacm->addNewGroup(SNMP_SECURITY_MODEL_USM, "SHAIDEA",
            "testGroup", storageType_nonVolatile);
    vacm->addNewGroup(SNMP_SECURITY_MODEL_USM, "MD5AES128",
            "testGroup", storageType_nonVolatile);
    vacm->addNewGroup(SNMP_SECURITY_MODEL_USM, "SHAAES128",
            "testGroup", storageType_nonVolatile);
    vacm->addNewGroup(SNMP_SECURITY_MODEL_USM, "MD5AES192",
            "testGroup", storageType_nonVolatile);
    vacm->addNewGroup(SNMP_SECURITY_MODEL_USM, "SHAAES192",
            "testGroup", storageType_nonVolatile);
    vacm->addNewGroup(SNMP_SECURITY_MODEL_USM, "MD5AES256",
            "testGroup", storageType_nonVolatile);
    vacm->addNewGroup(SNMP_SECURITY_MODEL_USM, "SHAAES256",
            "testGroup", storageType_nonVolatile);

    // remove a group with:
    //vacm->deleteGroup(SNMP_SECURITY_MODEL_USM, "neu");

    // Set access rights of groups.
    // The group "newGroup" (when using the USM with a security
    // level >= noAuthNoPriv within context "") would have full access  
    // (read, write, notify) to all objects in view "newView". 
    vacm->addNewAccessEntry("newGroup",
            "other", // context
            SNMP_SECURITY_MODEL_USM,
            SNMP_SECURITY_LEVEL_NOAUTH_NOPRIV,
            match_exact, // context must mach exactly
            // alternatively: match_prefix  
            "newView", // readView
            "newView", // writeView
            "newView", // notifyView
            storageType_nonVolatile);
    vacm->addNewAccessEntry("testGroup", "",
            SNMP_SECURITY_MODEL_USM,
            SNMP_SECURITY_LEVEL_AUTH_PRIV,
            match_prefix,
            "testView", "testView",
            "testView", storageType_nonVolatile);
    vacm->addNewAccessEntry("testNoPrivGroup", "",
            SNMP_SECURITY_MODEL_USM, SecurityLevel_authNoPriv,
            match_prefix,
            "testView", "testView",
            "testView", storageType_nonVolatile);
    vacm->addNewAccessEntry("testNoPrivGroup", "",
            SNMP_SECURITY_MODEL_USM,
            SNMP_SECURITY_LEVEL_AUTH_NOPRIV,
            match_prefix,
            "testView", "testView",
            "testView", storageType_nonVolatile);
    vacm->addNewAccessEntry("testGroup", "",
            SNMP_SECURITY_MODEL_USM,
            SNMP_SECURITY_LEVEL_NOAUTH_NOPRIV,
            match_prefix,
            "testView", "testView",
            "testView", storageType_nonVolatile);
    vacm->addNewAccessEntry("v1v2group", "",
            SNMP_SECURITY_MODEL_V2,
            SNMP_SECURITY_LEVEL_NOAUTH_NOPRIV,
            match_exact,
            "v1ReadView", "v1WriteView",
            "v1NotifyView", storageType_nonVolatile);
    vacm->addNewAccessEntry("v1v2group", "",
            SNMP_SECURITY_MODEL_V1,
            SNMP_SECURITY_LEVEL_NOAUTH_NOPRIV,
            match_exact,
            "v1ReadView", "v1WriteView",
            "v1NotifyView", storageType_nonVolatile);
    vacm->addNewAccessEntry("initial", "",
            SNMP_SECURITY_MODEL_USM,
            SNMP_SECURITY_LEVEL_NOAUTH_NOPRIV,
            match_exact,
            "restricted", "",
            "restricted", storageType_nonVolatile);
    vacm->addNewAccessEntry("initial", "",
            SNMP_SECURITY_MODEL_USM,
            SNMP_SECURITY_LEVEL_AUTH_NOPRIV,
            match_exact,
            "internet", "internet",
            "internet", storageType_nonVolatile);
    vacm->addNewAccessEntry("initial", "",
            SNMP_SECURITY_MODEL_USM,
            SNMP_SECURITY_LEVEL_AUTH_PRIV,
            match_exact,
            "internet", "internet",
            "internet", storageType_nonVolatile);

    // remove an AccessEntry with:
    // vacm->deleteAccessEntry("newGroup", 
    //	      		"",        
    //			SNMP_SECURITY_MODEL_USM, 
    //			SNMP_SECURITY_LEVEL_NOAUTH_NOPRIV);


    // Defining Views
    // View "v1ReadView" includes all objects starting with "1.3".
    // If the ith bit of the mask is not set (0), then also all objects
    // which have a different subid at position i are included in the 
    // view.
    // For example: Oid "6.5.4.3.2.1", Mask(binary) 110111 
    //              Then all objects with Oid with "6.5.<?>.3.2.1" 
    //              are included in the view, whereas <?> may be any
    //              natural number.

    vacm->addNewView("v1ReadView",
            "1.3",
            "", // Mask "" is same as 0xFFFFFFFFFF...
            view_included, // alternatively: view_excluded
            storageType_nonVolatile);

    vacm->addNewView("v1WriteView",
            "1.3",
            "", // Mask "" is same as 0xFFFFFFFFFF...
            view_included, // alternatively: view_excluded
            storageType_nonVolatile);

    vacm->addNewView("v1NotifyView",
            "1.3",
            "", // Mask "" is same as 0xFFFFFFFFFF...
            view_included, // alternatively: view_excluded
            storageType_nonVolatile);

    vacm->addNewView("newView", "1.3", "",
            view_included, storageType_nonVolatile);
    vacm->addNewView("testView", "1.3.6", "",
            view_included, storageType_nonVolatile);
    vacm->addNewView("internet", "1.3.6.1", "",
            view_included, storageType_nonVolatile);

    vacm->addNewView("restricted", "1.3.6.1.2.1.1", "",
            view_included, storageType_nonVolatile);
    vacm->addNewView("restricted", "1.3.6.1.2.1.11", "",
            view_included, storageType_nonVolatile);
    vacm->addNewView("restricted", "1.3.6.1.6.3.10.2.1", "",
            view_included, storageType_nonVolatile);
    vacm->addNewView("restricted", "1.3.6.1.6.3.11.2.1", "",
            view_included, storageType_nonVolatile);
    vacm->addNewView("restricted", "1.3.6.1.6.3.15.1.1", "",
            view_included, storageType_nonVolatile);

#endif  
    // load persistent objects from disk
    mib->init();

    Vbx* vbs = 0;
    coldStartOid coldOid;
    NotificationOriginator no;
    UdpAddress dest("127.0.0.1/162");
    no.add_v1_trap_destination(dest, "defaultV1Trap", "v1trap", "public");
    no.generate(vbs, 0, coldOid, "", "");

    Request* req;
    while (run) {

        req = reqList->receive(2);

        if (req) {
            mib->process_request(req);
        } else {
            mib->cleanup();
        }
    }
    delete reqList;
    delete mib;
#ifdef _SNMPv3
    delete vacm;
    delete v3mp;
#endif 
    Snmp::socket_cleanup(); // Shut down socket subsystem
    return 0;
}
