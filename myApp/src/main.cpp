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
#include <sstream>
#include <iomanip>

#include <agent_pp/agent++.h>
#include <agent_pp/snmp_group.h>
#include <agent_pp/system_group.h>
#include <agent_pp/snmp_target_mib.h>
#include <agent_pp/snmp_notification_mib.h>
#include <agent_pp/notification_originator.h>
#include <agent_pp/mib_complex_entry.h>
#include <agent_pp/v3_mib.h>
#include <agent_pp/vacm.h>

#include <snmp_pp/oid_def.h>
#include <snmp_pp/mp_v3.h>
#include <snmp_pp/log.h>

#ifdef SNMP_PP_NAMESPACE
using namespace Snmp_pp;
#endif

#ifdef AGENTPP_NAMESPACE
using namespace Agentpp;
#endif

// globals:

static const char *loggerModuleName = "agent++.static_table";

unsigned short port;
Mib *mib;
RequestList *reqList;
bool run = TRUE;

static void sig(int signo)
{
  if ((signo == SIGTERM) || (signo == SIGINT) ||
      (signo == SIGSEGV))
  {

    printf("\n");

    switch (signo)
    {
    case SIGSEGV:
    {
      printf("Segmentation fault, aborting.\n");
      exit(1);
    }
    case SIGTERM:
    case SIGINT:
    {
      if (run)
      {
        run = FALSE;
        printf("User abort\n");
      }
    }
    }
  }
}

void init_signals()
{
  signal(SIGTERM, sig);
  signal(SIGINT, sig);
  signal(SIGSEGV, sig);
}

void init(Mib &mib, const NS_SNMP OctetStr &engineID)
{
  mib.add(new sysGroup("Sensuron SNMP data",
                       "1.3.6.1.4.1.57", 10));
  mib.add(new snmpGroup());
  mib.add(new snmp_target_mib());
  mib.add(new snmp_notification_mib());

  // An example usage of the MibStaticTable for a read-only scalar
  // group:
  MibStaticTable *ssg = new MibStaticTable("1.3.6.1.4.1.57.6.1.2");

  char uint32DataStr[4] = {0};
  uint32_t uint32Data = 12345;
  memcpy(uint32DataStr, &uint32Data, sizeof(uint32Data));

  ssg->add(MibStaticEntry("1.0", OctetStr(uint32DataStr)));

  char floatDataStr[4] = {0};
  float floatData = 123.45;
  memcpy(floatDataStr, &floatData, sizeof(floatData));

  ssg->add(MibStaticEntry("2.0", OctetStr(floatDataStr)));

  // Create an array of 2048 floats and serialize them into an OctetStr
  std::stringstream ss("");

  for (int i = 0; i < 2048; ++i)
  {
    std::string oid = "3." + std::to_string(i + 1); // Creating OID for each float in the array
    float floatData = static_cast<float>(i) + 0.1;

    OctetStr octetStr(reinterpret_cast<const unsigned char *>(&floatData), sizeof(floatData));

    ssg->add(MibStaticEntry(oid.c_str(), octetStr)); // Example values
  }

  mib.add(ssg);

#ifdef _SNMPv3
  UsmUserTable *uut = new UsmUserTable();

  uut->addNewRow("unsecureUser",
                 SNMP_AUTHPROTOCOL_NONE,
                 SNMP_PRIVPROTOCOL_NONE, "", "", engineID, false);

  // add non persistent USM statistics
  mib.add(new UsmStats());
  // add the USM MIB - usm_mib MibGroup is used to
  // make user added entries persistent
  mib.add(new usm_mib(uut));
  // add non persistent SNMPv3 engine object
  mib.add(new V3SnmpEngine());
#endif
}

int main(int argc, char *argv[])
{
  if (argc > 1)
    port = atoi(argv[1]);
  else
    port = 4700;

#ifndef _NO_LOGGING
  DefaultLog::log()->set_filter(ERROR_LOG, 5);
  DefaultLog::log()->set_filter(WARNING_LOG, 5);
  DefaultLog::log()->set_filter(EVENT_LOG, 5);
  DefaultLog::log()->set_filter(INFO_LOG, 5);
  DefaultLog::log()->set_filter(DEBUG_LOG, 6);
#endif
  int status;
  Snmp::socket_startup(); // Initialize socket subsystem
  Snmpx snmp(status, port);

  if (status == SNMP_CLASS_SUCCESS)
  {

    LOG_BEGIN(loggerModuleName, EVENT_LOG | 1);
    LOG("main: SNMP listen port");
    LOG(port);
    LOG_END;
  }
  else
  {
    LOG_BEGIN(loggerModuleName, ERROR_LOG | 0);
    LOG("main: SNMP port init failed");
    LOG(status);
    LOG_END;
    exit(1);
  }
  mib = new Mib();
#ifdef _SNMPv3
  unsigned int snmpEngineBoots = 0;
  OctetStr engineId(SnmpEngineID::create_engine_id(port));

  // you may use your own methods to load/store this counter
  status = mib->get_boot_counter(engineId, snmpEngineBoots);
  if ((status != SNMPv3_OK) && (status < SNMPv3_FILEOPEN_ERROR))
  {
    LOG_BEGIN(loggerModuleName, ERROR_LOG | 0);
    LOG("main: Error loading snmpEngineBoots counter (status)");
    LOG(status);
    LOG_END;
    exit(1);
  }

  snmpEngineBoots++;
  status = mib->set_boot_counter(engineId, snmpEngineBoots);
  if (status != SNMPv3_OK)
  {
    LOG_BEGIN(loggerModuleName, ERROR_LOG | 0);
    LOG("main: Error saving snmpEngineBoots counter (status)");
    LOG(status);
    LOG_END;
    exit(1);
  }

  int stat;
  v3MP *v3mp = new v3MP(engineId, snmpEngineBoots, stat);
#else
  OctetStr engineId; // not used without SNMPv3
#endif
  reqList = new RequestList(mib);
#ifdef _SNMPv3
  // register v3MP
  reqList->set_v3mp(v3mp);
  snmp.set_mpv3(v3mp);
#endif
  // register requestList for outgoing requests
  mib->set_request_list(reqList);

  init_signals();

  // add supported objects
  init(*mib, engineId);
  // load persistent objects from disk
  mib->init();

  reqList->set_snmp(&snmp);

#ifdef _SNMPv3
  // register VACM
  Vacm *vacm = new Vacm(*mib);
  reqList->set_vacm(vacm);

  // initialize security information
  vacm->addNewContext("");
  vacm->addNewContext("other");

  // Define a new view that includes the OID you want to access
  vacm->addNewView("myReadView", "1.3.6.1.4.1.57.6.1", "", view_included, storageType_nonVolatile);

  // Ensure the user group has access to this view
  vacm->addNewGroup(SNMP_SECURITY_MODEL_USM, "unsecureUser", "newGroup", storageType_nonVolatile);
  vacm->addNewAccessEntry("newGroup", "", SNMP_SECURITY_MODEL_USM, SNMP_SECURITY_LEVEL_NOAUTH_NOPRIV,
                          match_exact, "myReadView", "myReadView", "myReadView", storageType_nonVolatile);

#endif
  Vbx *vbs = 0;
  coldStartOid coldOid;
  NotificationOriginator no;
  UdpAddress dest("127.0.0.1/162");
  no.add_v1_trap_destination(dest, "defaultV1Trap", "v1trap", "public");
  no.generate(vbs, 0, coldOid, "", "");

  Request *req;
  while (run)
  {

    req = reqList->receive(2);

    if (req)
    {
      mib->process_request(req);
    }
    else
    {
      mib->cleanup();
    }
  }
  delete mib;
  Snmp::socket_cleanup(); // Shut down socket subsystem
  return 0;
}
