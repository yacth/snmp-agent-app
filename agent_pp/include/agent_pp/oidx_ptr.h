/*_############################################################################
  _## 
  _##  AGENT++ 4.5 - oidx_ptr.h  
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

#ifndef _oidx_ptr_h_
#define _oidx_ptr_h_

#include <libagent.h>

#include <agent_pp/agent++.h>
#include <agent_pp/snmp_pp_ext.h>

#ifdef AGENTPP_NAMESPACE
namespace Agentpp {
    using namespace Snmp_pp;
#endif

typedef Oidx* OidxPtr;

#ifdef AGENTPP_NAMESPACE
}
#endif
#endif
