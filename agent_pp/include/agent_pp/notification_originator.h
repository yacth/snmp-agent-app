/*_############################################################################
  _## 
  _##  AGENT++ 4.5 - notification_originator.h  
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

#ifndef _notification_originator_h_
#define _notification_originator_h_

#include <agent_pp/agent++.h>
#include <agent_pp/mib.h>
#include <agent_pp/snmp_target_mib.h>
#include <agent_pp/snmp_community_mib.h>
#include <agent_pp/snmp_notification_mib.h>
#include <agent_pp/notification_log_mib.h>

#define mpV1  0
#define mpV2c 1
#define mpV3  3

#ifdef AGENTPP_NAMESPACE
namespace Agentpp {
    using namespace Snmp_pp;
#endif


/*--------------------- class NotificationOriginator ---------------------*/

/**
 * The NotificationOriginator provides services to send traps and 
 * notifications by using the SNMP-TARGET-MIB and the SNMP-NOTIFICATION-MIB.
 * NotificationOriginator is typically used outside the main loop of an 
 * agent's request handling.
 * 
 * @author Frank Fock
 * @version 3.5.10
 */

class AGENTPP_DECL NotificationOriginator: public NotificationSender {

 public:
	/**
	 * Constructs a notification originator instance for using a static
         * Mib::instance
         * @deprecated Use NotificationOriginator(Mib*) instead to avoid static
         * references.
	 */
	NotificationOriginator();

        /**
	 * Constructs a notification originator instance for using a static
         * Mib::instance
         * @param mibRef a pointer to the Mib instance.
         * @since 4.3.0.
	 */
	NotificationOriginator(Mib* mibRef): NotificationOriginator() { 
            mib = mibRef; 
        }

	/**
	 * Destructor.
	 */
	virtual ~NotificationOriginator();

	/**
	 * Generate a notification message.
	 *
	 * @param vbs
	 *    an array of variable bindings - the payload of the notification.
	 * @param size
	 *    the size of the above array.
	 * @param id
	 *    the trap oid which identifies the notification.
	 * @param enterprise
	 *    the enterprise oid. For v2,v3 and enterprise specific v1 traps
	 *    this parameter should be "" (empty OID).
	 * @param contextName
	 *    the context in which the trap occurred. 
	 */			       
	void    generate(Vbx*, int, const Oidx&, const Oidx&, const NS_SNMP OctetStr&);

	/**
	 * Generate a notification message.
	 *
	 * @param vbs
	 *    an array of variable bindings - the payload of the notification.
	 * @param size
	 *    the size of the above array.
	 * @param id
	 *    the trap oid which identifies the notification.
	 * @param sysUpTime
	 *    the timestamp to be used
	 * @param contextName
	 *    the context in which the trap occured. 
	 */			       
	void    generate(Vbx*, int, const Oidx&, 
			 unsigned int, const NS_SNMP OctetStr&);

	/**
	 * Send a notification. This implements the NotificationSender 
	 * interface.
	 *
	 * @param context
	 *    the context originating the notification ("" for the default 
	 *    context).
	 * @param trapoid
	 *    the oid of the notification.
	 * @param vbs
	 *    an array of variable bindings.
	 * @param size
	 *    the size of the above variable binding array.
	 * @param timestamp
	 *    an optional timestamp.
	 * @return 
	 *    SNMP_ERROR_SUCCESS if the notification could be sent
	 *    successfully, otherwise an appropriate SNMP error is
	 *    returned.
	 */
	virtual int		notify(const NS_SNMP OctetStr&, const Oidx&,
				       Vbx*, int, unsigned int=0); 
	
	/**
	 * Make all necessary entries in snmpTargetAddressTable,
	 * snmpTargetParamsTable, and snmpNotifyTable for the given
	 * v1, v2 or v3 trap destination.
	 *
	 * @param addr
	 *    an UDP target address.
	 * @param name
	 *    unique name for the entries.
	 * @param tag
	 *    unique tag for the entries.
	 * @param community / secName
	 *    community / security name to use when sending traps.
	 * @param secLevel
	 *    security level to use when sending v3 traps
	 * @return
	 *    TRUE if the operation has been successful, FALSE otherwise.
	 */
	/**@{ */
	virtual bool add_v1_trap_destination(const NS_SNMP UdpAddress& addr,
					     const NS_SNMP OctetStr &name,
					     const NS_SNMP OctetStr &tag,
					     const NS_SNMP OctetStr &community);
	virtual bool add_v2_trap_destination(const NS_SNMP UdpAddress& addr,
					     const NS_SNMP OctetStr &name,
					     const NS_SNMP OctetStr &tag,
					     const NS_SNMP OctetStr &community);
	virtual bool add_v3_trap_destination(const NS_SNMP UdpAddress& addr,
					     const NS_SNMP OctetStr &name,
					     const NS_SNMP OctetStr &tag,
					     const NS_SNMP OctetStr &secName,
					     const int secLevel);
	/**@} */

#ifdef _SNMPv3
	/**
	 * Sets the local engine ID to be used when sending notifications.
	 *
	 * @param engineID
	 *    an OctetStr instance.
	 */
	void		set_local_engine_id(const NS_SNMP OctetStr& id)
	    { if (localEngineID) { delete localEngineID; } 
	      localEngineID = new NS_SNMP OctetStr(id); }
#endif
        
        /**
         * Sets the cached reference for the snmpTargetAddrEntry. If set to 
         * null, the reference will be determined by looking up the OID
         * 1.3.6.1.6.3.12.1.2.1 from the Mib reference.
         * @param targetAddrRef
         * @since 4.3.0
         */
        void set_snmp_target_addr_entry(snmpTargetAddrEntry* targetAddrRef) {
            targetAddrEntry = targetAddrRef;
        }
        
        /**
         * Gets the reference for the snmpTargetAddrEntry instance associated
         * with the Mib reference by looking up the OID
         * 1.3.6.1.6.3.12.1.2.1 there and caching the reference locally.
         * @return 
         *     a snmpTargetAddrEntry instance pointer.
         * @since 4.3.0
         */
        virtual snmpTargetAddrEntry* get_snmp_target_addr_entry();

        /**
         * Sets the cached reference for the snmpTargetParamsEntry. If set to 
         * null, the reference will be determined by looking up the OID
         * 1.3.6.1.6.3.12.1.3.1 from the Mib reference.
         * @param targetParamsRef
         * @since 4.3.0
         */
        void set_snmp_target_params_entry(snmpTargetParamsEntry* targetParamsRef) {
            targetParamsEntry = targetParamsRef;
        }
        
        /**
         * Gets the reference for the snmpTargetAddrEntry instance associated
         * with the Mib reference by looking up the OID
         * 1.3.6.1.6.3.12.1.3.1 there and caching the reference locally.
         * @return 
         *     a snmpTargetAddrEntry instance pointer.
         * @since 4.3.0
         */
        virtual snmpTargetParamsEntry* get_snmp_target_params_entry();

#ifdef _SNMPv3
        /**
         * Sets the cached reference for the snmpCommunityEntry. If set to 
         * null, the reference will be determined by looking up the OID
         * 1.3.6.1.6.3.18.1.1.1 from the Mib reference.
         * @param communityEntryRef
         * @since 4.3.0
         */
        void set_snmp_community_entry(snmpCommunityEntry* communityEntryRef) {
            communityEntry = communityEntryRef;
        }
        
        /**
         * Gets the reference for the snmpCommunityEntry instance associated
         * with the Mib reference by looking up the OID
         * 1.3.6.1.6.3.18.1.1.1 there and caching the reference locally.
         * @return 
         *     a snmpCommunityEntry instance pointer.
         * @since 4.3.0
         */
        virtual snmpCommunityEntry* get_snmp_community_entry();
#endif

        /**
         * Sets the cached reference for the snmpNotifyEntry. If set to 
         * null, the reference will be determined by looking up the OID
         * 1.3.6.1.6.3.13.1.1.1 from the Mib reference.
         * @param communityEntryRef
         * @since 4.3.0
         */
        void set_snmp_notify_entry(snmpNotifyEntry* notifyEntryRef) {
            notifyEntry = notifyEntryRef;
        }
        
        /**
         * Gets the reference for the snmpNotifyEntry instance associated
         * with the Mib reference by looking up the OID
         * 1.3.6.1.6.3.13.1.1.1 there and caching the reference locally.
         * @return 
         *     a snmpNotifyEntry instance pointer.
         * @since 4.3.0
         */
        virtual snmpNotifyEntry* get_snmp_notify_entry();

        /**
         * Sets the cached reference for the snmpNotifyFilterEntry. If set to 
         * null, the reference will be determined by looking up the OID
         * 1.3.6.1.6.3.13.1.1.1 from the Mib reference.
         * @param notifyFilterEntryRef
         * @since 4.3.0
         */
        void set_snmp_notify_filter_entry(snmpNotifyFilterEntry* notifyFilterEntryRef) {
            notifyFilterEntry = notifyFilterEntryRef;
        }
        
        /**
         * Gets the reference for the snmpNotifyFilterEntry instance associated
         * with the Mib reference by looking up the OID
         * 1.3.6.1.6.3.13.1.3.1 there and caching the reference locally.
         * @return 
         *     a snmpNotifyFilterEntry instance pointer.
         * @since 4.3.0
         */
        virtual snmpNotifyFilterEntry* get_snmp_notify_filter_entry();

#ifdef _SNMPv3
        /**
         * Sets the cached reference for the nlmLogyEntry. If set to 
         * null, the reference will be determined by looking up the OID
         * 1.3.6.1.2.1.92.1.3.1 from the Mib reference.
         * @param nlmLogyEntryRef
         * @since 4.3.0
         */
        void set_nlm_log_entry(nlmLogEntry* nlmLogEntryRef) {
            _nlmLogEntry = nlmLogEntryRef;
        }
        
        /**
         * Gets the reference for the nlmLogEntry instance associated
         * with the Mib reference by looking up the OID
         * 1.3.6.1.2.1.92.1.3.1 there and caching the reference locally.
         * @return 
         *     a nlmLogEntry instance pointer.
         * @since 4.3.0
         */
        virtual nlmLogEntry* get_nlm_log_entry();
        virtual v3MP* get_v3mp();
#endif

 protected:
     
 
        Mib*                    mib;
        snmpTargetAddrEntry*    targetAddrEntry;
        snmpTargetParamsEntry*  targetParamsEntry;
#ifdef _SNMPv3
        snmpCommunityEntry*     communityEntry;
#endif
        snmpNotifyEntry*        notifyEntry;
        snmpNotifyFilterEntry*  notifyFilterEntry;
#ifdef _SNMPv3
        nlmLogEntry*            _nlmLogEntry;
        v3MP*                   v3mp;
#endif

	class NotificationOriginatorParams {
	public:
		NotificationOriginatorParams(Vbx* _vbs, int _size, const Oidx& _id,
				unsigned int _timestamp,
				const Oidx& _enterprise, 
				const NS_SNMP OctetStr& _contextName) :
				vbs(_vbs), size(_size), id(_id), timestamp(_timestamp),
				enterprise(_enterprise), contextName(_contextName)
				{ target = 0; }

		Vbx* vbs;
		int size;
		Oidx id;
		unsigned int timestamp;
		Oidx enterprise;
		NS_SNMP OctetStr contextName;
		NS_SNMP OctetStr securityName;
		int securityModel;
		int securityLevel;
		int mpModel;
#ifdef _SNMPv3
		NS_SNMP UTarget* target;
#else
		NS_SNMP CTarget* target;
#endif

	private:
		NotificationOriginatorParams();
	};

	/**
	 * Generate a notification message.
	 *
	 * @param vbs
	 *    an array of variable bindings - the payload of the notification.
	 * @param size
	 *    the size of the above array.
	 * @param id
	 *    the trap oid which identifies the notification.
	 * @param sysUpTime
	 *    the timestamp to be used
	 * @param enterprise
	 *    the enterprise oid. For v2,v3 and enterprise specific v1 traps
	 *    this parameter should be "" (empty OID).
	 * @param contextName
	 *    the context in which the trap occured. 
	 */			       
	int    generate(Vbx*, int, const Oidx&, unsigned int, 
			const Oidx&, const NS_SNMP OctetStr&);

	/**
	 * Check notification access for a management target.
	 * Call this to validate access before sending the notificaiton.  The
	 * NotificationOriginatorParams parameter must have the vbs, size, id,
	 * and contextName parameters filled in.  Upon a TRUE return, the
	 * securityName, securityModel, securityLevel, mpModel, and target
	 * parameters will be filled in.  If TRUE is returned, the caller is
	 * responsible to delete the target object in the
	 * NotificationOriginatorParams object (after sending the notification).
	 *
	 * @param cur
	 *    the selected entry in the snmpTargetAddrTable
	 * @param nop
	 *    the notification originator parameters
	 * @return
	 *    TRUE if access is okay, FALSE otherwise
	 */			       
	bool check_access(ListCursor<MibTableRow>& cur, NotificationOriginatorParams& nop);

	/**
	 * Send a notification to a valid target.
	 * Call this only after validating access by calling the check_access
	 * method first.  The NotificationOriginatorParams parameter must have
	 * the vbs, size, id, timestamp, enterprise, contextName, securityName,
	 * securityLevel, mpModel, and target parameters filled in.
	 *
	 * @param cur
	 *    the selected entry in the snmpTargetAddrTable
	 * @param nop
	 *    the notification originator parameters
	 * @param notify
	 *    specifies the notification type (trap or inform)
	 * @return
	 *    The result from calling SnmpRequestV3::send or
	 *    SnmpRequest::process_trap
	 */			       
	int send_notify(ListCursor<MibTableRow>& cur, NotificationOriginatorParams& nop, int notify);

#ifdef _SNMPv3
	NS_SNMP OctetStr*	localEngineID;
#endif
};
#ifdef AGENTPP_NAMESPACE
}
#endif
#endif
