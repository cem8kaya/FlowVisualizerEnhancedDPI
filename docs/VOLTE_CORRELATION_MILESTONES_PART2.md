# VoLTE Cross-Protocol Correlation Implementation
## Milestone Prompts 4-8 (Continuation)

---

# Milestone 4: GTPv2 Intra-Protocol Correlator (2 weeks)

## PROMPT 4.1: GTPv2 Session and Bearer Tracking

```markdown
# GTPv2 Intra-Protocol Correlator
## nDPI Callflow Visualizer - GTPv2 Session and Bearer Management

**Context:**
I'm building the nDPI Callflow Visualizer. This prompt implements the GTPv2 intra-protocol correlator that groups GTPv2-C messages into sessions, tracks bearer lifecycle (default and dedicated), and extracts subscriber/network information for cross-protocol correlation.

**Analysis Reference:**
The Python GTPv2 parser (gtpv2_s11_s5_s2b.py, 2918 lines) handles:
- Session tracking by Control TEID + Sequence Number
- Bearer tracking (EBI, LBI for dedicated bearers)
- F-TEID extraction for GTP-U tunnel correlation
- IMSI/MSISDN/MEI extraction from IEs
- PDN address (UE IPv4/IPv6) tracking
- APN detection and classification (IMS, internet, emergency)
- Message pairing (Create Session Req/Resp, etc.)

**3GPP References:**
- TS 29.274 (GTPv2-C Protocol)
- TS 23.401 (EPS Architecture)
- TS 29.281 (GTPv1-U for User Plane)

---

## Requirements

### 1. GTPv2 Message Types

```cpp
// Bearer-related messages
enum class Gtpv2MessageType : uint8_t {
    // Session management
    CREATE_SESSION_REQUEST = 32,
    CREATE_SESSION_RESPONSE = 33,
    DELETE_SESSION_REQUEST = 36,
    DELETE_SESSION_RESPONSE = 37,
    
    // Bearer management
    CREATE_BEARER_REQUEST = 95,
    CREATE_BEARER_RESPONSE = 96,
    UPDATE_BEARER_REQUEST = 97,
    UPDATE_BEARER_RESPONSE = 98,
    DELETE_BEARER_REQUEST = 99,
    DELETE_BEARER_RESPONSE = 100,
    
    // Modify bearer
    MODIFY_BEARER_REQUEST = 34,
    MODIFY_BEARER_RESPONSE = 35,
    
    // Access bearers
    MODIFY_ACCESS_BEARERS_REQUEST = 211,
    MODIFY_ACCESS_BEARERS_RESPONSE = 212,
    RELEASE_ACCESS_BEARERS_REQUEST = 170,
    RELEASE_ACCESS_BEARERS_RESPONSE = 171,
    
    // Downlink data notification
    DOWNLINK_DATA_NOTIFICATION = 176,
    DOWNLINK_DATA_NOTIFICATION_ACK = 177,
    DOWNLINK_DATA_NOTIFICATION_FAILURE = 70,
    
    // Handover
    CONTEXT_REQUEST = 130,
    CONTEXT_RESPONSE = 131,
    CONTEXT_ACKNOWLEDGE = 132,
    FORWARD_RELOCATION_REQUEST = 133,
    FORWARD_RELOCATION_RESPONSE = 134,
    
    // Echo
    ECHO_REQUEST = 1,
    ECHO_RESPONSE = 2,
};

// Cause codes
enum class Gtpv2Cause : uint8_t {
    REQUEST_ACCEPTED = 16,
    REQUEST_ACCEPTED_PARTIALLY = 17,
    NEW_PDN_TYPE_DUE_TO_NETWORK_PREFERENCE = 18,
    NEW_PDN_TYPE_DUE_TO_SINGLE_ADDRESS_BEARER_ONLY = 19,
    CONTEXT_NOT_FOUND = 64,
    INVALID_MESSAGE_FORMAT = 65,
    // ... more causes
};
```

### 2. Bearer Types and Tracking

```cpp
// PDN Type classification (from APN)
enum class PdnClass {
    IMS,        // IMS APN for VoLTE
    INTERNET,   // Default internet APN
    EMERGENCY,  // Emergency services
    MMS,        // MMS APN
    OTHER
};

// Bearer types
enum class BearerType {
    DEFAULT,     // Default EPS bearer (EBI = LBI)
    DEDICATED    // Dedicated bearer (linked to default via LBI)
};

struct GtpBearer {
    uint8_t ebi;              // EPS Bearer ID (5-15)
    uint8_t lbi;              // Linked Bearer ID (for dedicated)
    BearerType type;
    uint8_t qci;              // QoS Class Identifier
    uint32_t mbr_ul;          // Max Bitrate Uplink
    uint32_t mbr_dl;          // Max Bitrate Downlink
    uint32_t gbr_ul;          // Guaranteed Bitrate Uplink (GBR bearers)
    uint32_t gbr_dl;          // Guaranteed Bitrate Downlink
    
    // GTP-U tunnel info
    std::string s1u_enb_ip;
    uint32_t s1u_enb_teid;
    std::string s1u_sgw_ip;
    uint32_t s1u_sgw_teid;
    std::string s5_pgw_ip;
    uint32_t s5_pgw_teid;
};
```

### 3. F-TEID Structure

```cpp
// Fully Qualified TEID (F-TEID)
struct Gtpv2Fteid {
    uint8_t interface_type;   // See 3GPP TS 29.274 Table 8.22-1
    uint32_t teid;            // Tunnel Endpoint ID
    std::string ipv4;
    std::string ipv6;
    
    // Interface type meanings
    static constexpr uint8_t S1_U_ENB = 0;
    static constexpr uint8_t S1_U_SGW = 1;
    static constexpr uint8_t S12_RNC = 2;
    static constexpr uint8_t S4_SGSN = 3;
    static constexpr uint8_t S5_S8_SGW = 4;
    static constexpr uint8_t S5_S8_PGW = 5;
    static constexpr uint8_t S11_MME = 10;
    static constexpr uint8_t S11_SGW = 11;
};
```

---

## Implementation

### File Structure

```
include/correlation/gtpv2/
├── gtpv2_types.h             // Enums and constants
├── gtpv2_ie_parser.h         // Information Element parsing
├── gtpv2_session.h           // GTPv2 session container
├── gtpv2_bearer.h            // Bearer tracking
├── gtpv2_correlator.h        // Main GTPv2 correlator
└── gtpv2_fteid_manager.h     // F-TEID tracking for GTP-U linking

src/correlation/gtpv2/
├── gtpv2_ie_parser.cpp
├── gtpv2_session.cpp
├── gtpv2_bearer.cpp
├── gtpv2_correlator.cpp
└── gtpv2_fteid_manager.cpp

tests/unit/gtpv2/
├── test_gtpv2_ie_parser.cpp
├── test_gtpv2_session.cpp
├── test_gtpv2_bearer.cpp
└── test_gtpv2_correlator.cpp
```

### gtpv2_session.h

```cpp
#pragma once

#include "correlation/gtpv2/gtpv2_types.h"
#include "correlation/gtpv2/gtpv2_bearer.h"
#include "correlation/identity/subscriber_identity.h"
#include <vector>
#include <memory>
#include <optional>

namespace callflow {
namespace correlation {

class Gtpv2Message;

/**
 * @brief Represents a GTPv2-C session (PDN Connection)
 * 
 * A session is identified by Control TEID and contains:
 * - Default bearer and all dedicated bearers
 * - Subscriber information (IMSI, MSISDN, MEI)
 * - PDN address (UE IP)
 * - F-TEIDs for all interfaces
 */
class Gtpv2Session {
public:
    Gtpv2Session(uint32_t control_teid, uint32_t sequence);
    ~Gtpv2Session() = default;
    
    // Session identification
    uint32_t getControlTeid() const { return control_teid_; }
    std::string getSessionKey() const;  // TEID + Sequence hash
    
    // PDN Type
    PdnClass getPdnClass() const { return pdn_class_; }
    bool isIms() const { return pdn_class_ == PdnClass::IMS; }
    bool isEmergency() const { return pdn_class_ == PdnClass::EMERGENCY; }
    
    // Add message
    void addMessage(const Gtpv2Message& msg);
    
    // Messages
    const std::vector<Gtpv2Message>& getMessages() const { return messages_; }
    size_t getMessageCount() const { return messages_.size(); }
    
    // Bearer management
    void addBearer(const GtpBearer& bearer);
    GtpBearer* getDefaultBearer();
    GtpBearer* getBearer(uint8_t ebi);
    std::vector<GtpBearer*> getDedicatedBearers();
    bool hasDedicatedBearers() const;
    
    // Subscriber information
    std::optional<std::string> getImsi() const { return imsi_; }
    std::optional<std::string> getMsisdn() const { return msisdn_; }
    std::optional<std::string> getMei() const { return mei_; }
    
    // Network information
    std::string getApn() const { return apn_; }
    std::optional<std::string> getPdnAddressV4() const { return pdn_addr_v4_; }
    std::optional<std::string> getPdnAddressV6() const { return pdn_addr_v6_; }
    
    // F-TEIDs
    std::vector<Gtpv2Fteid> getFteids() const { return fteids_; }
    std::optional<Gtpv2Fteid> getFteidByInterface(uint8_t iface_type) const;
    
    // RAT Type
    std::string getRatType() const { return rat_type_; }
    
    // Time window
    double getStartTime() const { return start_time_; }
    double getEndTime() const { return end_time_; }
    uint32_t getStartFrame() const { return start_frame_; }
    uint32_t getEndFrame() const { return end_frame_; }
    
    // Session state
    enum class State {
        CREATING,       // Create Session Request sent
        ACTIVE,         // Create Session Response (accepted) received
        MODIFYING,      // Modify/Update in progress
        DELETING,       // Delete Session Request sent
        DELETED         // Delete Session Response received
    };
    State getState() const { return state_; }
    
    // Subsession tracking (for dedicated bearers)
    struct Subsession {
        std::string type;         // "dflt_ebi", "ded_ebi"
        std::string idx;          // e.g., "5", "6"
        uint32_t start_frame;
        uint32_t end_frame;
    };
    std::vector<Subsession> getSubsessions() const { return subsessions_; }
    
    // Correlation
    void setIntraCorrelator(const std::string& id) { intra_correlator_ = id; }
    std::string getIntraCorrelator() const { return intra_correlator_; }
    
    void setInterCorrelator(const std::string& id) { inter_correlator_ = id; }
    std::string getInterCorrelator() const { return inter_correlator_; }
    
    // Finalize
    void finalize();

private:
    uint32_t control_teid_;
    uint32_t sequence_;
    
    PdnClass pdn_class_ = PdnClass::OTHER;
    State state_ = State::CREATING;
    
    std::vector<Gtpv2Message> messages_;
    std::vector<GtpBearer> bearers_;
    std::vector<Gtpv2Fteid> fteids_;
    std::vector<Subsession> subsessions_;
    
    // Subscriber info
    std::optional<std::string> imsi_;
    std::optional<std::string> msisdn_;
    std::optional<std::string> mei_;
    
    // Network info
    std::string apn_;
    std::optional<std::string> pdn_addr_v4_;
    std::optional<std::string> pdn_addr_v6_;
    std::string rat_type_;
    
    // Time window
    double start_time_ = 0.0;
    double end_time_ = 0.0;
    uint32_t start_frame_ = 0;
    uint32_t end_frame_ = 0;
    
    // Correlation
    std::string intra_correlator_;
    std::string inter_correlator_;
    
    // Internal methods
    void extractSubscriberInfo(const Gtpv2Message& msg);
    void extractBearerInfo(const Gtpv2Message& msg);
    void extractFteids(const Gtpv2Message& msg);
    void detectPdnClass();
    void updateTimeWindow(const Gtpv2Message& msg);
    void updateState(const Gtpv2Message& msg);
};

} // namespace correlation
} // namespace callflow
```

### gtpv2_correlator.h

```cpp
#pragma once

#include "correlation/gtpv2/gtpv2_session.h"
#include "correlation/gtpv2/gtpv2_fteid_manager.h"
#include "correlation/identity/subscriber_context_manager.h"
#include <unordered_map>
#include <memory>
#include <mutex>

namespace callflow {
namespace correlation {

/**
 * @brief GTPv2 intra-protocol correlator
 * 
 * Groups GTPv2-C messages into sessions, tracks bearers,
 * and maintains F-TEID mappings for GTP-U correlation.
 */
class Gtpv2Correlator {
public:
    Gtpv2Correlator();
    explicit Gtpv2Correlator(SubscriberContextManager* ctx_manager);
    ~Gtpv2Correlator() = default;
    
    /**
     * @brief Add a parsed GTPv2 message
     */
    void addMessage(const Gtpv2Message& msg);
    
    /**
     * @brief Finalize all sessions
     */
    void finalize();
    
    /**
     * @brief Get all sessions
     */
    std::vector<Gtpv2Session*> getSessions();
    
    /**
     * @brief Get IMS sessions only (for VoLTE correlation)
     */
    std::vector<Gtpv2Session*> getImsSessions();
    
    /**
     * @brief Get sessions with dedicated bearers (active VoLTE calls)
     */
    std::vector<Gtpv2Session*> getSessionsWithDedicatedBearers();
    
    /**
     * @brief Find session by Control TEID
     */
    Gtpv2Session* findByControlTeid(uint32_t teid);
    
    /**
     * @brief Find session by IMSI
     */
    std::vector<Gtpv2Session*> findByImsi(const std::string& imsi);
    
    /**
     * @brief Find session by MSISDN
     */
    std::vector<Gtpv2Session*> findByMsisdn(const std::string& msisdn);
    
    /**
     * @brief Find session by PDN address (UE IP)
     */
    Gtpv2Session* findByPdnAddress(const std::string& ip);
    
    /**
     * @brief Find session by F-TEID
     */
    Gtpv2Session* findByFteid(const std::string& ip, uint32_t teid);
    
    /**
     * @brief Get F-TEID manager for GTP-U linking
     */
    Gtpv2FteidManager& getFteidManager() { return fteid_manager_; }
    
    /**
     * @brief Get statistics
     */
    struct Stats {
        size_t total_messages = 0;
        size_t total_sessions = 0;
        size_t ims_sessions = 0;
        size_t internet_sessions = 0;
        size_t dedicated_bearers = 0;
        size_t session_errors = 0;
    };
    Stats getStats() const;
    
    /**
     * @brief Clear all sessions
     */
    void clear();

private:
    std::mutex mutex_;
    std::unordered_map<std::string, std::unique_ptr<Gtpv2Session>> sessions_;
    // Key: Control TEID + Sequence hash
    
    Gtpv2FteidManager fteid_manager_;
    SubscriberContextManager* ctx_manager_ = nullptr;
    
    int session_sequence_ = 0;
    Stats stats_;
    
    // PDN address index for fast lookup
    std::unordered_map<std::string, Gtpv2Session*> pdn_address_index_;
    
    std::string generateSessionKey(uint32_t teid, uint32_t sequence);
    std::string generateIntraCorrelator(double timestamp);
    void updateSubscriberContext(const Gtpv2Session& session);
    void updatePdnAddressIndex(Gtpv2Session* session);
};

/**
 * @brief Manages F-TEID to Session mapping for GTP-U correlation
 */
class Gtpv2FteidManager {
public:
    /**
     * @brief Register F-TEID with associated session
     */
    void registerFteid(const Gtpv2Fteid& fteid, Gtpv2Session* session);
    
    /**
     * @brief Find session by F-TEID
     */
    Gtpv2Session* findSessionByFteid(const std::string& ip, uint32_t teid);
    
    /**
     * @brief Find session by GTP-U packet (for linking user plane)
     */
    Gtpv2Session* findSessionByGtpuPacket(const std::string& src_ip,
                                           const std::string& dst_ip,
                                           uint32_t teid);
    
    /**
     * @brief Get subscriber context for GTP-U packet
     */
    std::optional<std::string> getImsiForGtpuPacket(const std::string& src_ip,
                                                     const std::string& dst_ip,
                                                     uint32_t teid);

private:
    // Key: "IP:TEID" -> Session
    std::unordered_map<std::string, Gtpv2Session*> fteid_to_session_;
    
    std::string makeKey(const std::string& ip, uint32_t teid);
};

} // namespace correlation
} // namespace callflow
```

---

## Success Criteria

- [ ] Correctly tracks session by Control TEID
- [ ] Pairs Request/Response messages by Sequence
- [ ] Tracks default and dedicated bearers
- [ ] Extracts F-TEIDs for all interfaces
- [ ] Classifies PDN type (IMS, internet, emergency)
- [ ] Extracts IMSI, MSISDN, MEI from IEs
- [ ] Provides fast lookup by PDN address
- [ ] Unit test coverage > 85%
```

---

# Milestone 5: NAS/S1AP Correlator (2 weeks)

## PROMPT 5.1: NAS Message Parsing and S1AP Integration

```markdown
# NAS/S1AP Intra-Protocol Correlator
## nDPI Callflow Visualizer - LTE Mobility and Session Management

**Context:**
I'm building the nDPI Callflow Visualizer. This prompt implements the NAS (Non-Access Stratum) and S1AP correlators. NAS messages (EMM/ESM) handle mobility and session management, carried within S1AP messages between UE and MME.

**Analysis Reference:**
NAS messages contain critical subscriber identifiers (IMSI, IMEI, GUTI) and session information (PDN connectivity, bearer activation). The Python correlator links NAS sessions by:
- IMSI/IMEI/GUTI matching
- S1AP UE context (MME-UE-S1AP-ID + eNB-UE-S1AP-ID)
- Tracking 4G_TMSI for session continuity

**3GPP References:**
- TS 24.301 (NAS for EPS)
- TS 36.413 (S1AP)
- TS 23.401 (EPS Architecture)

---

## Requirements

### 1. EMM Message Types

```cpp
enum class NasEmmMessageType : uint8_t {
    // Attach
    ATTACH_REQUEST = 0x41,
    ATTACH_ACCEPT = 0x42,
    ATTACH_COMPLETE = 0x43,
    ATTACH_REJECT = 0x44,
    
    // Detach
    DETACH_REQUEST = 0x45,
    DETACH_ACCEPT = 0x46,
    
    // TAU
    TAU_REQUEST = 0x48,
    TAU_ACCEPT = 0x49,
    TAU_COMPLETE = 0x4A,
    TAU_REJECT = 0x4B,
    
    // Service Request (short form)
    SERVICE_REQUEST = 0x4C,
    
    // Authentication
    AUTH_REQUEST = 0x52,
    AUTH_RESPONSE = 0x53,
    AUTH_FAILURE = 0x54,
    AUTH_REJECT = 0x54,  // Same as failure
    
    // Identity
    IDENTITY_REQUEST = 0x55,
    IDENTITY_RESPONSE = 0x56,
    
    // Security
    SECURITY_MODE_COMMAND = 0x5D,
    SECURITY_MODE_COMPLETE = 0x5E,
    SECURITY_MODE_REJECT = 0x5F,
    
    // GUTI Reallocation
    GUTI_REALLOC_COMMAND = 0x50,
    GUTI_REALLOC_COMPLETE = 0x51,
};
```

### 2. ESM Message Types

```cpp
enum class NasEsmMessageType : uint8_t {
    // Default Bearer
    ACTIVATE_DEFAULT_BEARER_REQ = 0xC1,
    ACTIVATE_DEFAULT_BEARER_ACC = 0xC2,
    ACTIVATE_DEFAULT_BEARER_REJ = 0xC3,
    
    // Dedicated Bearer
    ACTIVATE_DEDICATED_BEARER_REQ = 0xC5,
    ACTIVATE_DEDICATED_BEARER_ACC = 0xC6,
    ACTIVATE_DEDICATED_BEARER_REJ = 0xC7,
    
    // Modify Bearer
    MODIFY_BEARER_REQ = 0xC9,
    MODIFY_BEARER_ACC = 0xCA,
    MODIFY_BEARER_REJ = 0xCB,
    
    // Deactivate Bearer
    DEACTIVATE_BEARER_REQ = 0xCD,
    DEACTIVATE_BEARER_ACC = 0xCE,
    
    // PDN Connectivity
    PDN_CONNECTIVITY_REQUEST = 0xD0,
    PDN_CONNECTIVITY_REJECT = 0xD1,
    PDN_DISCONNECT_REQUEST = 0xD2,
    PDN_DISCONNECT_REJECT = 0xD3,
    
    // ESM Information
    ESM_INFO_REQUEST = 0xD9,
    ESM_INFO_RESPONSE = 0xDA,
};
```

### 3. S1AP Procedure Codes

```cpp
enum class S1apProcedureCode : uint8_t {
    // UE Context Management
    INITIAL_UE_MESSAGE = 12,
    DOWNLINK_NAS_TRANSPORT = 11,
    UPLINK_NAS_TRANSPORT = 13,
    INITIAL_CONTEXT_SETUP = 9,
    UE_CONTEXT_RELEASE_REQUEST = 18,
    UE_CONTEXT_RELEASE_COMMAND = 23,
    UE_CONTEXT_RELEASE_COMPLETE = 24,
    UE_CONTEXT_MODIFICATION = 21,
    
    // Handover
    HANDOVER_REQUIRED = 0,
    HANDOVER_REQUEST = 1,
    HANDOVER_NOTIFY = 2,
    PATH_SWITCH_REQUEST = 3,
    
    // Paging
    PAGING = 10,
    
    // S1 Setup
    S1_SETUP = 17,
    ENB_CONFIGURATION_UPDATE = 29,
    MME_CONFIGURATION_UPDATE = 30,
    
    // Reset
    RESET = 14,
    ERROR_INDICATION = 15,
};
```

---

## Implementation

### File Structure

```
include/correlation/nas/
├── nas_types.h               // EMM/ESM enums
├── nas_message.h             // NAS message container
├── nas_ie_parser.h           // Information Element parsing
├── nas_session.h             // NAS session tracking
├── nas_correlator.h          // NAS correlator

include/correlation/s1ap/
├── s1ap_types.h              // S1AP enums
├── s1ap_message.h            // S1AP message container
├── s1ap_context.h            // UE context tracking
├── s1ap_correlator.h         // S1AP correlator

src/correlation/nas/
├── nas_message.cpp
├── nas_ie_parser.cpp
├── nas_session.cpp
├── nas_correlator.cpp

src/correlation/s1ap/
├── s1ap_message.cpp
├── s1ap_context.cpp
├── s1ap_correlator.cpp
```

### nas_session.h

```cpp
#pragma once

#include "correlation/nas/nas_types.h"
#include "correlation/identity/subscriber_identity.h"
#include <vector>
#include <optional>

namespace callflow {
namespace correlation {

class NasMessage;

/**
 * @brief NAS session types
 */
enum class NasSessionType {
    EMM,        // Mobility management (attach, TAU, detach)
    ESM,        // Session management (PDN, bearer)
    UNKNOWN
};

/**
 * @brief Represents a NAS session
 * 
 * A NAS session tracks:
 * - EMM procedures (Attach, TAU, Detach, Auth, Security)
 * - ESM procedures (PDN Connectivity, Bearer activation)
 * - Subscriber identifiers (IMSI, IMEI, GUTI, TMSI)
 */
class NasSession {
public:
    NasSession();
    ~NasSession() = default;
    
    // Add message
    void addMessage(const NasMessage& msg);
    
    // Messages
    const std::vector<NasMessage>& getMessages() const { return messages_; }
    size_t getMessageCount() const { return messages_.size(); }
    
    // Session type
    NasSessionType getType() const { return type_; }
    
    // Subscriber identifiers
    std::optional<std::string> getImsi() const { return imsi_; }
    std::optional<std::string> getImei() const { return imei_; }
    std::optional<std::string> getImeisv() const { return imeisv_; }
    std::optional<Guti4G> getGuti() const { return guti_; }
    std::optional<uint32_t> getTmsi() const { return tmsi_; }
    
    // PDN information (from ESM)
    std::optional<std::string> getApn() const { return apn_; }
    std::optional<std::string> getPdnAddress() const { return pdn_address_; }
    std::optional<uint8_t> getEpsBearerId() const { return eps_bearer_id_; }
    std::optional<uint8_t> getLinkedBearerId() const { return linked_bearer_id_; }
    
    // QoS (from ESM)
    std::optional<uint8_t> getQci() const { return qci_; }
    
    // PDN Class (IMS detection)
    PdnClass getPdnClass() const { return pdn_class_; }
    bool isIms() const { return pdn_class_ == PdnClass::IMS; }
    
    // EMM state
    enum class EmmState {
        DEREGISTERED,
        REGISTERED_INITIATED,
        REGISTERED,
        DEREGISTERED_INITIATED,
        TAU_INITIATED,
        SERVICE_REQUEST_INITIATED
    };
    EmmState getEmmState() const { return emm_state_; }
    
    // Security state
    bool isSecurityActivated() const { return security_activated_; }
    
    // Time window
    double getStartTime() const { return start_time_; }
    double getEndTime() const { return end_time_; }
    uint32_t getStartFrame() const { return start_frame_; }
    uint32_t getEndFrame() const { return end_frame_; }
    
    // Correlation
    void setIntraCorrelator(const std::string& id) { intra_correlator_ = id; }
    std::string getIntraCorrelator() const { return intra_correlator_; }
    
    void setInterCorrelator(const std::string& id) { inter_correlator_ = id; }
    std::string getInterCorrelator() const { return inter_correlator_; }
    
    // Link to S1AP context
    void setS1apContext(uint32_t mme_ue_id, uint32_t enb_ue_id);
    std::optional<uint32_t> getMmeUeS1apId() const { return mme_ue_s1ap_id_; }
    std::optional<uint32_t> getEnbUeS1apId() const { return enb_ue_s1ap_id_; }
    
    // Finalize
    void finalize();

private:
    NasSessionType type_ = NasSessionType::UNKNOWN;
    EmmState emm_state_ = EmmState::DEREGISTERED;
    
    std::vector<NasMessage> messages_;
    
    // Subscriber identifiers
    std::optional<std::string> imsi_;
    std::optional<std::string> imei_;
    std::optional<std::string> imeisv_;
    std::optional<Guti4G> guti_;
    std::optional<uint32_t> tmsi_;
    
    // PDN info
    std::optional<std::string> apn_;
    std::optional<std::string> pdn_address_;
    std::optional<uint8_t> eps_bearer_id_;
    std::optional<uint8_t> linked_bearer_id_;
    std::optional<uint8_t> qci_;
    PdnClass pdn_class_ = PdnClass::OTHER;
    
    // Security
    bool security_activated_ = false;
    
    // S1AP context
    std::optional<uint32_t> mme_ue_s1ap_id_;
    std::optional<uint32_t> enb_ue_s1ap_id_;
    
    // Time window
    double start_time_ = 0.0;
    double end_time_ = 0.0;
    uint32_t start_frame_ = 0;
    uint32_t end_frame_ = 0;
    
    // Correlation
    std::string intra_correlator_;
    std::string inter_correlator_;
    
    // Internal methods
    void extractIdentifiers(const NasMessage& msg);
    void extractPdnInfo(const NasMessage& msg);
    void updateEmmState(const NasMessage& msg);
    void updateTimeWindow(const NasMessage& msg);
    void detectPdnClass();
};

} // namespace correlation
} // namespace callflow
```

### nas_correlator.h

```cpp
#pragma once

#include "correlation/nas/nas_session.h"
#include "correlation/identity/subscriber_context_manager.h"
#include <unordered_map>
#include <memory>
#include <mutex>

namespace callflow {
namespace correlation {

/**
 * @brief NAS intra-protocol correlator
 * 
 * Groups NAS messages into sessions by:
 * - IMSI (when available)
 * - GUTI/TMSI (for temporary identity)
 * - S1AP context (MME-UE-S1AP-ID + eNB-UE-S1AP-ID)
 */
class NasCorrelator {
public:
    NasCorrelator();
    explicit NasCorrelator(SubscriberContextManager* ctx_manager);
    ~NasCorrelator() = default;
    
    /**
     * @brief Add a parsed NAS message
     * @param msg NAS message
     * @param mme_ue_id MME-UE-S1AP-ID from S1AP (optional)
     * @param enb_ue_id eNB-UE-S1AP-ID from S1AP (optional)
     */
    void addMessage(const NasMessage& msg,
                    std::optional<uint32_t> mme_ue_id = std::nullopt,
                    std::optional<uint32_t> enb_ue_id = std::nullopt);
    
    /**
     * @brief Finalize all sessions
     */
    void finalize();
    
    /**
     * @brief Get all sessions
     */
    std::vector<NasSession*> getSessions();
    
    /**
     * @brief Get EMM sessions only
     */
    std::vector<NasSession*> getEmmSessions();
    
    /**
     * @brief Get ESM sessions only
     */
    std::vector<NasSession*> getEsmSessions();
    
    /**
     * @brief Get IMS ESM sessions (for VoLTE)
     */
    std::vector<NasSession*> getImsEsmSessions();
    
    /**
     * @brief Find session by IMSI
     */
    std::vector<NasSession*> findByImsi(const std::string& imsi);
    
    /**
     * @brief Find session by TMSI
     */
    NasSession* findByTmsi(uint32_t tmsi);
    
    /**
     * @brief Find session by S1AP context
     */
    NasSession* findByS1apContext(uint32_t mme_ue_id, uint32_t enb_ue_id);
    
    /**
     * @brief Get statistics
     */
    struct Stats {
        size_t total_messages = 0;
        size_t total_sessions = 0;
        size_t emm_sessions = 0;
        size_t esm_sessions = 0;
        size_t ims_esm_sessions = 0;
        size_t attach_procedures = 0;
        size_t tau_procedures = 0;
        size_t detach_procedures = 0;
    };
    Stats getStats() const;

private:
    std::mutex mutex_;
    std::vector<std::unique_ptr<NasSession>> sessions_;
    
    // Index by IMSI
    std::unordered_map<std::string, NasSession*> imsi_index_;
    // Index by TMSI
    std::unordered_map<uint32_t, NasSession*> tmsi_index_;
    // Index by S1AP context
    std::unordered_map<std::string, NasSession*> s1ap_context_index_;
    
    SubscriberContextManager* ctx_manager_ = nullptr;
    
    Stats stats_;
    
    NasSession* findOrCreateSession(const NasMessage& msg,
                                    std::optional<uint32_t> mme_ue_id,
                                    std::optional<uint32_t> enb_ue_id);
    std::string makeS1apContextKey(uint32_t mme_ue_id, uint32_t enb_ue_id);
    void updateSubscriberContext(const NasSession& session);
};

} // namespace correlation
} // namespace callflow
```

---

## Success Criteria

- [ ] Correctly parses EMM message types
- [ ] Correctly parses ESM message types
- [ ] Extracts IMSI, IMEI, GUTI from NAS IEs
- [ ] Links NAS sessions by IMSI/TMSI
- [ ] Links to S1AP context
- [ ] Tracks IMS bearer activations
- [ ] Unit test coverage > 85%
```

---

# Milestone 6: RTP Stream Correlator (1 week)

## PROMPT 6.1: RTP Stream Tracking and Quality Metrics

```markdown
# RTP Stream Correlator
## nDPI Callflow Visualizer - Media Stream Tracking

**Context:**
I'm building the nDPI Callflow Visualizer. This prompt implements RTP stream tracking and quality metrics calculation for VoLTE media correlation.

**Analysis Reference:**
RTP streams are correlated to VoLTE calls by:
- Matching UE IP address from SIP SDP with RTP endpoints
- Time-windowing within call duration
- Calculating jitter, packet loss, and other quality metrics

**3GPP/IETF References:**
- RFC 3550 (RTP)
- RFC 3551 (RTP Profile for Audio/Video)
- TS 26.114 (VoLTE Codec Requirements)

---

## Requirements

### 1. RTP Stream Identification

```cpp
struct RtpStreamKey {
    std::string src_ip;
    uint16_t src_port;
    std::string dst_ip;
    uint16_t dst_port;
    uint32_t ssrc;
    
    bool operator==(const RtpStreamKey& other) const;
    size_t hash() const;
};
```

### 2. Quality Metrics

```cpp
struct RtpQualityMetrics {
    // Packet statistics
    uint32_t packets_received = 0;
    uint32_t packets_lost = 0;
    uint32_t packets_out_of_order = 0;
    uint32_t packets_duplicated = 0;
    
    // Loss rate
    float packet_loss_rate = 0.0f;  // 0.0 - 1.0
    
    // Jitter (RFC 3550 interarrival jitter)
    double jitter_ms = 0.0;
    double max_jitter_ms = 0.0;
    
    // Delay (if RTCP available)
    std::optional<double> round_trip_time_ms;
    
    // MOS estimate (based on packet loss and jitter)
    std::optional<float> estimated_mos;  // 1.0 - 5.0
    
    // Codec info
    uint8_t payload_type = 0;
    std::string codec_name;
    uint32_t clock_rate = 0;
};
```

---

## Implementation

### rtp_stream.h

```cpp
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <chrono>

namespace callflow {
namespace correlation {

struct RtpPacketInfo {
    uint32_t frame_number;
    double timestamp;           // Epoch time
    
    std::string src_ip;
    uint16_t src_port;
    std::string dst_ip;
    uint16_t dst_port;
    
    // RTP header fields
    uint8_t version;
    bool padding;
    bool extension;
    uint8_t csrc_count;
    bool marker;
    uint8_t payload_type;
    uint16_t sequence_number;
    uint32_t rtp_timestamp;
    uint32_t ssrc;
    
    size_t payload_size;
};

class RtpStream {
public:
    RtpStream(const RtpPacketInfo& first_packet);
    ~RtpStream() = default;
    
    // Stream identification
    uint32_t getSsrc() const { return ssrc_; }
    std::string getSrcIp() const { return src_ip_; }
    uint16_t getSrcPort() const { return src_port_; }
    std::string getDstIp() const { return dst_ip_; }
    uint16_t getDstPort() const { return dst_port_; }
    
    // Add packet
    void addPacket(const RtpPacketInfo& packet);
    
    // Packet count
    size_t getPacketCount() const { return packets_.size(); }
    
    // Time window
    double getStartTime() const { return start_time_; }
    double getEndTime() const { return end_time_; }
    uint32_t getStartFrame() const { return start_frame_; }
    uint32_t getEndFrame() const { return end_frame_; }
    double getDurationMs() const { return (end_time_ - start_time_) * 1000.0; }
    
    // Codec info
    uint8_t getPayloadType() const { return payload_type_; }
    std::string getCodecName() const { return codec_name_; }
    
    // Quality metrics (call after all packets added)
    RtpQualityMetrics calculateMetrics() const;
    
    // Direction detection
    enum class Direction {
        UPLINK,      // UE to network
        DOWNLINK,    // Network to UE
        UNKNOWN
    };
    Direction getDirection() const { return direction_; }
    void setDirection(Direction dir) { direction_ = dir; }
    
    // UE association
    void setUeIp(const std::string& ip) { ue_ip_ = ip; }
    std::optional<std::string> getUeIp() const { return ue_ip_; }
    bool isUeEndpoint(const std::string& ip) const;
    
    // Correlation
    void setInterCorrelator(const std::string& id) { inter_correlator_ = id; }
    std::string getInterCorrelator() const { return inter_correlator_; }

private:
    uint32_t ssrc_;
    std::string src_ip_;
    uint16_t src_port_;
    std::string dst_ip_;
    uint16_t dst_port_;
    
    std::vector<RtpPacketInfo> packets_;
    
    double start_time_ = 0.0;
    double end_time_ = 0.0;
    uint32_t start_frame_ = 0;
    uint32_t end_frame_ = 0;
    
    uint8_t payload_type_ = 0;
    std::string codec_name_;
    
    Direction direction_ = Direction::UNKNOWN;
    std::optional<std::string> ue_ip_;
    
    std::string inter_correlator_;
    
    // Jitter calculation state
    mutable double last_arrival_time_ = 0.0;
    mutable uint32_t last_rtp_timestamp_ = 0;
    mutable double jitter_estimate_ = 0.0;
    
    void updateJitter(const RtpPacketInfo& packet);
    std::string detectCodecName(uint8_t pt) const;
};

} // namespace correlation
} // namespace callflow
```

### rtp_correlator.h

```cpp
#pragma once

#include "correlation/rtp/rtp_stream.h"
#include <unordered_map>
#include <vector>
#include <memory>
#include <mutex>

namespace callflow {
namespace correlation {

/**
 * @brief RTP stream correlator
 * 
 * Tracks RTP streams by SSRC and provides:
 * - Stream lookup by endpoint
 * - Quality metrics calculation
 * - Correlation to SIP sessions by UE IP
 */
class RtpCorrelator {
public:
    RtpCorrelator() = default;
    ~RtpCorrelator() = default;
    
    /**
     * @brief Add RTP packet
     */
    void addPacket(const RtpPacketInfo& packet);
    
    /**
     * @brief Get all streams
     */
    std::vector<RtpStream*> getStreams();
    
    /**
     * @brief Find streams by SSRC
     */
    RtpStream* findBySsrc(uint32_t ssrc);
    
    /**
     * @brief Find streams involving an IP address
     */
    std::vector<RtpStream*> findByIp(const std::string& ip);
    
    /**
     * @brief Find streams within time window
     */
    std::vector<RtpStream*> findByTimeWindow(double start, double end);
    
    /**
     * @brief Find streams matching UE IP from SIP SDP
     */
    std::vector<RtpStream*> findByUeIp(const std::string& ue_ip);
    
    /**
     * @brief Set UE IP for streams matching endpoint
     */
    void setUeIpForEndpoint(const std::string& endpoint_ip, 
                            const std::string& ue_ip);
    
    /**
     * @brief Get aggregate statistics
     */
    struct Stats {
        size_t total_packets = 0;
        size_t total_streams = 0;
        double avg_packet_loss = 0.0;
        double avg_jitter_ms = 0.0;
    };
    Stats getStats() const;

private:
    std::mutex mutex_;
    std::unordered_map<uint32_t, std::unique_ptr<RtpStream>> streams_;
    // Key: SSRC
    
    // Index by IP for fast lookup
    std::unordered_multimap<std::string, RtpStream*> ip_index_;
    
    Stats stats_;
    
    void updateIpIndex(RtpStream* stream);
};

} // namespace correlation
} // namespace callflow
```

---

## Success Criteria

- [ ] Correctly identifies streams by SSRC
- [ ] Calculates packet loss rate
- [ ] Calculates jitter per RFC 3550
- [ ] Detects codec from payload type
- [ ] Provides time-windowed lookup
- [ ] Links streams by UE IP
- [ ] Unit test coverage > 85%
```

---

# Milestone 7: VoLTE Inter-Protocol Correlator (2 weeks)

## PROMPT 7.1: Cross-Protocol Correlation Engine

```markdown
# VoLTE Inter-Protocol Correlator
## nDPI Callflow Visualizer - Cross-Protocol Call Flow Assembly

**Context:**
I'm building the nDPI Callflow Visualizer. This is the main VoLTE correlation engine that links protocol-specific sessions (SIP, Diameter, GTPv2, NAS, RTP) into complete call flows.

**Analysis Reference:**
Based on the Python correlator analysis:
- Phase 1: Link subscriber identities (IMSI ↔ MSISDN ↔ IMEI)
- Phase 2: Detect SIP voice/video calls
- Phase 3: Correlate other protocols within call time window
- Phase 4: Link residual sessions (no SIP parent)
- Phase 5: Resolve network elements (UEa, UEb, UEc)

**Key Matching Logic:**
- MSISDN matching with format normalization
- UE IP address matching
- Time-windowed correlation
- GTP TEID linking

---

## Requirements

### 1. VoLTE Flow Types

```cpp
enum class VolteFlowType {
    MO_VOICE_CALL,        // Mobile Originated voice
    MT_VOICE_CALL,        // Mobile Terminated voice
    MO_VIDEO_CALL,        // Mobile Originated video
    MT_VIDEO_CALL,        // Mobile Terminated video
    VOICE_CALL_FORWARDING, // Call with CFU/CFB/CFNR
    CONFERENCE_CALL,      // 3-way conference
    MO_SMS,               // Mobile Originated SMS
    MT_SMS,               // Mobile Terminated SMS
    IMS_REGISTRATION,     // IMS registration
    SUPPLEMENTARY_SERVICE, // USSD, etc.
    DATA_SESSION,         // Non-IMS data (when no SIP)
    UNKNOWN
};
```

### 2. Call Flow Structure

```cpp
struct VolteCallFlow {
    std::string flow_id;
    VolteFlowType type;
    
    // Call parties
    struct Party {
        std::string msisdn;
        std::optional<std::string> imsi;
        std::optional<std::string> imei;
        std::string ip_v4;
        std::string ip_v6_prefix;
        std::string role;  // "UEa", "UEb", "UEc"
    };
    Party caller;   // UEa
    Party callee;   // UEb
    std::optional<Party> forward_target;  // UEc
    
    // Time window
    double start_time;
    double end_time;
    uint32_t start_frame;
    uint32_t end_frame;
    
    // Protocol sessions
    std::vector<std::string> sip_sessions;
    std::vector<std::string> diameter_sessions;
    std::vector<std::string> gtpv2_sessions;
    std::vector<std::string> nas_sessions;
    std::vector<uint32_t> rtp_ssrcs;
    
    // All frames in this flow
    std::vector<uint32_t> frame_numbers;
    
    // Quality metrics
    struct Stats {
        uint32_t sip_messages;
        uint32_t diameter_messages;
        uint32_t gtp_messages;
        uint32_t nas_messages;
        uint32_t rtp_packets;
        
        std::optional<double> setup_time_ms;
        std::optional<double> ring_time_ms;
        std::optional<double> call_duration_ms;
        
        std::optional<double> rtp_jitter_ms;
        std::optional<float> rtp_packet_loss;
        std::optional<float> estimated_mos;
    } stats;
    
    // Network elements traversed
    std::vector<std::string> network_path;
};
```

---

## Implementation

### volte_correlator.h

```cpp
#pragma once

#include "correlation/volte/volte_types.h"
#include "correlation/sip/sip_correlator.h"
#include "correlation/diameter/diameter_correlator.h"
#include "correlation/gtpv2/gtpv2_correlator.h"
#include "correlation/nas/nas_correlator.h"
#include "correlation/rtp/rtp_correlator.h"
#include "correlation/identity/subscriber_context_manager.h"
#include <vector>
#include <memory>

namespace callflow {
namespace correlation {

/**
 * @brief VoLTE inter-protocol correlator
 * 
 * Links protocol-specific sessions into complete VoLTE call flows
 */
class VolteCorrelator {
public:
    VolteCorrelator();
    ~VolteCorrelator() = default;
    
    /**
     * @brief Set protocol correlators
     */
    void setSipCorrelator(SipCorrelator* correlator);
    void setDiameterCorrelator(DiameterCorrelator* correlator);
    void setGtpv2Correlator(Gtpv2Correlator* correlator);
    void setNasCorrelator(NasCorrelator* correlator);
    void setRtpCorrelator(RtpCorrelator* correlator);
    void setSubscriberContextManager(SubscriberContextManager* manager);
    
    /**
     * @brief Run correlation algorithm
     */
    void correlate();
    
    /**
     * @brief Get all call flows
     */
    std::vector<VolteCallFlow*> getCallFlows();
    
    /**
     * @brief Get call flows by type
     */
    std::vector<VolteCallFlow*> getCallFlowsByType(VolteFlowType type);
    
    /**
     * @brief Get voice calls only
     */
    std::vector<VolteCallFlow*> getVoiceCalls();
    
    /**
     * @brief Find call flow by ID
     */
    VolteCallFlow* findByFlowId(const std::string& flow_id);
    
    /**
     * @brief Find call flows by MSISDN
     */
    std::vector<VolteCallFlow*> findByMsisdn(const std::string& msisdn);
    
    /**
     * @brief Find call flows by IMSI
     */
    std::vector<VolteCallFlow*> findByImsi(const std::string& imsi);
    
    /**
     * @brief Find call flow containing frame
     */
    VolteCallFlow* findByFrame(uint32_t frame_number);
    
    /**
     * @brief Get correlation statistics
     */
    struct Stats {
        size_t total_call_flows = 0;
        size_t voice_calls = 0;
        size_t video_calls = 0;
        size_t sms_sessions = 0;
        size_t registrations = 0;
        size_t uncorrelated_sip_sessions = 0;
        size_t uncorrelated_diameter_sessions = 0;
        size_t uncorrelated_gtp_sessions = 0;
    };
    Stats getStats() const;

private:
    SipCorrelator* sip_correlator_ = nullptr;
    DiameterCorrelator* diameter_correlator_ = nullptr;
    Gtpv2Correlator* gtpv2_correlator_ = nullptr;
    NasCorrelator* nas_correlator_ = nullptr;
    RtpCorrelator* rtp_correlator_ = nullptr;
    SubscriberContextManager* subscriber_manager_ = nullptr;
    
    std::vector<std::unique_ptr<VolteCallFlow>> call_flows_;
    Stats stats_;
    
    // Correlation phases
    void phase1_LinkSubscriberIdentities();
    void phase2_DetectSipCalls();
    void phase3_CorrelateWithinCallWindow();
    void phase4_LinkResidualSessions();
    void phase5_ResolveNetworkElements();
    void phase6_CalculateStatistics();
    
    // Phase 3 helpers
    void correlateDialogToCallFlow(VolteCallFlow& flow);
    void correlateDiameterGx(VolteCallFlow& flow);
    void correlateDiameterRx(VolteCallFlow& flow);
    void correlateDiameterCxSh(VolteCallFlow& flow);
    void correlateGtpv2ImsBearer(VolteCallFlow& flow);
    void correlateNasEsm(VolteCallFlow& flow);
    void correlateRtp(VolteCallFlow& flow);
    
    // Matching helpers
    bool matchesMsisdn(const std::string& m1, const std::string& m2);
    bool matchesUeIp(const std::string& ip1, const std::string& ip2);
    bool isWithinTimeWindow(double ts, double start, double end, 
                            double tolerance_ms = 1000.0);
    
    // Flow ID generation
    std::string generateFlowId(const SipSession& sip_session);
};

} // namespace correlation
} // namespace callflow
```

### volte_correlator.cpp (Key Methods)

```cpp
void VolteCorrelator::correlate() {
    if (!sip_correlator_) {
        return;
    }
    
    // Phase 1: Link subscriber identities across protocols
    phase1_LinkSubscriberIdentities();
    
    // Phase 2: Detect SIP voice/video calls and create initial flows
    phase2_DetectSipCalls();
    
    // Phase 3: Correlate other protocols within each call's time window
    phase3_CorrelateWithinCallWindow();
    
    // Phase 4: Link residual Diameter/GTP sessions without SIP parent
    phase4_LinkResidualSessions();
    
    // Phase 5: Resolve network elements (UEa, UEb, UEc, IMS nodes)
    phase5_ResolveNetworkElements();
    
    // Phase 6: Calculate statistics for each flow
    phase6_CalculateStatistics();
}

void VolteCorrelator::phase2_DetectSipCalls() {
    auto sip_calls = sip_correlator_->getCallSessions();
    
    for (auto* sip_session : sip_calls) {
        auto flow = std::make_unique<VolteCallFlow>();
        
        flow->flow_id = generateFlowId(*sip_session);
        
        // Determine flow type
        if (sip_session->hasVideo()) {
            flow->type = VolteFlowType::MO_VIDEO_CALL;  // Refine later
        } else {
            flow->type = VolteFlowType::MO_VOICE_CALL;  // Refine later
        }
        
        // Set call parties
        flow->caller.msisdn = sip_session->getCallerMsisdn();
        flow->caller.ip_v4 = sip_session->getCallerIp();
        flow->caller.role = "UEa";
        
        flow->callee.msisdn = sip_session->getCalleeMsisdn();
        flow->callee.ip_v4 = sip_session->getCalleeIp();
        flow->callee.role = "UEb";
        
        // Check for call forwarding
        if (auto fwd = sip_session->getForwardTargetMsisdn()) {
            flow->forward_target = VolteCallFlow::Party{};
            flow->forward_target->msisdn = *fwd;
            flow->forward_target->role = "UEc";
            flow->type = VolteFlowType::VOICE_CALL_FORWARDING;
        }
        
        // Set time window
        flow->start_time = sip_session->getStartTime();
        flow->end_time = sip_session->getEndTime();
        flow->start_frame = sip_session->getStartFrame();
        flow->end_frame = sip_session->getEndFrame();
        
        // Add SIP session reference
        flow->sip_sessions.push_back(sip_session->getIntraCorrelator());
        
        // Resolve IMSI from subscriber context
        if (subscriber_manager_) {
            auto ctx = subscriber_manager_->findByMsisdn(flow->caller.msisdn);
            if (ctx && ctx->imsi) {
                flow->caller.imsi = ctx->imsi->digits;
            }
            
            ctx = subscriber_manager_->findByMsisdn(flow->callee.msisdn);
            if (ctx && ctx->imsi) {
                flow->callee.imsi = ctx->imsi->digits;
            }
        }
        
        call_flows_.push_back(std::move(flow));
        stats_.total_call_flows++;
        stats_.voice_calls++;
    }
}

void VolteCorrelator::phase3_CorrelateWithinCallWindow() {
    for (auto& flow : call_flows_) {
        correlateDiameterGx(*flow);
        correlateDiameterRx(*flow);
        correlateDiameterCxSh(*flow);
        correlateGtpv2ImsBearer(*flow);
        correlateNasEsm(*flow);
        correlateRtp(*flow);
    }
}

void VolteCorrelator::correlateDiameterGx(VolteCallFlow& flow) {
    if (!diameter_correlator_) return;
    
    auto gx_sessions = diameter_correlator_->getGxSessions();
    
    for (auto* gx : gx_sessions) {
        // Check time window
        if (!isWithinTimeWindow(gx->getStartTime(), 
                                flow.start_time, flow.end_time)) {
            continue;
        }
        
        // Match by UE IP address
        auto framed_ip = gx->getFramedIpAddress();
        if (!framed_ip) continue;
        
        if (matchesUeIp(*framed_ip, flow.caller.ip_v4) ||
            matchesUeIp(*framed_ip, flow.callee.ip_v4)) {
            flow.diameter_sessions.push_back(gx->getSessionId());
            flow.stats.diameter_messages += gx->getMessageCount();
            
            // Mark as correlated
            gx->setInterCorrelator(flow.flow_id);
        }
    }
}

void VolteCorrelator::correlateGtpv2ImsBearer(VolteCallFlow& flow) {
    if (!gtpv2_correlator_) return;
    
    auto ims_sessions = gtpv2_correlator_->getSessionsWithDedicatedBearers();
    
    for (auto* gtp : ims_sessions) {
        if (!gtp->isIms()) continue;
        
        // Check time window
        if (!isWithinTimeWindow(gtp->getStartTime(), 
                                flow.start_time, flow.end_time)) {
            continue;
        }
        
        // Match by MSISDN
        if (auto msisdn = gtp->getMsisdn()) {
            if (matchesMsisdn(*msisdn, flow.caller.msisdn) ||
                matchesMsisdn(*msisdn, flow.callee.msisdn)) {
                flow.gtpv2_sessions.push_back(gtp->getIntraCorrelator());
                flow.stats.gtp_messages += gtp->getMessageCount();
                
                // Copy IMSI if not already set
                if (!flow.caller.imsi && gtp->getImsi()) {
                    if (matchesMsisdn(*msisdn, flow.caller.msisdn)) {
                        flow.caller.imsi = gtp->getImsi();
                    }
                }
                
                gtp->setInterCorrelator(flow.flow_id);
            }
        }
    }
}

bool VolteCorrelator::matchesMsisdn(const std::string& m1, 
                                     const std::string& m2) {
    if (m1.empty() || m2.empty()) return false;
    
    auto n1 = MsisdnNormalizer::normalize(m1);
    auto n2 = MsisdnNormalizer::normalize(m2);
    
    return MsisdnNormalizer::matches(n1, n2);
}

bool VolteCorrelator::matchesUeIp(const std::string& ip1, 
                                   const std::string& ip2) {
    if (ip1.empty() || ip2.empty()) return false;
    
    // Exact match
    if (ip1 == ip2) return true;
    
    // IPv6 prefix match (first 64 bits)
    if (ip1.find(':') != std::string::npos && 
        ip2.find(':') != std::string::npos) {
        // TODO: Implement proper IPv6 prefix matching
    }
    
    return false;
}
```

---

## Success Criteria

- [ ] Correctly links SIP calls to Diameter Gx/Rx
- [ ] Correctly links SIP calls to GTPv2 IMS bearers
- [ ] Correctly links SIP calls to NAS ESM sessions
- [ ] Correctly links SIP calls to RTP streams
- [ ] Handles call forwarding (UEc detection)
- [ ] Calculates call setup time and duration
- [ ] Aggregates quality metrics from RTP
- [ ] Unit test coverage > 85%
```

---

# Milestone 8: Testing, API & Optimization (1 week)

## PROMPT 8.1: Integration Testing and REST API Extensions

```markdown
# Integration Testing and API Extensions
## nDPI Callflow Visualizer - Final Integration

**Context:**
Final milestone for VoLTE correlation implementation. Includes integration tests, REST API extensions, and performance optimization.

---

## Requirements

### 1. Integration Test Cases

```cpp
// Test scenarios with sample PCAPs
struct TestScenario {
    std::string pcap_file;
    std::string description;
    ExpectedResults expected;
};

std::vector<TestScenario> VOLTE_TEST_SCENARIOS = {
    {
        "volte_mo_call_complete.pcap",
        "Mobile Originated voice call with all protocols",
        {
            .total_call_flows = 1,
            .sip_sessions = 1,
            .diameter_gx_sessions = 1,
            .diameter_rx_sessions = 1,
            .gtpv2_ims_sessions = 1,
            .nas_esm_sessions = 1,
            .rtp_streams = 2  // UL + DL
        }
    },
    {
        "volte_mt_call.pcap",
        "Mobile Terminated voice call",
        {
            .total_call_flows = 1,
            .flow_type = VolteFlowType::MT_VOICE_CALL
        }
    },
    {
        "volte_call_forwarding.pcap",
        "Call with call forwarding (CFU)",
        {
            .total_call_flows = 1,
            .has_forward_target = true,
            .flow_type = VolteFlowType::VOICE_CALL_FORWARDING
        }
    },
    {
        "volte_sms.pcap",
        "SMS over IMS",
        {
            .total_call_flows = 1,
            .flow_type = VolteFlowType::MO_SMS
        }
    }
};
```

### 2. REST API Extensions

```cpp
// New endpoints for VoLTE

// GET /api/v1/jobs/{job_id}/volte/calls
// Returns all VoLTE call flows

// GET /api/v1/jobs/{job_id}/volte/calls/{flow_id}
// Returns specific call flow with all protocol sessions

// GET /api/v1/jobs/{job_id}/volte/calls?msisdn={msisdn}
// Search by MSISDN

// GET /api/v1/jobs/{job_id}/volte/calls?imsi={imsi}
// Search by IMSI

// GET /api/v1/jobs/{job_id}/volte/calls/{flow_id}/timeline
// Get chronological timeline of all events

// GET /api/v1/jobs/{job_id}/volte/calls/{flow_id}/stats
// Get quality statistics

// GET /api/v1/jobs/{job_id}/volte/summary
// Get overall VoLTE statistics
```

### 3. JSON Response Schema

```json
{
  "flow_id": "1702396800.123_S_1_call1",
  "type": "MO_VOICE_CALL",
  "parties": {
    "caller": {
      "msisdn": "+14155551234",
      "imsi": "310260123456789",
      "imei": "35123456789012",
      "ip_v4": "10.100.1.50",
      "role": "UEa"
    },
    "callee": {
      "msisdn": "+14155555678",
      "imsi": "310260987654321",
      "ip_v4": "10.100.2.75",
      "role": "UEb"
    }
  },
  "time_window": {
    "start_time": "2023-12-12T15:30:00.123Z",
    "end_time": "2023-12-12T15:35:42.567Z",
    "start_frame": 1234,
    "end_frame": 5678
  },
  "protocol_sessions": {
    "sip": ["1702396800.123_S_1"],
    "diameter": {
      "gx": ["gx_session_1"],
      "rx": ["rx_session_1"]
    },
    "gtpv2": ["1702396800.123_G_1"],
    "nas": ["nas_session_1"],
    "rtp_ssrcs": [3456789012, 2109876543]
  },
  "statistics": {
    "message_counts": {
      "sip": 24,
      "diameter": 12,
      "gtp": 8,
      "nas": 4,
      "rtp": 15420
    },
    "timing": {
      "setup_time_ms": 320,
      "ring_time_ms": 4500,
      "call_duration_ms": 342444
    },
    "quality": {
      "rtp_jitter_ms": 12.5,
      "rtp_packet_loss_percent": 0.1,
      "estimated_mos": 4.2
    }
  }
}
```

---

## Success Criteria

- [ ] All integration tests passing
- [ ] REST API endpoints implemented
- [ ] JSON schema validated
- [ ] Performance: < 100ms per 1000 packets
- [ ] Memory: < 500 bytes per correlated message
- [ ] Documentation complete
```

---

# Summary

## Complete Milestone Overview

| Milestone | Duration | Key Deliverables |
|-----------|----------|------------------|
| M1: Subscriber Identity | 2 weeks | MSISDN/IMSI/IMEI normalizers, Context Manager |
| M2: SIP Correlator | 2 weeks | Call detection, Dialog tracking, Party extraction |
| M3: Diameter Correlator | 2 weeks | Session tracking, Interface detection, AVP parsing |
| M4: GTPv2 Correlator | 2 weeks | Bearer tracking, F-TEID management, PDN class |
| M5: NAS/S1AP Correlator | 2 weeks | EMM/ESM parsing, Identity extraction |
| M6: RTP Correlator | 1 week | Stream tracking, Quality metrics |
| M7: VoLTE Correlator | 2 weeks | Cross-protocol linking, Flow assembly |
| M8: Testing & API | 1 week | Integration tests, REST API, Documentation |

**Total: 14 weeks**

## Prompt Usage Instructions

1. Copy each prompt section (between the triple backticks)
2. Paste into Claude Code session
3. Review generated code and tests
4. Iterate as needed
5. Move to next milestone

Each prompt is self-contained with:
- Context and requirements
- File structure
- Header files with full implementations
- Key implementation examples
- Testing requirements
- Success criteria
