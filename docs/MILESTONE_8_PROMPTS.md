# MILESTONE 8: DIAMETER & SCTP PROTOCOLS
## Claude Code Development Prompts

---

## PROMPT 6: SCTP Transport Layer Parser

```
I'm working on the nDPI Callflow Visualizer project. This is Milestone 8, Phase 1: SCTP Protocol Support.

CONTEXT:
- SCTP (Stream Control Transmission Protocol) is the transport for S1AP, X2AP, NGAP, Diameter
- Provides multi-streaming, avoiding head-of-line blocking
- SCTP ports: 36412 (S1AP), 38412 (NGAP), 3868 (Diameter)
- Need to reassemble SCTP chunks into complete application messages

REQUIREMENTS:

1. Implement SCTP packet parser:

```cpp
struct SctpCommonHeader {
    uint16_t source_port;
    uint16_t dest_port;
    uint32_t verification_tag;
    uint32_t checksum;  // CRC32c
};

enum class SctpChunkType : uint8_t {
    DATA = 0,
    INIT = 1,
    INIT_ACK = 2,
    SACK = 3,               // Selective Acknowledgment
    HEARTBEAT = 4,
    HEARTBEAT_ACK = 5,
    ABORT = 6,
    SHUTDOWN = 7,
    SHUTDOWN_ACK = 8,
    ERROR = 9,
    COOKIE_ECHO = 10,
    COOKIE_ACK = 11,
    SHUTDOWN_COMPLETE = 14,
    // Extensions
    ASCONF = 0xC1,          // Address Configuration
    ASCONF_ACK = 0x80,
    FORWARD_TSN = 0xC0,     // Forward TSN
    PKTDROP = 0x81,
    RE_CONFIG = 0x82        // Stream Reconfiguration
};

struct SctpChunkHeader {
    uint8_t type;
    uint8_t flags;
    uint16_t length;
};

struct SctpDataChunk {
    SctpChunkHeader header;
    uint32_t tsn;           // Transmission Sequence Number
    uint16_t stream_id;
    uint16_t stream_seq;    // Stream Sequence Number
    uint32_t payload_protocol_id;  // PPID (18 for S1AP, etc.)
    std::vector<uint8_t> user_data;
    
    // Flags
    bool unordered;         // U bit
    bool beginning;         // B bit
    bool ending;            // E bit
};

struct SctpInitChunk {
    SctpChunkHeader header;
    uint32_t initiate_tag;
    uint32_t a_rwnd;        // Advertised Receiver Window Credit
    uint16_t num_outbound_streams;
    uint16_t num_inbound_streams;
    uint32_t initial_tsn;
    std::vector<SctpParameter> parameters;
};
```

2. Implement SCTP association tracking:

```cpp
class SctpAssociationManager {
public:
    struct Association {
        std::string assoc_id;   // UUID
        
        // Endpoints
        struct Endpoint {
            std::string ip;
            uint16_t port;
            std::vector<std::string> additional_ips;  // Multi-homing
        };
        Endpoint local;
        Endpoint remote;
        
        uint32_t local_vtag;
        uint32_t remote_vtag;
        
        // Stream management
        uint16_t num_outbound_streams;
        uint16_t num_inbound_streams;
        
        // State
        enum class State {
            CLOSED,
            COOKIE_WAIT,
            COOKIE_ECHOED,
            ESTABLISHED,
            SHUTDOWN_PENDING,
            SHUTDOWN_SENT,
            SHUTDOWN_RECEIVED,
            SHUTDOWN_ACK_SENT
        };
        State state;
        
        // Per-stream reassembly buffers
        std::map<uint16_t, StreamReassembler> streams;
        
        // Metrics
        std::chrono::system_clock::time_point start_time;
        std::optional<std::chrono::system_clock::time_point> end_time;
        uint64_t packets_sent;
        uint64_t packets_received;
        uint64_t bytes_sent;
        uint64_t bytes_received;
    };
    
    void processSctpPacket(const SctpPacket& packet);
    std::optional<Association> findAssociation(const std::string& assoc_id);
    std::vector<Association> getActiveAssociations();
    
private:
    void handleInit(const SctpInitChunk& chunk, const SctpCommonHeader& header);
    void handleInitAck(const SctpInitAckChunk& chunk);
    void handleDataChunk(const SctpDataChunk& chunk, Association& assoc);
    void handleShutdown(const SctpShutdownChunk& chunk);
    
    std::string getAssociationKey(const SctpCommonHeader& header);
    
    std::unordered_map<std::string, Association> associations_;
    std::mutex mutex_;
};
```

3. Implement stream reassembly:

```cpp
class StreamReassembler {
public:
    void addChunk(const SctpDataChunk& chunk);
    std::optional<std::vector<uint8_t>> tryAssemble();
    bool isComplete() const;
    void reset();
    
private:
    struct Fragment {
        uint16_t stream_seq;
        bool beginning;
        bool ending;
        std::vector<uint8_t> data;
    };
    
    std::map<uint16_t, Fragment> fragments_;  // Ordered by stream_seq
    uint16_t next_expected_seq_;
    bool reassembly_in_progress_;
};
```

4. Handle SCTP Payload Protocol IDs (PPID):

```cpp
enum class SctpPayloadProtocolId : uint32_t {
    RESERVED = 0,
    IUA = 1,                // ISDN Q.921 User Adaptation
    M2UA = 2,               // SS7 MTP2 User Adaptation
    M3UA = 3,               // SS7 MTP3 User Adaptation
    SUA = 4,                // SS7 SCCP User Adaptation
    M2PA = 5,               // SS7 MTP2 Peer Adaptation
    V5UA = 6,               // V5.2 User Adaptation
    H248 = 7,               // H.248
    BICC = 8,               // BICC/Q.1902
    TALI = 9,               // TALI
    DUA = 10,               // DPNSS/DASS2 User Adaptation
    ASAP = 11,              // ASAP
    ENRP = 12,              // ENRP
    H323 = 13,              // H.323
    QIPC = 14,              // QIPC
    SIMCO = 15,             // SIMCO
    DDP_SEG = 16,           // DDP Segment
    DDP_STREAM = 17,        // DDP Stream
    S1AP = 18,              // S1 Application Protocol
    RUA = 19,               // RANAP User Adaptation
    HNBAP = 20,             // HNB Application Part
    FORCES_HP = 21,         // ForCES-HP
    FORCES_MP = 22,         // ForCES-MP
    FORCES_LP = 23,         // ForCES-LP
    SBC_AP = 24,            // SBc-AP
    DIAMETER = 46,          // Diameter (sometimes used)
    NGAP = 60,              // NG Application Protocol (5G)
    
    // Vendor-specific range: 0x00000080 - 0xFFFFFFFF
};
```

5. Multi-homing support:
   - Track multiple IP addresses per endpoint
   - Handle ASCONF chunks for address changes
   - Correlate packets from different IPs to same association

6. Error handling:
   - Invalid checksum detection
   - Out-of-order chunk handling
   - Missing chunks detection
   - Association timeout

FILE STRUCTURE:
```
include/protocol_parsers/sctp/
  sctp_parser.h
  sctp_types.h
  sctp_association.h
  sctp_reassembly.h

src/protocol_parsers/sctp/
  sctp_parser.cpp
  sctp_association_manager.cpp
  sctp_stream_reassembly.cpp
  sctp_checksum.cpp

tests/unit/
  test_sctp_parser.cpp
  test_sctp_association.cpp
  test_sctp_reassembly.cpp

tests/pcaps/
  sctp_init.pcap
  sctp_data_multistream.pcap
  sctp_multihoming.pcap
```

DEPENDENCIES:
- libsctp (for checksum validation)
- Implement CRC32c for checksum verification

TESTING:
- Unit tests for chunk parsing
- Test association establishment (INIT, INIT-ACK, COOKIE-ECHO, COOKIE-ACK)
- Test stream reassembly with fragmented messages
- Validate multi-stream handling
- Test association shutdown
- Verify PPID detection

ACCEPTANCE CRITERIA:
- Parse all common SCTP chunk types
- Track association state machine correctly
- Reassemble fragmented messages across streams
- Handle multi-homing
- Validate checksums
- Support 100+ concurrent associations
- Deliver reassembled payload to upper layer (S1AP/NGAP/Diameter)
- Achieve 85%+ code coverage

Please implement with comprehensive error handling, detailed logging of association state transitions, and extensive unit tests.
```

---

## PROMPT 7: Diameter Base Protocol Parser

```
I'm working on the nDPI Callflow Visualizer project. This is Milestone 8, Phase 2: Diameter Base Protocol.

CONTEXT:
- Diameter (RFC 6733) replaces RADIUS for AAA in 3GPP networks
- Used on S6a, Gx, Rx, Gy, Ro, Cx, Sh interfaces
- Runs on TCP/SCTP port 3868 (or 5868 for TLS)
- Binary protocol with AVP (Attribute-Value Pair) encoding

REQUIREMENTS:

1. Implement Diameter message parser:

```cpp
struct DiameterHeader {
    uint8_t version;           // Must be 1
    uint32_t length : 24;      // Message length
    uint8_t flags;             // R P E T bits
    uint32_t command_code : 24;
    uint32_t application_id;
    uint32_t hop_by_hop_id;
    uint32_t end_to_end_id;
    
    // Flags
    bool request;              // R bit
    bool proxyable;            // P bit
    bool error;                // E bit
    bool potentially_retransmitted; // T bit
};

struct DiameterAVP {
    uint32_t code;
    uint8_t flags;             // V M P bits
    uint32_t length : 24;
    std::optional<uint32_t> vendor_id;  // If V flag set
    std::vector<uint8_t> data;
    
    // Flags
    bool vendor_specific;      // V bit
    bool mandatory;            // M bit
    bool protected_;           // P bit (renamed to avoid keyword)
    
    // Decoded value
    std::variant<
        std::monostate,
        int32_t,               // INTEGER32
        int64_t,               // INTEGER64
        uint32_t,              // UNSIGNED32
        uint64_t,              // UNSIGNED64
        float,                 // FLOAT32
        double,                // FLOAT64
        std::string,           // UTF8String, DiameterIdentity
        std::vector<uint8_t>,  // OctetString
        std::vector<DiameterAVP>  // Grouped AVP
    > decoded_value;
};

struct DiameterMessage {
    DiameterHeader header;
    std::vector<DiameterAVP> avps;
    
    // Commonly used AVPs (extracted for convenience)
    std::optional<std::string> session_id;
    std::optional<std::string> origin_host;
    std::optional<std::string> origin_realm;
    std::optional<std::string> destination_host;
    std::optional<std::string> destination_realm;
    std::optional<uint32_t> result_code;
    std::optional<uint32_t> auth_application_id;
    std::optional<uint32_t> acct_application_id;
};
```

2. Support base protocol command codes (RFC 6733):

```cpp
enum class DiameterCommandCode : uint32_t {
    // Base Protocol
    CAPABILITIES_EXCHANGE = 257,   // CER/CEA
    RE_AUTH = 258,                 // RAR/RAA
    ACCOUNTING = 271,              // ACR/ACA
    CREDIT_CONTROL = 272,          // CCR/CCA (RFC 4006)
    ABORT_SESSION = 274,           // ASR/ASA
    SESSION_TERMINATION = 275,     // STR/STA
    DEVICE_WATCHDOG = 280,         // DWR/DWA
    DISCONNECT_PEER = 282,         // DPR/DPA
    
    // 3GPP-specific (will be extended in application parsers)
    USER_AUTHORIZATION = 300,      // Cx: UAR/UAA
    SERVER_ASSIGNMENT = 301,       // Cx: SAR/SAA
    LOCATION_INFO = 302,           // Cx: LIR/LIA
    MULTIMEDIA_AUTH = 303,         // Cx: MAR/MAA
    REGISTRATION_TERMINATION = 304,// Cx: RTR/RTA
    PUSH_PROFILE = 305,            // Cx: PPR/PPA
    USER_DATA = 306,               // Sh: UDR/UDA
    PROFILE_UPDATE = 307,          // Sh: PUR/PUA
    SUBSCRIBE_NOTIFICATIONS = 308, // Sh: SNR/SNA
    PUSH_NOTIFICATION = 309,       // Sh: PNR/PNA
    
    UPDATE_LOCATION = 316,         // S6a: ULR/ULA
    CANCEL_LOCATION = 317,         // S6a: CLR/CLA
    AUTHENTICATION_INFORMATION = 318, // S6a: AIR/AIA
    INSERT_SUBSCRIBER_DATA = 319,  // S6a: IDR/IDA
    DELETE_SUBSCRIBER_DATA = 320,  // S6a: DSR/DSA
    PURGE_UE = 321,                // S6a: PUR/PUA
    RESET = 322,                   // S6a: RSR/RSA
    NOTIFY = 323                   // S6a: NOR/NOA
};
```

3. Implement AVP parser with data type support:

```cpp
class DiameterAVPParser {
public:
    static DiameterAVP parse(const uint8_t* data, size_t length);
    static std::variant<...> decodeAVPData(const DiameterAVP& avp, AVPDataType type);
    
    // Data type parsers
    static int32_t parseInt32(const std::vector<uint8_t>& data);
    static int64_t parseInt64(const std::vector<uint8_t>& data);
    static uint32_t parseUnsigned32(const std::vector<uint8_t>& data);
    static uint64_t parseUnsigned64(const std::vector<uint8_t>& data);
    static std::string parseUTF8String(const std::vector<uint8_t>& data);
    static std::string parseDiameterIdentity(const std::vector<uint8_t>& data);
    static std::string parseDiameterURI(const std::vector<uint8_t>& data);
    static std::vector<DiameterAVP> parseGrouped(const std::vector<uint8_t>& data);
    static std::array<uint8_t, 4> parseIPv4Address(const std::vector<uint8_t>& data);
    static std::array<uint8_t, 16> parseIPv6Address(const std::vector<uint8_t>& data);
    static std::chrono::system_clock::time_point parseTime(const std::vector<uint8_t>& data);
};
```

4. Define base protocol AVPs:

```cpp
enum class DiameterAVPCode : uint32_t {
    // Base Protocol (RFC 6733)
    USER_NAME = 1,
    CLASS = 25,
    SESSION_TIMEOUT = 27,
    PROXY_STATE = 33,
    ACCOUNTING_SESSION_ID = 44,
    ACCT_MULTI_SESSION_ID = 50,
    EVENT_TIMESTAMP = 55,
    ACCT_INTERIM_INTERVAL = 85,
    HOST_IP_ADDRESS = 257,
    AUTH_APPLICATION_ID = 258,
    ACCT_APPLICATION_ID = 259,
    VENDOR_SPECIFIC_APPLICATION_ID = 260,
    REDIRECT_HOST_USAGE = 261,
    REDIRECT_MAX_CACHE_TIME = 262,
    SESSION_ID = 263,
    ORIGIN_HOST = 264,
    SUPPORTED_VENDOR_ID = 265,
    VENDOR_ID = 266,
    FIRMWARE_REVISION = 267,
    RESULT_CODE = 268,
    PRODUCT_NAME = 269,
    SESSION_BINDING = 270,
    SESSION_SERVER_FAILOVER = 271,
    MULTI_ROUND_TIME_OUT = 272,
    DISCONNECT_CAUSE = 273,
    AUTH_REQUEST_TYPE = 274,
    AUTH_GRACE_PERIOD = 276,
    AUTH_SESSION_STATE = 277,
    ORIGIN_STATE_ID = 278,
    FAILED_AVP = 279,
    PROXY_HOST = 280,
    ERROR_MESSAGE = 281,
    ROUTE_RECORD = 282,
    DESTINATION_REALM = 283,
    PROXY_INFO = 284,
    RE_AUTH_REQUEST_TYPE = 285,
    DESTINATION_HOST = 293,
    ERROR_REPORTING_HOST = 294,
    TERMINATION_CAUSE = 295,
    ORIGIN_REALM = 296,
    EXPERIMENTAL_RESULT = 297,
    EXPERIMENTAL_RESULT_CODE = 298,
    INBAND_SECURITY_ID = 299,
    
    // Credit Control (RFC 4006)
    CC_REQUEST_TYPE = 416,
    CC_REQUEST_NUMBER = 415,
    CC_SESSION_FAILOVER = 418,
    
    // 3GPP Vendor ID: 10415
    // (Application-specific AVPs defined in application parsers)
};
```

5. Implement Diameter session tracking:

```cpp
class DiameterSessionManager {
public:
    struct DiameterSession {
        std::string session_id;
        std::string origin_host;
        std::string origin_realm;
        InterfaceType interface;  // S6a, Gx, Rx, etc.
        uint32_t application_id;
        
        // Message pairs
        struct MessagePair {
            DiameterMessage request;
            std::optional<DiameterMessage> answer;
            std::chrono::milliseconds latency;
        };
        std::vector<MessagePair> messages;
        
        std::chrono::system_clock::time_point start_time;
        std::optional<std::chrono::system_clock::time_point> end_time;
        
        // For subscriber sessions
        std::optional<std::string> imsi;
        std::optional<std::string> msisdn;
    };
    
    void processMessage(const DiameterMessage& msg);
    std::optional<DiameterSession> findSession(const std::string& session_id);
    void correlateRequestResponse(const DiameterMessage& request, 
                                   const DiameterMessage& answer);
                                   
private:
    std::unordered_map<std::string, DiameterSession> sessions_;
    std::unordered_map<uint32_t, std::string> hop_to_session_;  // For correlation
    std::mutex mutex_;
};
```

6. Result code handling:

```cpp
enum class DiameterResultCode : uint32_t {
    // Success
    DIAMETER_SUCCESS = 2001,
    DIAMETER_LIMITED_SUCCESS = 2002,
    
    // Protocol Errors (3xxx)
    DIAMETER_COMMAND_UNSUPPORTED = 3001,
    DIAMETER_UNABLE_TO_DELIVER = 3002,
    DIAMETER_REALM_NOT_SERVED = 3003,
    DIAMETER_TOO_BUSY = 3004,
    DIAMETER_LOOP_DETECTED = 3005,
    DIAMETER_REDIRECT_INDICATION = 3006,
    DIAMETER_APPLICATION_UNSUPPORTED = 3007,
    DIAMETER_INVALID_HDR_BITS = 3008,
    DIAMETER_INVALID_AVP_BITS = 3009,
    DIAMETER_UNKNOWN_PEER = 3010,
    
    // Transient Failures (4xxx)
    DIAMETER_AUTHENTICATION_REJECTED = 4001,
    DIAMETER_OUT_OF_SPACE = 4002,
    DIAMETER_ELECTION_LOST = 4003,
    
    // Permanent Failures (5xxx)
    DIAMETER_AVP_UNSUPPORTED = 5001,
    DIAMETER_UNKNOWN_SESSION_ID = 5002,
    DIAMETER_AUTHORIZATION_REJECTED = 5003,
    DIAMETER_INVALID_AVP_VALUE = 5004,
    DIAMETER_MISSING_AVP = 5005,
    DIAMETER_RESOURCES_EXCEEDED = 5006,
    DIAMETER_CONTRADICTING_AVPS = 5007,
    DIAMETER_AVP_NOT_ALLOWED = 5008,
    DIAMETER_AVP_OCCURS_TOO_MANY_TIMES = 5009,
    DIAMETER_NO_COMMON_APPLICATION = 5010,
    DIAMETER_UNSUPPORTED_VERSION = 5011,
    DIAMETER_UNABLE_TO_COMPLY = 5012,
    DIAMETER_INVALID_BIT_IN_HEADER = 5013,
    DIAMETER_INVALID_AVP_LENGTH = 5014,
    DIAMETER_INVALID_MESSAGE_LENGTH = 5015,
    DIAMETER_INVALID_AVP_BIT_COMBO = 5016,
    DIAMETER_NO_COMMON_SECURITY = 5017
};
```

FILE STRUCTURE:
```
include/protocol_parsers/diameter/
  diameter_base.h
  diameter_types.h
  diameter_avp_parser.h
  diameter_session.h

src/protocol_parsers/diameter/
  diameter_parser.cpp
  diameter_avp_parser.cpp
  diameter_session_manager.cpp
  diameter_result_codes.cpp

tests/unit/
  test_diameter_parser.cpp
  test_diameter_avp_parsing.cpp
  test_diameter_session.cpp

tests/pcaps/
  diameter_cer_cea.pcap
  diameter_dwr_dwa.pcap
```

TESTING:
- Unit tests for header parsing
- Test AVP parsing for all data types
- Validate grouped AVP parsing (recursive)
- Test session correlation
- Verify request-answer pairing
- Test result code extraction

ACCEPTANCE CRITERIA:
- Parse Diameter headers correctly
- Decode all base protocol AVPs
- Handle grouped AVPs recursively
- Correlate request/answer pairs by hop-by-hop ID
- Calculate request-answer latency
- Support 3GPP Vendor-ID (10415)
- Achieve 90%+ code coverage
- Handle malformed messages gracefully

Please implement with comprehensive error handling, detailed logging, and extensive unit tests.
```

---

## PROMPT 8: Diameter S6a Interface Parser

```
I'm working on the nDPI Callflow Visualizer project. This is Milestone 8, Phase 3: Diameter S6a Application.

CONTEXT:
- S6a interface (3GPP TS 29.272) connects MME to HSS
- Application ID: 16777251
- Used for subscriber authentication and profile retrieval
- Critical for LTE attach procedure

REQUIREMENTS:

1. Extend Diameter parser for S6a:

```cpp
class DiameterS6aParser : public DiameterApplicationParser {
public:
    static constexpr uint32_t APPLICATION_ID = 16777251;
    static constexpr uint32_t VENDOR_ID_3GPP = 10415;
    
    struct S6aMessage {
        DiameterMessage base;
        CommandCode command;
        
        // Common S6a AVPs (extracted)
        std::optional<std::string> user_name;  // IMSI
        std::optional<std::string> visited_plmn_id;
        std::optional<uint32_t> rat_type;
        std::optional<ULRFlags> ulr_flags;
        std::optional<SubscriptionData> subscription_data;
        std::optional<AuthenticationInfo> auth_info;
        std::optional<uint32_t> cancellation_type;
    };
    
    S6aMessage parse(const DiameterMessage& msg);
    
private:
    void parseUpdateLocationRequest(const DiameterMessage& msg, S6aMessage& s6a_msg);
    void parseAuthenticationInformationRequest(const DiameterMessage& msg, S6aMessage& s6a_msg);
    void parsePurgeUE(const DiameterMessage& msg, S6aMessage& s6a_msg);
};
```

2. Define S6a-specific AVPs:

```cpp
enum class S6aAVPCode : uint32_t {
    // 3GPP TS 29.272
    SUPPORTED_FEATURES = 628,
    FEATURE_LIST_ID = 629,
    FEATURE_LIST = 630,
    
    // Subscriber data
    SUBSCRIPTION_DATA = 1400,
    TERMINAL_INFORMATION = 1401,
    IMEI = 1402,
    SOFTWARE_VERSION = 1403,
    
    // Location updates
    ULR_FLAGS = 1405,
    ULA_FLAGS = 1406,
    VISITED_PLMN_ID = 1407,
    
    // Authentication
    REQUESTED_EUTRAN_AUTH_INFO = 1408,
    REQUESTED_UTRAN_GERAN_AUTH_INFO = 1409,
    NUMBER_OF_REQUESTED_VECTORS = 1410,
    RE_SYNCHRONIZATION_INFO = 1411,
    IMMEDIATE_RESPONSE_PREFERRED = 1412,
    AUTHENTICATION_INFO = 1413,
    E_UTRAN_VECTOR = 1414,
    UTRAN_VECTOR = 1415,
    GERAN_VECTOR = 1416,
    
    // Crypto
    RAND = 1447,
    XRES = 1448,
    AUTN = 1449,
    KASME = 1450,
    
    // Subscriber profile
    SUBSCRIBER_STATUS = 1424,
    OPERATOR_DETERMINED_BARRING = 1425,
    ACCESS_RESTRICTION_DATA = 1426,
    APN_OI_REPLACEMENT = 1427,
    ALL_APN_CONFIG_INC_IND = 1428,
    APN_CONFIGURATION_PROFILE = 1429,
    APN_CONFIGURATION = 1430,
    
    // QoS
    EPS_SUBSCRIBED_QOS_PROFILE = 1431,
    QOS_CLASS_IDENTIFIER = 1028,
    MAX_REQUESTED_BANDWIDTH_UL = 516,
    MAX_REQUESTED_BANDWIDTH_DL = 515,
    
    // PDN
    PDN_TYPE = 1456,
    PDN_GW_ALLOCATION_TYPE = 1438,
    
    // Cancellation
    CANCELLATION_TYPE = 1420,
    CLR_FLAGS = 1638,
    
    // Context
    CONTEXT_IDENTIFIER = 1423,
    SERVICE_SELECTION = 493,  // APN
    
    // Network access
    RAT_TYPE = 1032,
    ULR_FLAGS = 1405,
    IDA_FLAGS = 1490,
    PUA_FLAGS = 1442
};
```

3. Implement S6a procedures:

```cpp
// Update Location Request/Answer (ULR/ULA)
struct UpdateLocationRequest {
    std::string user_name;      // IMSI
    std::string visited_plmn_id;
    uint32_t rat_type;          // E-UTRAN, UTRAN, etc.
    ULRFlags ulr_flags;
    std::optional<uint32_t> ue_srvcc_capability;
    std::optional<HomogeneousSupportOfIMSVoiceOverPSSessions> homogeneous_support;
};

struct UpdateLocationAnswer {
    uint32_t result_code;
    ULAFlags ula_flags;
    SubscriptionData subscription_data;
};

// Authentication Information Request/Answer (AIR/AIA)
struct AuthenticationInformationRequest {
    std::string user_name;      // IMSI
    std::string visited_plmn_id;
    RequestedEUTRANAuthInfo requested_eutran_auth_info;
    std::optional<std::vector<uint8_t>> resync_info;  // For AKA failure
};

struct AuthenticationInformationAnswer {
    uint32_t result_code;
    AuthenticationInfo auth_info;
};

struct AuthenticationInfo {
    std::vector<EUTRANVector> eutran_vectors;
};

struct EUTRANVector {
    std::array<uint8_t, 16> rand;    // Random challenge
    std::array<uint8_t, 16> xres;    // Expected response
    std::array<uint8_t, 16> autn;    // Authentication token
    std::array<uint8_t, 32> kasme;   // Key for MME
};

// Purge UE Request/Answer (PUR/PUA)
struct PurgeUERequest {
    std::string user_name;      // IMSI
    std::optional<PURFlags> pur_flags;
};

struct PurgeUEAnswer {
    uint32_t result_code;
    PUAFlags pua_flags;
};

// Cancel Location Request/Answer (CLR/CLA)
struct CancelLocationRequest {
    std::string user_name;      // IMSI
    CancellationType cancellation_type;
    CLRFlags clr_flags;
};

struct CancelLocationAnswer {
    uint32_t result_code;
};

// Insert Subscriber Data Request/Answer (IDR/IDA)
struct InsertSubscriberDataRequest {
    std::string user_name;      // IMSI
    SubscriptionData subscription_data;
    IDAFlags ida_flags;
};

struct InsertSubscriberDataAnswer {
    uint32_t result_code;
    std::optional<IMSVoiceOverPSSessionsSupported> ims_voice_over_ps;
};
```

4. Parse subscription data (complex grouped AVP):

```cpp
struct SubscriptionData {
    std::optional<SubscriberStatus> subscriber_status;
    std::optional<std::string> msisdn;
    std::optional<std::string> a_msisdn;
    std::optional<NetworkAccessMode> network_access_mode;
    std::optional<OperatorDeterminedBarring> operator_determined_barring;
    std::optional<AMBR> ambr;  // Aggregate Maximum Bit Rate
    std::optional<APNConfigurationProfile> apn_configuration_profile;
    std::optional<RATFrequencySelectionPriorityID> rat_frequency_selection_priority_id;
    std::optional<TraceInfo> trace_info;
};

struct APNConfigurationProfile {
    uint32_t context_identifier;
    std::vector<APNConfiguration> apn_configs;
    bool all_apn_config_inc_ind;
};

struct APNConfiguration {
    uint32_t context_identifier;
    std::string service_selection;  // APN
    PDNType pdn_type;               // IPv4, IPv6, IPv4v6
    EPSSubscribedQoSProfile qos_profile;
    std::optional<std::string> served_party_ip_address;
    std::optional<AMBR> ambr;
};

struct EPSSubscribedQoSProfile {
    uint32_t qos_class_identifier;  // QCI
    AllocationRetentionPriority allocation_retention_priority;
};

struct AMBR {
    uint32_t max_requested_bandwidth_ul;  // bits per second
    uint32_t max_requested_bandwidth_dl;
};
```

5. Session correlation with GTP:
   - Use IMSI to correlate S6a with S11/S1-U sessions
   - Extract authentication vectors and match with NAS
   - Link subscription data to GTP bearer QoS

FILE STRUCTURE:
```
include/protocol_parsers/diameter/
  diameter_s6a.h
  s6a_types.h
  s6a_avp_parser.h

src/protocol_parsers/diameter/
  diameter_s6a_parser.cpp
  s6a_subscription_data_parser.cpp
  s6a_auth_info_parser.cpp

tests/unit/
  test_diameter_s6a.cpp
  test_s6a_subscription_parsing.cpp

tests/pcaps/
  s6a_ulr_ula.pcap
  s6a_air_aia.pcap
  s6a_pur_pua.pcap
  s6a_clr_cla.pcap
```

TESTING:
- Unit tests for all S6a message types
- Test subscription data parsing (complex grouped AVP)
- Validate authentication vector extraction
- Test IMSI extraction and correlation
- Verify QoS profile parsing

ACCEPTANCE CRITERIA:
- Parse all S6a command codes
- Decode subscription data with all nested AVPs
- Extract authentication vectors (RAND, XRES, AUTN, KASME)
- Parse APN configuration profiles
- Correlate S6a sessions with GTP sessions by IMSI
- Handle experimental result codes
- Achieve 95%+ code coverage

Please implement with comprehensive error handling and extensive unit tests.
```

---

## PROMPT 9: Diameter Gx/Rx/Gy Interface Parsers

```
I'm working on the nDPI Callflow Visualizer project. This is Milestone 8, Phase 4: Diameter Policy and Charging.

CONTEXT:
- Gx (TS 29.212): P-GW to PCRF for policy control
- Rx (TS 29.214): AF (P-CSCF) to PCRF for media authorization
- Gy/Ro (TS 32.299): Online charging with OCS
- All use Diameter Credit Control Application (DCCA)

REQUIREMENTS:

1. Implement Gx interface parser:

```cpp
class DiameterGxParser : public DiameterApplicationParser {
public:
    static constexpr uint32_t APPLICATION_ID = 16777238;
    
    struct GxMessage {
        DiameterMessage base;
        
        // CCR/CCA specific
        CCRequestType cc_request_type;
        uint32_t cc_request_number;
        
        // Session info
        std::optional<std::string> framed_ip_address;
        std::optional<std::string> called_station_id;  // APN
        std::optional<uint32_t> rat_type;
        
        // Policy rules
        std::vector<ChargingRuleInstall> charging_rule_install;
        std::vector<ChargingRuleRemove> charging_rule_remove;
        std::optional<QoSInformation> qos_information;
        std::optional<DefaultEPSBearerQoS> default_eps_bearer_qos;
        
        // Usage monitoring
        std::vector<UsageMonitoringInformation> usage_monitoring;
        
        // Event triggers
        std::vector<EventTrigger> event_triggers;
    };
    
    GxMessage parse(const DiameterMessage& msg);
};

// Gx-specific AVPs
enum class GxAVPCode : uint32_t {
    // Charging rules
    CHARGING_RULE_INSTALL = 1001,
    CHARGING_RULE_REMOVE = 1002,
    CHARGING_RULE_DEFINITION = 1003,
    CHARGING_RULE_BASE_NAME = 1004,
    CHARGING_RULE_NAME = 1005,
    
    // Event triggers
    EVENT_TRIGGER = 1006,
    
    // Metering
    METERING_METHOD = 1007,
    OFFLINE = 1008,
    ONLINE = 1009,
    PRECEDENCE = 1010,
    REPORTING_LEVEL = 1011,
    
    // QoS
    QOS_INFORMATION = 1016,
    QOS_CLASS_IDENTIFIER = 1028,  // QCI
    MAX_REQUESTED_BANDWIDTH_DL = 515,
    MAX_REQUESTED_BANDWIDTH_UL = 516,
    GUARANTEED_BITRATE_DL = 1025,
    GUARANTEED_BITRATE_UL = 1026,
    BEARER_IDENTIFIER = 1020,
    
    // Usage monitoring
    USAGE_MONITORING_INFORMATION = 1067,
    MONITORING_KEY = 1066,
    GRANTED_SERVICE_UNIT = 1068,
    USED_SERVICE_UNIT = 1069,
    
    // Session management
    BEARER_CONTROL_MODE = 1023,
    NETWORK_REQUEST_SUPPORT = 1024,
    BEARER_OPERATION = 1021,
    
    // IP CAN
    IP_CAN_TYPE = 1027,
    RAT_TYPE = 1032,
    TGPP_SGSN_ADDRESS = 6,
    TGPP_GGSN_ADDRESS = 7,
    
    // PCC rule
    PCC_RULE_STATUS = 1019,
    RULE_ACTIVATION_TIME = 1043,
    RULE_DEACTIVATION_TIME = 1044,
    
    // Default EPS bearer QoS
    DEFAULT_EPS_BEARER_QOS = 1049,
    ALLOCATION_RETENTION_PRIORITY = 1034,
    PRIORITY_LEVEL = 1046,
    PRE_EMPTION_CAPABILITY = 1047,
    PRE_EMPTION_VULNERABILITY = 1048
};

struct ChargingRuleInstall {
    std::vector<ChargingRuleDefinition> charging_rule_definition;
    std::vector<std::string> charging_rule_base_name;
    std::optional<std::string> bearer_identifier;
    std::optional<RuleActivationTime> rule_activation_time;
    std::optional<RuleDeactivationTime> rule_deactivation_time;
};

struct ChargingRuleDefinition {
    std::string charging_rule_name;
    std::optional<ServiceIdentifier> service_identifier;
    std::optional<uint32_t> rating_group;
    std::vector<FlowInformation> flow_information;
    std::optional<QoSInformation> qos_information;
    std::optional<uint32_t> precedence;
    std::optional<ReportingLevel> reporting_level;
    std::optional<OnlineOfflineCharging> online_charging;
    std::optional<OnlineOfflineCharging> offline_charging;
    std::optional<MeteringMethod> metering_method;
};

struct FlowInformation {
    FlowDirection flow_direction;
    std::string flow_description;  // IPFilterRule format
    std::optional<std::string> tof_traffic;
};

enum class EventTrigger : uint32_t {
    SGSN_CHANGE = 0,
    QOS_CHANGE = 1,
    RAT_CHANGE = 2,
    TFT_CHANGE = 3,
    PLMN_CHANGE = 4,
    LOSS_OF_BEARER = 5,
    RECOVERY_OF_BEARER = 6,
    IP_CAN_CHANGE = 7,
    // ... many more
    AN_GW_CHANGE = 28,
    SUCCESSFUL_RESOURCE_ALLOCATION = 29,
    RESOURCE_MODIFICATION_REQUEST = 30,
    OUT_OF_CREDIT = 14,
    REALLOCATION_OF_CREDIT = 15,
    USAGE_REPORT = 33
};
```

2. Implement Rx interface parser:

```cpp
class DiameterRxParser : public DiameterApplicationParser {
public:
    static constexpr uint32_t APPLICATION_ID = 16777236;
    
    struct RxMessage {
        DiameterMessage base;
        
        // Session info
        std::optional<std::string> framed_ip_address;
        std::optional<std::string> framed_ipv6_prefix;
        
        // Media components
        std::vector<MediaComponentDescription> media_components;
        
        // AF application identifier
        std::optional<std::string> af_application_identifier;
        
        // Service info
        std::optional<ServiceInfoStatus> service_info_status;
        std::optional<std::string> service_urn;
        std::optional<SpecificAction> specific_action;
    };
    
    RxMessage parse(const DiameterMessage& msg);
};

enum class RxAVPCode : uint32_t {
    // Rx-specific
    MEDIA_COMPONENT_DESCRIPTION = 517,
    MEDIA_COMPONENT_NUMBER = 518,
    MEDIA_SUB_COMPONENT = 519,
    MEDIA_TYPE = 520,
    FLOW_DESCRIPTION = 507,
    FLOW_NUMBER = 509,
    FLOW_STATUS = 511,
    FLOW_USAGE = 512,
    MAX_REQUESTED_BANDWIDTH_DL = 515,
    MAX_REQUESTED_BANDWIDTH_UL = 516,
    
    // AF application
    AF_APPLICATION_IDENTIFIER = 504,
    AF_CHARGING_IDENTIFIER = 505,
    
    // Service info
    SERVICE_INFO_STATUS = 527,
    SERVICE_URN = 525,
    SPECIFIC_ACTION = 513,
    
    // Codecs
    CODEC_DATA = 524,
    
    // RR/RS Bandwidth
    RR_BANDWIDTH = 521,
    RS_BANDWIDTH = 522
};

struct MediaComponentDescription {
    uint32_t media_component_number;
    std::vector<MediaSubComponent> media_sub_components;
    std::optional<AFApplicationIdentifier> af_application_identifier;
    std::optional<MediaType> media_type;
    std::optional<uint32_t> max_requested_bandwidth_dl;
    std::optional<uint32_t> max_requested_bandwidth_ul;
    std::optional<FlowStatus> flow_status;
    std::optional<std::string> codec_data;
};

struct MediaSubComponent {
    uint32_t flow_number;
    std::vector<std::string> flow_descriptions;  // SDP-like format
    FlowUsage flow_usage;
};
```

3. Implement Gy/Ro parser (Credit Control):

```cpp
class DiameterGyParser : public DiameterApplicationParser {
public:
    static constexpr uint32_t APPLICATION_ID = 4;  // DCCA
    
    struct GyMessage {
        DiameterMessage base;
        
        // CC-specific
        CCRequestType cc_request_type;
        uint32_t cc_request_number;
        
        // Service units
        std::vector<MultipleServicesCreditControl> mscc;
        
        // User equipment
        std::optional<std::string> user_equipment_info;
        std::optional<SubscriptionId> subscription_id;
        
        // Service info
        std::optional<ServiceInformation> service_information;
    };
    
    GyMessage parse(const DiameterMessage& msg);
};

enum class CCRequestType : uint32_t {
    INITIAL_REQUEST = 1,
    UPDATE_REQUEST = 2,
    TERMINATION_REQUEST = 3,
    EVENT_REQUEST = 4
};

struct MultipleServicesCreditControl {
    std::optional<GrantedServiceUnit> granted_service_unit;
    std::optional<RequestedServiceUnit> requested_service_unit;
    std::optional<UsedServiceUnit> used_service_unit;
    std::optional<uint32_t> rating_group;
    std::optional<uint32_t> service_identifier;
    std::optional<uint32_t> validity_time;
    std::optional<FinalUnitIndication> final_unit_indication;
    std::optional<uint32_t> result_code;
};

struct GrantedServiceUnit {
    std::optional<uint32_t> cc_time;           // seconds
    std::optional<uint64_t> cc_total_octets;
    std::optional<uint64_t> cc_input_octets;
    std::optional<uint64_t> cc_output_octets;
    std::optional<uint32_t> cc_service_specific_units;
};

struct UsedServiceUnit {
    std::optional<uint32_t> cc_time;
    std::optional<uint64_t> cc_total_octets;
    std::optional<uint64_t> cc_input_octets;
    std::optional<uint64_t> cc_output_octets;
    std::optional<TariffChangeUsage> tariff_change_usage;
};
```

4. Cross-interface correlation:
   - Gx session correlates with GTP bearer by Framed-IP-Address
   - Rx session correlates with SIP Call-ID (VoLTE)
   - Gy session tracks credit for data usage

FILE STRUCTURE:
```
include/protocol_parsers/diameter/
  diameter_gx.h
  diameter_rx.h
  diameter_gy.h
  diameter_policy_types.h

src/protocol_parsers/diameter/
  diameter_gx_parser.cpp
  diameter_rx_parser.cpp
  diameter_gy_parser.cpp
  policy_rule_parser.cpp

tests/unit/
  test_diameter_gx.cpp
  test_diameter_rx.cpp
  test_diameter_gy.cpp

tests/pcaps/
  gx_ccr_cca_initial.pcap
  rx_aar_aaa_volte.pcap
  gy_charging_session.pcap
```

TESTING:
- Unit tests for all policy and charging message types
- Test charging rule parsing
- Validate media component description parsing
- Test credit control unit calculations
- Verify event trigger handling

ACCEPTANCE CRITERIA:
- Parse Gx, Rx, Gy message types
- Decode charging rules and QoS policies
- Extract media component descriptions
- Parse credit control units
- Correlate with GTP and SIP sessions
- Achieve 90%+ code coverage

Please implement with comprehensive error handling and extensive unit tests.
```

---

## PROMPT 10: IMS Diameter Interfaces (Cx/Sh/Dx)

```
I'm working on the nDPI Callflow Visualizer project. This is Milestone 8, Phase 5: IMS Diameter Interfaces.

CONTEXT:
- Cx (TS 29.228/229): I-CSCF/S-CSCF to HSS
- Dx: Uses same application as Cx, SLF lookup
- Sh (TS 29.328/329): AS to HSS for subscriber data
- Critical for IMS registration and services

REQUIREMENTS:

1. Implement Cx/Dx interface parser:

```cpp
class DiameterCxParser : public DiameterApplicationParser {
public:
    static constexpr uint32_t APPLICATION_ID = 16777216;
    
    struct CxMessage {
        DiameterMessage base;
        CxCommandCode command;
        
        // User identity
        std::optional<std::string> public_identity;  // SIP URI
        std::optional<std::string> private_identity; // IMPI
        std::optional<std::string> server_name;      // S-CSCF name
        
        // Registration info
        std::optional<ServerCapabilities> server_capabilities;
        std::optional<UserDataSH> user_data;
        std::optional<ChargingInformation> charging_information;
        
        // Authentication
        std::optional<SIPAuthDataItem> sip_auth_data_item;
        std::optional<SIPNumberAuthItems> sip_number_auth_items;
    };
    
    CxMessage parse(const DiameterMessage& msg);
};

enum class CxDxCommandCode : uint32_t {
    USER_AUTHORIZATION_REQUEST = 300,      // UAR
    USER_AUTHORIZATION_ANSWER = 300,       // UAA
    SERVER_ASSIGNMENT_REQUEST = 301,       // SAR
    SERVER_ASSIGNMENT_ANSWER = 301,        // SAA
    LOCATION_INFO_REQUEST = 302,           // LIR
    LOCATION_INFO_ANSWER = 302,            // LIA
    MULTIMEDIA_AUTH_REQUEST = 303,         // MAR
    MULTIMEDIA_AUTH_ANSWER = 303,          // MAA
    REGISTRATION_TERMINATION_REQUEST = 304,// RTR
    REGISTRATION_TERMINATION_ANSWER = 304, // RTA
    PUSH_PROFILE_REQUEST = 305,            // PPR
    PUSH_PROFILE_ANSWER = 305              // PPA
};

enum class CxDxAVPCode : uint32_t {
    PUBLIC_IDENTITY = 601,
    SERVER_NAME = 602,
    SERVER_CAPABILITIES = 603,
    MANDATORY_CAPABILITY = 604,
    OPTIONAL_CAPABILITY = 605,
    USER_DATA = 606,
    SIP_NUMBER_AUTH_ITEMS = 607,
    SIP_AUTHENTICATION_SCHEME = 608,
    SIP_AUTHENTICATE = 609,
    SIP_AUTHORIZATION = 610,
    SIP_AUTHENTICATION_CONTEXT = 611,
    SIP_AUTH_DATA_ITEM = 612,
    SIP_ITEM_NUMBER = 613,
    SERVER_ASSIGNMENT_TYPE = 614,
    DEREGISTRATION_REASON = 615,
    REASON_CODE = 616,
    REASON_INFO = 617,
    CHARGING_INFORMATION = 618,
    PRIMARY_EVENT_CHARGING_FUNCTION_NAME = 619,
    SECONDARY_EVENT_CHARGING_FUNCTION_NAME = 620,
    PRIMARY_CHARGING_COLLECTION_FUNCTION_NAME = 621,
    SECONDARY_CHARGING_COLLECTION_FUNCTION_NAME = 622,
    USER_AUTHORIZATION_TYPE = 623,
    USER_DATA_ALREADY_AVAILABLE = 624,
    CONFIDENTIALITY_KEY = 625,
    INTEGRITY_KEY = 626,
    USER_DATA_REQUEST_TYPE = 627,
    SUPPORTED_FEATURES = 628,
    FEATURE_LIST_ID = 629,
    FEATURE_LIST = 630,
    SUPPORTED_APPLICATIONS = 631,
    ASSOCIATED_IDENTITIES = 632,
    ORIGINATING_REQUEST = 633,
    WILDCARDED_PUBLIC_IDENTITY = 634,
    SIP_DIGEST_AUTHENTICATE = 635,
    WILDCARDED_IMPU = 636,
    UAR_FLAGS = 637,
    LOOSE_ROUTE_INDICATION = 638,
    SCSCF_RESTORATION_INFO = 639,
    PATH = 640,
    CONTACT = 641,
    SUBSCRIPTION_INFO = 642,
    CALL_ID_SIP_HEADER = 643,
    FROM_SIP_HEADER = 644,
    TO_SIP_HEADER = 645,
    RECORD_ROUTE = 646,
    ASSOCIATED_REGISTERED_IDENTITIES = 647,
    MULTIPLE_REGISTRATION_INDICATION = 648,
    RESTORATION_INFO = 649,
    SESSION_PRIORITY = 650,
    IDENTITY_WITH_EMERGENCY_REGISTRATION = 651,
    PRIVILEDGED_SENDER_INDICATION = 652
};

struct ServerCapabilities {
    std::vector<uint32_t> mandatory_capabilities;
    std::vector<uint32_t> optional_capabilities;
    std::vector<std::string> server_names;
};

struct SIPAuthDataItem {
    uint32_t sip_item_number;
    std::optional<std::string> sip_authentication_scheme;  // "Digest-AKAv1-MD5", etc.
    std::optional<std::string> sip_authenticate;
    std::optional<std::string> sip_authorization;
    std::optional<std::string> sip_authentication_context;
    std::optional<std::string> confidentiality_key;
    std::optional<std::string> integrity_key;
};

struct ChargingInformation {
    std::optional<std::string> primary_event_charging_function_name;
    std::optional<std::string> secondary_event_charging_function_name;
    std::optional<std::string> primary_charging_collection_function_name;
    std::optional<std::string> secondary_charging_collection_function_name;
};
```

2. Implement Sh interface parser:

```cpp
class DiameterShParser : public DiameterApplicationParser {
public:
    static constexpr uint32_t APPLICATION_ID = 16777217;
    
    struct ShMessage {
        DiameterMessage base;
        ShCommandCode command;
        
        // User identity
        std::vector<UserIdentity> user_identities;
        
        // Data reference
        std::vector<DataReference> data_references;
        
        // User data
        std::optional<UserDataSH> user_data;
        
        // Repository data
        std::optional<RepositoryDataID> repository_data_id;
        std::optional<ServiceIndication> service_indication;
    };
    
    ShMessage parse(const DiameterMessage& msg);
};

enum class ShCommandCode : uint32_t {
    USER_DATA_REQUEST = 306,       // UDR
    USER_DATA_ANSWER = 306,        // UDA
    PROFILE_UPDATE_REQUEST = 307,  // PUR
    PROFILE_UPDATE_ANSWER = 307,   // PUA
    SUBSCRIBE_NOTIFICATIONS_REQUEST = 308,  // SNR
    SUBSCRIBE_NOTIFICATIONS_ANSWER = 308,   // SNA
    PUSH_NOTIFICATION_REQUEST = 309,        // PNR
    PUSH_NOTIFICATION_ANSWER = 309          // PNA
};

enum class ShAVPCode : uint32_t {
    USER_IDENTITY = 700,
    MSISDN = 701,
    USER_DATA = 702,
    DATA_REFERENCE = 703,
    SERVICE_INDICATION = 704,
    SUBS_REQ_TYPE = 705,
    REQUESTED_DOMAIN = 706,
    CURRENT_LOCATION = 707,
    IDENTITY_SET = 708,
    EXPIRY_TIME = 709,
    SEND_DATA_INDICATION = 710,
    DSAI_TAG = 711,
    WILDCARDED_PUBLIC_IDENTITY = 634,
    WILDCARDED_IMPU = 636,
    SESSION_PRIORITY = 650,
    ONE_TIME_NOTIFICATION = 712,
    REQUESTED_NODES = 713,
    SERVING_NODE_INDICATION = 714,
    REPOSITORY_DATA_ID = 715,
    SEQUENCE_NUMBER = 716,
    PRE_PAGING_SUPPORTED = 717,
    LOCAL_TIME_ZONE_INDICATION = 718,
    UDR_FLAGS = 719,
    CALL_REFERENCE_INFO = 720,
    CALL_REFERENCE_NUMBER = 721,
    AS_NUMBER = 722
};

enum class DataReference : uint32_t {
    REPOSITORY_DATA = 0,
    IMS_PUBLIC_IDENTITY = 10,
    IMS_USER_STATE = 11,
    S_CSCF_NAME = 12,
    INITIAL_FILTER_CRITERIA = 13,
    LOCATION_INFORMATION = 14,
    USER_STATE = 15,
    CHARGING_INFORMATION = 16,
    MSISDN = 17,
    PSI_ACTIVATION = 18,
    DSAI = 19,
    SERVICE_LEVEL_TRACE_INFO = 21,
    IP_ADDRESS_SECURE_BINDING_INFO = 22,
    SERVICE_PRIORITY_LEVEL = 23,
    SMS_REGISTRATION_INFO = 24,
    UE_REACHABILITY_FOR_IP = 25,
    TAD_INFO = 26
};

struct UserIdentity {
    std::optional<std::string> public_identity;   // SIP URI or Tel URI
    std::optional<std::string> msisdn;
    std::optional<std::string> external_identifier;
};
```

3. Session correlation:
   - Cx: Correlate with SIP REGISTER by Public-Identity
   - Sh: Track AS queries for subscriber data
   - Link to IMS sessions via IMPU

FILE STRUCTURE:
```
include/protocol_parsers/diameter/
  diameter_cx.h
  diameter_sh.h
  ims_types.h

src/protocol_parsers/diameter/
  diameter_cx_parser.cpp
  diameter_sh_parser.cpp
  ims_user_data_parser.cpp

tests/unit/
  test_diameter_cx.cpp
  test_diameter_sh.cpp

tests/pcaps/
  cx_uar_uaa.pcap
  cx_mar_maa.pcap
  cx_sar_saa.pcap
  sh_udr_uda.pcap
  sh_pnr_pna.pcap
```

TESTING:
- Unit tests for all Cx/Dx/Sh message types
- Test SIP authentication data parsing
- Validate server capabilities extraction
- Test user data parsing
- Verify correlation with SIP sessions

ACCEPTANCE CRITERIA:
- Parse all Cx/Dx command codes
- Parse all Sh command codes
- Extract SIP authentication data
- Parse server capabilities
- Decode user data (XML)
- Correlate with SIP REGISTER messages
- Achieve 90%+ code coverage

Please implement with comprehensive error handling and extensive unit tests.
```

---

## Summary

These 5 prompts complete Milestone 8:

6. ✅ SCTP transport layer with association tracking
7. ✅ Diameter base protocol parser
8. ✅ Diameter S6a interface (MME-HSS)
9. ✅ Diameter Gx/Rx/Gy interfaces (policy and charging)
10. ✅ IMS Diameter interfaces (Cx/Sh/Dx)

**Estimated Development Time**: 4 weeks  
**Lines of Code**: ~10,000 new  
**Test Coverage Target**: 90%+

After completing these prompts, the system will have:
- Full SCTP support with stream reassembly
- Complete Diameter protocol stack
- All major Diameter applications (S6a, Gx, Rx, Gy, Cx, Sh)
- Integration with GTP and SIP sessions
- Foundation for control plane protocols in Milestone 9
