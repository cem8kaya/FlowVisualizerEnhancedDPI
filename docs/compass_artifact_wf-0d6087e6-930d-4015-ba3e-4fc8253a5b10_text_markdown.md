# 3GPP protocol specifications for 4G LTE and 5G core networks

Building a protocol analyzer for mobile networks requires deep understanding of over **50 distinct interfaces** spanning control plane, user plane, charging, and policy functions. This comprehensive reference covers every major 3GPP-defined protocol from the Evolved Packet Core (EPC) through to the 5G Service-Based Architecture (SBA), including IMS protocols, cross-cutting protocol families, and multi-vendor implementation considerations. The specifications span **3GPP Releases 15 through 18**, with HTTP/2-based SBI interfaces fundamentally transforming how 5G network functions communicate compared to the Diameter and GTP protocols that dominated 4G.

---

## 4G LTE EPC interfaces use GTP, Diameter, and SCTP protocols

The Evolved Packet Core architecture defined in **TS 23.401** employs three primary protocol families across its interfaces: GTP for tunneling and session management, Diameter for authentication and policy, and SCTP for reliable signaling transport.

### Control plane interfaces

| Interface | Endpoints | Protocol | Transport | Port | 3GPP Spec |
|-----------|-----------|----------|-----------|------|-----------|
| **S1-MME** | eNodeB ↔ MME | S1-AP | SCTP | **36412** | TS 36.413 |
| **S6a** | MME ↔ HSS | Diameter | SCTP/TCP | **3868** | TS 29.272 |
| **S11** | MME ↔ S-GW | GTPv2-C | UDP | **2123** | TS 29.274 |
| **S10** | MME ↔ MME | GTPv2-C | UDP | 2123 | TS 29.274 |
| **S3** | MME ↔ SGSN | GTPv2-C | UDP | 2123 | TS 29.274 |
| **SGs** | MME ↔ MSC/VLR | SGsAP | SCTP | **29118** | TS 29.118 |
| **Sv** | MME ↔ MSC (SRVCC) | GTPv2-C | UDP | 2123 | TS 29.280 |
| **SLg** | MME ↔ GMLC | Diameter | SCTP/TCP | 3868 | TS 29.172 |
| **SLs** | MME ↔ E-SMLC | LCS-AP | SCTP | Config-dependent | TS 29.171 |

### User plane interfaces

| Interface | Endpoints | Protocol | Transport | Port | 3GPP Spec |
|-----------|-----------|----------|-----------|------|-----------|
| **S1-U** | eNodeB ↔ S-GW | GTP-U | UDP | **2152** | TS 29.281 |
| **S5/S8** | S-GW ↔ P-GW | GTPv2-C + GTP-U | UDP | 2123/2152 | TS 29.274, 29.281 |
| **S4** | S-GW ↔ SGSN | GTPv2-C + GTP-U | UDP | 2123/2152 | TS 29.274, 29.281 |
| **SGi** | P-GW ↔ External PDN | IP | UDP/TCP | Application-specific | TS 29.061 |

### Policy and charging interfaces

| Interface | Endpoints | Protocol | Transport | Port | 3GPP Spec |
|-----------|-----------|----------|-----------|------|-----------|
| **Gx** | P-GW (PCEF) ↔ PCRF | Diameter | SCTP/TCP | **3868** | TS 29.212 |
| **Gy** | P-GW ↔ OCS | Diameter (DCCA) | SCTP/TCP | 3868 | TS 32.299 |
| **Gz** | P-GW ↔ OFCS | GTP' | UDP | **3386** | TS 32.295 |
| **Rx** | P-CSCF ↔ PCRF | Diameter | SCTP/TCP | 3868 | TS 29.214 |
| **Sp** | PCRF ↔ SPR | Diameter (Sh-based) | SCTP/TCP | 3868 | TS 29.329 |

The S1-AP protocol uses **SCTP Payload Protocol ID 18**, enabling multi-stream transport that prevents head-of-line blocking. Diameter interfaces share the standardized port **3868** (or **5868** for TLS), with 3GPP-specific applications identified by unique Application IDs in the 16777xxx range.

---

## 5G Core employs HTTP/2-based service architecture alongside traditional protocols

The 5G Core architecture represents a fundamental shift toward cloud-native design, with Network Functions exposing services through RESTful APIs while maintaining protocol continuity for user plane and RAN interfaces. All SBI specifications use **HTTP/2 with JSON encoding** as defined in **TS 29.500**.

### Reference point interfaces (non-SBI)

| Interface | Endpoints | Protocol | Transport | Port | 3GPP Spec |
|-----------|-----------|----------|-----------|------|-----------|
| **N1** | UE ↔ AMF | 5G NAS | via N2/NGAP | — | TS 24.501 |
| **N2** | gNB ↔ AMF | **NGAP** | SCTP | **38412** | TS 38.413 |
| **N3** | gNB ↔ UPF | GTP-U | UDP | **2152** | TS 29.281 |
| **N4** | SMF ↔ UPF | **PFCP** | UDP | **8805** | TS 29.244 |
| **N6** | UPF ↔ Data Network | IP | Various | Application-specific | TS 23.501 |
| **N9** | UPF ↔ UPF | GTP-U | UDP | 2152 | TS 29.281 |
| **N26** | AMF ↔ MME | GTPv2-C | UDP | 2123 | TS 29.274 |

### Service-Based Interfaces (SBI)

All SBI interfaces share a common protocol stack: **HTTP/2 → TLS 1.2/1.3 → TCP → IP**, using ports **80** (HTTP) or **443** (HTTPS with mutual TLS).

| Service Interface | Network Function | Primary Spec | Key Services |
|-------------------|------------------|--------------|--------------|
| **Namf** | AMF | TS 29.518 | Communication, EventExposure, Location, MT |
| **Nsmf** | SMF | TS 29.502 | PDUSession, EventExposure |
| **Nausf** | AUSF | TS 29.509 | UEAuthentication, SoRProtection |
| **Nudm** | UDM | TS 29.503 | SDM, UECM, UEAU, EventExposure |
| **Npcf** | PCF | TS 29.507/512/514 | AMPolicy, SMPolicy, PolicyAuthorization |
| **Nnrf** | NRF | TS 29.510 | NFManagement, NFDiscovery, AccessToken |
| **Nnssf** | NSSF | TS 29.531 | NSSelection, NSSAIAvailability |
| **Nchf** | CHF | TS 32.291 | ConvergedCharging, SpendingLimitControl |
| **Nnef** | NEF | TS 29.522 | Exposure APIs for external applications |
| **Nudr** | UDR | TS 29.504 | DataRepository |
| **Nsmsf** | SMSF | TS 29.540 | SMService |
| **N5g-eir** | 5G-EIR | TS 29.511 | EquipmentIdentityCheck |

The SBI framework uses **3GPP custom HTTP headers** including `3gpp-Sbi-Message-Priority` (0-31 priority levels), `3gpp-Sbi-Oci` (overload control), and `3gpp-Sbi-Binding` (session binding). The NRF issues OAuth 2.0 access tokens for inter-NF authorization, and OpenAPI 3.0 specifications are maintained at the 3GPP Forge repository.

---

## IMS interfaces combine SIP signaling with Diameter-based subscriber management

The IP Multimedia Subsystem architecture defined in **TS 23.228** uses SIP for call control and Diameter for backend database interactions. Understanding both protocol families is essential for VoLTE and VoNR analysis.

### Diameter interfaces for IMS

| Interface | Endpoints | Application ID | 3GPP Spec | Key Functions |
|-----------|-----------|----------------|-----------|---------------|
| **Cx** | HSS ↔ I-CSCF/S-CSCF | **16777216** | TS 29.228/229 | User registration, authentication, profile download |
| **Dx** | SLF ↔ I-CSCF/S-CSCF | 16777216 | TS 29.228/229 | HSS location via redirect |
| **Sh** | HSS ↔ AS | **16777217** | TS 29.328/329 | Subscriber data management |
| **Rf** | IMS nodes ↔ CDF | 3 (Accounting) | TS 32.299 | Offline charging |
| **Ro** | IMS nodes ↔ OCS | 4 (DCCA) | TS 32.299 | Online credit control |

### Cx/Dx Diameter command codes

| Command | Code | Direction | Purpose |
|---------|------|-----------|---------|
| User-Authorization-Request/Answer | **300** | I-CSCF → HSS | REGISTER authorization |
| Server-Assignment-Request/Answer | **301** | S-CSCF → HSS | S-CSCF assignment |
| Location-Info-Request/Answer | **302** | I-CSCF → HSS | Locate S-CSCF for terminating calls |
| Multimedia-Auth-Request/Answer | **303** | S-CSCF → HSS | Authentication vector retrieval |
| Registration-Termination-Request/Answer | **304** | HSS → S-CSCF | Network-initiated deregistration |
| Push-Profile-Request/Answer | **305** | HSS → S-CSCF | Profile updates |

### SIP interfaces

| Interface | Endpoints | Protocol | Port | Description |
|-----------|-----------|----------|------|-------------|
| **Gm** | UE ↔ P-CSCF | SIP/SDP | 5060/5061 | UE registration and sessions |
| **Mw** | CSCF ↔ CSCF | SIP | Internal | Inter-CSCF communication |
| **ISC** | S-CSCF ↔ AS | SIP | Internal | Application server triggering |
| **Mg/Mi/Mj/Mk** | CSCF ↔ MGCF/BGCF | SIP | Internal | PSTN breakout |
| **Ut** | UE ↔ AS | HTTP/XCAP | 80/443 | Supplementary service configuration |

### 3GPP SIP P-headers (RFC 7315)

The IMS extends standard SIP with private headers for network assertions:

- **P-Asserted-Identity**: Network-asserted caller identity
- **P-Access-Network-Info**: Access type (3GPP-E-UTRAN, IEEE-802.11) and cell ID
- **P-Visited-Network-ID**: Roaming network identifier
- **P-Charging-Vector**: Correlation IDs (ICID, orig-ioi, term-ioi) for billing
- **P-Charging-Function-Addresses**: CCF and ECF addresses
- **P-Served-User**: Served user identity on ISC interface

Media uses **RTP/RTCP** (RFC 3550) with codecs including **AMR**, **AMR-WB**, **EVS** for voice and **H.264/H.265** for video, as specified in GSMA IR.92 for VoLTE.

---

## GTP and Diameter protocols form the backbone of cellular tunneling and AAA

### GTP protocol variants

The GPRS Tunneling Protocol family handles both user data transport and control signaling. **No GTPv2-U exists**—user plane always uses GTPv1-U regardless of control plane version.

| Variant | Port | Purpose | Specification |
|---------|------|---------|---------------|
| **GTPv1-C** | UDP 2123 | Legacy 2G/3G control | TS 29.060 |
| **GTPv1-U** | UDP **2152** | User plane (all generations) | TS 29.281 |
| **GTPv2-C** | UDP **2123** | EPC/5GC control plane | TS 29.274 |
| **GTP'** | UDP **3386** | Charging data transfer | TS 32.295 |

**Key GTPv2-C message types** for protocol analysis:

| Value | Message | Value | Message |
|-------|---------|-------|---------|
| 32/33 | Create Session Request/Response | 95/96 | Create Bearer Request/Response |
| 34/35 | Modify Bearer Request/Response | 97/98 | Update Bearer Request/Response |
| 36/37 | Delete Session Request/Response | 99/100 | Delete Bearer Request/Response |
| 170/171 | Downlink Data Notification/Ack | 1/2 | Echo Request/Response |

The **TEID (Tunnel Endpoint Identifier)** is a 32-bit value uniquely identifying each tunnel endpoint. **F-TEID** combines TEID with an IP address for complete tunnel identification.

### Diameter protocol framework

Diameter (RFC 6733) provides AAA services using a hop-by-hop reliable protocol. All 3GPP Diameter applications use **Vendor-ID 10415** for vendor-specific AVPs.

| Application | Application ID | Interface | Specification |
|-------------|---------------|-----------|---------------|
| S6a/S6d | **16777251** | MME/SGSN ↔ HSS | TS 29.272 |
| Gx | **16777238** | PCEF ↔ PCRF | TS 29.212 |
| Rx | **16777236** | AF ↔ PCRF | TS 29.214 |
| Cx/Dx | **16777216** | I/S-CSCF ↔ HSS | TS 29.229 |
| Sh | **16777217** | AS ↔ HSS | TS 29.329 |
| SWx | 16777265 | 3GPP AAA ↔ HSS | TS 29.273 |
| Ro/Gy | 4 (IETF DCCA) | OCS charging | TS 32.299 |
| Rf | 3 (IETF Accounting) | Offline charging | TS 32.299 |

**Common Diameter command codes**:
- **CER/CEA (257)**: Capability exchange
- **CCR/CCA (272)**: Credit control (Gx, Gy)
- **RAR/RAA (258)**: Re-authorization
- **DWR/DWA (280)**: Device watchdog
- **STR/STA (275)**: Session termination

---

## PFCP enables control-user plane separation in EPC and 5GC

The Packet Forwarding Control Protocol (**TS 29.244**) separates control and user plane functions, enabling flexible deployment architectures. It operates on **UDP port 8805**.

### PFCP interfaces

| Interface | Endpoints | Architecture |
|-----------|-----------|--------------|
| **Sxa** | SGW-C ↔ SGW-U | EPC CUPS |
| **Sxb** | PGW-C ↔ PGW-U | EPC CUPS |
| **N4** | SMF ↔ UPF | 5G Core |

### PFCP rule types

A protocol analyzer must parse these fundamental rule structures:

- **PDR (Packet Detection Rule)**: Defines packet matching criteria (source interface, UE IP, SDF filters) and references to other rules
- **FAR (Forwarding Action Rule)**: Specifies actions—DROP, FORWARD, BUFFER, DUPLICATE—and forwarding parameters
- **QER (QoS Enforcement Rule)**: Enforces MBR/GBR, gate status, and QoS Flow Identifier (QFI)
- **URR (Usage Reporting Rule)**: Configures measurement method, triggers, and thresholds for charging
- **BAR (Buffering Action Rule)**: Controls buffering behavior during paging

**PFCP message types** include Session Establishment/Modification/Deletion (50-55), Association Setup/Release (5-10), Heartbeat (1-2), and Session Report (56-57) for usage reporting.

---

## NAS protocols handle mobility and session management between UE and core

### 4G NAS (TS 24.301)

The Non-Access Stratum protocol for EPS uses **Protocol Discriminator 0x07** for EMM and **0x02** for ESM.

**EMM (EPS Mobility Management) procedures**:

| Message | Type Code | Purpose |
|---------|-----------|---------|
| Attach Request | 0x41 | Initial network registration |
| Attach Accept | 0x42 | Registration confirmed |
| TAU Request | 0x48 | Tracking Area Update |
| Authentication Request | 0x52 | AKA challenge |
| Security Mode Command | 0x5D | Enable encryption/integrity |
| Service Request | 0x4C | Transition from idle to connected |

**ESM (EPS Session Management) procedures**:

| Message | Type Code | Purpose |
|---------|-----------|---------|
| Activate Default EPS Bearer Request | 0xC1 | PDN connection establishment |
| Activate Dedicated EPS Bearer Request | 0xC5 | Additional bearer for QoS |
| Deactivate EPS Bearer Request | 0xCD | Bearer teardown |

### 5G NAS (TS 24.501)

5G NAS uses **Extended Protocol Discriminator 0x7E** for 5GMM and **0x2E** for 5GSM.

**5GMM key messages**: Registration Request (0x41), Authentication Request (0x56), Security Mode Command (0x5D), Service Request (0x4C)

**5GSM key messages**: PDU Session Establishment Request (0xC1), PDU Session Modification Request (0xC5), PDU Session Release Request (0xD1)

**PDU session types** in 5G include IPv4, IPv6, IPv4v6, Unstructured, and **Ethernet** (new in 5G for industrial IoT).

---

## 3GPP specifications follow a structured numbering system across releases

### Key specification series

| Series | Scope | Examples |
|--------|-------|----------|
| **23.xxx** | Architecture (Stage 2) | TS 23.401 (EPC), TS 23.501 (5GC), TS 23.228 (IMS) |
| **24.xxx** | NAS protocols (Stage 3) | TS 24.301 (4G NAS), TS 24.501 (5G NAS), TS 24.229 (IMS SIP) |
| **29.xxx** | Core network protocols | TS 29.272 (S6a), TS 29.274 (GTPv2-C), TS 29.500-599 (SBI) |
| **32.xxx** | Charging | TS 32.299 (Diameter charging), TS 32.291 (5G charging) |
| **36.xxx** | LTE RAN | TS 36.413 (S1AP), TS 36.423 (X2AP) |
| **38.xxx** | 5G NR RAN | TS 38.413 (NGAP), TS 38.423 (XnAP) |

### Release timeline

| Release | Status | Key Features |
|---------|--------|--------------|
| **Rel-15** | Frozen (2018) | First 5G NR; NSA and SA modes; initial 5GC |
| **Rel-16** | Frozen (2020) | URLLC, V2X, industrial IoT, NPN |
| **Rel-17** | Frozen (2022) | NTN (satellite), RedCap, positioning, XR |
| **Rel-18** | Frozen (2024) | **5G-Advanced**: AI/ML, network energy savings |
| **Rel-19** | In Progress | 6G foundations, further AI/ML |

---

## Vendor implementations vary in deployment architecture and configuration

### Major vendor approaches

**Ericsson** deploys a dual-mode 5G Cloud Core supporting both EPC and 5GC on a unified, Kubernetes-orchestrated platform with CI/CD pipelines. **Nokia** emphasizes cloud-native SBA with advanced network slicing and NEF capabilities. **Huawei** leads globally (~30% market share) with strong MEC integration and AI automation. **Samsung** offers containerized solutions optimized for Intel processing with OpenRAN focus.

**Cloud-native challengers** like **Mavenir** (DISH, Rakuten deployments), **Affirmed/Microsoft** (Azure for Operators), and **Cisco** provide webscale architectures with multi-cloud portability and ONAP/MANO integration.

### Interoperability considerations

Protocol analyzers must account for these vendor variations:

- **Timer values**: Diameter/SCTP keepalive and timeout intervals differ
- **Optional AVP handling**: Vendors may include different sets of optional AVPs
- **Feature-List negotiation**: Capability advertisements vary between implementations
- **PFCP vendor-specific IEs**: Section 5.9 of TS 29.244 defines enterprise IE ranges (32768-65535)
- **SBI API versions**: Different vendors may support different API version combinations

**Critical port summary for packet capture**:

| Port | Protocol | Usage |
|------|----------|-------|
| **2123/UDP** | GTPv2-C, GTPv1-C | Control plane tunneling |
| **2152/UDP** | GTP-U | User plane tunneling |
| **3868/TCP/SCTP** | Diameter | S6a, Gx, Rx, Cx interfaces |
| **5868/TCP** | Diameter/TLS | Secured Diameter |
| **8805/UDP** | PFCP | N4/Sx control-user plane |
| **36412/SCTP** | S1AP | LTE RAN-Core |
| **38412/SCTP** | NGAP | 5G RAN-Core |
| **80, 443/TCP** | HTTP/2 SBI | 5G NF communication |
| **5060, 5061/UDP/TCP** | SIP, SIP-TLS | IMS signaling |
| **3386/UDP** | GTP' | Charging transfer |

---

## Conclusion

A complete 3GPP protocol analyzer requires parsing capabilities for **three distinct protocol paradigms**: binary-encoded protocols (GTP, PFCP, NAS, S1AP/NGAP), Diameter's AVP-based structure, and HTTP/2-based JSON APIs for 5G SBI. The shift from 4G's point-to-point Diameter interfaces to 5G's service mesh architecture represents the most significant protocol evolution, though GTP-U remains unchanged for user plane transport across all generations.

Key implementation priorities should include GTPv2-C message decoding for session establishment flows, Diameter AVP parsing with 3GPP vendor-specific extensions (Vendor-ID 10415), PFCP rule structure analysis for traffic steering verification, and HTTP/2 frame parsing with JSON body extraction for SBI troubleshooting. The SCTP multi-streaming on ports 36412 (S1AP) and 38412 (NGAP) requires association-aware capture to properly correlate streams, while Diameter's mandatory peer discovery (CER/CEA) must be handled before any application-layer analysis.