# X2AP, NGAP, and 5G NAS Testing Guide

This directory should contain PCAP files for testing the X2AP, NGAP, and 5G NAS parsers.

## Required Test Files

### 1. lte_handover_x2.pcapng
**Description**: LTE X2 handover between eNodeBs

**Expected Traffic**:
- SCTP association between two eNodeBs on port 36422
- X2AP Handover Request (procedure code 0)
- X2AP Handover Request Acknowledge (procedure code 0)
- X2AP SN Status Transfer (procedure code 4)
- X2AP UE Context Release (procedure code 5)

**Key IEs to Verify**:
- Old eNB UE X2AP ID (IE 10)
- New eNB UE X2AP ID (IE 9)
- Target Cell ID (IE 11)
- E-RABs to be Setup (IE 18)
- UE Context Information (IE 45)

**Capture Command**:
```bash
# Capture on X2 interface
tcpdump -i eth0 -s0 -w lte_handover_x2.pcapng sctp port 36422
```

---

### 2. 5g_registration.pcapng
**Description**: 5G UE registration procedure with gNB and AMF

**Expected Traffic**:
- SCTP association on port 38412 (NGAP)
- NGAP Initial UE Message (procedure code 15)
  - Contains 5G NAS Registration Request
- NGAP Downlink NAS Transport (procedure code 4)
  - Contains 5G NAS Authentication Request
  - Contains 5G NAS Security Mode Command
  - Contains 5G NAS Registration Accept
- NGAP Uplink NAS Transport (procedure code 46)
  - Contains 5G NAS responses

**Key Fields to Verify**:
- RAN UE NGAP ID (IE 85)
- AMF UE NGAP ID (IE 10)
- NAS PDU (IE 38) containing:
  - 5GMM Registration Request (0x41)
  - SUPI/SUCI extraction
  - 5G-GUTI

**Capture Command**:
```bash
# Capture on N2 interface (gNB-AMF)
tcpdump -i eth0 -s0 -w 5g_registration.pcapng sctp port 38412
```

---

### 3. 5g_pdu_session.pcapng
**Description**: 5G PDU session establishment

**Expected Traffic**:
- NGAP PDU Session Resource Setup Request (procedure code 30)
  - Contains 5GSM PDU Session Establishment Request
- NGAP PDU Session Resource Setup Response
  - Contains 5GSM PDU Session Establishment Accept
- DNN (Data Network Name) extraction
- S-NSSAI (Network Slice) information
- QoS Flow parameters

**Key Fields to Verify**:
- PDU Session ID (IE 88)
- PDU Session Resource Setup List (IE 74)
- NAS PDU containing:
  - 5GSM PDU Session Establishment Request (0xC1)
  - DNN (e.g., "internet", "ims")
  - S-NSSAI (SST + SD)

**Capture Command**:
```bash
# Capture on N2 interface during data session
tcpdump -i eth0 -s0 -w 5g_pdu_session.pcapng sctp port 38412
```

---

## Generating Test Traffic

### LTE X2 Handover (X2AP)

Using srsRAN or OpenAirInterface:
```bash
# Configure two eNodeBs with X2 interface
# Trigger handover by moving UE between cells
# Monitor X2 interface traffic
```

### 5G Registration (NGAP + 5G NAS)

Using Open5GS or free5GC:
```bash
# Start 5G core network
cd open5gs
./install/bin/open5gs-amfd -c config/amf.yaml

# Start gNB (e.g., srsRAN 5G)
cd srsRAN_Project
sudo ./apps/gnb/gnb -c gnb.yaml

# Connect UE and capture N2 traffic
tcpdump -i any -s0 -w 5g_registration.pcapng sctp port 38412
```

### 5G PDU Session

```bash
# After UE registration, trigger data session
# UE initiates PDU session for internet connectivity
# Capture NGAP messages during session setup
```

---

## Parser Validation

### X2AP Parser
```cpp
// Test X2AP parsing
X2apParser parser;
auto msg = parser.parse(sctp_payload, payload_len);
if (msg.has_value()) {
    assert(msg->procedure_code == X2apProcedureCode::HANDOVER_PREPARATION);
    assert(msg->old_enb_ue_x2ap_id.has_value());
    assert(msg->new_enb_ue_x2ap_id.has_value());
}
```

### NGAP Parser
```cpp
// Test NGAP parsing
NgapParser parser;
auto msg = parser.parse(sctp_payload, payload_len);
if (msg.has_value()) {
    assert(msg->procedure_code == NgapProcedureCode::INITIAL_UE_MESSAGE);
    assert(msg->ran_ue_ngap_id.has_value());
    assert(msg->nas_pdu.has_value());
}
```

### 5G NAS Parser
```cpp
// Test 5G NAS parsing
Nas5gParser parser;
auto msg = parser.parse(nas_pdu, nas_len);
if (msg.has_value()) {
    assert(msg->message_type == Nas5gMessageType::REGISTRATION_REQUEST);
    assert(msg->is5gmm());
    assert(msg->supi.has_value());
}
```

---

## Protocol Standards References

- **X2AP**: 3GPP TS 36.423 (E-UTRAN X2 Application Protocol)
- **NGAP**: 3GPP TS 38.413 (NG-RAN; NG Application Protocol)
- **5G NAS**: 3GPP TS 24.501 (Non-Access-Stratum protocol for 5G)

## Port Numbers

- **X2AP**: SCTP port 36422
- **NGAP**: SCTP port 38412
- **S1AP** (for reference): SCTP port 36412

---

## Alternative: Synthetic PCAP Generation

If real network equipment is not available, synthetic PCAPs can be generated:

```python
from scapy.all import *

# Create synthetic X2AP handover request
# (Requires proper ASN.1 encoding - use asn1tools library)
```

Or use pcap-generator tools with X2AP/NGAP templates.

---

## Expected Parser Output

### X2AP Message
```json
{
  "procedure_name": "Handover-Preparation",
  "old_enb_ue_x2ap_id": 123456,
  "new_enb_ue_x2ap_id": 234567,
  "target_cell_id": 0x0F12345,
  "ie_count": 8
}
```

### NGAP Message
```json
{
  "procedure_name": "Initial-UE-Message",
  "ran_ue_ngap_id": 1,
  "nas_pdu_length": 128,
  "ie_count": 5
}
```

### 5G NAS Message
```json
{
  "message_type_name": "Registration-Request",
  "supi": "SUCI-001010000000001",
  "is_5gmm": true,
  "security_header_type": 0
}
```
