#pragma once

#include "correlation/sip/sip_types.h"
#include <string>
#include <unordered_map>
#include <vector>
#include <optional>

namespace callflow {
namespace correlation {

/**
 * @brief Represents a SIP message (request or response)
 *
 * This class holds parsed SIP message data extracted from nDPI.
 * It supports both SIP requests (INVITE, REGISTER, etc.) and
 * responses (1xx, 2xx, 3xx, 4xx, 5xx, 6xx).
 */
class SipMessage {
public:
    SipMessage() = default;
    ~SipMessage() = default;

    // Message type
    bool isRequest() const { return is_request_; }
    bool isResponse() const { return !is_request_; }

    void setRequest(bool is_request) { is_request_ = is_request; }

    // Request line
    void setMethod(const std::string& method) { method_ = method; }
    std::string getMethod() const { return method_; }

    void setRequestUri(const std::string& uri) { request_uri_ = uri; }
    std::string getRequestUri() const { return request_uri_; }

    // Status line (for responses)
    void setStatusCode(int code) { status_code_ = code; }
    int getStatusCode() const { return status_code_; }

    void setReasonPhrase(const std::string& reason) { reason_phrase_ = reason; }
    std::string getReasonPhrase() const { return reason_phrase_; }

    // Essential headers
    void setCallId(const std::string& call_id) { call_id_ = call_id; }
    std::string getCallId() const { return call_id_; }

    void setFromUri(const std::string& uri) { from_uri_ = uri; }
    std::string getFromUri() const { return from_uri_; }

    void setFromTag(const std::string& tag) { from_tag_ = tag; }
    std::string getFromTag() const { return from_tag_; }

    void setToUri(const std::string& uri) { to_uri_ = uri; }
    std::string getToUri() const { return to_uri_; }

    void setToTag(const std::string& tag) { to_tag_ = tag; }
    std::string getToTag() const { return to_tag_; }

    void setCSeq(uint32_t cseq) { cseq_ = cseq; }
    uint32_t getCSeq() const { return cseq_; }

    void setCSeqMethod(const std::string& method) { cseq_method_ = method; }
    std::string getCSeqMethod() const { return cseq_method_; }

    // Via headers (list, topmost first)
    void addViaHeader(const SipViaHeader& via) { via_headers_.push_back(via); }
    const std::vector<SipViaHeader>& getViaHeaders() const { return via_headers_; }
    std::optional<SipViaHeader> getTopVia() const {
        if (!via_headers_.empty()) {
            return via_headers_[0];
        }
        return std::nullopt;
    }

    // Contact header
    void setContactHeader(const SipContactHeader& contact) { contact_ = contact; }
    std::optional<SipContactHeader> getContactHeader() const { return contact_; }

    // P-Asserted-Identity (PAI)
    void setPAssertedIdentity(const std::string& pai) { p_asserted_identity_ = pai; }
    std::optional<std::string> getPAssertedIdentity() const { return p_asserted_identity_; }

    // P-Preferred-Identity (PPI)
    void setPPreferredIdentity(const std::string& ppi) { p_preferred_identity_ = ppi; }
    std::optional<std::string> getPPreferredIdentity() const { return p_preferred_identity_; }

    // SDP body
    void setSdpBody(const std::string& sdp) { sdp_body_ = sdp; }
    std::optional<std::string> getSdpBody() const { return sdp_body_; }

    // Media information extracted from SDP
    void addMediaInfo(const SipMediaInfo& media) { media_info_.push_back(media); }
    const std::vector<SipMediaInfo>& getMediaInfo() const { return media_info_; }

    // Generic headers
    void setHeader(const std::string& name, const std::string& value) {
        headers_[name] = value;
    }
    std::optional<std::string> getHeader(const std::string& name) const {
        auto it = headers_.find(name);
        if (it != headers_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    // Frame and timing information
    void setFrameNumber(uint32_t frame) { frame_number_ = frame; }
    uint32_t getFrameNumber() const { return frame_number_; }

    void setTimestamp(double timestamp) { timestamp_ = timestamp; }
    double getTimestamp() const { return timestamp_; }

    void setSourceIp(const std::string& ip) { source_ip_ = ip; }
    std::string getSourceIp() const { return source_ip_; }

    void setDestIp(const std::string& ip) { dest_ip_ = ip; }
    std::string getDestIp() const { return dest_ip_; }

    void setSourcePort(uint16_t port) { source_port_ = port; }
    uint16_t getSourcePort() const { return source_port_; }

    void setDestPort(uint16_t port) { dest_port_ = port; }
    uint16_t getDestPort() const { return dest_port_; }

    // Helper methods
    bool hasToTag() const { return !to_tag_.empty(); }
    bool isInvite() const { return method_ == "INVITE"; }
    bool isRegister() const { return method_ == "REGISTER"; }
    bool isAck() const { return method_ == "ACK"; }
    bool isBye() const { return method_ == "BYE"; }
    bool isCancel() const { return method_ == "CANCEL"; }
    bool isMessage() const { return method_ == "MESSAGE"; }
    bool isProvisional() const { return status_code_ >= 100 && status_code_ < 200; }
    bool isSuccess() const { return status_code_ >= 200 && status_code_ < 300; }
    bool isRedirection() const { return status_code_ >= 300 && status_code_ < 400; }
    bool isClientError() const { return status_code_ >= 400 && status_code_ < 500; }
    bool isServerError() const { return status_code_ >= 500 && status_code_ < 600; }
    bool isGlobalFailure() const { return status_code_ >= 600 && status_code_ < 700; }
    bool isError() const { return status_code_ >= 400; }

    // Dialog key generation
    std::string getDialogId() const;
    std::string getTransactionId() const;

private:
    // Message type
    bool is_request_ = true;

    // Request line
    std::string method_;
    std::string request_uri_;

    // Status line
    int status_code_ = 0;
    std::string reason_phrase_;

    // Essential headers
    std::string call_id_;
    std::string from_uri_;
    std::string from_tag_;
    std::string to_uri_;
    std::string to_tag_;
    uint32_t cseq_ = 0;
    std::string cseq_method_;

    // Via headers
    std::vector<SipViaHeader> via_headers_;

    // Contact header
    std::optional<SipContactHeader> contact_;

    // Identity headers
    std::optional<std::string> p_asserted_identity_;
    std::optional<std::string> p_preferred_identity_;

    // SDP
    std::optional<std::string> sdp_body_;
    std::vector<SipMediaInfo> media_info_;

    // Generic headers
    std::unordered_map<std::string, std::string> headers_;

    // Frame and timing
    uint32_t frame_number_ = 0;
    double timestamp_ = 0.0;
    std::string source_ip_;
    std::string dest_ip_;
    uint16_t source_port_ = 0;
    uint16_t dest_port_ = 0;
};

} // namespace correlation
} // namespace callflow
