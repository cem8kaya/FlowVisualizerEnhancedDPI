#include "correlation/sip/sip_message.h"

#include <sstream>

namespace callflow {
namespace correlation {

std::string SipMessage::getDialogId() const {
    // Dialog ID = Call-ID + From-tag + To-tag
    // For early dialogs (no To-tag yet), use Call-ID + From-tag
    std::ostringstream oss;
    oss << call_id_;
    if (!from_tag_.empty()) {
        oss << ":" << from_tag_;
    }
    if (!to_tag_.empty()) {
        oss << ":" << to_tag_;
    }
    return oss.str();
}

std::string SipMessage::getTransactionId() const {
    // Transaction ID = Branch parameter from Via header + CSeq method
    // RFC 3261: branch must start with "z9hG4bK" for RFC 3261 compliance
    std::ostringstream oss;

    auto top_via = getTopVia();
    if (top_via.has_value() && !top_via->branch.empty()) {
        oss << top_via->branch;
    }

    oss << ":" << cseq_method_;

    return oss.str();
}

nlohmann::json SipMessage::toJson() const {
    nlohmann::json j;
    j["is_request"] = is_request_;

    if (is_request_) {
        j["method"] = method_;
        j["request_uri"] = request_uri_;
    } else {
        j["status_code"] = status_code_;
        j["reason_phrase"] = reason_phrase_;
    }

    j["call_id"] = call_id_;
    j["from"] = from_uri_;
    j["to"] = to_uri_;
    j["cseq"] = cseq_;
    j["cseq_method"] = cseq_method_;

    if (!from_tag_.empty())
        j["from_tag"] = from_tag_;
    if (!to_tag_.empty())
        j["to_tag"] = to_tag_;

    // Serialize Via headers
    if (!via_headers_.empty()) {
        nlohmann::json via_array = nlohmann::json::array();
        for (const auto& via : via_headers_) {
            nlohmann::json v;
            v["protocol"] = via.protocol;
            v["sent_by"] = via.sent_by;
            v["branch"] = via.branch;

            if (via.received.has_value())
                v["received"] = *via.received;
            if (via.rport.has_value())
                v["rport"] = *via.rport;
            v["index"] = via.index;

            via_array.push_back(v);
        }
        j["via"] = via_array;
    }

    // Network info
    j["source_ip"] = source_ip_;
    j["dest_ip"] = dest_ip_;
    j["source_port"] = source_port_;
    j["dest_port"] = dest_port_;
    j["timestamp"] = timestamp_;

    // Headers
    j["headers"] = headers_;

    // SDP
    if (sdp_body_.has_value()) {
        j["body"] = *sdp_body_;
    }

    return j;
}

}  // namespace correlation
}  // namespace callflow
