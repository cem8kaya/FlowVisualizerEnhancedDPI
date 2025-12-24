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

} // namespace correlation
} // namespace callflow
