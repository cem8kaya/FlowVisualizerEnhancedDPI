#include "pcap_ingest/tcp_state_machine.h"

#include "common/logger.h"

namespace callflow {

bool TcpStateMachine::processFlags(TcpStreamState& state, uint8_t flags, bool is_client) {
    auto old_state = state.state;

    // Handle RST
    if (flags & TCP_FLAG_RST) {
        handleRst(state);
        return state.state != old_state;
    }

    // Handle based on current state
    switch (state.state) {
        case TcpStreamState::State::CLOSED:
            if (flags & TCP_FLAG_SYN) {
                handleSynInClosed(state, is_client);
            }
            break;

        case TcpStreamState::State::SYN_SENT:
            if ((flags & TCP_FLAG_SYN) && (flags & TCP_FLAG_ACK)) {
                handleSynAckInSynSent(state);
            }
            break;

        case TcpStreamState::State::SYN_RECEIVED:
            if (flags & TCP_FLAG_ACK) {
                handleAckInSynReceived(state);
            }
            break;

        case TcpStreamState::State::ESTABLISHED:
            if (flags & TCP_FLAG_FIN) {
                handleFinInEstablished(state, is_client);
            }
            break;

        case TcpStreamState::State::FIN_WAIT_1:
            if (flags & TCP_FLAG_ACK) {
                state.state = TcpStreamState::State::FIN_WAIT_2;
                LOG_DEBUG("TCP state: FIN_WAIT_1 -> FIN_WAIT_2");
            } else if (flags & TCP_FLAG_FIN) {
                state.state = TcpStreamState::State::CLOSING;
                LOG_DEBUG("TCP state: FIN_WAIT_1 -> CLOSING");
            }
            break;

        case TcpStreamState::State::FIN_WAIT_2:
            if (flags & TCP_FLAG_FIN) {
                state.state = TcpStreamState::State::TIME_WAIT;
                LOG_DEBUG("TCP state: FIN_WAIT_2 -> TIME_WAIT");
            }
            break;

        case TcpStreamState::State::CLOSE_WAIT:
            if (flags & TCP_FLAG_FIN) {
                state.state = TcpStreamState::State::LAST_ACK;
                LOG_DEBUG("TCP state: CLOSE_WAIT -> LAST_ACK");
            }
            break;

        case TcpStreamState::State::CLOSING:
            if (flags & TCP_FLAG_ACK) {
                state.state = TcpStreamState::State::TIME_WAIT;
                LOG_DEBUG("TCP state: CLOSING -> TIME_WAIT");
            }
            break;

        case TcpStreamState::State::LAST_ACK:
            if (flags & TCP_FLAG_ACK) {
                state.state = TcpStreamState::State::CLOSED;
                LOG_DEBUG("TCP state: LAST_ACK -> CLOSED");
            }
            break;

        case TcpStreamState::State::TIME_WAIT:
            // Wait for timeout (handled by cleanup)
            break;
    }

    return state.state != old_state;
}

bool TcpStateMachine::isEstablished(const TcpStreamState& state) {
    return state.state == TcpStreamState::State::ESTABLISHED;
}

bool TcpStateMachine::isClosed(const TcpStreamState& state) {
    return state.state == TcpStreamState::State::CLOSED;
}

bool TcpStateMachine::isClosing(const TcpStreamState& state) {
    return state.state == TcpStreamState::State::FIN_WAIT_1 ||
           state.state == TcpStreamState::State::FIN_WAIT_2 ||
           state.state == TcpStreamState::State::CLOSE_WAIT ||
           state.state == TcpStreamState::State::CLOSING ||
           state.state == TcpStreamState::State::LAST_ACK ||
           state.state == TcpStreamState::State::TIME_WAIT;
}

void TcpStateMachine::handleSynInClosed(TcpStreamState& state, bool is_client) {
    if (is_client) {
        state.state = TcpStreamState::State::SYN_SENT;
        LOG_DEBUG("TCP state: CLOSED -> SYN_SENT (client)");
    } else {
        // Simultaneous open (rare) or server initiated
        state.state = TcpStreamState::State::SYN_RECEIVED;
        LOG_DEBUG("TCP state: CLOSED -> SYN_RECEIVED (server)");
    }
}

void TcpStateMachine::handleSynAckInSynSent(TcpStreamState& state) {
    state.state = TcpStreamState::State::SYN_RECEIVED;
    LOG_DEBUG("TCP state: SYN_SENT -> SYN_RECEIVED");
}

void TcpStateMachine::handleAckInSynReceived(TcpStreamState& state) {
    state.state = TcpStreamState::State::ESTABLISHED;
    LOG_DEBUG("TCP state: SYN_RECEIVED -> ESTABLISHED");
}

void TcpStateMachine::handleFinInEstablished(TcpStreamState& state, bool is_client) {
    if (is_client) {
        state.state = TcpStreamState::State::FIN_WAIT_1;
        LOG_DEBUG("TCP state: ESTABLISHED -> FIN_WAIT_1 (client FIN)");
    } else {
        state.state = TcpStreamState::State::CLOSE_WAIT;
        LOG_DEBUG("TCP state: ESTABLISHED -> CLOSE_WAIT (server FIN)");
    }
}

void TcpStateMachine::handleRst(TcpStreamState& state) {
    state.state = TcpStreamState::State::CLOSED;
    LOG_DEBUG("TCP state: RST -> CLOSED");
}

}  // namespace callflow
