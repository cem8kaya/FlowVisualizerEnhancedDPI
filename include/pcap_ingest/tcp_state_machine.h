#pragma once

#include <cstdint>
#include "tcp_reassembly.h"

namespace callflow {

/**
 * TCP State Machine
 * Handles TCP connection state transitions according to RFC 793
 */
class TcpStateMachine {
public:
    /**
     * Process TCP flags and update state
     * @param state Current stream state (will be updated)
     * @param flags TCP flags from packet
     * @param is_client True if packet is from client
     * @return True if state was changed
     */
    static bool processFlags(TcpStreamState& state, uint8_t flags, bool is_client);

    /**
     * Check if connection is established
     */
    static bool isEstablished(const TcpStreamState& state);

    /**
     * Check if connection is closed
     */
    static bool isClosed(const TcpStreamState& state);

    /**
     * Check if connection is in closing state
     */
    static bool isClosing(const TcpStreamState& state);

private:
    static void handleSynInClosed(TcpStreamState& state, bool is_client);
    static void handleSynAckInSynSent(TcpStreamState& state);
    static void handleAckInSynReceived(TcpStreamState& state);
    static void handleFinInEstablished(TcpStreamState& state, bool is_client);
    static void handleRst(TcpStreamState& state);
};

}  // namespace callflow
