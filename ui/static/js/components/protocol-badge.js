/**
 * Protocol Badge Component
 * Renders a standardized badge for network protocols
 */
class ProtocolBadge {
    static getProtocolClass(protocol) {
        const map = {
            'SIP': 'badge-sip',
            'RTP': 'badge-rtp',
            'GTP': 'badge-gtp',
            'GTPV2': 'badge-gtp',
            'DIAMETER': 'badge-diameter',
            'HTTP2': 'badge-http2',
            'NGAP': 'badge-ngap',
            'S1AP': 'badge-s1ap'
        };
        return map[protocol.toUpperCase()] || 'badge-neutral';
    }

    static render(protocol) {
        if (!protocol) return '';
        const className = this.getProtocolClass(protocol);
        return `<span class="badge badge-protocol ${className}">${protocol}</span>`;
    }
}

// Export for module usage if using modules, but for now attaching to window for simplicity
window.ProtocolBadge = ProtocolBadge;
