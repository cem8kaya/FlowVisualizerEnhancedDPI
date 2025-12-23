/**
 * Session Card Component
 * Renders a compact session summary card
 */
class SessionCard {
    /**
     * Render a session card
     * @param {Object} session - Session data object
     * @param {Function} onClick - Optional click handler
     * @returns {string} HTML string for the session card
     */
    static render(session, onClick = null) {
        const {
            session_id,
            protocol = 'Unknown',
            src_ip = '-',
            dst_ip = '-',
            packets = 0,
            bytes = 0,
            duration = 0,
            imsi = null,
            msisdn = null,
            mos_score = null
        } = session;

        const protocolBadge = window.ProtocolBadge
            ? window.ProtocolBadge.render(protocol)
            : `<span class="badge">${protocol}</span>`;

        const formattedBytes = window.app
            ? window.app.formatBytes(bytes)
            : `${bytes} B`;

        const formattedDuration = window.app
            ? window.app.formatDuration(duration)
            : `${duration}ms`;

        const clickHandler = onClick ? `onclick="(${onClick.toString()})(${JSON.stringify(session)})"` : '';
        const cursorStyle = onClick ? 'cursor: pointer;' : '';

        // Quality indicator for VoLTE sessions
        const qualityIndicator = mos_score !== null ? this.renderQualityIndicator(mos_score) : '';

        return `
            <div class="session-card" ${clickHandler} style="${cursorStyle}">
                <div class="session-card-header">
                    <span class="session-id">${session_id || 'N/A'}</span>
                    ${protocolBadge}
                </div>
                <div class="session-card-body">
                    ${imsi ? `<div class="session-metric">
                        <span class="metric-label">IMSI:</span>
                        <span class="metric-value font-mono text-sm">${imsi}</span>
                    </div>` : ''}
                    ${msisdn ? `<div class="session-metric">
                        <span class="metric-label">MSISDN:</span>
                        <span class="metric-value font-mono text-sm">${msisdn}</span>
                    </div>` : ''}
                    <div class="session-metric">
                        <span class="metric-label">Source:</span>
                        <span class="metric-value font-mono text-sm">${src_ip}</span>
                    </div>
                    <div class="session-metric">
                        <span class="metric-label">Destination:</span>
                        <span class="metric-value font-mono text-sm">${dst_ip}</span>
                    </div>
                    <div class="session-metric">
                        <span class="metric-label">Packets:</span>
                        <span class="metric-value">${packets.toLocaleString()}</span>
                    </div>
                    <div class="session-metric">
                        <span class="metric-label">Data:</span>
                        <span class="metric-value">${formattedBytes}</span>
                    </div>
                    <div class="session-metric">
                        <span class="metric-label">Duration:</span>
                        <span class="metric-value">${formattedDuration}</span>
                    </div>
                    ${qualityIndicator}
                </div>
            </div>
        `;
    }

    /**
     * Render quality indicator for VoLTE calls
     * @param {number} mosScore - MOS score (1-5)
     * @returns {string} HTML string for quality indicator
     */
    static renderQualityIndicator(mosScore) {
        let qualityClass = 'badge-error';
        let qualityText = 'Poor';

        if (mosScore >= 4.0) {
            qualityClass = 'badge-success';
            qualityText = 'Excellent';
        } else if (mosScore >= 3.5) {
            qualityClass = 'badge-success';
            qualityText = 'Good';
        } else if (mosScore >= 3.0) {
            qualityClass = 'badge-warning';
            qualityText = 'Fair';
        }

        return `
            <div class="session-metric">
                <span class="metric-label">Quality:</span>
                <span class="badge badge-status ${qualityClass}">${qualityText} (${mosScore.toFixed(2)})</span>
            </div>
        `;
    }

    /**
     * Render a grid of session cards
     * @param {Array} sessions - Array of session objects
     * @param {string} containerId - ID of container element
     * @param {Function} onCardClick - Optional click handler for each card
     */
    static renderGrid(sessions, containerId, onCardClick = null) {
        const container = document.getElementById(containerId);
        if (!container) {
            console.error(`Container ${containerId} not found`);
            return;
        }

        if (!sessions || sessions.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <div class="empty-state-icon">
                        <i class="bi bi-inbox"></i>
                    </div>
                    <h3>No Sessions Found</h3>
                    <p>No sessions match the current filters.</p>
                </div>
            `;
            return;
        }

        const cardsHTML = sessions.map(session => this.render(session, onCardClick)).join('');
        container.innerHTML = `<div class="grid grid-cols-3">${cardsHTML}</div>`;
    }

    /**
     * Render loading skeleton for session cards
     * @param {number} count - Number of skeleton cards to show
     * @returns {string} HTML string for skeleton cards
     */
    static renderSkeleton(count = 6) {
        const skeletonCard = `
            <div class="session-card">
                <div class="session-card-header">
                    <div class="skeleton skeleton-text" style="width: 80px;"></div>
                    <div class="skeleton skeleton-text" style="width: 60px;"></div>
                </div>
                <div class="session-card-body">
                    <div class="skeleton skeleton-text"></div>
                    <div class="skeleton skeleton-text"></div>
                    <div class="skeleton skeleton-text"></div>
                    <div class="skeleton skeleton-text"></div>
                </div>
            </div>
        `;

        return `<div class="grid grid-cols-3">${skeletonCard.repeat(count)}</div>`;
    }
}

window.SessionCard = SessionCard;
