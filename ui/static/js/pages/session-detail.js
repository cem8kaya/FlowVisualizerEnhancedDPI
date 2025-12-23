/**
 * Session Detail Page Logic
 */
class SessionDetailPage {
    constructor() {
        this.sessionId = new URLSearchParams(window.location.search).get('session');
        this.jobId = new URLSearchParams(window.location.search).get('job');
        this.sessionData = null;

        this.init();
    }

    async init() {
        if (!this.sessionId) {
            window.Toast.error('No session ID provided');
            return;
        }

        this.updateBackLink();
        await this.loadSession();

        // Initialize interactive elements if any
    }

    updateBackLink() {
        if (this.jobId) {
            const backLink = document.getElementById('backLink');
            if (backLink) {
                backLink.href = `/sessions.html?job=${this.jobId}`;
            }
        }
    }

    async loadSession() {
        try {
            // Pass jobId if available to help backend locate the session
            this.sessionData = await window.app.getSession(this.sessionId, this.jobId);
            this.renderHeader();
            this.renderEvents();
            this.renderTimeline();
            this.renderFlowchart();
            this.renderMetrics();
        } catch (e) {
            console.error(e);
            window.Toast.error('Failed to load session data');
        }
    }

    renderHeader() {
        if (!this.sessionData) return;

        const setText = (id, val) => {
            const el = document.getElementById(id);
            if (el) el.textContent = val;
        };

        setText('sessionId', this.sessionData.session_id || '-');
        setText('sessionType', this.sessionData.type || '-');
        setText('startTime', window.app.formatTimestamp(this.sessionData.start_time));
        setText('duration', window.app.formatDuration(this.sessionData.metrics?.duration_ms));
        setText('packetCount', this.sessionData.metrics?.packets || 0);
        setText('byteCount', window.app.formatBytes(this.sessionData.metrics?.bytes || 0));

        const participants = document.getElementById('participants');
        if (participants) {
            if (this.sessionData.participants?.length > 0) {
                participants.innerHTML = this.sessionData.participants.map(p => `<li>${p}</li>`).join('');
            } else {
                participants.innerHTML = '<li class="text-secondary opacity-50">None</li>';
            }
        }
    }

    renderEvents() {
        const tbody = document.getElementById('eventsTableBody');
        if (!tbody || !this.sessionData?.events) return;

        tbody.innerHTML = this.sessionData.events.map((e, idx) => `
            <tr class="cursor-pointer hover:bg-tertiary" onclick="sessionDetail.showEventInspector(${idx})">
                <td class="font-mono text-xs">${new Date(e.timestamp).toLocaleTimeString()}</td>
                <td>${window.ProtocolBadge.render(e.proto || e.protocol)}</td>
                <td>${e.message_type || '-'}</td>
                <td class="font-mono text-xs">${e.src_ip}:${e.src_port}</td>
                <td class="font-mono text-xs">${e.dst_ip}:${e.dst_port}</td>
                <td class="text-sm text-secondary truncate" style="max-width: 300px;">${e.short || '-'}</td>
            </tr>
        `).join('');
    }

    renderTimeline() {
        if (!window.timeline || !this.sessionData?.events) return;

        const participants = new Set();
        this.sessionData.events.forEach(e => {
            participants.add(`${e.src_ip}:${e.src_port}`);
            participants.add(`${e.dst_ip}:${e.dst_port}`);
        });

        window.timeline.init('timelineViz', this.sessionData.events, Array.from(participants));
    }

    renderFlowchart() {
        if (!window.flowchart || !this.sessionData?.events) return;
        window.flowchart.init('flowchartViz', this.sessionData.events);
    }

    renderMetrics() {
        const tbody = document.getElementById('metricsTableBody');
        if (!tbody || !this.sessionData?.metrics) return;

        const m = this.sessionData.metrics;
        const rows = [
            ['Total Packets', m.packets || 0],
            ['Total Bytes', window.app.formatBytes(m.bytes || 0)],
            ['Duration', window.app.formatDuration(m.duration_ms)],
            ['RTP Packet Loss', m.rtp_loss !== undefined ? `${(m.rtp_loss * 100).toFixed(2)}%` : null],
            ['RTP Jitter', m.rtp_jitter_ms !== undefined ? `${m.rtp_jitter_ms.toFixed(2)} ms` : null],
            ['Setup Time', m.setup_time_ms !== undefined ? `${m.setup_time_ms} ms` : null]
        ];

        tbody.innerHTML = rows.filter(r => r[1] !== null).map(([label, val]) => `
            <tr>
                <th class="w-1/3 text-secondary text-sm font-medium">${label}</th>
                <td class="font-mono text-sm">${val}</td>
            </tr>
        `).join('');

        // Charts initialization could go here if using Chart.js
    }

    showEventInspector(idx) {
        if (window.packetInspector) {
            window.packetInspector.show(this.sessionData.events[idx], this.sessionData.events, idx);
        }
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.sessionDetail = new SessionDetailPage();
});
