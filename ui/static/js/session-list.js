// Session List and Detail View

const sessionView = {
    sessionId: null,
    sessionData: null,

    async init() {
        // Get session ID from URL
        const params = new URLSearchParams(window.location.search);
        this.sessionId = params.get('session');
        this.jobId = params.get('job');

        if (!this.sessionId) {
            app.showToast('No session ID provided', 'error');
            return;
        }

        this.updateBackLink();
        await this.loadSession();
    },

    updateBackLink() {
        if (this.jobId) {
            const backLink = document.getElementById('backLink');
            if (backLink) {
                backLink.href = `/sessions.html?job=${this.jobId}`;
                backLink.innerHTML = '<i class="bi bi-arrow-left"></i> Back to Job';
            }
        }
    },

    async loadSession() {
        try {
            this.sessionData = await app.getSession(this.sessionId);
            this.renderSessionInfo();
            this.renderEvents();
            this.renderEvents();
            this.renderTimeline();
            this.renderFlowchart();
            this.renderMetrics();
        } catch (error) {
            console.error('Failed to load session:', error);
            app.showToast('Failed to load session data', 'error');
        }
    },

    renderSessionInfo() {
        if (!this.sessionData) return;

        document.getElementById('sessionId').textContent = this.sessionData.session_id || '-';
        document.getElementById('sessionType').textContent = this.sessionData.type || '-';
        document.getElementById('startTime').textContent = app.formatTimestamp(this.sessionData.start_time);
        document.getElementById('duration').textContent = app.formatDuration(this.sessionData.metrics?.duration_ms);
        document.getElementById('packetCount').textContent = this.sessionData.metrics?.packets || 0;
        document.getElementById('byteCount').textContent = app.formatBytes(this.sessionData.metrics?.bytes || 0);

        // Render participants
        const participantsList = document.getElementById('participants');
        if (this.sessionData.participants && this.sessionData.participants.length > 0) {
            participantsList.innerHTML = this.sessionData.participants
                .map(p => `<li>${p}</li>`)
                .join('');
        } else {
            participantsList.innerHTML = '<li class="text-muted">None</li>';
        }
    },

    renderEvents() {
        const tbody = document.getElementById('eventsTableBody');
        if (!tbody || !this.sessionData || !this.sessionData.events) return;

        if (this.sessionData.events.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No events</td></tr>';
            return;
        }

        tbody.innerHTML = this.sessionData.events.map((event, index) => `
            <tr class="cursor-pointer" onclick="sessionView.showEventDetails(${index})">
                <td><small class="font-monospace">${new Date(event.timestamp).toLocaleTimeString()}</small></td>
                <td><span class="badge bg-secondary">${event.proto || event.protocol || 'UNKNOWN'}</span></td>
                <td>${event.message_type || '-'}</td>
                <td><small>${event.src_ip}:${event.src_port}</small></td>
                <td><small>${event.dst_ip}:${event.dst_port}</small></td>
                <td><small class="text-muted">${event.short || '-'}</small></td>
            </tr>
        `).join('');
    },

    renderTimeline() {
        if (!this.sessionData || !this.sessionData.events) return;

        // Extract unique participants
        const participants = new Set();
        this.sessionData.events.forEach(event => {
            participants.add(`${event.src_ip}:${event.src_port}`);
            participants.add(`${event.dst_ip}:${event.dst_port}`);
        });

        // Initialize timeline
        timeline.init('timelineViz', this.sessionData.events, Array.from(participants));
    },

    renderFlowchart() {
        if (!this.sessionData || !this.sessionData.events) return;
        flowchart.init('flowchartViz', this.sessionData.events);
    },

    renderMetrics() {
        const tbody = document.getElementById('metricsTableBody');
        if (!tbody || !this.sessionData || !this.sessionData.metrics) return;

        const metrics = this.sessionData.metrics;
        tbody.innerHTML = `
            <tr>
                <th>Total Packets</th>
                <td>${metrics.packets || 0}</td>
            </tr>
            <tr>
                <th>Total Bytes</th>
                <td>${app.formatBytes(metrics.bytes || 0)}</td>
            </tr>
            <tr>
                <th>Duration</th>
                <td>${app.formatDuration(metrics.duration_ms)}</td>
            </tr>
            ${metrics.rtp_loss !== undefined ? `
            <tr>
                <th>RTP Packet Loss</th>
                <td>${(metrics.rtp_loss * 100).toFixed(2)}%</td>
            </tr>
            ` : ''}
            ${metrics.rtp_jitter_ms !== undefined ? `
            <tr>
                <th>RTP Jitter</th>
                <td>${metrics.rtp_jitter_ms.toFixed(2)} ms</td>
            </tr>
            ` : ''}
            ${metrics.setup_time_ms !== undefined ? `
            <tr>
                <th>Setup Time</th>
                <td>${metrics.setup_time_ms} ms</td>
            </tr>
            ` : ''}
        `;
    },

    showEventDetails(index) {
        if (!this.sessionData || !this.sessionData.events[index]) return;

        const event = this.sessionData.events[index];
        if (typeof packetInspector !== 'undefined') {
            packetInspector.show(event, this.sessionData.events, index);
        }
    }
};

// Initialize on session page
if (window.location.pathname.includes('session.html')) {
    document.addEventListener('DOMContentLoaded', () => {
        sessionView.init();
    });
}
