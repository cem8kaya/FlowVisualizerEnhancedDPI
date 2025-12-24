class SessionDetailPage {
    constructor() {
        this.sessionId = null;
        this.jobId = null;
        this.sessionData = null;
        this.diagramData = null;
        this.ladderDiagram = null;
        this.init();
    }

    async init() {
        const params = new URLSearchParams(window.location.search);
        this.sessionId = params.get('session');
        this.jobId = params.get('job');

        if (!this.sessionId || !this.jobId) {
            window.Toast?.error('Missing session or job ID');
            return;
        }

        // Custom Tab Switching Implementation (Bypassing Bootstrap JS)
        const tabButtons = document.querySelectorAll('#sessionTabs button');
        const tabPanes = document.querySelectorAll('.tab-pane');

        const switchTab = (targetId) => {
            console.log('Switching to tab:', targetId);

            // Update buttons
            tabButtons.forEach(btn => {
                if (btn.getAttribute('data-target') === targetId) {
                    btn.classList.add('active');
                } else {
                    btn.classList.remove('active');
                }
            });

            // Update panes
            tabPanes.forEach(pane => {
                const paneId = `#${pane.id}`;
                if (paneId === targetId) {
                    pane.classList.add('active', 'show');
                    pane.style.display = 'block';

                    // Specific renders
                    if (pane.id === 'timeline') {
                        setTimeout(() => this.renderTimeline(), 50);
                    } else if (pane.id === 'flowchart') {
                        this.renderFlowchart();
                    }
                } else {
                    pane.classList.remove('active', 'show');
                    pane.style.display = 'none';
                }
            });
        };

        // Attach listeners
        tabButtons.forEach(btn => {
            // Clone button to remove any existing event listeners from Bootstrap/others
            const newBtn = btn.cloneNode(true);
            btn.parentNode.replaceChild(newBtn, btn);

            newBtn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation(); // Stop Bootstrap from interfering
                const target = newBtn.getAttribute('data-target');
                if (target) {
                    switchTab(target);
                }
            });
        });

        await this.loadSession();

        // Initialize first tab (usually timeline)
        // We use a slight delay to ensure everything is rendered
        setTimeout(() => {
            const activeBtn = document.querySelector('#sessionTabs button.active');
            if (activeBtn) {
                switchTab(activeBtn.getAttribute('data-target'));
            } else {
                // Fallback to timeline
                switchTab('#timeline');
            }
        }, 100);
    }

    async loadSession() {
        try {
            // Load session data
            const sessionRes = await window.app.getSession(this.sessionId, this.jobId);
            this.sessionData = sessionRes;

            if (!this.sessionData) {
                throw new Error('Session data is empty');
            }

            // Load diagram data
            let diagramValid = false;
            try {
                const diagramRes = await fetch(
                    `/api/v1/sessions/${this.sessionId}/diagram?job_id=${this.jobId}&format=ladder`
                );
                if (diagramRes.ok) {
                    const data = await diagramRes.json();
                    if (data && Array.isArray(data.participants) && Array.isArray(data.messages)) {
                        this.diagramData = data;
                        diagramValid = true;
                        console.log('Loaded diagram data from API');
                    }
                }
            } catch (e) {
                console.warn('Diagram API unavailable:', e);
            }

            // Fallback if API failed or returned invalid data
            if (!diagramValid) {
                console.log('Generating diagram from events (fallback)');
                this.diagramData = this.convertEventsToDiagram(this.sessionData.events);
            }

            // Render all sections
            this.renderHeader();
            this.renderEvents();
            this.renderTimeline();
            this.renderLadderDiagram();
            this.renderMetrics();

        } catch (e) {
            console.error('Failed to load session:', e);
            window.Toast?.error('Failed to load session data');
        }
    }

    renderHeader() {
        if (!this.sessionData) return;

        const updateText = (id, text) => {
            const el = document.getElementById(id);
            if (el) el.textContent = text;
        };

        const startTime = new Date(this.sessionData.start_time * 1000); // Assuming seconds
        const endTime = new Date(this.sessionData.end_time * 1000);
        const duration = ((this.sessionData.end_time - this.sessionData.start_time)).toFixed(3);

        // Handle potentially different timestamp formats
        const formatTime = (ts) => {
            if (!ts) return '-';
            const date = new Date(ts > 2000000000000 ? ts : ts * 1000); // Handle ms vs s
            return date.toLocaleString();
        };

        updateText('sessionId', this.sessionId);
        updateText('sessionType', this.sessionData.type || 'Unknown');
        updateText('startTime', formatTime(this.sessionData.start_time));
        updateText('duration', `${duration}s`);
        updateText('packetCount', this.sessionData.packet_count || this.sessionData.events?.length || 0);
        updateText('byteCount', window.app?.formatBytes(this.sessionData.byte_count || 0) || '0 B');

        // Render participants
        const participantsList = document.getElementById('participants');
        if (participantsList && this.diagramData?.participants) {
            participantsList.innerHTML = this.diagramData.participants.map(p => `
                <li class="mb-1">
                    <span class="badge bg-secondary me-2">${p.type}</span>
                    <span class="text-muted">${p.ip}:${p.port}</span>
                </li>
            `).join('');
        }
    }

    renderTimeline() {
        if (!this.diagramData || !window.timeline) return;

        window.timeline.init(
            'timelineViz',
            this.sessionData.events,
            this.diagramData.participants.map(p => `${p.ip}:${p.port}`)
        );
    }

    renderMetrics() {
        const tbody = document.getElementById('metricsTableBody');
        if (!tbody || !this.sessionData) return;

        const metrics = [
            ['Type', this.sessionData.type || 'Generic'],
            ['Start Time', new Date(this.sessionData.start_time * 1000).toISOString()],
            ['End Time', new Date(this.sessionData.end_time * 1000).toISOString()],
            ['Duration', `${(this.sessionData.end_time - this.sessionData.start_time).toFixed(3)}s`],
            ['Packets', this.sessionData.packet_count || this.sessionData.events?.length],
            ['Bytes', this.sessionData.byte_count],
            ['State', this.sessionData.state || 'Closed']
        ];

        tbody.innerHTML = metrics.map(([label, value]) => `
            <tr>
                <td class="text-secondary" width="150">${label}</td>
                <td class="font-monospace">${value}</td>
            </tr>
        `).join('');
    }

    renderFlowchart() {
        if (!window.flowchart || !this.sessionData?.events) return;

        console.log('Rendering flowchart...');
        window.flowchart.init('flowchartViz', this.sessionData.events);
    }

    onLadderMessageSelected(msg) {
        // Find the original event index
        const idx = this.sessionData.events.findIndex(e => e.timestamp === msg.timestamp);
        if (idx !== -1) {
            this.showEventInspector(idx);
        }
    }

    // Convert events to diagram format (fallback)
    convertEventsToDiagram(events) {
        if (!events || events.length === 0) return null;

        // Extract unique endpoints
        const endpoints = new Map();
        let order = 0;

        events.forEach(e => {
            const srcKey = `${e.src_ip || e.source_ip}:${e.src_port || e.source_port}`;
            const dstKey = `${e.dst_ip || e.dest_ip}:${e.dst_port || e.dest_port}`;

            if (!endpoints.has(srcKey)) {
                endpoints.set(srcKey, {
                    id: `p${order++}`,
                    ip: e.src_ip || e.source_ip,
                    port: e.src_port || e.source_port,
                    label: this.generateLabel(e.src_ip || e.source_ip, e.src_port || e.source_port),
                    type: this.guessType(e.src_port || e.source_port, e.protocol || e.proto)
                });
            }

            if (!endpoints.has(dstKey)) {
                endpoints.set(dstKey, {
                    id: `p${order++}`,
                    ip: e.dst_ip || e.dest_ip,
                    port: e.dst_port || e.dest_port,
                    label: this.generateLabel(e.dst_ip || e.dest_ip, e.dst_port || e.dest_port),
                    type: this.guessType(e.dst_port || e.dest_port, e.protocol || e.proto)
                });
            }
        });

        // Convert to participants array
        const participants = Array.from(endpoints.values());

        // Convert events to messages
        const messages = events.map((e, idx) => {
            const srcKey = `${e.src_ip || e.source_ip}:${e.src_port || e.source_port}`;
            const dstKey = `${e.dst_ip || e.dest_ip}:${e.dst_port || e.dest_port}`;

            return {
                id: `msg${idx}`,
                from: endpoints.get(srcKey).id,
                to: endpoints.get(dstKey).id,
                label: e.message_type || e.short || e.type || 'Unknown',
                protocol: e.protocol || e.proto || 'Unknown',
                timestamp: e.timestamp,
                details: e.details || {}
            };
        });

        return { participants, messages };
    }

    generateLabel(ip, port) {
        const portLabels = {
            5060: 'SIP',
            5061: 'SIP-TLS',
            3868: 'Diameter',
            2123: 'GTP-C',
            2152: 'GTP-U'
        };

        if (portLabels[port]) {
            return `${portLabels[port]}\n${ip}`;
        }

        // High ports = likely UE
        if (port > 10000) {
            return `UE\n${ip}`;
        }

        return ip;
    }

    guessType(port, protocol) {
        if (port === 5060 || port === 5061) return 'sip-proxy';
        if (port === 3868) return 'diameter';
        if (port === 2123) return 'gtp-c';
        if (port === 2152) return 'gtp-u';
        if (port > 10000) return 'endpoint';
        if (protocol === 'RTP') return 'media';
        return 'server';
    }

    renderLadderDiagram() {
        const container = document.getElementById('ladderDiagramContainer');
        if (!container) {
            console.error('Ladder diagram container not found');
            return;
        }

        if (!this.diagramData || !this.diagramData.participants ||
            this.diagramData.participants.length === 0) {
            console.log('No diagram data available for ladder');
            container.innerHTML = `
                <div class="empty-state">
                    <div class="empty-icon">📊</div>
                    No diagram data available
                </div>
            `;
            return;
        }

        console.log('Rendering ladder diagram...');

        // Clear and initialize
        container.innerHTML = '';

        // Create ladder diagram instance
        this.ladderDiagram = new LadderDiagram(container, {
            onMessageSelect: (msg) => this.onLadderMessageSelected(msg),
            colors: {
                SIP: '#3b82f6',
                DIAMETER: '#8b5cf6',
                GTP: '#f59e0b',
                RTP: '#10b981',
                HTTP2: '#ec4899'
            }
        });

        // Render the diagram
        this.ladderDiagram.render(this.diagramData);

        // Enable toolbar buttons
        this.enableDiagramControls();
    }

    enableDiagramControls() {
        const buttons = {
            'btnZoomIn': () => this.ladderDiagram?.zoomIn(),
            'btnZoomOut': () => this.ladderDiagram?.zoomOut(),
            'btnResetZoom': () => this.ladderDiagram?.resetZoom(),
            'btnExportSvg': () => this.ladderDiagram?.exportSVG(`session-${this.sessionId}.svg`),
            'btnExportPng': () => this.ladderDiagram?.exportPNG(`session-${this.sessionId}.png`, 2)
        };

        Object.entries(buttons).forEach(([id, handler]) => {
            const btn = document.getElementById(id);
            if (btn) {
                btn.disabled = false;
                btn.onclick = handler;
            }
        });
    }

    renderEvents() {
        const tbody = document.getElementById('eventsTableBody');
        if (!tbody) return;

        const events = this.sessionData?.events || [];

        if (events.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="5" class="text-center text-muted py-4">
                        No events found
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = events.map((e, idx) => `
            <tr class="event-row" onclick="window.sessionDetail.showEventInspector(${idx})">
                <td class="text-nowrap font-monospace small">
                    ${new Date(e.timestamp).toLocaleTimeString('en-US', {
            hour12: false,
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            fractionalSecondDigits: 3
        })}
                </td>
                <td>${window.ProtocolBadge?.render(e.protocol || e.proto) || e.protocol}</td>
                <td>${this.formatDirection(e)}</td>
                <td>${e.message_type || e.short || '-'}</td>
                <td class="text-end">
                    <button class="btn btn-sm btn-icon btn-ghost-primary">
                        <i class="bi bi-eye"></i>
                    </button>
                </td>
            </tr>
        `).join('');
    }

    formatDirection(event) {
        const src = event.src_ip || event.source_ip || '?';
        const dst = event.dst_ip || event.dest_ip || '?';
        return `${src} → ${dst}`;
    }

    showEventInspector(idx) {
        if (!this.sessionData?.events || idx >= this.sessionData.events.length) return;

        const event = this.sessionData.events[idx];

        // Initialize packet inspector if needed
        if (!window.packetInspector) {
            window.packetInspector = new PacketInspector();
        }

        window.packetInspector.show(event, this.sessionData.events, idx);
    }
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    window.sessionDetail = new SessionDetailPage();
});
