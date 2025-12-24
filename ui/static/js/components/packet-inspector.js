class PacketInspector {
    constructor() {
        this.modal = null;
        this.currentEvent = null;
        this.allEvents = [];
        this.currentIndex = 0;
        this.createModal();
    }

    createModal() {
        // Check if modal already exists
        if (document.getElementById('packetInspectorModal')) {
            this.modal = document.getElementById('packetInspectorModal');
            return;
        }

        const modalHtml = `
            <div class="modal fade" id="packetInspectorModal" tabindex="-1">
                <div class="modal-dialog modal-lg modal-dialog-centered">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">
                                <i class="bi bi-search me-2"></i>
                                Packet Inspector
                            </h5>
                            <div class="ms-auto d-flex align-items-center gap-2">
                                <button class="btn btn-sm btn-outline-secondary" id="btnPrevPacket">
                                    <i class="bi bi-chevron-left"></i>
                                </button>
                                <span class="badge bg-secondary" id="packetPosition">1/1</span>
                                <button class="btn btn-sm btn-outline-secondary" id="btnNextPacket">
                                    <i class="bi bi-chevron-right"></i>
                                </button>
                                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                            </div>
                        </div>
                        <div class="modal-body p-0">
                            <ul class="nav nav-tabs nav-tabs-flush" role="tablist">
                                <li class="nav-item">
                                    <button class="nav-link active" data-bs-toggle="tab" data-bs-target="#decoded">Decoded</button>
                                </li>
                                <li class="nav-item">
                                    <button class="nav-link" data-bs-toggle="tab" data-bs-target="#raw">Raw Data</button>
                                </li>
                                <li class="nav-item">
                                    <button class="nav-link" data-bs-toggle="tab" data-bs-target="#headers">Headers</button>
                                </li>
                            </ul>
                            <div class="tab-content">
                                <div class="tab-pane fade show active p-3" id="decoded">
                                    <div class="code-block" id="decodedContent"></div>
                                </div>
                                <div class="tab-pane fade p-3" id="raw">
                                    <pre class="code-block json" id="rawContent"></pre>
                                </div>
                                <div class="tab-pane fade" id="headers">
                                    <div class="table-responsive">
                                        <table class="table table-sm table-striped mb-0" id="headersTable">
                                            <tbody></tbody>
                                        </table>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;

        document.body.insertAdjacentHTML('beforeend', modalHtml);
        this.modal = document.getElementById('packetInspectorModal');

        // Setup navigation
        document.getElementById('btnPrevPacket').onclick = () => this.previous();
        document.getElementById('btnNextPacket').onclick = () => this.next();

        // Keyboard navigation
        this.modal.addEventListener('keydown', (e) => {
            if (e.key === 'ArrowLeft') this.previous();
            if (e.key === 'ArrowRight') this.next();
        });
    }

    show(event, allEvents = [], index = 0) {
        this.currentEvent = event;
        this.allEvents = allEvents;
        this.currentIndex = index;

        this.render();

        const bsModal = new bootstrap.Modal(this.modal);
        bsModal.show();
    }

    render() {
        // Update position indicator
        document.getElementById('packetPosition').textContent =
            `${this.currentIndex + 1}/${this.allEvents.length}`;

        // Update navigation buttons
        document.getElementById('btnPrevPacket').disabled = this.currentIndex === 0;
        document.getElementById('btnNextPacket').disabled =
            this.currentIndex >= this.allEvents.length - 1;

        // Render decoded content
        const decoded = document.getElementById('decodedContent');
        decoded.innerHTML = this.renderDecoded(this.currentEvent);

        // Render raw content
        const raw = document.getElementById('rawContent');
        raw.textContent = JSON.stringify(this.currentEvent, null, 2);

        // Render headers table
        const headers = document.getElementById('headersTable').querySelector('tbody');
        headers.innerHTML = this.renderHeaders(this.currentEvent);
    }

    renderDecoded(event) {
        const protocol = event.protocol || event.proto || 'Unknown';
        const timestamp = new Date(event.timestamp).toISOString();

        let html = `
            <div class="d-flex align-items-center mb-3">
                <span class="badge bg-primary me-2">${protocol}</span>
                <span class="text-muted small">${timestamp}</span>
            </div>
            <div class="card bg-light mb-3">
                <div class="card-body py-2">
                    <small class="text-uppercase text-muted fw-bold">Direction</small>
                    <div class="d-flex align-items-center mt-1">
                        <span class="font-monospace">${event.src_ip || event.source_ip}:${event.src_port || event.source_port}</span> 
                        <i class="bi bi-arrow-right mx-2 text-muted"></i>
                        <span class="font-monospace">${event.dst_ip || event.dest_ip}:${event.dst_port || event.dest_port}</span>
                    </div>
                </div>
            </div>
        `;

        if (event.message_type) {
            html += `<div class="mb-2"><strong>Message Type:</strong> ${event.message_type}</div>`;
        }

        if (event.details && Object.keys(event.details).length > 0) {
            html += `<h6 class="mt-3">Details</h6>`;
            html += `<pre class="bg-light p-2 rounded">${JSON.stringify(event.details, null, 2)}</pre>`;
        }

        return html;
    }

    renderHeaders(event) {
        const fields = [
            ['Timestamp', new Date(event.timestamp).toISOString()],
            ['Protocol', event.protocol || event.proto],
            ['Source IP', event.src_ip || event.source_ip],
            ['Source Port', event.src_port || event.source_port],
            ['Dest IP', event.dst_ip || event.dest_ip],
            ['Dest Port', event.dst_port || event.dest_port],
            ['Message Type', event.message_type || event.short],
            ['Direction', event.direction]
        ];

        return fields
            .filter(([_, v]) => v !== undefined && v !== null)
            .map(([k, v]) => `<tr><th width="150">${k}</th><td>${v}</td></tr>`)
            .join('');
    }

    previous() {
        if (this.currentIndex > 0) {
            this.currentIndex--;
            this.currentEvent = this.allEvents[this.currentIndex];
            this.render();
        }
    }

    next() {
        if (this.currentIndex < this.allEvents.length - 1) {
            this.currentIndex++;
            this.currentEvent = this.allEvents[this.currentIndex];
            this.render();
        }
    }
}

window.PacketInspector = PacketInspector;
window.packetInspector = new PacketInspector();
