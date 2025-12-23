// Packet Inspector Modal

window.packetInspector = {
    currentEvent: null,
    allEvents: [],
    currentIndex: 0,
    modal: null,

    init() {
        this.modal = new bootstrap.Modal(document.getElementById('packetModal'));

        // Navigation buttons
        document.getElementById('prevPacketBtn')?.addEventListener('click', () => {
            this.navigate(-1);
        });

        document.getElementById('nextPacketBtn')?.addEventListener('click', () => {
            this.navigate(1);
        });

        // Copy button
        document.getElementById('copyRawBtn')?.addEventListener('click', () => {
            this.copyRawData();
        });
    },

    show(event, allEvents = [], index = 0) {
        this.currentEvent = event;
        this.allEvents = allEvents;
        this.currentIndex = index;

        if (!this.modal) {
            this.init();
        }

        this.render();
        this.modal.show();
    },

    render() {
        if (!this.currentEvent) return;

        // Summary tab
        const summaryBody = document.getElementById('packetSummaryBody');
        if (summaryBody) {
            const protocol = this.currentEvent.proto || this.currentEvent.protocol || 'UNKNOWN';
            summaryBody.innerHTML = `
                <tr><th>Timestamp</th><td>${new Date(this.currentEvent.timestamp).toLocaleString()}</td></tr>
                <tr><th>Protocol</th><td>${protocol}</td></tr>
                <tr><th>Message Type</th><td>${this.currentEvent.message_type || '-'}</td></tr>
                <tr><th>Source</th><td>${this.currentEvent.src_ip}:${this.currentEvent.src_port}</td></tr>
                <tr><th>Destination</th><td>${this.currentEvent.dst_ip}:${this.currentEvent.dst_port}</td></tr>
                <tr><th>Event Type</th><td>${this.currentEvent.event_type || '-'}</td></tr>
            `;
        }

        // Details tab
        const detailsContent = document.getElementById('packetDetailsContent');
        if (detailsContent && this.currentEvent.details) {
            detailsContent.textContent = JSON.stringify(this.currentEvent.details, null, 2);
        }

        // Raw data tab
        const rawContent = document.getElementById('packetRawContent');
        if (rawContent) {
            // In a real implementation, this would show hex dump
            rawContent.textContent = JSON.stringify(this.currentEvent, null, 2);
        }

        // Update navigation buttons
        const prevBtn = document.getElementById('prevPacketBtn');
        const nextBtn = document.getElementById('nextPacketBtn');
        if (prevBtn) prevBtn.disabled = this.currentIndex <= 0;
        if (nextBtn) nextBtn.disabled = this.currentIndex >= this.allEvents.length - 1;
    },

    navigate(direction) {
        if (this.allEvents.length === 0) return;

        this.currentIndex += direction;
        this.currentIndex = Math.max(0, Math.min(this.currentIndex, this.allEvents.length - 1));
        this.currentEvent = this.allEvents[this.currentIndex];
        this.render();
    },

    copyRawData() {
        const rawContent = document.getElementById('packetRawContent');
        if (rawContent) {
            navigator.clipboard.writeText(rawContent.textContent)
                .then(() => app.showToast('Copied to clipboard', 'success'))
                .catch(() => app.showToast('Failed to copy', 'error'));
        }
    }
};

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    if (document.getElementById('packetModal')) {
        window.packetInspector.init();
    }
});
