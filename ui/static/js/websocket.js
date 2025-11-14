// WebSocket Handler for Real-time Updates

const wsHandler = {
    socket: null,
    jobId: null,
    reconnectAttempts: 0,
    maxReconnectAttempts: 5,
    reconnectDelay: 2000,

    connect(jobId) {
        if (this.socket && this.socket.readyState === WebSocket.OPEN) {
            this.disconnect();
        }

        this.jobId = jobId;
        const wsUrl = `ws://${window.location.host}/ws/${jobId}`;

        console.log('Connecting to WebSocket:', wsUrl);

        this.socket = new WebSocket(wsUrl);

        this.socket.onopen = () => {
            console.log('WebSocket connected');
            this.reconnectAttempts = 0;
            app.showToast('Connected to real-time updates', 'success');
        };

        this.socket.onmessage = (event) => {
            this.handleMessage(event.data);
        };

        this.socket.onerror = (error) => {
            console.error('WebSocket error:', error);
        };

        this.socket.onclose = () => {
            console.log('WebSocket disconnected');
            this.attemptReconnect();
        };
    },

    disconnect() {
        if (this.socket) {
            this.socket.close();
            this.socket = null;
        }
    },

    attemptReconnect() {
        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            console.log('Max reconnect attempts reached');
            app.showToast('Lost connection to server', 'warning');
            return;
        }

        this.reconnectAttempts++;
        console.log(`Reconnecting... attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts}`);

        setTimeout(() => {
            if (this.jobId) {
                this.connect(this.jobId);
            }
        }, this.reconnectDelay * this.reconnectAttempts);
    },

    handleMessage(data) {
        try {
            const message = JSON.parse(data);
            console.log('WebSocket message:', message);

            switch (message.type) {
                case 'progress':
                    this.handleProgress(message);
                    break;
                case 'status':
                    this.handleStatus(message);
                    break;
                case 'event':
                    this.handleEvent(message);
                    break;
                case 'heartbeat':
                    // Heartbeat received, no action needed
                    break;
                default:
                    console.log('Unknown message type:', message.type);
            }
        } catch (error) {
            console.error('Failed to parse WebSocket message:', error);
        }
    },

    handleProgress(message) {
        // Update progress in jobs table
        if (typeof jobsTable !== 'undefined') {
            const job = jobsTable.currentJobs.find(j => j.job_id === this.jobId);
            if (job) {
                job.progress = message.progress;
                jobsTable.render();
            }
        }
    },

    handleStatus(message) {
        console.log('Job status update:', message.status);

        if (message.status === 'COMPLETED') {
            app.showToast('PCAP processing completed!', 'success');
            // Reload jobs to show updated session count
            if (typeof jobsTable !== 'undefined') {
                jobsTable.loadJobs();
            }
        } else if (message.status === 'FAILED') {
            app.showToast('PCAP processing failed: ' + (message.error || 'Unknown error'), 'error');
        }
    },

    handleEvent(message) {
        console.log('New event:', message);
        // This could be used for real-time event streaming in the future
    }
};

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (wsHandler.socket) {
        wsHandler.disconnect();
    }
});
