/**
 * Main Application Logic
 * Shared utilities and API wrappers
 */

const API_BASE = window.location.origin + '/api/v1';

const app = {
    // helpers
    formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
    },

    formatTimestamp(timestamp) {
        if (!timestamp) return '-';
        const date = new Date(timestamp);
        return date.toLocaleString();
    },

    formatDuration(ms) {
        if (!ms) return '-';
        const seconds = Math.floor(ms / 1000);
        const minutes = Math.floor(seconds / 60);
        const hours = Math.floor(minutes / 60);

        if (hours > 0) {
            return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
        } else if (minutes > 0) {
            return `${minutes}m ${seconds % 60}s`;
        } else {
            return `${seconds}s`;
        }
    },

    // Toast wrapper using new Toast component if available, else fallback
    showToast(message, type = 'info') {
        if (window.Toast) {
            window.Toast.show(message, type);
        } else {
            console.log(`[${type}] ${message}`);
            alert(message);
        }
    },

    // API request wrapper
    async apiRequest(endpoint, options = {}) {
        try {
            const response = await fetch(API_BASE + endpoint, {
                ...options,
                headers: {
                    'Content-Type': 'application/json',
                    ...options.headers
                }
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            return await response.json();
        } catch (error) {
            console.error('API request failed:', error);
            this.showToast(error.message, 'error');
            throw error;
        }
    },

    // API Methods
    async getJobs(statusFilter = '') {
        let url = '/jobs';
        if (statusFilter) {
            url += `?status=${statusFilter}`;
        }
        return await this.apiRequest(url);
    },

    async getJobStatus(jobId) {
        return await this.apiRequest(`/jobs/${jobId}/status`);
    },

    async getJobSessions(jobId, page = 1, limit = 20, imsi = '', msisdn = '') {
        let url = `/jobs/${jobId}/sessions?page=${page}&limit=${limit}`;
        if (imsi) url += `&imsi=${encodeURIComponent(imsi)}`;
        if (msisdn) url += `&msisdn=${encodeURIComponent(msisdn)}`;
        return await this.apiRequest(url);
    },

    async getSession(sessionId, jobId = null) {
        let url = `/sessions/${sessionId}`;
        if (jobId) url += `?job_id=${encodeURIComponent(jobId)}`;
        return await this.apiRequest(url);
    },

    async deleteJob(jobId) {
        return await this.apiRequest(`/jobs/${jobId}`, { method: 'DELETE' });
    },

    // Legacy support or helper for progress bar
    getProgressBar(progress) {
        // Returns HTML string for progress bar
        const colorClass = progress === 100 ? 'background-color: var(--color-success);' : 'background-color: var(--color-primary);';
        return `
            <div style="height: 6px; background: var(--bg-tertiary); border-radius: 3px; overflow: hidden; width: 100px;">
                <div style="width: ${progress}%; height: 100%; ${colorClass} transition: width 0.3s;"></div>
            </div>
        `;
    }
};

// Expose app to window
window.app = app;
