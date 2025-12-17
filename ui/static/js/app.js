// Main Application Logic

const API_BASE = window.location.origin + '/api/v1';

// Utility functions
const app = {
    // Format bytes to human-readable format
    formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
    },

    // Format timestamp
    formatTimestamp(timestamp) {
        if (!timestamp) return '-';
        const date = new Date(timestamp);
        return date.toLocaleString();
    },

    // Format duration
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

    // Show toast notification
    showToast(message, type = 'info') {
        const toastContainer = document.querySelector('.toast-container');
        const template = document.getElementById('toastTemplate');
        const toast = template.cloneNode(true);

        toast.id = '';
        toast.style.display = 'block';
        toast.classList.add(`toast-${type}`);

        const titleMap = {
            success: 'Success',
            error: 'Error',
            warning: 'Warning',
            info: 'Info'
        };

        toast.querySelector('.toast-title').textContent = titleMap[type] || 'Notification';
        toast.querySelector('.toast-body').textContent = message;

        toastContainer.appendChild(toast);

        const bsToast = new bootstrap.Toast(toast, { delay: 5000 });
        bsToast.show();

        toast.addEventListener('hidden.bs.toast', () => {
            toast.remove();
        });
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

    // Get all jobs
    async getJobs(statusFilter = '') {
        let url = '/jobs';
        if (statusFilter) {
            url += `?status=${statusFilter}`;
        }
        return await this.apiRequest(url);
    },

    // Get job status
    async getJobStatus(jobId) {
        return await this.apiRequest(`/jobs/${jobId}/status`);
    },

    // Get job sessions
    async getJobSessions(jobId, page = 1, limit = 20) {
        return await this.apiRequest(`/jobs/${jobId}/sessions?page=${page}&limit=${limit}`);
    },

    // Get session details
    async getSession(sessionId) {
        return await this.apiRequest(`/sessions/${sessionId}`);
    },

    // Delete job
    async deleteJob(jobId) {
        return await this.apiRequest(`/jobs/${jobId}`, { method: 'DELETE' });
    },

    // Initialize dark mode
    initDarkMode() {
        const darkModeToggle = document.getElementById('darkModeToggle');
        if (!darkModeToggle) return;

        // Load saved preference
        const darkMode = localStorage.getItem('darkMode') === 'true';
        if (darkMode) {
            document.body.classList.add('dark-mode');
            darkModeToggle.innerHTML = '<i class="bi bi-sun-fill"></i> Light Mode';
        }

        darkModeToggle.addEventListener('click', (e) => {
            e.preventDefault();
            document.body.classList.toggle('dark-mode');
            const isDark = document.body.classList.contains('dark-mode');
            localStorage.setItem('darkMode', isDark);
            darkModeToggle.innerHTML = isDark
                ? '<i class="bi bi-sun-fill"></i> Light Mode'
                : '<i class="bi bi-moon-fill"></i> Dark Mode';
        });
    },

    // Render job status badge
    getStatusBadge(status) {
        const statusClasses = {
            'QUEUED': 'status-queued',
            'RUNNING': 'status-running',
            'COMPLETED': 'status-completed',
            'FAILED': 'status-failed'
        };

        const badgeClass = statusClasses[status] || 'status-queued';
        return `<span class="status-badge ${badgeClass}">${status}</span>`;
    },

    // Render progress bar
    getProgressBar(progress) {
        const variant = progress === 100 ? 'bg-success' : 'bg-primary';
        return `
            <div class="progress" style="height: 20px;">
                <div class="progress-bar ${variant}" role="progressbar"
                     style="width: ${progress}%" aria-valuenow="${progress}"
                     aria-valuemin="0" aria-valuemax="100">${progress}%</div>
            </div>
        `;
    }
};

// Jobs Table Management
const jobsTable = {
    currentJobs: [],
    statusFilter: '',

    async init() {
        const refreshBtn = document.getElementById('refreshJobsBtn');
        const statusFilterSelect = document.getElementById('statusFilter');

        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => this.loadJobs());
        }

        if (statusFilterSelect) {
            statusFilterSelect.addEventListener('change', (e) => {
                this.statusFilter = e.target.value;
                this.loadJobs();
            });
        }

        await this.loadJobs();

        // Auto-refresh every 5 seconds
        setInterval(() => this.loadJobs(), 5000);
    },

    async loadJobs() {
        try {
            const response = await app.getJobs(this.statusFilter);
            this.currentJobs = response.jobs || [];
            this.render();
        } catch (error) {
            console.error('Failed to load jobs:', error);
        }
    },

    render() {
        const tbody = document.getElementById('jobsTableBody');
        if (!tbody) return;

        if (this.currentJobs.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="7" class="text-center text-muted">
                        No jobs found. Upload a PCAP file to get started.
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = this.currentJobs.map(job => `
            <tr class="fade-in" onclick="jobsTable.viewSessions('${job.job_id}')">
                <td>
                    <small class="text-muted font-monospace">${job.job_id.substring(0, 8)}</small>
                </td>
                <td>
                    <span title="${job.input_filename}">${this.truncateFilename(job.input_filename)}</span>
                </td>
                <td>${app.getStatusBadge(job.status)}</td>
                <td>${app.getProgressBar(job.progress)}</td>
                <td><span class="badge bg-secondary">${job.session_count || 0}</span></td>
                <td><small>${app.formatTimestamp(job.created_at)}</small></td>
                <td>
                    <button class="btn btn-sm btn-outline-primary"
                            onclick="event.stopPropagation(); jobsTable.viewSessions('${job.job_id}')">
                        <i class="bi bi-eye"></i> View
                    </button>
                    <button class="btn btn-sm btn-outline-danger"
                            onclick="event.stopPropagation(); jobsTable.confirmDelete('${job.job_id}')">
                        <i class="bi bi-trash"></i>
                    </button>
                </td>
            </tr>
        `).join('');
    },

    truncateFilename(filename, maxLen = 30) {
        if (filename.length <= maxLen) return filename;
        const extension = filename.substring(filename.lastIndexOf('.'));
        const name = filename.substring(0, maxLen - extension.length - 3);
        return name + '...' + extension;
    },

    async viewSessions(jobId) {
        // Navigate to sessions view
        window.location.href = `/sessions.html?job=${jobId}`;
    },

    confirmDelete(jobId) {
        const modal = new bootstrap.Modal(document.getElementById('deleteModal'));
        document.getElementById('confirmDeleteBtn').onclick = async () => {
            await this.deleteJob(jobId);
            modal.hide();
        };
        modal.show();
    },

    async deleteJob(jobId) {
        try {
            await app.deleteJob(jobId);
            app.showToast('Job deleted successfully', 'success');
            await this.loadJobs();
        } catch (error) {
            app.showToast('Failed to delete job', 'error');
        }
    }
};

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    app.initDarkMode();

    // Initialize jobs table if on main page
    if (document.getElementById('jobsTable')) {
        jobsTable.init();
    }
});
