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
    allJobs: [],
    currentJobs: [],
    statusFilter: '',
    searchFilter: '',
    selectedJobs: new Set(),
    sortField: 'created_at',
    sortOrder: 'desc',

    async init() {
        const refreshBtn = document.getElementById('refreshJobsBtn');
        const statusFilterSelect = document.getElementById('statusFilter');
        const searchInput = document.getElementById('jobSearchInput');
        const selectAllCheckbox = document.getElementById('selectAllJobs');
        const bulkDeleteBtn = document.getElementById('bulkDeleteBtn');

        // Add sort listeners
        document.querySelectorAll('th.sortable').forEach(th => {
            th.addEventListener('click', () => {
                this.handleSort(th.dataset.sort);
            });
        });

        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => this.loadJobs());
        }

        if (statusFilterSelect) {
            statusFilterSelect.addEventListener('change', (e) => {
                this.statusFilter = e.target.value;
                this.applyFilters();
            });
        }

        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                this.searchFilter = e.target.value.toLowerCase();
                this.applyFilters();
            });
        }

        if (selectAllCheckbox) {
            selectAllCheckbox.addEventListener('change', (e) => {
                this.toggleSelectAll(e.target.checked);
            });
        }

        if (bulkDeleteBtn) {
            bulkDeleteBtn.addEventListener('click', () => {
                this.confirmBulkDelete();
            });
        }

        await this.loadJobs();

        // Auto-refresh every 5 seconds
        setInterval(() => this.loadJobs(), 5000);
    },

    async loadJobs() {
        try {
            // Fetch all jobs, client-side filtering handles the rest
            const response = await app.getJobs('');
            this.allJobs = response.jobs || [];
            this.applyFilters();
        } catch (error) {
            console.error('Failed to load jobs:', error);
        }
    },

    applyFilters() {
        this.currentJobs = this.allJobs.filter(job => {
            // Apply status filter (Case insensitive)
            if (this.statusFilter && job.status.toUpperCase() !== this.statusFilter.toUpperCase()) {
                return false;
            }

            // Apply search filter (ID or Filename)
            if (this.searchFilter) {
                const searchStr = this.searchFilter;
                const matchesId = job.job_id && job.job_id.toLowerCase().includes(searchStr);
                const matchesFile = job.input_filename && job.input_filename.toLowerCase().includes(searchStr);
                return matchesId || matchesFile;
            }

            return true;
        });

        // Apply sorting
        this.sortJobs();

        this.render();
    },

    handleSort(field) {
        if (this.sortField === field) {
            this.sortOrder = this.sortOrder === 'asc' ? 'desc' : 'asc';
        } else {
            this.sortField = field;
            this.sortOrder = 'desc'; // Default to desc for new field
        }
        this.applyFilters(); // Re-sort and render
    },

    sortJobs() {
        this.currentJobs.sort((a, b) => {
            let valA = a[this.sortField];
            let valB = b[this.sortField];

            // Handle strings (case insensitive)
            if (typeof valA === 'string') valA = valA.toLowerCase();
            if (typeof valB === 'string') valB = valB.toLowerCase();

            // Handle nulls
            if (valA == null) return 1;
            if (valB == null) return -1;

            if (valA < valB) return this.sortOrder === 'asc' ? -1 : 1;
            if (valA > valB) return this.sortOrder === 'asc' ? 1 : -1;
            return 0;
        });
    },

    render() {
        const tbody = document.getElementById('jobsTableBody');
        if (!tbody) return;

        // Update header checkbox
        const selectAllCheckbox = document.getElementById('selectAllJobs');
        if (selectAllCheckbox) {
            selectAllCheckbox.checked = this.currentJobs.length > 0 &&
                this.currentJobs.every(job => this.selectedJobs.has(job.job_id));
        }

        // Update bulk delete button
        this.updateBulkDeleteUI();

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

        // Update sort icons
        document.querySelectorAll('th.sortable i').forEach(icon => {
            icon.className = 'bi bi-arrow-down-up text-muted small'; // Reset
        });
        const activeHeader = document.querySelector(`th[data-sort="${this.sortField}"]`);
        if (activeHeader) {
            const icon = activeHeader.querySelector('i');
            if (icon) {
                icon.className = this.sortOrder === 'asc' ? 'bi bi-arrow-up text-primary' : 'bi bi-arrow-down text-primary';
            }
        }

        tbody.innerHTML = this.currentJobs.map(job => `
            <tr class="fade-in ${this.selectedJobs.has(job.job_id) ? 'table-active' : ''}" 
                onclick="jobsTable.viewSessions('${job.job_id}')">
                <td onclick="event.stopPropagation()">
                    <input type="checkbox" class="form-check-input job-select" 
                           value="${job.job_id}" 
                           ${this.selectedJobs.has(job.job_id) ? 'checked' : ''}
                           onchange="jobsTable.toggleSelectJob('${job.job_id}', this.checked)">
                </td>
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

    toggleSelectAll(checked) {
        if (checked) {
            this.currentJobs.forEach(job => this.selectedJobs.add(job.job_id));
        } else {
            this.selectedJobs.clear();
        }
        this.render();
    },

    toggleSelectJob(jobId, checked) {
        if (checked) {
            this.selectedJobs.add(jobId);
        } else {
            this.selectedJobs.delete(jobId);
        }
        this.render();
    },

    updateBulkDeleteUI() {
        const btn = document.getElementById('bulkDeleteBtn');
        const countSpan = document.getElementById('selectedCount');
        if (btn && countSpan) {
            const count = this.selectedJobs.size;
            countSpan.textContent = count;
            btn.disabled = count === 0;
        }
    },

    confirmBulkDelete() {
        if (this.selectedJobs.size === 0) return;

        const modal = new bootstrap.Modal(document.getElementById('deleteModal'));
        document.querySelector('#deleteModal .modal-body').textContent =
            `Are you sure you want to delete ${this.selectedJobs.size} selected job(s)?`;

        document.getElementById('confirmDeleteBtn').onclick = async () => {
            await this.deleteSelectedJobs();
            modal.hide();
        };
        modal.show();
    },

    async deleteSelectedJobs() {
        const jobs = Array.from(this.selectedJobs);
        let successCount = 0;

        // Delete sequentially to avoid overwhelming server
        for (const jobId of jobs) {
            try {
                await app.deleteJob(jobId);
                successCount++;
            } catch (error) {
                console.error(`Failed to delete job ${jobId}`, error);
            }
        }

        if (successCount > 0) {
            app.showToast(`Successfully deleted ${successCount} jobs`, 'success');
            this.selectedJobs.clear();
            await this.loadJobs();
        } else {
            app.showToast('Failed to delete selected jobs', 'error');
        }
    },

    truncateFilename(filename, maxLen = 30) {
        if (!filename) return '-';
        // Strip path
        const basename = filename.split('/').pop().split('\\').pop();

        if (basename.length <= maxLen) return basename;

        const extension = basename.substring(basename.lastIndexOf('.'));
        const name = basename.substring(0, maxLen - extension.length - 3);
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
