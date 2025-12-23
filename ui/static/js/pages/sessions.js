/**
 * Sessions Page Logic
 */
class SessionsPage {
    constructor() {
        const params = new URLSearchParams(window.location.search);
        this.jobId = params.get('job');
        this.currentPage = 1;
        this.limit = 20;
        this.total = 0;

        this.init();
    }

    async init() {
        if (!this.jobId) {
            window.Toast.error('No job ID provided');
            return;
        }

        // Initialize Filter Listeners
        const imsiFilter = document.getElementById('imsiFilter');
        const msisdnFilter = document.getElementById('msisdnFilter');
        const refreshBtn = document.getElementById('refreshSessionsBtn');

        if (imsiFilter) imsiFilter.addEventListener('change', () => this.loadSessions(1));
        if (msisdnFilter) msisdnFilter.addEventListener('change', () => this.loadSessions(1));

        if (refreshBtn) refreshBtn.addEventListener('click', () => this.refresh());

        // Load Data
        await this.loadJobDetails();
        await this.loadSessions();
    }

    async refresh() {
        await this.loadJobDetails();
        await this.loadSessions();
    }

    async loadJobDetails() {
        try {
            console.log(`Fetching job details for ${this.jobId}...`);
            let response = await window.app.getJobStatus(this.jobId);
            console.log('Job status response:', response);

            // Handle potentially wrapped response
            let job = response;
            if (response && response.job) {
                job = response.job;
            }

            if (!job || !job.job_id) {
                console.warn('Job data seems invalid or missing ID:', job);
            }

            this.updateJobInfo(job);
        } catch (e) {
            console.error('Failed to load job details:', e);
            window.Toast.error('Failed to load job details');
        }
    }

    updateJobInfo(job) {
        if (!job) return;

        const safeSetText = (id, val) => {
            const el = document.getElementById(id);
            if (el) el.textContent = val !== undefined && val !== null ? val : '-';
        };

        // Safe substring
        const shortId = job.job_id ? String(job.job_id).substring(0, 8) : '-';
        safeSetText('jobId', shortId);

        safeSetText('jobStatus', job.status);
        const statusEl = document.getElementById('jobStatus');
        if (statusEl) {
            statusEl.className = ''; // Reset
            statusEl.innerHTML = window.StatusBadge.render(job.status || 'UNKNOWN');
        }

        const filename = job.input_filename ? job.input_filename.split('/').pop() : (job.filename || '-');
        safeSetText('jobFile', filename);

        safeSetText('jobCreated', window.app.formatTimestamp(job.created_at));
        safeSetText('jobSessions', job.session_count || 0);

        let duration = '-';
        if (job.started_at && job.completed_at) {
            duration = window.app.formatDuration(new Date(job.completed_at) - new Date(job.started_at));
        }
        safeSetText('jobDuration', duration);

        // Handle bytes which might be total_bytes or bytes
        const bytes = job.total_bytes !== undefined ? job.total_bytes : (job.bytes || 0);
        safeSetText('jobBytes', window.app.formatBytes(bytes));
    }

    async loadSessions(page = this.currentPage) {
        this.currentPage = page;
        const tbody = document.getElementById('sessionsTableBody');
        if (!tbody) return;

        tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted p-4"><div class="spinner-border spinner-border-sm text-primary me-2"></div>Loading sessions...</td></tr>';

        try {
            const imsi = document.getElementById('imsiFilter')?.value || '';
            const msisdn = document.getElementById('msisdnFilter')?.value || '';

            console.log(`Loading sessions for job ${this.jobId}, page ${this.currentPage}`);

            const res = await window.app.getJobSessions(this.jobId, this.currentPage, this.limit, imsi, msisdn);
            console.log('Sessions response:', res);

            // Robust check for response structure
            let sessions = [];
            if (Array.isArray(res)) {
                sessions = res;
            } else if (res && Array.isArray(res.sessions)) {
                sessions = res.sessions;
            } else if (res && Array.isArray(res.data)) {
                sessions = res.data;
            }

            this.total = res.total || sessions.length; // Fallback if total not provided

            this.renderTable(sessions);
            this.renderPagination();
        } catch (e) {
            console.error("Session load failed:", e);
            tbody.innerHTML = `<tr><td colspan="8" class="text-center text-error p-4">
                <div class="mb-2">Error loading sessions</div>
                <small class="text-muted">${e.message}</small>
            </td></tr>`;
        }
    }

    renderTable(sessions) {
        const tbody = document.getElementById('sessionsTableBody');
        if (!tbody) return;

        if (!sessions || sessions.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="text-center p-4">No sessions found for this job.</td></tr>';
            return;
        }

        tbody.innerHTML = sessions.map(s => `
            <tr onclick="window.sessionsPage.viewSession('${s.master_id || s.session_id}')" style="cursor: pointer;" class="hover:bg-tertiary">
                <td class="font-mono text-xs">${(s.master_id || s.session_id || '').substring(0, 8)}</td>
                <td><span class="badge bg-secondary text-xs font-mono">${s.imsi || '-'}</span></td>
                <td><span class="badge bg-secondary text-xs font-mono">${s.msisdn || '-'}</span></td>
                <td>
                    ${(s.protocols || []).map(p => window.ProtocolBadge.render(p)).join(' ')}
                </td>
                <td class="text-sm">${window.app.formatTimestamp(s.start_time)}</td>
                <td class="text-sm">${window.app.formatDuration(s.duration_ms)}</td>
                <td class="text-center">${s.events ? s.events.length : 0}</td>
                <td>
                    <button class="btn btn-sm btn-outline btn-outline-primary" onclick="event.stopPropagation(); window.sessionsPage.viewSession('${s.master_id || s.session_id}')">
                        <i class="bi bi-eye"></i>
                    </button>
                </td>
            </tr>
        `).join('');
    }

    renderPagination() {
        const container = document.getElementById('pagination');
        if (!container) return;

        const totalPages = Math.ceil(this.total / this.limit);
        if (totalPages <= 1) {
            container.innerHTML = '';
            return;
        }

        let html = '';
        const prevDisabled = this.currentPage === 1 ? 'disabled' : '';
        const nextDisabled = this.currentPage === totalPages ? 'disabled' : '';

        html += `<button class="page-btn ${prevDisabled}" onclick="window.sessionsPage.loadSessions(${this.currentPage - 1})"><i class="bi bi-chevron-left"></i></button>`;

        // Simple pagination info
        html += `<span class="d-flex align-items-center px-4 text-sm text-secondary font-medium">Page ${this.currentPage} of ${totalPages}</span>`;

        html += `<button class="page-btn ${nextDisabled}" onclick="window.sessionsPage.loadSessions(${this.currentPage + 1})"><i class="bi bi-chevron-right"></i></button>`;

        container.innerHTML = html;
    }

    viewSession(sessionId) {
        window.location.href = `/session.html?session=${sessionId}&job=${this.jobId}`;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.sessionsPage = new SessionsPage();
});
