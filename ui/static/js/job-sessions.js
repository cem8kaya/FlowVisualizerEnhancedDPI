// Job Sessions List View

const jobSessions = {
    jobId: null,
    currentPage: 1,
    limit: 20,
    totalSessions: 0,
    jobData: null,

    async init() {
        // Get Job ID from URL
        const params = new URLSearchParams(window.location.search);
        this.jobId = params.get('job');

        if (!this.jobId) {
            app.showToast('No job ID provided', 'error');
            setTimeout(() => window.location.href = '/', 2000);
            return;
        }

        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => this.refresh());
        }

        // Add filter listeners
        const filterImsi = document.getElementById('filterImsi');
        const filterMsisdn = document.getElementById('filterMsisdn');
        const applyFiltersBtn = document.getElementById('applyFiltersBtn');

        if (applyFiltersBtn) {
            applyFiltersBtn.addEventListener('click', () => this.loadSessions(1));
        }

        if (filterImsi) {
            filterImsi.addEventListener('keyup', (e) => {
                if (e.key === 'Enter') this.loadSessions(1);
            });
        }
        if (filterMsisdn) {
            filterMsisdn.addEventListener('keyup', (e) => {
                if (e.key === 'Enter') this.loadSessions(1);
            });
        }

        await this.loadJobDetails();
        await this.loadSessions();

        app.initDarkMode();
    },

    async refresh() {
        await this.loadJobDetails();
        await this.loadSessions();
    },

    async loadJobDetails() {
        try {
            this.jobData = await app.getJobStatus(this.jobId);
            this.renderJobHeader();
        } catch (error) {
            console.error('Failed to load job details:', error);
            app.showToast('Failed to load job details', 'error');
        }
    },

    renderJobHeader() {
        if (!this.jobData) return;

        document.getElementById('jobId').textContent = this.jobData.job_id.substring(0, 8);
        document.getElementById('jobId').title = this.jobData.job_id;
        document.getElementById('jobStatus').innerHTML = app.getStatusBadge(this.jobData.status);

        // input_filename might be truncated if too long, better to handle via JS than CSS text-overflow if we want clear control
        // but simple textContent is safe
        document.getElementById('jobFile').textContent = this.jobData.input_filename || 'Unknown';
        document.getElementById('jobCreated').textContent = app.formatTimestamp(this.jobData.created_at);

        if (this.jobData.session_count !== undefined) {
            document.getElementById('jobSessions').textContent = this.jobData.session_count;
        }

        if (this.jobData.started_at && this.jobData.completed_at) {
            const start = new Date(this.jobData.started_at).getTime();
            const end = new Date(this.jobData.completed_at).getTime();
            const duration = end - start;
            document.getElementById('jobDuration').textContent = app.formatDuration(duration);
        } else {
            document.getElementById('jobDuration').textContent = '-';
        }

        document.getElementById('jobPackets').textContent = this.jobData.total_packets || 0;
        document.getElementById('jobBytes').textContent = app.formatBytes(this.jobData.total_bytes || 0);
    },

    async loadSessions(page = this.currentPage) {
        this.currentPage = page;
        const tbody = document.getElementById('sessionsTableBody');
        tbody.innerHTML = '<tr><td colspan="9" class="text-center text-muted">Loading...</td></tr>';

        try {
            const imsi = document.getElementById('filterImsi') ? document.getElementById('filterImsi').value : '';
            const msisdn = document.getElementById('filterMsisdn') ? document.getElementById('filterMsisdn').value : '';

            const response = await app.getJobSessions(this.jobId, this.currentPage, this.limit, imsi, msisdn);
            this.totalSessions = response.total;
            this.renderSessions(response.sessions);
            this.renderPagination();
        } catch (error) {
            console.error('Failed to load sessions:', error);
            tbody.innerHTML = `<tr><td colspan="9" class="text-center text-danger">Error loading sessions: ${error.message}</td></tr>`;
        }
    },

    renderSessions(sessions) {
        const tbody = document.getElementById('sessionsTableBody');
        if (!sessions || sessions.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">No sessions found in this job.</td></tr>';
            return;
        }

        tbody.innerHTML = sessions.map(session => `
            <tr class="cursor-pointer fade-in" onclick="jobSessions.viewSession('${session.master_id}')">
                <td><small class="font-monospace">${session.master_id.substring(0, 8)}</small></td>
                <td><span class="badge bg-light text-dark border">${session.imsi || '-'}</span></td>
                <td><span class="badge bg-light text-dark border">${session.msisdn || '-'}</span></td>
                <td>
                    ${(session.protocols || []).map(p => {
            let bgClass = 'bg-secondary';
            if (p === 'SIP') bgClass = 'bg-primary';
            if (p === 'GTPv2') bgClass = 'bg-success';
            if (p === 'DIAMETER') bgClass = 'bg-info';
            return `<span class="badge ${bgClass} me-1" style="font-size: 0.7em;">${p}</span>`;
        }).join('')}
                </td>
                <td><small>${app.formatTimestamp(session.start_time)}</small></td>
                <td>${app.formatDuration(session.duration_ms)}</td>
                <td><span class="badge bg-secondary rounded-pill">${session.events ? session.events.length : 0}</span></td>
                <td>
                    <button class="btn btn-sm btn-outline-primary" 
                            onclick="event.stopPropagation(); jobSessions.viewSession('${session.master_id}')">
                        <i class="bi bi-eye"></i> Details
                    </button>
                </td>
            </tr>
        `).join('');
    },

    renderPagination() {
        const pagination = document.getElementById('pagination');
        const totalPages = Math.ceil(this.totalSessions / this.limit);

        if (totalPages <= 1) {
            pagination.innerHTML = '';
            return;
        }

        let html = '';

        // Previous
        html += `
            <li class="page-item ${this.currentPage === 1 ? 'disabled' : ''}">
                <button class="page-link" onclick="jobSessions.loadSessions(${this.currentPage - 1})">Previous</button>
            </li>
        `;

        // Pages (simplified logic: show all or limited window if too many)
        // For now, let's show simple range around current
        const startPage = Math.max(1, this.currentPage - 2);
        const endPage = Math.min(totalPages, this.currentPage + 2);

        if (startPage > 1) {
            html += `<li class="page-item"><button class="page-link" onclick="jobSessions.loadSessions(1)">1</button></li>`;
            if (startPage > 2) html += `<li class="page-item disabled"><span class="page-link">...</span></li>`;
        }

        for (let i = startPage; i <= endPage; i++) {
            html += `
                <li class="page-item ${this.currentPage === i ? 'active' : ''}">
                    <button class="page-link" onclick="jobSessions.loadSessions(${i})">${i}</button>
                </li>
            `;
        }

        if (endPage < totalPages) {
            if (endPage < totalPages - 1) html += `<li class="page-item disabled"><span class="page-link">...</span></li>`;
            html += `<li class="page-item"><button class="page-link" onclick="jobSessions.loadSessions(${totalPages})">${totalPages}</button></li>`;
        }

        // Next
        html += `
            <li class="page-item ${this.currentPage === totalPages ? 'disabled' : ''}">
                <button class="page-link" onclick="jobSessions.loadSessions(${this.currentPage + 1})">Next</button>
            </li>
        `;

        pagination.innerHTML = html;
    },

    viewSession(sessionId) {
        window.location.href = `/session.html?session=${sessionId}&job=${this.jobId}`;
    }
};

document.addEventListener('DOMContentLoaded', () => {
    jobSessions.init();
});
