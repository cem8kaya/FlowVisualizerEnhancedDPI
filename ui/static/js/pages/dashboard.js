/**
 * Dashboard Page Loop
 */
class DashboardPage {
    constructor() {
        this.selectedJobs = new Set();
        this.jobs = [];
        this.sortField = 'created_at';
        this.sortOrder = 'desc';
        this.init();
    }

    async init() {
        console.log('Dashboard initialized');

        // Initialize DataTable
        // Note: We need to customize the render to support checkboxes and specific sorting

        // Load initial data
        await this.loadJobs();

        // Bind events
        const refreshBtn = document.getElementById('refreshJobsBtn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => this.loadJobs());
        }

        // Bind Bulk Delete
        const bulkDeleteBtn = document.getElementById('bulkDeleteBtn');
        if (bulkDeleteBtn) {
            bulkDeleteBtn.addEventListener('click', () => this.confirmBulkDelete());
        }

        // Bind Sort Headers
        document.querySelectorAll('th[data-sort]').forEach(th => {
            th.addEventListener('click', () => this.handleSort(th.dataset.sort));
            th.style.cursor = 'pointer';
        });

        // Auto refresh
        this.refreshInterval = setInterval(() => this.loadJobs(), 5000);
    }

    async loadJobs() {
        try {
            const result = await window.app.getJobs();
            this.jobs = result.jobs || [];
            this.applySorting();
            this.renderTable();
        } catch (error) {
            console.error('Failed to load jobs', error);
        }
    }

    handleSort(field) {
        if (this.sortField === field) {
            this.sortOrder = this.sortOrder === 'asc' ? 'desc' : 'asc';
        } else {
            this.sortField = field;
            this.sortOrder = 'desc'; // Default new sort to desc
        }
        this.applySorting();
        this.renderTable();
        this.updateSortIcons();
    }

    applySorting() {
        this.jobs.sort((a, b) => {
            let valA = a[this.sortField];
            let valB = b[this.sortField];

            // Handle null/undefined
            if (valA == null) valA = '';
            if (valB == null) valB = '';

            // Handle strings case-insensitive
            if (typeof valA === 'string') valA = valA.toLowerCase();
            if (typeof valB === 'string') valB = valB.toLowerCase();

            if (valA < valB) return this.sortOrder === 'asc' ? -1 : 1;
            if (valA > valB) return this.sortOrder === 'asc' ? 1 : -1;
            return 0;
        });
    }

    updateSortIcons() {
        document.querySelectorAll('th[data-sort] i').forEach(i => i.className = 'bi bi-arrow-down-up text-muted opacity-25');
        const activeHeader = document.querySelector(`th[data-sort="${this.sortField}"]`);
        if (activeHeader) {
            const icon = activeHeader.querySelector('i');
            if (icon) icon.className = this.sortOrder === 'asc' ? 'bi bi-arrow-up text-primary' : 'bi bi-arrow-down text-primary';
        }
    }

    renderTable() {
        const tbody = document.getElementById('jobsTableBody');
        if (!tbody) return;

        if (this.jobs.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" class="text-center p-4">No jobs found. Upload a PCAP file to get started.</td></tr>`;
            return;
        }

        tbody.innerHTML = this.jobs.map(job => `
            <tr class="${this.selectedJobs.has(job.job_id) ? 'bg-tertiary' : ''}">
                <td class="w-10">
                    <input type="checkbox" class="form-checkbox" 
                           ${this.selectedJobs.has(job.job_id) ? 'checked' : ''} 
                           onchange="dashboard.toggleSelectJob('${job.job_id}', this.checked)">
                </td>
                <td>${window.StatusBadge.render(job.status)}</td>
                <td class="font-mono text-xs">${job.job_id.substring(0, 8)}</td>
                <td>${this.renderFilename(job)}</td>
                <td class="text-center">${job.session_count || 0}</td>
                <td class="text-sm text-secondary">${window.app.formatTimestamp(job.created_at)}</td>
                <td class="text-right">
                     <div class="flex gap-2 justify-end">
                        <button class="btn btn-outline btn-sm" onclick="dashboard.viewJob('${job.job_id}')" title="View">
                            <i class="bi bi-eye"></i>
                        </button>
                        <button class="btn btn-outline btn-sm text-error" onclick="dashboard.deleteJob('${job.job_id}')" title="Delete">
                            <i class="bi bi-trash"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `).join('');

        this.updateBulkActionUI();
    }

    toggleSelectJob(jobId, checked) {
        if (checked) this.selectedJobs.add(jobId);
        else this.selectedJobs.delete(jobId);
        this.renderTable(); // Re-render to update row styling
    }

    toggleSelectAll(checked) {
        if (checked) {
            this.jobs.forEach(j => this.selectedJobs.add(j.job_id));
        } else {
            this.selectedJobs.clear();
        }
        this.renderTable();
    }

    updateBulkActionUI() {
        const btn = document.getElementById('bulkDeleteBtn');
        if (btn) {
            const count = this.selectedJobs.size;
            btn.disabled = count === 0;
            btn.innerHTML = `<i class="bi bi-trash me-2"></i> Delete Selected (${count})`;
        }

        const selectAll = document.getElementById('selectAll');
        if (selectAll) {
            selectAll.checked = this.jobs.length > 0 && this.jobs.every(j => this.selectedJobs.has(j.job_id));
        }
    }

    renderFilename(row) {
        const name = row.input_filename ? row.input_filename.split('/').pop() : 'Unknown';
        return `<span title="${row.input_filename}">${name}</span>`;
    }

    viewJob(jobId) {
        window.location.href = `/sessions.html?job=${jobId}`;
    }

    async deleteJob(jobId) {
        if (!confirm('Are you sure you want to delete this job?')) return;

        try {
            await window.app.deleteJob(jobId);
            window.Toast.success('Job deleted successfully');
            await this.loadJobs();
        } catch (e) {
            window.Toast.error('Failed to delete job');
        }
    }

    async confirmBulkDelete() {
        if (this.selectedJobs.size === 0) return;
        if (!confirm(`Are you sure you want to delete ${this.selectedJobs.size} selected jobs?`)) return;

        let successParams = 0;
        for (const jobId of this.selectedJobs) {
            try {
                await window.app.deleteJob(jobId);
                successParams++;
            } catch (e) { console.error(e); }
        }

        window.Toast.success(`Deleted ${successParams} jobs`);
        this.selectedJobs.clear();
        await this.loadJobs();
    }
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    // Only init if we are on dashboard
    if (document.getElementById('jobsTable')) {
        window.dashboard = new DashboardPage();

        // Bind header select all
        const selectAll = document.getElementById('selectAll');
        if (selectAll) {
            selectAll.addEventListener('change', (e) => window.dashboard.toggleSelectAll(e.target.checked));
        }
    }
});
