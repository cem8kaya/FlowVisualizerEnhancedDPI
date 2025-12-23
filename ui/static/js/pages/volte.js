/**
 * VoLTE Calls Page Logic
 */
class VoltePage {
    constructor() {
        this.currentPage = 1;
        this.limit = 20;
        this.init();
    }

    async init() {
        // Initialize filters if needed
        const filterInput = document.getElementById('volteFilter');
        if (filterInput) {
            filterInput.addEventListener('keyup', (e) => {
                if (e.key === 'Enter') this.loadCalls(1);
            });
        }

        await this.loadCalls();
    }

    async loadCalls(page = this.currentPage) {
        this.currentPage = page;
        const tbody = document.getElementById('volteTableBody');
        tbody.innerHTML = '<tr><td colspan="7" class="text-center p-4">Loading VoLTE calls...</td></tr>';

        try {
            // Fetch all jobs to find sessions, or if API supports aggregating sessions across jobs
            // Currently API is per job. For this demo, we might just fetch from the most recent job or require job selection.
            // As per requirements "VoLTE Calls: Dedicated call list", implying a global list or filtered list.
            // Existing API: getJobs() -> getJobSessions(jobId).
            // We will fetch recent jobs and then their sessions for demo purposes if no global session API.

            // Optimization: Fetch first active job or just show placeholder if no job selected context.
            // But let's try to get latest job.
            const jobsRes = await window.app.getJobs();
            const jobs = jobsRes.jobs || [];

            if (jobs.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" class="text-center p-4">No jobs found.</td></tr>';
                return;
            }

            // For now, take the most recent job
            const latestJob = jobs[0];
            const sessionsRes = await window.app.getJobSessions(latestJob.job_id, 1, 100); // Fetch 100 sessions

            // Filter for VoLTE (SIP + RTP usually)
            const volteCalls = sessionsRes.sessions.filter(s =>
                (s.protocols && s.protocols.includes('SIP')) ||
                (s.protocols && s.protocols.includes('RTP'))
            );

            this.renderTable(volteCalls, latestJob.job_id);

        } catch (e) {
            console.error(e);
            tbody.innerHTML = '<tr><td colspan="7" class="text-center text-error p-4">Failed to load calls</td></tr>';
        }
    }

    renderTable(calls, jobId) {
        const tbody = document.getElementById('volteTableBody');
        if (calls.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center p-4">No VoLTE calls found in recent job.</td></tr>';
            return;
        }

        tbody.innerHTML = calls.map(c => {
            const duration = window.app.formatDuration(c.duration_ms);
            const mos = this.calculateMOS(c.metrics); // Mock MOS calculation or usage
            const jitter = c.metrics?.rtp_jitter_ms ? c.metrics.rtp_jitter_ms.toFixed(2) + 'ms' : '-';
            const loss = c.metrics?.rtp_loss ? (c.metrics.rtp_loss * 100).toFixed(1) + '%' : '-';

            return `
            <tr class="cursor-pointer hover:bg-tertiary" onclick="window.location.href='/session.html?session=${c.master_id}&job=${jobId}'">
                <td class="font-mono text-xs">${c.imsi || '-'}</td>
                <td class="font-mono text-xs">${c.msisdn || '-'}</td>
                <td><span class="badge ${this.getMosBadge(mos)}">MOS: ${mos}</span></td>
                <td>${jitter}</td>
                <td>${loss}</td>
                <td>${duration}</td>
                <td>
                     <button class="btn btn-sm btn-outline-primary">
                        <i class="bi bi-eye"></i> Details
                    </button>
                </td>
            </tr>
            `;
        }).join('');
    }

    // Pseudo MOS calculation based on loss/jitter if not provided
    calculateMOS(metrics) {
        // Ideal is 4.5
        if (!metrics) return 4.5;
        let score = 4.5;
        if (metrics.rtp_loss) score -= metrics.rtp_loss * 50; // Heavy penalty for loss
        if (metrics.rtp_jitter_ms) score -= metrics.rtp_jitter_ms / 20;

        return Math.max(1, Math.min(4.5, score)).toFixed(2);
    }

    getMosBadge(score) {
        if (score >= 4.0) return 'badge-success';
        if (score >= 3.0) return 'badge-warning';
        return 'badge-error';
    }
}

document.addEventListener('DOMContentLoaded', () => {
    new VoltePage();
});
