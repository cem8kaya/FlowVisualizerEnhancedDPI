/**
 * Status Badge Component
 * Renders a standardized badge for status indicators
 */
class StatusBadge {
    static getStatusClass(status) {
        const s = status.toUpperCase();
        if (['COMPLETED', 'SUCCESS', 'finish'].includes(s)) return 'badge-success';
        if (['RUNNING', 'PROCESSING', 'pending'].includes(s)) return 'badge-warning';
        if (['FAILED', 'ERROR', 'CRASHED'].includes(s)) return 'badge-error';
        return 'badge-neutral';
    }

    static render(status) {
        if (!status) return '';
        const className = this.getStatusClass(status);
        return `<span class="badge badge-status ${className}">${status}</span>`;
    }
}

window.StatusBadge = StatusBadge;
