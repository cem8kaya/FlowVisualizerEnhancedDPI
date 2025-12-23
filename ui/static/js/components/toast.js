/**
 * Toast Service
 * Handles displaying toast notifications
 */
class Toast {
    static container() {
        let container = document.getElementById('toastContainer');
        if (!container) {
            container = document.createElement('div');
            container.id = 'toastContainer';
            container.style.cssText = 'position: fixed; bottom: 20px; right: 20px; z-index: 1000; display: flex; flex-direction: column; gap: 10px;';
            document.body.appendChild(container);
        }
        return container;
    }

    static show(message, type = 'info', duration = 3000) {
        const container = this.container();
        const toast = document.createElement('div');

        let bgColor = '#1a202c'; // Default/Info
        let icon = 'bi-info-circle';

        if (type === 'success') {
            bgColor = '#48bb78';
            icon = 'bi-check-circle';
        } else if (type === 'error') {
            bgColor = '#f56565';
            icon = 'bi-exclamation-circle';
        } else if (type === 'warning') {
            bgColor = '#ed8936';
            icon = 'bi-exclamation-triangle';
        }

        toast.className = 'toast show align-items-center text-white border-0';
        toast.style.backgroundColor = bgColor;

        toast.innerHTML = `
            <div class="d-flex">
                <div class="toast-body d-flex align-items-center">
                    <i class="bi ${icon} me-2"></i>
                    ${message}
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        `;

        container.appendChild(toast);

        // Auto remove
        setTimeout(() => {
            toast.remove();
        }, duration);

        // Remove on click
        const closeBtn = toast.querySelector('.btn-close');
        if (closeBtn) {
            closeBtn.onclick = () => toast.remove();
        }
    }

    static success(msg) { this.show(msg, 'success'); }
    static error(msg) { this.show(msg, 'error'); }
    static info(msg) { this.show(msg, 'info'); }
    static warning(msg) { this.show(msg, 'warning'); }
}

window.Toast = Toast;
