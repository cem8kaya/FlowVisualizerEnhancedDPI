/**
 * Modal Wrapper
 * Simple wrapper around Bootstrap Modal
 */
class Modal {
    constructor(elementId) {
        this.element = document.getElementById(elementId);
        this.bsModal = null;
        if (this.element && window.bootstrap) {
            this.bsModal = new bootstrap.Modal(this.element);
        }
    }

    show() {
        if (this.bsModal) this.bsModal.show();
    }

    hide() {
        if (this.bsModal) this.bsModal.hide();
    }

    setTitle(title) {
        const titleEl = this.element.querySelector('.modal-title');
        if (titleEl) titleEl.textContent = title;
    }

    setBody(html) {
        const bodyEl = this.element.querySelector('.modal-body');
        if (bodyEl) bodyEl.innerHTML = html;
    }
}

window.Modal = Modal;
