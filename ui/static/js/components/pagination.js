/**
 * Pagination Component
 * Handles page navigation with accessibility support
 */
class Pagination {
    constructor(containerId, options = {}) {
        this.container = document.getElementById(containerId);
        this.currentPage = options.currentPage || 1;
        this.totalPages = options.totalPages || 1;
        this.onPageChange = options.onPageChange || (() => {});
        this.maxVisible = options.maxVisible || 7;

        if (this.container) {
            this.render();
        }
    }

    /**
     * Update pagination state and re-render
     * @param {number} currentPage - Current page number
     * @param {number} totalPages - Total number of pages
     */
    update(currentPage, totalPages) {
        this.currentPage = currentPage;
        this.totalPages = totalPages;
        this.render();
    }

    /**
     * Render the pagination component
     */
    render() {
        if (!this.container) return;

        if (this.totalPages <= 1) {
            this.container.innerHTML = '';
            return;
        }

        const pages = this.getPageNumbers();
        const buttons = [];

        // Previous button
        buttons.push(this.renderButton(
            'prev',
            '<i class="bi bi-chevron-left"></i>',
            this.currentPage - 1,
            this.currentPage === 1,
            'Previous page'
        ));

        // Page numbers
        pages.forEach(page => {
            if (page === '...') {
                buttons.push('<span class="page-btn disabled">...</span>');
            } else {
                buttons.push(this.renderButton(
                    `page-${page}`,
                    page.toString(),
                    page,
                    false,
                    `Go to page ${page}`,
                    page === this.currentPage
                ));
            }
        });

        // Next button
        buttons.push(this.renderButton(
            'next',
            '<i class="bi bi-chevron-right"></i>',
            this.currentPage + 1,
            this.currentPage === this.totalPages,
            'Next page'
        ));

        this.container.innerHTML = `
            <nav class="pagination" role="navigation" aria-label="Pagination">
                ${buttons.join('')}
            </nav>
        `;

        this.attachEventListeners();
    }

    /**
     * Render a single pagination button
     */
    renderButton(id, content, page, disabled, ariaLabel, active = false) {
        const classes = ['page-btn'];
        if (disabled) classes.push('disabled');
        if (active) classes.push('active');

        const disabledAttr = disabled ? 'disabled' : '';
        const ariaCurrentAttr = active ? 'aria-current="page"' : '';

        return `
            <button
                class="${classes.join(' ')}"
                data-page="${page}"
                ${disabledAttr}
                ${ariaCurrentAttr}
                aria-label="${ariaLabel}"
            >
                ${content}
            </button>
        `;
    }

    /**
     * Calculate which page numbers to show
     */
    getPageNumbers() {
        const pages = [];
        const { currentPage, totalPages, maxVisible } = this;

        if (totalPages <= maxVisible) {
            // Show all pages
            for (let i = 1; i <= totalPages; i++) {
                pages.push(i);
            }
        } else {
            // Show subset with ellipsis
            const leftOffset = Math.floor((maxVisible - 3) / 2);
            const rightOffset = Math.ceil((maxVisible - 3) / 2);

            // Always show first page
            pages.push(1);

            if (currentPage <= leftOffset + 2) {
                // Near start
                for (let i = 2; i <= maxVisible - 2; i++) {
                    pages.push(i);
                }
                pages.push('...');
            } else if (currentPage >= totalPages - rightOffset - 1) {
                // Near end
                pages.push('...');
                for (let i = totalPages - (maxVisible - 3); i < totalPages; i++) {
                    pages.push(i);
                }
            } else {
                // Middle
                pages.push('...');
                for (let i = currentPage - leftOffset; i <= currentPage + rightOffset; i++) {
                    pages.push(i);
                }
                pages.push('...');
            }

            // Always show last page
            pages.push(totalPages);
        }

        return pages;
    }

    /**
     * Attach click event listeners to pagination buttons
     */
    attachEventListeners() {
        if (!this.container) return;

        const buttons = this.container.querySelectorAll('.page-btn:not(.disabled)');
        buttons.forEach(button => {
            button.addEventListener('click', (e) => {
                const page = parseInt(button.dataset.page);
                if (!isNaN(page) && page !== this.currentPage) {
                    this.onPageChange(page);
                }
            });
        });

        // Keyboard navigation
        this.container.addEventListener('keydown', (e) => {
            if (e.key === 'ArrowLeft' && this.currentPage > 1) {
                this.onPageChange(this.currentPage - 1);
            } else if (e.key === 'ArrowRight' && this.currentPage < this.totalPages) {
                this.onPageChange(this.currentPage + 1);
            }
        });
    }

    /**
     * Static helper to create pagination info text
     * @param {number} currentPage
     * @param {number} pageSize
     * @param {number} totalItems
     * @returns {string} Pagination info text
     */
    static getInfoText(currentPage, pageSize, totalItems) {
        const start = (currentPage - 1) * pageSize + 1;
        const end = Math.min(currentPage * pageSize, totalItems);
        return `Showing ${start}-${end} of ${totalItems}`;
    }
}

window.Pagination = Pagination;
