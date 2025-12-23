/**
 * Keyboard Navigation Utilities
 * Provides keyboard shortcuts and navigation helpers for accessibility
 */
class KeyboardNav {
    constructor() {
        this.shortcuts = new Map();
        this.focusableElements = 'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])';
        this.init();
    }

    /**
     * Initialize keyboard navigation
     */
    init() {
        document.addEventListener('keydown', this.handleKeyDown.bind(this));
        this.registerDefaultShortcuts();
    }

    /**
     * Register a keyboard shortcut
     * @param {string} key - Key combination (e.g., 'ctrl+k', 'shift+/', 'esc')
     * @param {Function} handler - Handler function
     * @param {string} description - Description of the shortcut
     */
    register(key, handler, description = '') {
        this.shortcuts.set(key.toLowerCase(), { handler, description });
    }

    /**
     * Handle keydown events
     * @param {KeyboardEvent} e - Keyboard event
     */
    handleKeyDown(e) {
        // Build key combination string
        const parts = [];
        if (e.ctrlKey) parts.push('ctrl');
        if (e.altKey) parts.push('alt');
        if (e.shiftKey) parts.push('shift');
        if (e.metaKey) parts.push('meta');

        // Add the actual key
        const key = e.key.toLowerCase();
        if (!['control', 'alt', 'shift', 'meta'].includes(key)) {
            parts.push(key);
        }

        const combination = parts.join('+');
        const shortcut = this.shortcuts.get(combination);

        if (shortcut) {
            e.preventDefault();
            shortcut.handler(e);
        }
    }

    /**
     * Register default application shortcuts
     */
    registerDefaultShortcuts() {
        // Search focus (Ctrl+K or Cmd+K)
        this.register('ctrl+k', () => {
            const searchInput = document.querySelector('.navbar-search input');
            if (searchInput) {
                searchInput.focus();
                searchInput.select();
            }
        }, 'Focus search');

        this.register('meta+k', () => {
            const searchInput = document.querySelector('.navbar-search input');
            if (searchInput) {
                searchInput.focus();
                searchInput.select();
            }
        }, 'Focus search (Mac)');

        // Theme toggle (Ctrl+Shift+T)
        this.register('ctrl+shift+t', () => {
            if (window.themeManager) {
                window.themeManager.toggleTheme();
            }
        }, 'Toggle theme');

        // Escape to close modals/dialogs
        this.register('escape', () => {
            // Close any open modals
            const modals = document.querySelectorAll('.modal.show');
            modals.forEach(modal => {
                const bsModal = bootstrap.Modal.getInstance(modal);
                if (bsModal) bsModal.hide();
            });

            // Close sidebar on mobile if open
            const sidebar = document.getElementById('sidebar');
            if (sidebar && sidebar.classList.contains('show')) {
                sidebar.classList.remove('show');
            }
        }, 'Close modals/dialogs');

        // Help dialog (?)
        this.register('shift+/', () => {
            this.showShortcutsHelp();
        }, 'Show keyboard shortcuts');
    }

    /**
     * Show keyboard shortcuts help dialog
     */
    showShortcutsHelp() {
        const shortcuts = Array.from(this.shortcuts.entries())
            .filter(([_, data]) => data.description)
            .map(([key, data]) => ({ key, description: data.description }));

        const helpHTML = `
            <div class="shortcuts-help">
                <h4 style="margin-bottom: var(--space-4);">Keyboard Shortcuts</h4>
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Shortcut</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${shortcuts.map(s => `
                            <tr>
                                <td><kbd style="padding: 2px 6px; background: var(--bg-tertiary); border-radius: 3px; font-family: var(--font-mono); font-size: 0.85rem;">${this.formatKey(s.key)}</kbd></td>
                                <td>${s.description}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;

        // Show in toast or modal
        if (window.Toast) {
            window.Toast.info('Press Shift+? to see all shortcuts');
        }

        // You would typically show this in a modal
        console.log('Keyboard Shortcuts:', shortcuts);
    }

    /**
     * Format key combination for display
     * @param {string} key - Key combination
     * @returns {string} Formatted key
     */
    formatKey(key) {
        return key
            .split('+')
            .map(k => k.charAt(0).toUpperCase() + k.slice(1))
            .join(' + ');
    }

    /**
     * Get all focusable elements in a container
     * @param {HTMLElement} container - Container element
     * @returns {Array} Array of focusable elements
     */
    getFocusableElements(container = document) {
        return Array.from(container.querySelectorAll(this.focusableElements))
            .filter(el => !el.disabled && el.offsetParent !== null);
    }

    /**
     * Trap focus within a container (useful for modals)
     * @param {HTMLElement} container - Container to trap focus in
     */
    trapFocus(container) {
        const focusable = this.getFocusableElements(container);
        if (focusable.length === 0) return;

        const firstFocusable = focusable[0];
        const lastFocusable = focusable[focusable.length - 1];

        const handleTab = (e) => {
            if (e.key !== 'Tab') return;

            if (e.shiftKey) {
                if (document.activeElement === firstFocusable) {
                    lastFocusable.focus();
                    e.preventDefault();
                }
            } else {
                if (document.activeElement === lastFocusable) {
                    firstFocusable.focus();
                    e.preventDefault();
                }
            }
        };

        container.addEventListener('keydown', handleTab);
        firstFocusable.focus();

        return () => container.removeEventListener('keydown', handleTab);
    }

    /**
     * Handle arrow key navigation in a list
     * @param {HTMLElement} list - List container
     * @param {string} itemSelector - Selector for list items
     */
    enableArrowNavigation(list, itemSelector) {
        let currentIndex = 0;
        const items = list.querySelectorAll(itemSelector);

        list.addEventListener('keydown', (e) => {
            if (e.key === 'ArrowDown') {
                e.preventDefault();
                currentIndex = Math.min(currentIndex + 1, items.length - 1);
                items[currentIndex].focus();
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                currentIndex = Math.max(currentIndex - 1, 0);
                items[currentIndex].focus();
            } else if (e.key === 'Home') {
                e.preventDefault();
                currentIndex = 0;
                items[currentIndex].focus();
            } else if (e.key === 'End') {
                e.preventDefault();
                currentIndex = items.length - 1;
                items[currentIndex].focus();
            }
        });
    }
}

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => {
    window.keyboardNav = new KeyboardNav();
});

window.KeyboardNav = KeyboardNav;
