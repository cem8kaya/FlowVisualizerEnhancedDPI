/**
 * Theme Manager
 * Handles light/dark mode toggling and persistence
 */

class ThemeManager {
    constructor() {
        this.storageKey = 'theme-preference';
        this.toggleBtnId = 'themeToggle';
        this.darkIconClass = 'bi-moon-fill';
        this.lightIconClass = 'bi-sun-fill';
        
        this.init();
    }

    init() {
        // Check for saved preference or system preference
        const savedTheme = localStorage.getItem(this.storageKey);
        const systemDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        
        const theme = savedTheme || (systemDark ? 'dark' : 'light');
        this.setTheme(theme);

        // Bind toggle button if it exists
        const toggleBtn = document.getElementById(this.toggleBtnId);
        if (toggleBtn) {
            toggleBtn.addEventListener('click', () => this.toggleTheme());
            this.updateIcon(theme);
        }
    }

    toggleTheme() {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        this.setTheme(newTheme);
    }

    setTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem(this.storageKey, theme);
        this.updateIcon(theme);
    }

    updateIcon(theme) {
        const toggleBtn = document.getElementById(this.toggleBtnId);
        if (!toggleBtn) return;

        const icon = toggleBtn.querySelector('i');
        if (icon) {
            icon.className = `bi ${theme === 'dark' ? this.lightIconClass : this.darkIconClass}`;
        }
    }
}

// Initialize on load
document.addEventListener('DOMContentLoaded', () => {
    window.themeManager = new ThemeManager(); 
});
