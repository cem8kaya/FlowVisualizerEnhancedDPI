# nDPI Callflow Visualizer - UI Design System

## Overview

Professional, telecom-focused design system for NOC environments and engineering analysis.

## 📐 Design Tokens

### Color Palette

#### Primary Colors
- **Primary**: `#1a365d` - Deep blue for main actions and branding
- **Primary Light**: `#2c5282` - Lighter variant for hover states
- **Secondary**: `#00bcd4` - Cyan for accents and highlights

#### Semantic Colors
- **Success**: `#48bb78` - Green for successful operations
- **Warning**: `#ed8936` - Amber for warnings
- **Error**: `#f56565` - Red for errors and critical alerts

#### Protocol Colors
- **SIP**: `#3b82f6` - Blue
- **RTP**: `#10b981` - Green
- **GTP**: `#f59e0b` - Amber
- **DIAMETER**: `#8b5cf6` - Purple
- **HTTP/2**: `#ec4899` - Pink
- **S1AP**: `#06b6d4` - Cyan
- **NGAP**: `#14b8a6` - Teal

### Typography

#### Font Families
- **UI Text**: Inter (sans-serif)
- **Code/Data**: JetBrains Mono (monospace)

#### Font Sizes
- `text-xs`: 0.75rem
- `text-sm`: 0.875rem
- `text-base`: 1rem
- `text-lg`: 1.125rem
- `text-xl`: 1.25rem

### Spacing

```css
--space-1: 4px
--space-2: 8px
--space-3: 12px
--space-4: 16px
--space-6: 24px
--space-8: 32px
```

### Border Radius

```css
--radius-sm: 4px
--radius-md: 8px
--radius-lg: 12px
```

### Shadows

```css
--shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05)
--shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1)
--shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1)
--shadow-xl: 0 20px 25px -5px rgba(0, 0, 0, 0.1)
```

## 🎨 Theme System

### Dark Mode (Default)
```css
--bg-primary: #0d1117
--bg-secondary: #161b22
--bg-tertiary: #21262d
--text-primary: #f0f6fc
--text-secondary: #8b949e
--border-color: #30363d
```

### Light Mode
```css
--bg-primary: #f7fafc
--bg-secondary: #ffffff
--bg-tertiary: #f0f0f0
--text-primary: #1a202c
--text-secondary: #4a5568
--border-color: #e2e8f0
```

### Theme Toggle
Theme preference is stored in `localStorage` and respects system preferences.

```javascript
// Toggle theme programmatically
window.themeManager.toggleTheme();

// Set specific theme
window.themeManager.setTheme('dark'); // or 'light'
```

## 🧩 Components

### Badges

#### Protocol Badge
```javascript
ProtocolBadge.render('SIP')
// Returns: <span class="badge badge-protocol badge-sip">SIP</span>
```

#### Status Badge
```javascript
StatusBadge.render('completed')
// Returns: <span class="badge badge-status badge-success">completed</span>
```

**Status Types**: `completed`, `running`, `failed`, `error`, `crashed`

### Cards

#### Basic Card
```html
<div class="card">
    <div class="card-header">
        <span>Card Title</span>
    </div>
    <div class="card-body">
        Card content goes here
    </div>
</div>
```

#### Session Card
```javascript
SessionCard.render(sessionData, onClickHandler)
```

**Session Data Structure**:
```javascript
{
    session_id: 'uuid',
    protocol: 'SIP',
    src_ip: '192.168.1.1',
    dst_ip: '192.168.1.2',
    packets: 1234,
    bytes: 567890,
    duration: 30000,
    imsi: '123456789012345', // Optional
    msisdn: '+1234567890', // Optional
    mos_score: 4.2 // Optional (for VoLTE)
}
```

#### Metric Card
```html
<div class="metric-card">
    <div class="metric-icon">
        <i class="bi bi-activity"></i>
    </div>
    <div class="metric-content">
        <h3>1,234</h3>
        <p>Total Sessions</p>
    </div>
</div>
```

### Data Tables

```javascript
const table = new DataTable('tableId', {
    columns: [
        { key: 'name', render: (row) => row.name },
        { key: 'status', render: (row) => StatusBadge.render(row.status) }
    ],
    emptyMessage: 'No data available',
    onRowClick: (row) => console.log(row)
});

table.render(data);
```

### Pagination

```javascript
const pagination = new Pagination('paginationContainer', {
    currentPage: 1,
    totalPages: 10,
    onPageChange: (page) => loadPage(page),
    maxVisible: 7
});

// Update pagination
pagination.update(2, 10);

// Get info text
const info = Pagination.getInfoText(2, 20, 100);
// Returns: "Showing 21-40 of 100"
```

### Modals

```javascript
const modal = new Modal('modalId');
modal.setTitle('Confirm Action');
modal.setBody('<p>Are you sure?</p>');
modal.show();

// Close modal
modal.hide();
```

### Toasts

```javascript
Toast.success('Operation completed');
Toast.error('Something went wrong');
Toast.warning('Please review');
Toast.info('Information message');

// Custom duration
Toast.show('Custom message', 'info', 5000);
```

### Loading States

#### Spinner
```html
<div class="loading-spinner"></div>
<div class="loading-spinner loading-spinner-lg"></div>
```

#### Skeleton
```html
<div class="skeleton skeleton-title"></div>
<div class="skeleton skeleton-text"></div>
<div class="skeleton skeleton-text"></div>
```

### Empty States

```html
<div class="empty-state">
    <div class="empty-state-icon">
        <i class="bi bi-inbox"></i>
    </div>
    <h3>No Data Available</h3>
    <p>Upload a PCAP file to get started.</p>
    <button class="btn btn-primary">Upload File</button>
</div>
```

### Alerts

```html
<div class="alert alert-success">
    <i class="alert-icon bi bi-check-circle"></i>
    <div class="alert-content">
        <div class="alert-title">Success!</div>
        <div>Your operation completed successfully.</div>
    </div>
</div>
```

**Alert Types**: `alert-info`, `alert-success`, `alert-warning`, `alert-error`

### Tabs

```html
<div class="tabs">
    <button class="tab active" data-tab="overview">Overview</button>
    <button class="tab" data-tab="details">Details</button>
    <button class="tab" data-tab="metrics">Metrics</button>
</div>

<div class="tab-content active" id="overview">Overview content</div>
<div class="tab-content" id="details">Details content</div>
<div class="tab-content" id="metrics">Metrics content</div>
```

### Progress Bars

```html
<div class="progress-bar">
    <div class="progress-bar-fill" style="width: 75%"></div>
</div>

<!-- With status color -->
<div class="progress-bar">
    <div class="progress-bar-fill success" style="width: 100%"></div>
</div>
```

## ⌨️ Keyboard Navigation

### Default Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+K` / `Cmd+K` | Focus search |
| `Ctrl+Shift+T` | Toggle theme |
| `Escape` | Close modals/dialogs |
| `Shift+/` | Show shortcuts help |
| `Arrow Keys` | Navigate lists |
| `Tab` | Navigate focusable elements |

### Custom Shortcuts

```javascript
keyboardNav.register('ctrl+shift+d', () => {
    console.log('Custom shortcut triggered');
}, 'Custom action description');
```

### Focus Management

```javascript
// Get focusable elements
const focusable = keyboardNav.getFocusableElements(container);

// Trap focus in modal
const cleanup = keyboardNav.trapFocus(modalElement);
// Later: cleanup() to remove trap

// Enable arrow navigation in list
keyboardNav.enableArrowNavigation(listElement, '.list-item');
```

## 📱 Responsive Design

### Breakpoints

- **Mobile**: < 768px
- **Tablet**: 768px - 1024px
- **Desktop**: > 1024px

### Mobile Adaptations

- Sidebar collapses to off-canvas menu
- Data tables become scrollable
- Grid layouts stack to single column
- Touch-friendly tap targets (min 44x44px)

## ♿ Accessibility

### WCAG 2.1 AA Compliance

- ✅ Color contrast ratios meet 4.5:1 minimum
- ✅ Focus indicators on all interactive elements
- ✅ ARIA labels and roles
- ✅ Keyboard navigation support
- ✅ Screen reader friendly

### ARIA Attributes

```html
<!-- Navigation -->
<nav role="navigation" aria-label="Main navigation">

<!-- Buttons -->
<button aria-label="Close dialog">
    <i class="bi bi-x"></i>
</button>

<!-- Status -->
<span role="status" aria-live="polite">Loading...</span>

<!-- Tables -->
<table role="table" aria-label="Session list">
```

### Screen Reader Support

- Semantic HTML5 elements
- Descriptive labels
- Skip navigation links
- Announcements for dynamic content

## 🎯 Best Practices

### Performance

- CSS variables for theming (no JavaScript re-calculation)
- Minimal DOM manipulation
- Debounced search/filter inputs
- Lazy loading for large datasets
- CSS animations over JavaScript

### Code Organization

```
ui/static/
├── css/
│   ├── design-system.css    # Design tokens & base styles
│   ├── layout.css            # Layout structure
│   ├── components.css        # Reusable components
│   └── pages/
│       ├── dashboard.css
│       ├── sessions.css
│       └── volte.css
├── js/
│   ├── app.js                # Core utilities
│   ├── theme.js              # Theme management
│   ├── keyboard-nav.js       # Keyboard navigation
│   └── components/
│       ├── session-card.js
│       ├── pagination.js
│       ├── data-table.js
│       ├── modal.js
│       ├── toast.js
│       ├── protocol-badge.js
│       └── status-badge.js
```

### Component Development

1. **Modularity**: Each component is self-contained
2. **Reusability**: Components accept configuration options
3. **Accessibility**: All components support keyboard navigation
4. **Documentation**: Inline JSDoc comments
5. **Error Handling**: Graceful degradation

## 🚀 Getting Started

### Include Required Resources

```html
<!-- Fonts -->
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">

<!-- Icons -->
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">

<!-- Design System -->
<link rel="stylesheet" href="/css/design-system.css">
<link rel="stylesheet" href="/css/layout.css">
<link rel="stylesheet" href="/css/components.css">

<!-- Page Specific -->
<link rel="stylesheet" href="/css/pages/dashboard.css">

<!-- Core JavaScript -->
<script src="/js/theme.js"></script>
<script src="/js/keyboard-nav.js"></script>
<script src="/js/app.js"></script>

<!-- Components -->
<script src="/js/components/toast.js"></script>
<script src="/js/components/modal.js"></script>
<script src="/js/components/protocol-badge.js"></script>
<script src="/js/components/status-badge.js"></script>
<script src="/js/components/session-card.js"></script>
<script src="/js/components/pagination.js"></script>
<script src="/js/components/data-table.js"></script>
```

### Basic Page Structure

```html
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Page Title - FlowVisualizer</title>
    <!-- Include resources above -->
</head>
<body>
    <div class="app-container">
        <!-- Sidebar -->
        <aside class="app-sidebar" id="sidebar">
            <!-- Sidebar content -->
        </aside>

        <!-- Navbar -->
        <header class="app-navbar">
            <!-- Navbar content -->
        </header>

        <!-- Main Content -->
        <main class="app-content">
            <!-- Your page content -->
        </main>
    </div>

    <!-- Toast Container -->
    <div id="toastContainer"></div>

    <!-- Include scripts -->
</body>
</html>
```

## 🎨 Customization

### Extending the Color Palette

```css
:root {
    --color-custom: #your-color;
}

[data-theme="dark"] {
    --color-custom: #your-dark-color;
}

[data-theme="light"] {
    --color-custom: #your-light-color;
}
```

### Creating Custom Components

```javascript
class CustomComponent {
    static render(data) {
        return `<div class="custom-component">${data}</div>`;
    }
}

window.CustomComponent = CustomComponent;
```

## 📊 Example Usage

### Dashboard Metrics

```javascript
const metrics = [
    { icon: 'bi-activity', value: '1,234', label: 'Sessions', trend: '+12%' },
    { icon: 'bi-check-circle', value: '98.5%', label: 'Success Rate', trend: '+2%' }
];

const metricsHTML = metrics.map(m => `
    <div class="metric-card">
        <div class="metric-icon"><i class="bi ${m.icon}"></i></div>
        <div class="metric-content">
            <h3>${m.value}</h3>
            <p>${m.label}</p>
            <span class="trend-indicator up">${m.trend}</span>
        </div>
    </div>
`).join('');
```

### Session List with Pagination

```javascript
async function loadSessions(page = 1) {
    const data = await app.getJobSessions(jobId, page, 20);

    // Render table
    const table = new DataTable('sessionsTable', {
        columns: [
            { key: 'protocol', render: row => ProtocolBadge.render(row.protocol) },
            { key: 'src_ip', render: row => `<code>${row.src_ip}</code>` },
            { key: 'dst_ip', render: row => `<code>${row.dst_ip}</code>` }
        ]
    });
    table.render(data.sessions);

    // Update pagination
    pagination.update(page, data.total_pages);
}
```

## 📝 Version

Current Version: **2.1.0**

---

For questions or contributions, see the main project README.
