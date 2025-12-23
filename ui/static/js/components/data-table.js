/**
 * DataTable Component
 * Reusable table renderer
 */
class DataTable {
    constructor(containerId, options = {}) {
        this.container = document.getElementById(containerId);
        this.columns = options.columns || [];
        this.emptyMessage = options.emptyMessage || 'No data available';
        this.onRowClick = options.onRowClick || null;
    }

    render(data) {
        if (!this.container) return;

        // Clear existing content
        const tableBody = this.container.querySelector('tbody') || this.createTableStructure();
        tableBody.innerHTML = '';

        if (!data || data.length === 0) {
            this.renderEmptyState(tableBody);
            return;
        }

        data.forEach(item => {
            const row = document.createElement('tr');
            if (this.onRowClick) {
                row.style.cursor = 'pointer';
                row.onclick = () => this.onRowClick(item);
            }

            this.columns.forEach(col => {
                const cell = document.createElement('td');
                if (col.render) {
                    cell.innerHTML = col.render(item);
                } else {
                    cell.textContent = item[col.key] || '-';
                }
                if (col.className) {
                    cell.className = col.className;
                }
                row.appendChild(cell);
            });

            tableBody.appendChild(row);
        });
    }

    renderEmptyState(tbody) {
        const row = document.createElement('tr');
        const cell = document.createElement('td');
        cell.colSpan = this.columns.length;
        cell.className = 'text-center text-muted p-4';
        cell.textContent = this.emptyMessage;
        row.appendChild(cell);
        tbody.appendChild(row);
    }

    createTableStructure() {
        // If the table doesn't exist, this helper could create it. 
        // For now, assuming the table structure exists in HTML and we are targeting the tbody.
        // If container is the table element itself:
        let tbody = this.container.querySelector('tbody');
        if (!tbody) {
            tbody = document.createElement('tbody');
            this.container.appendChild(tbody);
        }
        return tbody;
    }
}

window.DataTable = DataTable;
