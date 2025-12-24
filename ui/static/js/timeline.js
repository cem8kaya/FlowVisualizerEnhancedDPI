// Timeline Visualization using D3.js

window.timeline = {
    svg: null,
    width: 0,
    height: 0,
    margin: { top: 40, right: 40, bottom: 60, left: 150 },
    events: [],
    participants: [],

    init(containerId, events, participants) {
        this.events = events || [];
        this.participants = participants || [];

        const container = document.getElementById(containerId);
        if (!container) {
            console.error('Timeline container not found:', containerId);
            return;
        }

        // Clear existing content
        container.innerHTML = '';

        if (this.events.length === 0) {
            this.showEmptyState(container);
            return;
        }

        // Create resize observer if not already created
        if (!this.resizeObserver) {
            this.resizeObserver = new ResizeObserver(entries => {
                for (let entry of entries) {
                    if (entry.contentRect.width > 0) {
                        this.width = entry.contentRect.width;
                        if (!this.svg) {
                            // First time render
                            // Create SVG
                            this.svg = d3.select(container)
                                .append('svg')
                                .attr('class', 'timeline-svg')
                                .attr('width', this.width)
                                .attr('height', this.height);
                            this.render();
                        } else {
                            // Resize existing
                            this.svg.attr('width', this.width);
                            this.render(); // Re-render to adjust scales
                        }
                    }
                }
            });
            this.resizeObserver.observe(container);
        }

        // Set dimensions
        this.width = container.clientWidth;
        this.height = Math.max(500, this.participants.length * 80 + this.margin.top + this.margin.bottom);

        // If we have width, render immediately
        if (this.width > 0) {
            // Create SVG
            this.svg = d3.select(container)
                .append('svg')
                .attr('class', 'timeline-svg')
                .attr('width', this.width)
                .attr('height', this.height);

            this.render();
        } else {
            console.log('Timeline container has 0 width, waiting for resize...');
        }
    },

    showEmptyState(container) {
        container.innerHTML = `
            <div class="timeline-empty">
                <i class="bi bi-clock-history"></i>
                <p>No events to display</p>
            </div>
        `;
    },

    render() {
        if (!this.svg || this.events.length === 0) return;

        const innerWidth = this.width - this.margin.left - this.margin.right;
        const innerHeight = this.height - this.margin.top - this.margin.bottom;

        if (innerWidth <= 0 || innerHeight <= 0) {
            console.warn('Timeline dimensions too small to render');
            return;
        }

        // Create main group
        const g = this.svg.append('g')
            .attr('transform', `translate(${this.margin.left},${this.margin.top})`);

        // Time scale
        const timeExtent = d3.extent(this.events, d => new Date(d.timestamp));
        const xScale = d3.scaleTime()
            .domain(timeExtent)
            .range([0, innerWidth]);

        // Participant scale (Y-axis)
        const yScale = d3.scaleBand()
            .domain(this.participants)
            .range([0, innerHeight])
            .padding(0.1);

        // Draw axes
        const xAxis = d3.axisBottom(xScale)
            .ticks(10)
            .tickFormat(d3.timeFormat('%H:%M:%S'));

        g.append('g')
            .attr('class', 'timeline-axis x-axis')
            .attr('transform', `translate(0,${innerHeight})`)
            .call(xAxis);

        const yAxis = d3.axisLeft(yScale);

        g.append('g')
            .attr('class', 'timeline-axis y-axis')
            .call(yAxis);

        // Draw swim lanes
        g.selectAll('.timeline-lane')
            .data(this.participants)
            .enter()
            .append('rect')
            .attr('class', 'timeline-lane')
            .attr('x', 0)
            .attr('y', d => yScale(d))
            .attr('width', innerWidth)
            .attr('height', yScale.bandwidth());

        // Draw events
        const eventGroups = g.selectAll('.timeline-event')
            .data(this.events)
            .enter()
            .append('g')
            .attr('class', d => `timeline-event event-${this.getEventClass(d)}`)
            .attr('transform', d => {
                const x = xScale(new Date(d.timestamp));
                const y = yScale(this.getEventParticipant(d)) + yScale.bandwidth() / 2;
                return `translate(${x},${y})`;
            })
            .on('mouseover', (event, d) => this.showTooltip(event, d))
            .on('mouseout', () => this.hideTooltip())
            .on('click', (event, d) => this.onEventClick(d));

        // Add circles for events
        eventGroups.append('circle');

        // Add axis labels
        g.append('text')
            .attr('class', 'timeline-axis-label')
            .attr('x', innerWidth / 2)
            .attr('y', innerHeight + 50)
            .attr('text-anchor', 'middle')
            .text('Time');

        g.append('text')
            .attr('class', 'timeline-axis-label')
            .attr('transform', 'rotate(-90)')
            .attr('x', -innerHeight / 2)
            .attr('y', -100)
            .attr('text-anchor', 'middle')
            .text('Participants');
    },

    getEventClass(event) {
        const p = (event.proto || event.protocol || '').toUpperCase();
        if (p.includes('GTP')) return 'gtp';
        if (p.includes('SIP')) return 'sip';
        if (p.includes('DIAMETER')) return 'diameter';
        return 'info';
    },

    getEventParticipant(event) {
        // Return source participant (IP:port)
        const ip = event.src_ip || event.source_ip || '?';
        const port = event.src_port || event.source_port || '?';
        return `${ip}:${port}`;
    },

    showTooltip(event, data) {
        const tooltip = d3.select('body')
            .append('div')
            .attr('class', 'timeline-tooltip')
            .style('left', (event.pageX + 10) + 'px')
            .style('top', (event.pageY - 28) + 'px');

        const proto = data.proto || data.protocol || 'UNKNOWN';
        const src = `${data.src_ip || data.source_ip || '?'}:${data.src_port || data.source_port || '?'}`;
        const dst = `${data.dst_ip || data.dest_ip || '?'}:${data.dst_port || data.dest_port || '?'}`;

        tooltip.html(`
            <div class="timeline-tooltip-title">${data.message_type || 'Event'}</div>
            <div class="timeline-tooltip-time">${new Date(data.timestamp).toLocaleTimeString()}</div>
            <div class="timeline-tooltip-details">
                <strong>Protocol:</strong> ${proto}<br>
                <strong>From:</strong> ${src}<br>
                <strong>To:</strong> ${dst}
                ${data.details ? `<br><strong>Details:</strong> <pre style="margin:0; font-size:0.8em">${JSON.stringify(data.details, null, 2)}</pre>` : ''}
            </div>
        `);
    },

    hideTooltip() {
        d3.selectAll('.timeline-tooltip').remove();
    },

    onEventClick(event) {
        console.log('Event clicked:', event);
        // Open packet inspector modal
        if (typeof packetInspector !== 'undefined') {
            packetInspector.show(event);
        }
    },

    exportSVG() {
        if (!this.svg) return;

        const svgData = this.svg.node().outerHTML;
        const blob = new Blob([svgData], { type: 'image/svg+xml' });
        const url = URL.createObjectURL(blob);

        const link = document.createElement('a');
        link.href = url;
        link.download = 'timeline.svg';
        link.click();

        URL.revokeObjectURL(url);
    }
};

// Export button handler
document.addEventListener('DOMContentLoaded', () => {
    const exportBtn = document.getElementById('exportTimelineBtn');
    if (exportBtn) {
        exportBtn.addEventListener('click', () => window.timeline.exportSVG());
    }
});
