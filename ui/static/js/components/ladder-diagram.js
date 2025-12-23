/**
 * Ladder Diagram (MSC-Style) Renderer using D3.js v7
 * Visualizes telecom call flows as Message Sequence Charts
 */

class LadderDiagram {
    constructor(containerId, options = {}) {
        this.containerId = containerId;
        this.container = document.getElementById(containerId);

        if (!this.container) {
            console.error(`Container ${containerId} not found`);
            return;
        }

        // Configuration
        this.config = {
            participantWidth: 120,
            participantHeight: 60,
            participantSpacing: 180,
            messageHeight: 60,
            timelineWidth: 100,
            marginTop: 20,
            marginBottom: 40,
            marginLeft: 120,
            marginRight: 40,
            arrowSize: 8,
            ...options
        };

        // State
        this.data = null;
        this.svg = null;
        this.zoom = null;
        this.selectedMessage = null;
        this.participantPositions = new Map();

        // Initialize
        this.init();
    }

    init() {
        // Clear container
        this.container.innerHTML = '';

        // Create SVG container
        const containerRect = this.container.getBoundingClientRect();
        this.width = containerRect.width || 1000;
        this.height = 600;

        // Create main SVG
        this.svg = d3.select(`#${this.containerId}`)
            .append('svg')
            .attr('class', 'ladder-diagram-svg')
            .attr('width', this.width)
            .attr('height', this.height);

        // Create groups for different layers
        this.mainGroup = this.svg.append('g')
            .attr('class', 'ladder-main-group');

        this.lifelineGroup = this.mainGroup.append('g').attr('class', 'lifelines');
        this.messageGroup = this.mainGroup.append('g').attr('class', 'messages');
        this.participantGroup = this.mainGroup.append('g').attr('class', 'participants');
        this.timelineGroup = this.mainGroup.append('g').attr('class', 'timeline');

        // Setup zoom behavior
        this.setupZoom();

        // Add tooltip
        this.tooltip = d3.select('body')
            .append('div')
            .attr('class', 'ladder-tooltip')
            .style('opacity', 0);
    }

    setupZoom() {
        this.zoom = d3.zoom()
            .scaleExtent([0.5, 3])
            .on('zoom', (event) => {
                this.mainGroup.attr('transform', event.transform);
            });

        this.svg.call(this.zoom);
    }

    /**
     * Main render function
     * @param {Object} data - Ladder diagram data
     */
    render(data) {
        const startTime = performance.now();

        if (!data || !data.participants || !data.messages) {
            this.showEmptyState();
            return;
        }

        this.data = data;

        // Calculate layout
        this.calculateLayout();

        // Render components
        this.renderLifelines();
        this.renderMessages();
        this.renderParticipants();
        this.renderTimeline();

        const endTime = performance.now();
        console.log(`Ladder diagram rendered in ${(endTime - startTime).toFixed(2)}ms`);

        // Emit custom event
        this.container.dispatchEvent(new CustomEvent('ladder-rendered', {
            detail: { duration: endTime - startTime }
        }));
    }

    calculateLayout() {
        // Calculate participant positions
        this.participantPositions.clear();

        this.data.participants.forEach((participant, index) => {
            const x = this.config.marginLeft +
                     this.config.timelineWidth +
                     (index * this.config.participantSpacing);

            this.participantPositions.set(participant.id, {
                x: x,
                index: index,
                participant: participant
            });
        });

        // Calculate diagram height based on messages
        const totalHeight = this.config.marginTop +
                          this.config.participantHeight +
                          (this.data.messages.length * this.config.messageHeight) +
                          this.config.marginBottom;

        this.height = Math.max(600, totalHeight);
        this.svg.attr('height', this.height);
    }

    renderParticipants() {
        const participants = this.participantGroup
            .selectAll('.participant')
            .data(this.data.participants)
            .join('g')
            .attr('class', 'participant')
            .attr('transform', (d) => {
                const pos = this.participantPositions.get(d.id);
                return `translate(${pos.x}, ${this.config.marginTop})`;
            });

        // Participant box
        participants
            .append('rect')
            .attr('class', d => `participant-box participant-${d.type}`)
            .attr('x', -this.config.participantWidth / 2)
            .attr('y', 0)
            .attr('width', this.config.participantWidth)
            .attr('height', this.config.participantHeight)
            .attr('rx', 4);

        // Participant label
        participants
            .append('text')
            .attr('class', 'participant-label')
            .attr('x', 0)
            .attr('y', 20)
            .attr('text-anchor', 'middle')
            .text(d => d.label);

        // Participant IP
        participants
            .append('text')
            .attr('class', 'participant-ip')
            .attr('x', 0)
            .attr('y', 38)
            .attr('text-anchor', 'middle')
            .text(d => d.ip || '');
    }

    renderLifelines() {
        const lifelineHeight = this.height - this.config.marginTop - this.config.participantHeight;

        this.lifelineGroup
            .selectAll('.lifeline')
            .data(this.data.participants)
            .join('line')
            .attr('class', 'lifeline')
            .attr('x1', d => this.participantPositions.get(d.id).x)
            .attr('y1', this.config.marginTop + this.config.participantHeight)
            .attr('x2', d => this.participantPositions.get(d.id).x)
            .attr('y2', this.config.marginTop + this.config.participantHeight + lifelineHeight)
            .attr('stroke-dasharray', '5,5');
    }

    renderMessages() {
        const messages = this.messageGroup
            .selectAll('.message')
            .data(this.data.messages)
            .join('g')
            .attr('class', 'message')
            .attr('transform', (d, i) => {
                const y = this.config.marginTop +
                         this.config.participantHeight +
                         ((i + 1) * this.config.messageHeight);
                return `translate(0, ${y})`;
            });

        // Message arrows
        messages.each((d, i, nodes) => {
            const group = d3.select(nodes[i]);
            const fromPos = this.participantPositions.get(d.from);
            const toPos = this.participantPositions.get(d.to);

            if (!fromPos || !toPos) return;

            const x1 = fromPos.x;
            const x2 = toPos.x;
            const isRightward = x2 > x1;

            // Arrow line
            group.append('line')
                .attr('class', `message-line message-${d.protocol?.toLowerCase()}`)
                .attr('x1', x1)
                .attr('y1', 0)
                .attr('x2', x2)
                .attr('y2', 0);

            // Arrow head
            const arrowPath = isRightward
                ? `M ${x2 - this.config.arrowSize} ${-this.config.arrowSize} L ${x2} 0 L ${x2 - this.config.arrowSize} ${this.config.arrowSize}`
                : `M ${x2 + this.config.arrowSize} ${-this.config.arrowSize} L ${x2} 0 L ${x2 + this.config.arrowSize} ${this.config.arrowSize}`;

            group.append('path')
                .attr('class', `message-arrow message-${d.protocol?.toLowerCase()}`)
                .attr('d', arrowPath);

            // Message label background
            const labelX = (x1 + x2) / 2;
            const labelText = d.label || d.type || 'Message';

            const textElement = group.append('text')
                .attr('class', 'message-label-temp')
                .attr('x', labelX)
                .attr('y', -8)
                .attr('text-anchor', 'middle')
                .text(labelText);

            const bbox = textElement.node().getBBox();

            group.append('rect')
                .attr('class', 'message-label-bg')
                .attr('x', bbox.x - 4)
                .attr('y', bbox.y - 2)
                .attr('width', bbox.width + 8)
                .attr('height', bbox.height + 4)
                .attr('rx', 2);

            // Message label
            group.append('text')
                .attr('class', 'message-label')
                .attr('x', labelX)
                .attr('y', -8)
                .attr('text-anchor', 'middle')
                .text(labelText);

            // Protocol badge
            if (d.protocol) {
                const badge = group.append('g')
                    .attr('class', 'protocol-badge')
                    .attr('transform', `translate(${labelX}, 15)`);

                const badgeText = badge.append('text')
                    .attr('class', 'badge-text-temp')
                    .attr('text-anchor', 'middle')
                    .text(d.protocol);

                const badgeBbox = badgeText.node().getBBox();

                badge.append('rect')
                    .attr('class', `protocol-badge-bg badge-${d.protocol.toLowerCase()}`)
                    .attr('x', badgeBbox.x - 4)
                    .attr('y', badgeBbox.y - 1)
                    .attr('width', badgeBbox.width + 8)
                    .attr('height', badgeBbox.height + 2)
                    .attr('rx', 2);

                badge.append('text')
                    .attr('class', `protocol-badge-text badge-${d.protocol.toLowerCase()}`)
                    .attr('text-anchor', 'middle')
                    .text(d.protocol);

                badgeText.remove();
            }

            textElement.remove();

            // Invisible clickable area
            group.append('rect')
                .attr('class', 'message-clickable')
                .attr('x', Math.min(x1, x2))
                .attr('y', -25)
                .attr('width', Math.abs(x2 - x1))
                .attr('height', 50)
                .attr('fill', 'transparent')
                .attr('cursor', 'pointer')
                .on('click', (event) => this.selectMessage(d, event))
                .on('mouseenter', (event) => this.showTooltip(d, event))
                .on('mouseleave', () => this.hideTooltip());
        });
    }

    renderTimeline() {
        if (!this.data.messages || this.data.messages.length === 0) return;

        const timeScale = d3.scaleTime()
            .domain([
                new Date(this.data.messages[0].timestamp),
                new Date(this.data.messages[this.data.messages.length - 1].timestamp)
            ])
            .range([
                this.config.marginTop + this.config.participantHeight + this.config.messageHeight,
                this.config.marginTop + this.config.participantHeight +
                    (this.data.messages.length * this.config.messageHeight)
            ]);

        const timeAxis = d3.axisLeft(timeScale)
            .ticks(Math.min(10, this.data.messages.length))
            .tickFormat(d3.timeFormat('%H:%M:%S.%L'));

        this.timelineGroup
            .attr('transform', `translate(${this.config.marginLeft + this.config.timelineWidth - 10}, 0)`)
            .call(timeAxis)
            .selectAll('text')
            .attr('class', 'timeline-label');
    }

    selectMessage(message, event) {
        // Remove previous selection
        this.messageGroup.selectAll('.message').classed('selected', false);

        // Add selection to current
        const messageElements = this.messageGroup.selectAll('.message').nodes();
        const index = this.data.messages.indexOf(message);
        if (index >= 0) {
            d3.select(messageElements[index]).classed('selected', true);
        }

        this.selectedMessage = message;

        // Emit event
        this.container.dispatchEvent(new CustomEvent('message-selected', {
            detail: { message }
        }));
    }

    showTooltip(message, event) {
        const details = [];
        details.push(`<strong>${message.label || message.type}</strong>`);
        details.push(`Protocol: ${message.protocol}`);
        details.push(`Time: ${new Date(message.timestamp).toLocaleTimeString()}.${new Date(message.timestamp).getMilliseconds()}`);

        if (message.duration_ms) {
            details.push(`Duration: ${message.duration_ms}ms`);
        }

        if (message.details) {
            Object.entries(message.details).forEach(([key, value]) => {
                details.push(`${key}: ${value}`);
            });
        }

        this.tooltip
            .html(details.join('<br>'))
            .style('left', (event.pageX + 10) + 'px')
            .style('top', (event.pageY - 10) + 'px')
            .style('opacity', 1);
    }

    hideTooltip() {
        this.tooltip.style('opacity', 0);
    }

    showEmptyState() {
        this.container.innerHTML = `
            <div class="ladder-empty-state">
                <i class="bi bi-diagram-3" style="font-size: 48px; opacity: 0.3;"></i>
                <p>No data to display</p>
            </div>
        `;
    }

    // Zoom controls
    zoomIn() {
        this.svg.transition()
            .duration(300)
            .call(this.zoom.scaleBy, 1.3);
    }

    zoomOut() {
        this.svg.transition()
            .duration(300)
            .call(this.zoom.scaleBy, 0.7);
    }

    resetZoom() {
        this.svg.transition()
            .duration(300)
            .call(this.zoom.transform, d3.zoomIdentity);
    }

    // Export functions
    exportSVG() {
        const svgElement = this.svg.node();
        const serializer = new XMLSerializer();
        const svgString = serializer.serializeToString(svgElement);

        // Add CSS styles inline
        const styledSvgString = this.addStylesToSVG(svgString);

        const blob = new Blob([styledSvgString], { type: 'image/svg+xml' });
        const url = URL.createObjectURL(blob);

        const link = document.createElement('a');
        link.href = url;
        link.download = `ladder-diagram-${Date.now()}.svg`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    }

    exportPNG(scale = 2) {
        const svgElement = this.svg.node();
        const serializer = new XMLSerializer();
        const svgString = serializer.serializeToString(svgElement);
        const styledSvgString = this.addStylesToSVG(svgString);

        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        const img = new Image();

        const svgBlob = new Blob([styledSvgString], { type: 'image/svg+xml;charset=utf-8' });
        const url = URL.createObjectURL(svgBlob);

        img.onload = () => {
            canvas.width = this.width * scale;
            canvas.height = this.height * scale;
            ctx.scale(scale, scale);
            ctx.drawImage(img, 0, 0);

            canvas.toBlob((blob) => {
                const link = document.createElement('a');
                link.href = URL.createObjectURL(blob);
                link.download = `ladder-diagram-${Date.now()}.png`;
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                URL.revokeObjectURL(url);
            });
        };

        img.src = url;
    }

    addStylesToSVG(svgString) {
        // Get computed styles from CSS
        const styles = `
            <style>
                .participant-box {
                    fill: var(--bg-secondary, #161b22);
                    stroke: var(--border-color, #30363d);
                    stroke-width: 2;
                }
                .participant-label {
                    fill: var(--text-primary, #f0f6fc);
                    font-size: 14px;
                    font-weight: 600;
                }
                .participant-ip {
                    fill: var(--text-secondary, #8b949e);
                    font-size: 11px;
                }
                .lifeline {
                    stroke: var(--border-color, #30363d);
                    stroke-width: 1.5;
                }
                .message-line {
                    stroke: var(--text-primary, #f0f6fc);
                    stroke-width: 2;
                }
                .message-arrow {
                    fill: var(--text-primary, #f0f6fc);
                }
                .message-label {
                    fill: var(--text-primary, #f0f6fc);
                    font-size: 12px;
                }
                .message-label-bg {
                    fill: var(--bg-secondary, #161b22);
                }
                .timeline-label {
                    fill: var(--text-secondary, #8b949e);
                    font-size: 10px;
                }
            </style>
        `;

        return svgString.replace('<svg', `<svg>${styles}`);
    }

    destroy() {
        if (this.tooltip) {
            this.tooltip.remove();
        }
        if (this.container) {
            this.container.innerHTML = '';
        }
    }
}

// Make available globally
if (typeof window !== 'undefined') {
    window.LadderDiagram = LadderDiagram;
}
