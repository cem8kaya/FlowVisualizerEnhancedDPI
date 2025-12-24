class LadderDiagram {
    constructor(container, options = {}) {
        this.container = typeof container === 'string'
            ? document.getElementById(container)
            : container;

        this.options = {
            participantWidth: 100,
            participantGap: 120,
            messageHeight: 35,
            padding: { top: 70, right: 30, bottom: 40, left: 30 },
            colors: {
                SIP: '#3b82f6',
                DIAMETER: '#8b5cf6',
                GTP: '#f59e0b',
                RTP: '#10b981',
                HTTP2: '#ec4899',
                default: '#6b7280'
            },
            onMessageSelect: null,
            ...options
        };

        this.data = null;
        this.svg = null;
        this.mainGroup = null;
        this.zoom = null;
        this.currentScale = 1;
    }

    render(data) {
        if (!data || !data.participants || !data.messages) {
            console.error('Invalid diagram data');
            return;
        }

        this.data = data;
        this.container.innerHTML = '';

        const width = this.calculateWidth();
        const height = this.calculateHeight();

        // Create SVG with viewBox for responsiveness
        this.svg = d3.select(this.container)
            .append('svg')
            .attr('class', 'ladder-diagram-svg')
            .attr('width', '100%')
            .attr('height', height)
            .attr('viewBox', `0 0 ${width} ${height}`)
            .attr('preserveAspectRatio', 'xMidYMin meet');

        // Background
        this.svg.append('rect')
            .attr('width', width)
            .attr('height', height)
            .attr('fill', 'var(--bg-primary)');

        // Setup zoom
        this.zoom = d3.zoom()
            .scaleExtent([0.3, 3])
            .on('zoom', (event) => {
                this.mainGroup.attr('transform', event.transform);
                this.currentScale = event.transform.k;
            });

        this.svg.call(this.zoom);

        // Main group for all elements
        this.mainGroup = this.svg.append('g')
            .attr('class', 'main-group');

        // Render layers in order
        this.renderParticipants();
        this.renderLifelines();
        this.renderMessages();
    }

    calculateWidth() {
        const { participantWidth, participantGap, padding } = this.options;
        const numParticipants = this.data.participants.length;
        return padding.left + padding.right +
            numParticipants * participantWidth +
            (numParticipants - 1) * participantGap;
    }

    calculateHeight() {
        const { messageHeight, padding } = this.options;
        const numMessages = this.data.messages.length;
        return padding.top + padding.bottom + numMessages * messageHeight + 80;
    }

    renderParticipants() {
        const { participantWidth, participantGap, padding } = this.options;

        const participantGroup = this.mainGroup.append('g')
            .attr('class', 'participants');

        this.data.participants.forEach((p, i) => {
            const x = padding.left + i * (participantWidth + participantGap);
            const y = padding.top - 50;

            const group = participantGroup.append('g')
                .attr('class', 'participant')
                .attr('transform', `translate(${x}, ${y})`);

            // Box
            group.append('rect')
                .attr('class', 'participant-box')
                .attr('width', participantWidth)
                .attr('height', 45)
                .attr('rx', 4)
                .attr('fill', 'var(--bg-secondary)')
                .attr('stroke', 'var(--border-color)')
                .attr('stroke-width', 1);

            // Label (multiline support)
            const labelLines = (p.label || p.ip || 'Unknown').split('\n');
            labelLines.forEach((line, lineIdx) => {
                group.append('text')
                    .attr('class', lineIdx === 0 ? 'participant-label' : 'participant-sublabel')
                    .attr('x', participantWidth / 2)
                    .attr('y', 18 + lineIdx * 14)
                    .attr('text-anchor', 'middle')
                    .attr('fill', lineIdx === 0 ? 'var(--text-primary)' : 'var(--text-secondary)')
                    .attr('font-size', lineIdx === 0 ? '11px' : '9px')
                    .attr('font-weight', lineIdx === 0 ? '600' : '400')
                    .text(line);
            });

            // Store center X for messages
            p._centerX = x + participantWidth / 2;
        });
    }

    renderLifelines() {
        const { participantWidth, participantGap, padding, messageHeight } = this.options;
        const height = this.data.messages.length * messageHeight + 60;

        const lifelineGroup = this.mainGroup.append('g')
            .attr('class', 'lifelines');

        this.data.participants.forEach((p, i) => {
            const x = padding.left + i * (participantWidth + participantGap) + participantWidth / 2;

            lifelineGroup.append('line')
                .attr('class', 'lifeline')
                .attr('x1', x)
                .attr('y1', padding.top)
                .attr('x2', x)
                .attr('y2', padding.top + height)
                .attr('stroke', 'var(--border-color)')
                .attr('stroke-dasharray', '4,4')
                .attr('stroke-width', 1);
        });
    }

    renderMessages() {
        const { padding, messageHeight } = this.options;

        const messageGroup = this.mainGroup.append('g')
            .attr('class', 'messages');

        // Create participant ID to centerX mapping
        const participantCenters = {};
        this.data.participants.forEach(p => {
            participantCenters[p.id] = p._centerX;
        });

        this.data.messages.forEach((msg, i) => {
            const y = padding.top + 10 + i * messageHeight;
            const fromX = participantCenters[msg.from];
            const toX = participantCenters[msg.to];

            if (fromX === undefined || toX === undefined) {
                console.warn('Unknown participant in message:', msg);
                return;
            }

            const isLeftToRight = fromX < toX;
            const color = this.options.colors[msg.protocol] || this.options.colors.default;

            const group = messageGroup.append('g')
                .attr('class', 'message')
                .attr('data-id', msg.id)
                .style('cursor', 'pointer')
                .on('click', () => {
                    if (this.options.onMessageSelect) {
                        this.options.onMessageSelect(msg);
                    }
                });

            // Arrow line
            group.append('line')
                .attr('class', 'message-line')
                .attr('x1', fromX)
                .attr('y1', y)
                .attr('x2', toX)
                .attr('y2', y)
                .attr('stroke', color)
                .attr('stroke-width', 1.5);

            // Arrowhead
            const arrowX = isLeftToRight ? toX - 8 : toX + 8;
            group.append('polygon')
                .attr('class', 'message-arrow')
                .attr('points', isLeftToRight
                    ? `${toX},${y} ${arrowX},${y - 4} ${arrowX},${y + 4}`
                    : `${toX},${y} ${arrowX},${y - 4} ${arrowX},${y + 4}`)
                .attr('fill', color);

            // Label background
            const labelX = (fromX + toX) / 2;
            const label = msg.label || 'Unknown';
            const labelWidth = label.length * 6 + 16;

            group.append('rect')
                .attr('class', 'message-label-bg')
                .attr('x', labelX - labelWidth / 2)
                .attr('y', y - 18)
                .attr('width', labelWidth)
                .attr('height', 14)
                .attr('rx', 2)
                .attr('fill', 'var(--bg-primary)');

            // Label text
            group.append('text')
                .attr('class', 'message-label')
                .attr('x', labelX)
                .attr('y', y - 8)
                .attr('text-anchor', 'middle')
                .attr('fill', color)
                .attr('font-size', '10px')
                .attr('font-weight', '500')
                .text(label);

            // Hover effect
            group.on('mouseenter', function () {
                d3.select(this).select('.message-line').attr('stroke-width', 2.5);
                d3.select(this).select('.message-label').attr('font-weight', '700');
            }).on('mouseleave', function () {
                d3.select(this).select('.message-line').attr('stroke-width', 1.5);
                d3.select(this).select('.message-label').attr('font-weight', '500');
            });
        });
    }

    // Zoom controls
    zoomIn() {
        this.svg.transition().duration(300).call(
            this.zoom.scaleBy, 1.3
        );
    }

    zoomOut() {
        this.svg.transition().duration(300).call(
            this.zoom.scaleBy, 0.7
        );
    }

    resetZoom() {
        this.svg.transition().duration(300).call(
            this.zoom.transform, d3.zoomIdentity
        );
    }

    // Export functions
    exportSVG(filename = 'diagram.svg') {
        const svgElement = this.container.querySelector('svg');
        if (!svgElement) return;

        // Clone and add styles
        const clone = svgElement.cloneNode(true);
        clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg');

        // Add inline styles
        const styles = `
            .participant-box { fill: #1e293b; stroke: #334155; }
            .participant-label { fill: #f1f5f9; }
            .participant-sublabel { fill: #94a3b8; }
            .lifeline { stroke: #334155; }
            .message-line { stroke-linecap: round; }
            .message-label { font-family: Inter, sans-serif; }
        `;
        const styleElement = document.createElementNS('http://www.w3.org/2000/svg', 'style');
        styleElement.textContent = styles;
        clone.insertBefore(styleElement, clone.firstChild);

        // Download
        const blob = new Blob([clone.outerHTML], { type: 'image/svg+xml' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);
    }

    exportPNG(filename = 'diagram.png', scale = 2) {
        const svgElement = this.container.querySelector('svg');
        if (!svgElement) return;

        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        const svgData = new XMLSerializer().serializeToString(svgElement);
        const img = new Image();

        const width = svgElement.viewBox.baseVal.width * scale;
        const height = svgElement.viewBox.baseVal.height * scale;

        canvas.width = width;
        canvas.height = height;

        img.onload = () => {
            ctx.fillStyle = '#0f172a';  // Dark background
            ctx.fillRect(0, 0, width, height);
            ctx.drawImage(img, 0, 0, width, height);

            canvas.toBlob(blob => {
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = filename;
                a.click();
                URL.revokeObjectURL(url);
            }, 'image/png');
        };

        img.src = 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(svgData)));
    }
}

window.LadderDiagram = LadderDiagram;
