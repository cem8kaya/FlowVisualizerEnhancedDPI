// Flowchart / Sequence Diagram Visualization
// Placeholder for M4 - Basic implementation

const flowchart = {
    svg: null,

    init(containerId, events) {
        const container = document.getElementById(containerId);
        if (!container) return;

        if (!events || events.length === 0) {
            container.innerHTML = '<div class="text-center text-muted p-5">No events to display</div>';
            return;
        }

        // Initialize mermaid
        mermaid.initialize({ startOnLoad: true, theme: 'default' });

        // Generate Mermaid syntax
        const graphDefinition = this.generateSequenceDiagram(events);

        // Render
        container.innerHTML = `<div class="mermaid">${graphDefinition}</div>`;

        try {
            mermaid.init(undefined, container.querySelectorAll('.mermaid'));
        } catch (e) {
            console.error('Mermaid rendering failed:', e);
            container.innerHTML = `<div class="alert alert-danger">Failed to render diagram: ${e.message}</div>`;
        }
    },

    generateSequenceDiagram(events) {
        let diagram = 'sequenceDiagram\n';
        diagram += '    autonumber\n';

        // Extract participants
        const participants = new Set();
        events.forEach(e => {
            const src = `${e.src_ip}`; // Simplified for clarity, could include port
            const dst = `${e.dst_ip}`;
            participants.add(src);
            participants.add(dst);
        });

        // Add participants to diagram
        participants.forEach(p => {
            // Sanitize name for Mermaid
            const safeName = p.replace(/[^a-zA-Z0-9]/g, '_');
            diagram += `    participant ${safeName} as ${p}\n`;
        });

        // Add messages
        events.forEach(e => {
            const src = e.src_ip.replace(/[^a-zA-Z0-9]/g, '_');
            const dst = e.dst_ip.replace(/[^a-zA-Z0-9]/g, '_');
            const desc = e.short || e.message_type || 'Message';

            // Simple arrow for now
            diagram += `    ${src}->>${dst}: ${desc}\n`;

            // Add note for details if useful
            // diagram += `    Note right of ${src}: ${new Date(e.timestamp).toLocaleTimeString()}\n`;
        });

        return diagram;
    }
};
