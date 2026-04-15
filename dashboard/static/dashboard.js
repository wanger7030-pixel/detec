/* ============================================================
   Integrated Detection System — Dashboard JavaScript
   D3.js powered visualisations and API interaction
   ============================================================ */

// ============================================================
// Tab Navigation
// ============================================================

let graphLoaded = false;
document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        tab.classList.add('active');
        document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
        // Lazy-load the attack graph when its tab becomes visible
        if (tab.dataset.tab === 'graph' && !graphLoaded) {
            graphLoaded = true;
            setTimeout(() => loadGraph(), 50);
        }
    });
});


// ============================================================
// API Fetch Helper
// ============================================================

async function fetchAPI(endpoint) {
    try {
        const resp = await fetch(endpoint);
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        return await resp.json();
    } catch (err) {
        console.error(`API error [${endpoint}]:`, err);
        return null;
    }
}


// ============================================================
// Initialise Dashboard
// ============================================================

async function init() {
    const stats = await fetchAPI('/api/stats');
    if (!stats) {
        showEmptyState();
        return;
    }

    // Update header badges
    document.getElementById('total-alerts').textContent = stats.total_alerts || 0;
    document.getElementById('total-correlations').textContent = stats.total_correlations || 0;
    document.getElementById('total-iocs').textContent = stats.total_iocs || 0;

    // Render overview charts
    if (stats.alerts_by_source) renderDonut('#chart-source', stats.alerts_by_source, sourceColors);
    if (stats.alerts_by_severity) renderDonut('#chart-severity', stats.alerts_by_severity, severityColors);
    if (stats.iocs_by_type) renderBarChart('#chart-ioc-types', stats.iocs_by_type);

    // Load top correlations
    loadTopCorrelations();

    // Load timeline
    loadTimeline();

    // Attack graph is loaded lazily when the tab is clicked
    // (because the hidden tab has 0 width)

    // Load tables
    loadAlerts();
    loadIoCs();
}


function showEmptyState() {
    document.getElementById('tab-overview').innerHTML = `
        <div class="empty-state">
            <div class="icon">📭</div>
            <p>No data yet. Run the analysis pipeline first:</p>
            <pre style="text-align:left; display:inline-block; margin-top:16px;">
python -m src.orchestrator --pcap data/pcap/*.pcap --sample-dir data/malware_samples/
            </pre>
        </div>
    `;
}


// ============================================================
// Colour Maps
// ============================================================

const sourceColors = {
    snort: '#4f8cff',
    yara: '#a855f7',
    static: '#06b6d4',
    dynamic_cape: '#f97316',
};

const severityColors = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#22c55e',
};


// ============================================================
// Donut Chart (D3) — for source / severity breakdowns
// ============================================================

function renderDonut(selector, data, colorMap) {
    const container = document.querySelector(selector);
    container.innerHTML = '';

    const entries = Object.entries(data).filter(([, v]) => v > 0);
    if (entries.length === 0) {
        container.innerHTML = '<div class="empty-state"><p>No data</p></div>';
        return;
    }

    const width = container.clientWidth;
    const height = Math.min(container.clientHeight || 280, 260);
    const radius = Math.min(width, height) / 2 - 20;

    const svg = d3.select(selector)
        .append('svg')
        .attr('width', width)
        .attr('height', height)
        .append('g')
        .attr('transform', `translate(${width / 2}, ${height / 2})`);

    const pie = d3.pie().value(d => d[1]).sort(null);
    const arc = d3.arc().innerRadius(radius * 0.55).outerRadius(radius);
    const arcHover = d3.arc().innerRadius(radius * 0.55).outerRadius(radius + 6);

    const arcs = svg.selectAll('path')
        .data(pie(entries))
        .enter()
        .append('path')
        .attr('d', arc)
        .attr('fill', d => colorMap[d.data[0]] || '#666')
        .attr('stroke', '#1c1f2e')
        .attr('stroke-width', 2)
        .style('cursor', 'pointer')
        .on('mouseover', function (event, d) {
            d3.select(this).transition().duration(200).attr('d', arcHover);
            showTooltip(event, `${d.data[0]}: ${d.data[1]}`);
        })
        .on('mouseout', function () {
            d3.select(this).transition().duration(200).attr('d', arc);
            hideTooltip();
        });

    // Center total
    const total = entries.reduce((s, [, v]) => s + v, 0);
    svg.append('text')
        .attr('text-anchor', 'middle')
        .attr('dy', '-0.2em')
        .attr('fill', '#e4e6f0')
        .attr('font-size', '1.8rem')
        .attr('font-weight', '700')
        .text(total);
    svg.append('text')
        .attr('text-anchor', 'middle')
        .attr('dy', '1.2em')
        .attr('fill', '#5a5e73')
        .attr('font-size', '0.7rem')
        .text('TOTAL');

    // Legend
    const legend = d3.select(selector)
        .append('div')
        .style('display', 'flex')
        .style('justify-content', 'center')
        .style('gap', '16px')
        .style('margin-top', '8px')
        .style('flex-wrap', 'wrap');

    entries.forEach(([key, val]) => {
        legend.append('div')
            .style('display', 'flex')
            .style('align-items', 'center')
            .style('gap', '6px')
            .style('font-size', '0.75rem')
            .style('color', '#8b8fa3')
            .html(`<span style="width:10px;height:10px;border-radius:50%;background:${colorMap[key] || '#666'};display:inline-block;"></span>${key} (${val})`);
    });
}


// ============================================================
// Bar Chart (D3) — for IoC type distribution
// ============================================================

function renderBarChart(selector, data) {
    const container = document.querySelector(selector);
    container.innerHTML = '';

    const entries = Object.entries(data).filter(([, v]) => v > 0);
    if (entries.length === 0) {
        container.innerHTML = '<div class="empty-state"><p>No data</p></div>';
        return;
    }

    const margin = { top: 20, right: 20, bottom: 50, left: 50 };
    const width = container.clientWidth - margin.left - margin.right;
    const height = (container.clientHeight || 260) - margin.top - margin.bottom;

    const svg = d3.select(selector)
        .append('svg')
        .attr('width', width + margin.left + margin.right)
        .attr('height', height + margin.top + margin.bottom)
        .append('g')
        .attr('transform', `translate(${margin.left}, ${margin.top})`);

    const x = d3.scaleBand()
        .domain(entries.map(d => d[0]))
        .range([0, width])
        .padding(0.3);

    const y = d3.scaleLinear()
        .domain([0, d3.max(entries, d => d[1]) * 1.1])
        .range([height, 0]);

    // Bars
    svg.selectAll('rect')
        .data(entries)
        .enter()
        .append('rect')
        .attr('x', d => x(d[0]))
        .attr('y', d => y(d[1]))
        .attr('width', x.bandwidth())
        .attr('height', d => height - y(d[1]))
        .attr('rx', 4)
        .attr('fill', '#4f8cff')
        .style('cursor', 'pointer')
        .on('mouseover', function (event, d) {
            d3.select(this).attr('fill', '#6aa3ff');
            showTooltip(event, `${d[0]}: ${d[1]}`);
        })
        .on('mouseout', function () {
            d3.select(this).attr('fill', '#4f8cff');
            hideTooltip();
        });

    // Value labels
    svg.selectAll('.val-label')
        .data(entries)
        .enter()
        .append('text')
        .attr('x', d => x(d[0]) + x.bandwidth() / 2)
        .attr('y', d => y(d[1]) - 6)
        .attr('text-anchor', 'middle')
        .attr('fill', '#8b8fa3')
        .attr('font-size', '0.7rem')
        .text(d => d[1]);

    // X Axis
    svg.append('g')
        .attr('transform', `translate(0, ${height})`)
        .call(d3.axisBottom(x))
        .selectAll('text')
        .attr('fill', '#5a5e73')
        .attr('font-size', '0.65rem')
        .attr('transform', 'rotate(-25)')
        .style('text-anchor', 'end');

    svg.selectAll('.domain, .tick line').attr('stroke', '#2a2d3e');
}


// ============================================================
// Timeline Visualisation (D3)
// ============================================================

async function loadTimeline() {
    const data = await fetchAPI('/api/timeline');
    if (!data || !data.events || data.events.length === 0) return;

    const container = document.getElementById('timeline-chart');
    container.innerHTML = '';

    const margin = { top: 30, right: 30, bottom: 40, left: 120 };
    const width = container.clientWidth - margin.left - margin.right;
    const height = Math.max(400, data.events.length * 28);

    const svg = d3.select('#timeline-chart')
        .append('svg')
        .attr('width', width + margin.left + margin.right)
        .attr('height', height + margin.top + margin.bottom)
        .append('g')
        .attr('transform', `translate(${margin.left}, ${margin.top})`);

    // Parse timestamps
    const events = data.events.map((e, i) => ({
        ...e,
        idx: i,
        time: new Date(e.timestamp)
    }));

    const x = d3.scaleTime()
        .domain(d3.extent(events, d => d.time))
        .range([0, width]);

    const y = d3.scalePoint()
        .domain(events.map(d => d.alert_id))
        .range([0, height])
        .padding(0.5);

    // Grid lines
    svg.selectAll('.grid-line')
        .data(x.ticks(6))
        .enter()
        .append('line')
        .attr('x1', d => x(d))
        .attr('x2', d => x(d))
        .attr('y1', 0)
        .attr('y2', height)
        .attr('stroke', '#2a2d3e')
        .attr('stroke-dasharray', '3,3');

    // Correlation links
    if (data.links) {
        data.links.forEach(link => {
            const e1 = events.find(e => e.alert_id === link.alert_id_1);
            const e2 = events.find(e => e.alert_id === link.alert_id_2);
            if (e1 && e2) {
                svg.append('line')
                    .attr('x1', x(e1.time))
                    .attr('y1', y(e1.alert_id))
                    .attr('x2', x(e2.time))
                    .attr('y2', y(e2.alert_id))
                    .attr('stroke', '#a855f7')
                    .attr('stroke-width', 1.5)
                    .attr('stroke-opacity', Math.min(link.score || 0.5, 1))
                    .attr('stroke-dasharray', '4,2');
            }
        });
    }

    // Event dots
    svg.selectAll('circle')
        .data(events)
        .enter()
        .append('circle')
        .attr('cx', d => x(d.time))
        .attr('cy', d => y(d.alert_id))
        .attr('r', 6)
        .attr('fill', d => sourceColors[d.source] || '#666')
        .attr('stroke', '#1c1f2e')
        .attr('stroke-width', 2)
        .style('cursor', 'pointer')
        .on('mouseover', function (event, d) {
            d3.select(this).attr('r', 9);
            showTooltip(event, `[${d.source}] ${d.message}`);
        })
        .on('mouseout', function () {
            d3.select(this).attr('r', 6);
            hideTooltip();
        })
        .on('click', (event, d) => showAlertDetail(d));

    // Labels
    svg.selectAll('.event-label')
        .data(events)
        .enter()
        .append('text')
        .attr('x', d => x(d.time) + 10)
        .attr('y', d => y(d.alert_id) + 4)
        .attr('fill', '#8b8fa3')
        .attr('font-size', '0.65rem')
        .text(d => d.message ? d.message.substring(0, 50) : '')

    // X Axis
    svg.append('g')
        .attr('transform', `translate(0, ${height})`)
        .call(d3.axisBottom(x).ticks(6))
        .selectAll('text')
        .attr('fill', '#5a5e73')
        .attr('font-size', '0.7rem');

    svg.selectAll('.domain, .tick line').attr('stroke', '#2a2d3e');
}


// ============================================================
// Force-Directed Attack Graph (D3)
// ============================================================

async function loadGraph() {
    const [alertData, corrData] = await Promise.all([
        fetchAPI('/api/alerts'),
        fetchAPI('/api/correlations?min_score=0.3'),
    ]);

    if (!alertData || !corrData) return;

    const alerts = alertData.data || [];
    const correlations = corrData.data || [];

    if (alerts.length === 0) return;

    const container = document.getElementById('force-graph');
    container.innerHTML = '';

    const width = container.clientWidth;
    const height = container.clientHeight || 500;

    const svg = d3.select('#force-graph')
        .append('svg')
        .attr('width', width)
        .attr('height', height);

    // Build nodes and links
    const nodeMap = {};
    alerts.forEach(a => {
        nodeMap[a.alert_id] = {
            id: a.alert_id,
            source: a.source,
            severity: a.severity,
            message: a.message,
            data: a,
        };
    });

    // Ensure all correlated alert IDs exist as nodes
    correlations.forEach(c => {
        if (!nodeMap[c.alert_id_1]) {
            nodeMap[c.alert_id_1] = {
                id: c.alert_id_1,
                source: (c.details && c.details.source_1) || 'unknown',
                severity: 'medium',
                message: c.correlation_type,
                data: { alert_id: c.alert_id_1 },
            };
        }
        if (!nodeMap[c.alert_id_2]) {
            nodeMap[c.alert_id_2] = {
                id: c.alert_id_2,
                source: (c.details && c.details.source_2) || 'unknown',
                severity: 'medium',
                message: c.correlation_type,
                data: { alert_id: c.alert_id_2 },
            };
        }
    });

    // Only keep nodes that are part of a correlation (for cleaner graph)
    const correlatedIds = new Set();
    correlations.forEach(c => {
        correlatedIds.add(c.alert_id_1);
        correlatedIds.add(c.alert_id_2);
    });

    const nodes = Object.values(nodeMap).filter(n => correlatedIds.has(n.id));
    const links = correlations
        .map(c => ({
            source: c.alert_id_1,
            target: c.alert_id_2,
            score: c.score || 0.5,
            type: c.correlation_type,
        }));

    // --- Zoom & Pan support ---
    const g = svg.append('g');
    const zoom = d3.zoom()
        .scaleExtent([0.3, 4])
        .on('zoom', (event) => g.attr('transform', event.transform));
    svg.call(zoom);

    // Simulation — tighter forces for compact layout
    const simulation = d3.forceSimulation(nodes)
        .force('link', d3.forceLink(links).id(d => d.id).distance(60))
        .force('charge', d3.forceManyBody().strength(-120))
        .force('center', d3.forceCenter(width / 2, height / 2).strength(0.15))
        .force('collision', d3.forceCollide().radius(20))
        .force('x', d3.forceX(width / 2).strength(0.08))
        .force('y', d3.forceY(height / 2).strength(0.08));

    // Links
    const link = g.selectAll('line.link')
        .data(links)
        .enter()
        .append('line')
        .attr('class', 'link')
        .attr('stroke-width', d => Math.max(2, d.score * 6))
        .attr('stroke', d => d.score > 0.7 ? '#ef4444' : d.score > 0.4 ? '#f59e0b' : '#64748b')
        .attr('stroke-opacity', 0.6);

    // Nodes
    const node = g.selectAll('circle.node')
        .data(nodes)
        .enter()
        .append('circle')
        .attr('r', d => severityRadius(d.severity))
        .attr('fill', d => sourceColors[d.source] || '#8b8fa3')
        .attr('stroke', d => sourceColors[d.source] || '#8b8fa3')
        .attr('stroke-width', 3)
        .attr('stroke-opacity', 0.4)
        .style('cursor', 'grab')
        .on('mouseover', function (event, d) {
            d3.select(this).attr('r', severityRadius(d.severity) + 4).attr('stroke-opacity', 0.8);
            showTooltip(event, `[${d.source}] ${d.message}`);
        })
        .on('mouseout', function (event, d) {
            d3.select(this).attr('r', severityRadius(d.severity)).attr('stroke-opacity', 0.4);
            hideTooltip();
        })
        .on('click', (event, d) => showAlertDetail(d.data))
        .call(d3.drag()
            .on('start', (event, d) => {
                if (!event.active) simulation.alphaTarget(0.3).restart();
                d.fx = d.x; d.fy = d.y;
                d3.select(event.sourceEvent.target).style('cursor', 'grabbing');
            })
            .on('drag', (event, d) => { d.fx = event.x; d.fy = event.y; })
            .on('end', (event, d) => {
                if (!event.active) simulation.alphaTarget(0);
                d.fx = null; d.fy = null;
                d3.select(event.sourceEvent.target).style('cursor', 'grab');
            })
        );

    // Labels
    const label = g.selectAll('text.node-label')
        .data(nodes)
        .enter()
        .append('text')
        .attr('class', 'node-label')
        .attr('dy', -14)
        .attr('text-anchor', 'middle')
        .attr('fill', '#94a3b8')
        .attr('font-size', '10px')
        .text(d => d.id.substring(0, 12));

    simulation.on('tick', () => {
        link.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
        node.attr('cx', d => d.x).attr('cy', d => d.y);
        label.attr('x', d => d.x).attr('y', d => d.y);
    });

    // Auto-fit all nodes into view after simulation settles
    simulation.on('end', () => {
        const bounds = g.node().getBBox();
        if (bounds.width > 0 && bounds.height > 0) {
            const pad = 40;
            const scale = Math.min(
                (width - pad * 2) / bounds.width,
                (height - pad * 2) / bounds.height,
                1.5
            );
            const tx = width / 2 - scale * (bounds.x + bounds.width / 2);
            const ty = height / 2 - scale * (bounds.y + bounds.height / 2);
            svg.transition().duration(500).call(
                zoom.transform,
                d3.zoomIdentity.translate(tx, ty).scale(scale)
            );
        }
    });

    // Score slider — also hides nodes with no visible links
    document.getElementById('score-slider').addEventListener('input', function () {
        const val = this.value / 100;
        document.getElementById('score-value').textContent = val.toFixed(2);

        // Hide/show links based on score threshold
        link.attr('display', d => d.score >= val ? null : 'none');

        // Find nodes that still have at least one visible link
        const visibleIds = new Set();
        links.forEach(l => {
            if (l.score >= val) {
                const srcId = typeof l.source === 'object' ? l.source.id : l.source;
                const tgtId = typeof l.target === 'object' ? l.target.id : l.target;
                visibleIds.add(srcId);
                visibleIds.add(tgtId);
            }
        });

        // Hide/show nodes and labels accordingly
        node.attr('display', d => visibleIds.has(d.id) ? null : 'none');
        label.attr('display', d => visibleIds.has(d.id) ? null : 'none');
    });
}

function severityRadius(severity) {
    switch (severity) {
        case 'critical': return 14;
        case 'high': return 11;
        case 'medium': return 8;
        default: return 6;
    }
}


// ============================================================
// Alert Table
// ============================================================

async function loadAlerts() {
    const source = document.getElementById('filter-source')?.value || '';
    const severity = document.getElementById('filter-severity')?.value || '';
    let url = '/api/alerts?limit=200';
    if (source) url += `&source=${source}`;
    if (severity) url += `&severity=${severity}`;

    const data = await fetchAPI(url);
    if (!data || !data.data) return;

    const container = document.getElementById('alerts-table');
    if (data.data.length === 0) {
        container.innerHTML = '<div class="empty-state"><p>No alerts found</p></div>';
        return;
    }

    let html = `<table>
        <thead><tr>
            <th>ID</th><th>Source</th><th>Severity</th>
            <th>Message</th><th>Timestamp</th>
        </tr></thead><tbody>`;

    data.data.forEach(alert => {
        html += `<tr onclick='showAlertDetail(${JSON.stringify(alert).replace(/'/g, "\\'")})'>
            <td>${alert.alert_id || ''}</td>
            <td><span class="source source-${alert.source}">${alert.source}</span></td>
            <td><span class="severity severity-${alert.severity}">${alert.severity}</span></td>
            <td>${alert.message || ''}</td>
            <td>${alert.timestamp || ''}</td>
        </tr>`;
    });

    html += '</tbody></table>';
    container.innerHTML = html;
}


// ============================================================
// IoC Table
// ============================================================

async function loadIoCs() {
    const iocType = document.getElementById('filter-ioc-type')?.value || '';
    let url = '/api/iocs?limit=200';
    if (iocType) url += `&type=${iocType}`;

    const data = await fetchAPI(url);
    if (!data || !data.data) return;

    const container = document.getElementById('iocs-table');
    if (data.data.length === 0) {
        container.innerHTML = '<div class="empty-state"><p>No IoCs found</p></div>';
        return;
    }

    let html = `<table>
        <thead><tr>
            <th>Type</th><th>Value</th><th>Source</th>
            <th>Confidence</th><th>Context</th>
        </tr></thead><tbody>`;

    data.data.forEach(ioc => {
        html += `<tr>
            <td><span class="source source-${ioc.source}">${ioc.ioc_type}</span></td>
            <td style="font-family:monospace;">${ioc.value || ''}</td>
            <td>${ioc.source || ''}</td>
            <td>${(ioc.confidence || 1).toFixed(2)}</td>
            <td>${ioc.context || ''}</td>
        </tr>`;
    });

    html += '</tbody></table>';
    container.innerHTML = html;
}


// ============================================================
// Top Correlations
// ============================================================

async function loadTopCorrelations() {
    const data = await fetchAPI('/api/correlations?min_score=0.3&limit=10');
    if (!data || !data.data) return;

    const container = document.getElementById('top-correlations');
    if (data.data.length === 0) {
        container.innerHTML = '<div class="empty-state"><p>No correlations found</p></div>';
        return;
    }

    let html = `<table>
        <thead><tr>
            <th>Alert 1</th><th>Alert 2</th><th>Type</th><th>Score</th>
        </tr></thead><tbody>`;

    data.data.forEach(c => {
        const scoreColor = c.score > 0.7 ? 'var(--accent-red)' :
            c.score > 0.5 ? 'var(--accent-yellow)' : 'var(--accent-green)';
        html += `<tr>
            <td>${(c.alert_id_1 || '').substring(0, 16)}</td>
            <td>${(c.alert_id_2 || '').substring(0, 16)}</td>
            <td>${c.correlation_type || ''}</td>
            <td style="color:${scoreColor};font-weight:600;">${(c.score || 0).toFixed(3)}</td>
        </tr>`;
    });

    html += '</tbody></table>';
    container.innerHTML = html;
}


// ============================================================
// Detail Panel
// ============================================================

function showAlertDetail(alert) {
    const panel = document.getElementById('detail-panel');
    const overlay = document.getElementById('overlay');
    const title = document.getElementById('detail-title');
    const body = document.getElementById('detail-body');

    title.textContent = `Alert: ${(alert.alert_id || '').substring(0, 20)}`;

    let html = '';
    const fields = [
        ['Alert ID', alert.alert_id],
        ['Source', alert.source],
        ['Severity', alert.severity],
        ['Message', alert.message],
        ['Timestamp', alert.timestamp],
    ];

    fields.forEach(([label, value]) => {
        if (value) {
            html += `<div class="detail-field">
                <div class="detail-label">${label}</div>
                <div class="detail-value">${value}</div>
            </div>`;
        }
    });

    if (alert.details) {
        html += `<div class="detail-field">
            <div class="detail-label">Details (JSON)</div>
            <pre>${JSON.stringify(alert.details, null, 2)}</pre>
        </div>`;
    }

    body.innerHTML = html;
    panel.classList.add('open');
    overlay.classList.add('open');
}

function closeDetailPanel() {
    document.getElementById('detail-panel').classList.remove('open');
    document.getElementById('overlay').classList.remove('open');
}


// ============================================================
// Tooltip
// ============================================================

let tooltipEl = null;

function showTooltip(event, text) {
    if (!tooltipEl) {
        tooltipEl = document.createElement('div');
        tooltipEl.className = 'tooltip';
        document.body.appendChild(tooltipEl);
    }
    tooltipEl.textContent = text;
    tooltipEl.style.left = (event.pageX + 12) + 'px';
    tooltipEl.style.top = (event.pageY - 28) + 'px';
    tooltipEl.style.display = 'block';
}

function hideTooltip() {
    if (tooltipEl) tooltipEl.style.display = 'none';
}


// ============================================================
// File Upload & Real-Time Analysis
// ============================================================

function initUpload() {
    const zone = document.getElementById('upload-zone');
    const fileInput = document.getElementById('file-input');
    if (!zone || !fileInput) return;

    // Click to select
    zone.addEventListener('click', () => fileInput.click());

    // Drag events
    zone.addEventListener('dragover', (e) => {
        e.preventDefault();
        zone.classList.add('dragover');
    });
    zone.addEventListener('dragleave', () => zone.classList.remove('dragover'));
    zone.addEventListener('drop', (e) => {
        e.preventDefault();
        zone.classList.remove('dragover');
        if (e.dataTransfer.files.length > 0) {
            analyzeFile(e.dataTransfer.files[0]);
        }
    });

    // File input change
    fileInput.addEventListener('change', () => {
        if (fileInput.files.length > 0) {
            analyzeFile(fileInput.files[0]);
        }
    });
}

async function analyzeFile(file) {
    const progress = document.getElementById('upload-progress');
    const progressFill = document.getElementById('progress-fill');
    const statusText = document.getElementById('upload-status');
    const resultDiv = document.getElementById('analysis-result');
    const detailsCard = document.getElementById('analysis-details-card');
    const detailsDiv = document.getElementById('analysis-details');

    // Show progress
    progress.style.display = 'block';
    progressFill.style.width = '30%';
    statusText.textContent = `Uploading ${file.name} (${(file.size / 1024).toFixed(1)} KB)...`;
    resultDiv.innerHTML = '<p class="placeholder-text">Analyzing...</p>';

    const formData = new FormData();
    formData.append('file', file);

    progressFill.style.width = '60%';
    statusText.textContent = 'Running static analysis + YARA scan...';

    try {
        const resp = await fetch('/api/analyze', { method: 'POST', body: formData });
        const result = await resp.json();

        progressFill.style.width = '100%';
        statusText.textContent = `Analysis complete in ${result.analysis_time_ms} ms`;

        // Render result
        renderAnalysisResult(result, resultDiv);
        renderAnalysisDetails(result, detailsCard, detailsDiv);

        // Refresh dashboard stats
        setTimeout(() => {
            init();
            progressFill.style.width = '0%';
            progress.style.display = 'none';
        }, 2000);

    } catch (err) {
        progressFill.style.width = '100%';
        progressFill.style.background = 'var(--accent-red)';
        statusText.textContent = `Error: ${err.message}`;
        resultDiv.innerHTML = `<p class="placeholder-text" style="color:var(--accent-red);">Analysis failed: ${err.message}</p>`;
    }
}

function renderAnalysisResult(result, container) {
    const alerts = result.alerts_generated || 0;
    const iocs = result.iocs_extracted || 0;
    const yaraMatches = result.yara_matches?.matched_rules?.length || 0;
    const entropy = result.static_analysis?.entropy || 0;

    // Determine verdict
    let verdict, verdictClass;
    if (yaraMatches > 0 || alerts >= 3) {
        verdict = '⚠️ Malicious';
        verdictClass = 'verdict-malicious';
    } else if (alerts > 0 || entropy > 7.0) {
        verdict = '🔶 Suspicious';
        verdictClass = 'verdict-suspicious';
    } else {
        verdict = '✅ Clean';
        verdictClass = 'verdict-clean';
    }

    let html = `
        <div class="result-header">
            <span class="result-verdict ${verdictClass}">${verdict}</span>
            <span style="color:var(--text-muted);font-size:0.8rem;">${result.analysis_time_ms} ms</span>
        </div>
        <div class="result-metric"><span class="label">Filename</span><span class="value">${result.filename}</span></div>
        <div class="result-metric"><span class="label">File Size</span><span class="value">${(result.file_size / 1024).toFixed(1)} KB</span></div>
    `;

    if (result.static_analysis && !result.static_analysis.error) {
        const sa = result.static_analysis;
        if (sa.file_hash_md5) html += `<div class="result-metric"><span class="label">MD5</span><span class="value">${sa.file_hash_md5}</span></div>`;
        if (sa.file_hash_sha256) html += `<div class="result-metric"><span class="label">SHA-256</span><span class="value" style="font-size:0.7rem;">${sa.file_hash_sha256}</span></div>`;
        html += `<div class="result-metric"><span class="label">Entropy</span><span class="value" style="color:${entropy > 7.0 ? 'var(--accent-red)' : entropy > 6.0 ? 'var(--accent-yellow)' : 'var(--accent-green)'}">${entropy.toFixed(3)}</span></div>`;
        html += `<div class="result-metric"><span class="label">Strings Found</span><span class="value">${sa.strings_count || 0}</span></div>`;
    }

    html += `<div class="result-metric"><span class="label">Alerts Generated</span><span class="value" style="color:${alerts > 0 ? 'var(--accent-orange)' : 'var(--accent-green)'}">${alerts}</span></div>`;
    html += `<div class="result-metric"><span class="label">IoCs Extracted</span><span class="value">${iocs}</span></div>`;
    html += `<div class="result-metric"><span class="label">YARA Matches</span><span class="value" style="color:${yaraMatches > 0 ? 'var(--accent-red)' : 'var(--accent-green)'}">${yaraMatches > 0 ? result.yara_matches.matched_rules.join(', ') : 'None'}</span></div>`;

    container.innerHTML = html;
}

function renderAnalysisDetails(result, card, container) {
    const allAlerts = [
        ...(result.static_analysis?.alerts || []),
        ...(result.yara_matches?.alerts || []),
    ];

    if (allAlerts.length === 0) {
        card.style.display = 'none';
        return;
    }

    card.style.display = 'block';
    let html = '';

    allAlerts.forEach(alert => {
        const sevClass = `severity-${alert.severity || 'low'}`;
        html += `
            <div class="finding-item">
                <div class="finding-title">
                    <span class="severity ${sevClass}" style="margin-right:8px;">${alert.severity}</span>
                    <span class="source source-${alert.source}" style="margin-right:8px;">${alert.source}</span>
                    ${alert.title || ''}
                </div>
                <div class="finding-desc">${alert.description || ''}</div>
            </div>
        `;
    });

    container.innerHTML = html;
}


// ============================================================
// Start
// ============================================================

document.addEventListener('DOMContentLoaded', () => {
    init();
    initUpload();
});
