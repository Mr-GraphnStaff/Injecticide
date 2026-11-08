/* Local, bounded raster export. Package labels are drawn as text, never markup. */
async function downloadMapPng(map, filename, kindLabels = {}) {
    const nodes = map?.nodes;
    const edges = map?.edges;
    if (!Array.isArray(nodes) || !nodes.length) throw Error('Add a component before exporting a PNG.');
    if (nodes.length > 100 || !Array.isArray(edges) || edges.length > 200) throw Error('Map exceeds the PNG export limits.');
    if (nodes.some(node => !Number.isFinite(node.x) || !Number.isFinite(node.y) || Math.abs(node.x) > 100000 || Math.abs(node.y) > 100000)) {
        throw Error('The map contains unsupported component coordinates.');
    }

    // Include the entire map, including edge channels routed below the cards.
    // Raster allocation stays below 4096 pixels per side and 12 million pixels.
    const left = Math.min(...nodes.map(node => node.x)) - 64;
    const top = Math.min(...nodes.map(node => node.y)) - 24;
    const right = Math.max(...nodes.map(node => node.x)) + 284;
    const bottom = Math.max(...nodes.map(node => node.y)) + 144;
    const padding = 28, headerHeight = 110, footerHeight = 82;
    const width = Math.max(720, right - left + padding * 2);
    const height = bottom - top + headerHeight + footerHeight;
    const scale = Math.min(2, 4096 / width, 4096 / height, Math.sqrt(12000000 / (width * height)));
    const canvas = document.createElement('canvas');
    canvas.width = Math.max(1, Math.floor(width * scale));
    canvas.height = Math.max(1, Math.floor(height * scale));
    const context = canvas.getContext('2d', { alpha: false });
    if (!context) throw Error('PNG export is unavailable in this browser.');
    context.scale(scale, scale);
    context.fillStyle = '#081f19';
    context.fillRect(0, 0, width, height);

    function drawText(value, x, y, maxWidth, maxLines, lineHeight) {
        let remaining = String(value ?? '').replace(/\s+/g, ' ').trim().slice(0, 1000);
        const lines = [];
        while (remaining && lines.length < maxLines) {
            const letters = Array.from(remaining);
            let count = letters.length;
            while (count > 1 && context.measureText(letters.slice(0, count).join('')).width > maxWidth) count--;
            let line = letters.slice(0, count).join('');
            if (count < letters.length && line.lastIndexOf(' ') > 0) {
                line = line.slice(0, line.lastIndexOf(' '));
                count = Array.from(line).length;
            }
            lines.push(line);
            remaining = letters.slice(count).join('').trimStart();
        }
        if (remaining && lines.length) {
            let last = lines[lines.length - 1];
            while (last.length && context.measureText(last + '…').width > maxWidth) last = Array.from(last).slice(0, -1).join('');
            lines[lines.length - 1] = last + '…';
        }
        lines.forEach((line, index) => context.fillText(line, x, y + index * lineHeight));
    }

    context.fillStyle = '#a7e6d4';
    context.font = '600 12px system-ui, sans-serif';
    context.fillText('INJECTICIDE  /  ANOTHER DAF-TECH PRODUCT', padding, 26);
    context.fillStyle = '#effbf6';
    context.font = '700 23px system-ui, sans-serif';
    drawText(map.name || 'Untitled system', padding, 56, width - padding * 2, 2, 28);

    context.save();
    context.translate(padding - left, headerHeight - top);
    const byId = new Map(nodes.map(node => [node.id, node]));
    for (const edge of edges) {
        const source = byId.get(edge.source), target = byId.get(edge.target);
        if (!source || !target) continue;
        const color = edge.untrusted || edge.write ? '#edc47c' : '#91cbbb';
        context.strokeStyle = color;
        context.fillStyle = color;
        context.lineWidth = 2;
        // Orthogonal routing, matching the on-screen map: edges between the same
        // columns share a vertical channel instead of crossing as curves.
        context.globalAlpha = edges.length > 40 && !(edge.untrusted || edge.write) ? 0.45 : 1;
        context.beginPath();
        const sx = source.x + 220, sy = source.y + 50, tx = target.x, ty = target.y + 50;
        context.moveTo(sx, sy);
        if (tx - sx >= 24) {
            const mx = Math.round(sx + (tx - sx) / 2);
            context.lineTo(mx, sy); context.lineTo(mx, ty); context.lineTo(tx, ty);
        } else {
            const lane = Math.abs(source.y - target.y) > 120 ? Math.round((Math.min(source.y, target.y) + 100 + Math.max(source.y, target.y)) / 2) : Math.max(source.y, target.y) + 118;
            context.lineTo(sx + 18, sy); context.lineTo(sx + 18, lane); context.lineTo(tx - 18, lane); context.lineTo(tx - 18, ty); context.lineTo(tx, ty);
        }
        context.stroke();
        context.globalAlpha = 1;
        context.beginPath();
        context.moveTo(target.x, target.y + 50);
        context.lineTo(target.x - 10, target.y + 45);
        context.lineTo(target.x - 10, target.y + 55);
        context.closePath();
        context.fill();
    }
    for (const node of nodes) {
        context.fillStyle = '#153b30';
        context.fillRect(node.x, node.y, 220, 100);
        context.strokeStyle = node.kind === 'unresolved_reference' ? '#edc47c' : '#6aa791';
        context.lineWidth = 2;
        context.setLineDash(node.kind === 'unresolved_reference' ? [6, 4] : []);
        context.strokeRect(node.x, node.y, 220, 100);
        context.setLineDash([]);
        context.fillStyle = '#a7e6d4';
        context.font = '600 11px system-ui, sans-serif';
        drawText(kindLabels[node.kind] || node.kind, node.x + 12, node.y + 20, 196, 1, 14);
        context.fillStyle = '#effbf6';
        context.font = '600 14px system-ui, sans-serif';
        drawText(node.label || 'Unnamed component', node.x + 12, node.y + 44, 196, 2, 18);
        context.fillStyle = '#bed8cd';
        context.font = '11px system-ui, sans-serif';
        // Only declared values are drawn; a repeated "unknown · unknown" line adds no information.
        const footnote = [node.trust && node.trust !== 'unknown' ? `Trust: ${node.trust}` : '', node.sensitivity && node.sensitivity !== 'unknown' ? `Data: ${node.sensitivity}` : ''].filter(Boolean).join(' · ');
        if (footnote) drawText(footnote, node.x + 12, node.y + 85, 196, 1, 14);
    }
    context.restore();

    context.fillStyle = '#d1e8de';
    context.font = '600 12px system-ui, sans-serif';
    drawText('Modeled map · runtime and control enforcement unverified.', padding, height - 57, width - padding * 2, 1, 16);
    context.font = '11px system-ui, sans-serif';
    drawText('Gold connections: declared untrusted content or writes. Labels shortened to fit; export JSON for complete map data.', padding, height - 36, width - padding * 2, 2, 15);

    // PNG is required by the canvas API. A null callback indicates encoding
    // failure; no external images are drawn, so cross-origin canvas taint is avoided.
    let blob;
    try {
        blob = await new Promise((resolve, reject) => {
            canvas.toBlob(value => value && value.size ? resolve(value) : reject(Error('PNG encoding failed. Try exporting the map as JSON.')), 'image/png');
        });
    } catch (error) {
        throw Error(`PNG export failed: ${error.message || 'browser encoding unavailable'}`);
    } finally {
        canvas.width = 1;
        canvas.height = 1;
    }
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    try { link.click(); }
    finally { link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1500); }
}
