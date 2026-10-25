/*
 * Copyright (C) 2026 Onur Berkay <onurberkay@sakla.app>
 * All rights reserved. (BSD 2-Clause, see LICENSE)
 *
 * LAN Usage: small dependency free SVG charts (timeline, horizontal bars, donut).
 * Text is always set through textContent, data may contain untrusted strings.
 */
(function (global) {
    'use strict';

    const NS = 'http://www.w3.org/2000/svg';
    const PALETTE = ['#2a9fd6', '#e8742f', '#4caf50', '#9c6ade', '#f2b632', '#17a2b8',
                     '#d9534f', '#20c997', '#8d6e63', '#7f8c8d'];
    const registry = new Map();
    let tip = null;

    (function injectStyle() {
        const css = '.lu-svg{display:block;overflow:visible}.lu-svg text{fill:currentColor;font-size:11px}' +
            '.lu-svg .grid{stroke:currentColor;stroke-opacity:.12}.lu-svg .axis{opacity:.65}' +
            '.lu-svg .row:hover .bar{opacity:.8}.lu-svg .row.click{cursor:pointer}' +
            '.lu-tip{position:fixed;z-index:3000;pointer-events:none;display:none;background:rgba(25,25,25,.94);' +
            'color:#fff;padding:6px 9px;border-radius:3px;font-size:12px;line-height:1.5;box-shadow:0 2px 6px rgba(0,0,0,.3)}' +
            '.lu-tip i{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:6px}' +
            '.lu-legend{display:flex;flex-wrap:wrap;gap:4px 14px;font-size:12px;margin:2px 0 6px}' +
            '.lu-legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px;vertical-align:-1px}' +
            '.lu-empty{padding:40px 0;text-align:center;opacity:.6}';
        const style = document.createElement('style');
        style.textContent = css;
        document.head.appendChild(style);
    })();

    function el(name, attrs, parent) {
        const node = document.createElementNS(NS, name);
        Object.keys(attrs || {}).forEach(k => node.setAttribute(k, attrs[k]));
        if (parent) parent.appendChild(node);
        return node;
    }

    function label(parent, x, y, str, attrs) {
        const node = el('text', Object.assign({x: x, y: y}, attrs || {}), parent);
        node.textContent = str;
        return node;
    }

    function truncate(str, max) {
        str = String(str);
        return str.length > max ? str.slice(0, max - 1) + '…' : str;
    }

    function niceMax(v) {
        if (!(v > 0)) return 1;
        const p = Math.pow(10, Math.floor(Math.log10(v)));
        const n = v / p;
        return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 2.5 ? 2.5 : n <= 5 ? 5 : 10) * p;
    }

    /* tooltip: lines = [[color|null, text], ...] */
    function showTip(lines, ev) {
        if (!tip) {
            tip = document.createElement('div');
            tip.className = 'lu-tip';
            document.body.appendChild(tip);
        }
        tip.textContent = '';
        lines.forEach(function (line, i) {
            const div = document.createElement('div');
            if (line[0]) {
                const sw = document.createElement('i');
                sw.style.background = line[0];
                div.appendChild(sw);
            }
            div.appendChild(document.createTextNode(line[1]));
            if (i === 0) div.style.fontWeight = '600';
            tip.appendChild(div);
        });
        tip.style.display = 'block';
        const w = tip.offsetWidth, h = tip.offsetHeight;
        let x = ev.clientX + 14, y = ev.clientY + 14;
        if (x + w > window.innerWidth - 8) x = ev.clientX - w - 14;
        if (y + h > window.innerHeight - 8) y = ev.clientY - h - 14;
        tip.style.left = x + 'px';
        tip.style.top = y + 'px';
    }

    function hideTip() {
        if (tip) tip.style.display = 'none';
    }

    function prepare(container, draw) {
        registry.set(container, draw);
        container.textContent = '';
        return container.clientWidth || container.parentNode.clientWidth || 600;
    }

    function empty(container, msg) {
        const div = document.createElement('div');
        div.className = 'lu-empty';
        div.textContent = msg || 'No data for this period';
        container.appendChild(div);
    }

    function legend(container, items) {
        const box = document.createElement('div');
        box.className = 'lu-legend';
        items.forEach(function (item) {
            const span = document.createElement('span');
            const sw = document.createElement('i');
            sw.style.background = item.color;
            span.appendChild(sw);
            span.appendChild(document.createTextNode(item.label));
            box.appendChild(span);
        });
        container.appendChild(box);
    }

    /*
     * timeline(container, points, opts)
     *   points: [{t: epoch, values: [v1, v2, ...]}]
     *   opts: {series: [{label, color}], format(v), timeFormat(t), height}
     */
    function timeline(container, points, opts) {
        const W = prepare(container, () => timeline(container, points, opts));
        const H = opts.height || 240;
        const m = {l: 58, r: 14, t: 10, b: 24};
        const iw = W - m.l - m.r, ih = H - m.t - m.b;
        const fmt = opts.format || String;
        legend(container, opts.series);
        const n = points.length;
        let max = 0;
        points.forEach(p => p.values.forEach(v => { if (v > max) max = v; }));
        if (!n) return empty(container);
        max = niceMax(max);

        const svg = el('svg', {width: W, height: H, class: 'lu-svg'}, container);
        const x = i => m.l + (n === 1 ? iw / 2 : i * iw / (n - 1));
        const y = v => m.t + ih - (v / max) * ih;

        for (let i = 0; i <= 4; i++) {
            const v = max * i / 4;
            el('line', {x1: m.l, x2: W - m.r, y1: y(v), y2: y(v), class: 'grid'}, svg);
            label(svg, m.l - 6, y(v) + 4, fmt(v), {'text-anchor': 'end', class: 'axis'});
        }
        const ticks = Math.max(2, Math.floor(iw / 95));
        const step = Math.max(1, Math.ceil((n - 1) / ticks));
        for (let i = 0; i < n; i += step) {
            label(svg, x(i), H - 6, opts.timeFormat(points[i].t),
                  {'text-anchor': i === 0 ? 'start' : 'middle', class: 'axis'});
        }

        opts.series.forEach(function (s, si) {
            let line = '';
            points.forEach((p, i) => { line += (i ? 'L' : 'M') + x(i).toFixed(1) + ',' + y(p.values[si]).toFixed(1); });
            el('path', {d: line + 'L' + x(n - 1).toFixed(1) + ',' + y(0) + 'L' + x(0).toFixed(1) + ',' + y(0) + 'Z',
                        fill: s.color, 'fill-opacity': 0.12, stroke: 'none'}, svg);
            el('path', {d: line, fill: 'none', stroke: s.color, 'stroke-width': 1.7, 'stroke-linejoin': 'round'}, svg);
        });

        const guide = el('line', {y1: m.t, y2: m.t + ih, stroke: 'currentColor', 'stroke-opacity': 0.35,
                                  visibility: 'hidden'}, svg);
        const dots = opts.series.map(s => el('circle', {r: 3.5, fill: s.color, visibility: 'hidden'}, svg));
        const overlay = el('rect', {x: m.l, y: m.t, width: Math.max(iw, 1), height: ih, fill: 'transparent'}, svg);
        overlay.addEventListener('mousemove', function (ev) {
            const box = svg.getBoundingClientRect();
            const i = Math.min(n - 1, Math.max(0, Math.round((ev.clientX - box.left - m.l) / iw * (n - 1))));
            guide.setAttribute('x1', x(i));
            guide.setAttribute('x2', x(i));
            guide.setAttribute('visibility', 'visible');
            dots.forEach(function (d, si) {
                d.setAttribute('cx', x(i));
                d.setAttribute('cy', y(points[i].values[si]));
                d.setAttribute('visibility', 'visible');
            });
            showTip([[null, opts.timeFormat(points[i].t, true)]].concat(
                opts.series.map((s, si) => [s.color, s.label + ': ' + fmt(points[i].values[si])])), ev);
        });
        overlay.addEventListener('mouseleave', function () {
            guide.setAttribute('visibility', 'hidden');
            dots.forEach(d => d.setAttribute('visibility', 'hidden'));
            hideTip();
        });
    }

    /*
     * hbar(container, items, opts)
     *   items: [{label, sub, value, color}]
     *   opts: {format(v), onClick(item), color, tip(item) -> [[color, text], ...]}
     */
    function hbar(container, items, opts) {
        const W = prepare(container, () => hbar(container, items, opts));
        if (!items.length) return empty(container);
        const fmt = opts.format || String;
        const rowH = 24, lw = Math.min(190, Math.max(110, W * 0.36)), vw = 66;
        const bw = Math.max(20, W - lw - vw - 10);
        const max = Math.max.apply(null, items.map(i => i.value)) || 1;
        const svg = el('svg', {width: W, height: items.length * rowH + 4, class: 'lu-svg'}, container);
        items.forEach(function (item, idx) {
            const g = el('g', {class: 'row' + (opts.onClick ? ' click' : ''),
                               transform: 'translate(0,' + (idx * rowH + 2) + ')'}, svg);
            el('rect', {x: 0, y: 0, width: W, height: rowH, fill: 'transparent'}, g);
            const text = label(g, lw - 8, 16, '', {'text-anchor': 'end'});
            const main = document.createElementNS(NS, 'tspan');
            main.textContent = truncate(item.label, Math.floor(lw / 7.2));
            text.appendChild(main);
            if (item.sub) {
                const sub = document.createElementNS(NS, 'tspan');
                sub.setAttribute('opacity', '0.6');
                sub.textContent = ' ' + truncate(item.sub, 14);
                text.appendChild(sub);
            }
            const width = Math.max(2, item.value / max * bw);
            el('rect', {x: lw, y: 5, width: width, height: rowH - 10, rx: 2, class: 'bar',
                        fill: item.color || opts.color || PALETTE[0]}, g);
            label(g, lw + width + 6, 16, fmt(item.value), {class: 'axis'});
            g.addEventListener('mousemove', ev => showTip(opts.tip ? opts.tip(item)
                : [[null, item.label + (item.sub ? ' ' + item.sub : '')], [null, fmt(item.value)]], ev));
            g.addEventListener('mouseleave', hideTip);
            if (opts.onClick) g.addEventListener('click', () => { hideTip(); opts.onClick(item); });
        });
    }

    /*
     * donut(container, items, opts)
     *   items: [{label, value}]
     */
    function donut(container, items, opts) {
        const W = prepare(container, () => donut(container, items, opts));
        opts = opts || {};
        const total = items.reduce((a, i) => a + i.value, 0);
        if (!total) return empty(container, opts.emptyText);
        const shown = items.slice(0, 9);
        const rest = items.slice(9).reduce((a, i) => a + i.value, 0);
        if (rest) shown.push({label: 'other', value: rest});
        shown.forEach((item, i) => { item.color = item.color || PALETTE[i % PALETTE.length]; });

        const size = Math.min(200, W * 0.5), r = size / 2 - 4, r0 = r * 0.6, cx = size / 2, cy = size / 2;
        const wrap = document.createElement('div');
        wrap.style.cssText = 'display:flex;align-items:center;gap:16px;flex-wrap:wrap';
        container.appendChild(wrap);
        const svg = el('svg', {width: size, height: size, class: 'lu-svg'}, wrap);
        let a0 = -Math.PI / 2;
        shown.forEach(function (item) {
            const frac = item.value / total;
            const a1 = a0 + frac * Math.PI * 2 - (frac >= 1 ? 1e-4 : 0);
            const large = a1 - a0 > Math.PI ? 1 : 0;
            const p = (rad, a) => (cx + rad * Math.cos(a)).toFixed(2) + ',' + (cy + rad * Math.sin(a)).toFixed(2);
            const path = el('path', {
                d: 'M' + p(r, a0) + 'A' + r + ',' + r + ' 0 ' + large + ' 1 ' + p(r, a1) +
                   'L' + p(r0, a1) + 'A' + r0 + ',' + r0 + ' 0 ' + large + ' 0 ' + p(r0, a0) + 'Z',
                fill: item.color, stroke: 'rgba(128,128,128,.25)', 'stroke-width': 0.5
            }, svg);
            path.addEventListener('mousemove', ev => showTip([[item.color, item.label],
                [null, item.value + ' (' + (frac * 100).toFixed(1) + '%)']], ev));
            path.addEventListener('mouseleave', hideTip);
            a0 = a1;
        });
        label(svg, cx, cy + 2, String(total), {'text-anchor': 'middle', style: 'font-size:20px;font-weight:600'});
        label(svg, cx, cy + 18, opts.centerLabel || 'total', {'text-anchor': 'middle', class: 'axis'});

        const list = document.createElement('div');
        list.style.cssText = 'font-size:12px;line-height:1.75;min-width:120px';
        shown.forEach(function (item) {
            const row = document.createElement('div');
            const sw = document.createElement('i');
            sw.style.cssText = 'display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:6px;background:' + item.color;
            row.appendChild(sw);
            row.appendChild(document.createTextNode(item.label + ' · ' + item.value));
            list.appendChild(row);
        });
        wrap.appendChild(list);
    }

    let resizeTimer = null;
    window.addEventListener('resize', function () {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(function () {
            registry.forEach(function (draw, container) {
                if (!document.body.contains(container)) registry.delete(container);
                else if (container.offsetParent !== null) draw();
            });
        }, 200);
    });

    function redrawVisible() {
        registry.forEach(function (draw, container) {
            if (container.offsetParent !== null) draw();
        });
    }

    global.LUCharts = {timeline: timeline, hbar: hbar, donut: donut, redrawVisible: redrawVisible, palette: PALETTE};
})(window);
