{#
 # Copyright (C) 2026 Onur Berkay <onurberkay@sakla.app>
 # All rights reserved. (BSD 2-Clause, see LICENSE)
 #
 # HostGuard dashboard
 #}

<script src="{{ cache_safe('/ui/js/hostguard.charts.js') }}"></script>

<style>
    .hg-toolbar { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; padding: 12px 14px 4px; }
    .hg-toolbar .form-control { height: 30px; padding: 4px 8px; }
    .hg-toolbar .hg-sep { flex: 1 1 auto; }
    .hg-ipbox { display: flex; gap: 4px; align-items: center; }
    .hg-ipbox input { width: 190px; }
    .hg-kpis { display: flex; flex-wrap: wrap; gap: 10px; padding: 10px 14px 14px; }
    .hg-kpi { flex: 1 1 150px; border: 1px solid rgba(128,128,128,.25); border-radius: 3px; padding: 8px 12px; }
    .hg-kpi .l { font-size: 11px; opacity: .7; text-transform: uppercase; letter-spacing: .04em; }
    .hg-kpi .v { font-size: 22px; font-weight: 600; line-height: 1.3; }
    .hg-kpi .s { font-size: 11px; opacity: .65; }
    .hg-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 22px 28px; padding: 16px; }
    .hg-panel h4 { font-size: 13px; font-weight: 600; margin: 0 0 8px; }
    .hg-panel.wide { grid-column: 1 / -1; }
    .hg-chart { width: 100%; min-height: 60px; }
    .hg-badge { display: inline-block; padding: 1px 6px; margin: 1px 3px 1px 0; border-radius: 3px; font-size: 11px;
                background: rgba(128,128,128,.16); white-space: nowrap; }
    .hg-badge.in { background: rgba(42,159,214,.2); }
    .hg-badge.out { background: rgba(232,116,47,.22); }
    .hg-badge.svc { background: rgba(76,175,80,.22); }
    a.hg-badge { color: inherit; cursor: pointer; text-decoration: none; }
    a.hg-badge:hover { outline: 1px solid rgba(128,128,128,.5); }
    .hg-pane { padding: 14px; }
    .hg-table-tools { display: flex; gap: 10px; align-items: center; margin-bottom: 8px; flex-wrap: wrap; }
    .hg-table-tools .hg-search { width: 260px; height: 30px; }
    .hg-table-tools select { height: 30px; width: auto; }
    .hg-table-tools .hg-count { opacity: .65; font-size: 12px; margin-left: auto; }
    .hg-cond-form { display: flex; gap: 12px; align-items: flex-end; flex-wrap: wrap; margin-bottom: 8px; }
    .hg-cond-form label { font-size: 12px; font-weight: normal; margin: 0; display: flex; flex-direction: column; gap: 3px; }
    .hg-cond-form .form-control { height: 30px; width: auto; max-width: 100%; }
    .hg-cond-form #hg-cf-rule { max-width: 420px; }
    .hg-table-wrap { max-height: 640px; overflow: auto; }
    table.hg-table th { cursor: pointer; white-space: nowrap; user-select: none; }
    table.hg-table th.nosort { cursor: default; }
    table.hg-table td { vertical-align: middle !important; }
    table.hg-table td.num, table.hg-table th.num { text-align: right; white-space: nowrap; }
    table.hg-table td.nowrap { white-space: nowrap; }
    table.hg-table td.banner { max-width: 340px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
                               font-family: monospace; font-size: 11px; }
    .hg-ip { cursor: pointer; font-family: monospace; }
    .hg-state-open { color: #4caf50; font-weight: 600; }
    .hg-state-closed, .hg-state-error, .hg-state-unreachable { color: #d9534f; }
    .hg-state-filtered { color: #e8742f; }
    .hg-probe-form { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; margin-bottom: 12px; }
    .hg-probe-form input, .hg-probe-form select { height: 30px; width: auto; }
    #hg-probe-result { margin-bottom: 12px; }
    #hg-probe-result dl { margin: 0; }
    #hg-probe-result dt { width: 90px; }
    #hg-probe-result dd { margin-left: 110px; word-break: break-all; }
    .hg-kpi.alert-on { border-color: #d9534f; background: rgba(217,83,79,.08); }
    .hg-kpi.alert-on .v { color: #d9534f; }
    .hg-badge.lan { background: rgba(217,83,79,.2); }
    .hg-badge.warn { background: rgba(240,173,78,.3); }
    .hg-sev { display: inline-block; min-width: 62px; text-align: center; padding: 1px 6px; border-radius: 3px;
              font-size: 11px; font-weight: 600; color: #fff; text-transform: uppercase; }
    .hg-sev.critical { background: #a94442; }
    .hg-sev.high { background: #d9534f; }
    .hg-sev.medium { background: #e8942f; }
    .hg-sev.info { background: #5bc0de; }
    #hg-alert-strip { margin: 16px 16px 0; padding: 10px 14px; border-left: 4px solid #d9534f;
                      background: rgba(217,83,79,.07); display: none; }
    #hg-alert-strip h4 { font-size: 13px; font-weight: 600; margin: 0 0 6px; }
    #hg-alert-strip .row-a { padding: 2px 0; font-size: 12px; }
    #hg-alert-strip .row-a .t { opacity: .6; margin-left: 6px; }
    tr.hg-acked { opacity: .55; }
    tr.hg-row-warn > td { background: rgba(240,173,78,.12) !important; }
    tr.hg-row-bad > td { background: rgba(217,83,79,.10) !important; }
    #hg-tabs .badge { background: #d9534f; margin-left: 4px; }
    .hg-note { font-size: 12px; opacity: .7; margin-bottom: 8px; }
</style>

<script>
$(function () {
    'use strict';
    const API = '/api/hostguard/stats/';
    const COND_API = '/api/hostguard/conditions/';   // own privilege: it changes the virusprot table
    const COLOR_IN = '#2a9fd6', COLOR_OUT = '#e8742f';
    const S = {hours: 24, ip: '', metric: 'conns', tab: 'overview', summary: null, timer: null};

    function pref(key, value) {
        try {
            if (value === undefined) return window.localStorage.getItem('hostguard.' + key);
            window.localStorage.setItem('hostguard.' + key, value);
        } catch (e) {
            return null;
        }
    }

    /* formatting */
    function esc(v) {
        return String(v === null || v === undefined ? '' : v).replace(/[&<>"']/g, function (c) {
            return '&#' + c.charCodeAt(0) + ';';
        });
    }
    // "tcp/22"; port 0 of TCP / UDP is the traffic past a host's busiest ports ("tcp/other"); a protocol
    // without ports: its name
    function portText(proto, port) {
        if (proto === 'tcp' || proto === 'udp') return proto + '/' + (port ? port : 'other');
        return port ? proto + '/' + port : proto;
    }
    function fmtBytes(b) {
        b = Number(b) || 0;
        const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
        let i = 0;
        while (b >= 1024 && i < units.length - 1) {
            b /= 1024;
            i++;
        }
        return (i ? b.toFixed(b < 10 ? 1 : 0) : Math.round(b)) + ' ' + units[i];
    }
    function fmtNum(n) {
        n = Number(n) || 0;
        if (n >= 1e9) return (n / 1e9).toFixed(1) + 'G';
        if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
        if (n >= 1e4) return (n / 1e3).toFixed(1) + 'k';
        return String(Math.round(n * 100) / 100);
    }
    function fmtMetric(v) {
        return S.metric === 'bytes' ? fmtBytes(v) : fmtNum(v);
    }
    function pad(n) {
        return n < 10 ? '0' + n : String(n);
    }
    function fmtTime(t, full) {
        const d = new Date(t * 1000);
        const hm = pad(d.getHours()) + ':' + pad(d.getMinutes());
        if (!full && S.hours <= 24) return hm;
        return pad(d.getDate()) + '.' + pad(d.getMonth() + 1) + ((full || S.hours <= 72) ? ' ' + hm : '');
    }
    function fmtDate(t) {
        if (!t) return '';
        const d = new Date(t * 1000);
        return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' +
               pad(d.getHours()) + ':' + pad(d.getMinutes());
    }
    function ago(t) {
        if (!t) return '';
        const s = Math.max(0, Date.now() / 1000 - t);
        const txt = s < 90 ? 'just now' : s < 5400 ? Math.round(s / 60) + ' min ago' :
                    s < 129600 ? Math.round(s / 3600) + ' h ago' : Math.round(s / 86400) + ' d ago';
        return '<span title="' + esc(fmtDate(t)) + '">' + txt + '</span>';
    }
    function ipKey(ip) {
        ip = String(ip);
        if (ip.indexOf('.') > -1 && ip.indexOf(':') === -1) {
            return '4' + ip.split('.').map(function (o) { return ('00' + o).slice(-3); }).join('.');
        }
        return '6' + ip;
    }
    function ipLink(ip) {
        return '<a class="hg-ip" data-ip="' + esc(ip) + '" title="Show this host">' + esc(ip) + '</a>';
    }
    function dirBadge(d) {
        return d === 'in' ? '<span class="hg-badge in">→ in</span>' : '<span class="hg-badge out">← out</span>';
    }
    function testButton(ip, port, proto) {
        if (proto !== 'tcp' && proto !== 'udp') return '';
        return '<button type="button" class="btn btn-default btn-xs hg-test" title="Test service" data-ip="' +
               esc(ip) + '" data-port="' + esc(port) + '" data-proto="' + esc(proto) + '"><i class="fa fa-stethoscope"></i></button>';
    }

    // owner and network type of an outside source (public lists, lib/ipdata.py): from address lists (official
    // first), else the AS category ipverse estimates (isp / business / hosting / education / government)
    const NET_KINDS = {cloud: 'Cloud', cdn: 'CDN', vpn: 'VPN', hosting: 'Hosting / datacenter', service: 'Online service',
                       isp: 'ISP (home, mobile)', business: 'Business', education: 'Education / research',
                       government: 'Government', other: 'Unknown', unrouted: 'Not routed'};
    const NET_CLASS = {cloud: 'in', cdn: 'svc', vpn: 'warn', hosting: 'out', service: 'svc'};
    // what an address is used for, next to its network type
    const NET_ROLES = {tor: 'Tor exit', crawler: 'Crawler', monitoring: 'Monitoring', relay: 'Private Relay'};
    const ROLE_CLASS = {tor: 'lan', crawler: 'svc', monitoring: 'svc', relay: 'in'};
    function netKind(n) {
        // asn 0: announced by nobody; null: the owner list is missing, so unknown
        return n.kind || (n.asn === 0 ? 'unrouted' : 'other');
    }
    function netText(r) {
        const n = r.net;
        if (!n) return '';
        // "as:16276;" finds exactly that AS (a search term matches anywhere: AS16276 would also find AS162760)
        return 'kind:' + netKind(n) + ' ' + (n.role ? 'role:' + n.role + ' ' + n.role_name + ' ' : '') +
               (n.asn ? 'AS' + n.asn + ' as:' + n.asn + '; ' : '') + n.as_name + ' ' + n.provider + ' ' + n.cc + (n.drop ? ' asn-drop' : '');
    }
    function netCell(r) {
        const n = r.net;
        if (!n) return '';
        const kind = netKind(n);
        const estimated = n.basis === 'AS category';
        const tip = (n.asn ? 'AS' + n.asn + ' ' + n.as_name : n.asn === 0 ? 'no BGP origin' : 'owner unknown (list not downloaded)') + (n.cc ? ' (' + n.cc + ')' : '') +
                    (n.basis ? ' · type from: ' + n.basis : '');
        return '<span class="hg-badge ' + (NET_CLASS[kind] || '') + '"' + (estimated ?
                   ' style="border:1px dashed rgba(128,128,128,.6)" title="Estimated from the category of the AS (ipverse)"' : '') +
               '>' + esc(NET_KINDS[kind] || kind) + (estimated ? ' ~' : '') + '</span>' +
               (n.role ? '<span class="hg-badge ' + (ROLE_CLASS[n.role] || '') + '" title="' + esc(n.role_name) + '">' +
                         esc(NET_ROLES[n.role] || n.role) + '</span>' : '') +
               (n.drop ? '<span class="hg-badge lan" title="Spamhaus ASN-DROP: a network run by or for criminals">ASN-DROP</span>' : '') +
               ' <span title="' + esc(tip) + '">' + esc(n.provider || n.as_name || '') +
               (n.cc ? ' <span class="text-muted">' + esc(n.cc) + '</span>' : '') + '</span>';
    }

    function showError(msg) {
        $('#hg-error').text(msg || 'Request failed').show();
    }
    function ok(data) {
        if (!data || data.status !== 'ok') {
            showError(data && data.message ? data.message : 'Unexpected response from the backend');
            return false;
        }
        $('#hg-error').hide();
        return true;
    }
    // the outcome of an action: stays until closed (the reloads that follow hide #hg-error)
    function notice(msg, isError) {
        $('#hg-notice').toggleClass('alert-danger', !!isError).toggleClass('alert-warning', !isError)
            .find('.hg-notice-text').text(msg);
        $('#hg-notice').show();
    }
    $('#hg-notice-close').on('click', function () { $('#hg-notice').hide(); });

    // only the latest request of an endpoint is rendered: a slow answer for an earlier period or host
    // filter must not overwrite a newer one
    const latest = {};
    function api(endpoint, extra) {
        const params = Object.assign({hours: S.hours}, extra || {});
        if (S.ip) params.ip = S.ip;
        const seq = latest[endpoint] = (latest[endpoint] || 0) + 1;
        const result = $.Deferred();
        $.ajax({url: API + endpoint, data: params, dataType: 'json', cache: false})
            .done(function (data) { if (latest[endpoint] === seq) result.resolve(data); })
            .fail(function (xhr) {
                if (latest[endpoint] !== seq) return;
                showError('Request failed: ' + xhr.status + ' ' + xhr.statusText);
                result.reject(xhr);
            });
        return result.promise();
    }

    /* sortable / searchable table */
    function makeTable(id, columns, sortKey, rowClass, emptyText) {
        const t = {rows: [], sort: sortKey, desc: true, filter: ''};
        const $wrap = $('#' + id);
        const $head = $wrap.find('thead tr');
        columns.forEach(function (c) {
            const $th = $('<th/>').text(c.label).addClass((c.cls || '') + (c.nosort ? ' nosort' : '')).appendTo($head);
            if (c.nosort) return;
            $th.on('click', function () {
                if (t.sort === c.key) {
                    t.desc = !t.desc;
                } else {
                    t.sort = c.key;
                    t.desc = !!c.num;
                }
                t.render();
            });
        });
        $wrap.find('.hg-search').on('input', function () {
            t.filter = this.value.trim().toLowerCase();
            t.render();
        });
        t.setRows = function (rows) {
            rows.forEach(function (r) {
                r._s = columns.map(function (c) { return c.text ? c.text(r) : (c.key ? r[c.key] : ''); })
                              .join(' ').toLowerCase();
            });
            t.rows = rows;
            t.render();
        };
        t.setFilter = function (value) {
            $wrap.find('.hg-search').val(value);
            t.filter = value.toLowerCase();
            t.render();
        };
        t.render = function () {
            const terms = t.filter.split(/\s+/).filter(Boolean);
            const rows = t.rows.filter(function (r) {
                return terms.every(function (term) { return r._s.indexOf(term) !== -1; });
            });
            const col = columns.find(function (c) { return c.key === t.sort; });
            if (col) {
                const val = col.sortValue || function (r) { return r[col.key]; };
                rows.sort(function (a, b) {
                    const x = val(a), y = val(b);
                    const cmp = (typeof x === 'number' && typeof y === 'number') ? x - y
                        : String(x).localeCompare(String(y), undefined, {numeric: true});
                    return t.desc ? -cmp : cmp;
                });
            }
            const shown = rows.slice(0, 1000);
            const html = shown.map(function (r) {
                return '<tr class="' + (rowClass ? rowClass(r) : '') + '">' + columns.map(function (c) {
                    return '<td class="' + (c.cls || '') + '">' + (c.html ? c.html(r) : esc(r[c.key])) + '</td>';
                }).join('') + '</tr>';
            }).join('');
            $wrap.find('tbody').html(html ||
                '<tr><td colspan="' + columns.length + '" class="text-center text-muted">' + esc(emptyText || 'No data for this period') + '</td></tr>');
            $wrap.find('.hg-count').text(rows.length > shown.length
                ? 'showing ' + shown.length + ' of ' + rows.length : rows.length + ' rows');
            $head.find('th').each(function (i) {
                const c = columns[i];
                $(this).find('i').remove();
                if (c.key === t.sort) {
                    $(this).append(' <i class="fa fa-caret-' + (t.desc ? 'down' : 'up') + '"></i>');
                }
            });
        };
        return t;
    }

    const ALERT_TYPES = {
        lateral: 'LAN → LAN connection',
        lateral_scan: 'LAN → LAN scan',
        multi_ip: 'Multiple IPs on one MAC',
        l2_flood: 'ARP / ND flood',
        ip_changed: 'IP changed',
        mac_changed: 'IP moved to another MAC',
        state_table: 'State table filling up',
        pf_limit: 'pf limit reached',
        host_states: 'Many states (host, warning threshold)',
        host_rate: 'Connection rate (host, warning threshold)',
        rule_limit: 'Rule near its limit',
        in_table: 'LAN host in block table',
        blocked_out: 'Blocked outbound (host)',
        blocked_in: 'Blocked attack (host)',
        rule_blocking: 'Block rule busy',
        src_limit: 'Source at rule limit',
        attack: 'Attack on a host',
        ids: 'Suricata alert (severity 1)',
        autoblock: 'Block condition matched',
        shaper_drop: 'Shaper limit reached'
    };
    /* block reasons: table hit / limit / state table / bogon / no pass rule */
    function reasonClass(reason) {
        reason = String(reason || '');
        if (reason.charAt(0) === '<') return 'lan';
        if (reason.indexOf('limit') > -1 || reason.indexOf('state') > -1 || reason.indexOf('shaper') > -1) return 'warn';
        if (reason.indexOf('bogon') > -1) return 'out';
        return '';
    }
    function whyText(list) {
        return (list || []).map(function (w) { return w.reason; }).join(' ');
    }
    function whyHtml(list) {
        return (list || []).map(function (w) {
            return '<span class="hg-badge ' + reasonClass(w.reason) + '" title="' + esc(w.reason) + '">' +
                   esc(w.pct) + '% ' + esc(String(w.reason).length > 34 ? String(w.reason).slice(0, 33) + '…' : w.reason) + '</span>';
        }).join(' ');
    }
    function fmtBits(bps) {
        bps = Number(bps) || 0;
        if (bps >= 1e9) return (bps / 1e9).toFixed(2) + ' Gbit/s';
        if (bps >= 1e6) return (bps / 1e6).toFixed(1) + ' Mbit/s';
        if (bps >= 1e3) return (bps / 1e3).toFixed(0) + ' Kbit/s';
        return Math.round(bps) + ' bit/s';
    }
    function devLabel(dev, labels) {
        return labels && labels[dev] ? dev + ' (' + labels[dev] + ')' : dev;
    }
    // which connections a per source limit counts: the side that opens them
    var FLOWS = {
        'in': ['in', '→ in (clients)', 'Sources are outside: counts connections external clients open to your hosts (protects your hosts)'],
        'out': ['out', '← out (your hosts)', 'Sources are your LAN hosts: counts connections your hosts open to the internet'],
        'lan': ['lan', 'LAN ↔ LAN', 'Sources and destinations are both inside your LAN']
    };
    function flowBadge(flow, where) {
        var f = FLOWS[flow];
        var tip = f ? f[2] : 'Direction could not be told from the rule (e.g. any to any on a floating rule)';
        return (f ? '<span class="hg-badge ' + f[0] + '" title="' + esc(tip) + '">' + esc(f[1]) + '</span>'
                  : '<span class="text-muted" title="' + esc(tip) + '">?</span>') +
               (where ? '<div class="text-muted" style="font-size:11px">' + esc(where) + '</div>' : '');
    }
    function pctBar(pct) {
        const p = Math.min(100, Math.max(0, Number(pct) || 0));
        const color = p >= 100 ? '#d9534f' : (p >= 80 ? '#e8942f' : '#2a9fd6');
        return '<span style="display:inline-block;width:70px;height:8px;background:rgba(128,128,128,.18);' +
               'border-radius:2px;vertical-align:middle;margin-right:6px"><span style="display:block;height:8px;width:' +
               p + '%;background:' + color + ';border-radius:2px"></span></span>' + esc(pct) + '%';
    }
    function sevLabel(s) {
        return '<span class="hg-sev ' + esc(s) + '">' + esc(s) + '</span>';
    }
    function macCell(mac, count) {
        if (!mac) return '';
        return '<span style="font-family:monospace">' + esc(mac) + '</span>' + (count > 1
            ? ' <span class="hg-badge warn" title="This MAC used ' + count + ' IPv4 addresses in the selected period">⚠ ' + count + ' IPs</span>' : '');
    }

    const tables = {
        hosts: makeTable('hg-hosts', [
            {key: 'ip', label: 'LAN host', html: function (r) { return ipLink(r.ip); },
             sortValue: function (r) { return ipKey(r.ip); }},
            {key: 'mac', label: 'MAC', cls: 'nowrap', text: function (r) { return r.mac + (r.mac_ips > 1 ? ' multiple' : ''); },
             html: function (r) { return macCell(r.mac, r.mac_ips); }},
            {key: 'alerts', label: 'Alerts', cls: 'num', num: true,
             html: function (r) { return r.alerts ? '<span class="hg-badge lan">' + r.alerts + '</span>' : ''; }},
            {key: 'active', label: 'Open now', cls: 'num', num: true},
            {key: 'states', label: 'pf states', cls: 'num', num: true,
             html: function (r) { return '<span title="' + esc(r.state_detail) + '">' + fmtNum(r.states) + '</span>' +
                 (r.new_rate >= 1 ? ' <span class="text-muted" title="new connections per second">' + fmtNum(r.new_rate) + '/s</span>' : ''); }},
            {key: 'conns_in', label: 'In conns', cls: 'num', num: true, html: function (r) { return fmtNum(r.conns_in); }},
            {key: 'conns_out', label: 'Out conns', cls: 'num', num: true, html: function (r) { return fmtNum(r.conns_out); }},
            {key: 'bytes_in', label: 'In traffic', cls: 'num', num: true, html: function (r) { return fmtBytes(r.bytes_in); }},
            {key: 'bytes_out', label: 'Out traffic', cls: 'num', num: true, html: function (r) { return fmtBytes(r.bytes_out); }},
            {key: 'ports_in', label: 'Served ports (click to test)', nosort: true,
             text: function (r) { return r.ports_in.map(function (p) { return p.proto + '/' + p.port + ' ' + p.name; }).join(' '); },
             html: function (r) {
                 const list = r.ports_in.slice(0, 12).map(function (p) {
                     // only TCP / UDP ports can be tested (icmp, sctp: a plain badge)
                     if (p.proto !== 'tcp' && p.proto !== 'udp') {
                         return '<span class="hg-badge in">' + esc(portText(p.proto, p.port)) +
                                (p.name && p.name !== p.proto ? ' ' + esc(p.name) : '') + '</span>';
                     }
                     return '<a class="hg-badge in hg-test" data-ip="' + esc(r.ip) + '" data-port="' + esc(p.port) +
                            '" data-proto="' + esc(p.proto) + '" title="' + esc(fmtNum(p.conns)) + ' connections, click to test">' +
                            esc(p.proto + '/' + p.port) + (p.name ? ' ' + esc(p.name) : '') + '</a>';
                 }).join('');
                 return list + (r.ports_in.length > 12 ? ' <span class="text-muted">+' + (r.ports_in.length - 12) + '</span>' : '');
             }},
            {key: 'ports_out', label: 'Out ports', cls: 'num', num: true},
            {key: 'services', label: 'Detected services', nosort: true,
             text: function (r) { return r.services.map(function (s) { return s.service + ' ' + s.product; }).join(' '); },
             html: function (r) {
                 return r.services.map(function (s) {
                     return '<span class="hg-badge svc" title="' + esc(s.product) + '">' + esc(s.service) + ':' + esc(s.port) + '</span>';
                 }).join('');
             }},
            {key: 'blocked_out', label: 'Blocked out', cls: 'num', num: true,
             html: function (r) { return r.blocked_out ? '<span class="hg-badge lan" title="estimated blocked packets sent by this host">' + fmtNum(r.blocked_out) + '</span>' : ''; }},
            {key: 'blocked_in', label: 'Blocked in', cls: 'num', num: true,
             html: function (r) { return r.blocked_in ? '<span title="estimated blocked packets towards this host">' + fmtNum(r.blocked_in) + '</span>' : ''; }},
            {key: 'lateral', label: 'LAN→LAN', cls: 'num', num: true,
             html: function (r) { return r.lateral ? '<span class="hg-badge lan" title="connection attempts to other LAN hosts">' + fmtNum(r.lateral) + '</span>' : ''; }},
            {key: 'last_seen', label: 'Last seen', num: true, cls: 'nowrap', html: function (r) { return ago(r.last_seen); }}
        ], 'conns_in', function (r) { return r.alerts ? 'hg-row-warn' : ''; }),

        alerts: makeTable('hg-alerts', [
            {key: 'severity', label: 'Severity', html: function (r) { return sevLabel(r.severity); },
             sortValue: function (r) { return ['info', 'medium', 'high', 'critical'].indexOf(r.severity); }},
            {key: 'type', label: 'Type', cls: 'nowrap', text: function (r) { return ALERT_TYPES[r.type] || r.type; },
             html: function (r) { return esc(ALERT_TYPES[r.type] || r.type); }},
            {key: 'ip', label: 'Host', html: function (r) { return r.ip ? ipLink(r.ip) : ''; },
             sortValue: function (r) { return ipKey(r.ip); }},
            {key: 'detail', label: 'Detail'},
            {key: 'count', label: 'Count', cls: 'num', num: true},
            {key: 'first_seen', label: 'First', num: true, cls: 'nowrap', html: function (r) { return esc(fmtDate(r.first_seen)); }},
            {key: 'last_seen', label: 'Last', num: true, cls: 'nowrap', html: function (r) { return ago(r.last_seen); }},
            {key: '', label: '', nosort: true, cls: 'nowrap', html: function (r) {
                // attacks and Suricata alerts: offer to block their outside sources from now on
                const block = (r.type === 'attack' || r.type === 'ids') && r.peer ? ' ' + blockButtons(r.type, r.peer, r.ip) : '';
                return (r.acked ? '<span class="text-muted">acknowledged</span>'
                    : '<button type="button" class="btn btn-default btn-xs hg-ack" data-id="' + esc(r.id) +
                      '" title="Acknowledge"><i class="fa fa-check"></i></button>') + block;
            }}
        ], 'last_seen', function (r) { return r.acked ? 'hg-acked' : ''; }),

        lateral: makeTable('hg-lateral', [
            {key: 'src', label: 'Source', html: function (r) { return ipLink(r.src); },
             sortValue: function (r) { return ipKey(r.src); }},
            {key: 'dst', label: 'Destination', html: function (r) { return ipLink(r.dst); },
             sortValue: function (r) { return ipKey(r.dst); }},
            {key: 'port', label: 'Port', num: true, cls: 'nowrap',
             text: function (r) { return portText(r.proto, r.port); },
             html: function (r) { return esc(portText(r.proto, r.port)) +
                 (r.sensitive ? ' <span class="hg-badge lan" title="sensitive port">!</span>' : ''); }},
            {key: 'name', label: 'Service'},
            {key: 'status', label: 'Result', nosort: true,
             text: function (r) { return r.blocked ? 'blocked' : (r.answered ? 'connected' : 'no answer'); },
             html: function (r) {
                 if (r.blocked && !r.answered) return '<span class="hg-badge lan">blocked</span>';
                 if (!r.answered) return '<span class="hg-badge warn">no answer</span>';
                 return '<span class="hg-badge svc">connected</span>' + (r.blocked ? ' <span class="hg-badge lan">+blocked</span>' : '');
             }},
            {key: 'attempts', label: 'Attempts (incl. est. blocked)', cls: 'num', num: true, html: function (r) { return fmtNum(r.attempts); }},
            {key: 'answered', label: 'Answered', cls: 'num', num: true, html: function (r) { return fmtNum(r.answered); }},
            {key: 'blocked', label: 'Blocked (est.)', cls: 'num', num: true, html: function (r) { return fmtNum(r.blocked); }},
            {key: 'bytes', label: 'Traffic', cls: 'num', num: true, html: function (r) { return fmtBytes(r.bytes); }},
            {key: 'first_seen', label: 'First seen', num: true, cls: 'nowrap', html: function (r) { return esc(fmtDate(r.first_seen)); }},
            {key: 'last_seen', label: 'Last seen', num: true, cls: 'nowrap', html: function (r) { return ago(r.last_seen); }}
        ], 'last_seen', function (r) {
            return r.attempts > 0 && !r.answered ? 'hg-row-bad' : (r.sensitive ? 'hg-row-warn' : '');
        }),

        l2: makeTable('hg-l2', [
            {key: 'mac', label: 'MAC', cls: 'nowrap', html: function (r) { return '<span style="font-family:monospace">' + esc(r.mac) + '</span>'; }},
            {key: 'ip', label: 'IP', html: function (r) { return ipLink(r.ip); }, sortValue: function (r) { return ipKey(r.ip); }},
            {key: 'iface', label: 'Interface'},
            {key: 'warn', label: 'Warning', num: true,
             sortValue: function (r) { return (r.ip_macs.length > 1 ? 2 : 0) + (r.mac_ips.length > 1 ? 1 : 0); },
             text: function (r) { return (r.mac_ips.length > 1 ? 'multiple ips ' : '') + (r.ip_macs.length > 1 ? 'mac changed' : ''); },
             html: function (r) {
                 let out = '';
                 if (r.mac_ips.length > 1) {
                     out += '<span class="hg-badge warn" title="' + esc(r.mac_ips.join(', ')) + '">⚠ MAC used ' +
                            r.mac_ips.length + ' IPs: ' + esc(r.mac_ips.join(', ')) + '</span> ';
                 }
                 if (r.ip_macs.length > 1) {
                     out += '<span class="hg-badge lan" title="' + esc(r.ip_macs.join(', ')) + '">⚠ IP seen on ' +
                            r.ip_macs.length + ' MACs: ' + esc(r.ip_macs.join(', ')) + '</span>';
                 }
                 return out;
             }},
            {key: 'first_seen', label: 'First seen', num: true, cls: 'nowrap', html: function (r) { return esc(fmtDate(r.first_seen)); }},
            {key: 'last_seen', label: 'Last seen', num: true, cls: 'nowrap', html: function (r) { return ago(r.last_seen); }}
        ], 'warn', function (r) { return r.ip_macs.length > 1 ? 'hg-row-bad' : (r.mac_ips.length > 1 ? 'hg-row-warn' : ''); }),

        blockedHosts: makeTable('hg-blocked-hosts', [
            {key: 'ip', label: 'LAN host', html: function (r) { return ipLink(r.ip); }, sortValue: function (r) { return ipKey(r.ip); }},
            {key: 'out', label: 'Blocked out (est. pkts)', cls: 'num', num: true,
             html: function (r) { return r.out ? '<b>' + fmtNum(r.out) + '</b>' : '0'; }},
            {key: 'targets', label: 'Targets (sampled)', cls: 'num', num: true},
            {key: 'top_out', label: 'Outbound ports', nosort: true,
             text: function (r) { return r.top_out.map(function (p) { return portText(p.proto, p.port) + ' ' + p.name; }).join(' '); },
             html: function (r) { return r.top_out.map(function (p) {
                 return '<span class="hg-badge out">' + esc(portText(p.proto, p.port)) + (p.name && p.name !== p.proto ? ' ' + esc(p.name) : '') + '</span>';
             }).join(''); }},
            {key: 'why_out', label: 'Why (out)', nosort: true, text: function (r) { return whyText(r.why_out); },
             html: function (r) { return whyHtml(r.why_out); }},
            {key: 'in', label: 'Blocked in (est. pkts)', cls: 'num', num: true, html: function (r) { return fmtNum(r.in); }},
            {key: 'sources', label: 'Sources (sampled)', cls: 'num', num: true},
            {key: 'top_in', label: 'Attacked ports', nosort: true,
             text: function (r) { return r.top_in.map(function (p) { return portText(p.proto, p.port) + ' ' + p.name; }).join(' '); },
             html: function (r) { return r.top_in.map(function (p) {
                 return '<span class="hg-badge in">' + esc(portText(p.proto, p.port)) + (p.name && p.name !== p.proto ? ' ' + esc(p.name) : '') + '</span>';
             }).join(''); }},
            {key: 'why_in', label: 'Why (in)', nosort: true, text: function (r) { return whyText(r.why_in); },
             html: function (r) { return whyHtml(r.why_in); }}
        ], 'out', function (r) { return r.out > 0 ? 'hg-row-warn' : ''; }),

        blockedFlows: makeTable('hg-blocked-flows', [
            {key: 'ip', label: 'LAN host', html: function (r) { return ipLink(r.ip); }, sortValue: function (r) { return ipKey(r.ip); }},
            {key: 'dir', label: 'Dir', html: function (r) { return dirBadge(r.dir); }},
            {key: 'port', label: 'Port', num: true, cls: 'nowrap', text: function (r) { return r.proto + '/' + r.port; },
             html: function (r) { return esc(portText(r.proto, r.port)); }},
            {key: 'name', label: 'Service'},
            {key: 'remote', label: 'Remote', cls: 'nowrap', sortValue: function (r) { return ipKey(r.remote); },
             html: function (r) {
                 if (r.internal) return ipLink(r.remote) + ' <span class="hg-badge lan">LAN↔LAN</span>';
                 return r.external > 1 ? '<span title="top: ' + esc((r.top || []).join(', ')) + '">' + esc(r.remote) +
                        '</span> <a href="#" class="hg-goto" data-filter="' + esc('t=' + r.ip + '|' + (r.proto === 'tcp' || r.proto === 'udp' ? r.proto + '/' + r.port : r.proto) + ';') +
                        '" data-label="' + esc(r.ip + ' ' + portText(r.proto, r.port)) +
                        '" style="font-size:11px">list</a>' : esc(r.remote);
             }},
            {key: 'packets', label: 'Packets (est.)', cls: 'num', num: true, html: function (r) { return fmtNum(r.packets); }},
            {key: 'samples', label: 'Sampled pkts', cls: 'num', num: true},
            {key: 'reason', label: 'Why blocked', html: function (r) { return '<span class="hg-badge ' + reasonClass(r.reason) + '">' + esc(r.reason) + '</span>'; }},
            {key: 'iface', label: 'Seen on', cls: 'nowrap'},
            {key: 'first_seen', label: 'First seen', num: true, cls: 'nowrap', html: function (r) { return esc(fmtDate(r.first_seen)); }},
            {key: 'last_seen', label: 'Last seen', num: true, cls: 'nowrap', html: function (r) { return ago(r.last_seen); }}
        ], 'packets', function (r) { return r.internal || r.dir === 'out' ? 'hg-row-warn' : ''; }),

        blockRules: makeTable('hg-block-rules', [
            {key: 'nr', label: 'Rule', num: true, html: function (r) { return '@' + esc(r.nr); }},
            {key: 'descr', label: 'Description', text: function (r) { return r.descr + ' ' + r.text; },
             html: function (r) { return r.descr ? '<b>' + esc(r.descr) + '</b>' : '<span class="text-muted">' + esc(r.text) + '</span>'; }},
            {key: 'pps', label: 'Now (pkt/s)', cls: 'num', num: true, html: function (r) { return r.pps ? '<b>' + fmtNum(r.pps) + '</b>' : '0'; }},
            {key: 'period', label: 'Packets in period', cls: 'num', num: true, html: function (r) { return fmtNum(r.period); }},
            {key: 'packets', label: 'Packets since rule load', cls: 'num', num: true, html: function (r) { return fmtNum(r.packets); }}
        ], 'pps', null, 'No block rule matched packets in this period'),

        limitHosts: makeTable('hg-limit-hosts', [
            {key: 'ip', label: 'LAN host', html: function (r) { return ipLink(r.ip); }, sortValue: function (r) { return ipKey(r.ip); }},
            {key: 'states', label: 'pf states (in + out)', cls: 'num', num: true, html: function (r) { return fmtNum(r.states); }},
            {key: 'table_pct', label: 'Of the pf state table (total)', num: true, cls: 'nowrap',
             sortValue: function (r) { return r.table_pct === null ? -1 : r.table_pct; },
             html: function (r) { return r.table_pct === null ? '<span class="text-muted">-</span>' : pctBar(r.table_pct); }},
            {key: 'src', label: 'pf per source limit (strictest rule, its own connections)', num: true, cls: 'nowrap',
             sortValue: function (r) { return r.src ? r.src.pct : -1; },
             text: function (r) { return r.src ? r.src.kind + ' @' + r.src.rule + ' ' + r.src.descr : 'none'; },
             html: function (r) {
                 if (!r.src) {
                     return '<span class="text-muted" title="No rule with max-src-states / max-src-conn / max-src-conn-rate counts the connections this host opens">none</span>';
                 }
                 return pctBar(r.src.pct) + ' <span class="text-muted">' + esc(r.src.kind) + ' ' + esc(fmtNum(r.src.value)) +
                        ' / ' + esc(fmtNum(r.src.limit)) + '</span><div class="text-muted" style="font-size:11px">@' +
                        esc(r.src.rule) + ' ' + esc(r.src.descr) + '</div>';
             }},
            {key: 'pct', label: 'Of warning threshold (setting)', num: true, cls: 'nowrap', html: function (r) { return pctBar(r.pct); }},
            {key: 'new_rate', label: 'New conn/s', cls: 'num', num: true, html: function (r) { return fmtNum(r.new_rate); }},
            {key: 'detail', label: 'Where the states go (top ports, inbound share)'}
        ], 'states', function (r) {
            var src = r.src ? r.src.pct : 0;
            return src >= 100 ? 'hg-row-bad' : (src >= 90 || r.pct >= 100 ? 'hg-row-warn' : '');
        }, 'No LAN host holds firewall states right now'),

        srcLimits: makeTable('hg-src-limits', [
            {key: 'ip', label: 'Source', sortValue: function (r) { return ipKey(r.ip); },
             html: function (r) {
                 if (r.lan) return ipLink(r.ip) + ' <span class="hg-badge">LAN</span>';
                 // outside clients are grouped per rule and limit; every address is on the Attacks tab
                 return r.external > 1 ? '<span title="top: ' + esc((r.top || []).join(', ')) + '">' + esc(r.ip) +
                        '</span> <a href="#" class="hg-goto" data-filter="' + esc('l=' + r.kind + '@' + r.rule + ';') +
                        '" data-label="' + esc(r.kind + ' on rule @' + r.rule) +
                        '" style="font-size:11px">list</a>' : esc(r.ip);
             }},
            {key: 'dir', label: 'Direction', text: function (r) { return (FLOWS[r.dir] || ['', ''])[1] + ' ' + (r.where || ''); },
             html: function (r) { return flowBadge(r.dir, r.where); }},
            {key: 'kind', label: 'Limit'},
            {key: 'pct', label: 'Now', num: true, cls: 'nowrap',
             sortValue: function (r) { return r.pct === null ? -1 : r.pct; },
             html: function (r) {
                 if (!r.now) {
                     return '<span class="text-muted">below 90% now</span>';
                 }
                 if (r.kind === 'max-src-conn-rate') {
                     // pf counts new connections per N seconds: "16/5s" against "15/5"
                     const lim = String(r.limit_text || r.limit).split('/');
                     return pctBar(r.pct) + ' <span class="text-muted">' + esc(r.rate || r.value) + ' new conns, limit ' +
                            esc(lim[0]) + (lim[1] ? ' per ' + esc(lim[1]) + ' s' : '') + '</span>';
                 }
                 return pctBar(r.pct) + ' <span class="text-muted">' + esc(r.value) + ' / ' + esc(r.limit) +
                        (r.kind === 'max-src-states' ? ' states' : ' connections') + '</span>';
             }},
            {key: 'peak', label: 'Peak (unit of the limit)', cls: 'num', num: true},
            {key: 'hits', label: 'Polls at limit', cls: 'num', num: true},
            {key: 'rule', label: 'Rule', num: true, text: function (r) { return '@' + r.rule + ' ' + r.descr; },
             html: function (r) { return '@' + esc(r.rule) + ' <b>' + esc(r.descr) + '</b>'; }},
            {key: 'last_seen', label: 'Last at limit', num: true, cls: 'nowrap',
             html: function (r) { return r.last_seen ? ago(r.last_seen) : '<span class="text-muted">-</span>'; }},
            {key: '', label: 'Block from now on', nosort: true, cls: 'nowrap', html: function (r) {
                // outside clients only; the limit itself is read from the rule every poll. The condition names
                // the rule by its label: rule numbers change when the ruleset is reloaded
                if (r.lan) return '';
                return r.label ? blockButtons('src_limit', r.label + ':' + r.kind, '*') :
                       '<span class="text-muted" title="The rule has no label, a condition could not follow it across rule reloads">-</span>';
            }}
        ], 'pct', function (r) { return r.at_limit ? 'hg-row-bad' : (r.now ? 'hg-row-warn' : ''); },
           'No source reached 90% of a per source limit in this period'),

        episodes: makeTable('hg-episodes', [
            {key: 'active', label: 'State', html: function (r) {
                return r.active ? '<span class="hg-badge lan">ongoing</span>' : '<span class="text-muted">over</span>'; }},
            {key: 'target', label: 'Attacked host', html: function (r) { return ipLink(r.target); }, sortValue: function (r) { return ipKey(r.target); }},
            {key: 'kind', label: 'Type', text: function (r) { return ATTACK_KINDS[r.kind] || r.kind; },
             html: function (r) { return '<b>' + esc(ATTACK_KINDS[r.kind] || r.kind) + '</b>'; }},
            {key: 'peak_pps', label: 'Peak pkt/s (est.)', cls: 'num', num: true, html: function (r) { return fmtNum(r.peak_pps); }},
            {key: 'sources', label: 'Sources (sampled)', cls: 'num', num: true},
            {key: 'passed_pct', label: 'Passed firewall', num: true, cls: 'nowrap',
             html: function (r) { return pctBar(r.passed_pct) + (r.passed_pct >= 50 ? ' <span class="hg-badge lan">reaches host</span>' : ''); }},
            {key: 'ports', label: 'Ports'},
            {key: 'top_sources', label: 'Top sources', html: function (r) { return '<span class="text-muted" style="font-size:11px">' + esc(r.top_sources) + '</span>'; }},
            {key: 'first_seen', label: 'Started', num: true, cls: 'nowrap', html: function (r) { return esc(fmtDate(r.first_seen)); }},
            {key: 'last_seen', label: 'Last seen', num: true, cls: 'nowrap', html: function (r) { return ago(r.last_seen); }},
            {key: '', label: 'Block from now on', nosort: true, cls: 'nowrap', html: function (r) { return blockButtons('attack', r.kind, r.target); }}
        ], 'last_seen', function (r) { return r.active ? (r.passed_pct >= 50 ? 'hg-row-bad' : 'hg-row-warn') : ''; },
           'No attack on your hosts in this period'),

        attackSources: makeTable('hg-attack-sources', [
            {key: 'ip', label: 'Outside source', sortValue: function (r) { return ipKey(r.ip); },
             html: function (r) { return esc(r.ip) + (r.blocked_by.length ? ' <span class="hg-badge lan" title="in virusprot by block condition #' + esc(r.blocked_by.join(', #')) + '">blocked</span>' : ''); }},
            {key: 'net', label: 'Network', text: netText, html: netCell,
             sortValue: function (r) { return r.net ? netKind(r.net) + ' ' + (r.net.provider || r.net.as_name) : '~'; }},
            {key: 'packets', label: 'Blocked pkts (est.)', cls: 'num', num: true, html: function (r) { return fmtNum(r.packets); }},
            // the first 10 targets come with the row, targets_total counts all of them
            {key: 'targets', label: 'Targets', text: function (r) { return r.targets.join(' '); }, sortValue: function (r) { return r.targets_total || r.targets.length; },
             html: function (r) {
                 const total = r.targets_total || r.targets.length;
                 return r.targets.slice(0, 3).map(ipLink).join(' ') + (total > 3 ? ' <span class="text-muted">+' + (total - 3) + '</span>' : ''); }},
            {key: 'ports', label: 'Ports', text: function (r) { return r.ports.join(' '); },
             html: function (r) { return r.ports.map(function (p) { return '<span class="hg-badge in">' + esc(p.replace(/^(tcp|udp)\/0$/, '$1/other')) + '</span>'; }).join(''); }},
            {key: 'why', label: 'Why blocked', html: function (r) { return '<span class="hg-badge ' + reasonClass(r.why) + '">' + esc(r.why) + '</span>'; }},
            {key: 'crowdsec', label: 'CrowdSec', html: function (r) { return r.crowdsec ? '<span class="hg-badge lan">' + esc(r.crowdsec) + '</span>' : ''; }},
            {key: 'ids', label: 'Suricata hits', cls: 'num', num: true, html: function (r) { return r.ids ? fmtNum(r.ids) : ''; }},
            {key: 'limits', label: 'Rule limits hit', text: function (r) { return r.limits.join(' '); }, sortValue: function (r) { return r.limits.length; },
             html: function (r) { return esc(r.limits.slice(0, 3).join(', ')); }},
            {key: 'last_seen', label: 'Last seen', num: true, cls: 'nowrap', html: function (r) { return ago(r.last_seen); }}
        ], 'packets', null, 'No outside source sent blocked traffic to your hosts in this period'),

        ids: makeTable('hg-ids', [
            {key: 'severity', label: 'Sev.', num: true, html: function (r) {
                return '<span class="hg-sev ' + (r.severity === 1 ? 'critical' : r.severity === 2 ? 'high' : 'medium') + '">' + esc(r.severity) + '</span>'; }},
            {key: 'target', label: 'Attacked host', html: function (r) { return ipLink(r.target); }, sortValue: function (r) { return ipKey(r.target); }},
            {key: 'signature', label: 'Signature', text: function (r) { return r.signature + ' ' + r.category + ' ' + r.sid; },
             html: function (r) { return '<b>' + esc(r.signature) + '</b><div class="text-muted" style="font-size:11px">' + esc(r.category) + ' · sid ' + esc(r.sid) + '</div>'; }},
            {key: 'port', label: 'Port', cls: 'num', num: true},
            {key: 'action', label: 'Action', html: function (r) {
                return r.action === 'blocked' ? '<span class="hg-badge lan" title="Suricata dropped it (IPS mode, a rule set to drop)">dropped</span>' : esc(r.action); }},
            {key: 'hits', label: 'Hits', cls: 'num', num: true, html: function (r) { return fmtNum(r.hits); }},
            {key: 'sources', label: 'Sources', cls: 'num', num: true,
             html: function (r) { return '<span title="' + esc(r.top.join(', ')) + '">' + fmtNum(r.sources) + '</span>'; }},
            {key: 'last_seen', label: 'Last seen', num: true, cls: 'nowrap', html: function (r) { return ago(r.last_seen); }},
            // a signature Suricata drops: prepared as a "dropped" condition (the form can switch it to every alert)
            {key: '', label: 'Block from now on', nosort: true, cls: 'nowrap', html: function (r) {
                return blockButtons(r.action === 'blocked' ? 'ids_drop' : 'ids', String(r.sid), r.target); }}
        ], 'hits', function (r) { return r.severity === 1 ? 'hg-row-bad' : ''; },
           'No Suricata alert towards your hosts in this period (or Suricata / its EVE log is off)'),

        conditions: makeTable('hg-conditions', [
            {key: 'id', label: '#', cls: 'num', num: true},
            {key: 'ctype', label: 'Condition', text: condText, html: function (r) { return '<b>' + esc(condText(r)) + '</b>'; }},
            {key: 'duration', label: 'Ban', num: true, text: function (r) { return r.ban_text || fmtDuration(r.duration); },
             html: function (r) { return (r.ban === 'escalating' ? '<span class="hg-badge lan">escalating</span> ' : '') + esc(r.ban_text || fmtDuration(r.duration)); }},
            {key: 'blocked_now', label: 'Blocked now', cls: 'num', num: true,
             html: function (r) { return fmtNum(r.blocked_now) + (r.waiting ? ' <span class="text-muted" title="Addresses that matched, waiting for more matches before they are blocked">+' + fmtNum(r.waiting) + ' waiting</span>' : ''); }},
            {key: 'hits', label: 'Sources blocked (total)', cls: 'num', num: true},
            {key: 'last_hit', label: 'Last match', num: true, cls: 'nowrap', html: function (r) { return r.last_hit ? ago(r.last_hit) : '<span class="text-muted">never</span>'; }},
            {key: 'created', label: 'Created', num: true, cls: 'nowrap', html: function (r) { return esc(fmtDate(r.created)); }},
            {key: '', label: '', nosort: true, html: function (r) {
                if (r.ctype === 'auto') return '<span class="text-muted" title="Services: HostGuard: Settings, Automatic filtering">level in the settings</span>';
                return '<button type="button" class="btn btn-default btn-xs hg-cond-del" data-id="' + esc(r.id) +
                       '" title="Remove the condition and release the addresses only it holds"><i class="fa fa-trash"></i> remove</button>'; }}
        ], 'id', null, 'No block condition. Add one with the form above.'),

        autoblocked: makeTable('hg-autoblocked', [
            {key: 'ip', label: 'Address', sortValue: function (r) { return ipKey(r.ip); }},
            {key: 'cond', label: 'Condition', cls: 'num', num: true, html: function (r) { return '#' + esc(r.cond); }},
            {key: 'reason', label: 'Matched'},
            {key: 'tbl', label: 'Table', html: function (r) {
                return '&lt;' + esc(r.tbl) + '&gt;' + (r.owned ? '' : ' <span class="text-muted" title="It was in the table before the condition matched it (pf overload or another tool), the condition does not take it out">already there</span>'); }},
            {key: 'added', label: 'Added', num: true, cls: 'nowrap', html: function (r) { return ago(r.added); }},
            {key: 'expires', label: 'Released', num: true, cls: 'nowrap',
             html: function (r) {
                 // a time already past: the collector takes it out of the table (retried until pfctl succeeds)
                 if (r.expires && r.expires <= Date.now() / 1000) return '<span class="text-muted">being released</span>';
                 return r.expires ? esc(fmtDate(r.expires)) + ' <span class="text-muted">(later while it keeps matching)</span>' : '<span class="text-muted">with the condition</span>'; }},
            {key: 'span', label: 'This block', num: true, cls: 'nowrap',
             sortValue: function (r) { return r.span === null || r.span === undefined ? -1 : (r.span || Infinity); },
             html: function (r) {
                 // escalating bans: the how-manieth block of this address by the condition
                 return (r.span === null || r.span === undefined ? '<span class="text-muted">condition time</span>' : esc(fmtDuration(r.span))) +
                        (r.offense > 1 ? ' <span class="hg-badge lan" title="Blocked by this condition before: each repeat lasts longer">' + esc(r.offense) + '. time</span>' : ''); }}
        ], 'added', null, 'No address blocked by a condition'),

        counters: makeTable('hg-counters', [
            {key: 'name', label: 'pf counter', html: function (r) { return '<b>' + esc(r.name) + '</b>'; }},
            {key: 'increase', label: 'Increase in period', cls: 'num', num: true,
             html: function (r) { return r.increase ? '<b>+' + fmtNum(r.increase) + '</b>' : '0'; }},
            {key: 'total', label: 'Total since boot', cls: 'num', num: true, html: function (r) { return fmtNum(r.total); }},
            {key: 'meaning', label: 'Meaning'}
        ], 'increase', function (r) { return r.watched && r.increase > 0 ? 'hg-row-bad' : ''; }),

        rules: makeTable('hg-rules', [
            {key: 'nr', label: 'Rule', num: true, text: function (r) { return '@' + r.nr + ' ' + r.descr + ' ' + r.text; },
             html: function (r) {
                 return '@' + esc(r.nr) + ' ' + (r.descr ? '<b>' + esc(r.descr) + '</b>' : '') +
                        '<div class="text-muted" style="font-size:11px;max-width:380px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' +
                        esc(r.text) + '">' + esc(r.text) + '</div>';
             }},
            {key: 'flow', label: 'Counts', text: function (r) { return (FLOWS[r.flow] || ['', ''])[1] + ' ' + (r.where || ''); },
             html: function (r) { return flowBadge(r.flow, r.where); }},
            {key: 'tracking', label: 'Source tracking',
             html: function (r) {
                 return r.tracking ? '<span class="hg-badge" title="' + (r.tracking === 'global'
                     ? 'one counter per address, shared by all rules with per source limits' : 'counted per rule') + '">' +
                     esc(r.tracking) + '</span>' : '<span class="text-muted">-</span>';
             }},
            {key: 'worst', label: 'Fill (each limit of the rule)', num: true, cls: 'nowrap',
             html: function (r) {
                 return (r.metrics || []).map(function (m) {
                     return '<div style="white-space:nowrap"><span style="display:inline-block;min-width:120px">' + esc(m.kind) +
                            '</span>' + pctBar(m.pct) + ' <span class="text-muted">' + esc(fmtNum(m.value)) + ' / ' +
                            esc(fmtNum(m.limit)) + (m.ip ? ' · ' + esc(m.ip) : '') + '</span></div>';
                 }).join('') || '<span class="text-muted">-</span>';
             }},
            {key: 'sources', label: 'Sources', cls: 'num', num: true},
            {key: 'over80', label: 'Sources ≥ 80%', cls: 'num', num: true,
             html: function (r) { return r.over80 ? '<span class="hg-badge warn">' + esc(r.over80) + '</span>' : '0'; }}
        ], 'worst', function (r) { return r.worst >= 100 ? 'hg-row-bad' : (r.worst >= 90 ? 'hg-row-warn' : ''); },
           'No firewall rule carries a limit (max, max-src-*), or the collector has not run yet'),

        shaperObjects: makeTable('hg-shaper-objects', [
            {key: 'name', label: 'Pipe / queue', text: function (r) { return r.name + ' ' + r.rules.join(' '); },
             html: function (r) {
                 return '<b>' + esc(r.name) + '</b>' + (r.kind === 'queue' && r.pipe ? ' <span class="text-muted">in pipe ' + esc(r.pipe) +
                        ', weight ' + esc(r.weight) + '</span>' : '') +
                        r.rules.map(function (x) { return '<div class="text-muted" style="font-size:11px">' + esc(x) + '</div>'; }).join('');
             }},
            {key: 'limit', label: 'Limit', num: true, cls: 'nowrap',
             html: function (r) { return r.limit ? fmtBits(r.limit) : '<span class="text-muted">unlimited</span>'; }},
            {key: 'mask', label: 'Applies', html: function (r) {
                 return r.mask === 'src' ? 'per source IP' : r.mask === 'dst' ? 'per destination IP' :
                        r.mask === 'both' ? 'per address pair' : 'shared';
             }},
            {key: 'flows', label: 'Active flows', cls: 'num', num: true},
            {key: 'bps', label: 'Now', cls: 'num', num: true, html: function (r) { return fmtBits(r.bps); }},
            {key: 'util', label: 'Fill', num: true, cls: 'nowrap',
             html: function (r) { return r.limit ? pctBar(r.util) + (r.mask !== 'none' ? ' <span class="text-muted">busiest</span>' : '') : ''; }},
            {key: 'drops_ps', label: 'Drops/s', cls: 'num', num: true,
             html: function (r) { return r.drops_ps ? '<b>' + esc(r.drops_ps) + '</b>' : '0'; }}
        ], 'util', function (r) { return r.drops_ps > 0 ? 'hg-row-bad' : (r.util >= 90 ? 'hg-row-warn' : ''); }),

        shaperFlows: makeTable('hg-shaper-flows', [
            {key: 'ip', label: 'Address', sortValue: function (r) { return ipKey(r.ip); },
             html: function (r) { return r.ip ? (r.lan ? ipLink(r.ip) : esc(r.ip)) : '<span class="text-muted">shared</span>'; }},
            {key: 'name', label: 'Pipe / queue'},
            {key: 'bps', label: 'Now', cls: 'num', num: true, html: function (r) { return fmtBits(r.bps); }},
            {key: 'limit', label: 'Limit', cls: 'num', num: true, html: function (r) { return r.limit ? fmtBits(r.limit) : ''; }},
            {key: 'util', label: 'Fill', num: true, cls: 'nowrap',
             sortValue: function (r) { return r.util === null ? -1 : r.util; },
             html: function (r) { return r.util === null ? '<span class="text-muted">shared</span>' : pctBar(r.util); }},
            {key: 'drops_ps', label: 'Drops/s', cls: 'num', num: true,
             html: function (r) { return r.drops_ps ? '<b>' + esc(r.drops_ps) + '</b>' : '0'; }},
            {key: 'queued', label: 'Queued', cls: 'num', num: true}
        ], 'drops_ps', function (r) { return r.drops_ps > 0 ? 'hg-row-bad' : (r.util >= 90 ? 'hg-row-warn' : ''); }),

        shaperHits: makeTable('hg-shaper-hits', [
            {key: 'ip', label: 'Address', sortValue: function (r) { return ipKey(r.ip); },
             html: function (r) { return r.lan ? ipLink(r.ip) : esc(r.ip); }},
            {key: 'nr', label: 'Pipe / queue', num: true,
             html: function (r) { return esc(r.kind + ' ' + r.nr) + (r.descr ? ' <b>' + esc(r.descr) + '</b>' : ''); }},
            {key: 'limit', label: 'Limit', cls: 'num', num: true, html: function (r) { return r.limit ? fmtBits(r.limit) : ''; }},
            {key: 'peak_bps', label: 'Peak', cls: 'num', num: true, html: function (r) { return fmtBits(r.peak_bps); }},
            {key: 'drops', label: 'Dropped packets', cls: 'num', num: true, html: function (r) { return fmtNum(r.drops); }},
            {key: 'last_seen', label: 'Last drop', num: true, cls: 'nowrap', html: function (r) { return ago(r.last_seen); }}
        ], 'drops'),

        tablehits: makeTable('hg-tablehits', [
            {key: 'table', label: 'pf table'},
            {key: 'ip', label: 'LAN host', html: function (r) { return ipLink(r.ip); }, sortValue: function (r) { return ipKey(r.ip); }},
            {key: 'current', label: 'Listed now', html: function (r) {
                return r.current ? '<span class="hg-badge lan">yes</span>' : '<span class="text-muted">no (removed)</span>';
            }},
            {key: 'first_seen', label: 'First seen', num: true, cls: 'nowrap', html: function (r) { return esc(fmtDate(r.first_seen)); }},
            {key: 'last_seen', label: 'Last seen', num: true, cls: 'nowrap', html: function (r) { return ago(r.last_seen); }}
        ], 'last_seen', function (r) { return r.current ? 'hg-row-bad' : ''; }),

        ports: makeTable('hg-ports', [
            {key: 'dir', label: 'Direction', html: function (r) { return dirBadge(r.dir); }},
            {key: 'proto', label: 'Proto'},
            {key: 'port', label: 'Port', cls: 'num', num: true},
            {key: 'name', label: 'Service'},
            {key: 'hosts', label: 'LAN hosts', cls: 'num', num: true},
            {key: 'conns', label: 'Connections', cls: 'num', num: true, html: function (r) { return fmtNum(r.conns); }},
            {key: 'bytes', label: 'Traffic', cls: 'num', num: true, html: function (r) { return fmtBytes(r.bytes); }}
        ], 'conns'),

        flows: makeTable('hg-flows', [
            {key: 'ip', label: 'LAN host', html: function (r) { return ipLink(r.ip); },
             sortValue: function (r) { return ipKey(r.ip); }},
            {key: 'dir', label: 'Dir', html: function (r) { return dirBadge(r.dir); }},
            {key: 'port', label: 'Port', num: true, cls: 'nowrap',
             text: function (r) { return r.proto + '/' + r.port; },
             html: function (r) { return esc(r.proto + '/' + r.port); }},
            {key: 'name', label: 'Service'},
            {key: 'remote', label: 'Remote', cls: 'nowrap', sortValue: function (r) { return ipKey(r.remote); },
             text: function (r) { return r.remote + (r.internal ? ' lan' : ''); },
             html: function (r) { return r.internal ? ipLink(r.remote) + ' <span class="hg-badge lan" title="the remote side is also a LAN host">LAN↔LAN</span>' : esc(r.remote); }},
            {key: 'conns', label: 'Conns', cls: 'num', num: true, html: function (r) { return fmtNum(r.conns); }},
            {key: 'bytes', label: 'Traffic', cls: 'num', num: true, html: function (r) { return fmtBytes(r.bytes); }},
            {key: 'first_seen', label: 'First seen', num: true, cls: 'nowrap', html: function (r) { return esc(fmtDate(r.first_seen)); }},
            {key: 'last_seen', label: 'Last seen', num: true, cls: 'nowrap', html: function (r) { return ago(r.last_seen); }},
            {key: '', label: '', nosort: true, html: function (r) { return r.dir === 'in' ? testButton(r.ip, r.port, r.proto) : ''; }}
        ], 'last_seen', function (r) { return r.internal ? 'hg-row-warn' : ''; }),

        services: makeTable('hg-services', [
            {key: 'ip', label: 'LAN host', html: function (r) { return ipLink(r.ip); },
             sortValue: function (r) { return ipKey(r.ip); }},
            {key: 'port', label: 'Port', num: true, cls: 'nowrap',
             text: function (r) { return r.proto + '/' + r.port; },
             html: function (r) { return esc(r.proto + '/' + r.port); }},
            {key: 'state', label: 'State',
             html: function (r) { return '<span class="hg-state-' + esc(String(r.state).replace(/[^a-z]/g, '')) + '">' + esc(r.state) + '</span>'; }},
            {key: 'service', label: 'Service', html: function (r) { return '<b>' + esc(r.service) + '</b>'; }},
            {key: 'product', label: 'Product / version'},
            {key: 'tls', label: 'TLS'},
            {key: 'banner', label: 'Banner', cls: 'banner',
             html: function (r) { return '<span title="' + esc(r.banner) + '">' + esc(r.banner) + '</span>'; }},
            {key: 'method', label: 'Method'},
            {key: 'last_probe', label: 'Tested', num: true, cls: 'nowrap', html: function (r) { return ago(r.last_probe); }},
            {key: '', label: '', nosort: true, html: function (r) { return testButton(r.ip, r.port, r.proto); }}
        ], 'last_probe')
    };

    /* overview */
    function renderKpis(t) {
        const kpis = [
            ['Open alerts', fmtNum(t.alerts_open), fmtNum(t.alerts_high) + ' high / critical', t.alerts_high > 0],
            ['LAN ↔ LAN attempts', fmtNum(t.lateral), fmtNum(t.lateral_blocked) + ' blocked by the firewall'],
            ['pf state table', t.pf_states_limit ? Math.round(t.pf_states * 100 / t.pf_states_limit) + '%' : fmtNum(t.pf_states),
             fmtNum(t.pf_states) + (t.pf_states_limit ? ' of ' + fmtNum(t.pf_states_limit) : '') + ' states',
             t.pf_states_limit && t.pf_states * 100 / t.pf_states_limit >= (t.state_warn_pct || 80)],
            ['Active hosts', fmtNum(t.active_hosts), fmtNum(t.active_conns) + ' open connections'],
            ['Hosts seen', fmtNum(t.hosts), 'in selected period'],
            ['Inbound connections', fmtNum(t.conns_in), fmtBytes(t.bytes_in) + ' transferred'],
            ['Outbound connections', fmtNum(t.conns_out), fmtBytes(t.bytes_out) + ' transferred'],
            ['Distinct ports', fmtNum(t.ports), 'inbound + outbound'],
            ['Detected services', fmtNum(t.services), 'open ports tested']
        ];
        $('#hg-kpis').html(kpis.map(function (k) {
            return '<div class="hg-kpi' + (k[3] ? ' alert-on' : '') + '"><div class="l">' + esc(k[0]) +
                   '</div><div class="v">' + esc(k[1]) + '</div><div class="s">' + esc(k[2]) + '</div></div>';
        }).join(''));
        $('#hg-alert-badge').text(t.alerts_open || '').toggle(t.alerts_open > 0);
    }

    function renderAlertStrip(alerts) {
        const $strip = $('#hg-alert-strip');
        if (!alerts || !alerts.length) {
            $strip.hide();
            return;
        }
        $strip.find('.list').html(alerts.map(function (a) {
            return '<div class="row-a">' + sevLabel(a.severity) + ' <b>' + esc(ALERT_TYPES[a.type] || a.type) + '</b> ' +
                   esc(a.detail) + (a.count > 1 ? ' <span class="t">×' + esc(a.count) + '</span>' : '') +
                   '<span class="t">' + ago(a.last_seen) + '</span></div>';
        }).join(''));
        $strip.show();
    }

    function barItems(rows, color, labelFn, subFn) {
        const bytes = S.metric === 'bytes';
        return rows.map(function (r) {
            return {label: labelFn(r), sub: subFn ? subFn(r) : '', value: bytes ? r.bytes : r.conns, color: color, row: r};
        });
    }

    function barTip(item) {
        const r = item.row;
        const lines = [[null, item.label + (item.sub ? '  ' + item.sub : '')],
                       [item.color, 'Connections: ' + fmtNum(r.conns)], [null, 'Traffic: ' + fmtBytes(r.bytes)]];
        if (r.hosts !== undefined) lines.push([null, 'LAN hosts: ' + r.hosts]);
        return lines;
    }

    function renderOverview() {
        const d = S.summary;
        if (!d || S.tab !== 'overview') return;
        const bytes = S.metric === 'bytes';
        $('#hg-metric-label').text(bytes ? 'traffic' : 'connections');
        HGCharts.timeline(document.getElementById('hg-timeline'), d.timeline.map(function (p) {
            return {t: p.t, values: bytes ? [p.in_b, p.out_b] : [p.in_c, p.out_c]};
        }), {
            series: [{label: 'Inbound (LAN host served)', color: COLOR_IN},
                     {label: 'Outbound (LAN host connected out)', color: COLOR_OUT}],
            format: fmtMetric, timeFormat: fmtTime, height: 250
        });
        const portLabel = function (r) { return r.proto + '/' + r.port; };
        const portName = function (r) { return r.name; };
        const openFlows = function (dir) {
            return function (item) { showTab('flows', dir, item.row.proto + '/' + item.row.port); };
        };
        HGCharts.hbar(document.getElementById('hg-top-in'), barItems(d.top_in, COLOR_IN, portLabel, portName),
                      {format: fmtMetric, tip: barTip, onClick: openFlows('in')});
        HGCharts.hbar(document.getElementById('hg-top-out'), barItems(d.top_out, COLOR_OUT, portLabel, portName),
                      {format: fmtMetric, tip: barTip, onClick: openFlows('out')});
        $('#hg-top-hosts-title').text(d.peers_of_host ? 'Top remote peers of ' + d.ip : 'Top LAN hosts');
        HGCharts.hbar(document.getElementById('hg-top-hosts'), barItems(d.top_hosts, HGCharts.palette[2],
                      function (r) { return r.ip; }),
                      {format: fmtMetric, tip: barTip,
                       onClick: d.peers_of_host ? null : function (item) { setIp(item.row.ip); }});
        HGCharts.donut(document.getElementById('hg-mix'), d.service_mix.map(function (s) {
            return {label: s.service || 'unknown', value: s.count};
        }), {centerLabel: 'services', emptyText: 'No services tested yet'});
    }

    /* attacks on LAN hosts and block conditions */
    const ATTACK_KINDS = {
        'reflection': 'Reflection / amplification', 'syn flood': 'SYN flood', 'udp flood': 'UDP flood',
        'icmp flood': 'ICMP flood', 'brute force': 'Distributed brute force', 'port scan': 'Port scan',
        'mixed flood': 'Mixed flood'
    };
    // "block from now on": a condition; outside sources matching it later go into virusprot
    function blockButtons(type, value, target) {
        const b = function (tgt, label, tip) {
            return '<button type="button" class="btn btn-default btn-xs hg-block" data-type="' + esc(type) +
                   '" data-value="' + esc(value) + '" data-target="' + esc(tgt) + '" title="' + esc(tip) + '">' +
                   '<i class="fa fa-ban"></i> ' + esc(label) + '</button>';
        };
        return (target && target !== '*' ? b(target, 'block', 'From now on put outside sources of this on ' + target + ' into virusprot') + ' ' : '') +
               b('*', target && target !== '*' ? 'any host' : 'block', 'From now on put outside sources of this, towards any LAN host, into virusprot');
    }
    function condText(c) {
        // automatic filtering: the collector keeps these from the setting, the note says level and rule
        if (c.ctype === 'auto') return 'Automatic, ' + (c.note || c.value);
        const value = String(c.value), cut = value.lastIndexOf(':');
        const what = c.ctype === 'attack' ? (ATTACK_KINDS[c.value] || c.value) :
                     c.ctype === 'ids' ? 'Suricata sid ' + c.value :
                     c.ctype === 'ids_drop' ? (value === '*' ? 'any alert Suricata dropped' : 'Suricata dropped sid ' + value) :
                     'source at ' + value.slice(cut + 1) + ' (' + (value.slice(0, cut) === '*' ? 'any rule' : 'rule ' + value.slice(0, cut)) + ')';
        return what + ' → ' + (c.target === '*' ? 'any LAN host' : c.target);
    }
    function fmtDuration(s) {
        s = Number(s) || 0;
        if (!s) return 'until removed';
        return s % 86400 === 0 ? s / 86400 + ' d' : s % 3600 === 0 ? s / 3600 + ' h' : Math.round(s / 60) + ' min';
    }

    function loadSummary() {
        return api('summary').done(function (data) {
            if (!ok(data)) return;
            S.summary = data;
            renderKpis(data.totals);
            renderAlertStrip(data.recent_alerts);
            $('#hg-nodata').toggle(!data.totals.hosts && !data.ip);
            renderOverview();
        });
    }

    const loaders = {
        overview: function () {},
        hosts: function () {
            api('hosts').done(function (d) { if (ok(d)) tables.hosts.setRows(d.rows); });
        },
        ports: function () {
            api('ports', {dir: $('#hg-ports-dir').val()}).done(function (d) { if (ok(d)) tables.ports.setRows(d.rows); });
        },
        flows: function () {
            api('flows', {dir: $('#hg-flows-dir').val()}).done(function (d) { if (ok(d)) tables.flows.setRows(d.rows); });
        },
        services: function () {
            api('services').done(function (d) { if (ok(d)) tables.services.setRows(d.rows); });
        },
        alerts: function () {
            api('alerts', {which: $('#hg-alerts-which').val()}).done(function (d) { if (ok(d)) tables.alerts.setRows(d.rows); });
        },
        lateral: function () {
            api('lateral').done(function (d) { if (ok(d)) tables.lateral.setRows(d.rows); });
        },
        l2: function () {
            api('l2').done(function (d) { if (ok(d)) tables.l2.setRows(d.rows); });
        },
        limits: function () {
            api('limits').done(function (d) {
                if (!ok(d)) return;
                renderLimits(d);
            });
        },
        blocked: function () {
            api('blocked', {dir: $('#hg-blocked-dir').val()}).done(function (d) {
                if (!ok(d)) return;
                renderBlocked(d);
            });
        },
        attacks: function () {
            // a "list" link's group is filtered by the backend: every member, without shipping every key
            api('attacks', S.attackGroup ? {group: S.attackGroup} : {}).done(function (d) {
                if (!ok(d)) return;
                renderAttacks(d);
            });
        },
        conditions: function () {
            api('conditions').done(function (d) {
                if (!ok(d)) return;
                tables.conditions.setRows(d.conditions);
                tables.autoblocked.setRows(d.blocked);
                $('#hg-cond-total').text(fmtNum(d.total) + ' addresses in <' + d.table + '> by conditions');
                condForm.options(d);
            });
        }
    };

    function renderAttacks(d) {
        const ongoing = d.episodes.filter(function (e) { return e.active; });
        const reaching = ongoing.filter(function (e) { return e.passed_pct >= 50; }).length;
        const ids = d.ids_status || {}, cs = d.crowdsec_status || {}, ab = d.autoblock || {};
        const dropped = d.ids.filter(function (r) { return r.action === 'blocked'; }).length;
        const kpis = [
            ['Ongoing attacks', fmtNum(ongoing.length), reaching + ' reaching the host', ongoing.length > 0],
            ['Episodes in period', fmtNum(d.episodes.length), Object.keys(d.kinds).map(function (k) {
                return (ATTACK_KINDS[k] || k) + ' ' + d.kinds[k]; }).join(', ') || 'none'],
            ['Outside sources', fmtNum(d.sources.length + (d.truncated || 0) + (d.folded || 0)),
             [d.truncated ? fmtNum(d.truncated) + ' more not listed (row limit)' : '',
              d.folded ? fmtNum(d.folded) + ' only counted (not stored one by one)' : ''].filter(Boolean).join(' · ') ||
             'blocked or at a rule limit'],
            ['Suricata', ids.enabled ? (ids.readable ? fmtNum(d.ids.length) + ' alert rows' : 'no EVE log') : 'off',
             ids.enabled ? (ids.readable ? (d.ids.length ? fmtNum(dropped) + ' of them dropped by Suricata' +
                                                           (dropped ? '' : ' (IDS mode, or no rule set to drop)') : 'host / signature, towards your hosts')
                                         : String(ids.path || '')) : 'enable it in the settings', ids.enabled && !ids.readable],
            ['CrowdSec', cs.enabled ? (cs.decisions === null || cs.decisions === undefined ? 'n/a' : fmtNum(cs.decisions)) : 'off', 'local decisions'],
            ['Blocked by conditions', fmtNum(ab.blocked || 0), (ab.conditions || 0) + ' conditions' +
             ' · automatic filtering ' + (ab.auto_level ? 'level ' + ab.auto_level : 'off') +
             (ab.auto_spared && Object.keys(ab.auto_spared).length ? ' (spared: ' + Object.keys(ab.auto_spared).map(function (k) {
                 return k + ' ' + ab.auto_spared[k]; }).join(', ') + ')' : '') +
             (ab.table_ok === false ? ' · table update FAILED, retried every poll' : '') +
             (ab.table_unreadable ? ' · table could not be read, new matches wait' : '') +
             (ab.capped ? ' · limit of ' + fmtNum(ab.max) + ' addresses or ' + fmtNum(2000) + ' per poll reached' : ''),
             ab.table_ok === false || !!ab.table_unreadable || !!ab.capped]
        ];
        $('#hg-attack-kpis').html(kpis.map(function (k) {
            return '<div class="hg-kpi' + (k[3] ? ' alert-on' : '') + '"><div class="l">' + esc(k[0]) +
                   '</div><div class="v">' + esc(k[1]) + '</div><div class="s">' + esc(k[2]) + '</div></div>';
        }).join(''));
        $('#hg-attack-threshold').text(fmtNum(d.threshold));
        tables.episodes.setRows(d.episodes);
        tables.attackSources.setRows(d.sources);
        tables.ids.setRows(d.ids);
        renderNetworks(d.networks, d.sources.length);
    }

    // where the listed outside sources come from: per network type and per owner (AS)
    function renderNetworks(n, listed) {
        const $p = $('#hg-networks');
        if (!n || !n.enabled) {
            $p.html('<div class="hg-note">Owner and network type of the sources: off (Settings: Owner and network type of sources).</div>');
            return;
        }
        const last = n.last_try || {};
        const failed = Object.keys(n.sources || {}).filter(function (k) { return typeof n.sources[k] === 'string'; });
        const state = [
            n.available ? 'lists of ' + fmtDate(n.updated) : 'no list downloaded yet (the first download starts a minute after the service)',
            last.status === 'running' && Date.now() / 1000 - last.time < 3600 ? 'downloading now' : '',
            last.status === 'error' ? 'last download failed ' + fmtDate(last.time) + ': ' + last.message : '',
            failed.length ? 'could not download ' + failed.join(', ') + ' (data of an earlier download kept, if any)' : ''
        ].filter(Boolean).join(' · ');
        let html = '<div class="hg-note">Network type and owner (AS) of the sources: ' + esc(state) +
                   ' <button type="button" class="btn btn-default btn-xs" id="hg-ipdata-update"><i class="fa fa-refresh"></i> update now</button></div>';
        const kinds = n.kinds || [];
        if (n.available && kinds.length) {
            const sum = kinds.reduce(function (a, k) { return [a[0] + k.sources, a[1] + k.packets]; }, [0, 0]);
            const pct = function (v, total) { return total ? Math.round(v * 100 / total) + ' %' : '-'; };
            html += '<div style="display:flex;flex-wrap:wrap;gap:16px;margin-bottom:8px"><div style="flex:1 1 300px">' +
                    '<table class="table table-condensed" style="font-size:12px;margin:0"><thead><tr><th>Network type</th>' +
                    '<th class="text-right">Addresses</th><th class="text-right">Blocked pkts</th></tr></thead><tbody>' +
                    kinds.map(function (k) {
                        return '<tr><td><a href="#" class="hg-badge hg-net-kind ' + (NET_CLASS[k.kind] || '') + '" data-kind="' + esc(k.kind) +
                               '" title="Show only these">' + esc(NET_KINDS[k.kind] || k.kind) + '</a>' +
                               (k.by_category ? ' <span class="text-muted" title="Type estimated from the category of the AS (ipverse), no address list names them">' +
                                                (k.by_category === k.sources ? 'estimated' : fmtNum(k.by_category) + ' estimated') + '</span>' : '') +
                               '</td><td class="text-right">' +
                               fmtNum(k.sources) + ' (' + pct(k.sources, sum[0]) + ')</td><td class="text-right">' +
                               fmtNum(k.packets) + ' (' + pct(k.packets, sum[1]) + ')</td></tr>';
                    }).join('') + '</tbody></table></div><div style="flex:1 1 300px">' +
                    '<table class="table table-condensed" style="font-size:12px;margin:0"><thead><tr><th>Busiest owners (of ' +
                    fmtNum(n.asns) + ')</th><th class="text-right">Addresses</th><th class="text-right">Blocked pkts</th></tr></thead><tbody>' +
                    (n.owners || []).slice(0, 8).map(function (o) {
                        return '<tr><td><a href="#" class="hg-net-as" data-as="as:' + esc(o.asn) + ';" title="Show only these">AS' + esc(o.asn) +
                               '</a> ' + esc(o.name) + (o.cc ? ' <span class="text-muted">' + esc(o.cc) + '</span>' : '') +
                               (o.category ? ' <span class="hg-badge ' + (NET_CLASS[o.category] || '') + '" title="Category of the AS (ipverse, estimated)">' +
                                             esc(NET_KINDS[o.category] || o.category) + '</span>' : '') +
                               (o.drop ? '<span class="hg-badge lan">ASN-DROP</span>' : '') + '</td><td class="text-right">' +
                               fmtNum(o.sources) + '</td><td class="text-right">' + fmtNum(o.packets) + '</td></tr>';
                    }).join('') + '</tbody></table></div></div>' +
                    ((n.roles || []).length ? '<div class="hg-note">Also: ' + n.roles.map(function (r) {
                        return '<a href="#" class="hg-badge hg-net-role ' + (ROLE_CLASS[r.role] || '') + '" data-role="' + esc(r.role) +
                               '" title="Show only these">' + esc(NET_ROLES[r.role] || r.role) + ' ' + fmtNum(r.sources) + '</a>';
                    }).join(' ') + ' (crawlers and monitoring are wanted traffic: block them only on purpose)</div>' : '') +
                    '<div class="hg-note">Of the ' + fmtNum(listed) + ' sources listed. Scans and brute force mostly come from hosting ' +
                    'and cloud networks; the source addresses of SYN / UDP / ICMP floods are usually forged, so their owners say nothing.</div>';
        }
        if (n.credits) html += '<div class="hg-note" style="font-size:11px">' + esc(n.credits) + '</div>';
        $p.html(html);
    }
    $(document).on('click', '.hg-net-kind', function (e) {
        e.preventDefault();
        tables.attackSources.setFilter('kind:' + $(this).data('kind'));
    });
    $(document).on('click', '.hg-net-role', function (e) {
        e.preventDefault();
        tables.attackSources.setFilter('role:' + $(this).data('role'));
    });
    $(document).on('click', '.hg-net-as', function (e) {
        e.preventDefault();
        tables.attackSources.setFilter(String($(this).data('as')));
    });
    $(document).on('click', '#hg-ipdata-update', function () {
        ajaxCall('/api/hostguard/service/updateipdata', {}, function (res) {
            notice(res && res.status === 'ok'
                ? 'Downloading the lists in the background (about a minute); reload the tab afterwards.'
                : res && res.status === 403 ? 'No privilege for the HostGuard settings.' : (res && res.message) || 'Starting the download failed.',
                !(res && res.status === 'ok'));
        });
    });

    // the new condition form of the Block conditions tab; "block" elsewhere fills it in, the ban is chosen there
    const condForm = {
        rules: [],
        init: function () {
            $('#hg-cf-attack').html(Object.keys(ATTACK_KINDS).map(function (k) {
                return '<option value="' + esc(k) + '">' + esc(ATTACK_KINDS[k]) + '</option>'; }).join(''));
            $('#hg-cf-factor').html([2, 3, 4, 5, 10].map(function (f) { return '<option value="' + f + '">' + f + '</option>'; }).join(''));
            this.options({});
        },
        options: function (d) {
            // the rules with a per source limit and a label, from the last poll; the choice survives a reload
            // (also one "block" chose that is not in the list)
            const $rule = $('#hg-cf-rule'), keep = $rule.val(), self = this;
            const old = this.rules.filter(function (r) { return r.label === keep; })[0];
            this.rules = (d.src_rules || []).slice();
            if (keep && keep !== '*' && old && !this.rules.some(function (r) { return r.label === keep; })) this.rules.push(old);
            $rule.html('<option value="*">any rule with a per source limit</option>' + this.rules.map(function (r) {
                return '<option value="' + esc(r.label) + '">@' + esc(r.nr) + ' ' + esc(r.descr || r.label) + '</option>'; }).join(''));
            if (keep && self.rules.some(function (r) { return r.label === keep; })) $rule.val(keep);
            this.kinds();
            this.show();
        },
        kinds: function () {
            // only the limits the chosen rule has (any rule: all three)
            const label = $('#hg-cf-rule').val(), $kind = $('#hg-cf-kind'), keep = $kind.val();
            const rule = this.rules.filter(function (r) { return r.label === label; })[0];
            const kinds = rule ? rule.kinds : ['max-src-states', 'max-src-conn', 'max-src-conn-rate'];
            const names = {'max-src-states': 'max source states', 'max-src-conn': 'max established connections',
                           'max-src-conn-rate': 'max new connections (rate)'};
            $kind.html(kinds.map(function (k) {
                return '<option value="' + esc(k) + '">' + esc(names[k] || k) + (rule && rule.limits[k] ? ' (' + esc(rule.limits[k]) + ')' : '') + '</option>'; }).join(''));
            if (keep && kinds.indexOf(keep) >= 0) $kind.val(keep);
        },
        show: function () {
            const type = $('#hg-cf-type').val(), ban = $('#hg-cf-ban').val();
            $('.hg-cf-for').each(function () { $(this).toggle(String($(this).data('for')).split(' ').indexOf(type) >= 0); });
            $('.hg-cf-ban').each(function () { $(this).toggle(String($(this).data('for')).split(' ').indexOf(ban) >= 0); });
            $('.hg-cf-hours-label').text(ban === 'escalating' ? 'First block (hours)' : 'Block for (hours)');
            $('#hg-cf-sid').attr('placeholder', type === 'ids_drop' ? 'every dropped alert' : 'e.g. 2001219');
            $('.hg-cf-window').toggle((parseInt($('#hg-cf-strikes').val(), 10) || 1) > 1);
            const hints = {
                attack: 'Sources of this attack type, as the Attacks tab classifies them.',
                ids_drop: 'Alerts Suricata dropped itself: IPS mode, a rule your policy sets to drop. In IDS mode nothing is dropped and this never matches.',
                ids: 'Every alert of this signature, also the ones Suricata only logged. The severity says nothing about how sure a match is.',
                _strikes: ' Matches are counted once per poll: N matches need a window of at least N polls.',
                src_limit: 'Outside sources at the limit of this rule (read from the rule every poll). Only rules with a description (label) are listed: a condition follows the label across rule reloads.'
            };
            $('#hg-cf-hint').text((hints[type] || '') + ((parseInt($('#hg-cf-strikes').val(), 10) || 1) > 1 ? hints._strikes : ''));
        },
        fill: function (type, value, target) {
            // from a "block" button: the matching fields, the rest stays as chosen last
            $('#hg-cf-type').val(type);
            if (type === 'attack') $('#hg-cf-attack').val(value);
            if (type === 'ids' || type === 'ids_drop') $('#hg-cf-sid').val(value === '*' ? '' : value);
            if (type === 'src_limit') {
                const cut = value.lastIndexOf(':'), label = value.slice(0, cut);
                const $rule = $('#hg-cf-rule');
                if (!$rule.find('option').filter(function () { return this.value === label; }).length) {
                    // a rule not in the last poll's list (no longer at the top 100): offered as it is
                    $rule.append('<option value="' + esc(label) + '">' + esc(label) + '</option>');
                    this.rules.push({label: label, nr: '?', kinds: [value.slice(cut + 1)], limits: {}});
                }
                $rule.val(label);
                const kind = value.slice(cut + 1), rule = this.rules.filter(function (r) { return r.label === label; })[0];
                // a limit the rule had when the source hit it, but not in the last poll's ruleset any more
                if (rule.kinds.indexOf(kind) < 0) rule.kinds.push(kind);
                this.kinds();
                $('#hg-cf-kind').val(kind);
            }
            $('#hg-cf-target').val(target && target !== '*' ? target : '');
            this.show();
        },
        spec: function () {
            // -> the POST fields, or an error text
            const type = $('#hg-cf-type').val(), ban = $('#hg-cf-ban').val();
            const whole = function (id, min, max, what) {
                const s = String($(id).val()).trim();
                const n = /^\d+$/.test(s) ? parseInt(s, 10) : NaN;
                if (isNaN(n) || n < min || n > max) throw what + ': a whole number between ' + min + ' and ' + max;
                return n;
            };
            let value = '';
            if (type === 'attack') value = $('#hg-cf-attack').val();
            if (type === 'ids' || type === 'ids_drop') {
                const sid = String($('#hg-cf-sid').val()).trim();
                if (!sid && type === 'ids_drop') value = '*';
                else if (/^\d{1,12}$/.test(sid)) value = sid;
                else throw 'Signature id: the sid number' + (type === 'ids_drop' ? ', or empty for every dropped alert' : '');
            }
            if (type === 'src_limit') value = $('#hg-cf-rule').val() + ':' + $('#hg-cf-kind').val();
            const target = type === 'src_limit' ? '*' : String($('#hg-cf-target').val()).trim() || '*';
            if (target !== '*' && !isIp(target)) throw 'Towards LAN host: one IP address, or empty for any';
            const hours = ban === 'permanent' ? 0 : whole('#hg-cf-hours', 1, 8784, 'Hours');
            const strikes = whole('#hg-cf-strikes', 1, 100, 'Block after matches');
            const fields = {type: type, value: value, target: target, duration: String(hours * 3600),
                            ban: ban === 'escalating' ? 'escalating' : 'fixed', strikes: String(strikes),
                            window: String(strikes > 1 ? whole('#hg-cf-window', 1, 10080, 'Within minutes') * 60 : 0)};
            if (ban === 'escalating') {
                const longest = whole('#hg-cf-max', 1, 8784, 'Longest block');
                if (longest < hours) throw 'The longest block must be at least the first one';
                Object.assign(fields, {factor: String($('#hg-cf-factor').val()), max_duration: String(longest * 3600),
                                       forget: String(whole('#hg-cf-forget', 1, 366, 'Start again after days') * 86400)});
            }
            return fields;
        }
    };
    condForm.init();
    $('#hg-cf-type, #hg-cf-ban').on('change', function () { condForm.show(); });
    $('#hg-cf-strikes').on('input', function () { condForm.show(); });
    $('#hg-cf-rule').on('change', function () { condForm.kinds(); });
    $('#hg-cf-add').on('click', function () {
        let fields;
        try {
            fields = condForm.spec();
        } catch (e) {
            notice(String(e), true);
            return;
        }
        const text = condText({ctype: fields.type, value: fields.value, target: fields.target});
        if (!window.confirm('Block condition: ' + text + '\n\nFrom now on every OUTSIDE source matching this goes into <virusprot> ' +
                            '(LAN hosts and trusted networks never).')) return;
        ajaxCall(COND_API + 'add', fields, function (res) {
            if (!res || res.status !== 'ok') {
                // stays visible (the next reload hides #hg-error): e.g. no "Block conditions" privilege
                notice(res && res.status === 403
                    ? 'No privilege for block conditions (Firewall: HostGuard: Block conditions).'
                    : (res && res.message) || 'Adding the condition failed.', true);
                return;
            }
            // the same condition again only changes its ban, also for the addresses it holds
            if (res.updated) notice('This condition already existed: its ban is changed, also for the addresses it holds now.');
            loaders.conditions();
        });
    });
    $(document).on('click', '.hg-block', function () {
        const $b = $(this);
        condForm.fill(String($b.data('type')), String($b.data('value')), String($b.data('target')));
        showTab('conditions');
        notice('Choose the ban and press "Add condition".');
    });
    $(document).on('click', '.hg-cond-del', function () {
        const id = $(this).data('id');
        if (!window.confirm('Remove block condition #' + id + '? Addresses only this condition holds leave <virusprot> now.')) return;
        ajaxCall(COND_API + 'del', {id: String(id)}, function (res) {
            // reload in any case (the condition may be gone even if pfctl failed), keep the outcome visible
            loaders.conditions();
            if (!res || res.status !== 'ok') {
                notice((res && res.message) || 'Removing the condition failed', true);
            }
        });
    });
    // grouped outside sources: every one of them, filtered to the group, on the Attacks tab
    function setAttackGroup(group, label) {
        S.attackGroup = group || '';
        $('#hg-attack-group').toggle(!!S.attackGroup).find('.hg-attack-group-text')
            .text(S.attackGroup ? 'Only the sources of ' + (label || S.attackGroup) : '');
    }
    $(document).on('click', '.hg-goto', function (e) {
        e.preventDefault();
        setAttackGroup(String($(this).data('filter') || ''), String($(this).data('label') || ''));
        tables.attackSources.setFilter('');
        showTab('attacks');
    });
    $('#hg-attack-group-clear').on('click', function (e) {
        e.preventDefault();
        setAttackGroup('');
        loaders.attacks();
    });

    function renderBlocked(d) {
        const sampling = d.sampling || {};
        const last = sampling.last || {};
        const devs = Object.keys(last);
        const capped = devs.filter(function (k) { return last[k].capped; });
        const nowRules = d.rules.reduce(function (a, r) { return a + (r.pps || 0); }, 0);
        const kpis = [
            ['Blocked outbound', fmtNum(d.totals.out), 'packets sent by LAN hosts (est.)', d.totals.out > 0],
            ['Blocked inbound', fmtNum(d.totals.in), 'packets towards LAN hosts (est.)'],
            ['Block rules now', fmtNum(nowRules) + ' pkt/s', 'exact, pf rule counters'],
            ['Sampling', devs.length ? devs.map(function (k) { return devLabel(k, sampling.labels); }).join(', ') : 'off',
             devs.length ? sampling.seconds + ' s / ' + fmtNum(sampling.max_packets) + ' packets per poll' +
                 (capped.length ? ', cap reached on ' + capped.join(', ') : '') : 'enable it in the settings']
        ];
        $('#hg-blocked-kpis').html(kpis.map(function (k) {
            return '<div class="hg-kpi' + (k[3] ? ' alert-on' : '') + '"><div class="l">' + esc(k[0]) +
                   '</div><div class="v">' + esc(k[1]) + '</div><div class="s">' + esc(k[2]) + '</div></div>';
        }).join(''));
        HGCharts.timeline(document.getElementById('hg-blocked-chart'), d.timeline.map(function (p) {
            return {t: p.t, values: [p.in_pps, p.out_pps]};
        }), {series: [{label: 'blocked towards LAN hosts (pkt/s)', color: COLOR_IN},
                      {label: 'blocked from LAN hosts (pkt/s)', color: COLOR_OUT}],
             format: fmtNum, timeFormat: fmtTime, height: 220});
        HGCharts.hbar(document.getElementById('hg-blocked-why'), (d.reasons || []).slice(0, 10).map(function (r) {
            return {label: r.reason, sub: r.dir === 'in' ? 'in' : 'out', value: r.packets,
                    color: r.dir === 'in' ? COLOR_IN : COLOR_OUT, row: r};
        }), {format: fmtNum, tip: function (item) {
            return [[null, item.row.reason], [item.color, (item.row.dir === 'in' ? 'towards LAN hosts' : 'from LAN hosts') +
                    ': ' + fmtNum(item.row.packets) + ' packets (est.)']];
        }});
        tables.blockedHosts.setRows(d.hosts);
        tables.blockedFlows.setRows(d.flows);
        tables.blockRules.setRows(d.rules);
    }

    function renderLimits(d) {
        const pf = d.pf || {};
        const pct = function (a, b) { return b ? Math.round(a * 100 / b) + '%' : '-'; };
        const hits = d.counters.filter(function (c) { return c.watched; }).reduce(function (a, c) { return a + c.increase; }, 0);
        const listed = d.tablehits.filter(function (t) { return t.current; }).length;
        const kpis = [
            ['State table', pct(pf.states, pf.states_limit), fmtNum(pf.states) + ' of ' + fmtNum(pf.states_limit) + ' states',
             pf.states_limit && pf.states * 100 / pf.states_limit >= d.thresholds.state_warn_pct],
            ['Source nodes', fmtNum(pf.src_nodes), 'limit ' + fmtNum(pf.src_limit)],
            ['Limit hits', fmtNum(hits), 'pf limit counters in period', hits > 0],
            (function () {
                // outside clients come grouped per rule and limit: count the members at the limit now
                const rows = d.src_limits || [];
                const out = rows.filter(function (s) { return s.lan && s.now && s.at_limit; }).length;
                const inb = rows.reduce(function (a, s) { return a + (s.lan ? 0 : (s.at_limit_now || 0)); }, 0);
                return ['Sources at a pf rule limit', fmtNum(out + inb),
                        out + ' ← out (your hosts) · ' + inb + ' → in (clients)', out > 0];
            })(),
            ['Over warning threshold', fmtNum(d.hosts.filter(function (h) { return h.pct >= 100; }).length),
             '≥ ' + fmtNum(d.thresholds.host_states) + ' states per host (setting, not a pf limit)'],
            ['LAN hosts in block tables', fmtNum(listed), d.tables.map(function (t) { return t.name; }).join(', ') || 'no watched table', listed > 0]
        ];
        $('#hg-limit-kpis').html(kpis.map(function (k) {
            return '<div class="hg-kpi' + (k[3] ? ' alert-on' : '') + '"><div class="l">' + esc(k[0]) +
                   '</div><div class="v">' + esc(k[1]) + '</div><div class="s">' + esc(k[2]) + '</div></div>';
        }).join(''));
        $('#hg-limit-stale').toggle(!d.status_time || Date.now() / 1000 - d.status_time > 600);
        HGCharts.timeline(document.getElementById('hg-pf-states'), d.timeline.map(function (p) {
            return {t: p.t, values: [p.states, p.src_nodes]};
        }), {series: [{label: 'pf states', color: COLOR_IN}, {label: 'source nodes', color: HGCharts.palette[3]}],
             format: fmtNum, timeFormat: fmtTime, height: 200});
        HGCharts.timeline(document.getElementById('hg-pf-hits'), d.timeline.map(function (p) {
            return {t: p.t, values: [p.limit_hits]};
        }), {series: [{label: 'limit counter increases', color: '#d9534f'}], format: fmtNum, timeFormat: fmtTime, height: 200});
        tables.limitHosts.setRows(d.hosts);
        tables.srcLimits.setRows(d.src_limits || []);
        tables.counters.setRows(d.counters);
        tables.rules.setRows(d.rules);
        const sh = d.shaper || {};
        $('#hg-shaper-none').toggle(!(sh.objects || []).length);
        tables.shaperObjects.setRows(sh.objects || []);
        tables.shaperFlows.setRows(sh.flows || []);
        tables.shaperHits.setRows(d.shaper_hits || []);
        tables.tablehits.setRows(d.tablehits);
    }

    function ack(id, $btn) {
        const data = {id: String(id)};
        if (id === 'all' && S.ip) data.ip = S.ip;
        ajaxCall(API + 'ack', data, function (res) {
            if (ok(res)) {
                loaders.alerts();
                loadSummary();
            } else if ($btn) {
                $btn.prop('disabled', false);
            }
        });
    }
    $(document).on('click', '.hg-ack', function (e) {
        e.preventDefault();
        $(this).prop('disabled', true);
        ack($(this).data('id'), $(this));
    });
    $('#hg-ack-all').on('click', function () {
        // acknowledges every open alert, not only the ones the search or period shows
        const which = S.ip ? 'ALL open alerts of ' + S.ip : 'ALL open alerts';
        if (window.confirm('Acknowledge ' + which + ' (also those hidden by the search or the period)?')) {
            ack('all');
        }
    });
    $('#hg-alerts-which').on('change', function () { loaders.alerts(); });
    $('#hg-strip-all').on('click', function (e) {
        e.preventDefault();
        showTab('alerts');
    });

    function refresh() {
        loadSummary();
        loaders[S.tab]();
    }

    function showTab(tab, dir, filter) {
        if (dir !== undefined) $('#hg-' + tab + '-dir').val(dir);
        if (filter !== undefined && tables[tab]) tables[tab].setFilter(filter);
        if (S.tab === tab) {
            loaders[tab]();
        } else {
            $('#hg-tabs a[href="#hg-tab-' + tab + '"]').tab('show');
        }
    }

    function isIp(s) {
        const v4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
        // IPv6: the characters only, the backend checks it exactly
        return v4.test(s) || (/^[0-9a-fA-F:.]+$/.test(s) && s.indexOf(':') >= 0);
    }
    function setIp(ip) {
        ip = String(ip || '').trim();
        if (ip && !isIp(ip)) {
            // never fall back to every host silently (an "acknowledge all" would reach every host)
            // the box shows the filter in force again: the message stays until it is closed
            notice('Not a single IP address: ' + ip, true);
            $('#hg-ip').val(S.ip);
            return;
        }
        // a "list" group of the Attacks tab belongs to the earlier filter (another host's port: an empty list)
        if (ip !== S.ip) setAttackGroup('');
        S.ip = ip;
        $('#hg-ip').val(S.ip);
        $('#hg-ip-clear').toggle(!!S.ip);
        $('#hg-filter-note').text(S.ip ? 'Showing only ' + S.ip : '');
        // stay on the current tab: it reloads filtered to the host
        refresh();
    }

    /* service test */
    function showProbeResult(data) {
        const $box = $('#hg-probe-result');
        if (!data || data.status !== 'ok') {
            $box.attr('class', 'alert alert-danger').text((data && data.message) || 'Test failed').show();
            return;
        }
        const fields = [['Target', data.proto + '://' + data.ip + ':' + data.port], ['State', data.state],
                        ['Service', data.service], ['Product', data.product], ['TLS', data.tls],
                        ['Banner', data.banner], ['Method', data.method]];
        const cls = data.state === 'open' ? 'alert-success' : (data.state === 'closed' ? 'alert-warning' : 'alert-info');
        $box.attr('class', 'alert ' + cls).html('<dl class="dl-horizontal">' + fields.filter(function (f) { return f[1]; })
            .map(function (f) { return '<dt>' + esc(f[0]) + '</dt><dd>' + esc(f[1]) + '</dd>'; }).join('') + '</dl>').show();
    }

    // tests running: a port badge is a link, "disabled" does not stop a second click on it
    const probing = {};
    function runProbe(ip, port, proto, $btn) {
        const key = proto + '://' + ip + ':' + port;
        if (probing[key]) return;
        probing[key] = true;
        const $icon = $btn.find('i');
        const iconClass = $icon.attr('class');
        $btn.prop('disabled', true).addClass('disabled');
        $icon.attr('class', 'fa fa-spinner fa-pulse');
        $('#hg-probe-result').attr('class', 'alert alert-info').text('Testing ' + proto + '://' + ip + ':' + port + ' ...').show();
        if (S.tab !== 'services') showTab('services');
        ajaxCall(API + 'probe', {ip: ip, port: port, proto: proto}, function (data) {
            delete probing[key];
            $btn.prop('disabled', false).removeClass('disabled');
            $icon.attr('class', iconClass);
            showProbeResult(data);
            loaders.services();
            loadSummary();
        });
    }

    $(document).on('click', '.hg-test', function (e) {
        e.preventDefault();
        const $b = $(this);
        runProbe(String($b.data('ip')), String($b.data('port')), String($b.data('proto')), $b);
    });
    $('#hg-probe-go').on('click', function () {
        const ip = $('#hg-probe-ip').val().trim(), port = $('#hg-probe-port').val().trim();
        if (!ip || !/^\d+$/.test(port)) {
            showProbeResult({status: 'error', message: 'Enter a LAN address and a port number.'});
            return;
        }
        runProbe(ip, port, $('#hg-probe-proto').val(), $(this));
    });

    /* toolbar */
    $(document).on('click', '.hg-ip', function (e) {
        e.preventDefault();
        setIp($(this).data('ip'));
    });
    $('#hg-range button').on('click', function () {
        S.hours = parseInt($(this).data('hours'), 10);
        pref('hours', S.hours);
        $('#hg-range button').removeClass('active btn-primary').addClass('btn-default');
        $(this).addClass('active btn-primary').removeClass('btn-default');
        refresh();
    });
    $('#hg-metric button').on('click', function () {
        S.metric = $(this).data('metric');
        pref('metric', S.metric);
        $('#hg-metric button').removeClass('active btn-primary').addClass('btn-default');
        $(this).addClass('active btn-primary').removeClass('btn-default');
        renderOverview();
    });
    $('#hg-ip').on('keydown', function (e) {
        if (e.key === 'Enter') setIp($(this).val().trim());
    });
    $('#hg-ip-go').on('click', function () { setIp($('#hg-ip').val().trim()); });
    $('#hg-ip-clear').on('click', function () { setIp(''); });
    $('#hg-refresh').on('click', refresh);
    $('#hg-auto').on('change', function () {
        pref('auto', this.checked ? '1' : '0');
        clearInterval(S.timer);
        if (this.checked) S.timer = setInterval(refresh, 60000);
    });
    $('#hg-ports-dir, #hg-flows-dir, #hg-blocked-dir').on('change', function () { loaders[S.tab](); });
    $('#hg-tabs a[data-toggle="tab"]').on('shown.bs.tab', function (e) {
        S.tab = $(e.target).attr('href').replace('#hg-tab-', '');
        // the address follows the tab (no hashchange): a reload or the menu entries then behave as expected
        if (window.history.replaceState) {
            window.history.replaceState(null, '', window.location.pathname + window.location.search +
                                        (S.tab === 'overview' ? '' : '#' + S.tab));
        }
        if (S.tab === 'overview') {
            renderOverview();
        } else {
            loaders[S.tab]();
        }
    });

    /* restore preferences and start */
    const savedHours = parseInt(pref('hours'), 10);
    if ([1, 6, 24, 168, 720].indexOf(savedHours) > -1) S.hours = savedHours;
    if (pref('metric') === 'bytes') S.metric = 'bytes';
    $('#hg-range button[data-hours="' + S.hours + '"]').addClass('active btn-primary').removeClass('btn-default');
    $('#hg-metric button[data-metric="' + S.metric + '"]').addClass('active btn-primary').removeClass('btn-default');
    $('#hg-auto').prop('checked', pref('auto') !== '0').trigger('change');
    // the running / stopped badge only: start / stop / restart belong to the Settings privilege
    if (typeof updateServiceStatusUI === 'function') {
        ajaxCall('/api/hostguard/service/status', {}, function (d) {
            if (d && d.status) updateServiceStatusUI(d.status);
        });
    }
    const startTab = window.location.hash.replace('#', '');
    if (startTab && loaders[startTab] && startTab !== 'overview') {
        $('#hg-tabs a[href="#hg-tab-' + startTab + '"]').tab('show');
        loadSummary();
    } else {
        refresh();
    }
    $(window).on('hashchange', function () {
        const tab = window.location.hash.replace('#', '');
        if (loaders[tab]) showTab(tab);
    });
});
</script>

<div class="content-box">
    <div class="hg-toolbar">
        <div class="btn-group btn-group-sm" id="hg-range" role="group">
            <button type="button" class="btn btn-default" data-hours="1">1h</button>
            <button type="button" class="btn btn-default" data-hours="6">6h</button>
            <button type="button" class="btn btn-default" data-hours="24">24h</button>
            <button type="button" class="btn btn-default" data-hours="168">7d</button>
            <button type="button" class="btn btn-default" data-hours="720">30d</button>
        </div>
        <div class="btn-group btn-group-sm" id="hg-metric" role="group">
            <button type="button" class="btn btn-default" data-metric="conns">{{ lang._('Connections') }}</button>
            <button type="button" class="btn btn-default" data-metric="bytes">{{ lang._('Traffic') }}</button>
        </div>
        <div class="hg-ipbox">
            <input type="text" class="form-control" id="hg-ip" placeholder="{{ lang._('Filter by LAN host IP') }}"/>
            <button type="button" class="btn btn-default btn-sm" id="hg-ip-go" title="{{ lang._('Apply filter') }}"><i class="fa fa-filter"></i></button>
            <button type="button" class="btn btn-default btn-sm" id="hg-ip-clear" style="display:none" title="{{ lang._('Clear filter') }}"><i class="fa fa-times"></i></button>
            <span id="hg-filter-note" class="text-muted"></span>
        </div>
        <span class="hg-sep"></span>
        <label class="text-muted" style="margin:0;font-weight:normal">
            <input type="checkbox" id="hg-auto"/> {{ lang._('Auto refresh (60s)') }}
        </label>
        <button type="button" class="btn btn-default btn-sm" id="hg-refresh"><i class="fa fa-refresh"></i> {{ lang._('Refresh') }}</button>
    </div>
    <div class="alert alert-danger" id="hg-error" style="display:none;margin:10px 14px 0"></div>
    <div class="alert alert-warning" id="hg-notice" style="display:none;margin:10px 14px 0">
        <button type="button" class="close" id="hg-notice-close" aria-label="Close"><span aria-hidden="true">&times;</span></button>
        <span class="hg-notice-text"></span>
    </div>
    <div class="alert alert-info" id="hg-nodata" style="display:none;margin:10px 14px 0">
        {{ lang._('No data recorded yet. Enable the collector and select your LAN interfaces / customer networks under Reporting: HostGuard: Settings.') }}
    </div>
    <div class="hg-kpis" id="hg-kpis"></div>
</div>

<ul class="nav nav-tabs" data-tabs="tabs" id="hg-tabs">
    <li class="active"><a data-toggle="tab" href="#hg-tab-overview">{{ lang._('Overview') }}</a></li>
    <li><a data-toggle="tab" href="#hg-tab-alerts">{{ lang._('Alerts') }} <span class="badge" id="hg-alert-badge" style="display:none"></span></a></li>
    <li><a data-toggle="tab" href="#hg-tab-hosts">{{ lang._('Hosts') }}</a></li>
    <li><a data-toggle="tab" href="#hg-tab-lateral">{{ lang._('LAN ↔ LAN') }}</a></li>
    <li><a data-toggle="tab" href="#hg-tab-l2">{{ lang._('MAC / IP') }}</a></li>
    <li><a data-toggle="tab" href="#hg-tab-attacks">{{ lang._('Attacks') }}</a></li>
    <li><a data-toggle="tab" href="#hg-tab-conditions">{{ lang._('Block conditions') }}</a></li>
    <li><a data-toggle="tab" href="#hg-tab-blocked">{{ lang._('Blocked') }}</a></li>
    <li><a data-toggle="tab" href="#hg-tab-limits">{{ lang._('States / Limits') }}</a></li>
    <li><a data-toggle="tab" href="#hg-tab-ports">{{ lang._('Ports') }}</a></li>
    <li><a data-toggle="tab" href="#hg-tab-flows">{{ lang._('Connections') }}</a></li>
    <li><a data-toggle="tab" href="#hg-tab-services">{{ lang._('Services') }}</a></li>
</ul>

<div class="tab-content content-box">
    <div id="hg-tab-overview" class="tab-pane fade in active">
        <div id="hg-alert-strip">
            <h4><i class="fa fa-exclamation-triangle"></i> {{ lang._('Open alerts') }}
                <a href="#" id="hg-strip-all" style="font-weight:normal;margin-left:8px">{{ lang._('show all') }}</a></h4>
            <div class="list"></div>
        </div>
        <div class="hg-grid">
            <div class="hg-panel wide">
                <h4>{{ lang._('Activity over time') }} (<span id="hg-metric-label">connections</span>)</h4>
                <div class="hg-chart" id="hg-timeline"></div>
            </div>
            <div class="hg-panel">
                <h4>{{ lang._('Top ports served by LAN hosts (inbound)') }}</h4>
                <div class="hg-chart" id="hg-top-in"></div>
            </div>
            <div class="hg-panel">
                <h4>{{ lang._('Top ports used by LAN hosts (outbound)') }}</h4>
                <div class="hg-chart" id="hg-top-out"></div>
            </div>
            <div class="hg-panel">
                <h4 id="hg-top-hosts-title">{{ lang._('Top LAN hosts') }}</h4>
                <div class="hg-chart" id="hg-top-hosts"></div>
            </div>
            <div class="hg-panel">
                <h4>{{ lang._('Detected services') }}</h4>
                <div class="hg-chart" id="hg-mix"></div>
            </div>
        </div>
    </div>

    <div id="hg-tab-alerts" class="tab-pane fade">
        <div class="hg-pane" id="hg-alerts">
            <div class="hg-table-tools">
                <select class="form-control" id="hg-alerts-which">
                    <option value="all">{{ lang._('Open + acknowledged') }}</option>
                    <option value="open">{{ lang._('Open only') }}</option>
                </select>
                <input type="text" class="form-control hg-search" placeholder="{{ lang._('Search...') }}"/>
                <button type="button" class="btn btn-default btn-sm" id="hg-ack-all"><i class="fa fa-check"></i> {{ lang._('Acknowledge all open') }}</button>
                <span class="hg-count"></span>
            </div>
            <div class="hg-table-wrap">
                <table class="table table-condensed table-hover hg-table"><thead><tr></tr></thead><tbody></tbody></table>
            </div>
        </div>
    </div>

    <div id="hg-tab-lateral" class="tab-pane fade">
        <div class="hg-pane" id="hg-lateral">
            <div class="hg-note">
                {{ lang._('Connections from one LAN host to another. Only traffic that passes the firewall is visible (between different interfaces/subnets, or through a filtering bridge); blocked attempts are estimated from sampling. Red rows: blocked or unanswered attempts. Yellow rows: sensitive port (SSH, RDP, SMB, databases...).') }}
            </div>
            <div class="hg-table-tools">
                <input type="text" class="form-control hg-search" placeholder="{{ lang._('Search, e.g. tcp/22 or an address') }}"/>
                <span class="hg-count"></span>
            </div>
            <div class="hg-table-wrap">
                <table class="table table-condensed table-hover hg-table"><thead><tr></tr></thead><tbody></tbody></table>
            </div>
        </div>
    </div>

    <div id="hg-tab-l2" class="tab-pane fade">
        <div class="hg-pane" id="hg-l2">
            <div class="hg-note">
                {{ lang._('MAC / IP bindings from the firewall ARP and NDP tables in the selected period. Yellow: one MAC used several IPv4 addresses (multiple IPs or IP changed). Red: one IP appeared on several MACs (IP taken over, spoofing or conflict).') }}
            </div>
            <div class="hg-table-tools">
                <input type="text" class="form-control hg-search" placeholder="{{ lang._('Search MAC or IP...') }}"/>
                <span class="hg-count"></span>
            </div>
            <div class="hg-table-wrap">
                <table class="table table-condensed table-hover hg-table"><thead><tr></tr></thead><tbody></tbody></table>
            </div>
        </div>
    </div>

    <div id="hg-tab-attacks" class="tab-pane fade">
        <div class="hg-note" style="padding:14px 14px 0">
            {{ lang._('Attacks on your hosts from outside. An episode opens when one LAN host receives at least') }}
            <b id="hg-attack-threshold"></b> {{ lang._('attempts per second (estimated from the blocked traffic samples, blocked and passed together; brute force from a fifth of it) and ends after 10 quiet minutes. Types: reflection / amplification (UDP replies from DNS, NTP, memcached, SSDP, CLDAP ... servers), SYN / UDP / ICMP flood, distributed brute force on a login port, port scan. "Passed firewall" is the share that reached the host. Block: from now on, outside sources of this kind of event go into the virusprot table (see Block conditions).') }}
        </div>
        <div class="hg-kpis" id="hg-attack-kpis" style="padding-top:10px"></div>
        <div class="hg-pane" id="hg-episodes">
            <h4 style="font-size:13px;font-weight:600">{{ lang._('Attack episodes') }}</h4>
            <div class="hg-table-tools">
                <input type="text" class="form-control hg-search" placeholder="{{ lang._('Search...') }}"/>
                <span class="hg-count"></span>
            </div>
            <div class="hg-table-wrap" style="max-height:360px">
                <table class="table table-condensed table-hover hg-table"><thead><tr></tr></thead><tbody></tbody></table>
            </div>
        </div>
        <div class="hg-pane" id="hg-ids">
            <h4 style="font-size:13px;font-weight:600">{{ lang._('Suricata alerts towards your hosts (per host and signature)') }}</h4>
            <div class="hg-table-tools">
                <input type="text" class="form-control hg-search" placeholder="{{ lang._('Search...') }}"/>
                <span class="hg-count"></span>
            </div>
            <div class="hg-table-wrap" style="max-height:360px">
                <table class="table table-condensed table-hover hg-table"><thead><tr></tr></thead><tbody></tbody></table>
            </div>
        </div>
        <div class="hg-pane" id="hg-attack-sources">
            <h4 style="font-size:13px;font-weight:600">{{ lang._('Outside sources (every address, other tabs group them)') }}</h4>
            <div class="hg-note">{{ lang._('Sources that sent blocked traffic to your hosts, with their CrowdSec scenario, Suricata hits and rule limits. Per LAN host and port the 20 busiest sources are stored one by one, the rest only counted.') }}</div>
            <div id="hg-networks"></div>
            <div class="alert alert-info" id="hg-attack-group" style="display:none;padding:6px 10px;margin-bottom:8px">
                <span class="hg-attack-group-text"></span>
                <a href="#" id="hg-attack-group-clear" style="margin-left:8px">{{ lang._('show all') }}</a>
            </div>
            <div class="hg-table-tools">
                <input type="text" class="form-control hg-search" placeholder="{{ lang._('Search address, port, scenario...') }}"/>
                <span class="hg-count"></span>
            </div>
            <div class="hg-table-wrap" style="max-height:420px">
                <table class="table table-condensed table-hover hg-table"><thead><tr></tr></thead><tbody></tbody></table>
            </div>
        </div>
    </div>

    <div id="hg-tab-conditions" class="tab-pane fade">
        <div class="hg-note" style="padding:14px 14px 0">
            {{ lang._('Block conditions: created with the form below, or prepared by "block" on an attack, a Suricata alert or an outside source at a rule limit. A ban is a fixed time, escalating (each new block of the same address by the same condition lasts longer, up to the longest block) or until the condition is removed; "block after matches" waits until an address matched in that many polls within the time given. Every poll, outside sources matching a condition are added to the virusprot table (blocked by the OPNsense rule for it). LAN hosts, the firewall and trusted networks are never added. A source at a rule limit is matched against the limit the rule has now: change max-src-states and the condition follows. Removing a condition releases the addresses only it holds; each address is also released when its time is up. OPNsense may expire virusprot entries on its own schedule too.') }}
        </div>
        <div class="hg-pane" id="hg-cond-new">
            <h4 style="font-size:13px;font-weight:600">{{ lang._('New condition') }}</h4>
            <div class="hg-cond-form">
                <label>{{ lang._('Match') }}
                    <select class="form-control" id="hg-cf-type">
                        <option value="attack">{{ lang._('Attack type') }}</option>
                        <option value="ids_drop">{{ lang._('Alert Suricata dropped (IPS)') }}</option>
                        <option value="ids">{{ lang._('Suricata signature (any action)') }}</option>
                        <option value="src_limit">{{ lang._('Source at a rule limit') }}</option>
                    </select></label>
                <label class="hg-cf-for" data-for="attack">{{ lang._('Attack') }}
                    <select class="form-control" id="hg-cf-attack"></select></label>
                <label class="hg-cf-for" data-for="ids ids_drop">{{ lang._('Signature id (sid)') }}
                    <input type="text" class="form-control" id="hg-cf-sid" placeholder="{{ lang._('every dropped alert') }}" style="width:150px"/></label>
                <label class="hg-cf-for" data-for="src_limit">{{ lang._('Rule') }}
                    <select class="form-control" id="hg-cf-rule"></select></label>
                <label class="hg-cf-for" data-for="src_limit">{{ lang._('Limit') }}
                    <select class="form-control" id="hg-cf-kind"></select></label>
                <label class="hg-cf-for" data-for="attack ids ids_drop">{{ lang._('Towards LAN host') }}
                    <input type="text" class="form-control" id="hg-cf-target" placeholder="{{ lang._('any (empty)') }}" style="width:170px"/></label>
            </div>
            <div class="hg-cond-form">
                <label>{{ lang._('Ban') }}
                    <select class="form-control" id="hg-cf-ban">
                        <option value="fixed">{{ lang._('Fixed time') }}</option>
                        <option value="escalating">{{ lang._('Escalating (longer each repeat)') }}</option>
                        <option value="permanent">{{ lang._('Until the condition is removed') }}</option>
                    </select></label>
                <label class="hg-cf-ban" data-for="fixed escalating"><span class="hg-cf-hours-label">{{ lang._('Block for (hours)') }}</span>
                    <input type="text" class="form-control" id="hg-cf-hours" value="24" style="width:90px"/></label>
                <label class="hg-cf-ban" data-for="escalating">{{ lang._('Each repeat x') }}
                    <select class="form-control" id="hg-cf-factor"></select></label>
                <label class="hg-cf-ban" data-for="escalating">{{ lang._('Longest block (hours)') }}
                    <input type="text" class="form-control" id="hg-cf-max" value="720" style="width:90px"/></label>
                <label class="hg-cf-ban" data-for="escalating">{{ lang._('Start again after (days quiet)') }}
                    <input type="text" class="form-control" id="hg-cf-forget" value="30" style="width:80px"/></label>
                <label>{{ lang._('Block after matches') }}
                    <input type="text" class="form-control" id="hg-cf-strikes" value="1" style="width:70px"/></label>
                <label class="hg-cf-window">{{ lang._('within (minutes)') }}
                    <input type="text" class="form-control" id="hg-cf-window" value="10" style="width:80px"/></label>
                <button type="button" class="btn btn-primary" id="hg-cf-add"><i class="fa fa-ban"></i> {{ lang._('Add condition') }}</button>
            </div>
            <div class="hg-note" id="hg-cf-hint"></div>
        </div>
        <div class="hg-pane" id="hg-conditions">
            <h4 style="font-size:13px;font-weight:600">{{ lang._('Conditions') }} <span class="text-muted" id="hg-cond-total" style="font-weight:normal"></span></h4>
            <div class="hg-table-tools">
                <input type="text" class="form-control hg-search" placeholder="{{ lang._('Search...') }}"/>
                <span class="hg-count"></span>
            </div>
            <div class="hg-table-wrap" style="max-height:360px">
                <table class="table table-condensed table-hover hg-table"><thead><tr></tr></thead><tbody></tbody></table>
            </div>
        </div>
        <div class="hg-pane" id="hg-autoblocked">
            <h4 style="font-size:13px;font-weight:600">{{ lang._('Addresses blocked by conditions') }}</h4>
            <div class="hg-table-tools">
                <input type="text" class="form-control hg-search" placeholder="{{ lang._('Search...') }}"/>
                <span class="hg-count"></span>
            </div>
            <div class="hg-table-wrap" style="max-height:420px">
                <table class="table table-condensed table-hover hg-table"><thead><tr></tr></thead><tbody></tbody></table>
            </div>
        </div>
    </div>

    <div id="hg-tab-blocked" class="tab-pane fade">
        <div class="hg-note" style="padding:14px 14px 0">
            {{ lang._('Blocked traffic without firewall logging. Per host numbers are estimated: every poll connection attempts (TCP SYN, UDP, ICMP echo) are sampled for a few seconds and checked against the state table; attempts without a state were blocked. The block rule table is exact (pf rule counters).') }}
        </div>
        <div class="hg-kpis" id="hg-blocked-kpis" style="padding-top:10px"></div>
        <div class="hg-grid" style="padding-top:0">
            <div class="hg-panel wide">
                <h4>{{ lang._('Blocked packets per second (estimated)') }}</h4>
                <div class="hg-chart" id="hg-blocked-chart"></div>
            </div>
            <div class="hg-panel wide">
                <h4>{{ lang._('Why blocked') }}</h4>
                <div class="hg-note">{{ lang._('Without logging: a source in a table that a block rule uses (CrowdSec, virusprot, bogons, aliases), a per source limit, a full state table, a private / bogon source. Everything else did not match any pass rule (default deny or a block rule that cannot be named without logging).') }}</div>
                <div class="hg-chart" id="hg-blocked-why"></div>
            </div>
        </div>
        <div class="hg-pane" id="hg-blocked-hosts">
            <h4 style="font-size:13px;font-weight:600">{{ lang._('LAN hosts: blocked traffic they send (abuse?) and receive (attacked?)') }}</h4>
            <div class="hg-table-tools">
                <input type="text" class="form-control hg-search" placeholder="{{ lang._('Search...') }}"/>
                <span class="hg-count"></span>
            </div>
            <div class="hg-table-wrap" style="max-height:360px">
                <table class="table table-condensed table-hover hg-table"><thead><tr></tr></thead><tbody></tbody></table>
            </div>
        </div>
        <div class="hg-pane" id="hg-block-rules">
            <h4 style="font-size:13px;font-weight:600">{{ lang._('Block rules (exact packet counters)') }}</h4>
            <div class="hg-table-tools">
                <input type="text" class="form-control hg-search" placeholder="{{ lang._('Search...') }}"/>
                <span class="hg-count"></span>
            </div>
            <div class="hg-table-wrap" style="max-height:300px">
                <table class="table table-condensed table-hover hg-table"><thead><tr></tr></thead><tbody></tbody></table>
            </div>
        </div>
        <div class="hg-pane" id="hg-blocked-flows">
            <h4 style="font-size:13px;font-weight:600">{{ lang._('Blocked attempts') }}</h4>
            <div class="hg-table-tools">
                <select class="form-control" id="hg-blocked-dir">
                    <option value="">{{ lang._('Both directions') }}</option>
                    <option value="out">{{ lang._('Sent by LAN hosts') }}</option>
                    <option value="in">{{ lang._('Towards LAN hosts') }}</option>
                </select>
                <input type="text" class="form-control hg-search" placeholder="{{ lang._('Search, e.g. tcp/25 or an address') }}"/>
                <span class="hg-count"></span>
            </div>
            <div class="hg-table-wrap">
                <table class="table table-condensed table-hover hg-table"><thead><tr></tr></thead><tbody></tbody></table>
            </div>
        </div>
    </div>

    <div id="hg-tab-limits" class="tab-pane fade">
        <div class="alert alert-warning" id="hg-limit-stale" style="display:none;margin:14px 14px 0">
            {{ lang._('No recent status from the collector. Is the service running?') }}
        </div>
        <div class="hg-kpis" id="hg-limit-kpis" style="padding-top:14px"></div>
        <div class="hg-grid" style="padding-top:0">
            <div class="hg-panel">
                <h4>{{ lang._('pf state table') }}</h4>
                <div class="hg-chart" id="hg-pf-states"></div>
            </div>
            <div class="hg-panel">
                <h4>{{ lang._('Limit hits (memory, state-limit, src-limit, max-src-conn, overload, synflood ...)') }}</h4>
                <div class="hg-chart" id="hg-pf-hits"></div>
            </div>
        </div>
        <div class="hg-pane" id="hg-limit-hosts">
            <h4 style="font-size:13px;font-weight:600">{{ lang._('LAN hosts by firewall states (now)') }}</h4>
            <div class="hg-note">{{ lang._('pf has no per host limit. A host is limited only by (1) the state table in total, shared by everyone, and (2) the per source limits of the rules its own connections go through (max-src-states, max-src-conn, max-src-conn-rate). The warning threshold is a HostGuard setting that only raises an alert, it drops nothing. pf states counts both directions; a per source limit counts only the connections the host opens.') }}</div>
            <div class="hg-table-tools">
                <input type="text" class="form-control hg-search" placeholder="{{ lang._('Search...') }}"/>
                <span class="hg-count"></span>
            </div>
            <div class="hg-table-wrap" style="max-height:360px">
                <table class="table table-condensed table-hover hg-table"><thead><tr></tr></thead><tbody></tbody></table>
            </div>
        </div>
        <div class="hg-pane" id="hg-src-limits">
            <h4 style="font-size:13px;font-weight:600">{{ lang._('Sources at a per source rule limit (max-src-states, max-src-conn, max-src-conn-rate)') }}</h4>
            <div class="hg-note">{{ lang._('From the pf source tracking table: which address reached which limit on which rule. New connections of a source at its limit are dropped.') }}
                <br/>{{ lang._('"Source" is always the side that opens the connection. → in (clients): an outside address connecting to your hosts hit the limit (the limit protects your hosts, your host itself is fine). ← out (your hosts): one of your LAN hosts opened too many connections and its own new connections are dropped.') }}</div>
            <div class="hg-table-tools">
                <input type="text" class="form-control hg-search" placeholder="{{ lang._('Search...') }}"/>
                <span class="hg-count"></span>
            </div>
            <div class="hg-table-wrap" style="max-height:360px">
                <table class="table table-condensed table-hover hg-table"><thead><tr></tr></thead><tbody></tbody></table>
            </div>
        </div>
        <div class="hg-pane" id="hg-tablehits">
            <h4 style="font-size:13px;font-weight:600">{{ lang._('LAN hosts in watched pf tables (virusprot, sshlockout, crowdsec ...)') }}</h4>
            <div class="hg-table-tools">
                <input type="text" class="form-control hg-search" placeholder="{{ lang._('Search...') }}"/>
                <span class="hg-count"></span>
            </div>
            <div class="hg-table-wrap" style="max-height:300px">
                <table class="table table-condensed table-hover hg-table"><thead><tr></tr></thead><tbody></tbody></table>
            </div>
        </div>
        <div class="hg-pane" id="hg-counters">
            <h4 style="font-size:13px;font-weight:600">{{ lang._('pf counters') }}</h4>
            <div class="hg-table-tools">
                <input type="text" class="form-control hg-search" placeholder="{{ lang._('Search...') }}"/>
                <span class="hg-count"></span>
            </div>
            <div class="hg-table-wrap" style="max-height:360px">
                <table class="table table-condensed table-hover hg-table"><thead><tr></tr></thead><tbody></tbody></table>
            </div>
        </div>
        <div class="hg-pane" id="hg-rules">
            <h4 style="font-size:13px;font-weight:600">{{ lang._('Rule limits and how full they are') }}</h4>
            <div class="hg-note">{{ lang._('Read from every firewall rule that carries a limit: max (states of the rule), max-src-nodes (source addresses of the rule), and per source max-src-states, max-src-conn, max-src-conn-rate (busiest source shown). With global source tracking, the default for OPNsense rules, one counter per address is shared by all rules with per source limits.') }}
                <br/>{{ lang._('Counts: whose connections the per source limits of the rule count, taken from the rule (from / to addresses, interface and direction). → in (clients) for rules that let the internet reach your hosts, ← out (your hosts) for rules your hosts use to go out.') }}</div>
            <div class="hg-table-tools">
                <input type="text" class="form-control hg-search" placeholder="{{ lang._('Search...') }}"/>
                <span class="hg-count"></span>
            </div>
            <div class="hg-table-wrap" style="max-height:420px">
                <table class="table table-condensed table-hover hg-table"><thead><tr></tr></thead><tbody></tbody></table>
            </div>
        </div>
        <div class="hg-pane" id="hg-shaper-objects">
            <h4 style="font-size:13px;font-weight:600">{{ lang._('Traffic shaper: pipes and queues') }}</h4>
            <div class="hg-note">{{ lang._('Limits, masks, descriptions and the shaper rules feeding them come from Firewall: Shaper; throughput and drops from the ipfw counters. A per IP pipe gives every address the full bandwidth; a shared pipe splits it; queues share their pipe by weight. Drops mean the limit is reached.') }}</div>
            <div class="text-muted" id="hg-shaper-none" style="display:none">{{ lang._('No shaper pipes found (shaper not used, or ipfw not loaded).') }}</div>
            <div class="hg-table-tools">
                <input type="text" class="form-control hg-search" placeholder="{{ lang._('Search...') }}"/>
                <span class="hg-count"></span>
            </div>
            <div class="hg-table-wrap" style="max-height:360px">
                <table class="table table-condensed table-hover hg-table"><thead><tr></tr></thead><tbody></tbody></table>
            </div>
        </div>
        <div class="hg-pane" id="hg-shaper-flows">
            <h4 style="font-size:13px;font-weight:600">{{ lang._('Traffic shaper: addresses now') }}</h4>
            <div class="hg-table-tools">
                <input type="text" class="form-control hg-search" placeholder="{{ lang._('Search...') }}"/>
                <span class="hg-count"></span>
            </div>
            <div class="hg-table-wrap" style="max-height:360px">
                <table class="table table-condensed table-hover hg-table"><thead><tr></tr></thead><tbody></tbody></table>
            </div>
        </div>
        <div class="hg-pane" id="hg-shaper-hits">
            <h4 style="font-size:13px;font-weight:600">{{ lang._('Traffic shaper: addresses that hit their limit (dropped packets) in the period') }}</h4>
            <div class="hg-table-tools">
                <input type="text" class="form-control hg-search" placeholder="{{ lang._('Search...') }}"/>
                <span class="hg-count"></span>
            </div>
            <div class="hg-table-wrap" style="max-height:360px">
                <table class="table table-condensed table-hover hg-table"><thead><tr></tr></thead><tbody></tbody></table>
            </div>
        </div>
    </div>

    <div id="hg-tab-hosts" class="tab-pane fade">
        <div class="hg-pane" id="hg-hosts">
            <div class="hg-table-tools">
                <input type="text" class="form-control hg-search" placeholder="{{ lang._('Search...') }}"/>
                <span class="hg-count"></span>
            </div>
            <div class="hg-table-wrap">
                <table class="table table-striped table-condensed table-hover hg-table"><thead><tr></tr></thead><tbody></tbody></table>
            </div>
        </div>
    </div>

    <div id="hg-tab-ports" class="tab-pane fade">
        <div class="hg-pane" id="hg-ports">
            <div class="hg-table-tools">
                <select class="form-control" id="hg-ports-dir">
                    <option value="">{{ lang._('Both directions') }}</option>
                    <option value="in">{{ lang._('Inbound (served)') }}</option>
                    <option value="out">{{ lang._('Outbound (used)') }}</option>
                </select>
                <input type="text" class="form-control hg-search" placeholder="{{ lang._('Search...') }}"/>
                <span class="hg-count"></span>
            </div>
            <div class="hg-table-wrap">
                <table class="table table-striped table-condensed table-hover hg-table"><thead><tr></tr></thead><tbody></tbody></table>
            </div>
        </div>
    </div>

    <div id="hg-tab-flows" class="tab-pane fade">
        <div class="hg-pane" id="hg-flows">
            <div class="hg-table-tools">
                <select class="form-control" id="hg-flows-dir">
                    <option value="">{{ lang._('Both directions') }}</option>
                    <option value="in">{{ lang._('Inbound (served)') }}</option>
                    <option value="out">{{ lang._('Outbound (used)') }}</option>
                </select>
                <input type="text" class="form-control hg-search" placeholder="{{ lang._('Search, e.g. tcp/443 or an address') }}"/>
                <span class="hg-count"></span>
            </div>
            <div class="hg-table-wrap">
                <table class="table table-striped table-condensed table-hover hg-table"><thead><tr></tr></thead><tbody></tbody></table>
            </div>
        </div>
    </div>

    <div id="hg-tab-services" class="tab-pane fade">
        <div class="hg-pane" id="hg-services">
            <div class="hg-probe-form">
                <strong>{{ lang._('Test a service') }}:</strong>
                <input type="text" class="form-control" id="hg-probe-ip" placeholder="{{ lang._('LAN address') }}" style="width:180px"/>
                <input type="text" class="form-control" id="hg-probe-port" placeholder="{{ lang._('Port') }}" style="width:80px"/>
                <select class="form-control" id="hg-probe-proto">
                    <option value="tcp">tcp</option>
                    <option value="udp">udp</option>
                </select>
                <button type="button" class="btn btn-primary btn-sm" id="hg-probe-go"><i class="fa fa-stethoscope"></i> {{ lang._('Test') }}</button>
            </div>
            <div id="hg-probe-result" style="display:none"></div>
            <div class="hg-table-tools">
                <input type="text" class="form-control hg-search" placeholder="{{ lang._('Search...') }}"/>
                <span class="hg-count"></span>
            </div>
            <div class="hg-table-wrap">
                <table class="table table-striped table-condensed table-hover hg-table"><thead><tr></tr></thead><tbody></tbody></table>
            </div>
        </div>
    </div>
</div>
