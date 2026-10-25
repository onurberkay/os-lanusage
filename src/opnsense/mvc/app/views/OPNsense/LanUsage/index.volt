{#
 # Copyright (C) 2026 Onur Berkay <onurberkay@sakla.app>
 # All rights reserved. (BSD 2-Clause, see LICENSE)
 #
 # LAN Usage dashboard
 #}

<script src="{{ cache_safe('/ui/js/lanusage.charts.js') }}"></script>

<style>
    .lu-toolbar { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; padding: 12px 14px 4px; }
    .lu-toolbar .form-control { height: 30px; padding: 4px 8px; }
    .lu-toolbar .lu-sep { flex: 1 1 auto; }
    .lu-ipbox { display: flex; gap: 4px; align-items: center; }
    .lu-ipbox input { width: 190px; }
    .lu-kpis { display: flex; flex-wrap: wrap; gap: 10px; padding: 10px 14px 14px; }
    .lu-kpi { flex: 1 1 150px; border: 1px solid rgba(128,128,128,.25); border-radius: 3px; padding: 8px 12px; }
    .lu-kpi .l { font-size: 11px; opacity: .7; text-transform: uppercase; letter-spacing: .04em; }
    .lu-kpi .v { font-size: 22px; font-weight: 600; line-height: 1.3; }
    .lu-kpi .s { font-size: 11px; opacity: .65; }
    .lu-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 22px 28px; padding: 16px; }
    .lu-panel h4 { font-size: 13px; font-weight: 600; margin: 0 0 8px; }
    .lu-panel.wide { grid-column: 1 / -1; }
    .lu-chart { width: 100%; min-height: 60px; }
    .lu-badge { display: inline-block; padding: 1px 6px; margin: 1px 3px 1px 0; border-radius: 3px; font-size: 11px;
                background: rgba(128,128,128,.16); white-space: nowrap; }
    .lu-badge.in { background: rgba(42,159,214,.2); }
    .lu-badge.out { background: rgba(232,116,47,.22); }
    .lu-badge.svc { background: rgba(76,175,80,.22); }
    a.lu-badge { color: inherit; cursor: pointer; text-decoration: none; }
    a.lu-badge:hover { outline: 1px solid rgba(128,128,128,.5); }
    .lu-pane { padding: 14px; }
    .lu-table-tools { display: flex; gap: 10px; align-items: center; margin-bottom: 8px; flex-wrap: wrap; }
    .lu-table-tools .lu-search { width: 260px; height: 30px; }
    .lu-table-tools select { height: 30px; width: auto; }
    .lu-table-tools .lu-count { opacity: .65; font-size: 12px; margin-left: auto; }
    .lu-table-wrap { max-height: 640px; overflow: auto; }
    table.lu-table th { cursor: pointer; white-space: nowrap; user-select: none; }
    table.lu-table th.nosort { cursor: default; }
    table.lu-table td { vertical-align: middle !important; }
    table.lu-table td.num, table.lu-table th.num { text-align: right; white-space: nowrap; }
    table.lu-table td.nowrap { white-space: nowrap; }
    table.lu-table td.banner { max-width: 340px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
                               font-family: monospace; font-size: 11px; }
    .lu-ip { cursor: pointer; font-family: monospace; }
    .lu-state-open { color: #4caf50; font-weight: 600; }
    .lu-state-closed, .lu-state-error, .lu-state-unreachable { color: #d9534f; }
    .lu-state-filtered { color: #e8742f; }
    .lu-probe-form { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; margin-bottom: 12px; }
    .lu-probe-form input, .lu-probe-form select { height: 30px; width: auto; }
    #lu-probe-result { margin-bottom: 12px; }
    #lu-probe-result dl { margin: 0; }
    #lu-probe-result dt { width: 90px; }
    #lu-probe-result dd { margin-left: 110px; word-break: break-all; }
    .lu-kpi.alert-on { border-color: #d9534f; background: rgba(217,83,79,.08); }
    .lu-kpi.alert-on .v { color: #d9534f; }
    .lu-badge.lan { background: rgba(217,83,79,.2); }
    .lu-badge.warn { background: rgba(240,173,78,.3); }
    .lu-sev { display: inline-block; min-width: 62px; text-align: center; padding: 1px 6px; border-radius: 3px;
              font-size: 11px; font-weight: 600; color: #fff; text-transform: uppercase; }
    .lu-sev.critical { background: #a94442; }
    .lu-sev.high { background: #d9534f; }
    .lu-sev.medium { background: #e8942f; }
    .lu-sev.info { background: #5bc0de; }
    #lu-alert-strip { margin: 16px 16px 0; padding: 10px 14px; border-left: 4px solid #d9534f;
                      background: rgba(217,83,79,.07); display: none; }
    #lu-alert-strip h4 { font-size: 13px; font-weight: 600; margin: 0 0 6px; }
    #lu-alert-strip .row-a { padding: 2px 0; font-size: 12px; }
    #lu-alert-strip .row-a .t { opacity: .6; margin-left: 6px; }
    tr.lu-acked { opacity: .55; }
    tr.lu-row-warn > td { background: rgba(240,173,78,.12) !important; }
    tr.lu-row-bad > td { background: rgba(217,83,79,.10) !important; }
    #lu-tabs .badge { background: #d9534f; margin-left: 4px; }
    .lu-note { font-size: 12px; opacity: .7; margin-bottom: 8px; }
</style>

<script>
$(function () {
    'use strict';
    const API = '/api/lanusage/stats/';
    const COLOR_IN = '#2a9fd6', COLOR_OUT = '#e8742f';
    const S = {hours: 24, ip: '', metric: 'conns', tab: 'overview', summary: null, timer: null};

    function pref(key, value) {
        try {
            if (value === undefined) return window.localStorage.getItem('lanusage.' + key);
            window.localStorage.setItem('lanusage.' + key, value);
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
        return '<a class="lu-ip" data-ip="' + esc(ip) + '" title="Show this host">' + esc(ip) + '</a>';
    }
    function dirBadge(d) {
        return d === 'in' ? '<span class="lu-badge in">→ in</span>' : '<span class="lu-badge out">← out</span>';
    }
    function testButton(ip, port, proto) {
        if (proto !== 'tcp' && proto !== 'udp') return '';
        return '<button type="button" class="btn btn-default btn-xs lu-test" title="Test service" data-ip="' +
               esc(ip) + '" data-port="' + esc(port) + '" data-proto="' + esc(proto) + '"><i class="fa fa-stethoscope"></i></button>';
    }

    function showError(msg) {
        $('#lu-error').text(msg || 'Request failed').show();
    }
    function ok(data) {
        if (!data || data.status !== 'ok') {
            showError(data && data.message ? data.message : 'Unexpected response from the backend');
            return false;
        }
        $('#lu-error').hide();
        return true;
    }

    function api(endpoint, extra) {
        const params = Object.assign({hours: S.hours}, extra || {});
        if (S.ip) params.ip = S.ip;
        return $.ajax({url: API + endpoint, data: params, dataType: 'json', cache: false})
            .fail(function (xhr) { showError('Request failed: ' + xhr.status + ' ' + xhr.statusText); });
    }

    /* sortable / searchable table */
    function makeTable(id, columns, sortKey, rowClass) {
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
        $wrap.find('.lu-search').on('input', function () {
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
            $wrap.find('.lu-search').val(value);
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
                '<tr><td colspan="' + columns.length + '" class="text-center text-muted">No data for this period</td></tr>');
            $wrap.find('.lu-count').text(rows.length > shown.length
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
        ip_changed: 'IP changed',
        mac_changed: 'IP moved to another MAC',
        state_table: 'State table filling up',
        pf_limit: 'pf limit reached',
        host_states: 'Too many states (host)',
        host_rate: 'Connection rate (host)',
        rule_limit: 'Rule near max states',
        in_table: 'LAN host in block table',
        blocked_out: 'Blocked outbound (host)',
        blocked_in: 'Blocked attack (host)',
        rule_blocking: 'Block rule busy',
        src_limit: 'Source at rule limit'
    };
    function pctBar(pct) {
        const p = Math.min(100, Math.max(0, Number(pct) || 0));
        const color = p >= 100 ? '#d9534f' : (p >= 80 ? '#e8942f' : '#2a9fd6');
        return '<span style="display:inline-block;width:70px;height:8px;background:rgba(128,128,128,.18);' +
               'border-radius:2px;vertical-align:middle;margin-right:6px"><span style="display:block;height:8px;width:' +
               p + '%;background:' + color + ';border-radius:2px"></span></span>' + esc(pct) + '%';
    }
    function sevLabel(s) {
        return '<span class="lu-sev ' + esc(s) + '">' + esc(s) + '</span>';
    }
    function macCell(mac, count) {
        if (!mac) return '';
        return '<span style="font-family:monospace">' + esc(mac) + '</span>' + (count > 1
            ? ' <span class="lu-badge warn" title="This MAC used ' + count + ' IPv4 addresses in the selected period">⚠ ' + count + ' IPs</span>' : '');
    }

    const tables = {
        hosts: makeTable('lu-hosts', [
            {key: 'ip', label: 'LAN host', html: function (r) { return ipLink(r.ip); },
             sortValue: function (r) { return ipKey(r.ip); }},
            {key: 'mac', label: 'MAC', cls: 'nowrap', text: function (r) { return r.mac + (r.mac_ips > 1 ? ' multiple' : ''); },
             html: function (r) { return macCell(r.mac, r.mac_ips); }},
            {key: 'alerts', label: 'Alerts', cls: 'num', num: true,
             html: function (r) { return r.alerts ? '<span class="lu-badge lan">' + r.alerts + '</span>' : ''; }},
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
                     return '<a class="lu-badge in lu-test" data-ip="' + esc(r.ip) + '" data-port="' + esc(p.port) +
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
                     return '<span class="lu-badge svc" title="' + esc(s.product) + '">' + esc(s.service) + ':' + esc(s.port) + '</span>';
                 }).join('');
             }},
            {key: 'blocked_out', label: 'Blocked out', cls: 'num', num: true,
             html: function (r) { return r.blocked_out ? '<span class="lu-badge lan" title="estimated blocked packets sent by this host">' + fmtNum(r.blocked_out) + '</span>' : ''; }},
            {key: 'blocked_in', label: 'Blocked in', cls: 'num', num: true,
             html: function (r) { return r.blocked_in ? '<span title="estimated blocked packets towards this host">' + fmtNum(r.blocked_in) + '</span>' : ''; }},
            {key: 'lateral', label: 'LAN→LAN', cls: 'num', num: true,
             html: function (r) { return r.lateral ? '<span class="lu-badge lan" title="connection attempts to other LAN hosts">' + fmtNum(r.lateral) + '</span>' : ''; }},
            {key: 'last_seen', label: 'Last seen', num: true, cls: 'nowrap', html: function (r) { return ago(r.last_seen); }}
        ], 'conns_in', function (r) { return r.alerts ? 'lu-row-warn' : ''; }),

        alerts: makeTable('lu-alerts', [
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
            {key: '', label: '', nosort: true, html: function (r) {
                return r.acked ? '<span class="text-muted">acknowledged</span>'
                    : '<button type="button" class="btn btn-default btn-xs lu-ack" data-id="' + esc(r.id) +
                      '" title="Acknowledge"><i class="fa fa-check"></i></button>';
            }}
        ], 'last_seen', function (r) { return r.acked ? 'lu-acked' : ''; }),

        lateral: makeTable('lu-lateral', [
            {key: 'src', label: 'Source', html: function (r) { return ipLink(r.src); },
             sortValue: function (r) { return ipKey(r.src); }},
            {key: 'dst', label: 'Destination', html: function (r) { return ipLink(r.dst); },
             sortValue: function (r) { return ipKey(r.dst); }},
            {key: 'port', label: 'Port', num: true, cls: 'nowrap',
             text: function (r) { return r.proto + '/' + r.port; },
             html: function (r) { return esc(r.proto === 'tcp' || r.proto === 'udp' ? r.proto + '/' + r.port : r.proto) +
                 (r.sensitive ? ' <span class="lu-badge lan" title="sensitive port">!</span>' : ''); }},
            {key: 'name', label: 'Service'},
            {key: 'status', label: 'Result', nosort: true,
             text: function (r) { return r.blocked ? 'blocked' : (r.answered ? 'connected' : 'no answer'); },
             html: function (r) {
                 if (r.blocked && !r.answered) return '<span class="lu-badge lan">blocked</span>';
                 if (!r.answered) return '<span class="lu-badge warn">no answer</span>';
                 return '<span class="lu-badge svc">connected</span>' + (r.blocked ? ' <span class="lu-badge lan">+blocked</span>' : '');
             }},
            {key: 'attempts', label: 'Attempts', cls: 'num', num: true, html: function (r) { return fmtNum(r.attempts); }},
            {key: 'answered', label: 'Answered', cls: 'num', num: true, html: function (r) { return fmtNum(r.answered); }},
            {key: 'blocked', label: 'Blocked', cls: 'num', num: true, html: function (r) { return fmtNum(r.blocked); }},
            {key: 'bytes', label: 'Traffic', cls: 'num', num: true, html: function (r) { return fmtBytes(r.bytes); }},
            {key: 'first_seen', label: 'First seen', num: true, cls: 'nowrap', html: function (r) { return esc(fmtDate(r.first_seen)); }},
            {key: 'last_seen', label: 'Last seen', num: true, cls: 'nowrap', html: function (r) { return ago(r.last_seen); }}
        ], 'last_seen', function (r) {
            return r.attempts > 0 && !r.answered ? 'lu-row-bad' : (r.sensitive ? 'lu-row-warn' : '');
        }),

        l2: makeTable('lu-l2', [
            {key: 'mac', label: 'MAC', cls: 'nowrap', html: function (r) { return '<span style="font-family:monospace">' + esc(r.mac) + '</span>'; }},
            {key: 'ip', label: 'IP', html: function (r) { return ipLink(r.ip); }, sortValue: function (r) { return ipKey(r.ip); }},
            {key: 'iface', label: 'Interface'},
            {key: 'warn', label: 'Warning', num: true,
             sortValue: function (r) { return (r.ip_macs.length > 1 ? 2 : 0) + (r.mac_ips.length > 1 ? 1 : 0); },
             text: function (r) { return (r.mac_ips.length > 1 ? 'multiple ips ' : '') + (r.ip_macs.length > 1 ? 'mac changed' : ''); },
             html: function (r) {
                 let out = '';
                 if (r.mac_ips.length > 1) {
                     out += '<span class="lu-badge warn" title="' + esc(r.mac_ips.join(', ')) + '">⚠ MAC used ' +
                            r.mac_ips.length + ' IPs: ' + esc(r.mac_ips.join(', ')) + '</span> ';
                 }
                 if (r.ip_macs.length > 1) {
                     out += '<span class="lu-badge lan" title="' + esc(r.ip_macs.join(', ')) + '">⚠ IP seen on ' +
                            r.ip_macs.length + ' MACs: ' + esc(r.ip_macs.join(', ')) + '</span>';
                 }
                 return out;
             }},
            {key: 'first_seen', label: 'First seen', num: true, cls: 'nowrap', html: function (r) { return esc(fmtDate(r.first_seen)); }},
            {key: 'last_seen', label: 'Last seen', num: true, cls: 'nowrap', html: function (r) { return ago(r.last_seen); }}
        ], 'warn', function (r) { return r.ip_macs.length > 1 ? 'lu-row-bad' : (r.mac_ips.length > 1 ? 'lu-row-warn' : ''); }),

        blockedHosts: makeTable('lu-blocked-hosts', [
            {key: 'ip', label: 'LAN host', html: function (r) { return ipLink(r.ip); }, sortValue: function (r) { return ipKey(r.ip); }},
            {key: 'out', label: 'Blocked outbound', cls: 'num', num: true,
             html: function (r) { return r.out ? '<b>' + fmtNum(r.out) + '</b>' : '0'; }},
            {key: 'targets', label: 'Targets', cls: 'num', num: true},
            {key: 'top_out', label: 'Outbound ports', nosort: true,
             text: function (r) { return r.top_out.map(function (p) { return p.proto + '/' + p.port + ' ' + p.name; }).join(' '); },
             html: function (r) { return r.top_out.map(function (p) {
                 return '<span class="lu-badge out">' + esc(p.proto + '/' + p.port) + (p.name ? ' ' + esc(p.name) : '') + '</span>';
             }).join(''); }},
            {key: 'in', label: 'Blocked inbound', cls: 'num', num: true, html: function (r) { return fmtNum(r.in); }},
            {key: 'sources', label: 'Sources', cls: 'num', num: true},
            {key: 'top_in', label: 'Attacked ports', nosort: true,
             text: function (r) { return r.top_in.map(function (p) { return p.proto + '/' + p.port + ' ' + p.name; }).join(' '); },
             html: function (r) { return r.top_in.map(function (p) {
                 return '<span class="lu-badge in">' + esc(p.proto + '/' + p.port) + (p.name ? ' ' + esc(p.name) : '') + '</span>';
             }).join(''); }}
        ], 'out', function (r) { return r.out > 0 ? 'lu-row-warn' : ''; }),

        blockedFlows: makeTable('lu-blocked-flows', [
            {key: 'ip', label: 'LAN host', html: function (r) { return ipLink(r.ip); }, sortValue: function (r) { return ipKey(r.ip); }},
            {key: 'dir', label: 'Dir', html: function (r) { return dirBadge(r.dir); }},
            {key: 'port', label: 'Port', num: true, cls: 'nowrap', text: function (r) { return r.proto + '/' + r.port; },
             html: function (r) { return esc(r.proto === 'tcp' || r.proto === 'udp' ? r.proto + '/' + r.port : r.proto); }},
            {key: 'name', label: 'Service'},
            {key: 'remote', label: 'Remote', cls: 'nowrap', sortValue: function (r) { return ipKey(r.remote); },
             html: function (r) { return r.internal ? ipLink(r.remote) + ' <span class="lu-badge lan">LAN↔LAN</span>' : esc(r.remote); }},
            {key: 'packets', label: 'Packets (est.)', cls: 'num', num: true, html: function (r) { return fmtNum(r.packets); }},
            {key: 'samples', label: 'Sampled', cls: 'num', num: true},
            {key: 'first_seen', label: 'First seen', num: true, cls: 'nowrap', html: function (r) { return esc(fmtDate(r.first_seen)); }},
            {key: 'last_seen', label: 'Last seen', num: true, cls: 'nowrap', html: function (r) { return ago(r.last_seen); }}
        ], 'packets', function (r) { return r.internal || r.dir === 'out' ? 'lu-row-warn' : ''; }),

        blockRules: makeTable('lu-block-rules', [
            {key: 'nr', label: 'Rule', num: true, html: function (r) { return '@' + esc(r.nr); }},
            {key: 'descr', label: 'Description', text: function (r) { return r.descr + ' ' + r.text; },
             html: function (r) { return r.descr ? '<b>' + esc(r.descr) + '</b>' : '<span class="text-muted">' + esc(r.text) + '</span>'; }},
            {key: 'pps', label: 'Now (pkt/s)', cls: 'num', num: true, html: function (r) { return r.pps ? '<b>' + fmtNum(r.pps) + '</b>' : '0'; }},
            {key: 'period', label: 'In period', cls: 'num', num: true, html: function (r) { return fmtNum(r.period); }},
            {key: 'packets', label: 'Since rule load', cls: 'num', num: true, html: function (r) { return fmtNum(r.packets); }}
        ], 'pps'),

        limitHosts: makeTable('lu-limit-hosts', [
            {key: 'ip', label: 'LAN host', html: function (r) { return ipLink(r.ip); }, sortValue: function (r) { return ipKey(r.ip); }},
            {key: 'states', label: 'pf states', cls: 'num', num: true, html: function (r) { return fmtNum(r.states); }},
            {key: 'pct', label: 'of host limit', num: true, cls: 'nowrap', html: function (r) { return pctBar(r.pct); }},
            {key: 'new_rate', label: 'New conn/s', cls: 'num', num: true, html: function (r) { return fmtNum(r.new_rate); }},
            {key: 'detail', label: 'Where the states go (top ports, inbound share)'}
        ], 'states', function (r) { return r.pct >= 100 ? 'lu-row-bad' : (r.pct >= 80 ? 'lu-row-warn' : ''); }),

        srcLimits: makeTable('lu-src-limits', [
            {key: 'ip', label: 'Source', sortValue: function (r) { return ipKey(r.ip); },
             html: function (r) { return r.lan ? ipLink(r.ip) + ' <span class="lu-badge">LAN</span>' : esc(r.ip); }},
            {key: 'kind', label: 'Limit'},
            {key: 'pct', label: 'Now', num: true, cls: 'nowrap',
             sortValue: function (r) { return r.pct === null ? -1 : r.pct; },
             html: function (r) {
                 return r.now ? pctBar(r.pct) + ' <span class="text-muted">' + esc(r.value) + ' / ' + esc(r.limit) + '</span>'
                     : '<span class="text-muted">below 90% now</span>';
             }},
            {key: 'peak', label: 'Peak', cls: 'num', num: true},
            {key: 'hits', label: 'Polls at limit', cls: 'num', num: true},
            {key: 'rule', label: 'Rule', num: true, text: function (r) { return '@' + r.rule + ' ' + r.descr; },
             html: function (r) { return '@' + esc(r.rule) + ' <b>' + esc(r.descr) + '</b>'; }},
            {key: 'last_seen', label: 'Last at limit', num: true, cls: 'nowrap',
             html: function (r) { return r.last_seen ? ago(r.last_seen) : '<span class="text-muted">-</span>'; }}
        ], 'pct', function (r) { return r.at_limit ? 'lu-row-bad' : (r.now ? 'lu-row-warn' : ''); }),

        counters: makeTable('lu-counters', [
            {key: 'name', label: 'pf counter', html: function (r) { return '<b>' + esc(r.name) + '</b>'; }},
            {key: 'increase', label: 'Increase in period', cls: 'num', num: true,
             html: function (r) { return r.increase ? '<b>+' + fmtNum(r.increase) + '</b>' : '0'; }},
            {key: 'total', label: 'Total since boot', cls: 'num', num: true, html: function (r) { return fmtNum(r.total); }},
            {key: 'meaning', label: 'Meaning'}
        ], 'increase', function (r) { return r.watched && r.increase > 0 ? 'lu-row-bad' : ''; }),

        rules: makeTable('lu-rules', [
            {key: 'nr', label: 'Rule', num: true, html: function (r) { return '@' + esc(r.nr); }},
            {key: 'states', label: 'States', cls: 'num', num: true, html: function (r) { return fmtNum(r.states); }},
            {key: 'usage', label: 'of max', num: true, cls: 'nowrap',
             html: function (r) { return r.usage === null ? '<span class="text-muted">no max</span>' : pctBar(r.usage); }},
            {key: 'options', label: 'Limits', nosort: true,
             text: function (r) { return Object.keys(r.options).map(function (k) { return k + ' ' + r.options[k]; }).join(' '); },
             html: function (r) {
                 return Object.keys(r.options).map(function (k) {
                     return '<span class="lu-badge">' + esc(k + ' ' + r.options[k]) + '</span>';
                 }).join('');
             }},
            {key: 'text', label: 'Rule', cls: 'banner', html: function (r) { return '<span title="' + esc(r.text) + '">' + esc(r.text) + '</span>'; }}
        ], 'usage', function (r) { return r.usage >= 100 ? 'lu-row-bad' : (r.usage >= 90 ? 'lu-row-warn' : ''); }),

        tablehits: makeTable('lu-tablehits', [
            {key: 'table', label: 'pf table'},
            {key: 'ip', label: 'LAN host', html: function (r) { return ipLink(r.ip); }, sortValue: function (r) { return ipKey(r.ip); }},
            {key: 'current', label: 'Listed now', html: function (r) {
                return r.current ? '<span class="lu-badge lan">yes</span>' : '<span class="text-muted">no (removed)</span>';
            }},
            {key: 'first_seen', label: 'First seen', num: true, cls: 'nowrap', html: function (r) { return esc(fmtDate(r.first_seen)); }},
            {key: 'last_seen', label: 'Last seen', num: true, cls: 'nowrap', html: function (r) { return ago(r.last_seen); }}
        ], 'last_seen', function (r) { return r.current ? 'lu-row-bad' : ''; }),

        ports: makeTable('lu-ports', [
            {key: 'dir', label: 'Direction', html: function (r) { return dirBadge(r.dir); }},
            {key: 'proto', label: 'Proto'},
            {key: 'port', label: 'Port', cls: 'num', num: true},
            {key: 'name', label: 'Service'},
            {key: 'hosts', label: 'LAN hosts', cls: 'num', num: true},
            {key: 'conns', label: 'Connections', cls: 'num', num: true, html: function (r) { return fmtNum(r.conns); }},
            {key: 'bytes', label: 'Traffic', cls: 'num', num: true, html: function (r) { return fmtBytes(r.bytes); }}
        ], 'conns'),

        flows: makeTable('lu-flows', [
            {key: 'ip', label: 'LAN host', html: function (r) { return ipLink(r.ip); },
             sortValue: function (r) { return ipKey(r.ip); }},
            {key: 'dir', label: 'Dir', html: function (r) { return dirBadge(r.dir); }},
            {key: 'port', label: 'Port', num: true, cls: 'nowrap',
             text: function (r) { return r.proto + '/' + r.port; },
             html: function (r) { return esc(r.proto + '/' + r.port); }},
            {key: 'name', label: 'Service'},
            {key: 'remote', label: 'Remote', cls: 'nowrap', sortValue: function (r) { return ipKey(r.remote); },
             text: function (r) { return r.remote + (r.internal ? ' lan' : ''); },
             html: function (r) { return r.internal ? ipLink(r.remote) + ' <span class="lu-badge lan" title="the remote side is also a LAN host">LAN↔LAN</span>' : esc(r.remote); }},
            {key: 'conns', label: 'Conns', cls: 'num', num: true, html: function (r) { return fmtNum(r.conns); }},
            {key: 'bytes', label: 'Traffic', cls: 'num', num: true, html: function (r) { return fmtBytes(r.bytes); }},
            {key: 'first_seen', label: 'First seen', num: true, cls: 'nowrap', html: function (r) { return esc(fmtDate(r.first_seen)); }},
            {key: 'last_seen', label: 'Last seen', num: true, cls: 'nowrap', html: function (r) { return ago(r.last_seen); }},
            {key: '', label: '', nosort: true, html: function (r) { return r.dir === 'in' ? testButton(r.ip, r.port, r.proto) : ''; }}
        ], 'last_seen', function (r) { return r.internal ? 'lu-row-warn' : ''; }),

        services: makeTable('lu-services', [
            {key: 'ip', label: 'LAN host', html: function (r) { return ipLink(r.ip); },
             sortValue: function (r) { return ipKey(r.ip); }},
            {key: 'port', label: 'Port', num: true, cls: 'nowrap',
             text: function (r) { return r.proto + '/' + r.port; },
             html: function (r) { return esc(r.proto + '/' + r.port); }},
            {key: 'state', label: 'State',
             html: function (r) { return '<span class="lu-state-' + esc(String(r.state).replace(/[^a-z]/g, '')) + '">' + esc(r.state) + '</span>'; }},
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
             t.pf_states_limit && t.pf_states * 100 / t.pf_states_limit >= 80],
            ['Active hosts', fmtNum(t.active_hosts), fmtNum(t.active_conns) + ' open connections'],
            ['Hosts seen', fmtNum(t.hosts), 'in selected period'],
            ['Inbound connections', fmtNum(t.conns_in), fmtBytes(t.bytes_in) + ' transferred'],
            ['Outbound connections', fmtNum(t.conns_out), fmtBytes(t.bytes_out) + ' transferred'],
            ['Distinct ports', fmtNum(t.ports), 'inbound + outbound'],
            ['Detected services', fmtNum(t.services), 'open ports tested']
        ];
        $('#lu-kpis').html(kpis.map(function (k) {
            return '<div class="lu-kpi' + (k[3] ? ' alert-on' : '') + '"><div class="l">' + esc(k[0]) +
                   '</div><div class="v">' + esc(k[1]) + '</div><div class="s">' + esc(k[2]) + '</div></div>';
        }).join(''));
        $('#lu-alert-badge').text(t.alerts_open || '').toggle(t.alerts_open > 0);
    }

    function renderAlertStrip(alerts) {
        const $strip = $('#lu-alert-strip');
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
        $('#lu-metric-label').text(bytes ? 'traffic' : 'connections');
        LUCharts.timeline(document.getElementById('lu-timeline'), d.timeline.map(function (p) {
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
        LUCharts.hbar(document.getElementById('lu-top-in'), barItems(d.top_in, COLOR_IN, portLabel, portName),
                      {format: fmtMetric, tip: barTip, onClick: openFlows('in')});
        LUCharts.hbar(document.getElementById('lu-top-out'), barItems(d.top_out, COLOR_OUT, portLabel, portName),
                      {format: fmtMetric, tip: barTip, onClick: openFlows('out')});
        $('#lu-top-hosts-title').text(d.peers_of_host ? 'Top remote peers of ' + d.ip : 'Top LAN hosts');
        LUCharts.hbar(document.getElementById('lu-top-hosts'), barItems(d.top_hosts, LUCharts.palette[2],
                      function (r) { return r.ip; }),
                      {format: fmtMetric, tip: barTip,
                       onClick: d.peers_of_host ? null : function (item) { setIp(item.row.ip); }});
        LUCharts.donut(document.getElementById('lu-mix'), d.service_mix.map(function (s) {
            return {label: s.service || 'unknown', value: s.count};
        }), {centerLabel: 'services', emptyText: 'No services tested yet'});
    }

    function loadSummary() {
        return api('summary').done(function (data) {
            if (!ok(data)) return;
            S.summary = data;
            renderKpis(data.totals);
            renderAlertStrip(data.recent_alerts);
            $('#lu-nodata').toggle(!data.totals.hosts && !data.ip);
            renderOverview();
        });
    }

    const loaders = {
        overview: function () {},
        hosts: function () {
            api('hosts').done(function (d) { if (ok(d)) tables.hosts.setRows(d.rows); });
        },
        ports: function () {
            api('ports', {dir: $('#lu-ports-dir').val()}).done(function (d) { if (ok(d)) tables.ports.setRows(d.rows); });
        },
        flows: function () {
            api('flows', {dir: $('#lu-flows-dir').val()}).done(function (d) { if (ok(d)) tables.flows.setRows(d.rows); });
        },
        services: function () {
            api('services').done(function (d) { if (ok(d)) tables.services.setRows(d.rows); });
        },
        alerts: function () {
            api('alerts', {which: $('#lu-alerts-which').val()}).done(function (d) { if (ok(d)) tables.alerts.setRows(d.rows); });
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
            api('blocked', {dir: $('#lu-blocked-dir').val()}).done(function (d) {
                if (!ok(d)) return;
                renderBlocked(d);
            });
        }
    };

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
            ['Sampling', devs.length ? devs.join(', ') : 'off',
             devs.length ? sampling.seconds + ' s / ' + fmtNum(sampling.max_packets) + ' packets per poll' +
                 (capped.length ? ', cap reached on ' + capped.join(', ') : '') : 'enable it in the settings']
        ];
        $('#lu-blocked-kpis').html(kpis.map(function (k) {
            return '<div class="lu-kpi' + (k[3] ? ' alert-on' : '') + '"><div class="l">' + esc(k[0]) +
                   '</div><div class="v">' + esc(k[1]) + '</div><div class="s">' + esc(k[2]) + '</div></div>';
        }).join(''));
        LUCharts.timeline(document.getElementById('lu-blocked-chart'), d.timeline.map(function (p) {
            return {t: p.t, values: [p.in_pps, p.out_pps]};
        }), {series: [{label: 'blocked towards LAN hosts (pkt/s)', color: COLOR_IN},
                      {label: 'blocked from LAN hosts (pkt/s)', color: COLOR_OUT}],
             format: fmtNum, timeFormat: fmtTime, height: 220});
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
            ['Hosts over limit', fmtNum(d.hosts.filter(function (h) { return h.pct >= 100; }).length),
             '≥ ' + fmtNum(d.thresholds.host_states) + ' states per host'],
            ['LAN hosts in block tables', fmtNum(listed), d.tables.map(function (t) { return t.name; }).join(', ') || 'no watched table', listed > 0]
        ];
        $('#lu-limit-kpis').html(kpis.map(function (k) {
            return '<div class="lu-kpi' + (k[3] ? ' alert-on' : '') + '"><div class="l">' + esc(k[0]) +
                   '</div><div class="v">' + esc(k[1]) + '</div><div class="s">' + esc(k[2]) + '</div></div>';
        }).join(''));
        $('#lu-limit-stale').toggle(!d.status_time || Date.now() / 1000 - d.status_time > 600);
        LUCharts.timeline(document.getElementById('lu-pf-states'), d.timeline.map(function (p) {
            return {t: p.t, values: [p.states, p.src_nodes]};
        }), {series: [{label: 'pf states', color: COLOR_IN}, {label: 'source nodes', color: LUCharts.palette[3]}],
             format: fmtNum, timeFormat: fmtTime, height: 200});
        LUCharts.timeline(document.getElementById('lu-pf-hits'), d.timeline.map(function (p) {
            return {t: p.t, values: [p.limit_hits]};
        }), {series: [{label: 'limit counter increases', color: '#d9534f'}], format: fmtNum, timeFormat: fmtTime, height: 200});
        tables.limitHosts.setRows(d.hosts);
        tables.srcLimits.setRows(d.src_limits || []);
        tables.counters.setRows(d.counters);
        tables.rules.setRows(d.rules);
        tables.tablehits.setRows(d.tablehits);
    }

    function ack(id) {
        const data = {id: String(id)};
        if (id === 'all' && S.ip) data.ip = S.ip;
        ajaxCall(API + 'ack', data, function (res) {
            if (ok(res)) {
                loaders.alerts();
                loadSummary();
            }
        });
    }
    $(document).on('click', '.lu-ack', function (e) {
        e.preventDefault();
        $(this).prop('disabled', true);
        ack($(this).data('id'));
    });
    $('#lu-ack-all').on('click', function () { ack('all'); });
    $('#lu-alerts-which').on('change', function () { loaders.alerts(); });
    $('#lu-strip-all').on('click', function (e) {
        e.preventDefault();
        showTab('alerts');
    });

    function refresh() {
        loadSummary();
        loaders[S.tab]();
    }

    function showTab(tab, dir, filter) {
        if (dir !== undefined) $('#lu-' + tab + '-dir').val(dir);
        if (filter !== undefined && tables[tab]) tables[tab].setFilter(filter);
        if (S.tab === tab) {
            loaders[tab]();
        } else {
            $('#lu-tabs a[href="#lu-tab-' + tab + '"]').tab('show');
        }
    }

    function setIp(ip) {
        S.ip = ip || '';
        $('#lu-ip').val(S.ip);
        $('#lu-ip-clear').toggle(!!S.ip);
        $('#lu-filter-note').text(S.ip ? 'Showing only ' + S.ip : '');
        if (S.ip && S.tab !== 'overview') {
            $('#lu-tabs a[href="#lu-tab-overview"]').tab('show');
        }
        refresh();
    }

    /* service test */
    function showProbeResult(data) {
        const $box = $('#lu-probe-result');
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

    function runProbe(ip, port, proto, $btn) {
        const $icon = $btn.find('i');
        const iconClass = $icon.attr('class');
        $btn.prop('disabled', true).addClass('disabled');
        $icon.attr('class', 'fa fa-spinner fa-pulse');
        $('#lu-probe-result').attr('class', 'alert alert-info').text('Testing ' + proto + '://' + ip + ':' + port + ' ...').show();
        if (S.tab !== 'services') showTab('services');
        ajaxCall(API + 'probe', {ip: ip, port: port, proto: proto}, function (data) {
            $btn.prop('disabled', false).removeClass('disabled');
            $icon.attr('class', iconClass);
            showProbeResult(data);
            loaders.services();
            loadSummary();
        });
    }

    $(document).on('click', '.lu-test', function (e) {
        e.preventDefault();
        const $b = $(this);
        runProbe(String($b.data('ip')), String($b.data('port')), String($b.data('proto')), $b);
    });
    $('#lu-probe-go').on('click', function () {
        const ip = $('#lu-probe-ip').val().trim(), port = $('#lu-probe-port').val().trim();
        if (!ip || !/^\d+$/.test(port)) {
            showProbeResult({status: 'error', message: 'Enter a LAN address and a port number.'});
            return;
        }
        runProbe(ip, port, $('#lu-probe-proto').val(), $(this));
    });

    /* toolbar */
    $(document).on('click', '.lu-ip', function (e) {
        e.preventDefault();
        setIp($(this).data('ip'));
    });
    $('#lu-range button').on('click', function () {
        S.hours = parseInt($(this).data('hours'), 10);
        pref('hours', S.hours);
        $('#lu-range button').removeClass('active btn-primary').addClass('btn-default');
        $(this).addClass('active btn-primary').removeClass('btn-default');
        refresh();
    });
    $('#lu-metric button').on('click', function () {
        S.metric = $(this).data('metric');
        pref('metric', S.metric);
        $('#lu-metric button').removeClass('active btn-primary').addClass('btn-default');
        $(this).addClass('active btn-primary').removeClass('btn-default');
        renderOverview();
    });
    $('#lu-ip').on('keydown', function (e) {
        if (e.key === 'Enter') setIp($(this).val().trim());
    });
    $('#lu-ip-go').on('click', function () { setIp($('#lu-ip').val().trim()); });
    $('#lu-ip-clear').on('click', function () { setIp(''); });
    $('#lu-refresh').on('click', refresh);
    $('#lu-auto').on('change', function () {
        pref('auto', this.checked ? '1' : '0');
        clearInterval(S.timer);
        if (this.checked) S.timer = setInterval(refresh, 60000);
    });
    $('#lu-ports-dir, #lu-flows-dir, #lu-blocked-dir').on('change', function () { loaders[S.tab](); });
    $('#lu-tabs a[data-toggle="tab"]').on('shown.bs.tab', function (e) {
        S.tab = $(e.target).attr('href').replace('#lu-tab-', '');
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
    $('#lu-range button[data-hours="' + S.hours + '"]').addClass('active btn-primary').removeClass('btn-default');
    $('#lu-metric button[data-metric="' + S.metric + '"]').addClass('active btn-primary').removeClass('btn-default');
    $('#lu-auto').prop('checked', pref('auto') !== '0').trigger('change');
    if (typeof updateServiceControlUI === 'function') updateServiceControlUI('lanusage');
    const startTab = window.location.hash.replace('#', '');
    if (startTab && loaders[startTab] && startTab !== 'overview') {
        $('#lu-tabs a[href="#lu-tab-' + startTab + '"]').tab('show');
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
    <div class="lu-toolbar">
        <div class="btn-group btn-group-sm" id="lu-range" role="group">
            <button type="button" class="btn btn-default" data-hours="1">1h</button>
            <button type="button" class="btn btn-default" data-hours="6">6h</button>
            <button type="button" class="btn btn-default" data-hours="24">24h</button>
            <button type="button" class="btn btn-default" data-hours="168">7d</button>
            <button type="button" class="btn btn-default" data-hours="720">30d</button>
        </div>
        <div class="btn-group btn-group-sm" id="lu-metric" role="group">
            <button type="button" class="btn btn-default" data-metric="conns">{{ lang._('Connections') }}</button>
            <button type="button" class="btn btn-default" data-metric="bytes">{{ lang._('Traffic') }}</button>
        </div>
        <div class="lu-ipbox">
            <input type="text" class="form-control" id="lu-ip" placeholder="{{ lang._('Filter by LAN host IP') }}"/>
            <button type="button" class="btn btn-default btn-sm" id="lu-ip-go" title="{{ lang._('Apply filter') }}"><i class="fa fa-filter"></i></button>
            <button type="button" class="btn btn-default btn-sm" id="lu-ip-clear" style="display:none" title="{{ lang._('Clear filter') }}"><i class="fa fa-times"></i></button>
            <span id="lu-filter-note" class="text-muted"></span>
        </div>
        <span class="lu-sep"></span>
        <label class="text-muted" style="margin:0;font-weight:normal">
            <input type="checkbox" id="lu-auto"/> {{ lang._('Auto refresh (60s)') }}
        </label>
        <button type="button" class="btn btn-default btn-sm" id="lu-refresh"><i class="fa fa-refresh"></i> {{ lang._('Refresh') }}</button>
    </div>
    <div class="alert alert-danger" id="lu-error" style="display:none;margin:10px 14px 0"></div>
    <div class="alert alert-info" id="lu-nodata" style="display:none;margin:10px 14px 0">
        {{ lang._('No data recorded yet. Enable the collector and select your LAN interfaces / customer networks under Reporting: LAN Usage: Settings.') }}
    </div>
    <div class="lu-kpis" id="lu-kpis"></div>
</div>

<ul class="nav nav-tabs" data-tabs="tabs" id="lu-tabs">
    <li class="active"><a data-toggle="tab" href="#lu-tab-overview">{{ lang._('Overview') }}</a></li>
    <li><a data-toggle="tab" href="#lu-tab-alerts">{{ lang._('Alerts') }} <span class="badge" id="lu-alert-badge" style="display:none"></span></a></li>
    <li><a data-toggle="tab" href="#lu-tab-hosts">{{ lang._('Hosts') }}</a></li>
    <li><a data-toggle="tab" href="#lu-tab-lateral">{{ lang._('LAN ↔ LAN') }}</a></li>
    <li><a data-toggle="tab" href="#lu-tab-l2">{{ lang._('MAC / IP') }}</a></li>
    <li><a data-toggle="tab" href="#lu-tab-blocked">{{ lang._('Blocked') }}</a></li>
    <li><a data-toggle="tab" href="#lu-tab-limits">{{ lang._('States / Limits') }}</a></li>
    <li><a data-toggle="tab" href="#lu-tab-ports">{{ lang._('Ports') }}</a></li>
    <li><a data-toggle="tab" href="#lu-tab-flows">{{ lang._('Connections') }}</a></li>
    <li><a data-toggle="tab" href="#lu-tab-services">{{ lang._('Services') }}</a></li>
</ul>

<div class="tab-content content-box">
    <div id="lu-tab-overview" class="tab-pane fade in active">
        <div id="lu-alert-strip">
            <h4><i class="fa fa-exclamation-triangle"></i> {{ lang._('Open alerts') }}
                <a href="#" id="lu-strip-all" style="font-weight:normal;margin-left:8px">{{ lang._('show all') }}</a></h4>
            <div class="list"></div>
        </div>
        <div class="lu-grid">
            <div class="lu-panel wide">
                <h4>{{ lang._('Activity over time') }} (<span id="lu-metric-label">connections</span>)</h4>
                <div class="lu-chart" id="lu-timeline"></div>
            </div>
            <div class="lu-panel">
                <h4>{{ lang._('Top ports served by LAN hosts (inbound)') }}</h4>
                <div class="lu-chart" id="lu-top-in"></div>
            </div>
            <div class="lu-panel">
                <h4>{{ lang._('Top ports used by LAN hosts (outbound)') }}</h4>
                <div class="lu-chart" id="lu-top-out"></div>
            </div>
            <div class="lu-panel">
                <h4 id="lu-top-hosts-title">{{ lang._('Top LAN hosts') }}</h4>
                <div class="lu-chart" id="lu-top-hosts"></div>
            </div>
            <div class="lu-panel">
                <h4>{{ lang._('Detected services') }}</h4>
                <div class="lu-chart" id="lu-mix"></div>
            </div>
        </div>
    </div>

    <div id="lu-tab-alerts" class="tab-pane fade">
        <div class="lu-pane" id="lu-alerts">
            <div class="lu-table-tools">
                <select class="form-control" id="lu-alerts-which">
                    <option value="all">{{ lang._('Open + acknowledged') }}</option>
                    <option value="open">{{ lang._('Open only') }}</option>
                </select>
                <input type="text" class="form-control lu-search" placeholder="{{ lang._('Search...') }}"/>
                <button type="button" class="btn btn-default btn-sm" id="lu-ack-all"><i class="fa fa-check"></i> {{ lang._('Acknowledge all') }}</button>
                <span class="lu-count"></span>
            </div>
            <div class="lu-table-wrap">
                <table class="table table-condensed table-hover lu-table"><thead><tr></tr></thead><tbody></tbody></table>
            </div>
        </div>
    </div>

    <div id="lu-tab-lateral" class="tab-pane fade">
        <div class="lu-pane" id="lu-lateral">
            <div class="lu-note">
                {{ lang._('Connections from one LAN host to another. Only traffic that passes the firewall is visible (between different interfaces/subnets, or through a filtering bridge); blocked attempts are estimated from sampling. Red rows: blocked or unanswered attempts. Yellow rows: sensitive port (SSH, RDP, SMB, databases...).') }}
            </div>
            <div class="lu-table-tools">
                <input type="text" class="form-control lu-search" placeholder="{{ lang._('Search, e.g. tcp/22 or an address') }}"/>
                <span class="lu-count"></span>
            </div>
            <div class="lu-table-wrap">
                <table class="table table-condensed table-hover lu-table"><thead><tr></tr></thead><tbody></tbody></table>
            </div>
        </div>
    </div>

    <div id="lu-tab-l2" class="tab-pane fade">
        <div class="lu-pane" id="lu-l2">
            <div class="lu-note">
                {{ lang._('MAC / IP bindings from the firewall ARP and NDP tables in the selected period. Yellow: one MAC used several IPv4 addresses (multiple IPs or IP changed). Red: one IP appeared on several MACs (IP taken over, spoofing or conflict).') }}
            </div>
            <div class="lu-table-tools">
                <input type="text" class="form-control lu-search" placeholder="{{ lang._('Search MAC or IP...') }}"/>
                <span class="lu-count"></span>
            </div>
            <div class="lu-table-wrap">
                <table class="table table-condensed table-hover lu-table"><thead><tr></tr></thead><tbody></tbody></table>
            </div>
        </div>
    </div>

    <div id="lu-tab-blocked" class="tab-pane fade">
        <div class="lu-note" style="padding:14px 14px 0">
            {{ lang._('Blocked traffic without firewall logging. Per host numbers are estimated: every poll connection attempts (TCP SYN, UDP, ICMP echo) are sampled for a few seconds and checked against the state table; attempts without a state were blocked. The block rule table is exact (pf rule counters).') }}
        </div>
        <div class="lu-kpis" id="lu-blocked-kpis" style="padding-top:10px"></div>
        <div class="lu-grid" style="padding-top:0">
            <div class="lu-panel wide">
                <h4>{{ lang._('Blocked packets per second (estimated)') }}</h4>
                <div class="lu-chart" id="lu-blocked-chart"></div>
            </div>
        </div>
        <div class="lu-pane" id="lu-blocked-hosts">
            <h4 style="font-size:13px;font-weight:600">{{ lang._('LAN hosts: blocked traffic they send (abuse?) and receive (attacked?)') }}</h4>
            <div class="lu-table-tools">
                <input type="text" class="form-control lu-search" placeholder="{{ lang._('Search...') }}"/>
                <span class="lu-count"></span>
            </div>
            <div class="lu-table-wrap" style="max-height:360px">
                <table class="table table-condensed table-hover lu-table"><thead><tr></tr></thead><tbody></tbody></table>
            </div>
        </div>
        <div class="lu-pane" id="lu-block-rules">
            <h4 style="font-size:13px;font-weight:600">{{ lang._('Block rules (exact packet counters)') }}</h4>
            <div class="lu-table-tools">
                <input type="text" class="form-control lu-search" placeholder="{{ lang._('Search...') }}"/>
                <span class="lu-count"></span>
            </div>
            <div class="lu-table-wrap" style="max-height:300px">
                <table class="table table-condensed table-hover lu-table"><thead><tr></tr></thead><tbody></tbody></table>
            </div>
        </div>
        <div class="lu-pane" id="lu-blocked-flows">
            <h4 style="font-size:13px;font-weight:600">{{ lang._('Blocked attempts') }}</h4>
            <div class="lu-table-tools">
                <select class="form-control" id="lu-blocked-dir">
                    <option value="">{{ lang._('Both directions') }}</option>
                    <option value="out">{{ lang._('Sent by LAN hosts') }}</option>
                    <option value="in">{{ lang._('Towards LAN hosts') }}</option>
                </select>
                <input type="text" class="form-control lu-search" placeholder="{{ lang._('Search, e.g. tcp/25 or an address') }}"/>
                <span class="lu-count"></span>
            </div>
            <div class="lu-table-wrap">
                <table class="table table-condensed table-hover lu-table"><thead><tr></tr></thead><tbody></tbody></table>
            </div>
        </div>
    </div>

    <div id="lu-tab-limits" class="tab-pane fade">
        <div class="alert alert-warning" id="lu-limit-stale" style="display:none;margin:14px 14px 0">
            {{ lang._('No recent status from the collector. Is the service running?') }}
        </div>
        <div class="lu-kpis" id="lu-limit-kpis" style="padding-top:14px"></div>
        <div class="lu-grid" style="padding-top:0">
            <div class="lu-panel">
                <h4>{{ lang._('pf state table') }}</h4>
                <div class="lu-chart" id="lu-pf-states"></div>
            </div>
            <div class="lu-panel">
                <h4>{{ lang._('Limit hits (memory, state-limit, src-limit, max-src-conn, overload, synflood ...)') }}</h4>
                <div class="lu-chart" id="lu-pf-hits"></div>
            </div>
        </div>
        <div class="lu-pane" id="lu-limit-hosts">
            <h4 style="font-size:13px;font-weight:600">{{ lang._('LAN hosts by firewall states (now)') }}</h4>
            <div class="lu-table-tools">
                <input type="text" class="form-control lu-search" placeholder="{{ lang._('Search...') }}"/>
                <span class="lu-count"></span>
            </div>
            <div class="lu-table-wrap" style="max-height:360px">
                <table class="table table-condensed table-hover lu-table"><thead><tr></tr></thead><tbody></tbody></table>
            </div>
        </div>
        <div class="lu-pane" id="lu-src-limits">
            <h4 style="font-size:13px;font-weight:600">{{ lang._('Sources at a per source rule limit (max-src-states, max-src-conn, max-src-conn-rate)') }}</h4>
            <div class="lu-note">{{ lang._('From the pf source tracking table: which address reached which limit on which rule. New connections of a source at its limit are dropped.') }}</div>
            <div class="lu-table-tools">
                <input type="text" class="form-control lu-search" placeholder="{{ lang._('Search...') }}"/>
                <span class="lu-count"></span>
            </div>
            <div class="lu-table-wrap" style="max-height:360px">
                <table class="table table-condensed table-hover lu-table"><thead><tr></tr></thead><tbody></tbody></table>
            </div>
        </div>
        <div class="lu-pane" id="lu-tablehits">
            <h4 style="font-size:13px;font-weight:600">{{ lang._('LAN hosts in watched pf tables (virusprot, sshlockout, crowdsec ...)') }}</h4>
            <div class="lu-table-tools">
                <input type="text" class="form-control lu-search" placeholder="{{ lang._('Search...') }}"/>
                <span class="lu-count"></span>
            </div>
            <div class="lu-table-wrap" style="max-height:300px">
                <table class="table table-condensed table-hover lu-table"><thead><tr></tr></thead><tbody></tbody></table>
            </div>
        </div>
        <div class="lu-pane" id="lu-counters">
            <h4 style="font-size:13px;font-weight:600">{{ lang._('pf counters') }}</h4>
            <div class="lu-table-tools">
                <input type="text" class="form-control lu-search" placeholder="{{ lang._('Search...') }}"/>
                <span class="lu-count"></span>
            </div>
            <div class="lu-table-wrap" style="max-height:360px">
                <table class="table table-condensed table-hover lu-table"><thead><tr></tr></thead><tbody></tbody></table>
            </div>
        </div>
        <div class="lu-pane" id="lu-rules">
            <h4 style="font-size:13px;font-weight:600">{{ lang._('Rules with connection limits') }}</h4>
            <div class="lu-table-tools">
                <input type="text" class="form-control lu-search" placeholder="{{ lang._('Search...') }}"/>
                <span class="lu-count"></span>
            </div>
            <div class="lu-table-wrap" style="max-height:360px">
                <table class="table table-condensed table-hover lu-table"><thead><tr></tr></thead><tbody></tbody></table>
            </div>
        </div>
    </div>

    <div id="lu-tab-hosts" class="tab-pane fade">
        <div class="lu-pane" id="lu-hosts">
            <div class="lu-table-tools">
                <input type="text" class="form-control lu-search" placeholder="{{ lang._('Search...') }}"/>
                <span class="lu-count"></span>
            </div>
            <div class="lu-table-wrap">
                <table class="table table-striped table-condensed table-hover lu-table"><thead><tr></tr></thead><tbody></tbody></table>
            </div>
        </div>
    </div>

    <div id="lu-tab-ports" class="tab-pane fade">
        <div class="lu-pane" id="lu-ports">
            <div class="lu-table-tools">
                <select class="form-control" id="lu-ports-dir">
                    <option value="">{{ lang._('Both directions') }}</option>
                    <option value="in">{{ lang._('Inbound (served)') }}</option>
                    <option value="out">{{ lang._('Outbound (used)') }}</option>
                </select>
                <input type="text" class="form-control lu-search" placeholder="{{ lang._('Search...') }}"/>
                <span class="lu-count"></span>
            </div>
            <div class="lu-table-wrap">
                <table class="table table-striped table-condensed table-hover lu-table"><thead><tr></tr></thead><tbody></tbody></table>
            </div>
        </div>
    </div>

    <div id="lu-tab-flows" class="tab-pane fade">
        <div class="lu-pane" id="lu-flows">
            <div class="lu-table-tools">
                <select class="form-control" id="lu-flows-dir">
                    <option value="">{{ lang._('Both directions') }}</option>
                    <option value="in">{{ lang._('Inbound (served)') }}</option>
                    <option value="out">{{ lang._('Outbound (used)') }}</option>
                </select>
                <input type="text" class="form-control lu-search" placeholder="{{ lang._('Search, e.g. tcp/443 or an address') }}"/>
                <span class="lu-count"></span>
            </div>
            <div class="lu-table-wrap">
                <table class="table table-striped table-condensed table-hover lu-table"><thead><tr></tr></thead><tbody></tbody></table>
            </div>
        </div>
    </div>

    <div id="lu-tab-services" class="tab-pane fade">
        <div class="lu-pane" id="lu-services">
            <div class="lu-probe-form">
                <strong>{{ lang._('Test a service') }}:</strong>
                <input type="text" class="form-control" id="lu-probe-ip" placeholder="{{ lang._('LAN address') }}" style="width:180px"/>
                <input type="text" class="form-control" id="lu-probe-port" placeholder="{{ lang._('Port') }}" style="width:80px"/>
                <select class="form-control" id="lu-probe-proto">
                    <option value="tcp">tcp</option>
                    <option value="udp">udp</option>
                </select>
                <button type="button" class="btn btn-primary btn-sm" id="lu-probe-go"><i class="fa fa-stethoscope"></i> {{ lang._('Test') }}</button>
            </div>
            <div id="lu-probe-result" style="display:none"></div>
            <div class="lu-table-tools">
                <input type="text" class="form-control lu-search" placeholder="{{ lang._('Search...') }}"/>
                <span class="lu-count"></span>
            </div>
            <div class="lu-table-wrap">
                <table class="table table-striped table-condensed table-hover lu-table"><thead><tr></tr></thead><tbody></tbody></table>
            </div>
        </div>
    </div>
</div>
