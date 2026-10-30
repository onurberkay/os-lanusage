{#
 # Copyright (C) 2026 Onur Berkay <onurberkay@sakla.app>
 # All rights reserved. (BSD 2-Clause, see LICENSE)
 #
 # HostGuard settings
 #}

<script>
$(function () {
    'use strict';
    mapDataToFormUI({'frm_general': '/api/hostguard/settings/get'}).done(function () {
        formatTokenizersUI();
        $('.selectpicker').selectpicker('refresh');
    });
    updateServiceControlUI('hostguard');

    $('#saveAct').on('click', function () {
        saveFormToEndpoint('/api/hostguard/settings/set', 'frm_general', function () {
            $('#saveAct_progress').addClass('fa fa-spinner fa-pulse');
            ajaxCall('/api/hostguard/service/reconfigure', {}, function () {
                $('#saveAct_progress').removeClass('fa fa-spinner fa-pulse');
                updateServiceControlUI('hostguard');
            });
        });
    });

    function esc(v) {
        return String(v === null || v === undefined ? '' : v).replace(/[&<>"']/g, function (c) {
            return '&#' + c.charCodeAt(0) + ';';
        });
    }

    /* what the collector currently sees: helps verifying bridge / interface / network setup */
    function loadStatus() {
        const $box = $('#statusBody');
        // POST without a query string: the Settings privilege grants exactly api/hostguard/stats/status
        ajaxCall('/api/hostguard/stats/status', {}, function (s, status) {
            if (status !== 'success') {
                $box.html('<p class="text-danger">' + esc("{{ lang._('Status could not be loaded') }}" +
                          (s && s.message ? ': ' + s.message : '')) + '</p>');
                return;
            }
            if (s && s.status && s.status !== 'ok') {
                $box.html('<p class="text-danger">' + esc(s.message || 'error') + '</p>');
                return;
            }
            if (!s || !s.time) {
                $box.html('<p class="text-muted">' + esc("{{ lang._('No status yet: the collector has not completed a poll (is it enabled and running?).') }}") + '</p>');
                return;
            }
            const age = Math.round(s.now - s.time);
            const bridges = Object.keys(s.bridges || {}).map(function (b) {
                return b + ' (' + (s.bridges[b].join(', ') || 'no members') + ')';
            }).join('; ');
            const sniff = Object.keys(s.sniffer || {}).map(function (d) {
                return d + ': ' + s.sniffer[d].state + ', ' + s.sniffer[d].lines + ' packets';
            }).join('; ');
            const pf = s.pf || {};
            const rows = [
                ['Last poll', age + ' s ago, took ' + s.poll_seconds + ' s'],
                ['pf states read', s.raw_states + ' (' + s.connections + ' LAN connections)'],
                ['State table', (pf.states || 0) + ' of ' + (pf.states_limit || '?')],
                ['LAN networks', (s.lan_networks || []).join(', ') || 'none'],
                ['Firewall addresses', (s.own_addresses || []).join(', ')],
                ['Bridges', bridges || 'none (routed)'],
                ['MAC / IP source', s.l2_source + (sniff ? ' | listening: ' + sniff : '') + ' | ARP table entries: ' + s.arp_entries],
                ['Blocked sampling', (function () {
                    const sm = s.sampling || {};
                    const last = sm.last || {};
                    const labels = sm.labels || {};
                    const parts = Object.keys(last).map(function (d) {
                        const x = last[d];
                        return d + (labels[d] ? ' (' + labels[d] + ')' : '') + ': ' + (x.error ? 'ERROR ' + x.error :
                               x.lines + ' attempts in ' + x.elapsed + ' s, ' + x.blocked + ' blocked' +
                               (x.capped ? ' (cap reached)' : '') +
                               (x.inbound_only === false ? ' (both directions: this device cannot filter inbound only)' : ''));
                    });
                    const tables = (sm.reason_tables || []).length ? ' | block reasons from ' + sm.reason_tables.join(', ') : '';
                    return (sm.devices || []).length ? (parts.join('; ') || 'waiting for the first poll') + tables : 'off';
                })()],
                ['Firewall log', s.filterlog.enabled ? (s.filterlog.readable ? 'readable' : 'NOT readable') + ', ' +
                    s.filterlog.blocked_lan_last_poll + ' blocked LAN to LAN packets in the last poll' : 'not read'],
                ['Watched tables', (s.tables || []).map(function (t) { return t.name + ' (' + t.entries + ')'; }).join(', ') || 'none found'],
                ['Database', Math.round((s.db_size || 0) / 1048576) + ' MB']
            ];
            let html = (s.hints || []).map(function (h) {
                return '<div class="alert alert-warning" style="margin-bottom:6px">' + esc(h) + '</div>';
            }).join('');
            if (age > 300) {
                html += '<div class="alert alert-danger" style="margin-bottom:6px">' +
                        esc("{{ lang._('The last poll is old: the collector is probably not running.') }}") + '</div>';
            }
            html += '<table class="table table-condensed" style="margin:0">' + rows.map(function (r) {
                return '<tr><td style="width:180px"><b>' + esc(r[0]) + '</b></td><td>' + esc(r[1]) + '</td></tr>';
            }).join('') + '</table>';
            $box.html(html);
        });
    }
    loadStatus();
    $('#statusRefresh').on('click', loadStatus);

    $('#clearAct').on('click', function () {
        const run = function () {
            ajaxCall('/api/hostguard/settings/clear', {}, function (data) {
                let msg;
                if (data && data.status === 'ok') {
                    msg = "{{ lang._('Collected data removed.') }}" + (data.vacuum === false
                        ? ' ' + "{{ lang._('The database file was not shrunk (the collector was writing), clear again later to shrink it.') }}" : '');
                } else {
                    msg = "{{ lang._('Could not clear the database.') }}" + (data && data.message ? ' ' + data.message : '');
                }
                $('#clearMsg').text(msg).show();
                loadStatus();
            });
        };
        if (typeof stdDialogConfirm === 'function') {
            stdDialogConfirm("{{ lang._('Clear collected data') }}",
                             "{{ lang._('Remove all recorded hosts, ports, connections and service test results?') }}",
                             "{{ lang._('Yes') }}", "{{ lang._('Cancel') }}", run);
        } else if (window.confirm("{{ lang._('Remove all recorded data?') }}")) {
            run();
        }
    });
});
</script>

<div class="content-box">
    {{ partial("layout_partials/base_form", ['fields': generalForm, 'id': 'frm_general']) }}
    <div class="col-md-12" style="padding-bottom: 15px">
        <hr/>
        <button class="btn btn-primary" id="saveAct" type="button">
            <b>{{ lang._('Apply') }}</b> <i id="saveAct_progress"></i>
        </button>
        <button class="btn btn-default" id="clearAct" type="button">
            <i class="fa fa-trash"></i> {{ lang._('Clear collected data') }}
        </button>
        <a class="btn btn-default" href="/ui/hostguard/"><i class="fa fa-area-chart"></i> {{ lang._('Open dashboard') }}</a>
        <span id="clearMsg" class="text-muted" style="display:none; margin-left: 10px"></span>
    </div>
</div>

<div class="content-box" style="margin-top: 15px; padding: 10px 15px">
    <h4 style="font-size:14px;font-weight:600">
        {{ lang._('Collector status') }}
        <button class="btn btn-default btn-xs" id="statusRefresh" type="button" style="margin-left:8px"><i class="fa fa-refresh"></i></button>
    </h4>
    <div id="statusBody"><p class="text-muted">{{ lang._('Loading...') }}</p></div>
</div>
