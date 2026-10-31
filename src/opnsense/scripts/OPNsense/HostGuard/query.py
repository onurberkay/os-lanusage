#!/usr/local/bin/python3
"""
    Copyright (c) 2026 Onur Berkay <onurberkay@sakla.app>
    All rights reserved. (BSD 2-Clause, see LICENSE)

    Read side of the HostGuard database, called by configd:
        query.py <command> <hours> <ip|-> <extra|->
    commands: summary, hosts, ports, flows, services, alerts, lateral, l2, limits, blocked, status, ack, clear,
              attacks, conditions, cond_add, cond_del
    extra: in|out (ports, flows), open|all (alerts), <id>|all (ack),
           <type>|<value>|<target>|<seconds> (cond_add), <id> (cond_del)
    Prints JSON.
"""
import ipaddress
import json
import os
import re
import sqlite3
import sys
import time
from collections import Counter, defaultdict

from lib import bans, common, detect, ipdata, pfstats

ROW_LIMIT = 5000
FOLD_KEEP = 20      # the collector stores the 20 busiest remotes per host / port each poll, folds the rest
# a group of outside sources the Blocked / Limits tabs link to: "t=<LAN host>|<proto/port>;" or "l=<limit>@<rule>;"
GROUP_RE = re.compile(r'(t=[0-9a-f:.]+\|[a-z0-9/-]+|l=[a-z-]+@[0-9]+);')


def distinct_estimate(named, folded):
    """ distinct remotes, a lower bound: a poll that folded N stored FOLD_KEEP one by one besides them """
    return max(named, folded + FOLD_KEEP) if folded else named


class LanAddresses:
    """ "is it a LAN address": a host seen, else inside the LAN networks the collector uses (from its status),
    so that an address is LAN or outside the same way wherever its row comes from """

    def __init__(self, con, status):
        self.known = {r[0]: True for r in con.execute('SELECT ip FROM hosts')}
        self.networks = []
        for net in status.get('lan_networks') or []:
            try:
                self.networks.append(ipaddress.ip_network(net, strict=False))
            except ValueError:
                pass

    def __contains__(self, addr):
        found = self.known.get(addr)
        if found is None:
            try:
                parsed = ipaddress.ip_address(addr)
                found = any(parsed in net for net in self.networks)
            except ValueError:
                found = False       # "others (N)", "*"
            self.known[addr] = found
        return found


def bucket_size(hours):
    if hours <= 6:
        return 300
    if hours <= 24:
        return 900
    if hours <= 168:
        return 3600
    return 6 * 3600


def where_ip(ip, column='ip'):
    return (' AND %s = ?' % column, [ip]) if ip else ('', [])


def service_names(con, ip=None):
    """ (proto, port) -> detected service, most common one wins when several hosts serve the port """
    clause, args = where_ip(ip)
    votes = {}
    for proto, port, service, count in con.execute(
            "SELECT proto, port, service, COUNT(*) FROM services WHERE state = 'open' AND service != ''"
            + clause + ' GROUP BY proto, port, service', args):
        best = votes.get((proto, port))
        if best is None or count > best[1]:
            votes[(proto, port)] = (service, count)
    return {key: value[0] for key, value in votes.items()}


def name_of(names, proto, port):
    return names.get((proto, port)) or detect.port_name(port, proto)


def cmd_summary(con, hours, ip, _direction):
    now = int(time.time())
    since = now - hours * 3600
    size = bucket_size(hours)
    clause, args = where_ip(ip)

    series = {}
    for t, direction, conns, nbytes in con.execute(
            'SELECT (ts / ?) * ? AS t, dir, SUM(conns), SUM(bytes) FROM ts_host WHERE ts >= ?' + clause
            + ' GROUP BY t, dir', [size, size, since] + args):
        series.setdefault(t, {})[direction] = (conns, nbytes)
    timeline = []
    for t in range(since - since % size, now + 1, size):
        point = series.get(t, {})
        timeline.append({
            't': t,
            'in_c': point.get('in', (0, 0))[0], 'out_c': point.get('out', (0, 0))[0],
            'in_b': point.get('in', (0, 0))[1], 'out_b': point.get('out', (0, 0))[1],
        })

    totals = {'conns_in': 0, 'conns_out': 0, 'bytes_in': 0, 'bytes_out': 0}
    for direction, conns, nbytes in con.execute(
            'SELECT dir, SUM(conns), SUM(bytes) FROM ts_host WHERE ts >= ?' + clause + ' GROUP BY dir',
            [since] + args):
        totals['conns_' + direction] = conns or 0
        totals['bytes_' + direction] = nbytes or 0
    totals['hosts'] = con.execute(
        'SELECT COUNT(DISTINCT ip) FROM ts_host WHERE ts >= ?' + clause, [since] + args).fetchone()[0]
    active = con.execute(
        'SELECT COUNT(*), COALESCE(SUM(active), 0) FROM hosts WHERE active > 0' + clause, args).fetchone()
    totals['active_hosts'], totals['active_conns'] = active
    totals['ports'] = con.execute(
        'SELECT COUNT(*) FROM (SELECT DISTINCT dir, proto, port FROM ts_port WHERE ts >= ?' + clause + ')',
        [since] + args).fetchone()[0]
    totals['services'] = con.execute(
        "SELECT COUNT(*) FROM services WHERE state = 'open'" + clause, args).fetchone()[0]
    alert_clause, alert_args = where_alert_ip(ip)
    totals['alerts_open'], totals['alerts_high'] = con.execute(
        "SELECT COUNT(*), COALESCE(SUM(severity IN ('high', 'critical')), 0) FROM alerts WHERE acked = 0"
        + alert_clause, alert_args).fetchone()
    for direction, packets in con.execute(
            'SELECT dir, SUM(packets) FROM ts_blocked WHERE ts >= ?' + clause + ' GROUP BY dir', [since] + args):
        totals['blocked_' + direction] = packets
    totals.setdefault('blocked_in', 0)
    totals.setdefault('blocked_out', 0)
    pf = common.read_status().get('pf') or {}
    totals['pf_states'], totals['pf_states_limit'] = pf.get('states', 0), pf.get('states_limit', 0)
    totals['state_warn_pct'] = common.load_config()['state_warn_pct']
    lat_clause, lat_args = where_lateral_ip(ip)
    totals['lateral'], totals['lateral_blocked'] = con.execute(
        'SELECT COALESCE(SUM(attempts), 0), COALESCE(SUM(blocked), 0) FROM lateral WHERE last_seen >= ?'
        + lat_clause, [since] + lat_args).fetchone()

    names = service_names(con, ip)
    top = {}
    for direction in ('in', 'out'):
        top[direction] = [
            {'proto': proto, 'port': port, 'name': name_of(names, proto, port) if direction == 'in'
             else detect.port_name(port, proto), 'conns': conns, 'bytes': nbytes, 'hosts': nhosts}
            for proto, port, conns, nbytes, nhosts in con.execute(
                'SELECT proto, port, SUM(conns) AS c, SUM(bytes), COUNT(DISTINCT ip) FROM ts_port'
                ' WHERE ts >= ? AND dir = ?' + clause + ' GROUP BY proto, port ORDER BY c DESC LIMIT 10',
                [since, direction] + args)
        ]

    if ip:
        peers = [
            {'ip': remote, 'conns': conns, 'bytes': nbytes}
            for remote, conns, nbytes in con.execute(
                'SELECT remote, SUM(conns) AS c, SUM(bytes) FROM flows WHERE ip = ? AND last_seen >= ?'
                ' GROUP BY remote ORDER BY c DESC LIMIT 10', [ip, since])
        ]
    else:
        peers = [
            {'ip': host, 'conns': conns, 'bytes': nbytes}
            for host, conns, nbytes in con.execute(
                'SELECT ip, SUM(conns) AS c, SUM(bytes) FROM ts_host WHERE ts >= ?'
                ' GROUP BY ip ORDER BY c DESC LIMIT 10', [since])
        ]

    mix = [
        {'service': service, 'count': count}
        for service, count in con.execute(
            "SELECT service, COUNT(*) AS n FROM services WHERE state = 'open'" + clause
            + ' GROUP BY service ORDER BY n DESC', args)
    ]
    recent = alert_rows(con, 'WHERE acked = 0' + alert_clause, alert_args, 6)
    return {
        'hours': hours, 'bucket': size, 'now': now, 'ip': ip or '',
        'totals': totals, 'timeline': timeline, 'top_in': top['in'], 'top_out': top['out'],
        'top_hosts': peers, 'peers_of_host': bool(ip), 'service_mix': mix, 'recent_alerts': recent,
    }


def where_alert_ip(ip):
    return (" AND (ip = ? OR (',' || peer || ',') LIKE ?)", [ip, '%,' + ip + ',%']) if ip else ('', [])


def where_lateral_ip(ip):
    return (' AND (src = ? OR dst = ?)', [ip, ip]) if ip else ('', [])


ALERT_COLUMNS = ('id', 'type', 'severity', 'ip', 'mac', 'peer', 'detail', 'first_seen', 'last_seen', 'count', 'acked')
SEVERITY_RANK = "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END"


def alert_rows(con, where, args, limit=ROW_LIMIT):
    return [
        dict(zip(ALERT_COLUMNS, row)) for row in con.execute(
            'SELECT %s FROM alerts %s ORDER BY acked, last_seen DESC, %s LIMIT ?'
            % (', '.join(ALERT_COLUMNS), where, SEVERITY_RANK), args + [limit])
    ]


def cmd_alerts(con, hours, ip, which):
    since = int(time.time()) - hours * 3600
    clause, args = where_alert_ip(ip)
    where = 'WHERE (last_seen >= ? OR acked = 0)' + clause
    if which == 'open':
        where += ' AND acked = 0'
    rows = alert_rows(con, where, [since] + args)
    counts = dict(con.execute('SELECT severity, COUNT(*) FROM alerts WHERE acked = 0 GROUP BY severity').fetchall())
    return {'rows': rows, 'total': len(rows), 'open': counts}


def cmd_ack(con, _hours, ip, target):
    with con:
        if target == 'all':
            clause, args = where_alert_ip(ip)
            con.execute('UPDATE alerts SET acked = 1 WHERE acked = 0' + clause, args)
        else:
            con.execute('UPDATE alerts SET acked = 1 WHERE id = ?', (int(target),))
    return {'status': 'ok'}


def cmd_lateral(con, hours, ip, _extra):
    since = int(time.time()) - hours * 3600
    clause, args = where_lateral_ip(ip)
    names = service_names(con)
    rows = []
    for src, dst, proto, port, first, last, attempts, answered, blocked, nbytes in con.execute(
            'SELECT src, dst, proto, port, MIN(first_seen), MAX(last_seen) AS l, SUM(attempts), SUM(answered),'
            ' SUM(blocked), SUM(bytes) FROM lateral WHERE day >= ? AND last_seen >= ?' + clause
            + ' GROUP BY src, dst, proto, port ORDER BY l DESC LIMIT ?',
            [since - since % 86400, since] + args + [ROW_LIMIT]):
        rows.append({
            'src': src, 'dst': dst, 'proto': proto, 'port': port, 'first_seen': first, 'last_seen': last,
            'attempts': attempts, 'answered': answered, 'blocked': blocked, 'bytes': nbytes,
            'name': name_of(names, proto, port) if proto in ('tcp', 'udp') else '',
            'sensitive': proto in ('tcp', 'udp') and port in common.SENSITIVE_PORTS,
        })
    return {'rows': rows, 'total': len(rows)}


def cmd_l2(con, hours, ip, _extra):
    since = int(time.time()) - hours * 3600
    bindings = con.execute(
        'SELECT mac, ip, iface, first_seen, last_seen FROM l2bind WHERE last_seen >= ?', [since]).fetchall()
    mac_ips, ip_macs = {}, {}
    for mac, addr, _, _, _ in bindings:
        if ':' not in addr:
            mac_ips.setdefault(mac, []).append(addr)
        ip_macs.setdefault(addr, []).append(mac)
    rows = []
    for mac, addr, iface, first, last in bindings:
        if ip and ip != addr and ip not in mac_ips.get(mac, []):
            continue
        rows.append({
            'mac': mac, 'ip': addr, 'iface': iface, 'first_seen': first, 'last_seen': last,
            'mac_ips': sorted(mac_ips.get(mac, []), key=common.ip_sort_key),
            'ip_macs': sorted(ip_macs.get(addr, [])),
        })
    rows.sort(key=lambda r: (-(len(r['mac_ips']) > 1 or len(r['ip_macs']) > 1), r['mac'], common.ip_sort_key(r['ip'])))
    return {'rows': rows[:ROW_LIMIT], 'total': len(rows)}


COUNTER_HELP = {name: meaning for name, (_sev, meaning) in pfstats.WATCHED_COUNTERS.items()}


def cmd_limits(con, hours, ip, _extra):
    now = int(time.time())
    since = now - hours * 3600
    size = bucket_size(hours)
    status = common.read_status()
    cfg = common.load_config()

    series, increases = {}, {}
    for ts, states, states_limit, src_nodes, counters in con.execute(
            'SELECT ts, states, states_limit, src_nodes, counters FROM ts_pf WHERE ts >= ? ORDER BY ts', [since]):
        t = ts - ts % size
        point = series.setdefault(t, {'states': 0, 'src_nodes': 0, 'limit_hits': 0, 'limit': 0})
        point['states'] = max(point['states'], states or 0)
        point['src_nodes'] = max(point['src_nodes'], src_nodes or 0)
        point['limit'] = states_limit or point['limit']
        for name, delta in (json.loads(counters) if counters else {}).items():
            increases[name] = increases.get(name, 0) + delta
            if name in COUNTER_HELP:
                point['limit_hits'] += delta
    timeline = [dict(t=t, **series.get(t, {'states': 0, 'src_nodes': 0, 'limit_hits': 0, 'limit': 0}))
                for t in range(since - since % size, now + 1, size)]

    totals = (status.get('pf') or {}).get('counters', {})
    counters = [
        {'name': name, 'total': totals.get(name, 0), 'increase': increases.get(name, 0),
         'meaning': meaning, 'watched': True}
        for name, meaning in COUNTER_HELP.items()
    ]
    counters += [{'name': name, 'total': value, 'increase': increases.get(name, 0), 'meaning': '', 'watched': False}
                 for name, value in totals.items() if name not in COUNTER_HELP]

    clause, args = where_ip(ip)
    # pf has no per host limit: a host's states count against the state table in total and, for the
    # connections it opens, against the per source limits of the rules it uses. The warning threshold is ours.
    table_limit = (status.get('pf') or {}).get('states_limit') or 0
    host_src = status.get('host_src') or {}
    hosts = [
        {'ip': host, 'states': states, 'detail': detail or '', 'new_rate': rate or 0,
         'pct': round(states * 100.0 / cfg['host_state_limit'], 1) if cfg['host_state_limit'] else 0,
         'table_pct': round(states * 100.0 / table_limit, 2) if table_limit else None,
         'src': host_src.get(host)}
        for host, states, detail, rate in con.execute(
            'SELECT ip, states, state_detail, new_rate FROM hosts WHERE (states > 0 OR new_rate > 0)' + clause
            + ' ORDER BY states DESC LIMIT 200', args)
    ]
    current = {(t['name'], member) for t in status.get('tables', []) for member in t.get('lan', [])}
    tclause, targs = (' AND ip = ?', [ip]) if ip else ('', [])
    tablehits = [
        {'table': tbl, 'ip': host, 'first_seen': first, 'last_seen': last, 'current': (tbl, host) in current}
        for tbl, host, first, last in con.execute(
            'SELECT tbl, ip, first_seen, last_seen FROM tablehits WHERE last_seen >= ?' + tclause
            + ' ORDER BY last_seen DESC', [since] + targs)
    ]
    # sources at a per source limit: what is true now (status) merged with when it happened (srclimits)
    src = {}
    lan_hosts = LanAddresses(con, status)
    for f in status.get('src_limited', []):
        if ip and f['ip'] != ip:
            continue
        row = src[(f['ip'], f['rule'], f['kind'])] = dict(f, now=True, peak=f['value'], hits=0, first_seen=0,
                                                         last_seen=0)
        if not row.get('lan') and f['ip'] in lan_hosts:
            # a host seen in the LAN (its network since removed): LAN here too, as on the Attacks tab
            row.update(lan=True, dir='out')
    sclause, sargs = (' AND ip = ?', [ip]) if ip else ('', [])
    for host, nr, kind, descr, limit, peak, first, last, hits, label in con.execute(
            'SELECT ip, nr, kind, descr, limit_value, peak, first_seen, last_seen, hits, label FROM srclimits'
            ' WHERE last_seen >= ?' + sclause, [since] + sargs):
        row = src.setdefault((host, nr, kind), {
            'ip': host, 'lan': host in lan_hosts, 'rule': nr, 'descr': descr, 'kind': kind, 'limit': limit,
            'value': None, 'pct': None, 'at_limit': False, 'now': False, 'label': label or ''})
        row.update(peak=max(peak or 0, row.get('peak') or 0), hits=hits, first_seen=first, last_seen=last)
    where = dict((r['nr'], r.get('where', '')) for r in status.get('rules', []))
    for row in src.values():
        # the source opens the connections: LAN source = its outbound connections, else inbound to your hosts
        row.setdefault('dir', 'out' if row['lan'] else 'in')
        if not row.get('where'):
            row['where'] = where.get(row['rule'], '')
    # outside clients at a limit: one row per rule and limit, every address on the External sources tab
    rows, external = [], {}
    for row in src.values():
        if row['lan']:
            rows.append(row)
            continue
        group = external.get((row['rule'], row['kind']))
        if group is None:
            group = external[(row['rule'], row['kind'])] = dict(row, external=0, top=[], at_limit_now=0)
            rows.append(group)
        else:
            group['now'] = group['now'] or row['now']
            group['at_limit'] = group['at_limit'] or row['at_limit']
            group['label'] = group.get('label') or row.get('label', '')
            if (row['pct'] or 0) > (group['pct'] or 0):
                group.update(pct=row['pct'], value=row['value'], rate=row.get('rate', ''))
            group['peak'] = max(group.get('peak') or 0, row.get('peak') or 0)
            group['hits'] = (group.get('hits') or 0) + (row.get('hits') or 0)
            group['last_seen'] = max(group.get('last_seen') or 0, row.get('last_seen') or 0)
        group['external'] += 1
        if row['now'] and row['at_limit']:
            group['at_limit_now'] += 1
        group['top'].append(((row['pct'] or 0, row.get('peak') or 0), row['ip']))
    for group in external.values():
        group['top'] = [ip_ for _, ip_ in sorted(group['top'], reverse=True)[:3]]
        if group['external'] > 1:
            group['ip'] = '%d external clients' % group['external']
    src_limits = sorted(rows, key=lambda r: (not r['now'], -(r['pct'] or 0), -(r['last_seen'] or 0)))

    hclause, hargs = (' AND ip = ?', [ip]) if ip else ('', [])
    shaper_hits = [
        {'ip': host, 'kind': kind, 'nr': nr, 'descr': descr, 'limit': limit, 'peak_bps': peak, 'first_seen': first,
         'last_seen': last, 'drops': drops, 'lan': host in lan_hosts}
        for host, kind, nr, descr, limit, peak, first, last, drops in con.execute(
            'SELECT ip, kind, nr, descr, limit_bps, peak_bps, first_seen, last_seen, drops FROM shaperhits'
            ' WHERE last_seen >= ?' + hclause + ' ORDER BY drops DESC LIMIT 500', [since] + hargs)
    ]
    shaper_now = status.get('shaper') or {}
    if ip:
        shaper_now = dict(shaper_now, flows=[f for f in shaper_now.get('flows', []) if f['ip'] == ip])

    return {
        'shaper': shaper_now, 'shaper_hits': shaper_hits,
        'src_limits': src_limits,
        'pf': status.get('pf') or {}, 'status_time': status.get('time', 0), 'timeline': timeline,
        'counters': counters, 'hosts': hosts, 'tablehits': tablehits, 'tables': status.get('tables', []),
        'rules': status.get('rules', []),
        'thresholds': {'host_states': cfg['host_state_limit'], 'host_rate': cfg['host_rate_limit'],
                       'state_warn_pct': cfg['state_warn_pct']},
    }


def cmd_blocked(con, hours, ip, direction):
    """ blocked traffic estimated from samples, plus exact block rule counters """
    now = int(time.time())
    since = now - hours * 3600
    size = bucket_size(hours)
    status = common.read_status()
    clause, args = where_ip(ip)
    dclause, dargs = (' AND dir = ?', [direction]) if direction else ('', [])

    series = {}
    for t, d, packets in con.execute(
            'SELECT (ts / ?) * ? AS t, dir, SUM(packets) FROM ts_blocked WHERE ts >= ?' + clause + ' GROUP BY t, dir',
            [size, size, since] + args):
        series.setdefault(t, {})[d] = packets
    timeline = [{'t': t, 'in_pps': round(series.get(t, {}).get('in', 0) / float(size), 1),
                 'out_pps': round(series.get(t, {}).get('out', 0) / float(size), 1)}
                for t in range(since - since % size, now + 1, size)]

    totals = {'in': 0, 'out': 0}
    hosts = {}
    for host, d, packets in con.execute(
            'SELECT ip, dir, SUM(packets) FROM ts_blocked WHERE ts >= ?' + clause + ' GROUP BY ip, dir',
            [since] + args):
        totals[d] = totals.get(d, 0) + packets
        row = hosts.setdefault(host, {'ip': host, 'in': 0, 'out': 0, 'top_in': [], 'top_out': [],
                                      'sources': 0, 'targets': 0, 'why_in': [], 'why_out': []})
        row[d] = packets
    ports, remotes = {}, {}
    for host, d, proto, port, remote, packets in con.execute(
            'SELECT ip, dir, proto, port, remote, SUM(packets) FROM blocked WHERE last_seen >= ?' + clause
            + ' GROUP BY ip, dir, proto, port, remote', [since] + args):
        key = (host, d, proto, port)
        ports[key] = ports.get(key, 0) + packets
        # "others (N)": N remotes folded in one poll next to the 20 stored one by one; every poll writes its
        # own N, mostly the same addresses again (some of them stored one by one in another poll)
        folded = re.match(r'^others \((\d+)\)$', remote)
        if remote != '*':       # '*': remote addresses are not recorded (setting), nothing to count
            items = remotes.setdefault((host, d), {})
            if folded:
                items['others'] = max(items.get('others', 0), int(folded.group(1)))
            else:
                items[remote] = 1
    for (host, d, proto, port), packets in sorted(ports.items(), key=lambda x: -x[1]):
        row = hosts.get(host)
        if row is None:
            continue
        target = row['top_in'] if d == 'in' else row['top_out']
        if len(target) < 4:
            target.append({'proto': proto, 'port': port, 'packets': packets,
                           'name': detect.port_name(port, proto) if proto in ('tcp', 'udp') else ''})
    for (host, d), items in remotes.items():
        if host in hosts:
            hosts[host]['sources' if d == 'in' else 'targets'] = distinct_estimate(
                len(items) - (1 if 'others' in items else 0), items.get('others', 0))
    lan_hosts = LanAddresses(con, status)
    labels = (status.get('sampling') or {}).get('labels', {})
    # attacks from outside can come from thousands of addresses: one row per LAN host and port here,
    # every source on the External sources tab
    flows, grouped = [], {}
    for host, d, proto, port, remote, first, last, packets, samples, reason, iface in con.execute(
            'SELECT ip, dir, proto, port, remote, MIN(first_seen), MAX(last_seen), SUM(packets), SUM(samples),'
            ' MAX(reason), MAX(iface)'
            ' FROM blocked WHERE day >= ? AND last_seen >= ?' + clause + dclause
            + ' GROUP BY ip, dir, proto, port, remote', [since - since % 86400, since] + args + dargs):
        internal = remote in lan_hosts
        row = {'ip': host, 'dir': d, 'proto': proto, 'port': port, 'remote': remote, 'packets': packets,
               'samples': samples, 'first_seen': first, 'last_seen': last, 'internal': internal,
               'name': detect.port_name(port, proto) if proto in ('tcp', 'udp') else '', 'reason': reason or '',
               'iface': ('%s (%s)' % (iface, labels[iface]) if labels.get(iface) else iface or '')}
        if d != 'in' or internal:
            flows.append(row)
            continue
        group = grouped.get((host, proto, port))
        if group is None:
            group = grouped[(host, proto, port)] = dict(row, remote='', external=0, top=[], why=Counter(), folded=0)
            flows.append(group)
        else:
            group['packets'] += packets
            group['samples'] += samples
            group['first_seen'] = min(group['first_seen'], first)
            group['last_seen'] = max(group['last_seen'], last)
        folded = re.match(r'^others \((\d+)\)$', remote)
        group['why'][row['reason']] += packets
        if remote == '*':
            # remote addresses are not recorded (setting): nothing to count
            continue
        if folded:
            # the largest per poll count, not the sum over the polls (the same addresses again)
            group['folded'] = max(group['folded'], int(folded.group(1)))
        else:
            group['external'] += 1
            group['top'].append((packets, remote))
    for group in grouped.values():
        group['reason'] = group.pop('why').most_common(1)[0][0]
        group['top'] = [r for _, r in sorted(group['top'], reverse=True)[:3]]
        folded = group.pop('folded')
        group['external'] = distinct_estimate(group['external'], folded)
        if not group['external']:
            group['remote'] = 'outside (addresses not recorded)'
        elif group['external'] == 1 and group['top']:
            group['remote'] = group['top'][0]
        else:
            group['remote'] = '%s%d external sources' % ('at least ' if folded else '', group['external'])
    flows.sort(key=lambda r: -r['packets'])
    flows = flows[:ROW_LIMIT]
    # the direction filter belongs to the attempts table only; the hosts table shows why in and why out
    reasons, per_host_reasons = Counter(), defaultdict(Counter)
    for host, d, reason, packets in con.execute(
            'SELECT ip, dir, reason, SUM(packets) FROM blocked_reasons WHERE day >= ? AND last_seen >= ?'
            + clause + ' GROUP BY ip, dir, reason', [since - since % 86400, since] + args):
        reasons[(d, reason)] += packets
        per_host_reasons[(host, d)][reason] += packets
    for (host, d), counter in per_host_reasons.items():
        if host in hosts:
            total = float(sum(counter.values())) or 1.0
            hosts[host]['why_' + d] = [{'reason': r, 'pct': round(p * 100 / total)} for r, p in counter.most_common(3)]
    reason_rows = [{'dir': d, 'reason': r, 'packets': p} for (d, r), p in reasons.most_common()]
    period = dict(((label, nr), packets) for label, nr, packets in con.execute(
        'SELECT label, MIN(nr), SUM(packets) FROM ts_rules WHERE ts >= ? GROUP BY label', [since]))
    rules = []
    for rule in status.get('rule_activity', []):
        key = rule['label'] or 'nr:%d' % rule['nr']
        rule = dict(rule)
        rule['period'] = next((v for (label, _), v in period.items() if label == key), 0)
        rules.append(rule)
    return {
        'timeline': timeline, 'totals': totals, 'hosts': sorted(hosts.values(), key=lambda r: -(r['in'] + r['out'])),
        'flows': flows, 'rules': rules, 'sampling': status.get('sampling', {}), 'reasons': reason_rows,
    }


def cmd_status(con, _hours, _ip, _extra):
    status = common.read_status()
    try:
        status['db_size'] = os.path.getsize(common.DB_FILE)
    except OSError:
        status['db_size'] = 0
    status['now'] = int(time.time())
    return status


def host_macs(con, since):
    """ ip -> (latest mac, number of IPv4 addresses that mac used since) """
    latest, per_mac = {}, {}
    for mac, addr, _last in con.execute(
            'SELECT mac, ip, last_seen FROM l2bind WHERE last_seen >= ? ORDER BY last_seen', [since]):
        latest[addr] = mac
        if ':' not in addr:
            per_mac.setdefault(mac, set()).add(addr)
    return {addr: (mac, len(per_mac.get(mac, ()))) for addr, mac in latest.items()}


def cmd_hosts(con, hours, ip, _direction):
    since = int(time.time()) - hours * 3600
    clause, args = where_ip(ip)
    rows = {}
    for host, direction, conns, nbytes in con.execute(
            'SELECT ip, dir, SUM(conns), SUM(bytes) FROM ts_host WHERE ts >= ?' + clause + ' GROUP BY ip, dir',
            [since] + args):
        row = rows.setdefault(host, {
            'ip': host, 'conns_in': 0, 'conns_out': 0, 'bytes_in': 0, 'bytes_out': 0,
            'first_seen': 0, 'last_seen': 0, 'active': 0, 'ports_in': [], 'ports_out': 0, 'services': [],
            'mac': '', 'mac_ips': 0, 'lateral': 0, 'states': 0, 'state_detail': '', 'new_rate': 0,
            'blocked_in': 0, 'blocked_out': 0,
        })
        row['conns_' + direction] = conns
        row['bytes_' + direction] = nbytes
    for host, first, last, active, states, detail, rate in con.execute(
            'SELECT ip, first_seen, last_seen, active, states, state_detail, new_rate FROM hosts WHERE 1 = 1'
            + clause, args):
        if host in rows:
            rows[host].update(first_seen=first, last_seen=last, active=active, states=states or 0,
                              state_detail=detail or '', new_rate=rate or 0)
    names = service_names(con)
    for host, direction, proto, port, conns in con.execute(
            'SELECT ip, dir, proto, port, SUM(conns) AS c FROM ts_port WHERE ts >= ?' + clause
            + ' GROUP BY ip, dir, proto, port ORDER BY c DESC', [since] + args):
        if host not in rows:
            continue
        if direction == 'in':
            rows[host]['ports_in'].append(
                {'proto': proto, 'port': port, 'name': name_of(names, proto, port), 'conns': conns})
        else:
            rows[host]['ports_out'] += 1
    for host, proto, port, service, product in con.execute(
            "SELECT ip, proto, port, service, product FROM services WHERE state = 'open'" + clause
            + ' ORDER BY port', args):
        if host in rows:
            rows[host]['services'].append(
                {'proto': proto, 'port': port, 'service': service, 'product': product})
    for addr, (mac, count) in host_macs(con, since).items():
        if addr in rows:
            rows[addr].update(mac=mac, mac_ips=count)
    for addr, attempts in con.execute(
            'SELECT src, SUM(attempts) FROM lateral WHERE last_seen >= ? GROUP BY src', [since]):
        if addr in rows:
            rows[addr]['lateral'] = attempts
    for addr, direction, packets in con.execute(
            'SELECT ip, dir, SUM(packets) FROM ts_blocked WHERE ts >= ? GROUP BY ip, dir', [since]):
        if addr in rows:
            rows[addr]['blocked_' + direction] = packets
    alerts = {}
    for addr, count in con.execute('SELECT ip, COUNT(*) FROM alerts WHERE acked = 0 GROUP BY ip'):
        alerts[addr] = count
    for row in rows.values():
        row['alerts'] = alerts.get(row['ip'], 0)
    result = sorted(rows.values(), key=lambda r: r['conns_in'] + r['conns_out'], reverse=True)
    return {'rows': result[:ROW_LIMIT], 'total': len(result)}


def cmd_ports(con, hours, ip, direction):
    since = int(time.time()) - hours * 3600
    clause, args = where_ip(ip)
    if direction:
        clause += ' AND dir = ?'
        args.append(direction)
    names = service_names(con, ip)
    rows = [
        {'dir': d, 'proto': proto, 'port': port,
         'name': name_of(names, proto, port) if d == 'in' else detect.port_name(port, proto),
         'conns': conns, 'bytes': nbytes, 'hosts': nhosts}
        for d, proto, port, conns, nbytes, nhosts in con.execute(
            'SELECT dir, proto, port, SUM(conns) AS c, SUM(bytes), COUNT(DISTINCT ip) FROM ts_port'
            ' WHERE ts >= ?' + clause + ' GROUP BY dir, proto, port ORDER BY c DESC LIMIT ?',
            [since] + args + [ROW_LIMIT])
    ]
    return {'rows': rows, 'total': len(rows)}


def cmd_flows(con, hours, ip, direction):
    since = int(time.time()) - hours * 3600
    clause, args = where_ip(ip)
    if direction:
        clause += ' AND dir = ?'
        args.append(direction)
    names = service_names(con)
    lan_hosts = LanAddresses(con, common.read_status())
    rows = [
        {'ip': host, 'dir': d, 'proto': proto, 'port': port,
         'name': name_of(names, proto, port) if d == 'in' else detect.port_name(port, proto),
         'remote': remote, 'first_seen': first, 'last_seen': last, 'conns': conns, 'bytes': nbytes,
         'internal': remote in lan_hosts}
        for host, d, proto, port, remote, first, last, conns, nbytes in con.execute(
            'SELECT ip, dir, proto, port, remote, MIN(first_seen), MAX(last_seen) AS l, SUM(conns), SUM(bytes)'
            ' FROM flows WHERE day >= ? AND last_seen >= ?' + clause
            + ' GROUP BY ip, dir, proto, port, remote ORDER BY l DESC LIMIT ?',
            [since - since % 86400, since] + args + [ROW_LIMIT])
    ]
    return {'rows': rows, 'total': len(rows)}


def cmd_services(con, hours, ip, _direction):
    clause, args = where_ip(ip)
    columns = ('ip', 'proto', 'port', 'state', 'service', 'product', 'tls', 'banner', 'method',
               'last_probe', 'first_seen')
    rows = [
        dict(zip(columns, row)) for row in con.execute(
            'SELECT %s FROM services WHERE 1 = 1%s ORDER BY ip, port LIMIT ?' % (', '.join(columns), clause),
            args + [ROW_LIMIT])
    ]
    return {'rows': rows, 'total': len(rows)}


def cmd_attacks(con, hours, ip, extra):
    """ attacks on LAN hosts: episodes, every outside source, Suricata alerts, current CrowdSec decisions """
    now = int(time.time())
    since = now - hours * 3600
    status = common.read_status()
    lan_hosts = LanAddresses(con, status)
    tclause, targs = (' AND target = ?', [ip]) if ip else ('', [])
    columns = ('id', 'target', 'kind', 'first_seen', 'last_seen', 'peak_pps', 'packets', 'sources', 'ports',
               'passed_pct', 'top_sources')
    episodes = [dict(zip(columns, r), active=r[4] >= now - 600) for r in con.execute(
        'SELECT %s FROM attacks WHERE last_seen >= ?%s ORDER BY last_seen DESC LIMIT ?' % (', '.join(columns), tclause),
        [since] + targs + [ROW_LIMIT])]

    # every outside source that sent blocked traffic to a LAN host (the 20 busiest per host / port are stored)
    sclause, sargs = (' AND (ip = ? OR remote = ?)', [ip, ip]) if ip else ('', [])
    sources, folded_by_port = {}, {}
    for remote, target, proto, port, packets, reason, first, last in con.execute(
            "SELECT remote, ip, proto, port, SUM(packets), MAX(reason), MIN(first_seen), MAX(last_seen) FROM blocked"
            " WHERE dir = 'in' AND day >= ? AND last_seen >= ?" + sclause + ' GROUP BY remote, ip, proto, port',
            [since - since % 86400, since] + sargs):
        service = '%s/%d' % (proto, port) if proto in ('tcp', 'udp') else proto
        many = re.match(r'^others \((\d+)\)$', remote) if remote.startswith('others') else None
        if many:
            # every poll folds its own N, mostly the same addresses: the largest N per host and port
            key = 't=%s|%s;' % (target, service)
            folded_by_port[key] = max(folded_by_port.get(key, 0), int(many.group(1)))
            continue
        if remote == '*' or remote in lan_hosts:
            continue
        # a scanner has a row per host and port: built once, not for every row
        row = sources.get(remote)
        if row is None:
            row = sources[remote] = {'ip': remote, 'packets': 0, 'targets': set(), 'ports': Counter(),
                                     'why': Counter(), 'first_seen': first, 'last_seen': last,
                                     'limits': [], 'ids': 0, 'crowdsec': '', 'blocked_by': [], 'keys': set()}
        row['packets'] += packets
        row['targets'].add(target)
        row['ports'][service] += packets
        row['keys'].add('t=%s|%s;' % (target, service))
        row['why'][reason or ''] += packets
        row['first_seen'], row['last_seen'] = min(row['first_seen'], first), max(row['last_seen'], last)
    # outside clients at a per source rule limit are listed too, also when none of their traffic was blocked:
    # those that reached it in the period (srclimits) and those at 90 % or more now (status, the Limits tab
    # groups them: its "list" link must find every member)
    limited = [(src, nr, kind, first, last) for src, nr, kind, first, last in con.execute(
        'SELECT ip, nr, kind, first_seen, last_seen FROM srclimits WHERE last_seen >= ?', [since])]
    checked = status.get('time') or now
    limited += [(f['ip'], f['rule'], f['kind'], checked, checked) for f in status.get('src_limited', []) if not f.get('lan')]
    for src, nr, kind, first, last in limited:
        if src in lan_hosts or (ip and src != ip):
            continue
        row = sources.get(src)
        if row is None:
            row = sources[src] = {'ip': src, 'packets': 0, 'targets': set(), 'ports': Counter(), 'why': Counter(),
                                  'first_seen': first, 'last_seen': last, 'limits': [], 'ids': 0, 'crowdsec': '',
                                  'blocked_by': [], 'keys': set()}
            row['why']['%s limit rule @%d' % (kind, nr)] = 0
        key = 'l=%s@%d;' % (kind, nr)
        if key not in row['keys']:
            row['limits'].append('%s @%d' % (kind, nr))
            row['keys'].add(key)
        row['first_seen'], row['last_seen'] = min(row['first_seen'], first), max(row['last_seen'], last)
    for src, hits in con.execute('SELECT src, SUM(hits) FROM ids_alerts WHERE last_seen >= ? GROUP BY src', [since]):
        if src in sources:
            sources[src]['ids'] = hits
    for src, scenario in con.execute('SELECT ip, scenario FROM crowdsec WHERE until >= ?', [now]):
        if src in sources:
            sources[src]['crowdsec'] = scenario
    for src, cond in con.execute('SELECT ip, cond FROM autoblocked'):
        if src in sources:
            sources[src]['blocked_by'].append(cond)
    # the sources seen (a lower bound when some were only counted): the GUI shows len(rows) + truncated + folded
    seen =distinct_estimate(len(sources), max(folded_by_port.values() or [0]))
    group = extra if extra and GROUP_RE.fullmatch(extra) else None
    if group:
        # a "list" link of the Blocked / Limits tabs: only that group's members, every one of them
        # (one key per (target, port) and per limit: "t=10.0.0.5|tcp/22;" is neither 10.0.0.50 nor tcp/2222,
        # "l=max-src-conn@12;" neither max-src-conn-rate nor @120)
        selected = [r for r in sources.values() if group in r['keys']]
        seen = distinct_estimate(len(selected), folded_by_port.get(group, 0))
    else:
        selected = list(sources.values())
    # sources at a rule limit first: they have no blocked packets to sort by, but the Limits tab links to them
    rows = sorted(selected, key=lambda r: (not r['limits'], -r['packets']))[:ROW_LIMIT]
    truncated = len(selected) - len(rows)       # stored one by one, past the rows sent
    folded = seen - len(selected)               # only counted ("others (N)")
    for row in rows:
        del row['keys']
        row['targets_total'] = len(row['targets'])
        row['targets'] = sorted(row['targets'], key=common.ip_sort_key)[:10]
        row['ports'] = [p for p, _ in row['ports'].most_common(4)]
        row['why'] = row['why'].most_common(1)[0][0] if row['why'] else ''
    cfg = common.load_config()
    networks = source_networks(rows, cfg)

    # Suricata: one row per LAN host and signature, the sources counted (attacks can use thousands)
    iclause, iargs = (' AND (target = ? OR src = ?)', [ip, ip]) if ip else ('', [])
    ids = []
    for target, sid, signature, category, severity, action, port, n, hits, first, last, top in con.execute(
            'SELECT target, sid, MAX(signature), MAX(category), MIN(severity), MAX(action), MAX(port),'
            ' COUNT(DISTINCT src), SUM(hits), MIN(first_seen), MAX(last_seen), GROUP_CONCAT(DISTINCT src)'
            ' FROM ids_alerts WHERE last_seen >= ?' + iclause + ' GROUP BY target, sid ORDER BY SUM(hits) DESC LIMIT ?',
            [since] + iargs + [ROW_LIMIT]):
        ids.append({'target': target, 'sid': sid, 'signature': signature, 'category': category,
                    'severity': severity, 'action': action, 'port': port, 'sources': n, 'hits': hits,
                    'first_seen': first, 'last_seen': last, 'top': (top or '').split(',')[:3]})
    kinds = Counter(e['kind'] for e in episodes)
    return {
        'episodes': episodes, 'sources': rows, 'folded': folded, 'truncated': truncated, 'group': group or '', 'ids': ids, 'kinds': kinds,
        'now': status.get('attacks_now', []), 'ids_status': status.get('ids', {}),
        'crowdsec_status': status.get('crowdsec', {}), 'autoblock': status.get('autoblock', {}),
        'threshold': cfg['attack_pps'], 'networks': networks,
    }


def source_networks(rows, cfg):
    """
    owner (AS) and network type of every source row (row['net']), and the rows per type and per AS, by
    addresses and by packets. Spoofed floods make the source addresses (and so this) meaningless.
    """
    if not cfg['ipdata_enabled']:
        return {'enabled': False}
    db = ipdata.IpData(hosting_asns=ipdata.parse_asns(cfg['hosting_asns']))
    if not db.available:
        # the outcome of the download (running, failed ...) tells why there is nothing yet
        return {'enabled': True, **db.status()}
    kinds, roles, owners = {}, {}, {}
    for row in rows:
        net = db.lookup(row['ip'])
        if net is None:
            continue
        row['net'] = net
        # asn 0: announced by nobody; None: the owner list is missing, so unknown
        kind = net['kind'] or ('unrouted' if net['asn'] == 0 else 'other')
        item = kinds.setdefault(kind, {'kind': kind, 'sources': 0, 'packets': 0, 'by_category': 0})
        item['sources'] += 1
        item['packets'] += row['packets']
        # only the AS category (an estimate) said what this is
        item['by_category'] += net['basis'] == 'AS category'
        if net['role']:
            role = roles.setdefault(net['role'], {'role': net['role'], 'sources': 0, 'packets': 0})
            role['sources'] += 1
            role['packets'] += row['packets']
        if net['asn']:
            owner = owners.setdefault(net['asn'], {'asn': net['asn'], 'name': net['as_name'], 'cc': net['cc'],
                                                   'category': net['category'], 'drop': net['drop'], 'sources': 0,
                                                   'packets': 0})
            owner['sources'] += 1
            owner['packets'] += row['packets']
    db.con.close()
    by_sources = sorted(owners.values(), key=lambda o: (-o['sources'], -o['packets']))[:15]
    return {'enabled': True, 'available': True, 'kinds': sorted(kinds.values(), key=lambda k: -k['sources']),
            'roles': sorted(roles.values(), key=lambda r: -r['sources']),
            'owners': by_sources, 'asns': len(owners), **db.status()}


def cmd_conditions(con, _hours, _ip, _extra):
    columns = ('id', 'ctype', 'value', 'target', 'duration', 'note', 'created', 'hits', 'last_hit') + bans.FIELDS
    active = dict(con.execute('SELECT cond, COUNT(*) FROM autoblocked GROUP BY cond').fetchall())
    # addresses that can still reach the number of matches: inside the window of a condition that asks for it
    waiting = dict(con.execute(
        'SELECT s.cond, COUNT(*) FROM strikes s JOIN conditions c ON c.id = s.cond'
        ' WHERE c.strikes > 1 AND s.first_seen >= ? - c.strike_window GROUP BY s.cond', (int(time.time()),)).fetchall())
    conditions = []
    for r in con.execute('SELECT %s FROM conditions ORDER BY id' % ', '.join(columns)):
        cond = dict(zip(columns, r), blocked_now=active.get(r[0], 0), waiting=waiting.get(r[0], 0))
        cond['ban_text'] = bans.describe(cond)
        conditions.append(cond)
    blocked = [dict(zip(('ip', 'cond', 'tbl', 'added', 'expires', 'reason', 'owned', 'span', 'offense'), r))
               for r in con.execute(
        # the repeat count only means something for an escalating ban (one changed to fixed keeps old rows)
        'SELECT a.ip, a.cond, a.tbl, a.added, a.expires, a.reason, a.owned, a.span,'
        " CASE WHEN c.ban = 'escalating' THEN o.count END FROM autoblocked a"
        ' LEFT JOIN conditions c ON c.id = a.cond'
        ' LEFT JOIN offenses o ON o.ip = a.ip AND o.cond = a.cond ORDER BY a.added DESC LIMIT ?', [ROW_LIMIT])]
    return {'conditions': conditions, 'blocked': blocked, 'table': common.AUTOBLOCK_TABLE,
            'total': con.execute('SELECT COUNT(DISTINCT ip) FROM autoblocked').fetchone()[0],
            'src_rules': src_rules(common.read_status()), 'attack_kinds': list(common.ATTACK_KINDS),
            'factors': list(bans.FACTORS)}


def src_rules(status):
    """
    The rules a "source at a rule limit" condition can name: those with a per source limit and a label
    (a condition follows the label, rule numbers change with every reload), from the collector's last poll
    """
    rules = {}
    for rule in status.get('rules', []):
        kinds = [k for k in common.SRC_LIMIT_KINDS if k in (rule.get('options') or {})]
        if not kinds or not rule.get('label'):
            continue
        item = rules.setdefault(rule['label'], {'label': rule['label'], 'nr': rule['nr'], 'kinds': [],
                                                'descr': rule.get('descr') or rule.get('text', '')[:80],
                                                'limits': {}})
        for kind in kinds:
            if kind not in item['kinds']:
                item['kinds'].append(kind)
                item['limits'][kind] = rule['options'][kind]
    return sorted(rules.values(), key=lambda r: r['nr'])


CONDITION_VALUE_RE = re.compile(r'[A-Za-z0-9_:.*-]{1,100}')
DIGITS_RE = re.compile(r'[0-9]{1,12}')


def cmd_cond_add(con, _hours, _ip, spec):
    """
    spec: <type>|<value>|<target LAN host or *>|<seconds, 0 = until removed>, then optionally the ban
    (lib/bans.py): |<fixed or escalating>|<factor>|<longest block, seconds>|<matches>|<within seconds>|<reset
    after seconds>; '_' stands for a space
    """
    parts = spec.split('|')
    if len(parts) == 4:
        parts += ['fixed', '2', '0', '1', '0', str(bans.DEFAULT_FORGET)]
    if len(parts) != 10 or parts[0] not in common.CONDITION_TYPES or not CONDITION_VALUE_RE.fullmatch(parts[1]):
        return {'status': 'error', 'message': 'invalid condition'}
    ctype, value, target, duration, ban = parts[:5]
    numbers = parts[5:]
    if not DIGITS_RE.fullmatch(duration) or not all(DIGITS_RE.fullmatch(n) for n in numbers):
        return {'status': 'error', 'message': 'invalid duration'}
    duration = int(duration)
    factor, longest, strikes, window, forget = [int(n) for n in numbers]
    error = bans.check(ban, factor, longest, strikes, window, forget, duration,
                       common.load_config()['poll_interval'])
    if error:
        return {'status': 'error', 'message': error}
    settings = {'duration': duration, 'ban': ban, 'factor': factor, 'max_duration': longest, 'strikes': strikes,
                'strike_window': window if strikes > 1 else 0, 'forget': forget}
    if ban == 'fixed':
        # what a fixed ban does not use, as the collector writes it for the automatic rules
        settings.update(factor=2, max_duration=0)
    if ctype == 'attack':
        value = value.replace('_', ' ')
    # a value its type never produces would be listed as a condition that never matches
    rule, _, kind = value.rpartition(':')
    if not (value in common.ATTACK_KINDS if ctype == 'attack' else DIGITS_RE.fullmatch(value) if ctype == 'ids'
            else value == '*' or DIGITS_RE.fullmatch(value) if ctype == 'ids_drop'
            else rule and kind in common.SRC_LIMIT_KINDS):
        return {'status': 'error', 'message': 'invalid condition'}
    if ctype in ('ids', 'ids_drop') and value != '*':
        value = str(int(value))     # the collector compares str(sid): "0042" would never match
    if target != '*':
        if ctype == 'src_limit':
            # a per source limit is not about one LAN host: the collector would ignore the target
            return {'status': 'error', 'message': 'invalid target'}
        try:
            addr = ipaddress.ip_address(target)
            target = (getattr(addr, 'ipv4_mapped', None) or addr).compressed
        except ValueError:
            return {'status': 'error', 'message': 'invalid target'}
    now = int(time.time())
    with con:
        row = con.execute('SELECT id FROM conditions WHERE ctype = ? AND value = ? AND target = ?',
                          (ctype, value, target)).fetchone()
        if row is None:
            con.execute('INSERT INTO conditions (ctype, value, target, created, %s) VALUES (?, ?, ?, ?, %s)'
                        % (', '.join(settings), ', '.join('?' * len(settings))),
                        (ctype, value, target, now) + tuple(settings.values()))
            return {'status': 'ok', 'created': True, 'updated': False}
        # the same condition again: only how long its addresses stay blocked changes (its ban), also for those
        # it holds (counted from their last match, as the collector does)
        con.execute('UPDATE conditions SET %s WHERE id = ?' % ', '.join('%s = ?' % k for k in settings),
                    tuple(settings.values()) + (row[0],))
        bans.respan(con, dict(settings, id=row[0]), now)
    return {'status': 'ok', 'created': False, 'updated': True, 'id': row[0]}


def cmd_cond_del(con, _hours, _ip, cid):
    """ remove a condition and take the addresses only it was holding out of the table """
    cid = int(cid)
    # the collector writes in one transaction per poll: take the write lock first so that nothing it adds
    # for this condition in between is left in the table without a condition holding it
    con.isolation_level = None
    con.execute('BEGIN IMMEDIATE')
    try:
        row = con.execute('SELECT ctype FROM conditions WHERE id = ?', (cid,)).fetchone()
        if row and row[0] == 'auto':
            # the collector would create it again with the next poll
            con.execute('ROLLBACK')
            return {'status': 'error', 'message': 'an automatic filtering rule: change the level under '
                                                  'Services: HostGuard: Settings (Automatic filtering)'}
        ips = set(r[0] for r in con.execute('SELECT ip FROM autoblocked WHERE cond = ? AND owned = 1', (cid,)))
        still = set(r[0] for r in con.execute('SELECT ip FROM autoblocked WHERE cond != ?', (cid,)))
        gone = sorted(ips - still)
        if gone and not pfstats.table_change(common.AUTOBLOCK_TABLE, 'delete', gone):
            # nothing changes: the condition still holds its addresses and can be removed again
            con.execute('ROLLBACK')
            return {'status': 'error', 'message': 'pfctl could not remove the addresses from <%s>'
                                                  % common.AUTOBLOCK_TABLE}
        con.execute('DELETE FROM autoblocked WHERE cond = ?', (cid,))
        con.execute('DELETE FROM conditions WHERE id = ?', (cid,))
        con.execute('DELETE FROM offenses WHERE cond = ?', (cid,))
        con.execute('DELETE FROM strikes WHERE cond = ?', (cid,))
        con.execute('COMMIT')
    except Exception:
        con.execute('ROLLBACK')
        raise
    return {'status': 'ok', 'released': len(gone)}


def cmd_clear(con, *_args):
    # block conditions and what they hold are configuration, not collected data: they stay
    with con:
        for table in ('hosts', 'ts_host', 'ts_port', 'flows', 'services', 'lateral', 'l2bind', 'alerts',
                      'ts_pf', 'tablehits', 'blocked', 'ts_blocked', 'ts_rules', 'srclimits', 'blocked_reasons',
                      'shaperhits', 'attacks', 'ids_alerts', 'crowdsec'):
            con.execute('DELETE FROM %s' % table)
    try:
        con.execute('VACUUM')
    except sqlite3.OperationalError:
        # the data is gone already; the file shrinks with a later clear (the collector was writing)
        return {'status': 'ok', 'vacuum': False}
    return {'status': 'ok', 'vacuum': True}


COMMANDS = {
    'summary': cmd_summary, 'hosts': cmd_hosts, 'ports': cmd_ports, 'flows': cmd_flows,
    'services': cmd_services, 'alerts': cmd_alerts, 'ack': cmd_ack, 'lateral': cmd_lateral,
    'l2': cmd_l2, 'limits': cmd_limits, 'blocked': cmd_blocked, 'status': cmd_status, 'clear': cmd_clear,
    'attacks': cmd_attacks, 'conditions': cmd_conditions, 'cond_add': cmd_cond_add, 'cond_del': cmd_cond_del,
}


def check_extra(command, extra):
    if command == 'ack':
        return extra if extra == 'all' or DIGITS_RE.fullmatch(extra) else None
    if command == 'alerts':
        return extra if extra in ('open', 'all') else 'all'
    if command == 'cond_add':
        return extra if '|' in extra else None
    if command == 'cond_del':
        return extra if DIGITS_RE.fullmatch(extra) else None
    if command == 'attacks':
        return extra if GROUP_RE.fullmatch(extra) else None
    return extra if extra in ('in', 'out') else None


def main(argv):
    # configd passes the command alone for actions without parameters (clear)
    command = argv[0] if argv else ''
    hours, ip, extra = (argv[1:] + ['24', '-', '-'])[:3]
    if command not in COMMANDS:
        return {'status': 'error', 'message': 'unknown command'}
    try:
        hours = min(max(int(hours), 1), 24 * 366)
    except ValueError:
        hours = 24
    if ip in ('-', '', '*'):
        ip = None
    else:
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            return {'status': 'error', 'message': 'invalid address'}
    extra = check_extra(command, extra)
    if command == 'ack' and extra is None:
        return {'status': 'error', 'message': 'invalid alert id'}
    if command in ('cond_add', 'cond_del') and extra is None:
        return {'status': 'error', 'message': 'invalid condition'}
    try:
        con = common.connect()
        try:
            result = COMMANDS[command](con, hours, ip, extra)
        finally:
            con.close()
    except sqlite3.OperationalError as exc:
        # the collector holds the database for a long poll: an answer the GUI can show, not a traceback
        return {'status': 'error', 'message': 'database busy (%s), try again' % exc}
    result.setdefault('status', 'ok')
    return result


if __name__ == '__main__':
    print(json.dumps(main(sys.argv[1:])))
