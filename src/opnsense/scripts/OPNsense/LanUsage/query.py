#!/usr/local/bin/python3
"""
    Copyright (c) 2026 Onur Berkay <onurberkay@sakla.app>
    All rights reserved. (BSD 2-Clause, see LICENSE)

    Read side of the LAN usage database, called by configd:
        query.py <command> <hours> <ip|-> <extra|->
    commands: summary, hosts, ports, flows, services, alerts, lateral, l2, limits, blocked, status, ack, clear
    extra: in|out (ports, flows), open|all (alerts), <id>|all (ack)
    Prints JSON.
"""
import ipaddress
import json
import os
import re
import sys
import time
from collections import Counter, defaultdict

from lib import common, detect, pfstats

ROW_LIMIT = 5000


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
    hosts = [
        {'ip': host, 'states': states, 'detail': detail or '', 'new_rate': rate or 0,
         'pct': round(states * 100.0 / cfg['host_state_limit'], 1) if cfg['host_state_limit'] else 0}
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
    for f in status.get('src_limited', []):
        if ip and f['ip'] != ip:
            continue
        src[(f['ip'], f['rule'], f['kind'])] = dict(f, now=True, peak=f['value'], hits=0, first_seen=0, last_seen=0)
    sclause, sargs = (' AND ip = ?', [ip]) if ip else ('', [])
    lan_hosts = set(r[0] for r in con.execute('SELECT ip FROM hosts'))
    for host, nr, kind, descr, limit, peak, first, last, hits in con.execute(
            'SELECT ip, nr, kind, descr, limit_value, peak, first_seen, last_seen, hits FROM srclimits'
            ' WHERE last_seen >= ?' + sclause, [since] + sargs):
        row = src.setdefault((host, nr, kind), {
            'ip': host, 'lan': host in lan_hosts, 'rule': nr, 'descr': descr, 'kind': kind, 'limit': limit,
            'value': None, 'pct': None, 'at_limit': False, 'now': False})
        row.update(peak=max(peak or 0, row.get('peak') or 0), hits=hits, first_seen=first, last_seen=last)
    src_limits = sorted(src.values(), key=lambda r: (not r['now'], -(r['pct'] or 0), -(r['last_seen'] or 0)))

    return {
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
        # "others (N)" stands for N folded remotes
        folded = re.match(r'^others \((\d+)\)$', remote)
        remotes.setdefault((host, d), {})[remote] = int(folded.group(1)) if folded else 1
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
            hosts[host]['sources' if d == 'in' else 'targets'] = sum(items.values())
    lan_hosts = set(r[0] for r in con.execute('SELECT ip FROM hosts'))
    labels = (status.get('sampling') or {}).get('labels', {})
    flows = [
        {'ip': host, 'dir': d, 'proto': proto, 'port': port, 'remote': remote, 'packets': packets,
         'samples': samples, 'first_seen': first, 'last_seen': last, 'internal': remote in lan_hosts,
         'name': detect.port_name(port, proto) if proto in ('tcp', 'udp') else '', 'reason': reason or '',
         'iface': ('%s (%s)' % (iface, labels[iface]) if labels.get(iface) else iface or '')}
        for host, d, proto, port, remote, first, last, packets, samples, reason, iface in con.execute(
            'SELECT ip, dir, proto, port, remote, MIN(first_seen), MAX(last_seen) AS l, SUM(packets), SUM(samples),'
            ' MAX(reason), MAX(iface)'
            ' FROM blocked WHERE day >= ? AND last_seen >= ?' + clause + dclause
            + ' GROUP BY ip, dir, proto, port, remote ORDER BY SUM(packets) DESC LIMIT ?',
            [since - since % 86400, since] + args + dargs + [ROW_LIMIT])
    ]
    reasons, per_host_reasons = Counter(), defaultdict(Counter)
    for host, d, reason, packets in con.execute(
            'SELECT ip, dir, reason, SUM(packets) FROM blocked_reasons WHERE day >= ? AND last_seen >= ?'
            + clause + dclause + ' GROUP BY ip, dir, reason', [since - since % 86400, since] + args + dargs):
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
    lan_hosts = {row[0] for row in con.execute('SELECT ip FROM hosts')}
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


def cmd_clear(con, *_args):
    with con:
        for table in ('hosts', 'ts_host', 'ts_port', 'flows', 'services', 'lateral', 'l2bind', 'alerts',
                      'ts_pf', 'tablehits', 'blocked', 'ts_blocked', 'ts_rules', 'srclimits', 'blocked_reasons'):
            con.execute('DELETE FROM %s' % table)
    con.execute('VACUUM')
    return {'status': 'ok'}


COMMANDS = {
    'summary': cmd_summary, 'hosts': cmd_hosts, 'ports': cmd_ports, 'flows': cmd_flows,
    'services': cmd_services, 'alerts': cmd_alerts, 'ack': cmd_ack, 'lateral': cmd_lateral,
    'l2': cmd_l2, 'limits': cmd_limits, 'blocked': cmd_blocked, 'status': cmd_status, 'clear': cmd_clear,
}


def check_extra(command, extra):
    if command == 'ack':
        return extra if extra == 'all' or extra.isdigit() else None
    if command == 'alerts':
        return extra if extra in ('open', 'all') else 'all'
    return extra if extra in ('in', 'out') else None


def main(argv):
    args = (argv + ['', '24', '-', '-'])[:4]
    command, hours, ip, extra = args
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
    con = common.connect()
    try:
        result = COMMANDS[command](con, hours, ip, extra)
    finally:
        con.close()
    result.setdefault('status', 'ok')
    return result


if __name__ == '__main__':
    print(json.dumps(main(sys.argv[1:])))
