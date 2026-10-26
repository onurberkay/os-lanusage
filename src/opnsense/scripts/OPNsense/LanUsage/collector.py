#!/usr/local/bin/python3
"""
    Copyright (c) 2026 Onur Berkay <onurberkay@sakla.app>
    All rights reserved. (BSD 2-Clause, see LICENSE)

    LAN usage collector daemon.

    Polls the pf state table and records, per LAN host:
      - inbound  ("in"):  ports the host served (someone connected to it)
      - outbound ("out"): ports the host connected to elsewhere
    Ports that LAN hosts serve are probed in the background to name the
    service behind them.

    It also watches for things that may indicate an attack or abuse:
      - LAN to LAN connections (lateral movement), including attempts the
        rules blocked (firewall log) and port / host scans between LAN hosts
      - MAC addresses using more than one IP, a MAC whose IP changed and an
        IP that moved to another MAC (IP theft, ARP spoofing, IP conflicts)
"""
import json
import os
import signal
import sys
import syslog
import threading
import time
from collections import Counter, defaultdict, deque
from concurrent.futures import ThreadPoolExecutor

from lib import common, detect, filterlog, l2, pfstate, pfstats, sampler

PORT_PROTOS = ('tcp', 'udp', 'sctp')
TCP_ANSWERED = {'ESTABLISHED', 'FIN_WAIT_1', 'FIN_WAIT_2', 'CLOSE_WAIT', 'CLOSING', 'LAST_ACK'}
SCAN_WINDOW = 300


def log(priority, message):
    syslog.syslog(priority, message)


def is_answered(proto, tcpstate, pkts):
    """ did the responder really answer (not a scan / dead target / RST)? """
    if proto == 'tcp':
        if any(part in TCP_ANSWERED for part in tcpstate.split(':')):
            return True
        return pkts[1] >= 2     # SYN-ACK + more, i.e. not just a RST
    return pkts[1] >= 1


def _add(table, key, conns, nbytes):
    item = table.get(key)
    if item is None:
        table[key] = [conns, nbytes]
    else:
        item[0] += conns
        item[1] += nbytes


TABLE_MEANING = (
    ('virusprot', 'high', 'exceeded a connection limit of a firewall rule (overload table)'),
    ('sshlockout', 'high', 'too many failed SSH / web GUI logins against the firewall'),
    ('crowdsec', 'critical', 'banned by CrowdSec'),
)


class Collector:
    def __init__(self, cfg, stop=None):
        self.cfg = cfg
        self.con = common.connect()
        self.prev = {}          # connection key -> (bytes, counted, answered)
        self.lan, self.own = common.resolve_networks(cfg)
        self.resolved = time.time()
        self.pruned = 0
        self.trusted = common.NetworkSet(common.parse_network_list(cfg['lateral_trusted']))
        self.ignored_macs = common.parse_mac_list(cfg['l2_ignore_macs'])
        self.scan = defaultdict(deque)      # LAN source -> deque((ts, dst, proto, port))
        self.filterlog = filterlog.FilterLogReader() if cfg['lateral_blocked'] else None
        self.blocked_last = 0
        # last MAC seen per IP, survives restarts through the l2bind table
        self.ip_mac = dict(self.con.execute('SELECT ip, mac FROM l2bind ORDER BY last_seen').fetchall())
        # raw pf states per LAN host (what consumes the state table), rebuilt every poll
        self.raw_states = 0
        self.host_states = Counter()
        self.host_ports = Counter()     # (host, dir, proto, port) -> states
        self.last_poll = None
        self.pf = {}
        self.pf_counters = None
        self.pf_limits = {}
        self.limits_read = 0
        self.rules = []
        self.rules_read = 0
        self.tables = []
        self.tables_read = 0
        self.table_members = defaultdict(set)
        for tbl, ip in self.con.execute('SELECT tbl, ip FROM tablehits WHERE last_seen >= ?',
                                        (int(time.time()) - 600,)):
            self.table_members[tbl].add(ip)
        # transparent bridge: the firewall barely talks to the hosts, listen to ARP / ND instead
        self.bridges = l2.bridge_info()
        self.arp_entries = 0
        self.sniffer = None
        if cfg['l2_enabled'] and cfg['l2_source'] in ('both', 'sniff'):
            devices = self.sniff_devices()
            if devices:
                self.sniffer = l2.Sniffer(devices, stop or threading.Event())
                self.sniffer.start()
        # blocked traffic without firewall logging: bounded sampling + block rule counters
        self.sample_devices = self.capture_devices() if cfg['sample_enabled'] else []
        self.sample_info = {}
        self.last_sample = None
        self.rule_packets = {}
        self.rules_last = None
        self.rule_activity = []
        self.src_limited = []
        # block reasons: tables referenced by block rules, sources at a limit, last counter increases
        self.reason_tables = []
        self.reason_read = 0
        self.src_at_limit = {}
        self.last_deltas = {}
        self.iface_labels = common.interface_labels()

    def capture_devices(self):
        names = [x.strip() for x in self.cfg['sample_interfaces'].split(',') if x.strip()]
        devices = common.interface_devices(names) if names else self.sniff_devices()
        if not names:
            # in a bridge listen on every member of it, attacks from outside arrive on the upstream member
            for members in self.bridges.values():
                if any(dev in members for dev in devices):
                    devices += [m for m in members if m not in devices]
        result = []
        for dev in devices:
            for item in self.bridges.get(dev, [dev]):
                if item not in result:
                    result.append(item)
        return result

    def sniff_devices(self):
        names = [x.strip() for x in self.cfg['interfaces'].split(',') if x.strip()]
        devices = []
        for dev in common.interface_devices(names) or [m for ms in self.bridges.values() for m in ms]:
            # bridge members always see the bridged frames, the bridge device itself may not
            for item in self.bridges.get(dev, [dev]):
                if item not in devices:
                    devices.append(item)
        return devices

    def refresh_networks(self):
        self.lan, self.own = common.resolve_networks(self.cfg)
        self.resolved = time.time()

    def answered(self, proto, tcpstate, pkts):
        """ only count connections the responder actually answered (drops scans / dead targets) """
        return not self.cfg['answered_only'] or is_answered(proto, tcpstate, pkts)

    def is_lan_host(self, ip):
        return ip in self.lan and not (self.cfg['ignore_self'] and ip in self.own)

    def alert(self, now, atype, severity, key, **kwargs):
        if common.raise_alert(self.con, now, atype, severity, key, **kwargs):
            log(syslog.LOG_WARNING, 'ALERT [%s] %s: %s' % (severity, atype, kwargs.get('detail', '')))

    def _pick(self, candidates):
        """ prefer the address inside the LAN (and not the firewall) when NAT shows two """
        fallback = None
        for addr in candidates:
            if addr[0] in self.lan:
                if addr[0] not in self.own:
                    return addr
                fallback = fallback or addr
        return fallback or candidates[0]

    def snapshot(self):
        conns = {}
        ignore_self = self.cfg['ignore_self']
        host_states, host_ports = Counter(), Counter()
        raw = 0
        for st in pfstate.iter_states():
            if st is None:
                continue
            raw += 1
            init, resp = self._pick(st['init']), self._pick(st['resp'])
            if ignore_self and init[0] in self.own:
                continue    # firewall originated (incl. our own probes)
            i_lan = init[0] in self.lan
            r_lan = self.is_lan_host(resp[0])
            if not (i_lan or r_lan):
                continue
            port = resp[1] if st['proto'] in PORT_PROTOS else 0
            if i_lan:
                host_states[init[0]] += 1
                host_ports[(init[0], 'out', st['proto'], port)] += 1
            if r_lan:
                host_states[resp[0]] += 1
                host_ports[(resp[0], 'in', st['proto'], port)] += 1
            key = (st['proto'], init[0], init[1], resp[0], resp[1])
            real = is_answered(st['proto'], st['tcpstate'], st['pkts'])
            ok = real or not self.cfg['answered_only']
            item = conns.get(key)
            if item is None:
                conns[key] = [st['bytes'], ok, i_lan, r_lan, real]
            else:   # same connection seen on another interface
                item[0] = max(item[0], st['bytes'])
                item[1] = item[1] or ok
                item[4] = item[4] or real
        self.raw_states, self.host_states, self.host_ports = raw, host_states, host_ports
        return conns

    def poll(self):
        started = time.time()
        now = int(started)
        bucket, hour, day = now - now % 300, now - now % 3600, now - now % 86400
        track_remote = self.cfg['track_remote']
        # sample attempts first, then read the states they should have created
        samples = sampler.capture(self.sample_devices, self.cfg['sample_seconds'], self.cfg['sample_packets']) \
            if self.sample_devices else {}
        conns = self.snapshot()
        ts_host, ts_port, flows, hosts, lateral = {}, {}, {}, {}, {}
        new_by_host = Counter()
        prev, current = self.prev, {}
        for key, (nbytes, ok, i_lan, r_lan, real) in conns.items():
            old = prev.get(key)
            counted = old is not None and old[1]
            proto, iip, _, rip, rport = key
            port = rport if proto in PORT_PROTOS else 0
            if old is None:
                if i_lan:
                    new_by_host[iip] += 1
                if r_lan:
                    new_by_host[rip] += 1
            if i_lan and r_lan:
                # LAN to LAN: every attempt counts, answered or not (scans are exactly that)
                was_answered = old is not None and old[2]
                # [attempts, answered, bytes, blocked]
                item = lateral.setdefault((day, iip, rip, proto, port), [0, 0, 0, 0])
                item[0] += 1 if old is None else 0
                item[1] += 1 if real and not was_answered else 0
                if old is None:
                    self.scan[iip].append((now, rip, proto, port))
            if not (ok or counted):
                current[key] = (nbytes, False, real)
                continue
            current[key] = (nbytes, True, real or (old is not None and old[2]))
            if counted:
                new, delta = 0, nbytes - old[0]
                if delta < 0:
                    delta = nbytes
            else:
                new, delta = 1, nbytes
            if i_lan and r_lan:
                lateral[(day, iip, rip, proto, port)][2] += delta
            sides = []
            if i_lan:
                sides.append((iip, 'out', rip))
            if r_lan:
                sides.append((rip, 'in', iip))
            for ip, direction, remote in sides:
                _add(ts_host, (bucket, ip, direction), new, delta)
                _add(ts_port, (hour, ip, direction, proto, port), new, delta)
                _add(flows, (day, ip, direction, proto, port, remote if track_remote else '*'), new, delta)
                host = hosts.setdefault(ip, [0, 0, 0, 0, 0])
                host[0] += 1
                if direction == 'in':
                    host[1] += new
                    host[3] += delta
                else:
                    host[2] += new
                    host[4] += delta
        self.prev = current
        # new connections per second; the first poll sees every existing state as new
        rates = {}
        if self.last_poll is not None and now > self.last_poll:
            rates = {h: n / float(now - self.last_poll) for h, n in new_by_host.items()}
        self.last_poll = now
        self.read_blocked(now, day, lateral)
        blocked, blocked_hosts, blocked_reasons, interval = self.classify_samples(now, day, samples, conns, lateral)
        self.store(now, ts_host, ts_port, flows, hosts, lateral)
        details = self.state_details(rates)
        with self.con:
            self.store_blocked(now, day, bucket, blocked, blocked_hosts, blocked_reasons)
            self.blocked_alerts(now, blocked, blocked_hosts, blocked_reasons, interval)
            self.store_host_states(now, rates, details)
            scanners = self.scan_alerts(now)
            self.lateral_alerts(now, day, lateral, scanners)
            self.host_limit_alerts(now, rates, details)
            self.pf_check(now, details, rates)
            if self.cfg['l2_enabled']:
                self.poll_l2(now)
        self.write_status(now, time.time() - started, len(conns))
        return len(conns)

    #  blocked traffic (no firewall logging needed)

    def classify_samples(self, now, day, samples, conns, lateral):
        """
        A sampled attempt without a matching pf state was blocked (or dropped by a limit).
        Each sampled packet stands for interval / capture time packets.
        returns ({(ip, dir, proto, port, remote): [estimated, sampled, reason, device]},
                 {(ip, dir): estimated}, {(ip, dir, reason): estimated}, interval)
        """
        interval = float(now - self.last_sample) if self.last_sample else float(self.cfg['poll_interval'])
        self.last_sample = now
        blocked, per_host, per_reason, info = {}, Counter(), Counter(), {}
        if not samples:
            self.sample_info = {}
            return blocked, per_host, per_reason, interval
        if not self.reason_read:
            # first poll: know the block tables before the first classification
            self.refresh_reason_tables(now, pfstats.read_rules())
        keys = set(conns)
        icmp_pairs = set((k[1], k[3]) for k in conns if k[0] in ('icmp', 'ipv6-icmp'))
        reasons = {}
        for dev, res in samples.items():
            scale = max(1.0, interval / res['elapsed']) if res.get('elapsed') else 1.0
            count = 0
            for proto, src, sport, dst, dport in res.get('packets', []):
                if src in self.own or dst in self.own:
                    continue
                s_lan, d_lan = src in self.lan, dst in self.lan
                if not (s_lan or d_lan):
                    continue
                if proto in ('icmp', 'ipv6-icmp'):
                    passed = (src, dst) in icmp_pairs
                else:
                    passed = (proto, src, sport, dst, dport) in keys or (proto, dst, dport, src, sport) in keys
                if passed:
                    continue
                count += 1
                port = dport if proto in PORT_PROTOS else 0
                reason = reasons.get((src, dst))
                if reason is None:
                    reason = reasons[(src, dst)] = self.block_reason(src, dst, not s_lan)
                if s_lan and d_lan:
                    item = lateral.setdefault((day, src, dst, proto, port), [0, 0, 0, 0])
                    item[0] += scale
                    item[3] += scale
                    self.scan[src].append((now, dst, proto, port))
                for ip, direction, remote, inside in ((src, 'out', dst, s_lan), (dst, 'in', src, d_lan)):
                    if inside:
                        item = blocked.setdefault((ip, direction, proto, port, remote), [0.0, 0, reason, dev])
                        item[0] += scale
                        item[1] += 1
                        per_host[(ip, direction)] += scale
                        per_reason[(ip, direction, reason)] += scale
            info[dev] = {'lines': res.get('lines', 0), 'elapsed': res.get('elapsed', 0), 'capped': res.get('capped'),
                         'blocked': count, 'scale': round(scale, 1), 'error': res.get('error', ''),
                         'label': self.iface_labels.get(dev, '')}
        self.sample_info = info
        return blocked, per_host, per_reason, interval

    def block_reason(self, src, dst, from_outside):
        """
        Best known cause of a blocked attempt, without firewall logging:
        a table a block rule matches on, a per source limit, a full state table, a bogon source,
        otherwise no pass rule matched (default deny or a block rule we cannot name).
        """
        for ref in self.reason_tables:
            if (src if ref['side'] == 'from' else dst) in ref['index']:
                return '<%s> rule @%d %s' % (ref['table'], ref['nr'], ref['descr'])
        limit = self.src_at_limit.get(src)
        if limit is not None:
            return '%s limit rule @%d %s' % (limit['kind'], limit['rule'], limit['descr'])
        if self.last_deltas.get('memory'):
            return 'state table full (pf memory limit)'
        if from_outside and common.is_bogon(src):
            return 'private / bogon source'
        return 'no pass rule (default deny or a block rule)'

    def refresh_reason_tables(self, now, rules):
        """ tables used by block rules (CrowdSec, virusprot, bogons, aliases ...) with their entries """
        self.reason_read = now
        descriptions = pfstats.rule_descriptions()
        cache, refs = {}, []
        for rule in rules:
            if rule['action'] != 'block':
                continue
            for side, table in rule.get('tables', []):
                if table not in cache:
                    cache[table] = common.AddrIndex(pfstats.table_entries(table))
                if cache[table].size:
                    refs.append({'nr': rule['nr'], 'side': side, 'table': table, 'index': cache[table],
                                 'descr': descriptions.get(rule['label'], '') or rule['text'][:60]})
        self.reason_tables = refs

    def store_blocked(self, now, day, bucket, blocked, per_host, per_reason):
        if not blocked:
            return
        # keep the 20 busiest remotes per host/port, fold the rest (big DDoS) into "others"
        grouped = defaultdict(list)
        for (ip, direction, proto, port, remote), value in blocked.items():
            grouped[(ip, direction, proto, port)].append((value[0], remote, value[1], value[2], value[3]))
        rows = []
        for (ip, direction, proto, port), items in grouped.items():
            items.sort(key=lambda i: -i[0])
            if not self.cfg['track_remote']:
                items = [(sum(i[0] for i in items), '*', sum(i[2] for i in items), items[0][3], items[0][4])]
            elif len(items) > 20:
                rest = items[20:]
                why = Counter()
                for i in rest:
                    why[(i[3], i[4])] += i[0]
                reason, dev = why.most_common(1)[0][0]
                items = items[:20] + [(sum(i[0] for i in rest), 'others (%d)' % len(rest),
                                       sum(i[2] for i in rest), reason, dev)]
            for est, remote, sampled, reason, dev in items:
                rows.append((day, ip, direction, proto, port, remote, now, now, int(round(est)), sampled, reason, dev))
        self.con.executemany(
            """INSERT INTO blocked (day, ip, dir, proto, port, remote, first_seen, last_seen, packets, samples,
                                    reason, iface)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT (day, ip, dir, proto, port, remote) DO UPDATE SET last_seen = excluded.last_seen,
                   packets = packets + excluded.packets, samples = samples + excluded.samples,
                   reason = excluded.reason, iface = excluded.iface""", rows)
        self.con.executemany(
            """INSERT INTO ts_blocked (ts, ip, dir, packets) VALUES (?, ?, ?, ?)
               ON CONFLICT (ts, ip, dir) DO UPDATE SET packets = packets + excluded.packets""",
            [(bucket, ip, direction, int(round(est))) for (ip, direction), est in per_host.items()])
        self.con.executemany(
            """INSERT INTO blocked_reasons (day, ip, dir, reason, packets, last_seen) VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT (day, ip, dir, reason) DO UPDATE SET packets = packets + excluded.packets,
                   last_seen = excluded.last_seen""",
            [(day, ip, direction, reason, int(round(est)), now) for (ip, direction, reason), est in per_reason.items()])

    @staticmethod
    def reason_text(per_reason, ip, direction):
        mine = [(est, reason) for (rip, rdir, reason), est in per_reason.items() if rip == ip and rdir == direction]
        total = sum(est for est, _ in mine) or 1
        return ', '.join('%d%% %s' % (round(est * 100 / total), reason) for est, reason in sorted(mine, reverse=True)[:3])

    def blocked_alerts(self, now, blocked, per_host, per_reason, interval):
        hour = now - now % 3600
        for (ip, direction), est in per_host.items():
            pps = est / interval if interval else 0
            limit = self.cfg['blocked_out_pps'] if direction == 'out' else self.cfg['blocked_in_pps']
            if pps < limit:
                continue
            ports, remotes = Counter(), set()
            for (bip, bdir, proto, port, remote), value in blocked.items():
                if bip == ip and bdir == direction:
                    ports['%s/%d' % (proto, port) if proto in PORT_PROTOS else proto] += value[0]
                    remotes.add(remote)
            top = ', '.join('%s %s' % (p, detect.port_name(int(p.split('/')[1]), p.split('/')[0]) if '/' in p else '')
                            for p, _ in ports.most_common(3))
            why = self.reason_text(per_reason, ip, direction)
            if direction == 'out':
                self.alert(now, 'blocked_out', 'high', 'blocked_out:%s:%d' % (ip, hour), ip=ip, reopen=False,
                           detail='%s sends ~%.0f pkt/s that the firewall blocks, to %d destinations (top: %s; why: %s): '
                                  'possible spam, scan or compromised host (estimated from samples)'
                                  % (ip, pps, len(remotes), top, why))
            else:
                self.alert(now, 'blocked_in', 'critical' if pps >= 10 * limit else 'medium',
                           'blocked_in:%s:%d' % (ip, hour), ip=ip, reopen=False,
                           detail='~%.0f pkt/s towards %s blocked, from %d sources (top: %s; why: %s): attack being '
                                  'blocked (estimated from samples)' % (pps, ip, len(remotes), top, why))

    def rule_counters(self, now, rules):
        """ exact blocked packets per block rule from the pf rule counters (rules sharing a label are summed) """
        interval = float(now - self.rules_last) if self.rules_last else 0.0
        self.rules_last = now
        descriptions = pfstats.rule_descriptions()
        grouped = {}
        for rule in rules:
            if rule['action'] != 'block':
                continue
            key = rule['label'] or 'nr:%d' % rule['nr']
            item = grouped.setdefault(key, {'nr': rule['nr'], 'label': rule['label'], 'text': rule['text'],
                                            'descr': descriptions.get(rule['label'], ''), 'packets': 0})
            item['packets'] += rule['packets']
        bucket, hour = now - now % 300, now - now % 3600
        activity, rows, previous = [], [], self.rule_packets
        self.rule_packets = {key: item['packets'] for key, item in grouped.items()}
        for key, item in grouped.items():
            before = previous.get(key)
            delta = item['packets'] - before if before is not None and item['packets'] >= before else 0
            item['pps'] = round(delta / interval, 1) if interval else 0.0
            activity.append(item)
            if delta:
                rows.append((bucket, item['nr'], key, item['descr'], delta))
            if item['pps'] >= self.cfg['rule_block_pps']:
                name = item['descr'] or item['text'][:80]
                self.alert(now, 'rule_blocking', 'medium', 'rule_blocking:%s:%d' % (key, hour), reopen=False,
                           peer=str(item['nr']),
                           detail='block rule @%d (%s) drops ~%.0f pkt/s' % (item['nr'], name, item['pps']))
        self.con.executemany(
            """INSERT INTO ts_rules (ts, nr, label, descr, packets) VALUES (?, ?, ?, ?, ?)
               ON CONFLICT (ts, label, nr) DO UPDATE SET packets = packets + excluded.packets""", rows)
        activity.sort(key=lambda r: (-r['pps'], -r['packets']))
        self.rule_activity = activity[:50]

    #  limits

    def state_details(self, rates):
        """ host -> (short "where do the states go" text, inbound share %) for the busiest hosts """
        busy = set(h for h, _ in self.host_states.most_common(200))
        busy.update(h for h, n in self.host_states.items() if n >= self.cfg['host_state_limit'])
        busy.update(h for h, r in rates.items() if r >= self.cfg['host_rate_limit'])
        per_host = defaultdict(list)
        for (host, direction, proto, port), count in self.host_ports.items():
            if host in busy:
                per_host[host].append((count, direction, proto, port))
        details = {}
        for host, items in per_host.items():
            items.sort(reverse=True)
            inbound = sum(c for c, d, _, _ in items if d == 'in')
            share = inbound * 100 // max(1, self.host_states[host])
            parts = ['%s %s %d' % (d, '%s/%d' % (p, port) if p in PORT_PROTOS else p, c) for c, d, p, port in items[:3]]
            details[host] = ('%s; %d%% inbound' % (', '.join(parts), share), share)
        return details

    def store_host_states(self, now, rates, details):
        self.con.execute('UPDATE hosts SET states = 0, new_rate = 0 WHERE states != 0 OR new_rate != 0')
        self.con.executemany(
            """INSERT INTO hosts (ip, first_seen, last_seen, states, state_detail, new_rate) VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT (ip) DO UPDATE SET states = excluded.states, state_detail = excluded.state_detail,
                   new_rate = excluded.new_rate""",
            [(h, now, now, n, details.get(h, ('', 0))[0], round(rates.get(h, 0.0), 1))
             for h, n in self.host_states.items()])

    def top_hosts_text(self, rates):
        parts = ['%s (%d states)' % (h, n) for h, n in self.host_states.most_common(3)]
        fast = sorted(rates.items(), key=lambda x: -x[1])[:3]
        if fast and fast[0][1] >= 1:
            parts.append('fastest: ' + ', '.join('%s (%.0f new/s)' % (h, r) for h, r in fast if r >= 1))
        return '; '.join(parts) or 'no LAN host stands out'

    def host_limit_alerts(self, now, rates, details):
        hour = now - now % 3600
        limit, rate_limit = self.cfg['host_state_limit'], self.cfg['host_rate_limit']
        for host, count in self.host_states.items():
            if count >= limit:
                text, inbound = details.get(host, ('', 0))
                hint = 'mostly inbound: possible (D)DoS target' if inbound >= 50 else \
                    'mostly outbound: possible flood, abuse or compromised host'
                self.alert(now, 'host_states', 'critical' if count >= 2 * limit else 'high',
                           'host_states:%s:%d' % (host, hour), ip=host, reopen=False,
                           detail='%s holds %d firewall states (limit %d), %s. %s' % (host, count, limit, hint, text))
        for host, rate in rates.items():
            if rate >= rate_limit:
                text, inbound = details.get(host, ('', 0))
                hint = 'mostly inbound: possible (D)DoS target' if inbound >= 50 else \
                    'mostly outbound: possible flood, scan or compromised host'
                self.alert(now, 'host_rate', 'high', 'host_rate:%s:%d' % (host, hour), ip=host, reopen=False,
                           detail='%s opens %.0f new connections/s (limit %d), %s. %s'
                                  % (host, rate, rate_limit, hint, text))

    def pf_check(self, now, details, rates):
        info = pfstats.read_info()
        if now - self.limits_read >= 300:
            self.pf_limits = pfstats.read_limits() or self.pf_limits
            self.limits_read = now
        counters = info['counters']
        deltas = {}
        if self.pf_counters is not None:
            for name, value in counters.items():
                delta = value - self.pf_counters.get(name, value)
                if delta > 0:
                    deltas[name] = delta
        self.pf_counters = counters
        states_limit = self.pf_limits.get('states', 0)
        src_limit = self.pf_limits.get('src-nodes', 0)
        self.pf = {'states': info['states'], 'states_limit': states_limit,
                   'src_nodes': info['src_nodes'], 'src_limit': src_limit, 'counters': counters}

        bucket, hour = now - now % 300, now - now % 3600
        row = self.con.execute('SELECT states, src_nodes, counters FROM ts_pf WHERE ts = ?', (bucket,)).fetchone()
        merged = json.loads(row[2]) if row and row[2] else {}
        for name, delta in deltas.items():
            merged[name] = merged.get(name, 0) + delta
        self.con.execute(
            'INSERT OR REPLACE INTO ts_pf (ts, states, states_limit, src_nodes, src_limit, counters) VALUES (?, ?, ?, ?, ?, ?)',
            (bucket, max(info['states'], row[0] if row else 0), states_limit,
             max(info['src_nodes'], row[1] if row else 0), src_limit, json.dumps(merged)))

        self.last_deltas = deltas
        rules = pfstats.read_rules()
        self.rule_counters(now, rules)
        self.check_src_nodes(now, rules)
        if self.sample_devices and now - self.reason_read >= 60:
            self.refresh_reason_tables(now, rules)

        if states_limit:
            pct = info['states'] * 100.0 / states_limit
            if pct >= self.cfg['state_warn_pct']:
                self.alert(now, 'state_table', 'critical' if pct >= 95 else 'high', 'state_table:%d' % hour,
                           reopen=False, detail='pf state table at %.0f%% (%d of %d). Top LAN hosts: %s'
                                                % (pct, info['states'], states_limit, self.top_hosts_text(rates)))
        for name, delta in deltas.items():
            if name in pfstats.WATCHED_COUNTERS:
                severity, meaning = pfstats.WATCHED_COUNTERS[name]
                culprit = self.src_limit_text(name) if name in pfstats.SRC_COUNTERS else ''
                self.alert(now, 'pf_limit', severity, 'pf_limit:%s:%d' % (name, hour), count=delta, reopen=False,
                           peer=name, detail='%s +%d: %s. %s'
                                             % (name, delta, meaning, culprit or 'Top LAN hosts: '
                                                + self.top_hosts_text(rates)))

        if now - self.rules_read >= 60:
            self.rules_read = now
            self.check_rules(now, rules)
        if now - self.tables_read >= 60:
            self.tables_read = now
            self.check_tables(now)

    def check_src_nodes(self, now, rules):
        """
        Per source limits (max-src-states, max-src-conn, max-src-conn-rate) from the source tracking
        table: name the source address and the rule that is at (>= 90%) its limit.
        """
        limited = {r['nr']: r for r in rules if any(k.startswith('max-src-') and k != 'max-src-nodes'
                                                    for k in r['options'])}
        if not limited:
            self.src_limited = []
            self.src_at_limit = {}
            return
        descriptions = pfstats.rule_descriptions()
        hour = now - now % 3600
        found = []
        for node in pfstats.read_src_nodes():
            rule = limited.get(node['rule'])
            if rule is None:
                continue
            options = rule['options']
            checks = []
            if 'max-src-states' in options:
                checks.append(('max-src-states', node['states'], int(options['max-src-states'])))
            if 'max-src-conn' in options:
                checks.append(('max-src-conn', node['connections'], int(options['max-src-conn'])))
            if 'max-src-conn-rate' in options:
                count, seconds = options['max-src-conn-rate'].split('/')
                checks.append(('max-src-conn-rate', node['rate'], int(count)))
            for kind, value, limit in checks:
                if limit and value >= limit * 0.9:
                    found.append({
                        'ip': node['ip'], 'lan': node['ip'] in self.lan, 'rule': rule['nr'],
                        'descr': descriptions.get(rule['label'], '') or rule['text'][:80], 'kind': kind,
                        'value': value, 'limit': limit, 'pct': round(value * 100.0 / limit, 1),
                        'at_limit': value >= limit, 'states': node['states'], 'connections': node['connections'],
                        'rate': '%s/%ss' % (node['rate'], node['rate_seconds']),
                    })
        found.sort(key=lambda f: (-f['pct'], f['ip']))
        self.src_limited = found[:200]
        at_limit = [f for f in found if f['at_limit']]
        self.src_at_limit = {f['ip']: f for f in at_limit}
        self.con.executemany(
            """INSERT INTO srclimits (ip, nr, kind, descr, limit_value, peak, first_seen, last_seen, hits)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
               ON CONFLICT (ip, nr, kind) DO UPDATE SET descr = excluded.descr, limit_value = excluded.limit_value,
                   peak = MAX(peak, excluded.peak), last_seen = excluded.last_seen, hits = hits + 1""",
            [(f['ip'], f['rule'], f['kind'], f['descr'], f['limit'], int(f['value']), now, now) for f in at_limit])
        for f in at_limit:
            who = 'LAN host %s' % f['ip'] if f['lan'] else 'External source %s' % f['ip']
            hint = '' if f['lan'] else ' (the limit protects your hosts from it)'
            self.alert(now, 'src_limit', 'high' if f['lan'] else 'medium',
                       'src_limit:%s:%d:%s:%d' % (f['ip'], f['rule'], f['kind'], hour), ip=f['ip'], reopen=False,
                       peer=str(f['rule']),
                       detail='%s is at %s %s/%d on rule @%d (%s), new connections are dropped%s'
                              % (who, f['kind'], self._num(f['value']), f['limit'], f['rule'], f['descr'], hint))

    @staticmethod
    def _num(value):
        return ('%d' % value) if float(value).is_integer() else ('%.1f' % value)

    def src_limit_text(self, counter):
        """ exact culprit for a per source limit counter, empty when nobody is at a limit right now """
        kinds = {'max-src-states': ('max-src-states',), 'max-src-conn': ('max-src-conn',),
                 'max-src-conn-rate': ('max-src-conn-rate',)}.get(counter)
        hits = [f for f in self.src_limited if f['at_limit'] and (kinds is None or f['kind'] in kinds)]
        if not hits:
            return ''
        return 'At the limit now: ' + '; '.join(
            '%s%s (%s %s/%d, rule @%d "%s")' % (f['ip'], ' [LAN]' if f['lan'] else '', f['kind'],
                                                 self._num(f['value']), f['limit'], f['rule'], f['descr'])
            for f in hits[:5])

    def check_rules(self, now, all_rules):
        """ rules with "max states" close to their limit """
        hour = now - now % 3600
        rules = []
        for rule in all_rules:
            if not rule['options']:
                continue
            maximum = int(rule['options'].get('max', 0))
            rule['usage'] = round(rule['states'] * 100.0 / maximum, 1) if maximum else None
            rules.append(rule)
            if maximum and rule['states'] >= maximum * 0.9:
                self.alert(now, 'rule_limit', 'critical' if rule['states'] >= maximum else 'high',
                           'rule_limit:%d:%d' % (rule['nr'], hour), reopen=False, peer=str(rule['nr']),
                           detail='rule @%d holds %d of max %d states: %s'
                                  % (rule['nr'], rule['states'], maximum, rule['text'][:120]))
        rules.sort(key=lambda r: -(r['usage'] or 0))
        self.rules = rules[:50]

    def check_tables(self, now):
        """ LAN hosts listed in overload / lockout / CrowdSec tables """
        patterns = [p.strip().lower() for p in self.cfg['watch_tables'].split(',') if p.strip()]
        tables = []
        for name in pfstats.list_tables():
            if not any(p in name.lower() for p in patterns):
                continue
            entries = pfstats.table_entries(name)
            members = set(e for e in entries if e in self.lan)
            tables.append({'name': name, 'entries': len(entries), 'lan': sorted(members, key=common.ip_sort_key)[:50]})
            severity, meaning = 'high', 'listed in pf table %s' % name
            for marker, sev, text in TABLE_MEANING:
                if marker in name.lower():
                    severity, meaning = sev, text
            for ip in members - self.table_members[name]:
                self.alert(now, 'in_table', severity, 'in_table:%s:%s' % (name, ip), ip=ip, peer=name,
                           detail='LAN host %s is in pf table %s: %s' % (ip, name, meaning))
            self.con.executemany(
                """INSERT INTO tablehits (tbl, ip, first_seen, last_seen) VALUES (?, ?, ?, ?)
                   ON CONFLICT (tbl, ip) DO UPDATE SET last_seen = excluded.last_seen""",
                [(name, ip, now, now) for ip in members])
            self.table_members[name] = members
        self.tables = tables

    def write_status(self, now, duration, connections):
        hints = []
        if not self.lan:
            hints.append('No LAN networks resolved. In transparent bridge mode the interfaces usually have no '
                         'IP address: add your customer subnets under Additional networks.')
        if self.bridges and self.cfg['l2_source'] == 'table':
            hints.append('A bridge is configured: the ARP table only knows hosts that talk to the firewall '
                         'itself, set MAC / IP source to "both" or "passive listening".')
        if self.raw_states == 0:
            hints.append('The pf state table was empty or pfctl could not be read.')
        if self.filterlog is not None and not os.access(filterlog.LOG_FILE, os.R_OK):
            hints.append('Firewall log %s not readable.' % filterlog.LOG_FILE)
        if not self.sample_devices and self.filterlog is None:
            hints.append('Blocked traffic sampling is off and the firewall log is not read: blocked attempts '
                         'are only visible as block rule counters.')
        if any(i.get('error') for i in self.sample_info.values()):
            hints.append('Sampling failed on some interfaces, see the sampling line below.')
        common.write_status({
            'time': now, 'poll_seconds': round(duration, 2), 'raw_states': self.raw_states,
            'connections': connections, 'lan_networks': [str(n) for n in self.lan.networks],
            'own_addresses': sorted(self.own, key=common.ip_sort_key)[:20], 'bridges': self.bridges,
            'l2_source': self.cfg['l2_source'] if self.cfg['l2_enabled'] else 'off',
            'sniffer': self.sniffer.status() if self.sniffer else {}, 'arp_entries': self.arp_entries,
            'filterlog': {'enabled': self.filterlog is not None, 'path': filterlog.LOG_FILE,
                          'readable': os.access(filterlog.LOG_FILE, os.R_OK),
                          'blocked_lan_last_poll': self.blocked_last},
            'pf': self.pf, 'rules': self.rules, 'tables': self.tables, 'hints': hints,
            'sampling': {'devices': self.sample_devices, 'seconds': self.cfg['sample_seconds'],
                         'max_packets': self.cfg['sample_packets'], 'last': self.sample_info,
                         'labels': {d: self.iface_labels.get(d, '') for d in self.sample_devices},
                         'reason_tables': sorted(set('<%s> @%d' % (r['table'], r['nr']) for r in self.reason_tables))},
            'rule_activity': self.rule_activity, 'src_limited': self.src_limited,
        })

    def read_blocked(self, now, day, lateral):
        """ LAN to LAN packets the rules blocked (no pf state, only in the firewall log) """
        self.blocked_last = 0
        if self.filterlog is None:
            return
        for proto, src, dst, port in self.filterlog.read():
            if src in self.lan and self.is_lan_host(dst) and not (self.cfg['ignore_self'] and src in self.own):
                item = lateral.setdefault((day, src, dst, proto, port), [0, 0, 0, 0])
                item[0] += 1
                item[3] += 1
                self.blocked_last += 1
                self.scan[src].append((now, dst, proto, port))

    def lateral_alerts(self, now, day, lateral, scanners):
        """ one alert per new source -> destination:port per day (scanners are covered by their scan alert) """
        mode = self.cfg['lateral_alerts']
        if mode == 'off':
            return
        for (_, src, dst, proto, port), item in lateral.items():
            if not item[0] or src in scanners or src in self.trusted or dst in self.trusted:
                continue
            sensitive = proto in PORT_PROTOS and port in common.SENSITIVE_PORTS
            if mode == 'sensitive' and not sensitive:
                continue
            blocked = item[3]
            name = detect.port_name(port, proto) if proto in PORT_PROTOS else proto
            target = '%s/%d' % (proto, port) if proto in PORT_PROTOS else proto
            detail = '%s -> %s %s%s%s' % (src, dst, target, ' (%s)' % name if name and name != proto else '',
                                          ', blocked by the firewall' if blocked else
                                          ('' if item[1] else ', no answer'))
            self.alert(now, 'lateral', 'high' if sensitive else 'medium',
                       'lateral:%d:%s>%s:%s' % (day, src, dst, target),
                       ip=src, peer=dst, detail=detail, count=max(1, int(round(item[0]))), reopen=False)

    def scan_alerts(self, now):
        """ one LAN host touching many LAN hosts / ports within SCAN_WINDOW seconds, returns the scanners """
        limit = now - SCAN_WINDOW
        scanners = set()
        for src in list(self.scan):
            events = self.scan[src]
            while events and events[0][0] < limit:
                events.popleft()
            if not events:
                del self.scan[src]
                continue
            if src in self.trusted or self.cfg['lateral_alerts'] == 'off':
                continue
            targets = {e[1] for e in events}
            ports = {(e[1], e[2], e[3]) for e in events}
            if len(targets) >= self.cfg['scan_hosts'] or len(ports) >= self.cfg['scan_ports']:
                scanners.add(src)
                self.alert(now, 'lateral_scan', 'critical', 'lateral_scan:%s:%d' % (src, now - now % 3600),
                           ip=src, peer=','.join(sorted(targets)[:20]), reopen=False,
                           detail='%s contacted %d LAN hosts / %d ports in %d min (possible scan or worm)'
                                  % (src, len(targets), len(ports), SCAN_WINDOW // 60))
        return scanners

    def poll_l2(self, now):
        """ track MAC <-> IP bindings and alert on multiple / changed addresses """
        window = now - self.cfg['l2_window'] * 3600

        def wanted(ip, mac):
            return ip in self.lan and ip not in self.own and mac not in self.ignored_macs and not l2.is_virtual(mac)

        table = []
        if self.cfg['l2_source'] in ('both', 'table'):
            table = [e for e in l2.read_neighbors() if wanted(e[0], e[1])]
        self.arp_entries = len(table)
        events, recent = [], []
        if self.sniffer is not None:
            events = [(ip, mac, dev) for _, ip, mac, dev in self.sniffer.drain() if wanted(ip, mac)]
            recent = [e for e in self.sniffer.recent(600) if wanted(e[0], e[1])]
            # the ARP cache may hold a stale MAC for up to 20 minutes, trust what was heard on the wire
            heard = set(ip for ip, _, _ in self.sniffer.recent(1800))
            table = [e for e in table if e[0] not in heard]
        entries = events + table        # in order of observation

        known = {}
        for mac, ip, last in self.con.execute(
                'SELECT mac, ip, last_seen FROM l2bind WHERE last_seen >= ?', (window,)):
            known.setdefault(mac, {})[ip] = last
        current = defaultdict(set)
        for ip, mac, _ in recent + table:
            current[mac].add(ip)

        for ip, mac, ifc in entries:
            v4 = ':' not in ip
            if v4 and ip not in known.get(mac, {}):
                # a binding this MAC did not have within the window
                concurrent = sorted(o for o in current[mac] if o != ip and ':' not in o)
                older = sorted(((last, o) for o, last in known.get(mac, {}).items()
                                if o != ip and ':' not in o and o not in concurrent), reverse=True)
                if concurrent:
                    ips = sorted(set(concurrent) | {ip}, key=common.ip_sort_key)
                    self.alert(now, 'multi_ip', 'medium', 'multi_ip:%s' % mac, ip=ip, mac=mac,
                               peer=','.join(ips),
                               detail='MAC %s (%s) uses %d IPv4 addresses: %s' % (mac, ifc, len(ips), ', '.join(ips)))
                elif older:
                    old_ip = older[0][1]
                    self.alert(now, 'ip_changed', 'medium', 'ip_changed:%s:%s>%s' % (mac, old_ip, ip),
                               ip=ip, mac=mac, peer=old_ip,
                               detail='MAC %s (%s) changed IP %s -> %s within %dh'
                                      % (mac, ifc, old_ip, ip, self.cfg['l2_window']))
            previous = self.ip_mac.get(ip)
            if previous and previous != mac:
                self.alert(now, 'mac_changed', 'high', 'mac_changed:%s:%s' % (ip, '|'.join(sorted((previous, mac)))),
                           ip=ip, mac=mac, peer=previous, escalate_at=3,
                           detail='IP %s moved from MAC %s to %s on %s (IP taken over / ARP spoofing / '
                                  'reinstalled VM; repeated moves = conflict)' % (ip, previous, mac, ifc))
            self.ip_mac[ip] = mac
            known.setdefault(mac, {})[ip] = now      # one alert per binding, even if heard many times

        self.con.executemany(
            """INSERT INTO l2bind (mac, ip, iface, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)
               ON CONFLICT (mac, ip) DO UPDATE SET iface = excluded.iface, last_seen = excluded.last_seen""",
            [(mac, ip, ifc, now, now) for ip, mac, ifc in set(entries + recent)])

    def store(self, now, ts_host, ts_port, flows, hosts, lateral):
        con = self.con
        with con:
            con.executemany(
                """INSERT INTO lateral (day, src, dst, proto, port, first_seen, last_seen,
                                        attempts, answered, bytes, blocked)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT (day, src, dst, proto, port) DO UPDATE SET
                       last_seen = excluded.last_seen, attempts = attempts + excluded.attempts,
                       answered = answered + excluded.answered, bytes = bytes + excluded.bytes,
                       blocked = blocked + excluded.blocked""",
                [k + (now, now) + tuple(int(round(x)) for x in v) for k, v in lateral.items()]
            )
            con.executemany(
                """INSERT INTO ts_host (ts, ip, dir, conns, bytes) VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT (ts, ip, dir) DO UPDATE SET
                       conns = conns + excluded.conns, bytes = bytes + excluded.bytes""",
                [k + tuple(v) for k, v in ts_host.items() if v[0] or v[1]]
            )
            con.executemany(
                """INSERT INTO ts_port (ts, ip, dir, proto, port, conns, bytes) VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT (ts, ip, dir, proto, port) DO UPDATE SET
                       conns = conns + excluded.conns, bytes = bytes + excluded.bytes""",
                [k + tuple(v) for k, v in ts_port.items() if v[0] or v[1]]
            )
            con.executemany(
                """INSERT INTO flows (day, ip, dir, proto, port, remote, first_seen, last_seen, conns, bytes)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT (day, ip, dir, proto, port, remote) DO UPDATE SET
                       last_seen = excluded.last_seen,
                       conns = conns + excluded.conns, bytes = bytes + excluded.bytes""",
                [k + (now, now) + tuple(v) for k, v in flows.items()]
            )
            con.execute('UPDATE hosts SET active = 0 WHERE active != 0')
            con.executemany(
                """INSERT INTO hosts (ip, first_seen, last_seen, active, conns_in, conns_out, bytes_in, bytes_out)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT (ip) DO UPDATE SET
                       last_seen = excluded.last_seen, active = excluded.active,
                       conns_in = conns_in + excluded.conns_in, conns_out = conns_out + excluded.conns_out,
                       bytes_in = bytes_in + excluded.bytes_in, bytes_out = bytes_out + excluded.bytes_out""",
                [(ip, now, now) + tuple(v) for ip, v in hosts.items()]
            )

    def prune(self):
        now = int(time.time())
        cutoff = now - self.cfg['retention_days'] * 86400
        with self.con:
            for table, column in (('ts_host', 'ts'), ('ts_port', 'ts'), ('flows', 'last_seen'),
                                  ('hosts', 'last_seen'), ('services', 'last_probe'), ('lateral', 'last_seen'),
                                  ('l2bind', 'last_seen'), ('alerts', 'last_seen'), ('ts_pf', 'ts'),
                                  ('tablehits', 'last_seen'), ('blocked', 'last_seen'), ('ts_blocked', 'ts'),
                                  ('ts_rules', 'ts'), ('srclimits', 'last_seen'), ('blocked_reasons', 'last_seen')):
                self.con.execute('DELETE FROM %s WHERE %s < ?' % (table, column), (cutoff,))
        self.pruned = now


class Prober(threading.Thread):
    """ probes ports LAN hosts were seen serving, re-probing every probe_interval hours """

    def __init__(self, cfg, stop):
        super().__init__(name='prober', daemon=True)
        self.cfg = cfg
        self.stop = stop
        self.excluded = common.parse_port_list(cfg['probe_exclude'])

    def run(self):
        con = common.connect()
        if self.stop.wait(20):
            return
        while True:
            try:
                self.cycle(con)
            except Exception as exc:
                log(syslog.LOG_ERR, 'probe cycle failed: %s' % exc)
            if self.stop.wait(60):
                return

    def cycle(self, con):
        now = int(time.time())
        limit = self.cfg['probe_max']
        rows = con.execute(
            """SELECT p.ip, p.proto, p.port FROM ts_port p
               LEFT JOIN services s ON s.ip = p.ip AND s.proto = p.proto AND s.port = p.port
               WHERE p.dir = 'in' AND p.proto IN ('tcp', 'udp') AND p.ts >= ?
                 AND (s.last_probe IS NULL OR s.last_probe < ?)
               GROUP BY p.ip, p.proto, p.port
               ORDER BY MAX(p.ts) DESC LIMIT ?""",
            (now - 86400, now - self.cfg['probe_interval'] * 3600, limit)
        ).fetchall()
        targets, results = [], []
        for ip, proto, port in rows:
            if port in self.excluded:
                results.append(detect.unprobed(ip, port, proto, 'skipped', 'excluded'))
            else:
                targets.append((ip, port, proto))
        if targets:
            timeout, use_nmap = self.cfg['probe_timeout'], self.cfg['use_nmap']
            with ThreadPoolExecutor(max_workers=8) as pool:
                results += list(pool.map(lambda t: detect.probe(t[0], t[1], t[2], timeout, use_nmap), targets))
        if results:
            with con:
                for res in results:
                    common.store_service(con, res)
            log(syslog.LOG_INFO, 'probed %d service(s)' % len(results))


def main():
    syslog.openlog('lanusage', syslog.LOG_PID, syslog.LOG_DAEMON)
    cfg = common.load_config()
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())

    collector = Collector(cfg, stop)
    if not collector.lan:
        log(syslog.LOG_WARNING, 'no LAN networks configured, nothing will be recorded')
    log(syslog.LOG_NOTICE, 'started, monitoring %s every %ds' % (collector.lan, cfg['poll_interval']))
    if cfg['probe_enabled']:
        Prober(cfg, stop).start()

    while not stop.is_set():
        started = time.time()
        try:
            collector.poll()
        except Exception as exc:
            log(syslog.LOG_ERR, 'poll failed: %s' % exc)
        if started - collector.pruned > 3600:
            try:
                collector.prune()
            except Exception as exc:
                log(syslog.LOG_ERR, 'prune failed: %s' % exc)
        if started - collector.resolved > 300:
            collector.refresh_networks()
        stop.wait(max(1.0, cfg['poll_interval'] - (time.time() - started)))
    log(syslog.LOG_NOTICE, 'stopped')
    return 0


if __name__ == '__main__':
    sys.exit(main())
