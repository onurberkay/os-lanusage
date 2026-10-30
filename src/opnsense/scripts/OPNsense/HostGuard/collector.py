#!/usr/local/bin/python3
"""
    Copyright (c) 2026 Onur Berkay <onurberkay@sakla.app>
    All rights reserved. (BSD 2-Clause, see LICENSE)

    HostGuard collector daemon.

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
import heapq
import ipaddress
import json
import os
import re
import signal
import subprocess
import sys
import syslog
import threading
import time
from collections import Counter, defaultdict, deque
from concurrent.futures import ThreadPoolExecutor

from lib import attacks, autofilter, common, detect, filterlog, ipdata, l2, pfstate, pfstats, sampler, shaper

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


def _two_digits(n):
    """ 1234 -> 1200: rounded down to two significant digits """
    scale = 10 ** max(len(str(n)) - 2, 0)
    return n // scale * scale


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
        self.l2_held = {}       # (ip, mac) -> ts: new bindings held back during an ARP / ND flood
        # raw pf states per LAN host (what consumes the state table), rebuilt every poll
        self.raw_states = 0
        self.states_ok = False
        self.state_ifcs = {}
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
        # also after a longer stop: a host still listed is not new (its alert was raised before)
        for tbl, ip in self.con.execute('SELECT tbl, ip FROM tablehits WHERE last_seen >= ?',
                                        (int(time.time()) - 86400,)):
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
        self.host_src = {}
        # block reasons: tables referenced by block rules, sources at a limit, last counter increases
        self.reason_tables = []
        self.reason_read = 0
        self.src_at_limit = {}
        self.src_near = {}
        self.rules_full = []
        self.last_deltas = {}
        # traffic shaper: previous flow counters for rates, config.xml cache
        self.shaper_prev = {}
        self.shaper_last = None
        self.shaper_cfg = {'pipes': {}, 'queues': {}, 'rules': []}
        self.shaper_cfg_mtime = None
        self.shaper = {}
        self.shaper_drops = {}
        self.iface_labels = common.interface_labels()
        # monitored LAN interfaces as configured (bridge members are not expanded: the upstream one is WAN)
        self.lan_names = [x.strip() for x in cfg['interfaces'].split(',') if x.strip()]
        self.lan_devices = set(common.interface_devices(self.lan_names))
        # attacks on LAN hosts: per target stats of the last sample, Suricata alerts, CrowdSec decisions
        self.attack_targets = {}
        self.attack_interval = float(cfg['poll_interval'])
        self.attacks_now = []
        self.eve = attacks.EveReader(cfg['ids_eve']) if cfg['ids_enabled'] else None
        self.ids_last = 0
        self.crowdsec_read = 0
        self.crowdsec_count = None
        self.ids_sources = defaultdict(set)
        self.src_rule_hits = []
        # automatic filtering (lib/autofilter.py): what the last sample shows per outside source
        self.probes = {}                    # source -> {(LAN host, proto, port)} its blocked attempts reached
        self.blocked_sources = set()        # outside sources with blocked attempts towards LAN hosts
        self.ids_severity = defaultdict(dict)   # severity -> {source: 'sid N on host'}
        self.networks = autofilter.Networks()
        self.auto_exempted = Counter()      # wanted traffic an automatic rule matched but spared, this poll
        self.logged_lateral = Counter()     # LAN to LAN attempts the firewall log showed this poll
        self.rule_users = set()
        self.autoblock_status = {}
        self.autoblock_pending = None
        self.autoblock_synced = 0
        self.autoblock_ok = True
        # every LAN network seen since the start: a network missing for a moment (interface reconfigured,
        # prefix delegation renewed) must not make its hosts blockable
        self.lan_seen = list(self.lan.networks)
        self.own_seen = set(self.own)       # the same for the firewall's own addresses (ifconfig timing out)

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
        lan, own = common.resolve_networks(self.cfg)
        if not own and self.own:
            # ifconfig failed (timeout): keep what was known, the interface networks went with it
            self.resolved = time.time()
            return
        self.lan, self.own = lan, own
        self.lan_seen.extend(n for n in self.lan.networks if n not in self.lan_seen)
        self.own_seen.update(self.own)
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
        # connection key -> interface its states are bound to ("all" = floating), a set when several
        ifcs = {}
        # (outside initiator, rule that created its state): with global source tracking the only proof
        # that a source used a rule, block conditions on a rule's limit need it
        rule_users = set()
        raw = 0
        status = {}
        for st in pfstate.iter_states(status=status):
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
            ckey = (st['proto'], init[0], init[1], resp[0], resp[1])
            have = ifcs.get(ckey)
            ifc = st.get('ifc', 'all')
            if have is None:
                ifcs[ckey] = ifc
            elif have != ifc:
                ifcs[ckey] = (have if isinstance(have, set) else {have}) | {ifc}
            if not i_lan and st.get('rule') is not None:
                rule_users.add((init[0], st['rule']))
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
        # a failed or empty listing proves nothing: every sampled packet would look unanswered
        self.states_ok = bool(status.get('ok')) and raw > 0
        self.state_ifcs = ifcs
        self.rule_users = rule_users
        return conns

    def egress_blocked(self, dev, key, rkey):
        """
        An attempt that entered on <dev> and has states only on <dev>: passed going in, blocked going out
        (e.g. pass all on the LAN, no pass rule out on the WAN). Only with if-bound states: a floating
        ("all") state matches on every interface, so no rule is evaluated on the way out.
        -> the interface(s) it should have left on, '' when not blocked that way
        """
        bound = self.state_ifcs.get(key) or self.state_ifcs.get(rkey)
        if bound != dev:
            return ''
        others = [m for members in self.bridges.values() if dev in members for m in members if m != dev]
        return ', '.join('%s (%s)' % (m, self.iface_labels[m]) if self.iface_labels.get(m) else m
                         for m in others) or 'another interface'

    def poll(self):
        started = time.time()
        now = int(started)
        bucket, hour, day = now - now % 300, now - now % 3600, now - now % 86400
        track_remote = self.cfg['track_remote']
        # sample attempts first, then read the states they should have created
        samples = sampler.capture(self.sample_devices, self.cfg['sample_seconds'], self.cfg['sample_packets']) \
            if self.sample_devices else {}
        conns = self.snapshot()
        if not self.states_ok:
            # without the states a sample cannot be told blocked from passed, nor an attack from the answers
            # to the hosts' own traffic; the previous counters stay for the next poll
            log(syslog.LOG_WARNING, 'pfctl -ss failed or listed no states: poll skips traffic and attacks')
            samples, conns = {}, {}
        ts_host, ts_port, flows, hosts, lateral = {}, {}, {}, {}, {}
        new_by_host = Counter()
        prev, current = self.prev, {}
        if self.last_poll is None:
            # first poll after a start: the states that already exist are the baseline, not new connections
            # with the bytes of their whole lifetime (nor LAN to LAN attempts that would look like a scan)
            prev = dict((key, (nbytes, ok, real)) for key, (nbytes, ok, _, _, real) in conns.items())
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
        # new connections per second; the first poll sees every existing state as new
        rates = {}
        if self.states_ok:
            self.prev = current
            if self.last_poll is not None and now > self.last_poll:
                rates = {h: n / float(now - self.last_poll) for h, n in new_by_host.items()}
            self.last_poll = now
        self.read_blocked(now, day, lateral)
        blocked, blocked_hosts, blocked_reasons, interval = self.classify_samples(now, day, samples, conns, lateral)
        self.store(now, ts_host, ts_port, flows, hosts, lateral)
        details = self.state_details(rates)
        # a step that runs pfctl / cscli / ipfw / arp commits what came before it first (self.con.commit()):
        # the write lock is only held while writing, query.py's writes (conditions, ack) do not wait for pfctl
        with self.con:
            self.store_blocked(now, day, bucket, blocked, blocked_hosts, blocked_reasons)
            self.blocked_alerts(now, blocked, blocked_hosts, blocked_reasons, interval)
            self.attack_episodes(now)
            self.read_ids(now)
            self.con.commit()
            self.read_crowdsec(now)
            if self.states_ok:
                self.store_host_states(now, rates, details)
            scanners = self.scan_alerts(now)
            self.lateral_alerts(now, day, lateral, scanners)
            self.host_limit_alerts(now, rates, details)
            self.pf_check(now, details, rates)
            self.con.commit()
            self.autoblock(now)
        try:
            if self.cfg['l2_enabled']:
                with self.con:
                    self.poll_l2(now)
        finally:
            # the rows of this poll are committed: pf follows them even if a later step failed
            self.autoblock_apply(now)
        self.write_status(now, time.time() - started, len(conns))
        return len(conns)

    #  blocked traffic (no firewall logging needed)

    PROBES_MAX = 20000          # outside sources whose blocked attempts are kept per poll (automatic filtering)
    PROBES_PER_SOURCE = 500     # (host, proto, port) per source: enough to see a scan
    TRACE_PORT = 33000          # UDP destination ports from here on: traceroute (33434+), mtr (33000-65535), tracepath

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
        targets = self.attack_targets = {}
        self.attack_interval = interval
        probes = self.probes = {}
        self.blocked_sources = set()
        if not samples:
            self.sample_info = {}
            return blocked, per_host, per_reason, interval
        if not self.reason_read:
            # first poll: know the block tables before the first classification
            self.refresh_reason_tables(now, pfstats.read_rules())
        keys = set(conns)
        icmp_pairs = set((k[1], k[3]) for k in conns if k[0] in ('icmp', 'ipv6-icmp'))
        reasons = {}
        sampled_lateral = Counter()
        for dev, res in samples.items():
            scale = max(1.0, interval / res['elapsed']) if res.get('elapsed') else 1.0
            count = 0
            for proto, src, sport, dst, dport in res.get('packets', []):
                if src in self.own or dst in self.own:
                    continue
                s_lan, d_lan = src in self.lan, dst in self.lan
                if not (s_lan or d_lan):
                    continue
                inbound = d_lan and not s_lan
                egress = ''
                reply = False
                if proto in ('icmp', 'ipv6-icmp'):
                    passed = (src, dst) in icmp_pairs
                else:
                    key, rkey = (proto, src, sport, dst, dport), (proto, dst, dport, src, sport)
                    passed = key in keys or rkey in keys
                    # UDP is sampled in both directions: a packet of a flow the LAN host opened is an answer
                    reply = passed and key not in keys
                    if passed and res.get('inbound_only'):
                        egress = self.egress_blocked(dev, key, rkey)
                        passed = not egress
                if inbound and not reply:
                    # attacks on the host: every attempt from outside counts, blocked or passed (not the
                    # answers to its own DNS / QUIC / game traffic)
                    stats = targets.get(dst)
                    if stats is None:
                        stats = targets[dst] = attacks.TargetStats()
                    stats.add(proto, src, sport, dport, scale, passed)
                if passed:
                    continue
                count += 1
                port = dport if proto in PORT_PROTOS else 0
                if inbound:
                    # sampled packets themselves (not estimates): which hosts and ports one source tried
                    self.blocked_sources.add(src)
                    # probes: TCP SYNs (the capture takes no other TCP packets) and UDP from a client port; not
                    # UDP from a server port (a reflected DNS / NTP reply to random ports), not a UDP traceroute /
                    # mtr / tracepath (they count their probes up in the destination port, from 33000), not ICMP
                    # (pings of a monitoring service over many hosts)
                    tried = None
                    if proto in ('tcp', 'sctp') or (proto == 'udp' and sport and sport >= 1024 and
                                                    sport not in attacks.REFLECT_PORTS and port < self.TRACE_PORT):
                        tried = probes.get(src)
                        if tried is None and len(probes) < self.PROBES_MAX:
                            tried = probes[src] = set()
                    if tried is not None and len(tried) < self.PROBES_PER_SOURCE:
                        tried.add((dst, proto, port))
                if egress:
                    reason = 'passed in on %s, no pass rule out on %s' % (
                        '%s (%s)' % (dev, self.iface_labels[dev]) if self.iface_labels.get(dev) else dev, egress)
                else:
                    reason = reasons.get((src, dst))
                    if reason is None:
                        reason = reasons[(src, dst)] = self.block_reason(src, dst, not s_lan)
                if s_lan and d_lan:
                    sampled_lateral[(day, src, dst, proto, port)] += scale
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
                         'label': self.iface_labels.get(dev, ''), 'inbound_only': res.get('inbound_only', False)}
        # LAN to LAN: the firewall log (read_blocked) may have counted the same attempts already: only what the
        # sample estimates beyond it is added (the larger of the two counts)
        for key, estimated in sampled_lateral.items():
            extra = estimated - self.logged_lateral.get(key, 0)
            if extra > 0:
                item = lateral.setdefault(key, [0, 0, 0, 0])
                item[0] += extra
                item[3] += extra
        self.sample_info = info
        return blocked, per_host, per_reason, interval

    #  attacks on LAN hosts

    EPISODE_GAP = 600   # an attack quiet for this long is over, the next one is a new episode

    def attack_episodes(self, now):
        """
        One episode per LAN host: started when the inbound attempts from outside reach the attack
        threshold, extended while they continue. Brute force counts from a fifth of it.
        """
        threshold = float(self.cfg['attack_pps'])
        interval = self.attack_interval or 1.0
        current = []
        for target, stats in self.attack_targets.items():
            pps = stats.total / interval
            if pps < threshold and not (pps >= threshold / 5 and stats.is_brute_force()):
                continue
            kind, detail = stats.classify()
            passed_pct = round(stats.passed * 100.0 / (stats.total or 1), 1)
            ports = ', '.join(p for p, _ in stats.ports.most_common(4))
            top = ', '.join(s for s, _ in stats.sources.most_common(5))
            # one episode per host at a time: the type can change from poll to poll (syn flood <-> brute force
            # when fewer sources show up), it is the type of the strongest poll
            row = self.con.execute('SELECT id, peak_pps FROM attacks WHERE target = ?'
                                   ' AND last_seen >= ? ORDER BY id DESC LIMIT 1',
                                   (target, now - self.EPISODE_GAP)).fetchone()
            if row:
                episode = row[0]
                self.con.execute(
                    'UPDATE attacks SET last_seen = ?, peak_pps = MAX(peak_pps, ?), packets = packets + ?,'
                    ' sources = MAX(sources, ?), ports = ?, passed_pct = ?, top_sources = ?,'
                    ' kind = CASE WHEN ? > peak_pps THEN ? ELSE kind END WHERE id = ?',
                    (now, round(pps, 1), int(stats.total), len(stats.sources), ports, passed_pct, top,
                     round(pps, 1), kind, episode))
            else:
                episode = self.con.execute(
                    'INSERT INTO attacks (target, kind, first_seen, last_seen, peak_pps, packets, sources, ports,'
                    ' passed_pct, top_sources) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                    (target, kind, now, now, round(pps, 1), int(stats.total), len(stats.sources), ports,
                     passed_pct, top)).lastrowid
            # passing attacks reach the host: that is the dangerous case
            severity = 'critical' if passed_pct >= 50 or pps >= threshold * 20 else 'high'
            self.alert(now, 'attack', severity, 'attack:%d' % episode, ip=target, reopen=False, peer=kind,
                       detail='%s on %s: ~%.0f pkt/s from %d sources, %s; %.0f%% passed the firewall%s'
                              % (kind.upper(), target, pps, len(stats.sources), detail, passed_pct,
                                 ' (reaching the host!)' if passed_pct >= 50 else ''))
            current.append({'id': episode, 'target': target, 'kind': kind, 'detail': detail, 'pps': round(pps, 1),
                            'sources': len(stats.sources), 'passed_pct': passed_pct, 'ports': ports})
        # all of them: block conditions match on every attack, the status shows the 50 strongest
        self.attacks_now = sorted(current, key=lambda a: -a['pps'])

    def read_ids(self, now):
        """ Suricata alerts whose destination is a LAN host and whose source is outside """
        if self.eve is None:
            return
        day, hour = now - now % 86400, now - now % 3600
        rows, worst = {}, {}
        self.ids_sources = defaultdict(set)
        self.ids_severity = defaultdict(dict)
        for a in self.eve.read():
            if a['dst'] not in self.lan or a['src'] in self.lan or a['dst'] in self.own:
                continue
            self.ids_sources[(a['dst'], a['sid'])].add(a['src'])
            if a['severity'] in (1, 2):
                self.ids_severity[a['severity']][a['src']] = 'Suricata severity %d, sid %s on %s' % (
                    a['severity'], a['sid'], a['dst'])
            key = (day, a['dst'], a['src'], a['sid'])
            item = rows.get(key)
            if item is None:
                rows[key] = item = [a['signature'], a['category'], a['severity'], a['action'], a['dport'], 0]
            item[5] += 1
            if a['severity'] == 1:
                worst.setdefault((a['dst'], a['sid']), [a['signature'], set(), 0])
                w = worst[(a['dst'], a['sid'])]
                w[1].add(a['src'])
                w[2] += 1
        self.ids_last = sum(i[5] for i in rows.values())
        self.con.executemany(
            """INSERT INTO ids_alerts (day, target, src, sid, signature, category, severity, action, port,
                                       first_seen, last_seen, hits) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT (day, target, src, sid) DO UPDATE SET last_seen = excluded.last_seen,
                   hits = hits + excluded.hits, action = excluded.action""",
            [(d, t, s, sid, i[0], i[1], i[2], i[3], i[4], now, now, i[5]) for (d, t, s, sid), i in rows.items()])
        for (target, sid), (signature, sources, hits) in worst.items():
            self.alert(now, 'ids', 'high', 'ids:%s:%d:%d' % (target, sid, hour), ip=target, reopen=False,
                       count=hits, peer=str(sid),
                       detail='Suricata (severity 1) on %s: %s, %d hits from %d sources (%s)'
                              % (target, signature, hits, len(sources), ', '.join(sorted(sources)[:3])))

    def read_crowdsec(self, now):
        """ local CrowdSec decisions every 5 minutes: why an outside address is banned """
        if not self.cfg['crowdsec_enabled'] or now - self.crowdsec_read < 300:
            return
        self.crowdsec_read = now
        decisions = attacks.read_decisions(now)
        if decisions is None:
            self.crowdsec_count = None
            return
        self.crowdsec_count = len(decisions)
        items = list(decisions.items())[:50000]
        self.con.executemany(
            """INSERT INTO crowdsec (ip, scenario, origin, action, until, last_seen) VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT (ip) DO UPDATE SET scenario = excluded.scenario, origin = excluded.origin,
                   action = excluded.action, until = excluded.until, last_seen = excluded.last_seen""",
            [(ip, d['scenario'], d['origin'], d['action'], d['until'], now) for ip, d in items])
        if len(items) == len(decisions):
            # a decision removed before its time (cscli decisions delete, unban): no longer banned now
            self.con.execute('UPDATE crowdsec SET until = ? WHERE last_seen < ? AND until >= ?', (now - 1, now, now))

    #  block conditions: sources matching a condition the operator created go into virusprot

    AUTOBLOCK_PER_POLL = 2000
    AUTOBLOCK_MAX = 50000       # addresses held by conditions in all; pf's table-entries limit is shared
    AUTOBLOCK_SYNC = 600        # tables are empty after a reboot or a flush: everything held is added again

    def blockable(self, ip, hosts):
        """
        only outside addresses: never a LAN host (also one of a network not resolved right now, or one
        ever seen as a LAN host), the firewall itself or a trusted network -> the address or None
        """
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        # link-local (a neighbour on the segment, the gateway, the firewall's own fe80::), multicast, loopback,
        # 0.0.0.0, reserved: never a source to block (spoofed or local)
        if addr.is_link_local or addr.is_multicast or addr.is_loopback or addr.is_unspecified or addr.is_reserved:
            return None
        ip = addr.compressed
        if ip in self.lan or ip in self.own or ip in self.own_seen or ip in self.trusted or ip in hosts:
            return None
        if any(ipaddress.ip_address(ip) in net for net in self.lan_seen):
            return None
        return ip

    def condition_matches(self, cond):
        """ -> {source: reason} for the events of this poll that match the condition """
        ctype, value, target = cond['ctype'], cond['value'], cond['target']
        found = {}
        if ctype == 'attack':
            for a in self.attacks_now:
                if a['kind'] == value and target in ('*', a['target']):
                    stats = self.attack_targets.get(a['target'])
                    for src in (stats.attack_sources(a['kind']) if stats else ()):
                        found[src] = '%s on %s' % (a['kind'], a['target'])
        elif ctype == 'ids':
            for (dst, sid), sources in self.ids_sources.items():
                if str(sid) == value and target in ('*', dst):
                    for src in sources:
                        found[src] = 'Suricata sid %s on %s' % (sid, dst)
        elif ctype == 'src_limit':
            # "<rule label>:<limit kind>": the limit value itself is read from the rule every poll,
            # so a changed max-src-states applies at once; the label survives renumbering
            rule, _, kind = value.rpartition(':')
            for ip, label, nr, hit_kind in self.src_rule_hits:
                # the GUI sends a space in a label as "_"
                if hit_kind == kind and rule in ('*', label, label.replace(' ', '_')):
                    found[ip] = '%s on rule @%d' % (kind, nr)
        elif ctype == 'auto':
            found = self.auto_matches(value)
        return found

    def auto_matches(self, rule):
        """ -> {source: reason} for an automatic rule (lib/autofilter.py), from this poll's events """
        found = {}
        if rule == 'scan_ports':
            limit = autofilter.SCAN_PORTS
            for src, tried in self.probes.items():
                per_host = Counter(dst for dst, proto, port in tried if proto in ('tcp', 'udp'))
                for dst, ports in per_host.items():
                    if ports >= limit:
                        found[src] = 'port scan: %d ports of %s blocked' % (ports, dst)
                        break
        elif rule == 'scan_hosts':
            limit = autofilter.SCAN_HOSTS
            for src, tried in self.probes.items():
                hosts = len(set(dst for dst, _, _ in tried))
                if hosts >= limit:
                    found[src] = 'sweep: %d LAN hosts tried, blocked' % hosts
        elif rule == 'asn_drop':
            for src in self.blocked_sources:
                if self.networks.in_drop(src):
                    found[src] = 'blocked traffic from a Spamhaus ASN-DROP network'
        elif rule in ('brute_force', 'flood'):
            kinds = ('brute force',) if rule == 'brute_force' else autofilter.FLOODS
            for a in self.attacks_now:
                stats = self.attack_targets.get(a['target'])
                if a['kind'] not in kinds or not stats:
                    continue
                if rule == 'brute_force':
                    # mail clients and browsers open several connections at once: a busy mail or web
                    # login is no proof of guessing (the server's own logs are, e.g. CrowdSec on the host)
                    top = stats.ports.most_common(1)[0][0] if stats.ports else ''
                    if top.startswith('tcp/') and int(top[4:]) in autofilter.BRUTE_SKIP_PORTS:
                        continue
                for src in stats.attack_sources(a['kind']):
                    # a flood that only passed may be a busy day of a web site: only sources pf also blocked
                    if rule == 'brute_force' or src in self.blocked_sources:
                        found[src] = '%s on %s' % (a['kind'], a['target'])
        elif rule in ('ids_high', 'ids_medium'):
            found = dict(self.ids_severity.get(1 if rule == 'ids_high' else 2, {}))
        elif rule == 'src_limit':
            for ip, label, nr, hit_kind in self.src_rule_hits:
                found[ip] = '%s on rule @%d' % (hit_kind, nr)
        # reflectors (abused DNS / NTP / ... servers answering spoofed requests) are never taken automatically,
        # whatever else they look like (a UDP flood under the reflection share, a Suricata amplification alert);
        # a reflector sends repeated replies, also spread over many hosts (counted over all of them): at least
        # two sampled ones, and mostly replies (a source adding a few from port 53 to its brute force or a
        # Suricata alert does not become one). The scan rules need no such check: replies from a reflection
        # port are no probes, and a scanner adding a few of them must stay a scanner.
        if found and rule not in ('scan_ports', 'scan_hosts'):
            replies, sampled = Counter(), Counter()
            for stats in self.attack_targets.values():
                replies.update(stats.sampled_reflect)
                sampled.update(stats.sampled)
            for src, packets in replies.items():
                if packets >= 2 and packets * 2 >= sampled[src]:
                    found.pop(src, None)
        return found

    def sync_auto_conditions(self, now):
        """
        The automatic rules of the configured level as conditions of type "auto" (they hold what they block
        like any condition). A rule left out since (a lower level, filtering off) is removed: the addresses
        only it held are released.
        """
        self.networks.refresh(self.cfg['ipdata_enabled'] and self.cfg['auto_block_level'] > 0)
        wanted = autofilter.rules(self.cfg, self.networks.has_drop)
        duration = self.cfg['auto_block_hours'] * 3600
        existing = dict((r[1], (r[0], r[2], r[3])) for r in self.con.execute(
            "SELECT id, value, duration, note FROM conditions WHERE ctype = 'auto'"))
        for rule, (cid, old_duration, note) in existing.items():
            if rule not in wanted:
                self.con.execute('DELETE FROM conditions WHERE id = ?', (cid,))
            elif old_duration != duration or note != self.auto_note(rule, wanted[rule]):
                self.con.execute('UPDATE conditions SET duration = ?, note = ? WHERE id = ?',
                                 (duration, self.auto_note(rule, wanted[rule]), cid))
                if old_duration != duration:
                    # what the rule holds now follows the new time, counted from the last match (as query.py
                    # does for a condition created again); not the rows already due to leave
                    self.con.execute('UPDATE autoblocked SET expires = COALESCE(NULLIF(last_match, 0), added) + ?'
                                     ' WHERE cond = ? AND NOT (expires > 0 AND expires <= ?)', (duration, cid, now))
        for rule, spec in wanted.items():
            if rule not in existing:
                self.con.execute("INSERT INTO conditions (ctype, value, target, duration, note, created)"
                                 " VALUES ('auto', ?, '*', ?, ?, ?)", (rule, duration, self.auto_note(rule, spec), now))

    @staticmethod
    def auto_note(rule, spec):
        level, text = spec
        return 'level %d (%s): %s' % (level, autofilter.LEVELS[level], text)

    def autoblock_state(self):
        """ the conditions, what they hold and what they match this poll (reads only) """
        conditions = [dict(zip(('id', 'ctype', 'value', 'target', 'duration'), r)) for r in self.con.execute(
            'SELECT id, ctype, value, target, duration FROM conditions')]
        held = {}           # (ip, condition) -> expires
        owned = {}          # ip -> 1 when a condition put it into the table, 0 when it was there already
        for ip, cond, expires, own in self.con.execute('SELECT ip, cond, expires, owned FROM autoblocked'):
            held[(ip, cond)] = expires
            owned[ip] = owned.get(ip, 0) or own
        hosts = set(r[0] for r in self.con.execute('SELECT ip FROM hosts'))
        # held addresses are checked again every poll: one whose network has become a LAN or trusted network
        # since, or that showed up as a LAN host or the firewall's, is released like an expired one; so is
        # a row of a condition that does not exist any more
        unsafe = set(ip for ip in owned if self.blockable(ip, hosts) != ip)
        ids = set(c['id'] for c in conditions)
        release = [key for key in held if key[0] in unsafe or key[1] not in ids]
        matched = []
        self.auto_exempted = Counter()
        for cond in conditions:
            matches = {}
            for ip, why in self.condition_matches(cond).items():
                ip = self.blockable(ip, hosts)
                if not ip:
                    continue
                if cond['ctype'] == 'auto':
                    # wanted traffic (crawlers, monitoring, Private Relay, CDNs) is never taken automatically;
                    # one taken before the network data was there is no longer renewed and leaves in time
                    spared = self.networks.exempt(ip)
                    if spared:
                        self.auto_exempted[spared] += 1
                        continue
                matches[ip] = why
            if matches:
                matched.append((cond, matches))
        return conditions, held, owned, unsafe, release, matched

    def autoblock(self, now):
        """
        Record what the conditions hold now, in a write transaction of its own. pf is changed afterwards
        (autoblock_apply), once these rows are committed: a rollback must not leave addresses in the table
        that no row holds.
        """
        table = common.AUTOBLOCK_TABLE
        if not self.own_seen:
            # ifconfig has not answered yet: the firewall's own addresses could not be told apart
            log(syslog.LOG_WARNING, 'block conditions wait: the firewall addresses are not known yet')
            return
        # the automatic rules of the configured level, committed before pfctl runs (never with the write lock)
        self.sync_auto_conditions(now)
        self.con.commit()
        # the new addresses, or every address held when the table may have lost them (reboot, flush, failure)
        sync = not self.autoblock_ok or now - self.autoblock_synced >= self.AUTOBLOCK_SYNC
        # pfctl never runs with the write lock held: the table is listed first when this poll may need it ...
        conditions, held, owned, unsafe, release, matched = self.autoblock_state()
        present = False
        # the listing only answers "already there?" for the addresses new at the time it was taken: one that
        # was held then and released meanwhile (query.py cond_del) waits for the next poll
        asked = set(ip for _, matches in matched for ip in matches if ip not in owned)
        if asked or (sync and not all(owned.values())):
            present = pfstats.table_show(table)
        # ... then everything is read again under the write lock: a condition query.py removed or changed
        # meanwhile is neither written back nor kept
        self.con.commit()
        self.con.execute('BEGIN IMMEDIATE')
        conditions, held, owned, unsafe, release, matched = self.autoblock_state()
        if release:
            self.con.executemany('UPDATE autoblocked SET expires = 1 WHERE ip = ? AND cond = ?', release)
            held.update((key, 1) for key in release)
        added, budget, capped, unreadable = [], self.AUTOBLOCK_PER_POLL, False, False
        hour = now - now % 3600
        touched = []
        for cond, matches in matched:
            expires = now + cond['duration'] if cond['duration'] else 0
            fresh = []
            for ip, why in matches.items():
                key = (ip, cond['id'])
                if key in held:
                    # still matching: stays blocked for the full time from now on
                    if expires and held[key] and held[key] < expires:
                        self.con.execute('UPDATE autoblocked SET expires = ?, last_match = ? WHERE ip = ? AND cond = ?',
                                         (expires, now, ip, cond['id']))
                        held[key] = expires
                    else:
                        touched.append((now, ip, cond['id']))
                    continue
                if ip not in owned:
                    if budget <= 0 or len(owned) >= self.AUTOBLOCK_MAX:
                        capped = True
                        continue
                    if present is None:
                        # pfctl could not list the table: "already there" is unknown, wait for the next poll
                        unreadable = True
                        continue
                    if present is False or ip not in asked:
                        # new since the table was listed (a condition added or one removed meanwhile): the
                        # listing says nothing about it, the next poll
                        continue
                    owned[ip] = 0 if ip in present else 1
                    budget -= 1
                    if owned[ip]:
                        added.append(ip)
                self.con.execute('INSERT INTO autoblocked (ip, cond, tbl, added, expires, reason, owned, last_match)'
                                 ' VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                                 (ip, cond['id'], table, now, expires, why, owned[ip], now))
                held[(ip, cond['id'])] = expires
                fresh.append(ip)
            if not fresh:
                continue
            self.con.execute('UPDATE conditions SET hits = hits + ?, last_hit = ? WHERE id = ?',
                             (len(fresh), now, cond['id']))
            self.alert(now, 'autoblock', 'info', 'autoblock:%d:%d' % (cond['id'], hour), reopen=False,
                       count=len(fresh), peer=str(cond['id']),
                       detail='Condition #%d (%s %s, target %s) put %d outside sources into <%s>: %s'
                              % (cond['id'], cond['ctype'], cond['value'], cond['target'], len(fresh), table,
                                 ', '.join(fresh[:5]) + (' ...' if len(fresh) > 5 else '')))
        # last match of the addresses that still match (a later change of the duration counts from it)
        self.con.executemany('UPDATE autoblocked SET last_match = ? WHERE ip = ? AND cond = ?', touched)
        if sync and isinstance(present, set):
            # an address that was there already and has left the table since (expired, flushed, reboot)
            # is the conditions' own from now on
            mine = [ip for ip, own in owned.items() if not own and ip not in present and ip not in unsafe]
            self.con.executemany('UPDATE autoblocked SET owned = 1 WHERE ip = ?', [(ip,) for ip in mine])
            owned.update((ip, 1) for ip in mine)
        push = sorted(ip for ip, own in owned.items() if own and ip not in unsafe) if sync else added
        # expired entries leave the table once no other condition holds them: rows of addresses that need
        # no pfctl call go now, the others only after pfctl removed the address
        expired = [(ip, cond) for (ip, cond), exp in held.items() if 0 < exp <= now]
        still = set(ip for (ip, cond), exp in held.items() if not 0 < exp <= now)
        gone = set(ip for ip, _ in expired if ip not in still and owned.get(ip))
        self.con.executemany('DELETE FROM autoblocked WHERE ip = ? AND cond = ?',
                             [(ip, cond) for ip, cond in expired if ip not in gone])
        self.autoblock_pending = (push, sorted(gone), sync)
        self.autoblock_status = {
            'table': table, 'conditions': len(conditions), 'added_last_poll': len(added),
            'table_ok': self.autoblock_ok, 'capped': capped, 'max': self.AUTOBLOCK_MAX,
            'table_unreadable': unreadable, 'auto_level': self.cfg['auto_block_level'],
            'auto_spared': dict(self.auto_exempted.most_common(10)),
            'blocked': self.con.execute('SELECT COUNT(DISTINCT ip) FROM autoblocked').fetchone()[0],
        }

    def autoblock_apply(self, now):
        """
        After the poll's commit: change pf under the database write lock (query.py cond_del takes it too),
        and only for addresses a committed row still holds
        """
        pending, self.autoblock_pending = self.autoblock_pending, None
        if pending is None:
            return
        push, gone, sync = pending
        table = common.AUTOBLOCK_TABLE
        # until this has gone through, the next poll pushes everything held (the new addresses of this
        # poll are committed already and would otherwise wait for the periodic sync)
        self.autoblock_ok = False
        self.con.execute('BEGIN IMMEDIATE')
        try:
            holding = set(r[0] for r in self.con.execute(
                'SELECT DISTINCT a.ip FROM autoblocked a JOIN conditions c ON c.id = a.cond'
                ' WHERE a.owned = 1 AND NOT (a.expires > 0 AND a.expires <= ?)', (now,)))
            push = [ip for ip in push if ip in holding]
            ok = pfstats.table_change(table, 'add', push) if push else True
            self.autoblock_ok = ok
            if ok and sync:
                self.autoblock_synced = now
            if gone:
                # still expired and held by nothing else (a condition may have been changed meanwhile)
                keep = set(r[0] for r in self.con.execute(
                    'SELECT ip FROM autoblocked WHERE NOT (expires > 0 AND expires <= ?)', (now,)))
                gone = [ip for ip in gone if ip not in keep]
                if gone and pfstats.table_change(table, 'delete', gone):
                    self.con.executemany('DELETE FROM autoblocked WHERE ip = ? AND expires > 0 AND expires <= ?',
                                         [(ip, now) for ip in gone])
            self.con.commit()
        except Exception:
            # pf may hold an address whose row is not deleted: the safe side, it is released next time
            self.con.rollback()
            raise
        self.autoblock_status['table_ok'] = self.autoblock_ok
        # after the release: what is in the table for the conditions now (not the rows still being released)
        self.autoblock_status['blocked'] = self.con.execute(
            'SELECT COUNT(DISTINCT ip) FROM autoblocked WHERE NOT (expires > 0 AND expires <= ?)', (now,)).fetchone()[0]

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
        for ip in (src, dst):
            drop = self.shaper_drops.get(ip)
            if drop is not None:
                return 'shaper %s rate limit drops' % drop['label']
        near = self.src_near.get(src)
        if near is not None:
            return 'near %s limit rule @%d %s (likely)' % (near['kind'], near['rule'], near['descr'])
        if self.rules_full and (self.last_deltas.get('state-limit') or self.last_deltas.get('max states per rule')):
            rule = self.rules_full[0]
            return 'rule @%d max states full %s (likely)' % (rule['nr'], rule['descr'])
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

    PORTS_KEEP = 50     # blocked ports stored one by one per host and direction each poll

    def store_blocked(self, now, day, bucket, blocked, per_host, per_reason):
        if not blocked:
            return
        # a flood on random ports must not add a row per port: past the busiest PORTS_KEEP ports of a host and
        # direction, the rest go into port 0 ("other ports") of their protocol
        port_load = defaultdict(Counter)
        for (ip, direction, proto, port, _), value in blocked.items():
            port_load[(ip, direction)][(proto, port)] += value[0]
        kept = dict((key, set(p for p, _ in load.most_common(self.PORTS_KEEP)) if len(load) > self.PORTS_KEEP
                     else None) for key, load in port_load.items())
        merged = {}
        for (ip, direction, proto, port, remote), value in blocked.items():
            keep = kept[(ip, direction)]
            if keep is not None and (proto, port) not in keep:
                port = 0
            item = merged.get((ip, direction, proto, port, remote))
            if item is None:
                merged[(ip, direction, proto, port, remote)] = list(value)
            else:
                if value[0] > item[0]:
                    item[2], item[3] = value[2], value[3]
                item[0] += value[0]
                item[1] += value[1]
        # keep the 20 busiest remotes per host/port, fold the rest (big DDoS) into "others"
        grouped = defaultdict(list)
        for (ip, direction, proto, port, remote), value in merged.items():
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
                # N rounded down to two digits (a lower bound still): the row of a busy port is updated, not
                # written again with a new N every poll
                items = items[:20] + [(sum(i[0] for i in rest), 'others (%d)' % _two_digits(len(rest)),
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
                           detail='%s holds %d firewall states (HostGuard warning threshold %d, not a pf limit: '
                                  'pf only limits per rule and the state table in total), %s. %s'
                                  % (host, count, limit, hint, text))
        for host, rate in rates.items():
            if rate >= rate_limit:
                text, inbound = details.get(host, ('', 0))
                hint = 'mostly inbound: possible (D)DoS target' if inbound >= 50 else \
                    'mostly outbound: possible flood, scan or compromised host'
                self.alert(now, 'host_rate', 'high', 'host_rate:%s:%d' % (host, hour), ip=host, reopen=False,
                           detail='%s opens %.0f new connections/s (HostGuard warning threshold %d), %s. %s'
                                  % (host, rate, rate_limit, hint, text))

    def pf_check(self, now, details, rates):
        self.con.commit()
        info = pfstats.read_info()
        if now - self.limits_read >= 300:
            self.pf_limits = pfstats.read_limits() or self.pf_limits
            self.limits_read = now
        rules = pfstats.read_rules()
        nodes = pfstats.read_src_nodes() if any(r['tracking'] for r in rules) else []
        # lists the aliases rules with limits use (pfctl -T show): before the first write
        self.annotate_flows(rules)
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
        self.rule_counters(now, rules)
        self.check_src_nodes(now, rules, nodes)
        self.check_rules(now, rules, nodes)
        self.con.commit()
        self.check_shaper(now)
        if self.sample_devices and now - self.reason_read >= 60:
            self.con.commit()
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

        if now - self.tables_read >= 60:
            self.tables_read = now
            self.con.commit()
            self.check_tables(now)

    #  which side a rule's per source limits count: the side that opens the connection

    def addr_is_lan(self, spec, tables):
        """ rule address -> True (monitored LAN), False (outside it), None (any / unknown) """
        neg = spec.startswith('!')
        spec = spec.lstrip('!')
        result = None
        if spec in ('any', 'all', 'self', 'no-route', 'urpf-failed', ''):
            return None
        match = re.match(r'^\(?(?P<dev>[A-Za-z][A-Za-z0-9_.]*)(?::\w+)?\)?$', spec)
        if match and not (spec.startswith('(') or ':' in spec or match.group('dev') in self.iface_labels):
            match = None
        table = re.match(r'^<(?P<name>[^>]+)>$', spec)
        if table:
            name = table.group('name')
            iface = re.match(r'^__(?P<ifname>\w+?)_(?:network|address)$', name)
            if iface and iface.group('ifname') in self.lan_names:
                result = True
            else:
                # aliases, and interface networks of interfaces not configured here: look at the entries
                if name not in tables:
                    tables[name] = self._table_is_lan(pfstats.table_entries(name))
                result = tables[name]
        elif match and not re.match(r'^[0-9a-fA-F:.]+(?:/\d+)?$', spec):
            dev = match.group('dev')
            if dev in self.lan_devices or self.iface_labels.get(dev, '').upper() == 'LAN':
                result = True
            elif self.lan_devices:
                result = False
        else:
            try:
                result = ipaddress.ip_network(spec, strict=False).network_address.compressed in self.lan
            except ValueError:
                result = None
        return (not result) if (neg and result is not None) else result

    def _table_is_lan(self, entries):
        """ an alias / table counts as LAN when most of its entries are inside the monitored networks """
        inside = outside = 0
        for entry in entries[:500]:
            try:
                net = ipaddress.ip_network(entry.strip().lstrip('!'), strict=False)
            except ValueError:
                continue
            if net.network_address.compressed in self.lan:
                inside += 1
            else:
                outside += 1
        if inside == outside == 0:
            return None
        return inside > outside

    def rule_flow(self, rule, tables):
        """
        'in'  : the rule's sources are outside, per source limits count clients connecting to your hosts
        'out' : the sources are your LAN hosts, the limits count connections your hosts open
        'lan' : LAN to LAN, ''  : cannot tell (e.g. any to any on a floating rule)
        """
        src, dst = self.addr_is_lan(rule.get('src', 'any'), tables), self.addr_is_lan(rule.get('dst', 'any'), tables)
        if src and dst:
            return 'lan'
        if src:
            return 'out'
        if dst or src is False:
            return 'in'
        iface, direction = rule.get('iface', ''), rule.get('dir', '')
        if not direction:
            return ''
        label = self.iface_labels.get(iface, '').upper()
        if iface in self.lan_devices or label == 'LAN':
            return 'out' if direction == 'in' else 'in'
        if 'WAN' in label:
            return direction
        return ''

    def annotate_flows(self, rules):
        tables = {}
        for rule in rules:
            if rule['options'] or rule['tracking']:
                rule['flow'] = self.rule_flow(rule, tables)
                where = [rule.get('dir', '') or 'in/out']
                if rule.get('iface'):
                    label = self.iface_labels.get(rule['iface'], '')
                    where.append('on %s%s' % (rule['iface'], ' (%s)' % label if label else ''))
                rule['where'] = ' '.join(where)

    def rule_nodes(self, rule, nodes):
        """
        nodes_of() narrowed to the side the rule tracks: with global tracking every address has one node,
        and a LAN host's node is not limited by a rule whose sources are outside (and vice versa)
        """
        found = self.nodes_of(rule, nodes)
        flow = rule.get('flow', '')
        if rule['tracking'] != 'global' or flow not in ('in', 'out', 'lan'):
            return found
        want_lan = flow in ('out', 'lan')
        return [n for n in found if (n['ip'] in self.lan) == want_lan]

    @staticmethod
    def src_checks(options, node):
        """ (kind, current value, limit) for every per source limit of a rule """
        checks = []
        if 'max-src-states' in options:
            checks.append(('max-src-states', node['states'], int(options['max-src-states'])))
        if 'max-src-conn' in options:
            checks.append(('max-src-conn', node['connections'], int(options['max-src-conn'])))
        if 'max-src-conn-rate' in options:
            checks.append(('max-src-conn-rate', node['rate'], int(options['max-src-conn-rate'].split('/')[0])))
        return checks

    @staticmethod
    def nodes_of(rule, nodes):
        """
        Source nodes a rule's per source limits apply to. With "source-track rule" pf keeps nodes per rule
        (-sS names the rule); with global tracking (pf's default, what OPNsense generates) one node per
        address is shared by all those rules and -sS names none.
        """
        if rule['tracking'] == 'rule':
            return [n for n in nodes if n['rule'] == rule['nr']]
        return [n for n in nodes if n['rule'] is None or n['rule'] == rule['nr']]

    def check_src_nodes(self, now, rules, nodes):
        """
        Per source limits (max-src-states, max-src-conn, max-src-conn-rate) from the source tracking
        table: name the source address and the rule at (>= 90%) its limit. With global tracking a node
        is compared with every rule using it and the strictest one is reported.
        """
        limited = [r for r in rules if r['tracking'] and any(k in r['options'] for k in
                                                             ('max-src-states', 'max-src-conn', 'max-src-conn-rate'))]
        if not limited:
            self.src_limited, self.src_at_limit, self.src_near, self.host_src = [], {}, {}, {}
            self.src_rule_hits = []
            return
        descriptions = pfstats.rule_descriptions()
        hour = now - now % 3600
        best, host_src = {}, {}
        # every (outside source, rule, limit) at the limit, not only the strictest rule per source:
        # block conditions name one rule, global tracking can put a source over several
        self.src_rule_hits = []
        for rule in limited:
            for node in self.rule_nodes(rule, nodes):
                for kind, value, limit in self.src_checks(rule['options'], node):
                    if not limit:
                        continue
                    pct = round(value * 100.0 / limit, 1)
                    # with global tracking the node counts the source's states of every rule, pf compares it with
                    # this rule's limit only when the source opens a connection through this rule
                    outside = node['ip'] not in self.lan
                    uses = rule['tracking'] == 'rule' or (node['ip'], rule['nr']) in self.rule_users
                    if value >= limit and outside and uses and len(self.src_rule_hits) < 50000:
                        self.src_rule_hits.append((node['ip'], rule['label'], rule['nr'], kind))
                    if node['ip'] in self.lan:
                        # the per source limit that is closest to stopping this LAN host's own connections
                        mine = host_src.get(node['ip'])
                        if mine is None or pct > mine['pct']:
                            host_src[node['ip']] = {'kind': kind, 'value': value, 'limit': limit, 'pct': pct,
                                                    'rule': rule['nr'], 'tracking': rule['tracking'],
                                                    'descr': descriptions.get(rule['label'], '') or rule['text'][:80]}
                    if value < limit * 0.9:
                        continue
                    key = (node['ip'], kind)
                    # a rule the source uses comes before a stricter one it has no state of (global tracking)
                    if key in best and (best[key]['uses'], best[key]['pct']) >= (uses or not outside, pct):
                        continue
                    best[key] = {
                        'ip': node['ip'], 'lan': node['ip'] in self.lan, 'rule': rule['nr'],
                        'descr': descriptions.get(rule['label'], '') or rule['text'][:80], 'kind': kind,
                        'tracking': rule['tracking'], 'value': value, 'limit': limit, 'pct': pct,
                        'at_limit': value >= limit, 'states': node['states'], 'connections': node['connections'],
                        'rate': '%s/%ss' % (node['rate'], node['rate_seconds']),
                        # the source opens the connections: a LAN source is limited going out, others coming in
                        'dir': 'out' if node['ip'] in self.lan else 'in', 'where': rule.get('where', ''),
                        # "15/5" for max-src-conn-rate: 15 new connections per 5 seconds
                        'limit_text': rule['options'].get(kind, str(limit)),
                        # stable across rule reloads (the number is not): block conditions refer to it
                        'label': rule['label'],
                        # False: an outside source over this rule's limit (global tracking) without a state of
                        # the rule, its connections go through others; dropped once it tries this rule
                        'uses': uses or not outside,
                    }
        found = sorted(best.values(), key=lambda f: (-f['pct'], f['ip']))
        self.src_limited = found[:200]
        self.host_src = dict(sorted(host_src.items(), key=lambda x: -x[1]['pct'])[:500])
        at_limit = [f for f in found if f['at_limit']]
        self.src_at_limit = {f['ip']: f for f in at_limit}
        self.src_near = {f['ip']: f for f in found if not f['at_limit'] and f['pct'] >= 95}
        self.con.executemany(
            """INSERT INTO srclimits (ip, nr, kind, descr, limit_value, peak, first_seen, last_seen, hits, label)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
               ON CONFLICT (ip, nr, kind) DO UPDATE SET descr = excluded.descr, limit_value = excluded.limit_value,
                   peak = MAX(peak, excluded.peak), last_seen = excluded.last_seen, hits = hits + 1,
                   label = excluded.label""",
            [(f['ip'], f['rule'], f['kind'], f['descr'], f['limit'], int(f['value']), now, now, f['label'] or '')
             for f in at_limit])
        for f in at_limit:
            if f['lan']:
                who = 'OUTBOUND: LAN host %s (connections it opens)' % f['ip']
                hint = ''
            else:
                who = 'INBOUND: external client %s (connections it opens to your hosts)' % f['ip']
                hint = ' (the limit protects your hosts from it)'
            if f['tracking'] == 'global':
                hint += '; global source tracking: the count is shared by all rules with per source limits'
            # global tracking, no state of this rule: its connections go through other rules
            dropped = 'new connections are dropped' if f['uses'] else \
                'new connections through this rule would be dropped (it has none now, its count comes from others)'
            self.alert(now, 'src_limit', 'high' if f['lan'] else 'medium',
                       'src_limit:%s:%d:%s:%d' % (f['ip'], f['rule'], f['kind'], hour), ip=f['ip'], reopen=False,
                       peer=str(f['rule']),
                       detail='%s is at %s %s/%d on rule @%d (%s%s), %s%s'
                              % (who, f['kind'], self._num(f['value']), f['limit'], f['rule'], f['descr'],
                                 ', ' + f['where'] if f['where'] else '', dropped, hint))

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
            '%s%s (%s %s/%d, rule @%d "%s")' % (f['ip'], ' [LAN, outbound]' if f['lan'] else ' [inbound]', f['kind'],
                                                 self._num(f['value']), f['limit'], f['rule'], f['descr'])
            for f in hits[:5])

    def check_rules(self, now, all_rules, nodes):
        """
        Fill ratio of every limit a rule carries, taken from the rule itself:
        max (states of the rule), max-src-nodes (sources of the rule) and, per source,
        max-src-states / max-src-conn / max-src-conn-rate (busiest source shown).
        """
        hour = now - now % 3600
        descriptions = pfstats.rule_descriptions()
        rules = []
        for rule in all_rules:
            options = rule['options']
            if not options:
                continue
            metrics = []
            if 'max' in options:
                metrics.append({'kind': 'max', 'value': rule['states'], 'limit': int(options['max']), 'ip': ''})
            sources = self.rule_nodes(rule, nodes) if rule['tracking'] else []
            if 'max-src-nodes' in options and rule['tracking'] == 'rule':
                metrics.append({'kind': 'max-src-nodes', 'value': len(sources),
                                'limit': int(options['max-src-nodes']), 'ip': ''})
            over80 = set()
            if sources:
                per_kind = {}
                for node in sources:
                    for kind, value, limit in self.src_checks(options, node):
                        if limit and value >= limit * 0.8:
                            over80.add(node['ip'])
                        if kind not in per_kind or value > per_kind[kind]['value']:
                            per_kind[kind] = {'kind': kind, 'value': value, 'limit': limit, 'ip': node['ip']}
                metrics.extend(per_kind[k] for k in ('max-src-states', 'max-src-conn', 'max-src-conn-rate')
                               if k in per_kind)
            for metric in metrics:
                metric['pct'] = round(metric['value'] * 100.0 / metric['limit'], 1) if metric['limit'] else 0.0
            usage = next((m['pct'] for m in metrics if m['kind'] == 'max'), None)
            rules.append({
                'nr': rule['nr'], 'label': rule['label'], 'text': rule['text'], 'options': options,
                'descr': descriptions.get(rule['label'], ''), 'tracking': rule['tracking'], 'states': rule['states'],
                'flow': rule.get('flow', ''), 'where': rule.get('where', ''),
                'usage': usage, 'metrics': metrics, 'sources': len(sources), 'over80': len(over80),
                'worst': max([m['pct'] for m in metrics] or [0.0]),
            })
            name = descriptions.get(rule['label'], '') or rule['text'][:100]
            for metric in metrics:
                if metric['kind'] in ('max', 'max-src-nodes') and metric['limit'] and metric['pct'] >= 90:
                    what = 'states' if metric['kind'] == 'max' else 'source addresses'
                    self.alert(now, 'rule_limit', 'critical' if metric['pct'] >= 100 else 'high',
                               'rule_limit:%d:%s:%d' % (rule['nr'], metric['kind'], hour), reopen=False,
                               peer=str(rule['nr']),
                               detail='rule @%d (%s) holds %d of %s %d %s (%.0f%%)'
                                      % (rule['nr'], name, metric['value'], metric['kind'], metric['limit'], what,
                                         metric['pct']))
        rules.sort(key=lambda r: (-r['worst'], r['nr']))
        self.rules = rules[:100]
        self.rules_full = [r for r in rules if r['usage'] is not None and r['usage'] >= 99]

    #  traffic shaper (ipfw / dummynet)

    def shaper_config(self):
        try:
            mtime = os.path.getmtime(shaper.CONFIG_XML)
        except OSError:
            return {'pipes': {}, 'queues': {}, 'rules': []}
        if mtime != self.shaper_cfg_mtime:
            self.shaper_cfg = shaper.read_config()
            self.shaper_cfg_mtime = mtime
        return self.shaper_cfg

    def check_shaper(self, now):
        """
        Bandwidth limits of the shaper pipes / queues and how full they are, per flow (per IP when the
        pipe or queue has a mask): throughput from byte counter deltas, drops from the drop counters.
        """
        pipes, queues = shaper.read_pipes(), shaper.read_queues()
        if not pipes and not queues:
            self.shaper, self.shaper_drops = {}, {}
            return
        config = self.shaper_config()
        interval = float(now - self.shaper_last) if self.shaper_last else None
        self.shaper_last = now
        previous, current = self.shaper_prev, {}
        bandwidth = dict((p['nr'], p['bandwidth']) for p in pipes)
        hour = now - now % 3600
        threshold = self.cfg['shaper_drop_pps']
        flows, objects, drops_by_ip, hits = [], [], {}, []

        def label(kind, nr, meta):
            return '%s %d%s' % (kind, nr, ' "%s"' % meta['descr'] if meta.get('descr') else '')

        for kind, items in (('pipe', pipes), ('queue', queues)):
            for item in items:
                meta = config['pipes' if kind == 'pipe' else 'queues'].get(item['nr'], {})
                limit = item['bandwidth'] if kind == 'pipe' else bandwidth.get(item['pipe'], 0)
                name = label(kind, item['nr'], meta)
                total_bps = total_dps = 0.0
                peak_util = 0.0
                for flow in item['flows']:
                    key = (kind, item['nr'], flow['src'], flow['dst'])
                    current[key] = (flow['bytes'], flow['drops'])
                    old = previous.get(key)
                    if old is None or interval is None or flow['bytes'] < old[0] or not interval:
                        continue      # first sighting: rate unknown until the next poll
                    bps = (flow['bytes'] - old[0]) * 8 / interval
                    dps = max(0, flow['drops'] - old[1]) / interval
                    total_bps += bps
                    total_dps += dps
                    side = item['mask']
                    if side == 'src':
                        ip = flow['src']
                    elif side == 'dst':
                        ip = flow['dst']
                    elif side == 'both':
                        ip = flow['src'] if flow['src'] in self.lan else flow['dst']
                    else:
                        ip = ''         # shared pipe / queue: one flow for everybody
                    # masked pipe: every flow gets the full bandwidth; queues share their pipe by weight
                    util = round(bps * 100.0 / limit, 1) if limit and (kind == 'pipe' and side != 'none'
                                                                       or kind == 'queue') else None
                    peak_util = max(peak_util, util or 0)
                    flows.append({'kind': kind, 'nr': item['nr'], 'name': name, 'ip': ip, 'lan': ip in self.lan,
                                  'bps': round(bps), 'limit': limit, 'util': util, 'drops_ps': round(dps, 1),
                                  'drops_total': flow['drops'], 'queued': flow['queued']})
                    if ip and dps > 0:
                        if ip not in drops_by_ip or dps > drops_by_ip[ip]['dps']:
                            drops_by_ip[ip] = {'dps': dps, 'label': name}
                        hits.append((ip, kind, item['nr'], meta.get('descr', ''), limit, int(bps), now, now,
                                     int(round(dps * interval))))
                    if ip and dps >= threshold:
                        who = 'LAN host %s' % ip if ip in self.lan else 'Address %s' % ip
                        per = 'per IP' if kind == 'pipe' else 'shared, weight %s' % item.get('weight')
                        self.alert(now, 'shaper_drop', 'high' if ip in self.lan else 'medium',
                                   'shaper_drop:%s:%s:%d:%d' % (ip, kind, item['nr'], hour), ip=ip, reopen=False,
                                   peer='%s %d' % (kind, item['nr']),
                                   detail='%s is rate limited by shaper %s (%s, %s): %s now, %s, dropping ~%.0f pkt/s'
                                          % (who, name, self._bits(limit), per, self._bits(bps),
                                             '%.0f%% of the limit' % util if util is not None else 'shared',
                                             dps))
                if item['mask'] == 'none' and kind == 'pipe' and limit:
                    peak_util = round(total_bps * 100.0 / limit, 1)
                    if total_dps >= threshold:
                        self.alert(now, 'shaper_drop', 'medium', 'shaper_drop:pipe:%d:%d' % (item['nr'], hour),
                                   reopen=False, peer='pipe %d' % item['nr'],
                                   detail='shared shaper %s (%s for everyone in it) is full: %s now, dropping ~%.0f pkt/s'
                                          % (name, self._bits(limit), self._bits(total_bps), total_dps))
                objects.append({
                    'kind': kind, 'nr': item['nr'], 'name': name, 'descr': meta.get('descr', ''),
                    'limit': limit, 'mask': item['mask'], 'pipe': item.get('pipe'), 'weight': item.get('weight'),
                    'flows': len(item['flows']), 'bps': round(total_bps), 'util': peak_util,
                    'drops_ps': round(total_dps, 1),
                    'rules': ['%s %s %s -> %s%s' % (r['interface'], r['direction'], r['source'], r['destination'],
                                                    ' (%s)' % r['descr'] if r['descr'] else '')
                              for r in meta.get('rules', []) if r['enabled']],
                })
        self.shaper_prev = current
        flows.sort(key=lambda f: (-f['drops_ps'], -(f['util'] or 0), -f['bps']))
        self.shaper = {'objects': objects, 'flows': flows[:300], 'interval': interval}
        self.shaper_drops = drops_by_ip
        self.con.executemany(
            """INSERT INTO shaperhits (ip, kind, nr, descr, limit_bps, peak_bps, first_seen, last_seen, drops)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT (ip, kind, nr) DO UPDATE SET descr = excluded.descr, limit_bps = excluded.limit_bps,
                   peak_bps = MAX(peak_bps, excluded.peak_bps), last_seen = excluded.last_seen,
                   drops = drops + excluded.drops""", hits)

    @staticmethod
    def _bits(bps):
        for unit, size in (('Gbit/s', 1e9), ('Mbit/s', 1e6), ('Kbit/s', 1e3)):
            if bps >= size:
                return '%.1f %s' % (bps / size, unit)
        return '%d bit/s' % bps

    def check_tables(self, now):
        """ LAN hosts listed in overload / lockout / CrowdSec tables """
        patterns = [p.strip().lower() for p in self.cfg['watch_tables'].split(',') if p.strip()]
        tables = []
        # every table is read before the first write
        listed = [(name, pfstats.table_show(name)) for name in pfstats.list_tables()
                  if any(p in name.lower() for p in patterns)]
        for name, entries in listed:
            if entries is None:
                # pfctl failed or timed out: not "the table is empty", which would make every LAN host still
                # listed look new next time (and reopen its acknowledged alert)
                continue
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
            'rule_activity': self.rule_activity, 'src_limited': self.src_limited, 'shaper': self.shaper,
            'host_src': self.host_src, 'attacks_now': self.attacks_now[:50],
            'ids': {'enabled': self.eve is not None, 'path': self.cfg['ids_eve'],
                    'readable': os.access(self.cfg['ids_eve'], os.R_OK), 'alerts_last_poll': self.ids_last},
            'crowdsec': {'enabled': bool(self.cfg['crowdsec_enabled']), 'decisions': self.crowdsec_count},
            'autoblock': self.autoblock_status,
        })

    def read_blocked(self, now, day, lateral):
        """ LAN to LAN packets the rules blocked (no pf state, only in the firewall log) """
        self.blocked_last = 0
        self.logged_lateral = Counter()
        if self.filterlog is None:
            return
        for proto, src, dst, port in self.filterlog.read():
            if src in self.lan and self.is_lan_host(dst) and not (self.cfg['ignore_self'] and src in self.own):
                key = (day, src, dst, proto, port)
                item = lateral.setdefault(key, [0, 0, 0, 0])
                item[0] += 1
                item[3] += 1
                self.logged_lateral[key] += 1
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

    L2_NEW_MAX = 1000   # new MAC / IP bindings in one poll past which it is a flood, not hosts
    L2_HELD_MAX = 200000    # bindings held back during a flood

    def poll_l2(self, now):
        """ track MAC <-> IP bindings and alert on multiple / changed addresses """
        window = now - self.cfg['l2_window'] * 3600

        def wanted(ip, mac):
            return ip in self.lan and ip not in self.own and mac not in self.ignored_macs and not l2.is_virtual(mac)

        table = []
        if self.cfg['l2_source'] in ('both', 'table'):
            table = [e for e in l2.read_neighbors() if wanted(e[0], e[1])]
        self.arp_entries = len(table)
        events, recent, dropped = [], [], 0
        if self.sniffer is not None:
            drained, dropped = self.sniffer.drain()
            events = [(ip, mac, dev) for _, ip, mac, dev in drained if wanted(ip, mac)]
            recent = [e for e in self.sniffer.recent(600) if wanted(e[0], e[1])]
            # the ARP cache may hold a stale MAC for up to 20 minutes, trust what was heard on the wire
            heard = set(ip for ip, _, _ in self.sniffer.recent(1800))
            table = [e for e in table if e[0] not in heard]
        entries = events + table        # in order of observation

        known = {}
        for mac, ip, last in self.con.execute(
                'SELECT mac, ip, last_seen FROM l2bind WHERE last_seen >= ?', (window,)):
            known.setdefault(mac, {})[ip] = last
        # an ARP / ND flood (random addresses): one alert, its bindings are held back instead of recorded one by
        # one. A binding held back and heard again in a later poll is a real host (a fresh install on a big
        # LAN, an ARP table read every poll): it is recorded then, quietly
        self.l2_held = dict((b, ts) for b, ts in self.l2_held.items() if ts >= now - 3600)
        new = set((ip, mac) for ip, mac, _ in entries if ip not in known.get(mac, {}))
        quiet = set(b for b in new if b in self.l2_held)
        fresh = new - quiet
        if len(fresh) > self.L2_NEW_MAX:
            devices = Counter(ifc for ip, mac, ifc in entries if (ip, mac) in fresh)
            macs = Counter(mac for _, mac in fresh)
            self.alert(now, 'l2_flood', 'high', 'l2_flood', peer=','.join(d for d, _ in devices.most_common(3)),
                       detail='ARP / ND flood: %d new MAC / IP bindings in one poll%s on %s (busiest MACs: %s); '
                              'only those heard again later are recorded'
                              % (len(fresh), ' (%d more observations dropped)' % dropped if dropped else '',
                                 ', '.join(d for d, _ in devices.most_common(3)),
                                 ', '.join('%s (%d)' % m for m in macs.most_common(3))))
            for binding in fresh:
                self.l2_held[binding] = now
            if len(self.l2_held) > self.L2_HELD_MAX:
                self.l2_held = dict(heapq.nlargest(self.L2_HELD_MAX // 2, self.l2_held.items(), key=lambda kv: kv[1]))
            entries = [e for e in entries if (e[0], e[1]) not in fresh]
        for binding in quiet:
            self.l2_held.pop(binding, None)
        # only bindings accepted now or known before are kept (the sniffer's "recent" still holds a flood)
        accepted = set((ip, mac) for ip, mac, _ in entries)
        recent = [e for e in recent if (e[0], e[1]) in accepted or e[0] in known.get(e[1], {})]
        table = [e for e in table if (e[0], e[1]) in accepted or e[0] in known.get(e[1], {})]
        current = defaultdict(set)
        for ip, mac, _ in recent + table:
            current[mac].add(ip)

        for ip, mac, ifc in entries:
            if (ip, mac) in quiet:
                self.ip_mac[ip] = mac
                known.setdefault(mac, {})[ip] = now
                continue
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

    LATERAL_KEEP = 200  # LAN to LAN destination ports stored one by one per source each poll

    def fold_lateral(self, lateral):
        """ a scan across the LAN must not add a row per destination port: past the busiest LATERAL_KEEP
        (destination, port) of a source, the rest go into port 0 ("other ports") per destination """
        per_src = defaultdict(list)
        for key in lateral:
            per_src[key[1]].append(key)
        if all(len(keys) <= self.LATERAL_KEEP for keys in per_src.values()):
            return lateral
        folded = {}
        for keys in per_src.values():
            keys.sort(key=lambda k: -lateral[k][0])
            for i, key in enumerate(keys):
                target = key if i < self.LATERAL_KEEP else key[:4] + (0,)
                item = folded.setdefault(target, [0, 0, 0, 0])
                for n, value in enumerate(lateral[key]):
                    item[n] += value
        return folded

    def store(self, now, ts_host, ts_port, flows, hosts, lateral):
        con = self.con
        lateral = self.fold_lateral(lateral)
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
            if self.states_ok:
                # without the states of this poll nobody is known to be inactive
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
                                  ('ts_rules', 'ts'), ('srclimits', 'last_seen'), ('blocked_reasons', 'last_seen'),
                                  ('shaperhits', 'last_seen'), ('attacks', 'last_seen'), ('ids_alerts', 'last_seen')):
                self.con.execute('DELETE FROM %s WHERE %s < ?' % (table, column), (cutoff,))
            # decisions that ran out a day ago; conditions and what they blocked stay until removed / expired
            self.con.execute('DELETE FROM crowdsec WHERE until < ?', (now - 86400,))
        # the last MAC per IP only for the bindings still kept
        bound = set(r[0] for r in self.con.execute('SELECT DISTINCT ip FROM l2bind'))
        self.ip_mac = dict((ip, mac) for ip, mac in self.ip_mac.items() if ip in bound)
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


class IpDataUpdater(threading.Thread):
    """ keeps the owner / network type lists (lib/ipdata.py) at most a day old, in a child process """
    SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'update_ipdata.py')

    def __init__(self, stop):
        super().__init__(name='ipdata', daemon=True)
        self.stop = stop

    def run(self):
        if self.stop.wait(60):
            return
        while True:
            if ipdata.due():
                try:
                    out = subprocess.run([sys.executable, self.SCRIPT], capture_output=True, text=True,
                                         timeout=1800).stdout
                    result = json.loads(out or '{}')
                    if result.get('status') == 'error':
                        log(syslog.LOG_WARNING, 'outside source lists not updated: %s' % result.get('message'))
                    elif result.get('status') == 'ok':
                        failed = sorted(k for k, v in result.get('sources', {}).items() if isinstance(v, str))
                        log(syslog.LOG_INFO, 'outside source lists updated%s'
                            % ('' if not failed else ', could not download %s' % ', '.join(failed)))
                except (OSError, ValueError, subprocess.SubprocessError) as exc:
                    log(syslog.LOG_WARNING, 'outside source lists not updated: %s' % exc)
            # an hour after a failed try (nothing new came: the data is as old as before), once three hours
            # after one that missed a list, otherwise when the data turns a day old
            if self.stop.wait(3600):
                return


def main():
    syslog.openlog('hostguard', syslog.LOG_PID, syslog.LOG_DAEMON)
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
    if cfg['ipdata_enabled']:
        IpDataUpdater(stop).start()

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
        # every poll while the firewall's own addresses are unknown (ifconfig failed): block conditions wait
        if started - collector.resolved > 300 or not collector.own_seen:
            collector.refresh_networks()
        stop.wait(max(1.0, cfg['poll_interval'] - (time.time() - started)))
    log(syslog.LOG_NOTICE, 'stopped')
    return 0


if __name__ == '__main__':
    sys.exit(main())
