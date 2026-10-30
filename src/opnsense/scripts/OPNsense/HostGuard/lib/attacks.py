"""
    Copyright (c) 2026 Onur Berkay <onurberkay@sakla.app>
    All rights reserved. (BSD 2-Clause, see LICENSE)

    Attacks on LAN hosts from outside.

    TargetStats   per LAN host counters built from the sampled inbound attempts (blocked and passed),
                  classified into an attack type: reflection / amplification, SYN / UDP / ICMP flood,
                  distributed brute force, port scan. No extra capture: the blocked traffic samples are reused.
    EveReader     Suricata alerts from eve.json, read incrementally with a byte cap per poll.
    crowdsec      local CrowdSec decisions (cscli decisions list -o json): scenario per banned address.
"""
import ipaddress
import json
import os
import re
import subprocess
from collections import Counter

# UDP source ports of services abused for reflection / amplification
REFLECT_PORTS = {
    17: 'qotd', 19: 'chargen', 53: 'dns', 69: 'tftp', 111: 'portmap', 123: 'ntp', 137: 'netbios', 161: 'snmp',
    389: 'cldap', 427: 'slp', 520: 'rip', 1434: 'mssql', 1900: 'ssdp', 3283: 'ard', 3389: 'rdp',
    3478: 'stun', 3702: 'ws-discovery', 5353: 'mdns', 5683: 'coap', 10001: 'ubiquiti', 10074: 'mitel',
    11211: 'memcached', 27015: 'steam', 30718: 'lantronix', 32414: 'plex', 37810: 'dvr', 47808: 'bacnet',
}
# login services: many sources on one of these is a distributed brute force
AUTH_PORTS = {21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 110: 'pop3', 143: 'imap', 445: 'smb', 465: 'smtps',
              587: 'submission', 993: 'imaps', 995: 'pop3s', 1433: 'mssql', 3306: 'mysql', 3389: 'rdp',
              5432: 'postgresql', 5900: 'vnc', 8006: 'proxmox', 2222: 'ssh', 8443: 'https-alt'}


class TargetStats:
    """ inbound attempts towards one LAN host during one poll (scaled estimates) """

    def __init__(self):
        self.total = 0.0
        self.passed = 0.0
        self.proto = Counter()
        self.reflect = Counter()      # reflected service -> packets
        self.ports = Counter()        # proto/port -> packets
        self.sources = Counter()      # source -> packets
        self.source_ports = {}        # source -> set of ports (scan detection), only kept for a few sources
        # what a block condition may take: the sources of the attack itself, not every visitor of the host
        self.reflect_sources = Counter()  # source -> UDP packets from a reflection port
        self.port_sources = {}            # 'tcp/22' / 'icmp' -> Counter(source -> packets)
        self.scale = 1.0
        # sampled packets themselves (not scaled: captures of different scale can reach one host), to tell a
        # reflector (mostly replies from a reflection port) from a source that adds a few of them
        self.sampled = Counter()          # source -> sampled packets
        self.sampled_reflect = Counter()  # source -> sampled UDP packets from a reflection port

    def add(self, proto, src, sport, dport, scale, passed):
        self.total += scale
        self.scale = max(self.scale, scale)
        if passed:
            self.passed += scale
        family = 'icmp' if proto in ('icmp', 'ipv6-icmp') else proto
        self.proto[family] += scale
        self.sampled[src] += 1
        if proto == 'udp' and sport in REFLECT_PORTS:
            self.reflect[REFLECT_PORTS[sport]] += scale
            self.reflect_sources[src] += scale
            self.sampled_reflect[src] += 1
        port = 'icmp' if family == 'icmp' else '%s/%d' % (proto, dport)
        if family != 'icmp':
            self.ports[port] += scale
        per_port = self.port_sources.get(port)
        if per_port is None and len(self.port_sources) < 100:
            per_port = self.port_sources[port] = Counter()
        if per_port is not None:
            per_port[src] += scale
        self.sources[src] += scale
        ports = self.source_ports.get(src)
        if ports is None and len(self.source_ports) < 50:
            ports = self.source_ports[src] = set()
        if ports is not None and len(ports) < 1000:
            ports.add((proto, dport))

    def classify(self):
        """ -> (kind, detail) """
        total = self.total or 1.0
        reflect = sum(self.reflect.values())
        if reflect >= total * 0.5:
            names = ', '.join(name for name, _ in self.reflect.most_common(3))
            return 'reflection', 'UDP replies from %s servers (amplification)' % names
        top_src, top_pkts = self.sources.most_common(1)[0] if self.sources else ('', 0)
        if top_pkts >= total * 0.7 and len(self.source_ports.get(top_src, ())) >= 20:
            return 'port scan', '%s tried %d ports' % (top_src, len(self.source_ports[top_src]))
        share = dict((p, n / total) for p, n in self.proto.items())
        port, port_pkts = self.ports.most_common(1)[0] if self.ports else ('', 0)
        if share.get('tcp', 0) >= 0.6:
            number = int(port.split('/')[1]) if port.startswith('tcp/') else 0
            if number in AUTH_PORTS and port_pkts >= total * 0.6 and len(self.sources) >= 10:
                return 'brute force', 'distributed login attempts on %s (%s) from %d sources' % (
                    port, AUTH_PORTS[number], len(self.sources))
            return 'syn flood', 'TCP SYN, top port %s' % port
        if share.get('udp', 0) >= 0.6:
            return 'udp flood', 'UDP, top port %s' % port
        if share.get('icmp', 0) >= 0.6:
            return 'icmp flood', 'ICMP echo'
        return 'mixed flood', ', '.join('%s %d%%' % (p, round(s * 100)) for p, s in sorted(share.items()))

    def is_brute_force(self):
        return self.classify()[0] == 'brute force'

    def attack_sources(self, kind):
        """
        The sources a block condition on this attack may block: those sending what makes it this kind of
        attack, at least two sampled packets each (a visitor of the same service opens one connection;
        randomly spoofed floods have no repeat sources and nothing worth blocking). Floods also need a share.
        """
        repeat = 2 * self.scale
        if kind == 'reflection':
            return [s for s, n in self.sampled_reflect.items() if n >= 2]
        if kind == 'port scan':
            top = self.sources.most_common(1)
            return [top[0][0]] if top else []
        if kind == 'brute force':
            port = self.ports.most_common(1)[0][0] if self.ports else ''
            return [s for s, n in self.port_sources.get(port, {}).items() if n >= repeat]
        if kind == 'icmp flood':
            ports = ['icmp']
        elif kind in ('syn flood', 'udp flood'):
            family = 'tcp/' if kind == 'syn flood' else 'udp/'
            ports = [p for p, _ in self.ports.most_common() if p.startswith(family)][:1]
        else:
            ports = [p for p, _ in self.ports.most_common(1)] + ['icmp']
        share = max(repeat, self.total * 0.01)
        found = set()
        for port in ports:
            found.update(s for s, n in self.port_sources.get(port, {}).items() if n >= share)
        return sorted(found)


def _address(text):
    try:
        return ipaddress.ip_address(str(text or '')).compressed
    except ValueError:
        return ''


class EveReader:
    """ Suricata eve.json alerts, only what was appended since the last read """
    MAX_BYTES = 8 * 1024 * 1024

    def __init__(self, path):
        self.path = path
        self.inode = None
        self.offset = None

    def read(self):
        """ -> [{ts, src, dst, sport, dport, proto, sid, signature, category, severity, action}] """
        try:
            st = os.stat(self.path)
        except OSError:
            return []
        if self.offset is None or st.st_ino != self.inode or st.st_size < self.offset:
            # first read starts at the end (no history import), a rotated file from the start
            self.offset = st.st_size if self.offset is None else 0
            self.inode = st.st_ino
        if st.st_size == self.offset:
            return []
        alerts = []
        try:
            with open(self.path, 'rb') as handle:
                st = os.fstat(handle.fileno())      # the file actually opened, its size below
                if st.st_ino != self.inode:
                    # rotated between stat and open: this is the new file, from its start
                    self.inode, self.offset = st.st_ino, 0
                handle.seek(self.offset)
                data = handle.read(self.MAX_BYTES)
        except OSError:
            # rotated or removed between stat and open: the next poll sees the new file
            return []
        end = data.rfind(b'\n')
        if end < 0:
            if len(data) >= self.MAX_BYTES:
                # one line longer than the cap: skip it rather than reading it again every poll
                self.offset = max(st.st_size, self.offset + len(data))
            return []
        # skip what did not fit: an attack must not make us fall behind for ever (the file may have grown
        # past the size seen before reading: never back to what was just read)
        self.offset = (max(st.st_size, self.offset + end + 1) if len(data) >= self.MAX_BYTES
                       else self.offset + end + 1)
        for line in data[:end].split(b'\n'):
            if b'"event_type":"alert"' not in line:
                continue
            try:
                event = json.loads(line)
            except ValueError:
                continue
            alert = event.get('alert') or {}
            alerts.append({
                # Suricata writes IPv6 addresses without shortening them
                'src': _address(event.get('src_ip')), 'dst': _address(event.get('dest_ip')),
                'sport': event.get('src_port') or 0, 'dport': event.get('dest_port') or 0,
                'proto': str(event.get('proto', '')).lower(), 'sid': alert.get('signature_id') or 0,
                'signature': str(alert.get('signature', ''))[:200], 'category': str(alert.get('category', ''))[:100],
                'severity': alert.get('severity') or 3, 'action': alert.get('action', ''),
            })
        return alerts


CSCLI = '/usr/local/bin/cscli'
# Go durations: "3h59m30.5s", "500ms", "-1s" (ms before m, or 500ms reads as 500 minutes)
DURATION_RE = re.compile(r'(\d+(?:\.\d+)?)(ms|h|m|s)')


def _seconds(text):
    units = {'h': 3600, 'm': 60, 's': 1, 'ms': 0.001}
    text = (text or '').strip()
    seconds = sum(float(n) * units[u] for n, u in DURATION_RE.findall(text))
    return int(-seconds if text.startswith('-') else seconds)


def parse_decisions(text, now):
    """ cscli decisions list -o json -> {address or range: {scenario, origin, action, until}};
    None when the output is not that list (truncated, a warning on stdout): not "nothing banned" """
    try:
        data = json.loads(text or 'null') or []
    except ValueError:
        return None
    if not isinstance(data, list):
        return None
    result = {}
    for alert in data:
        for decision in alert.get('decisions') or []:
            value = decision.get('value')
            if not value:
                continue
            result[value] = {'scenario': decision.get('scenario') or alert.get('scenario') or '',
                             'origin': decision.get('origin', ''), 'action': decision.get('type', ''),
                             'until': now + _seconds(decision.get('duration', ''))}
    return result


def read_decisions(now):
    if not os.path.exists(CSCLI):
        return None
    try:
        res = subprocess.run([CSCLI, 'decisions', 'list', '--limit', '0', '-o', 'json'], capture_output=True, text=True,
                             errors='replace', timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    # no output is a failure (no decisions prints "null"), not "0 decisions"
    if res.returncode != 0 or not res.stdout.strip():
        return None
    return parse_decisions(res.stdout, now)
