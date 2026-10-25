"""
    Copyright (c) 2026 Onur Berkay <onurberkay@sakla.app>
    All rights reserved. (BSD 2-Clause, see LICENSE)

    MAC <-> IP bindings from the firewall's neighbour tables and, for
    transparent bridges (where the firewall itself rarely talks to the hosts),
    by passively listening to ARP / IPv6 neighbour discovery with tcpdump.

    arp -an:
        ? (10.0.0.5) at 52:54:00:12:34:56 on vtnet1 expires in 1185 seconds [ethernet]
        ? (10.0.0.1) at 52:54:00:aa:bb:cc on vtnet1 permanent [ethernet]     <- own address, skipped
        ? (10.0.0.9) at (incomplete) on vtnet1 expired [ethernet]            <- skipped
    ndp -an:
        Neighbor                Linklayer Address  Netif Expire    1s 5s
        2001:db8::5             52:54:00:12:34:56  vtnet1 23h59m59s S R
"""
import re
import subprocess
import threading
import time

from .common import normalize_mac

ARP = '/usr/sbin/arp'
NDP = '/usr/sbin/ndp'
TCPDUMP = '/usr/sbin/tcpdump'
IFCONFIG = '/sbin/ifconfig'

ND = '(icmp6 and ip6[40] >= 135 and ip6[40] <= 136)'
SNIFF_FILTER = 'arp or %s or (vlan and (arp or %s))' % (ND, ND)
TD_SRC_RE = re.compile(r'^\S+ (?P<smac>[0-9a-fA-F:]{11,17}) > [0-9a-fA-F:]{11,17},')
TD_REQUEST_RE = re.compile(r'Request who-has \S+(?: \([^)]*\))? tell (?P<ip>[0-9.]+)')
TD_REPLY_RE = re.compile(r'Reply (?P<ip>[0-9.]+) is-at (?P<mac>[0-9a-fA-F:]{11,17})')
TD_ND_RE = re.compile(r': (?P<ip>[0-9a-fA-F:]+) > [0-9a-fA-F:.]+: ICMP6, neighbor (?:solicitation|advertisement)')

ARP_RE = re.compile(r'^\S+ \((?P<ip>[0-9.]+)\) at (?P<mac>[0-9a-fA-F:]+) on (?P<ifc>\S+)(?P<rest>.*)$')
NDP_RE = re.compile(r'^(?P<ip>[0-9a-fA-F:]+)(?:%\S+)?\s+(?P<mac>[0-9a-fA-F:]+)\s+(?P<ifc>\S+)\s+(?P<exp>\S+)')

# VRRP / CARP virtual MACs (other HA members, routers) are shared on purpose
VIRTUAL_MAC_PREFIXES = ('00:00:5e:00:01:', '00:00:5e:00:02:')


def _run(args):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=15).stdout
    except (OSError, subprocess.SubprocessError):
        return ''


def parse_arp(text):
    for line in text.splitlines():
        match = ARP_RE.match(line.strip())
        if not match or 'permanent' in match.group('rest'):
            continue
        mac = normalize_mac(match.group('mac'))
        if mac:
            yield match.group('ip'), mac, match.group('ifc')


def parse_ndp(text):
    for line in text.splitlines():
        match = NDP_RE.match(line.strip())
        if not match or match.group('exp') == 'permanent' or match.group('ip').lower().startswith('fe80'):
            continue
        mac = normalize_mac(match.group('mac'))
        if mac:
            yield match.group('ip').lower(), mac, match.group('ifc')


def read_neighbors():
    """ [(ip, mac, interface)] currently known by the firewall """
    return list(parse_arp(_run([ARP, '-an']))) + list(parse_ndp(_run([NDP, '-an'])))


def is_virtual(mac):
    return mac.startswith(VIRTUAL_MAC_PREFIXES)


def parse_tcpdump_line(line):
    """ tcpdump -e -n line -> (ip, mac) announced by the sender, or None """
    src = TD_SRC_RE.match(line)
    if not src:
        return None
    match = TD_REPLY_RE.search(line)
    if match:
        return match.group('ip'), normalize_mac(match.group('mac'))
    match = TD_REQUEST_RE.search(line)
    if match and match.group('ip') != '0.0.0.0':      # 0.0.0.0 = duplicate address probe
        return match.group('ip'), normalize_mac(src.group('smac'))
    match = TD_ND_RE.search(line)
    if match:
        ip = match.group('ip').lower()
        if ip != '::' and not ip.startswith('fe80'):
            return ip, normalize_mac(src.group('smac'))
    return None


def bridge_info():
    """ {bridge device: [members]} as configured on the firewall """
    bridges, current = {}, None
    for line in _run([IFCONFIG, '-a']).splitlines():
        if line and not line[0].isspace():
            name = line.split(':', 1)[0]
            current = name if name.startswith('bridge') else None
            if current:
                bridges[current] = []
        elif current:
            match = re.match(r'^\s+member: (\S+)', line)
            if match:
                bridges[current].append(match.group(1))
    return bridges


class Sniffer:
    """
    One tcpdump per device, restarted when it exits.
    Observations are kept in arrival order for change detection and as
    "last seen" per binding for the "currently active" view.
    """

    def __init__(self, devices, stop):
        self.devices = devices
        self.stop = stop
        self.lock = threading.Lock()
        self.events = []                # (ts, ip, mac, device), drained every poll
        self.last = {}                  # (ip, mac, device) -> ts
        self.state = {dev: 'starting' for dev in devices}
        self.lines = {dev: 0 for dev in devices}

    def start(self):
        for dev in self.devices:
            threading.Thread(target=self._run, args=(dev,), name='sniff-%s' % dev, daemon=True).start()

    def _run(self, dev):
        while not self.stop.is_set():
            try:
                proc = subprocess.Popen([TCPDUMP, '-l', '-n', '-e', '-p', '-i', dev, SNIFF_FILTER],
                                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                        text=True, errors='replace')
            except OSError as exc:
                self.state[dev] = 'error: %s' % exc
                self.stop.wait(60)
                continue
            self.state[dev] = 'running'
            for line in proc.stdout:
                self.lines[dev] += 1
                found = parse_tcpdump_line(line)
                if found and found[1]:
                    now = time.time()
                    with self.lock:
                        self.events.append((now, found[0], found[1], dev))
                        self.last[(found[0], found[1], dev)] = now
                if self.stop.is_set():
                    break
            proc.kill()
            proc.wait()
            self.state[dev] = 'restarting (exit %s)' % proc.returncode
            self.stop.wait(10)

    def drain(self):
        with self.lock:
            events, self.events = self.events, []
            if len(self.last) > 200000:
                cutoff = time.time() - 3600
                self.last = {k: v for k, v in self.last.items() if v >= cutoff}
        return events

    def recent(self, seconds):
        cutoff = time.time() - seconds
        with self.lock:
            return [(ip, mac, dev) for (ip, mac, dev), ts in self.last.items() if ts >= cutoff]

    def status(self):
        return {dev: {'state': self.state[dev], 'lines': self.lines[dev]} for dev in self.devices}
