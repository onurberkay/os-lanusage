"""
    Copyright (c) 2026 Onur Berkay <onurberkay@sakla.app>
    All rights reserved. (BSD 2-Clause, see LICENSE)

    Bounded sampling of connection attempts, for blocked traffic without firewall logging.

    Every poll each device is listened to for at most <seconds> or <max_packets>,
    whichever comes first, capturing only connection attempts: TCP SYN (no ACK),
    ICMP / ICMPv6 echo requests and UDP. BPF sees packets before pf filters them,
    so an attempt that left no pf state behind was blocked (or dropped by a limit).
    The cost is bounded no matter how large an attack is, and nothing is written
    to disk except the aggregated statistics.

    tcpdump -n -l lines:
        12:00:00.000001 IP 198.51.100.7.51515 > 10.0.0.7.22: Flags [S], seq 1, win 64240, length 0
        12:00:00.000002 IP 10.0.0.5.40000 > 8.8.8.8.53: 1234+ A? example.com. (29)
        12:00:00.000003 IP 10.0.0.5 > 8.8.8.8: ICMP echo request, id 4242, seq 1, length 64
        12:00:00.000004 IP6 2001:db8::9.51515 > 2001:db8::5.22: Flags [S], seq 1, win 64800, length 0
        12:00:00.000005 IP6 2001:db8::9 > 2001:db8::5: ICMP6, echo request, id 7, seq 1, length 64
"""
import re
import subprocess
import threading
import time

TCPDUMP = '/usr/sbin/tcpdump'

_ATTEMPTS = ('(tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn) or (icmp[icmptype] == icmp-echo) or udp'
             ' or (ip6 and ((ip6[6] == 6 and ip6[53] & 0x12 == 0x02) or (ip6[6] == 58 and ip6[40] == 128)))')
CAPTURE_FILTER = '%s or (vlan and (%s))' % (_ATTEMPTS, _ATTEMPTS)

LINE_RE = re.compile(r'\bIP6? (?P<src>[0-9a-fA-F:.]+) > (?P<dst>[0-9a-fA-F:.]+): (?P<rest>.*)$')


def _split(addr):
    host, sep, port = addr.rpartition('.')
    if sep and port.isdigit() and (':' in host or host.count('.') == 3):
        return host, int(port)
    return addr, 0


def parse_line(line):
    """ -> (proto, src, sport, dst, dport) or None """
    match = LINE_RE.search(line)
    if not match:
        return None
    rest = match.group('rest')
    if rest.startswith('ICMP'):
        proto = 'ipv6-icmp' if rest.startswith('ICMP6') else 'icmp'
        if 'echo request' not in rest:
            return None
        return proto, match.group('src'), 0, match.group('dst'), 0
    proto = 'tcp' if rest.startswith('Flags [') else 'udp'
    src, sport = _split(match.group('src'))
    dst, dport = _split(match.group('dst'))
    if not sport or not dport:
        return None
    return proto, src, sport, dst, dport


# devices where BPF cannot filter by direction; captured in both directions instead
NO_DIRECTION = set()


def _run_tcpdump(dev, seconds, max_packets, inbound):
    """ -> (stdout, failed early) """
    args = [TCPDUMP, '-l', '-n', '-p'] + (['-Q', 'in'] if inbound else []) + \
           ['-i', dev, '-c', str(max_packets), CAPTURE_FILTER]
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors='replace')
    try:
        out, _ = proc.communicate(timeout=seconds)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
        return out, False
    return out, proc.returncode not in (0, None) and not out


def _capture_device(dev, seconds, max_packets, result):
    """
    Only packets entering the device (-Q in): a packet leaving the firewall has already passed pf,
    and on the upstream member of a bridge an outgoing attempt would otherwise look blocked.
    Every attempt is seen exactly once, where it enters, before pf decides.
    """
    started = time.time()
    inbound = dev not in NO_DIRECTION
    try:
        out, failed = _run_tcpdump(dev, seconds, max_packets, inbound)
        if failed and inbound:
            NO_DIRECTION.add(dev)
            inbound = False
            started = time.time()
            out, failed = _run_tcpdump(dev, seconds, max_packets, False)
    except OSError as exc:
        result[dev] = {'error': str(exc), 'elapsed': 0, 'packets': []}
        return
    elapsed = max(0.05, time.time() - started)
    lines = out.splitlines()
    packets = [p for p in map(parse_line, lines) if p]
    result[dev] = {'error': 'tcpdump failed' if failed else '', 'elapsed': round(elapsed, 2), 'lines': len(lines),
                   'packets': packets, 'capped': len(lines) >= max_packets, 'inbound_only': inbound}


def capture(devices, seconds, max_packets):
    """ capture on all devices in parallel: {dev: {elapsed, lines, packets, capped, error}} """
    result = {}
    threads = [threading.Thread(target=_capture_device, args=(dev, seconds, max_packets, result), daemon=True)
               for dev in devices]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(seconds + 15)
    return result
