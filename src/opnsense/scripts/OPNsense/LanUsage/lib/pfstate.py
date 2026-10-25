"""
    Copyright (c) 2026 Onur Berkay <onurberkay@sakla.app>
    All rights reserved. (BSD 2-Clause, see LICENSE)

    pf state table reader (pfctl -ss -v).

    State lines look like:
        all tcp 10.0.0.5:51234 -> 93.184.216.34:443       ESTABLISHED:ESTABLISHED
        all tcp 203.0.113.1:6000 (10.0.0.5:51234) -> 93.184.216.34:443   ESTABLISHED:ESTABLISHED
        all tcp 10.0.0.5:22 <- 198.51.100.7:50123       ESTABLISHED:ESTABLISHED
        all udp 2001:db8::5[53] <- 2001:db8:1::9[41000]   MULTIPLE:SINGLE
    followed by indented detail lines, one of which carries
        age 00:01:23, expires in 24:00:00, 10:12 pkts, 1234:5678 bytes, rule 12

    "->" means left is the initiator, "<-" means right is the initiator.
    A parenthesised address is the other side of a NAT translation; both
    are returned so the caller can pick the one inside its LAN.
"""
import re
import subprocess

PFCTL = '/sbin/pfctl'

HEAD_RE = re.compile(
    r'^(?P<ifc>\S+)\s+(?P<proto>\S+)\s+'
    r'(?P<a>\S+)(?:\s+\((?P<an>[^)\s]+)\))?\s+'
    r'(?P<dir><-|->)\s+'
    r'(?P<b>\S+)(?:\s+\((?P<bn>[^)\s]+)\))?\s+'
    r'(?P<state>\S+)'
)
COUNT_RE = re.compile(r'(\d+):(\d+) pkts, (\d+):(\d+) bytes')
V6PORT_RE = re.compile(r'^(.*)\[(\d+)\]$')


def split_host(token):
    """ "1.2.3.4:80" / "2001:db8::1[80]" / "1.2.3.4" -> (address, port) """
    match = V6PORT_RE.match(token)
    if match:
        return match.group(1), int(match.group(2))
    if token.count(':') == 1:
        host, _, port = token.partition(':')
        if port.isdigit():
            return host, int(port)
    return token, 0


def parse_head(line):
    match = HEAD_RE.match(line)
    if not match:
        return None
    left = [split_host(match.group('a'))]
    if match.group('an'):
        left.append(split_host(match.group('an')))
    right = [split_host(match.group('b'))]
    if match.group('bn'):
        right.append(split_host(match.group('bn')))
    initiator, responder = (left, right) if match.group('dir') == '->' else (right, left)
    return {
        'proto': match.group('proto').lower(),
        'init': initiator,
        'resp': responder,
        'tcpstate': match.group('state'),
        'pkts': (0, 0),     # initiator -> responder, responder -> initiator
        'bytes': 0,
    }


def parse_lines(lines):
    current = None
    for line in lines:
        if line[:1] in (' ', '\t'):
            if current is not None:
                match = COUNT_RE.search(line)
                if match:
                    current['pkts'] = (int(match.group(1)), int(match.group(2)))
                    current['bytes'] = int(match.group(3)) + int(match.group(4))
        elif line.strip():
            if current is not None:
                yield current
            current = parse_head(line)
    if current is not None:
        yield current


def iter_states(pfctl=PFCTL):
    proc = subprocess.Popen(
        [pfctl, '-ss', '-v'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, errors='replace', bufsize=1 << 16
    )
    try:
        yield from parse_lines(proc.stdout)
    finally:
        proc.stdout.close()
        proc.wait()
