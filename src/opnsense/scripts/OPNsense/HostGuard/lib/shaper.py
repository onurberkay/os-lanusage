"""
    Copyright (c) 2026 Onur Berkay <onurberkay@sakla.app>
    All rights reserved. (BSD 2-Clause, see LICENSE)

    Traffic shaper (ipfw / dummynet) pipes, queues and their flows.

    ipfw pipe show:
        10000:  10.000 Mbit/s    0 ms burst 0
        q141072  50 sl. 0 flows (256 buckets) sched 75536 weight 0 lmax 0 pri 0 droptail
            mask:  0x00 0xffffffff/0x0000 -> 0x00000000/0x0000
         sched 75536 type FIFO flags 0x1 256 buckets 1 active
        BKT Prot ___Source IP/port____ ____Dest. IP/port____ Tot_pkt/bytes Pkt/Byte Drp
         12 ip        198.51.100.7/0             0.0.0.0/0     4120  4932040  0    0   7
    ipfw queue show:
        q10001  50 sl. 0 flows (256 buckets) sched 10000 weight 100 lmax 0 pri 0 droptail
            mask:  0x00 0x00000000/0x0000 -> 0xffffffff/0x0000
        BKT Prot ...

    Byte and drop counters are cumulative per flow; a flow disappears when idle.
    The pipe / queue description and the shaper rules that feed them come from
    //OPNsense/TrafficShaper in config.xml.
"""
import re
import subprocess
import xml.etree.ElementTree as ET

IPFW = '/sbin/ipfw'
CONFIG_XML = '/conf/config.xml'

PIPE_RE = re.compile(r'^(?P<nr>\d+):\s+(?:unlimited|(?P<bw>[\d.]+)\s+(?P<unit>bit|Kbit|Mbit|Gbit)/s)')
QUEUE_RE = re.compile(r'^q(?P<nr>\d+)\s+(?P<size>\d+\s*(?:sl\.|KB|B))\s.*?sched (?P<sched>\d+)(?: weight (?P<weight>\d+))?')
MASK_RE = re.compile(r'mask:\s*(?:queue,\s*)?0x[0-9a-fA-F]+ 0x(?P<src>[0-9a-fA-F]{8})/0x[0-9a-fA-F]+ -> 0x(?P<dst>[0-9a-fA-F]{8})/')
MASK6_RE = re.compile(r'mask:.*?flow_id: 0x[0-9a-fA-F]+,\s+(?P<src>\S+)/0x[0-9a-fA-F]+ -> (?P<dst>\S+)/0x')
FLOW4_RE = re.compile(r'^\s*\d+[* ]?\s*\S+\s+(?P<src>[0-9.]+)/\d+\s+(?P<dst>[0-9.]+)/\d+\s+'
                      r'(?P<pkts>\d+)\s+(?P<bytes>\d+)\s+(?P<qpkts>\d+)\s+(?P<qbytes>\d+)\s+(?P<drops>\d+)\s*$')
FLOW6_RE = re.compile(r'^\s*\d+[* ]?\s*\S+\s+\d+\s+(?P<src>[0-9a-fA-F:]+)/\d+\s+(?P<dst>[0-9a-fA-F:]+)/\d+\s+'
                      r'(?P<pkts>\d+)\s+(?P<bytes>\d+)\s+(?P<qpkts>\d+)\s+(?P<qbytes>\d+)\s+(?P<drops>\d+)\s*$')
UNITS = {'bit': 1, 'Kbit': 1000, 'Mbit': 1000 ** 2, 'Gbit': 1000 ** 3}


def _run(args):
    try:
        return subprocess.run(args, capture_output=True, text=True, errors='replace', timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        return ''


def _mask_side(src, dst):
    """ which address identifies a flow: per source IP, per destination IP or shared """
    def used(value):
        return value.strip('0:x') != ''
    if used(src) and not used(dst):
        return 'src'
    if used(dst) and not used(src):
        return 'dst'
    return 'both' if used(src) else 'none'


def _flow(line):
    match = FLOW4_RE.match(line) or FLOW6_RE.match(line)
    if not match:
        return None
    return {'src': match.group('src'), 'dst': match.group('dst'), 'pkts': int(match.group('pkts')),
            'bytes': int(match.group('bytes')), 'queued': int(match.group('qpkts')), 'drops': int(match.group('drops'))}


def parse_pipes(text):
    """ ipfw pipe show -> [{nr, bandwidth (bit/s, 0 = unlimited), mask, slots, flows}] """
    pipes, current = [], None
    for line in text.splitlines():
        match = PIPE_RE.match(line)
        if match:
            bandwidth = float(match.group('bw')) * UNITS[match.group('unit')] if match.group('bw') else 0
            current = {'nr': int(match.group('nr')), 'bandwidth': int(bandwidth), 'mask': 'none', 'slots': '',
                       'flows': []}
            pipes.append(current)
            continue
        if current is None:
            continue
        match = QUEUE_RE.match(line.strip())
        if match and not current['slots']:
            current['slots'] = match.group('size').strip()
            continue
        match = MASK_RE.search(line) or MASK6_RE.search(line)
        if match:
            current['mask'] = _mask_side(match.group('src'), match.group('dst'))
            continue
        flow = _flow(line)
        if flow:
            current['flows'].append(flow)
    return pipes


def parse_queues(text):
    """ ipfw queue show -> [{nr, pipe, weight, mask, slots, flows}] """
    queues, current = [], None
    for line in text.splitlines():
        match = QUEUE_RE.match(line.strip()) if line.startswith('q') else None
        if match:
            current = {'nr': int(match.group('nr')), 'pipe': int(match.group('sched')),
                       'weight': int(match.group('weight') or 0), 'mask': 'none',
                       'slots': match.group('size').strip(), 'flows': []}
            queues.append(current)
            continue
        if current is None:
            continue
        match = MASK_RE.search(line) or MASK6_RE.search(line)
        if match:
            current['mask'] = _mask_side(match.group('src'), match.group('dst'))
            continue
        flow = _flow(line)
        if flow:
            current['flows'].append(flow)
    return queues


def read_pipes():
    return parse_pipes(_run([IPFW, 'pipe', 'show']))


def read_queues():
    return parse_queues(_run([IPFW, 'queue', 'show']))


def parse_config(root):
    """
    //OPNsense/TrafficShaper -> {'pipes': {nr: {...}}, 'queues': {nr: {...}}, 'rules': [...]}
    Rules point at a pipe or queue by uuid; they are resolved to ('pipe'|'queue', nr).
    """
    result = {'pipes': {}, 'queues': {}, 'rules': []}
    shaper = root.find('./OPNsense/TrafficShaper')
    if shaper is None:
        return result
    targets = {}

    def text(node, tag):
        return (node.findtext(tag) or '').strip()

    for pipe in shaper.findall('./pipes/pipe'):
        if not text(pipe, 'number').isdigit():
            continue
        nr = int(text(pipe, 'number'))
        result['pipes'][nr] = {
            'descr': text(pipe, 'description'), 'enabled': text(pipe, 'enabled') != '0',
            'bandwidth': '%s %s/s' % (text(pipe, 'bandwidth'), text(pipe, 'bandwidthMetric') or 'bit'),
            'mask': text(pipe, 'mask') or 'none', 'rules': [],
        }
        targets[pipe.get('uuid')] = ('pipe', nr)
    for queue in shaper.findall('./queues/queue'):
        if not text(queue, 'number').isdigit():
            continue
        nr = int(text(queue, 'number'))
        parent = targets.get(text(queue, 'pipe'), (None, None))[1]
        result['queues'][nr] = {'descr': text(queue, 'description'), 'enabled': text(queue, 'enabled') != '0',
                                'pipe': parent, 'weight': text(queue, 'weight'),
                                'mask': text(queue, 'mask') or 'none', 'rules': []}
        targets[queue.get('uuid')] = ('queue', nr)
    for rule in shaper.findall('./rules/rule'):
        target = targets.get(text(rule, 'target'))
        if target is None:
            continue
        item = {
            'sequence': text(rule, 'sequence'), 'enabled': text(rule, 'enabled') != '0',
            'interface': text(rule, 'interface'), 'direction': text(rule, 'direction') or 'both',
            'proto': text(rule, 'proto'), 'source': ('!' if text(rule, 'source_not') == '1' else '') + text(rule, 'source'),
            'destination': ('!' if text(rule, 'destination_not') == '1' else '') + text(rule, 'destination'),
            'descr': text(rule, 'description'), 'target': target,
        }
        result['rules'].append(item)
        owner = result['pipes' if target[0] == 'pipe' else 'queues'].get(target[1])
        if owner is not None:
            owner['rules'].append(item)
    return result


def read_config(path=CONFIG_XML):
    try:
        return parse_config(ET.parse(path).getroot())
    except (OSError, ET.ParseError):
        return {'pipes': {}, 'queues': {}, 'rules': []}
