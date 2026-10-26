"""
    Copyright (c) 2026 Onur Berkay <onurberkay@sakla.app>
    All rights reserved. (BSD 2-Clause, see LICENSE)

    pf limits and counters.

    pfctl -vsi    state table / source tracking sizes, "Counters" and "Limit Counters"
                  (memory, state-limit, src-limit, max-src-conn-rate, overload table insertion, ...)
    pfctl -sm     hard limits (states, src-nodes, ...)
    pfctl -vvsr   rules with their options (max N, max-src-conn N, ...) and current state count
    pfctl -sT / -t <table> -T show    tables such as virusprot (overload), sshlockout, crowdsec
"""
import os
import re
import subprocess

PFCTL = '/sbin/pfctl'

# counter -> (severity, explanation); an increase of any of these raises an alert
WATCHED_COUNTERS = {
    'memory': ('critical', 'pf could not allocate memory (state table or other pool full), new connections are dropped'),
    'state-limit': ('high', 'a rule reached its maximum number of states'),
    'src-limit': ('high', 'a source tracking limit was reached'),
    'state-insert': ('medium', 'state insertion failed'),
    'map-failed': ('high', 'NAT could not map a connection (port exhaustion)'),
    'congestion': ('high', 'pf dropped packets because of interface queue congestion'),
    'max states per rule': ('high', 'a rule reached its "max states" limit'),
    'max-src-states': ('high', 'a source reached its "max source states" limit'),
    'max-src-nodes': ('high', 'the source node limit was reached'),
    'max-src-conn': ('high', 'a source reached its "max established connections" limit'),
    'max-src-conn-rate': ('high', 'a source exceeded its "max new connections" rate'),
    'overload table insertion': ('high', 'a source was put into an overload table (e.g. virusprot)'),
    'overload flush states': ('medium', 'states of an overloaded source were flushed'),
    'synfloods detected': ('critical', 'pf detected a SYN flood'),
}

SECTION_RE = re.compile(r'^(?P<name>[A-Z][A-Za-z ]+?)\s*(?:Total.*)?$')
ENTRY_RE = re.compile(r'^\s+(?P<name>[A-Za-z][A-Za-z0-9 _-]*?)\s{2,}(?P<value>\d+)')
LIMIT_RE = re.compile(r'^(?P<name>\S+)\s+hard limit\s+(?P<value>\d+)')
RULE_RE = re.compile(r'^@(?P<nr>\d+)(?:\([^)]*\))?\s+(?P<text>.*)$')
RULE_STATES_RE = re.compile(r'States:\s*(\d+)')
RULE_PACKETS_RE = re.compile(r'Packets:\s*(\d+)')
RULES_DEBUG = '/tmp/rules.debug'
DEBUG_LABEL_RE = re.compile(r'label "(?P<label>[^"]+)"\s*#\s*(?P<descr>.+)$')
_descriptions = {'mtime': None, 'map': {}}
RULE_OPTS = {
    'max': re.compile(r'[(,\s]max (\d+)'),
    'max-src-states': re.compile(r'max-src-states (\d+)'),
    'max-src-conn': re.compile(r'max-src-conn (\d+)'),
    'max-src-nodes': re.compile(r'max-src-nodes (\d+)'),
    'max-src-conn-rate': re.compile(r'max-src-conn-rate (\d+/\d+)'),
}
LABEL_RE = re.compile(r'label "([^"]*)"')
TRACK_RE = re.compile(r'source-track (rule|global)')
TABLE_REF_RE = re.compile(r'\b(?P<side>from|to)\s+(?P<neg>!\s*)?<(?P<table>[^>]+)>')


def _run(args, timeout=30):
    try:
        return subprocess.run(args, capture_output=True, text=True, errors='replace', timeout=timeout).stdout
    except (OSError, subprocess.SubprocessError):
        return ''


def parse_info(text):
    """ -> {'states': n, 'src_nodes': n, 'counters': {name: total}} """
    result = {'states': 0, 'src_nodes': 0, 'counters': {}}
    section = ''
    for line in text.splitlines():
        if not line.strip():
            continue
        if not line[0].isspace():
            match = SECTION_RE.match(line)
            section = match.group('name').strip() if match else ''
            continue
        match = ENTRY_RE.match(line)
        if not match:
            continue
        name, value = match.group('name').strip(), int(match.group('value'))
        if name == 'current entries':
            if section.startswith('State Table'):
                result['states'] = value
            elif section.startswith('Source Tracking'):
                result['src_nodes'] = value
        elif section in ('Counters', 'Limit Counters'):
            result['counters'][name] = value
    return result


def parse_limits(text):
    return {m.group('name'): int(m.group('value')) for m in map(LIMIT_RE.match, text.splitlines()) if m}


def parse_rules(text):
    """ every rule with its action, limit options, packet counter and current number of states """
    rules, current = [], None
    for line in text.splitlines():
        match = RULE_RE.match(line)
        if match:
            options = {}
            for key, regex in RULE_OPTS.items():
                found = regex.search(match.group('text'))
                if found:
                    options[key] = found.group(1)
            label = LABEL_RE.search(match.group('text'))
            text = LABEL_RE.sub('', match.group('text')).strip()
            tables = [(m.group('side'), m.group('table')) for m in TABLE_REF_RE.finditer(text) if not m.group('neg')]
            # per source limits without "source-track rule" use pf's default, global tracking:
            # one source node per address shared by all such rules, -sS then names no rule
            tracking = ''
            found = TRACK_RE.search(text)
            if found:
                tracking = found.group(1)
            elif any(k.startswith('max-src-') for k in options):
                tracking = 'global'
            current = {'nr': int(match.group('nr')), 'action': text.split(' ', 1)[0], 'text': text[:200],
                       'label': label.group(1) if label else '', 'options': options, 'states': 0, 'packets': 0,
                       'tables': tables, 'tracking': tracking}
            rules.append(current)
            continue
        if current is not None:
            found = RULE_STATES_RE.search(line)
            if found:
                current['states'] = int(found.group(1))
            found = RULE_PACKETS_RE.search(line)
            if found:
                current['packets'] = int(found.group(1))
    return rules


SRC_NODE_RE = re.compile(
    r'^(?P<ip>[0-9a-fA-F:.]+)(?:/\d+)?\s+->\s+\S+\s+\(\s*states (?P<states>\d+), connections (?P<conns>\d+),'
    r' rate (?P<rate>[\d.]+)/(?P<secs>\d+)s\s*\)')
SRC_RULE_RE = re.compile(r'filter rule (\d+)')
# counters that a per source limit increments
SRC_COUNTERS = ('src-limit', 'max-src-states', 'max-src-conn', 'max-src-conn-rate', 'max-src-nodes')


def parse_src_nodes(text):
    """
    pfctl -sS -v (source tracking):
        198.51.100.7 -> 0.0.0.0 ( states 3000, connections 12, rate 4.0/10s )
           age 00:12:01, 40123 pkts, 9123456 bytes, filter rule 12
    """
    nodes, current = [], None
    for line in text.splitlines():
        match = SRC_NODE_RE.match(line.strip())
        if match:
            current = {'ip': match.group('ip'), 'states': int(match.group('states')),
                       'connections': int(match.group('conns')), 'rate': float(match.group('rate')),
                       'rate_seconds': int(match.group('secs')), 'rule': None}
            nodes.append(current)
            continue
        if current is not None and current['rule'] is None:
            found = SRC_RULE_RE.search(line)
            if found:
                current['rule'] = int(found.group(1))
    return nodes


def read_src_nodes():
    return parse_src_nodes(_run([PFCTL, '-sS', '-v'], timeout=60))


def parse_descriptions(text):
    """ label -> description from rules.debug ("... label "abc" # Block customer SMTP") """
    result = {}
    for line in text.splitlines():
        match = DEBUG_LABEL_RE.search(line)
        if match:
            result[match.group('label')] = match.group('descr').strip()[:120]
    return result


def rule_descriptions(path=RULES_DEBUG):
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return {}
    if mtime != _descriptions['mtime']:
        try:
            with open(path, errors='replace') as handle:
                _descriptions['map'] = parse_descriptions(handle.read())
        except OSError:
            _descriptions['map'] = {}
        _descriptions['mtime'] = mtime
    return _descriptions['map']


def read_info():
    return parse_info(_run([PFCTL, '-vsi']))


def read_limits():
    return parse_limits(_run([PFCTL, '-sm']))


def read_rules():
    return parse_rules(_run([PFCTL, '-vvsr'], timeout=60))


def list_tables():
    return [line.strip() for line in _run([PFCTL, '-sT']).splitlines() if line.strip()]


def table_entries(name):
    if not re.match(r'^[A-Za-z0-9_.-]+$', name):
        return []
    entries = []
    for line in _run([PFCTL, '-t', name, '-T', 'show'], timeout=60).splitlines():
        item = line.strip().lstrip('!')
        if item:
            entries.append(item)
    return entries
