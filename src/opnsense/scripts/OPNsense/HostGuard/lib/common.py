"""
    Copyright (c) 2026 Onur Berkay <onurberkay@sakla.app>
    All rights reserved. (BSD 2-Clause, see LICENSE)

    Shared helpers for the HostGuard plugin: configuration, network discovery
    and the SQLite schema.
"""
import configparser
import ipaddress
import json
import os
import re
import sqlite3
import subprocess
import time
import xml.etree.ElementTree as ET

from . import bans

CONF_FILE = '/usr/local/etc/hostguard/hostguard.conf'
DB_DIR = '/var/db/hostguard'
DB_FILE = os.path.join(DB_DIR, 'hostguard.db')
CONFIG_XML = '/conf/config.xml'
IFCONFIG = '/sbin/ifconfig'

DEFAULTS = {
    'enabled': False,
    'interfaces': '',
    'networks': '',
    'ignore_self': True,
    'answered_only': True,
    'track_remote': True,
    'poll_interval': 30,
    'retention_days': 30,
    'probe_enabled': True,
    'probe_interval': 24,
    'probe_timeout': 4,
    'probe_max': 20,
    'probe_exclude': '',
    'use_nmap': False,
    'lateral_alerts': 'all',
    'lateral_trusted': '',
    'lateral_blocked': False,
    'sample_enabled': True,
    'sample_interfaces': '',
    'sample_seconds': 5,
    'sample_packets': 20000,
    'blocked_out_pps': 20,
    'blocked_in_pps': 500,
    'rule_block_pps': 2000,
    'scan_hosts': 10,
    'scan_ports': 20,
    'l2_enabled': True,
    'l2_window': 24,
    'l2_ignore_macs': '',
    'l2_source': 'both',
    'host_state_limit': 10000,
    'host_rate_limit': 300,
    'state_warn_pct': 80,
    'watch_tables': 'virusprot,sshlockout,crowdsec',
    'shaper_drop_pps': 5,
    # inbound attacks on LAN hosts: attempts per second from outside that open an attack episode
    'attack_pps': 50,
    'ids_enabled': True,
    'ids_eve': '/var/log/suricata/eve.json',
    'crowdsec_enabled': True,
    # outside sources: owner (AS) and network type from public lists, downloaded once a day (lib/ipdata.py)
    'ipdata_enabled': True,
    'hosting_asns': '',
    # automatic filtering (lib/autofilter.py): 0 off, 1 certain, 2 + likely, 3 + possible
    'auto_block_level': 0,
    'auto_block_hours': 24,
    # fixed, or escalating: x2 each repeat up to auto_block_max_hours (lib/bans.py)
    'auto_block_ban': 'fixed',
    'auto_block_max_hours': 720,
}
STATUS_FILE = os.path.join(DB_DIR, 'status.json')

# ports where a LAN to LAN connection is a typical lateral movement / attack path
SENSITIVE_PORTS = {21, 22, 23, 135, 139, 445, 1433, 1521, 2375, 2376, 3306, 3389, 5432, 5900, 5985, 5986,
                   6379, 8006, 9200, 11211, 27017}

SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    ip TEXT PRIMARY KEY,
    first_seen INTEGER, last_seen INTEGER, active INTEGER DEFAULT 0,
    conns_in INTEGER DEFAULT 0, conns_out INTEGER DEFAULT 0,
    bytes_in INTEGER DEFAULT 0, bytes_out INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS ts_host (
    ts INTEGER, ip TEXT, dir TEXT, conns INTEGER, bytes INTEGER,
    PRIMARY KEY (ts, ip, dir)
);
CREATE INDEX IF NOT EXISTS ts_host_ip ON ts_host (ip, ts);
CREATE TABLE IF NOT EXISTS ts_port (
    ts INTEGER, ip TEXT, dir TEXT, proto TEXT, port INTEGER, conns INTEGER, bytes INTEGER,
    PRIMARY KEY (ts, ip, dir, proto, port)
);
CREATE INDEX IF NOT EXISTS ts_port_ip ON ts_port (ip, ts);
CREATE TABLE IF NOT EXISTS flows (
    day INTEGER, ip TEXT, dir TEXT, proto TEXT, port INTEGER, remote TEXT,
    first_seen INTEGER, last_seen INTEGER, conns INTEGER, bytes INTEGER,
    PRIMARY KEY (day, ip, dir, proto, port, remote)
);
CREATE INDEX IF NOT EXISTS flows_last ON flows (last_seen);
CREATE INDEX IF NOT EXISTS flows_ip ON flows (ip, last_seen);
CREATE TABLE IF NOT EXISTS services (
    ip TEXT, proto TEXT, port INTEGER, state TEXT, service TEXT, product TEXT,
    tls TEXT, banner TEXT, method TEXT, last_probe INTEGER, first_seen INTEGER,
    PRIMARY KEY (ip, proto, port)
);
CREATE TABLE IF NOT EXISTS lateral (
    day INTEGER, src TEXT, dst TEXT, proto TEXT, port INTEGER,
    first_seen INTEGER, last_seen INTEGER,
    attempts INTEGER DEFAULT 0, answered INTEGER DEFAULT 0, blocked INTEGER DEFAULT 0, bytes INTEGER DEFAULT 0,
    PRIMARY KEY (day, src, dst, proto, port)
);
CREATE INDEX IF NOT EXISTS lateral_last ON lateral (last_seen);
CREATE TABLE IF NOT EXISTS l2bind (
    mac TEXT, ip TEXT, iface TEXT, first_seen INTEGER, last_seen INTEGER,
    PRIMARY KEY (mac, ip)
);
CREATE INDEX IF NOT EXISTS l2bind_ip ON l2bind (ip);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT, akey TEXT UNIQUE, type TEXT, severity TEXT,
    ip TEXT, mac TEXT, peer TEXT, detail TEXT,
    first_seen INTEGER, last_seen INTEGER, count INTEGER DEFAULT 1, acked INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS alerts_last ON alerts (last_seen);
CREATE TABLE IF NOT EXISTS ts_pf (
    ts INTEGER PRIMARY KEY, states INTEGER, states_limit INTEGER, src_nodes INTEGER, src_limit INTEGER,
    counters TEXT
);
CREATE TABLE IF NOT EXISTS blocked (
    day INTEGER, ip TEXT, dir TEXT, proto TEXT, port INTEGER, remote TEXT,
    first_seen INTEGER, last_seen INTEGER, packets INTEGER DEFAULT 0, samples INTEGER DEFAULT 0,
    PRIMARY KEY (day, ip, dir, proto, port, remote)
);
CREATE INDEX IF NOT EXISTS blocked_last ON blocked (last_seen);
CREATE TABLE IF NOT EXISTS ts_blocked (
    ts INTEGER, ip TEXT, dir TEXT, packets INTEGER,
    PRIMARY KEY (ts, ip, dir)
);
CREATE TABLE IF NOT EXISTS ts_rules (
    ts INTEGER, nr INTEGER, label TEXT, descr TEXT, packets INTEGER,
    PRIMARY KEY (ts, label, nr)
);
CREATE TABLE IF NOT EXISTS blocked_reasons (
    day INTEGER, ip TEXT, dir TEXT, reason TEXT, packets INTEGER DEFAULT 0, last_seen INTEGER,
    PRIMARY KEY (day, ip, dir, reason)
);
CREATE TABLE IF NOT EXISTS shaperhits (
    ip TEXT, kind TEXT, nr INTEGER, descr TEXT, limit_bps INTEGER, peak_bps INTEGER,
    first_seen INTEGER, last_seen INTEGER, drops INTEGER DEFAULT 0,
    PRIMARY KEY (ip, kind, nr)
);
CREATE TABLE IF NOT EXISTS srclimits (
    ip TEXT, nr INTEGER, kind TEXT, descr TEXT, limit_value INTEGER, peak INTEGER,
    first_seen INTEGER, last_seen INTEGER, hits INTEGER DEFAULT 0, label TEXT DEFAULT '',
    PRIMARY KEY (ip, nr, kind)
);
CREATE TABLE IF NOT EXISTS tablehits (
    tbl TEXT, ip TEXT, first_seen INTEGER, last_seen INTEGER,
    PRIMARY KEY (tbl, ip)
);
CREATE TABLE IF NOT EXISTS attacks (
    id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT, kind TEXT, first_seen INTEGER, last_seen INTEGER,
    peak_pps REAL DEFAULT 0, packets INTEGER DEFAULT 0, sources INTEGER DEFAULT 0, ports TEXT DEFAULT '',
    passed_pct REAL DEFAULT 0, top_sources TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS attacks_target ON attacks (target, kind, last_seen);
CREATE INDEX IF NOT EXISTS attacks_last ON attacks (last_seen);
CREATE TABLE IF NOT EXISTS ids_alerts (
    day INTEGER, target TEXT, src TEXT, sid INTEGER, signature TEXT, category TEXT, severity INTEGER,
    action TEXT, port INTEGER, first_seen INTEGER, last_seen INTEGER, hits INTEGER DEFAULT 0,
    PRIMARY KEY (day, target, src, sid)
);
CREATE INDEX IF NOT EXISTS ids_alerts_last ON ids_alerts (last_seen);
CREATE TABLE IF NOT EXISTS crowdsec (
    ip TEXT PRIMARY KEY, scenario TEXT, origin TEXT, action TEXT, until INTEGER, last_seen INTEGER
);
CREATE TABLE IF NOT EXISTS conditions (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ctype TEXT, value TEXT, target TEXT, duration INTEGER,
    note TEXT DEFAULT '', created INTEGER, hits INTEGER DEFAULT 0, last_hit INTEGER DEFAULT 0,
    UNIQUE (ctype, value, target)
);
CREATE TABLE IF NOT EXISTS autoblocked (
    ip TEXT, cond INTEGER, tbl TEXT, added INTEGER, expires INTEGER, reason TEXT,
    owned INTEGER DEFAULT 1, last_match INTEGER DEFAULT 0,
    PRIMARY KEY (ip, cond)
);
CREATE TABLE IF NOT EXISTS offenses (
    ip TEXT, cond INTEGER, count INTEGER DEFAULT 0, until INTEGER,
    PRIMARY KEY (ip, cond)
);
CREATE TABLE IF NOT EXISTS strikes (
    ip TEXT, cond INTEGER, count INTEGER DEFAULT 0, first_seen INTEGER, last_seen INTEGER,
    PRIMARY KEY (ip, cond)
);
"""

# block conditions: what a condition matches on, and the table outside sources go into
# what the operator can add; "auto" comes from the settings
CONDITION_TYPES = ('attack', 'ids', 'ids_drop', 'src_limit')
# what each type matches on: an attack kind (attacks.TargetStats.classify), a Suricata sid, a Suricata sid
# or * for the alerts Suricata dropped (IPS mode), "<rule label or *>:<per source limit>"
ATTACK_KINDS = ('reflection', 'port scan', 'brute force', 'syn flood', 'udp flood', 'icmp flood', 'mixed flood')
SRC_LIMIT_KINDS = ('max-src-states', 'max-src-conn', 'max-src-conn-rate')
AUTOBLOCK_TABLE = 'virusprot'

# columns added after 1.0, created on existing databases by connect()
MIGRATIONS = {
    'hosts': (('states', 'INTEGER DEFAULT 0'), ('state_detail', "TEXT DEFAULT ''"), ('new_rate', 'REAL DEFAULT 0')),
    'blocked': (('reason', "TEXT DEFAULT ''"), ('iface', "TEXT DEFAULT ''")),
    'srclimits': (('label', "TEXT DEFAULT ''"),),
    # 0: the address was already in the table (pf overload, another tool): never taken out by a condition;
    # span: how long this block lasts after each match (NULL: the condition's duration, rows before 1.8)
    'autoblocked': (('owned', 'INTEGER DEFAULT 1'), ('last_match', 'INTEGER DEFAULT 0'), ('span', 'INTEGER')),
    # the ban type of a condition (lib/bans.py)
    'conditions': bans.COLUMNS,
}


def load_config(path=CONF_FILE):
    parser = configparser.ConfigParser(interpolation=None)
    parser.read(path)
    section = parser['general'] if parser.has_section('general') else {}
    cfg = {}
    for key, default in DEFAULTS.items():
        raw = (section.get(key, '') if section else '').strip()
        if raw == '' and isinstance(default, str) and section and key in section:
            # an empty text setting stays empty (e.g. no tables to watch); the template writes every key
            cfg[key] = ''
        elif raw == '':
            cfg[key] = default
        elif isinstance(default, bool):
            cfg[key] = raw.lower() in ('1', 'yes', 'true', 'on')
        elif isinstance(default, int):
            try:
                cfg[key] = int(raw)
            except ValueError:
                cfg[key] = default
        else:
            cfg[key] = raw
    return cfg


def parse_port_list(text):
    """ "22,80,1000-1010" -> set of ints """
    ports = set()
    for item in re.split(r'[,\s]+', text or ''):
        if not item:
            continue
        lo, _, hi = item.partition('-')
        try:
            lo = int(lo)
            hi = int(hi) if hi else lo
        except ValueError:
            continue
        lo, hi = min(lo, hi), max(lo, hi)      # "8100-8000" is the same range
        ports.update(range(max(lo, 0), min(hi, 65535) + 1))
    return ports


def normalize_mac(mac):
    """ "0:c:29:a:b:c" -> "00:0c:29:0a:0b:0c" (empty string when not a MAC) """
    parts = mac.strip().lower().replace('-', ':').split(':')
    if len(parts) != 6 or not all(re.match(r'^[0-9a-f]{1,2}$', p) for p in parts):
        return ''
    return ':'.join(p.zfill(2) for p in parts)


def parse_mac_list(text):
    return set(filter(None, (normalize_mac(x) for x in re.split(r'[,\s]+', text or '') if x)))


def ip_sort_key(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return addr.version, int(addr)
    except ValueError:
        return 9, 0


def parse_network_list(text):
    networks = []
    for item in re.split(r'[,\s]+', text or ''):
        if item:
            try:
                networks.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                pass
    return networks


#  network discovery

# a point-to-point interface (tunnel) shows "inet <own> --> <peer> netmask ..."
INET_RE = re.compile(r'^\s*inet (\S+)(?: --> \S+)? netmask (0x[0-9a-fA-F]+)')
INET6_RE = re.compile(r'^\s*inet6 ([0-9a-fA-F:]+)(?:%\S+)? prefixlen (\d+)')


def _ifconfig(args):
    try:
        return subprocess.run(
            [IFCONFIG] + args, capture_output=True, text=True, timeout=10
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return ''


def parse_ifconfig(text):
    """ return [(address, network)] for every address found in ifconfig output """
    result = []
    for line in text.splitlines():
        match = INET_RE.match(line)
        if match:
            prefix = bin(int(match.group(2), 16)).count('1')
            net = ipaddress.ip_network('%s/%d' % (match.group(1), prefix), strict=False)
            result.append((match.group(1), net))
            continue
        match = INET6_RE.match(line)
        if match:
            addr = ipaddress.ip_address(match.group(1))
            if addr.is_link_local:
                continue
            net = ipaddress.ip_network('%s/%s' % (addr, match.group(2)), strict=False)
            result.append((str(addr), net))
    return result


def interface_devices(names):
    """ map OPNsense interface names (lan, opt1, ...) to devices (vtnet1, igb0, ...) """
    try:
        root = ET.parse(CONFIG_XML).getroot()
    except (OSError, ET.ParseError):
        return []
    section = root.find('interfaces')
    devices = []
    if section is None:
        return devices
    for name in names:
        if not re.match(r'^[a-zA-Z0-9_]+$', name):
            continue
        node = section.find(name)
        device = (node.findtext('if') or '').strip() if node is not None else ''
        if device:
            devices.append(device)
    return devices


class NetworkSet:
    """ fast(ish) membership test for many addresses against a few networks """

    def __init__(self, networks):
        self.networks = sorted(set(networks), key=lambda n: (n.version, n))
        self._v4 = [n for n in self.networks if n.version == 4]
        self._v6 = [n for n in self.networks if n.version == 6]
        self._cache = {}

    def __contains__(self, ip):
        result = self._cache.get(ip)
        if result is None:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                result = False
            else:
                nets = self._v4 if addr.version == 4 else self._v6
                result = any(addr in net for net in nets)
            if len(self._cache) > 250000:
                self._cache.clear()
            self._cache[ip] = result
        return result

    def __bool__(self):
        return bool(self.networks)

    def __str__(self):
        return ', '.join(str(n) for n in self.networks) or '(none)'


class AddrIndex:
    """
    membership test for large pf tables (CrowdSec lists hold tens of thousands of entries):
    host entries in a set, networks grouped per prefix length so a lookup costs one mask per length
    """

    def __init__(self, entries):
        self.hosts = set()
        self.nets = {}
        self.size = 0
        for entry in entries:
            try:
                net = ipaddress.ip_network(entry.strip(), strict=False)
            except ValueError:
                continue
            self.size += 1
            if net.prefixlen == net.max_prefixlen:
                self.hosts.add(str(net.network_address))
            else:
                self.nets.setdefault((net.version, net.prefixlen), set()).add(int(net.network_address))

    def __contains__(self, ip):
        if ip in self.hosts:
            return True
        if not self.nets:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        value, bits = int(addr), addr.max_prefixlen
        for (version, prefix), nets in self.nets.items():
            if version == addr.version and (value >> (bits - prefix)) << (bits - prefix) in nets:
                return True
        return False


def is_bogon(ip):
    """ private, reserved and other addresses that never come from the internet """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_reserved or addr.is_loopback or addr.is_link_local or addr.is_multicast \
        or addr.is_unspecified


def interface_labels():
    """ device -> "WAN" / "LAN" / description, as named in the OPNsense configuration """
    try:
        root = ET.parse(CONFIG_XML).getroot()
    except (OSError, ET.ParseError):
        return {}
    labels = {}
    section = root.find('interfaces')
    for node in (section if section is not None else []):
        device = (node.findtext('if') or '').strip()
        if device:
            labels[device] = (node.findtext('descr') or '').strip() or node.tag.upper()
    return labels


def resolve_networks(cfg):
    """ return (NetworkSet of monitored LAN networks, set of the firewall's own addresses) """
    networks = []
    names = [x.strip() for x in cfg['interfaces'].split(',') if x.strip()]
    for device in interface_devices(names):
        networks.extend(net for _, net in parse_ifconfig(_ifconfig([device])))
    networks.extend(parse_network_list(cfg['networks']))
    own =set(addr for addr, _ in parse_ifconfig(_ifconfig(['-a'])))
    return NetworkSet(networks), own


#  database

def connect(path=DB_FILE):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    con = sqlite3.connect(path, timeout=30)
    con.execute('PRAGMA busy_timeout=30000')
    con.execute('PRAGMA journal_mode=WAL')
    con.execute('PRAGMA synchronous=NORMAL')
    con.executescript(SCHEMA)
    for table, columns in MIGRATIONS.items():
        existing = {row[1] for row in con.execute('PRAGMA table_info(%s)' % table)}
        for name, definition in columns:
            if name not in existing:
                try:
                    con.execute('ALTER TABLE %s ADD COLUMN %s %s' % (table, name, definition))
                except sqlite3.OperationalError as exc:
                    # the collector and a GUI query starting together after an upgrade: the other one added it
                    if 'duplicate column' not in str(exc):
                        raise
    return con


def write_status(data, path=None):
    path = path or STATUS_FILE
    tmp = path + '.tmp'
    try:
        with open(tmp, 'w') as handle:
            json.dump(data, handle)
        os.replace(tmp, path)
    except OSError:
        pass


def read_status(path=None):
    try:
        with open(path or STATUS_FILE) as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {}


SEVERITIES = ('info', 'medium', 'high', 'critical')


def raise_alert(con, now, atype, severity, key, ip='', mac='', peer='', detail='', count=1,
                reopen=True, escalate_at=0):
    """
    record an alert, alerts with the same key are merged (count / last_seen / detail).
    reopen: a repeated event clears an earlier acknowledgement
    escalate_at: raise severity to critical once count reaches this value
    returns True when the alert is new or was reopened (worth logging)
    """
    row = con.execute('SELECT id, count, acked, severity FROM alerts WHERE akey = ?', (key,)).fetchone()
    if row is None:
        if escalate_at and count >= escalate_at:
            severity = 'critical'
        con.execute(
            """INSERT INTO alerts (akey, type, severity, ip, mac, peer, detail, first_seen, last_seen, count, acked)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)""",
            (key, atype, severity, ip, mac, peer, detail, now, now, count))
        return True
    total = row[1] + count
    if escalate_at and total >= escalate_at:
        severity = 'critical'
    # relative to the stored row, not to the SELECT above: an acknowledgement query.py wrote in between
    # (the collector does not hold the write lock between its steps) is kept. The worst severity of the
    # hour / episode stays, with its detail ("critical, reaching the host" is not replaced by a quieter poll)
    # An acknowledged alert that gets worse (high -> critical) is open again, also without reopen.
    rank = "CASE %s WHEN 'critical' THEN 3 WHEN 'high' THEN 2 WHEN 'medium' THEN 1 ELSE 0 END"
    worse = '(%s >= %s)' % (rank % '?', rank % 'severity')
    escalated = '(%s > %s)' % (rank % '?', rank % 'severity')
    con.execute(
        """UPDATE alerts SET last_seen = ?, count = count + ?,
               detail = CASE WHEN %s THEN ? ELSE detail END, peer = CASE WHEN %s THEN ? ELSE peer END,
               acked = CASE WHEN ? OR %s THEN 0 ELSE acked END,
               severity = CASE WHEN %s THEN ? ELSE severity END WHERE id = ?""" % (worse, worse, escalated, worse),
        (now, count, severity, detail, severity, peer, 1 if reopen else 0, severity, severity, severity, row[0]))
    ranks = {'critical': 3, 'high': 2, 'medium': 1}
    return bool(row[2] and (reopen or ranks.get(severity, 0) > ranks.get(row[3], 0)))


def store_service(con, res):
    now = res.get('time') or int(time.time())
    con.execute(
        """INSERT INTO services (ip, proto, port, state, service, product, tls, banner, method, last_probe, first_seen)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT (ip, proto, port) DO UPDATE SET
               state = excluded.state, service = excluded.service, product = excluded.product,
               tls = excluded.tls, banner = excluded.banner, method = excluded.method,
               last_probe = excluded.last_probe""",
        (res['ip'], res['proto'], res['port'], res['state'], res['service'], res['product'],
         res['tls'], res['banner'], res['method'], now, now)
    )
