"""
    Copyright (c) 2026 Onur Berkay <onurberkay@sakla.app>
    All rights reserved. (BSD 2-Clause, see LICENSE)

    Automatic filtering: built-in block conditions (type "auto"), graded by how sure the detection is.
    The level chosen in the settings takes its rules and those of the more certain levels:

    1 certain: what a legitimate client does not do. A source whose blocked TCP SYNs or UDP packets from a
      client port (not a traceroute / mtr) reached many ports of one LAN host (port scan) or many LAN hosts (sweep) within one sample, or
      blocked traffic from a network on Spamhaus ASN-DROP (run by or for criminals).
    2 likely: repeated logins in a distributed brute force (not on mail and web ports: their clients open
      several connections at once), alerts Suricata dropped (IPS mode: a rule the operator's policy set to
      drop). A legitimate user can be among them (an own SSH session during the attack, a false positive
      signature).
    3 possible: repeat sources of a SYN / UDP / ICMP flood that pf also blocked, sources over a per source
      rule limit; shared addresses (CGNAT, a company's NAT) and spoofed floods make mistakes likelier.

    Not the Suricata severity: it is the priority of the signature's class (policy-violation, e.g. a curl user
    agent, is 1 like trojan-activity), not how sure the match is.

    Reflection sources are never taken automatically: they are the abused DNS / NTP / ... servers themselves,
    blocking them breaks what the hosts use them for (their replies from a server port to random ports are
    not counted as a port scan either). Wanted traffic is never taken either: search engine and
    AI crawlers, monitoring probes, iCloud Private Relay and CDNs (lib/ipdata.py), besides what every
    condition spares (LAN hosts, the firewall, trusted networks).
"""
import bisect
import os
import sqlite3

from . import bans, ipdata

# fixed, not the LAN scan settings: level 1 must keep meaning "certain" whatever those are set to
SCAN_PORTS = 20     # different ports of one LAN host whose blocked attempts one sample shows from one source
SCAN_HOSTS = 10     # different LAN hosts
# (rule, level, what it takes)
RULES = (
    ('scan_ports', 1, 'port scan: blocked attempts on %d+ ports of one LAN host in one sample' % SCAN_PORTS),
    ('scan_hosts', 1, 'sweep: blocked attempts on %d+ LAN hosts in one sample' % SCAN_HOSTS),
    ('asn_drop', 1, 'blocked traffic from a network on Spamhaus ASN-DROP'),
    ('brute_force', 2, 'repeated logins in a distributed brute force (not mail / web ports)'),
    ('ids_drop', 2, 'an alert from outside that Suricata dropped (IPS mode)'),
    ('flood', 3, 'repeat sources of a SYN / UDP / ICMP / mixed flood that pf also blocked'),
    ('src_limit', 3, 'over a per source rule limit'),
)
ESCALATE_FACTOR = 2
LEVELS = {1: 'certain', 2: 'likely', 3: 'possible'}
FLOODS = ('syn flood', 'udp flood', 'icmp flood', 'mixed flood')
# login ports whose clients reconnect in parallel (mail, web): a busy one looks like a brute force
BRUTE_SKIP_PORTS = {25, 110, 143, 465, 587, 993, 995, 8006, 8443}
EXEMPT_ROLES = ('crawler', 'monitoring', 'relay')
EXEMPT_KINDS = ('cdn',)


def rules(cfg, have_drop):
    """ the rules the configured level takes: {rule: (level, description)} """
    level = cfg['auto_block_level']
    return dict((rule, (lvl, text)) for rule, lvl, text in RULES
                if lvl <= level and (rule != 'asn_drop' or have_drop))


def ban(cfg):
    """ the ban of every automatic rule (lib/bans.py) from the settings: duration and bans.FIELDS """
    duration = cfg['auto_block_hours'] * 3600
    escalating = cfg['auto_block_ban'] == 'escalating'
    longest = cfg['auto_block_max_hours'] * 3600
    return {'duration': duration, 'ban': 'escalating' if escalating else 'fixed', 'factor': ESCALATE_FACTOR,
            # the longest block is never shorter than the first one, nor longer than a year
            'max_duration': min(max(longest, duration), bans.MAX_BAN) if escalating else 0,
            'strikes': 1, 'strike_window': 0, 'forget': bans.DEFAULT_FORGET}


class Networks:
    """ the owner / network type database (lib/ipdata.py), opened again when the daily update replaced it """

    def __init__(self, path=None):
        self.path = path
        self.mtime = None
        self.db = None
        self.drop_starts, self.drop_stops = [], []

    def refresh(self, enabled):
        path = self.path or ipdata.DATA_FILE
        try:
            mtime = os.stat(path).st_mtime if enabled else None
        except OSError:
            mtime = None
        if mtime == self.mtime:
            return
        self.mtime = mtime
        if self.db is not None and self.db.con is not None:
            self.db.con.close()
        self.db, self.drop_starts, self.drop_stops = None, [], []
        if mtime is None:
            return
        db = ipdata.IpData(path)
        if not db.available:
            return
        self.db = db
        try:
            rows = db.con.execute('SELECT r.start, r.stop FROM ranges r JOIN asns a ON a.asn = r.asn'
                                  ' WHERE a.dropped = 1 ORDER BY r.start').fetchall()
        except sqlite3.Error:
            rows = []
        self.drop_starts = [r[0] for r in rows]
        self.drop_stops = [r[1] for r in rows]

    @property
    def has_drop(self):
        return bool(self.drop_starts)

    def in_drop(self, ip):
        """ is the address in a network of an AS on Spamhaus ASN-DROP (no database query: bisect) """
        k = ipdata.key(ip)
        if k is None or not self.drop_starts:
            return False
        i = bisect.bisect_right(self.drop_starts, k) - 1
        return i >= 0 and self.drop_stops[i] >= k

    def exempt(self, ip):
        """ why an automatic rule must not take this address (wanted traffic), or '' """
        if self.db is None:
            return ''
        net = self.db.lookup(ip)
        if not net:
            return ''
        if net['role'] in EXEMPT_ROLES:
            return net['role_name'] or net['role']
        if net['kind'] in EXEMPT_KINDS:
            return '%s (CDN)' % (net['provider'] or 'CDN')
        return ''
