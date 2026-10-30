"""
    Copyright (c) 2026 Onur Berkay <onurberkay@sakla.app>
    All rights reserved. (BSD 2-Clause, see LICENSE)

    Who owns an outside address and what kind of network it is in, from public lists that need no account.
    Where lists disagree the more reliable one wins (a lower tier):

    1 official, from the publisher itself: the address ranges AWS, Google Cloud, Oracle Cloud, DigitalOcean,
      Linode, Cloudflare and Fastly publish; the Tor Project's exit list
    2 official lists collected by rezmoss/cloud-provider-ip-addresses (CC0): Azure, Vultr, CDNs, SaaS, the
      crawler ranges search engines and AI bots publish, monitoring probes, Apple Private Relay, Mullvad
    3 ranges derived from the AS / BGP data of a company: X4BNet lists_vpn (MIT, IPLocate data CC BY-SA 4.0)
      and the rezmoss providers that publish no list of their own
    then per AS (owner from iptoasn.com, PDDL): the "Also hosting" setting, and last the category
    ipverse/as-metadata (CC0) estimates for every AS: ISP, business, hosting, education, government.

    Tor exit, crawler, monitoring and Private Relay are roles next to the network type (an Amazonbot address
    is in AWS and a crawler). Spamhaus ASN-DROP ((c) The Spamhaus Project) marks AS run by or for criminals.

    The lists are downloaded once a day (once more three hours after a build that missed one) into a local
    SQLite database (update_ipdata.py); a lookup never sends
    an address anywhere. A list that cannot be downloaded keeps its rows of the previous database.
"""
import gzip
import io
import json
import os
import socket
import sqlite3
import ssl
import time
import urllib.request

DATA_FILE = '/var/db/hostguard/ipdata.db'
STATUS_FILE = '/var/db/hostguard/ipdata.status'
USER_AGENT = 'os-hostguard (OPNsense plugin)'
MAX_DOWNLOAD = 64 * 1024 * 1024         # as sent (GitHub compresses)
MAX_TEXT = 512 * 1024 * 1024            # unpacked
MAX_JSON = 64 * 1024 * 1024             # unpacked JSON, held in memory at once (the real ones are a few MB)
MAX_LINE = 1024 * 1024                  # one line (a packed line of gigabytes must not fill the memory)
MAX_NETS = 1000000                      # rows of one address list (rezmoss, the largest, has about 450000)
# shorter prefixes are no provider's network: a line cut off by a broken download ("/24" -> "/2")
MIN_PLEN_V4, MIN_PLEN_V6 = 8, 16
MIN_DROP = 10                           # ASN-DROP lists hundreds of AS: fewer is an error page, not the list
MAX_AGE = 86400
RETRY_PARTIAL = 3 * 3600                # a build that missed a list (kept the earlier data) is tried again sooner

OFFICIAL, MIRROR, DERIVED = 1, 2, 3
BASIS = {OFFICIAL: 'official', MIRROR: 'official (mirrored)', DERIVED: 'derived from AS'}

OWNER_URL = 'https://iptoasn.com/data/ip2asn-combined.tsv.gz'
ASNDROP_URL = 'https://www.spamhaus.org/drop/asndrop.json'
CATEGORY_URL = 'https://raw.githubusercontent.com/ipverse/as-metadata/master/as.json'
X4B = 'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/%s/%s.txt'
REZMOSS_URL = ('https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/'
               'all_providers/all_providers.csv')
# (source, url, format, kind or role, provider, tier)
NET_SOURCES = [
    ('aws', 'https://ip-ranges.amazonaws.com/ip-ranges.json', 'aws', 'cloud', 'AWS', OFFICIAL),
    ('gcp', 'https://www.gstatic.com/ipranges/cloud.json', 'gcp', 'cloud', 'Google Cloud', OFFICIAL),
    ('oracle', 'https://docs.oracle.com/iaas/tools/public_ip_ranges.json', 'oracle', 'cloud', 'Oracle Cloud', OFFICIAL),
    ('digitalocean', 'https://www.digitalocean.com/geo/google.csv', 'csv', 'cloud', 'DigitalOcean', OFFICIAL),
    ('linode', 'https://geoip.linode.com/', 'csv', 'cloud', 'Linode / Akamai', OFFICIAL),
    ('cloudflare4', 'https://www.cloudflare.com/ips-v4/', 'lines', 'cdn', 'Cloudflare', OFFICIAL),
    ('cloudflare6', 'https://www.cloudflare.com/ips-v6/', 'lines', 'cdn', 'Cloudflare', OFFICIAL),
    ('fastly', 'https://api.fastly.com/public-ip-list', 'fastly', 'cdn', 'Fastly', OFFICIAL),
    ('tor', 'https://check.torproject.org/torbulkexitlist', 'lines', 'tor', 'Tor', OFFICIAL),
    ('rezmoss', REZMOSS_URL, 'rezmoss', '', '', MIRROR),
    ('vpn4', X4B % ('vpn', 'ipv4'), 'lines', 'vpn', '', DERIVED),
    ('vpn6', X4B % ('vpn', 'ipv6'), 'lines', 'vpn', '', DERIVED),
    ('datacenter4', X4B % ('datacenter', 'ipv4'), 'lines', 'hosting', '', DERIVED),
    ('datacenter6', X4B % ('datacenter', 'ipv6'), 'lines', 'hosting', '', DERIVED),
]
# rezmoss provider -> (kind or role, name, tier as its README states: an official list or the company's AS);
# providers fetched from the publisher above and new ones not named here are left out
REZMOSS = {
    'azure': ('cloud', 'Microsoft Azure', MIRROR),
    'googleservices': ('service', 'Google', MIRROR),
    'github': ('service', 'GitHub', MIRROR),
    'microsoft365': ('service', 'Microsoft 365', MIRROR),
    'zoom': ('service', 'Zoom', MIRROR),
    'atlassian': ('service', 'Atlassian', MIRROR),
    'telegram': ('service', 'Telegram', MIRROR),
    'discord': ('service', 'Discord', MIRROR),
    'circleci': ('cloud', 'CircleCI', MIRROR),
    'teamcity': ('cloud', 'TeamCity Cloud', MIRROR),
    'vultr': ('hosting', 'Vultr', MIRROR),
    'play2go': ('hosting', 'Play2Go', MIRROR),
    'imperva': ('cdn', 'Imperva', MIRROR),
    'gcore': ('cdn', 'G-Core', MIRROR),
    'cachefly': ('cdn', 'CacheFly', MIRROR),
    'gocache': ('cdn', 'GoCache', MIRROR),
    'quiccloud': ('cdn', 'QUIC.cloud', MIRROR),
    'mullvad': ('vpn', 'Mullvad', MIRROR),
    'apple_private_relay': ('relay', 'iCloud Private Relay', MIRROR),
    'googlebot': ('crawler', 'Googlebot', MIRROR),
    'bingbot': ('crawler', 'Bingbot', MIRROR),
    'gptbot': ('crawler', 'OpenAI bots', MIRROR),
    'claudebot': ('crawler', 'ClaudeBot', MIRROR),
    'applebot': ('crawler', 'Applebot', MIRROR),
    'perplexitybot': ('crawler', 'PerplexityBot', MIRROR),
    'duckduckbot': ('crawler', 'DuckDuckBot', MIRROR),
    'amazonbot': ('crawler', 'Amazonbot', MIRROR),
    'commoncrawl': ('crawler', 'Common Crawl', MIRROR),
    'uptimerobot': ('monitoring', 'UptimeRobot', MIRROR),
    'statuscake': ('monitoring', 'StatusCake', MIRROR),
    'pingdom': ('monitoring', 'Pingdom', MIRROR),
    'datadog': ('monitoring', 'Datadog', MIRROR),
    'akamai': ('cdn', 'Akamai', DERIVED),
    'bunny': ('cdn', 'Bunny CDN', DERIVED),
    'stormwall': ('cdn', 'StormWall', DERIVED),
    'sucuri': ('cdn', 'Sucuri', DERIVED),
    'alibaba': ('cloud', 'Alibaba Cloud', DERIVED),
    'tencent': ('cloud', 'Tencent Cloud', DERIVED),
    'huawei': ('cloud', 'Huawei Cloud', DERIVED),
    'ibmcloud': ('cloud', 'IBM Cloud', DERIVED),
    'backblaze': ('cloud', 'Backblaze', DERIVED),
    'wasabi': ('cloud', 'Wasabi', DERIVED),
    'contabo': ('hosting', 'Contabo', DERIVED),
    'hetzner': ('hosting', 'Hetzner', DERIVED),
    'ovhcloud': ('hosting', 'OVHcloud', DERIVED),
    'leaseweb': ('hosting', 'Leaseweb', DERIVED),
    'scaleway': ('hosting', 'Scaleway', DERIVED),
    'upcloud': ('hosting', 'UpCloud', DERIVED),
    'rackspace': ('hosting', 'Rackspace', DERIVED),
    'hostway': ('hosting', 'Hostway', DERIVED),
    'gabia': ('hosting', 'Gabia', DERIVED),
    'nhncloud': ('hosting', 'NHN Cloud', DERIVED),
    'meta': ('service', 'Meta', DERIVED),
    'salesforce': ('service', 'Salesforce', DERIVED),
    'zoho': ('service', 'Zoho', DERIVED),
    'zscaler': ('service', 'Zscaler', DERIVED),
    'yandex': ('service', 'Yandex', DERIVED),
    'baidu': ('service', 'Baidu', DERIVED),
    'internetarchive': ('service', 'Internet Archive', DERIVED),
}
KIND_ORDER = ('cloud', 'cdn', 'vpn', 'hosting', 'service')
ROLES = ('tor', 'crawler', 'monitoring', 'relay')
CATEGORIES = {'isp': 'isp', 'business': 'business', 'hosting': 'hosting', 'education_research': 'education',
              'government_admin': 'government'}
CREDITS = ('Network data: iptoasn.com (public domain), the address ranges cloud providers and the Tor Project '
           'publish, rezmoss/cloud-provider-ip-addresses (CC0), X4BNet lists_vpn (MIT, IPLocate data CC BY-SA 4.0), '
           'ipverse/as-metadata (CC0), Spamhaus ASN-DROP (c) The Spamhaus Project')

SCHEMA = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE ranges (start BLOB PRIMARY KEY, stop BLOB, asn INTEGER) WITHOUT ROWID;
CREATE TABLE asns (asn INTEGER PRIMARY KEY, cc TEXT, name TEXT, dropped INTEGER DEFAULT 0, category TEXT);
CREATE TABLE nets (net BLOB, plen INTEGER, kind TEXT, provider TEXT, source TEXT, tier INTEGER,
                   PRIMARY KEY (net, plen, source)) WITHOUT ROWID;
"""
# what a build copies from the previous database when a list cannot be downloaded (and checks it has)
OLD_COLUMNS = {'ranges': 'start, stop, asn', 'asns': 'asn, cc, name, dropped, category',
               'nets': 'net, plen, kind, provider, source, tier'}

V4_PREFIX = b'\x00' * 10 + b'\xff\xff'


def key(address):
    """ 16 byte sort key of an address, IPv4 as ::ffff:a.b.c.d; None when it is none """
    try:
        if ':' in address:
            return socket.inet_pton(socket.AF_INET6, address)
        return V4_PREFIX + socket.inet_pton(socket.AF_INET, address)
    except (OSError, ValueError, TypeError):
        return None


def parse_asns(text):
    """ "AS16276, 24940" -> {16276, 24940} """
    result = set()
    for item in str(text or '').replace(' ', ',').split(','):
        item = item.strip().upper()
        if item.startswith('AS'):
            item = item[2:]
        if item.isdigit():
            result.add(int(item))
    return result


def network(cidr):
    """ "198.51.100.0/24" -> (16 byte network key, prefix length of the 128 bit key); None when invalid """
    address, _, plen = cidr.strip().partition('/')
    start = key(address)
    if start is None:
        return None
    full = 32 if ':' not in address else 128
    try:
        plen = int(plen) if plen else full
    except ValueError:
        return None
    if not 0 <= plen <= full:
        return None
    plen += 128 - full
    mask = ((1 << 128) - 1) ^ ((1 << (128 - plen)) - 1)
    return (int.from_bytes(start, 'big') & mask).to_bytes(16, 'big'), plen


def collapse(nets):
    """ (network key, prefix length) pairs -> the fewest that cover the same addresses """
    spans = sorted((int.from_bytes(net, 'big'), int.from_bytes(net, 'big') + (1 << (128 - plen)) - 1)
                   for net, plen in nets)
    merged = []
    for start, end in spans:
        if merged and start <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    for start, end in merged:
        while start <= end:
            size = (start & -start).bit_length() - 1 if start else 128
            while start + (1 << size) - 1 > end:
                size -= 1
            yield start.to_bytes(16, 'big'), 128 - size
            start += 1 << size


#  parsers: bytes of a download (gzip or not) -> CIDR strings, or (CIDR, kind, provider, source, tier)

def _text_lines(data, limit=MAX_TEXT):
    """ the lines of a download, unpacked while read when it is gzip (at most limit, lines at most MAX_LINE) """
    if data[:2] == b'\x1f\x8b':
        stream, total, rest = gzip.GzipFile(fileobj=io.BytesIO(data)), 0, b''
        while True:
            chunk = stream.read(1 << 20)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise ValueError('more than %d bytes unpacked' % limit)
            lines = (rest + chunk).split(b'\n')
            rest = lines.pop()
            if len(rest) > MAX_LINE:
                raise ValueError('a line longer than %d bytes' % MAX_LINE)
            for line in lines:
                yield (line + b'\n').decode('utf-8', 'replace')
        if rest:
            yield rest.decode('utf-8', 'replace')
    else:
        for line in io.BytesIO(data):
            if len(line) > MAX_LINE:
                raise ValueError('a line longer than %d bytes' % MAX_LINE)
            yield line.decode('utf-8', 'replace')


def _lines(data):
    for line in _text_lines(data):
        line = line.strip()
        if line and not line.startswith('#'):
            yield line.split(None, 1)[0]


def _csv(data):
    # RFC 8805 geofeed / DigitalOcean: the prefix is the first column
    for line in _lines(data):
        yield line.split(',')[0]


def _json(data):
    return json.loads(''.join(_text_lines(data, MAX_JSON)))


def _aws(data):
    doc = _json(data)
    for item in doc.get('prefixes', []):
        yield item.get('ip_prefix', '')
    for item in doc.get('ipv6_prefixes', []):
        yield item.get('ipv6_prefix', '')


def _gcp(data):
    for item in _json(data).get('prefixes', []):
        yield item.get('ipv4Prefix') or item.get('ipv6Prefix') or ''


def _oracle(data):
    for region in _json(data).get('regions', []):
        for item in region.get('cidrs', []) + region.get('ipv6_cidrs', []):
            yield item.get('cidr', '')


def _fastly(data):
    doc = _json(data)
    for cidr in doc.get('addresses', []) + doc.get('ipv6_addresses', []):
        yield cidr


def _rezmoss(data):
    """ all_providers.csv: cidr,ip_version,provider,service,region,last_updated """
    lines = _text_lines(data)
    header = next(lines, '').strip().split(',')
    if header[:3] != ['cidr', 'ip_version', 'provider']:
        raise ValueError('unexpected columns %s' % header[:3])
    for line in lines:
        parts = line.split(',', 3)
        if len(parts) >= 3 and parts[2] in REZMOSS:
            kind, name, tier = REZMOSS[parts[2]]
            yield parts[0], kind, name, 'rezmoss:' + parts[2], tier


PARSERS = {'lines': _lines, 'csv': _csv, 'aws': _aws, 'gcp': _gcp, 'oracle': _oracle, 'fastly': _fastly,
           'rezmoss': _rezmoss}


def parse_owner(data):
    """ ip2asn-combined.tsv.gz -> (start key, stop key, asn, country, AS name); "not routed" (AS 0) left out """
    for line in _text_lines(data):
        parts = line.rstrip('\r\n').split('\t')
        if len(parts) < 5:
            continue
        try:
            asn = int(parts[2])
        except ValueError:
            continue
        start, stop = key(parts[0]), key(parts[1])
        if asn and start and stop:
            # the country is a two letter code, or "Unknown" / "None"
            cc = parts[3] if len(parts[3]) == 2 else ''
            yield start, stop, asn, cc, parts[4][:100]


def parse_asndrop(data):
    """ Spamhaus ASN-DROP (one JSON object per line, the last one is metadata) -> AS numbers """
    for line in _text_lines(data):
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict) and isinstance(item.get('asn'), int):
            yield item['asn']


def parse_categories(data):
    """
    ipverse as.json -> (asn, isp / business / hosting / education / government), read line by line (the file
    has one "asn" and one "metadata" line per AS) instead of loading 70 MB of JSON at once
    """
    asn = None
    for line in _text_lines(data):
        line = line.strip()
        if line.startswith('"asn":'):
            try:
                asn = int(line[6:].strip().rstrip(','))
            except ValueError:
                asn = None
        elif line.startswith('"metadata":') and asn is not None:
            try:
                meta = json.loads(line[11:].strip().rstrip(','))
            except ValueError:
                meta = None
            category = CATEGORIES.get((meta or {}).get('category'))
            if category:
                yield asn, category
            asn = None


def _tls_context():
    """ certificates verified; the CA bundle of ca_root_nss when Python's OpenSSL has none configured """
    context = ssl.create_default_context()
    if not context.get_ca_certs():
        for bundle in ('/usr/local/etc/ssl/cert.pem', '/etc/ssl/cert.pem'):
            if os.path.exists(bundle):
                context.load_verify_locations(bundle)
                break
    return context


def fetch(url, timeout=120):
    """ the body as sent: gzip when the server compressed it (the parsers unpack it) """
    request = urllib.request.Request(url, headers={'User-Agent': USER_AGENT, 'Accept-Encoding': 'gzip'})
    with urllib.request.urlopen(request, timeout=timeout, context=_tls_context()) as response:
        data = response.read(MAX_DOWNLOAD + 1)
        length = response.headers.get('Content-Length')
    if len(data) > MAX_DOWNLOAD:
        raise ValueError('larger than %d bytes' % MAX_DOWNLOAD)
    # a connection closed early is not an error to http.client: a cut off list would look complete
    if length and length.strip().isdigit() and int(length) != len(data):
        raise ValueError('incomplete: %d of %s bytes' % (len(data), length.strip()))
    return data


def build(path=None, fetch=fetch, now=None):
    """
    Download every list and replace the database in one step (readers see the old or the new one).
    -> {source: number of entries, or "error: ..." (that list's rows are taken from the previous database)}
    """
    path = path or DATA_FILE
    now = int(now or time.time())
    tmp = path + '.new'
    if os.path.exists(tmp):
        os.remove(tmp)
    previous = path if os.path.exists(path) else None
    con = sqlite3.connect(tmp)
    con.executescript(SCHEMA)
    if previous:
        try:
            con.execute('ATTACH DATABASE ? AS old', (previous,))
            for table, columns in OLD_COLUMNS.items():
                con.execute('SELECT %s FROM old.%s LIMIT 1' % (columns, table)).fetchall()
        except sqlite3.Error:
            # damaged or from another version: start without it
            previous = None
            con.close()
            os.remove(tmp)
            con = sqlite3.connect(tmp)
            con.executescript(SCHEMA)
    result = {}
    try:
        try:
            data, asns = fetch(OWNER_URL), {}

            def owners():
                for start, stop, asn, cc, name in parse_owner(data):
                    asns[asn] = (cc, name)
                    yield start, stop, asn
            con.executemany('INSERT OR REPLACE INTO ranges VALUES (?, ?, ?)', owners())
            del data
            count = con.execute('SELECT COUNT(*) FROM ranges').fetchone()[0]
            if count < 1000:
                raise ValueError('only %d ranges' % count)
            con.executemany('INSERT INTO asns (asn, cc, name) VALUES (?, ?, ?)',
                            [(asn, cc, name) for asn, (cc, name) in asns.items()])
            result['iptoasn'] = count
        except Exception as exc:
            result['iptoasn'] = 'error: %s' % exc
            con.execute('DELETE FROM ranges')
            con.execute('DELETE FROM asns')
            if previous:
                con.execute('INSERT INTO ranges (start, stop, asn) SELECT start, stop, asn FROM old.ranges')
                con.execute('INSERT INTO asns (asn, cc, name) SELECT asn, cc, name FROM old.asns')
        try:
            dropped = set(parse_asndrop(fetch(ASNDROP_URL)))
            if len(dropped) < MIN_DROP:
                raise ValueError('only %d AS' % len(dropped))
            result['asndrop'] = len(dropped)
        except Exception as exc:
            result['asndrop'] = 'error: %s' % exc
            dropped = set(r[0] for r in con.execute('SELECT asn FROM old.asns WHERE dropped = 1')) if previous else set()
        con.executemany('UPDATE asns SET dropped = 1 WHERE asn = ?', [(asn,) for asn in dropped])
        try:
            categories = [(category, asn) for asn, category in parse_categories(fetch(CATEGORY_URL))]
            if len(categories) < 1000:
                raise ValueError('only %d AS' % len(categories))
            con.executemany('UPDATE asns SET category = ? WHERE asn = ?', categories)
            result['ipverse'] = len(categories)
        except Exception as exc:
            result['ipverse'] = 'error: %s' % exc
            if previous:
                con.execute('UPDATE asns SET category = (SELECT o.category FROM old.asns o WHERE o.asn = asns.asn)')
        for source, url, fmt, kind, provider, tier in NET_SOURCES:
            try:
                groups, total = {}, 0
                for item in PARSERS[fmt](fetch(url)):
                    total += 1
                    if total > MAX_NETS:
                        raise ValueError('more than %d networks' % MAX_NETS)
                    cidr, label = (item[0], item[1:]) if isinstance(item, tuple) else (item, (kind, provider, source, tier))
                    net = network(cidr) if cidr else None
                    if not net:
                        continue
                    v4 = net[1] >= 96 and net[0][:12] == V4_PREFIX
                    if net[1] < (96 + MIN_PLEN_V4 if v4 else MIN_PLEN_V6):
                        raise ValueError('implausible network %s' % cidr.strip()[:50])
                    groups.setdefault(label + (v4,), set()).add(net)
                if not groups:
                    raise ValueError('empty')
                count = 0
                for (label_kind, label_provider, label_source, label_tier, _v4), nets in groups.items():
                    rows = [(net, plen, label_kind, label_provider, label_source, label_tier)
                            for net, plen in collapse(nets)]
                    con.executemany('INSERT OR IGNORE INTO nets VALUES (?, ?, ?, ?, ?, ?)', rows)
                    count += len(rows)
                result[source] = count
            except Exception as exc:
                result[source] = 'error: %s' % exc
                if previous:
                    con.execute('INSERT OR IGNORE INTO nets (%s) SELECT %s FROM old.nets WHERE source = ? OR source LIKE ?'
                                % (OLD_COLUMNS['nets'], OLD_COLUMNS['nets']), (source, source + ':%'))
        plens = sorted(set(r[0] for r in con.execute('SELECT DISTINCT plen FROM nets')), reverse=True)
        # the lists missed: tried again after RETRY_PARTIAL once, not every few hours when one stays broken
        missed = sorted(source for source, value in result.items() if isinstance(value, str))
        before = set()
        if previous:
            try:
                row = con.execute("SELECT value FROM old.meta WHERE key = 'missed'").fetchone()
                value = json.loads(row[0]) if row and isinstance(row[0], str) else []
                before = set(item for item in value if isinstance(item, str)) if isinstance(value, list) else set()
            except (sqlite3.Error, ValueError):
                before = set()
        con.executemany('INSERT INTO meta VALUES (?, ?)', [
            ('updated', str(now)), ('sources', json.dumps(result)), ('plens', json.dumps(plens)),
            ('missed', json.dumps(missed)), ('retry', '1' if set(missed) - before else '0')])
        con.commit()
        if previous:
            con.execute('DETACH DATABASE old')
        # without owner data (iptoasn unreachable on the first download) the network types are still worth
        # keeping; when no list came at all (the WAN is down) the previous database stays as it is, with its
        # own date, and the next try is in an hour
        fresh = [source for source, value in result.items() if not isinstance(value, str)]
        if not fresh or (not con.execute('SELECT COUNT(*) FROM ranges').fetchone()[0] and
                         not con.execute('SELECT COUNT(*) FROM nets').fetchone()[0]):
            raise ValueError('nothing downloaded: %s' % result.get('iptoasn'))
        con.execute('VACUUM')
        con.close()
        os.replace(tmp, path)
    except Exception:
        con.close()
        if os.path.exists(tmp):
            os.remove(tmp)
        raise
    return result


def last_try(path=None):
    """ {status: ok / error, time, message or sources} of the last download, {} before the first """
    try:
        with open(path or STATUS_FILE) as handle:
            result = json.load(handle)
        return result if isinstance(result, dict) else {}
    except (OSError, ValueError):
        return {}


def write_last_try(result, path=None):
    path = path or STATUS_FILE
    tmp = path + '.tmp'
    with open(tmp, 'w') as handle:
        json.dump(result, handle)
    os.replace(tmp, path)


def age(path=None, now=None):
    """ seconds since the last build, None when there is none """
    return _built(path, now)[0]


def _built(path=None, now=None):
    """ (seconds since the last build or None, try again early: it missed a list the build before did not) """
    try:
        con = sqlite3.connect('file:%s?mode=ro' % (path or DATA_FILE), uri=True)
        try:
            meta = dict(con.execute("SELECT key, value FROM meta WHERE key IN ('updated', 'retry')"))
        finally:
            con.close()
        if 'updated' not in meta:
            return None, False
        return int(now or time.time()) - int(meta['updated']), meta.get('retry') == '1'
    except (sqlite3.Error, ValueError):
        return None, False


def due(path=None, now=None):
    """
    is a download due: no data yet, a day old, RETRY_PARTIAL after a build that missed a list (once: a list
    that stays broken waits for the daily one), or dated in the future (the clock was wrong then)
    """
    current, retry = _built(path, now)
    return current is None or current < 0 or current >= MAX_AGE or (retry and current >= RETRY_PARTIAL)


class IpData:
    """ lookups in the local database; available is False while there is none """

    def __init__(self, path=None, hosting_asns=()):
        path = path or DATA_FILE
        self.cache = {}
        self.hosting_asns = set(hosting_asns)
        self.meta = {}
        self.plens = []
        self.con = None
        self.owners = False     # owner data (iptoasn) there: without it "no AS" means unknown, not "not routed"
        if not os.path.exists(path):
            return
        try:
            self.con = sqlite3.connect('file:%s?mode=ro' % path, uri=True)
            self.meta = dict(self.con.execute('SELECT key, value FROM meta'))
            self.plens = json.loads(self.meta.get('plens', '[]'))
            self.owners = self.con.execute('SELECT 1 FROM ranges LIMIT 1').fetchone() is not None
        except (sqlite3.Error, ValueError):
            self.con = None

    @property
    def available(self):
        return self.con is not None

    def status(self):
        """ the data in use and the outcome of the last download (update_ipdata.py) """
        result = {'available': self.available, 'credits': CREDITS, 'last_try': last_try()}
        if self.available:
            try:
                sources = json.loads(self.meta.get('sources', '{}'))
            except ValueError:
                sources = {}
            result.update(updated=int(self.meta.get('updated', 0) or 0), sources=sources)
        return result

    def lookup(self, address):
        """
        -> {asn, as_name, cc, category (of the AS), kind, provider, basis, role, role_name, drop} or None;
        kind: cloud / cdn / vpn / hosting / service from an address list, else hosting by the setting, else the
        AS category (isp / business / hosting / education / government), else ""; basis says which of these;
        asn 0: in no announced range, None: unknown (the owner list could not be downloaded yet)
        """
        if address in self.cache:
            return self.cache[address]
        result = None
        k = key(address)
        if self.available and k is not None:
            result = {'asn': 0 if self.owners else None, 'as_name': '', 'cc': '', 'category': '', 'kind': '', 'provider': '', 'basis': '',
                      'role': '', 'role_name': '', 'drop': False}
            row = self.con.execute(
                'SELECT r.stop, r.asn, a.cc, a.name, a.dropped, a.category FROM ranges r'
                ' LEFT JOIN asns a ON a.asn = r.asn WHERE r.start <= ? ORDER BY r.start DESC LIMIT 1', (k,)).fetchone()
            if row and row[0] >= k:
                result.update(asn=row[1], cc=row[2] or '', as_name=row[3] or '', drop=bool(row[4]),
                              category=row[5] or '')
            # every network the address could be in, in one query; a row only counts with its own prefix length
            value = int.from_bytes(k, 'big')
            masked = {}
            for plen in self.plens:
                if plen >= 96 or k[:12] != V4_PREFIX:
                    masked[plen] = (value >> (128 - plen) << (128 - plen)).to_bytes(16, 'big')
            kinds, roles = [], []
            nets = sorted(set(masked.values()))
            if nets:
                for net, plen, kind, provider, tier in self.con.execute(
                        'SELECT net, plen, kind, provider, tier FROM nets WHERE net IN (%s)'
                        % ','.join('?' * len(nets)), nets):
                    if masked.get(plen) == net:
                        # the more reliable list first, then the more specific network
                        rank = (tier, -plen, KIND_ORDER.index(kind) if kind in KIND_ORDER else 99)
                        (roles if kind in ROLES else kinds).append((rank, kind, provider, tier))
            if kinds:
                _, kind, provider, tier = min(kinds)
                result.update(kind=kind, provider=provider, basis=BASIS.get(tier, ''))
            elif result['asn'] in self.hosting_asns:
                result.update(kind='hosting', basis='setting')
            elif result['category']:
                result.update(kind=result['category'], basis='AS category')
            if roles:
                _, role, name, _tier = min(roles)
                result.update(role=role, role_name=name)
            if result['kind'] and not result['provider']:
                result['provider'] = result['as_name']
        if len(self.cache) < 200000:
            self.cache[address] = result
        return result
