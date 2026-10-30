"""
    Copyright (c) 2026 Onur Berkay <onurberkay@sakla.app>
    All rights reserved. (BSD 2-Clause, see LICENSE)

    Lightweight service detection.

    Connects to ip:port, listens for a greeting and otherwise sends a few
    harmless protocol openers (HTTP HEAD, TLS client hello, Redis PING,
    PostgreSQL SSLRequest, RDP connection request, ...) to name the service.
    When enabled and installed, nmap -sV is used first.
"""
import os
import re
import socket
import ssl
import struct
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET

NMAP = '/usr/local/bin/nmap'

WELL_KNOWN = {
    'tcp': {
        20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns', 80: 'http',
        110: 'pop3', 111: 'rpcbind', 135: 'msrpc', 139: 'netbios-ssn', 143: 'imap', 389: 'ldap',
        443: 'https', 445: 'smb', 465: 'smtps', 587: 'submission', 636: 'ldaps', 853: 'dns-over-tls',
        873: 'rsync', 993: 'imaps', 995: 'pop3s', 1194: 'openvpn', 1433: 'mssql', 1521: 'oracle',
        1723: 'pptp', 2049: 'nfs', 2082: 'cpanel', 2083: 'cpanel-ssl', 2086: 'whm', 2087: 'whm-ssl',
        2095: 'webmail', 2096: 'webmail-ssl', 2375: 'docker', 2376: 'docker-tls', 3000: 'http-alt',
        3306: 'mysql', 3389: 'rdp', 5432: 'postgresql', 5672: 'amqp', 5900: 'vnc', 5985: 'winrm',
        5986: 'winrm-https', 6379: 'redis', 6443: 'kubernetes-api', 8006: 'proxmox', 8080: 'http-proxy',
        8443: 'https-alt', 8888: 'http-alt', 9090: 'http-alt', 9200: 'elasticsearch', 9443: 'https-alt',
        10000: 'webmin', 11211: 'memcached', 25565: 'minecraft', 27017: 'mongodb',
    },
    'udp': {
        53: 'dns', 67: 'dhcp', 69: 'tftp', 123: 'ntp', 137: 'netbios-ns', 161: 'snmp', 500: 'isakmp',
        514: 'syslog', 1194: 'openvpn', 1900: 'ssdp', 3478: 'stun', 4500: 'ipsec-nat-t', 5060: 'sip',
        27015: 'srcds', 51820: 'wireguard',
    },
}

TLS_PORTS = {443, 465, 636, 853, 993, 995, 2083, 2087, 2096, 2376, 5986, 6443, 8006, 8443, 9443, 10000}
TLS_SERVICE = {'http': 'https', 'imap': 'imaps', 'pop3': 'pop3s', 'smtp': 'smtps', 'ftp': 'ftps'}


def port_name(port, proto):
    if proto not in WELL_KNOWN:
        return proto
    if not port:
        return 'other ports'    # blocked traffic past the busiest ports of a host (collector store_blocked)
    name = WELL_KNOWN[proto].get(port)
    if name:
        return name
    try:
        return socket.getservbyport(port, proto)
    except (OSError, OverflowError):
        return ''


def _result(ip, port, proto):
    return {
        'ip': ip, 'port': port, 'proto': proto, 'state': 'unknown', 'service': port_name(port, proto),
        'product': '', 'tls': '', 'banner': '', 'method': 'port', 'time': int(time.time()),
    }


def unprobed(ip, port, proto, state, method):
    """ result record for a port that is named by number only """
    res = _result(ip, port, proto)
    res.update(state=state, method=method)
    return res


def _printable(data, limit=200):
    text = data.decode('utf-8', 'replace') if isinstance(data, bytes) else data
    text = re.sub(r'[^\x20-\x7e -￿]+', ' ', text).strip()
    return text[:limit]


def _connect(ip, port, timeout, kind=socket.SOCK_STREAM):
    family = socket.AF_INET6 if ':' in ip else socket.AF_INET
    sock = socket.socket(family, kind)
    sock.settimeout(timeout)
    sock.connect((ip, port))
    return sock


def _recv(sock, timeout, size=4096):
    sock.settimeout(timeout)
    try:
        return sock.recv(size)
    except (socket.timeout, OSError):
        return b''


def _exchange(ip, port, payload, timeout, wait=2.0):
    """ connect, send payload, return first answer (or b'') """
    try:
        with _connect(ip, port, timeout) as sock:
            if payload:
                sock.sendall(payload)
            return _recv(sock, min(timeout, wait))
    except OSError:
        return b''


#  banner classification

def _set(res, service, product='', banner=b'', method='banner'):
    res['service'] = service
    if product:
        res['product'] = _printable(product, 120)
    if banner:
        res['banner'] = _printable(banner)
    res['method'] = method
    return True


def classify_banner(res, data, method='banner'):
    """ name the service from what it said first; returns True when recognised """
    port = res['port']
    text = data.decode('latin-1')
    first = text.split('\n', 1)[0].strip()
    low = text.lower()
    if text.startswith('SSH-'):
        return _set(res, 'ssh', first.split('-', 2)[-1], data, method)
    if re.match(r'^220[ -]', text):
        product = first[4:]
        if 'ftp' in low or port == 21:
            return _set(res, 'ftp', product, data, method)
        if 'smtp' in low or 'mail' in low or port in (25, 465, 587):
            return _set(res, 'smtp', product, data, method)
        return _set(res, port_name(port, 'tcp') or 'ftp/smtp', product, data, method)
    if text.startswith('+OK'):
        return _set(res, 'pop3', first[3:], data, method)
    if text.startswith('* OK') or text.startswith('* PREAUTH'):
        return _set(res, 'imap', first[4:], data, method)
    if text.startswith('RFB '):
        return _set(res, 'vnc', first, data, method)
    if text.startswith('@RSYNCD:'):
        return _set(res, 'rsync', first, data, method)
    if text.startswith('AMQP'):
        return _set(res, 'amqp', '', data, method)
    if len(data) > 2 and data[0] == 0xff and data[1] in (0xfb, 0xfc, 0xfd, 0xfe):
        return _set(res, 'telnet', '', b'', method)
    if len(data) > 6 and data[4] == 0x0a and data[3] == 0:
        version = data[5:].split(b'\0', 1)[0].decode('latin-1')
        if re.match(r'^\d+\.\d+', version):
            vendor = 'MariaDB' if 'mariadb' in version.lower() else 'MySQL'
            return _set(res, 'mysql', '%s %s' % (vendor, version), b'', method)
    if len(data) > 7 and data[4] == 0xff and (b'MySQL' in data or b'is not allowed to connect' in data):
        return _set(res, 'mysql', 'host not allowed', data[7:], method)
    if text.startswith('HTTP/'):
        return _classify_http(res, text, method)
    if text.startswith('-ERR') or text.startswith('-NOAUTH') or text.startswith('-DENIED') or text.startswith('+PONG'):
        return _set(res, 'redis', '', data, method)
    if text.startswith('VERSION '):
        return _set(res, 'memcached', first[8:], b'', method)
    if first and re.match(r'^[\x20-\x7e]{4,}$', first):
        # unknown but readable greeting: keep it, name by port
        res['banner'] = _printable(data)
        res['method'] = method
        if not res['service']:
            res['service'] = 'unknown'
        return True
    return False


def _classify_http(res, text, method):
    headers = {}
    for line in text.split('\r\n')[1:]:
        key, sep, value = line.partition(':')
        if sep:
            headers[key.strip().lower()] = value.strip()
    server = headers.get('server', '')
    service = 'https' if res['tls'] else 'http'
    probe = (server + ' ' + text[:600]).lower()
    for marker, name in (('pve-api-daemon', 'proxmox'), ('cpsrvd', 'cpanel'), ('miniserv', 'webmin'),
                         ('microsoft-httpapi', 'http (winrm/http.sys)'), ('docker/', 'docker-api'),
                         ('plesk', 'plesk'), ('directadmin', 'directadmin')):
        if marker in probe:
            service = name
            break
    status = text.split('\r\n', 1)[0].strip()
    product = server or status
    return _set(res, service, product, status.encode(), method)


#  active probes, each returns True when the service was identified

def _http_request(ip):
    host = '[%s]' % ip if ':' in ip else ip
    return ('HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: opnsense-hostguard\r\n'
            'Connection: close\r\n\r\n' % host).encode()


def _try_http(res, ip, port, timeout):
    data = _exchange(ip, port, _http_request(ip), timeout)
    if not data:
        return False
    text = data.decode('latin-1')
    if 'plain http request was sent to https' in text.lower():
        return False        # let the TLS probe handle it
    if text.startswith('HTTP/'):
        return _classify_http(res, text, 'http')
    if data[:1] == b'\x15' and data[1:2] == b'\x03':
        return False        # TLS alert, TLS probe follows
    return classify_banner(res, data, 'http')


def _cert_summary(der):
    """ best effort subject CN / first SANs from a DER certificate """
    if not der:
        return ''
    path = None
    try:
        with tempfile.NamedTemporaryFile('w', suffix='.pem', delete=False) as handle:
            handle.write(ssl.DER_cert_to_PEM_cert(der))
            path = handle.name
        info = ssl._ssl._test_decode_cert(path)
    except Exception:
        return ''
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass
    common_name = ''
    for rdn in info.get('subject', ()):
        for key, value in rdn:
            if key == 'commonName':
                common_name = value
    sans = [value for key, value in info.get('subjectAltName', ()) if key == 'DNS']
    parts = []
    if common_name:
        parts.append('CN=%s' % common_name)
    extra = [s for s in sans if s != common_name][:2]
    if extra:
        parts.append('SAN=%s' % ','.join(extra))
    if info.get('notAfter'):
        parts.append('expires %s' % info['notAfter'])
    return ' '.join(parts)


def _tls_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        ctx.set_ciphers('ALL:@SECLEVEL=0')
    except (ValueError, ssl.SSLError, AttributeError):
        pass
    try:
        ctx.set_alpn_protocols(['http/1.1'])
    except NotImplementedError:
        pass
    return ctx


def _try_tls(res, ip, port, timeout):
    try:
        raw = _connect(ip, port, timeout)
    except OSError:
        return False
    try:
        with _tls_context().wrap_socket(raw) as sock:
            res['tls'] = ' '.join(x for x in (sock.version() or 'TLS',
                                              _cert_summary(sock.getpeercert(binary_form=True))) if x)
            greeting = _recv(sock, min(timeout, 1.5))
            if greeting and classify_banner(res, greeting, 'tls'):
                res['service'] = TLS_SERVICE.get(res['service'], res['service'])
                return True
            sock.sendall(_http_request(ip))
            data = _recv(sock, min(timeout, 2.5))
            if data.startswith(b'HTTP/'):
                return _classify_http(res, data.decode('latin-1'), 'tls')
            if data and classify_banner(res, data, 'tls'):
                return True
            res['service'] = res['service'] if port in TLS_PORTS and res['service'] else 'tls'
            res['method'] = 'tls'
            return True
    except (ssl.SSLError, OSError):
        try:
            raw.close()
        except OSError:
            pass
        return False


def _try_redis(res, ip, port, timeout):
    data = _exchange(ip, port, b'PING\r\n', timeout)
    if data[:1] in (b'+', b'-') and (b'PONG' in data or b'NOAUTH' in data or b'DENIED' in data or b'ERR' in data):
        return _set(res, 'redis', '', data, 'redis')
    return False


def _try_memcached(res, ip, port, timeout):
    data = _exchange(ip, port, b'version\r\n', timeout)
    if data.startswith(b'VERSION '):
        return _set(res, 'memcached', data[8:].split(b'\r', 1)[0].decode('latin-1'), b'', 'memcached')
    return False


def _try_postgres(res, ip, port, timeout):
    data = _exchange(ip, port, struct.pack('!II', 8, 80877103), timeout)
    if data in (b'S', b'N'):
        return _set(res, 'postgresql', 'SSL %s' % ('supported' if data == b'S' else 'not offered'),
                    b'', 'postgres')
    return False


def _try_rdp(res, ip, port, timeout):
    request = bytes.fromhex('030000130ee000000000000100080003000000')
    data = _exchange(ip, port, request, timeout)
    if len(data) >= 11 and data[:2] == b'\x03\x00' and data[5] == 0xd0:
        return _set(res, 'rdp', 'X.224 confirm', b'', 'rdp')
    return False


def probe_tcp(ip, port, timeout=4.0):
    res = _result(ip, port, 'tcp')
    try:
        sock = _connect(ip, port, timeout)
    except ConnectionRefusedError:
        res['state'] = 'closed'
        return res
    except socket.timeout:
        res['state'] = 'filtered'
        return res
    except OSError as exc:
        res['state'] = 'unreachable'
        res['banner'] = _printable(str(exc))
        return res
    res['state'] = 'open'
    with sock:
        greeting = _recv(sock, min(timeout, 3.0))
    if greeting and classify_banner(res, greeting):
        return res

    probes = [_try_tls, _try_http] if port in TLS_PORTS else [_try_http, _try_tls]
    probes += [_try_redis, _try_postgres, _try_rdp, _try_memcached]
    for probe in probes:
        if probe(res, ip, port, timeout):
            return res
    if not res['service']:
        res['service'] = 'unknown'
    return res


#  udp

def _dns_version_query():
    name = b'\x07version\x04bind\x00'
    return b'\x4c\x55\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + name + b'\x00\x10\x00\x03'


def _dns_txt_answer(data, query_len):
    """ first TXT string from the answer section, if any """
    try:
        if struct.unpack('!H', data[6:8])[0] == 0:
            return ''
        pos = query_len
        if data[pos] & 0xc0 == 0xc0:
            pos += 2
        else:
            while data[pos]:
                pos += data[pos] + 1
            pos += 1
        rtype, _, _, rdlen = struct.unpack('!HHIH', data[pos:pos + 10])
        pos += 10
        if rtype != 16 or rdlen < 1:
            return ''
        return data[pos + 1:pos + 1 + data[pos]].decode('latin-1')
    except (IndexError, struct.error):
        return ''


def probe_udp(ip, port, timeout=4.0):
    res = _result(ip, port, 'udp')
    res['state'] = 'open|filtered'
    if port == 53:
        payload = _dns_version_query()
    elif port == 123:
        payload = b'\x1b' + b'\x00' * 47
    else:
        return res
    try:
        with _connect(ip, port, timeout, socket.SOCK_DGRAM) as sock:
            sock.send(payload)
            data = sock.recv(4096)
    except ConnectionRefusedError:
        res['state'] = 'closed'
        return res
    except OSError:
        return res
    if port == 53 and len(data) >= 12 and data[:2] == payload[:2]:
        res['state'] = 'open'
        version = _dns_txt_answer(data, len(payload))
        _set(res, 'dns', version or 'DNS server', b'', 'dns')
    elif port == 123 and len(data) >= 48:
        res['state'] = 'open'
        _set(res, 'ntp', 'stratum %d' % data[1], b'', 'ntp')
    return res


#  nmap

def probe_nmap(ip, port, proto, timeout=4.0):
    if not os.path.exists(NMAP):
        return None
    args = [NMAP, '-Pn', '-n', '-sV', '--version-light', '-oX', '-',
            '-p', '%s:%d' % ('U' if proto == 'udp' else 'T', port), ip]
    if proto == 'udp':
        args.insert(1, '-sU')
    if ':' in ip:
        args.insert(1, '-6')
    try:
        output = subprocess.run(args, capture_output=True, text=True,
                                timeout=max(30, timeout * 10)).stdout
        node = ET.fromstring(output).find('.//port')
    except (OSError, subprocess.SubprocessError, ET.ParseError):
        return None
    if node is None:
        return None
    res = _result(ip, port, proto)
    state = node.find('state')
    res['state'] = state.get('state', 'unknown') if state is not None else 'unknown'
    svc = node.find('service')
    if svc is not None:
        res['service'] = svc.get('name') or res['service']
        res['product'] = ' '.join(x for x in (svc.get('product'), svc.get('version'), svc.get('extrainfo')) if x)
        if svc.get('tunnel') == 'ssl':
            res['tls'] = 'ssl'
    res['method'] = 'nmap'
    return res


def probe(ip, port, proto='tcp', timeout=4.0, use_nmap=False):
    try:
        if use_nmap:
            res = probe_nmap(ip, port, proto, timeout)
            if res is not None and res['service']:
                return res
        if proto == 'tcp':
            return probe_tcp(ip, port, timeout)
        if proto == 'udp':
            return probe_udp(ip, port, timeout)
        res = _result(ip, port, proto)
        res['state'] = 'n/a'
        return res
    except Exception as exc:    # never let one odd service kill the prober
        res = _result(ip, port, proto)
        res['state'] = 'error'
        res['banner'] = _printable(str(exc))
        return res
