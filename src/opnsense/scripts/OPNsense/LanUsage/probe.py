#!/usr/local/bin/python3
"""
    Copyright (c) 2026 Onur Berkay <onurberkay@sakla.app>
    All rights reserved. (BSD 2-Clause, see LICENSE)

    On-demand service test, called by configd:
        probe.py <ip> <port> <tcp|udp>
    Only addresses inside the monitored LAN networks are tested.
    The result is stored in the services table and printed as JSON.
"""
import ipaddress
import json
import sys

from lib import common, detect


def main(argv):
    if len(argv) < 3:
        return {'status': 'error', 'message': 'usage: probe.py <ip> <port> <tcp|udp>'}
    try:
        ip = str(ipaddress.ip_address(argv[0]))
        port = int(argv[1])
    except ValueError:
        return {'status': 'error', 'message': 'invalid address or port'}
    proto = argv[2].lower()
    if not 0 < port < 65536 or proto not in ('tcp', 'udp'):
        return {'status': 'error', 'message': 'invalid port or protocol'}

    cfg = common.load_config()
    lan, _own = common.resolve_networks(cfg)
    if ip not in lan:
        return {'status': 'error', 'message': '%s is not inside the monitored networks (%s)' % (ip, lan)}

    res = detect.probe(ip, port, proto, cfg['probe_timeout'], cfg['use_nmap'])
    con = common.connect()
    with con:
        common.store_service(con, res)
    con.close()
    res['status'] = 'ok'
    return res


if __name__ == '__main__':
    print(json.dumps(main(sys.argv[1:])))
