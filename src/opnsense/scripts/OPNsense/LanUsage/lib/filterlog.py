"""
    Copyright (c) 2026 Onur Berkay <onurberkay@sakla.app>
    All rights reserved. (BSD 2-Clause, see LICENSE)

    Incremental reader for blocked packets in the OPNsense firewall log.

    Blocked traffic never creates a pf state, so LAN to LAN attempts that the
    rules stop are only visible here (rules must log, the default deny rule
    does). Lines end with the filterlog CSV record:
        ...filterlog 1234 - [meta sequenceId="5"] 96,,,abc...,vtnet1,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,10.0.1.5,10.0.2.7,51234,22,0,S,...
    IPv4: [6]=action [8]=4 [16]=proto name [18]=src [19]=dst [20]=sport [21]=dport
    IPv6: [6]=action [8]=6 [12]=proto name [15]=src [16]=dst [17]=sport [18]=dport
"""
import os

LOG_FILE = '/var/log/filter/latest.log'
MAX_READ = 32 * 1024 * 1024


def parse_line(line):
    """ return (proto, src, dst, dport) for a blocked packet, else None """
    if 'filterlog' not in line:
        return None
    fields = line.rstrip().rsplit(' ', 1)[-1].split(',')
    try:
        if fields[6] != 'block':
            return None
        if fields[8] == '4':
            proto, src, dst, rest = fields[16].lower(), fields[18], fields[19], fields[20:]
        elif fields[8] == '6':
            proto, src, dst, rest = fields[12].lower(), fields[15], fields[16], fields[17:]
        else:
            return None
    except IndexError:
        return None
    port = 0
    if proto in ('tcp', 'udp') and len(rest) > 1 and rest[1].isdigit():
        port = int(rest[1])
    return proto, src, dst, port


class FilterLogReader:
    """ remembers its position, follows daily rotation (latest.log is a symlink) """

    def __init__(self, path=LOG_FILE):
        self.path = path
        self.inode = None
        self.offset = 0

    def read(self):
        try:
            stat = os.stat(self.path)
        except OSError:
            return []
        if self.inode is None:
            # first run: start at the end, history is not imported
            self.inode, self.offset = stat.st_ino, stat.st_size
            return []
        if stat.st_ino != self.inode or stat.st_size < self.offset:
            self.inode, self.offset = stat.st_ino, 0
        if stat.st_size == self.offset:
            return []
        start = max(self.offset, stat.st_size - MAX_READ)
        try:
            with open(self.path, 'rb') as handle:
                handle.seek(start)
                data = handle.read(stat.st_size - start)
        except OSError:
            return []
        end = data.rfind(b'\n')
        if end < 0:
            return []       # partial line, wait for the rest
        self.offset = start + end + 1
        result = []
        for raw in data[:end].split(b'\n'):
            record = parse_line(raw.decode('utf-8', 'replace'))
            if record:
                result.append(record)
        return result
