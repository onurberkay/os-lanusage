#!/usr/local/bin/python3
"""
    Copyright (c) 2026 Onur Berkay <onurberkay@sakla.app>
    All rights reserved. (BSD 2-Clause, see LICENSE)

    Download the owner / network type lists into the local database (lib/ipdata.py):
        update_ipdata.py            only when the data is a day old, or once 3 hours after a build that
                                    missed a list (run by the collector)
        update_ipdata.py force      always (the "Update now" button)
    One run at a time; the outcome of the last try is kept in ipdata.status for the GUI.
"""
import fcntl
import json
import os
import sys
import time

from lib import common, ipdata


def main(argv):
    cfg = common.load_config()
    if not cfg['ipdata_enabled']:
        return {'status': 'disabled'}
    force = argv[:1] == ['force']
    if not force and not ipdata.due():
        return {'status': 'current', 'age': ipdata.age()}
    os.makedirs(os.path.dirname(ipdata.DATA_FILE), exist_ok=True)
    lock = open(ipdata.DATA_FILE + '.lock', 'w')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        lock.close()
        return {'status': 'running'}
    try:
        started = int(time.time())
        ipdata.write_last_try({'status': 'running', 'time': started})
        try:
            status = {'status': 'ok', 'time': started, 'sources': ipdata.build()}
        except Exception as exc:
            status = {'status': 'error', 'time': started, 'message': str(exc)[:300]}
        ipdata.write_last_try(status)
        return status
    finally:
        lock.close()


if __name__ == '__main__':
    print(json.dumps(main(sys.argv[1:])))
