"""
    Copyright (c) 2026 Onur Berkay <onurberkay@sakla.app>
    All rights reserved. (BSD 2-Clause, see LICENSE)

    How long a block condition keeps an address blocked (its ban type):

    fixed        every block lasts the condition's duration (0: until the condition is removed)
    escalating   the first block lasts the duration, every further block of the same address by the same
                 condition `factor` times the one before, up to `max_duration`; an address whose last block ended
                 `forget` seconds ago starts again at the first step

    and when it starts: `strikes` > 1 waits until the address matched in that many polls within `strike_window`
    seconds (a single sample is not enough), 1 blocks at the first match.
"""

BANS = ('fixed', 'escalating')
MAX_BAN = 366 * 86400           # also the cap of an escalating ban without one of its own
FACTORS = (2, 3, 4, 5, 10)
MAX_STRIKES = 100
MAX_WINDOW = 7 * 86400
DEFAULT_FORGET = 30 * 86400
# the columns a condition row carries for its ban, with the value of a condition created before 1.8
COLUMNS = (('ban', "TEXT DEFAULT 'fixed'"), ('factor', 'INTEGER DEFAULT 2'), ('max_duration', 'INTEGER DEFAULT 0'),
           ('strikes', 'INTEGER DEFAULT 1'), ('strike_window', 'INTEGER DEFAULT 0'),
           ('forget', 'INTEGER DEFAULT %d' % DEFAULT_FORGET))
FIELDS = tuple(name for name, _ in COLUMNS)


def seconds(cond, offense):
    """ how long the offense-th block (1: the first) of an address by this condition lasts; 0: until removed """
    base = cond['duration']
    if not base or cond.get('ban') != 'escalating' or offense <= 1:
        return base
    cap = cond.get('max_duration') or MAX_BAN
    # the exponent is capped: factor 2 reaches a year after 25 steps, an offense count of 10 000 must not
    # build a number with thousands of digits
    return max(base, min(base * cond.get('factor', 2) ** min(offense - 1, 64), cap))


def describe(cond):
    """ the ban as text, for the alert of a condition and the GUI """
    if not cond['duration']:
        text = 'until removed'
    elif cond.get('ban') == 'escalating':
        text = '%s, x%d each repeat up to %s (reset after %s quiet)' % (
            span_text(cond['duration']), cond.get('factor', 2), span_text(cond.get('max_duration') or MAX_BAN),
            span_text(cond.get('forget') or DEFAULT_FORGET))
    else:
        text = span_text(cond['duration'])
    if (cond.get('strikes') or 1) > 1:
        text += ', after %d matches within %s' % (cond['strikes'], span_text(cond.get('strike_window') or 0))
    return text


def span_text(value):
    value = int(value or 0)
    if value % 86400 == 0 and value:
        return '%d d' % (value // 86400)
    if value % 3600 == 0 and value:
        return '%d h' % (value // 3600)
    return '%d min' % max(1, round(value / 60.0))


def min_window(strikes, poll_interval):
    """ the shortest window in which `strikes` polls can fall (polls drift by a second or two) """
    return strikes * poll_interval


def check(ban, factor, max_duration, strikes, window, forget, duration, poll_interval=30):
    """ -> error text or '' for the ban settings of a condition (all whole numbers but ban) """
    if ban not in BANS:
        return 'invalid ban type'
    if not 0 <= duration <= MAX_BAN:
        return 'invalid duration'
    if ban == 'escalating':
        if not duration:
            return 'an escalating ban needs a duration for its first step'
        if factor not in FACTORS:
            return 'invalid factor'
        if max_duration and not duration <= max_duration <= MAX_BAN:
            return 'the longest block must be at least the first one and at most 366 days'
        if not 3600 <= forget <= MAX_BAN:
            return 'invalid reset time'
    if not 1 <= strikes <= MAX_STRIKES:
        return 'invalid number of matches'
    if strikes > 1 and not 60 <= window <= MAX_WINDOW:
        return 'invalid time window for the matches'
    if strikes > 1 and window < min_window(strikes, poll_interval):
        # matches are counted once per poll: fewer polls fit into the window, the condition never blocks
        return '%d matches need a window of at least %s (one match per poll, every %d s)' % (
            strikes, span_text(min_window(strikes, poll_interval)), poll_interval)
    return ''


def respan(con, cond, now):
    """
    The addresses a condition holds follow its changed duration / ban at once, counted from their last match
    (not those already due to leave: the collector released them, e.g. an address no longer blockable).
    cond: id, duration and the FIELDS
    """
    offenses = dict(con.execute('SELECT ip, count FROM offenses WHERE cond = ?', (cond['id'],)).fetchall())
    rows = con.execute('SELECT ip, added, last_match, expires FROM autoblocked WHERE cond = ?', (cond['id'],)).fetchall()
    updates = []
    for ip, added, last_match, expires in rows:
        span = seconds(cond, offenses.get(ip, 1))
        if 0 < expires <= now:
            # due to leave (pfctl may still have to take it out): it keeps leaving, but a match before that
            # renews it with the new span, not the old one
            updates.append((span, expires, ip, cond['id']))
        else:
            updates.append((span, (last_match or added) + span if span else 0, ip, cond['id']))
    con.executemany('UPDATE autoblocked SET span = ?, expires = ? WHERE ip = ? AND cond = ?', updates)
    # the reset time counts from the end of the block
    con.executemany('UPDATE offenses SET until = ? WHERE ip = ? AND cond = ?',
                    [(expires, ip, cid) for _, expires, ip, cid in updates if expires > now])


def _strike_count(con, now, ip, cond):
    """ (matches including this poll, start of the window) """
    row = con.execute('SELECT count, first_seen FROM strikes WHERE ip = ? AND cond = ?', (ip, cond['id'])).fetchone()
    return (row[0] + 1, row[1]) if row and now - row[1] <= cond['strike_window'] else (1, now)


def would_block(con, now, ip, cond):
    """ read only: does this poll's match make the address reach `strikes` (strike() then counts it) """
    return (cond.get('strikes') or 1) <= 1 or _strike_count(con, now, ip, cond)[0] >= cond['strikes']


def strike(con, now, ip, cond):
    """ one more poll in which the address matched the condition: True once that makes `strikes` """
    count, first = _strike_count(con, now, ip, cond)
    con.execute('INSERT OR REPLACE INTO strikes (ip, cond, count, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)',
                (ip, cond['id'], count, first, now))
    return count >= cond['strikes']


def offense(con, now, ip, cond):
    """ the how-manieth block of the address by this condition this is: 1 again after `forget` quiet seconds """
    row = con.execute('SELECT count, until FROM offenses WHERE ip = ? AND cond = ?', (ip, cond['id'])).fetchone()
    return row[0] + 1 if row and now - (row[1] or 0) <= (cond.get('forget') or DEFAULT_FORGET) else 1


def record(con, ip, cond, count, until):
    con.execute('INSERT OR REPLACE INTO offenses (ip, cond, count, until) VALUES (?, ?, ?, ?)',
                (ip, cond['id'], count, until))


def prune(con, now):
    """ strikes older than the longest window, offenses quiet for longer than their condition forgets """
    con.execute('DELETE FROM strikes WHERE last_seen < ? OR cond NOT IN (SELECT id FROM conditions)',
                (now - MAX_WINDOW,))
    con.execute('DELETE FROM offenses WHERE cond NOT IN (SELECT id FROM conditions) OR until < ? - COALESCE('
                '(SELECT forget FROM conditions c WHERE c.id = offenses.cond), %d)' % DEFAULT_FORGET, (now,))
