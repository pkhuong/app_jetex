#!/usr/bin/env python3

import argparse
import atexit
import collections
import grp
import io
import os
import os.path
import pwd
import random
import re
import signal
import socket
import struct
import sys
import syslog
import time
import traceback


# LRU cache of (uid; socket option; bind options) -> cached socket object.
CACHE = collections.OrderedDict()
# Size limit on the LRU cache.
CACHE_LIMIT = 1000
# True if we should drop the cache.
RESET = False
# True if we received SIGTERM and should exit (gracefully).
TERMINATED = False
# Timeout (in seconds) for IO operations on client sockets.
TIME_LIMIT = 0.5
# Verbose logging (nop for now)
VERBOSE = False
# Log to stderr instead of syslog.
TO_STDERR = False
# Keepalive timeout (seconds)
KEEPALIVE = 120

try:
    # That's how the python3 guide says we should check for
    # identifiers.
    socket.SO_REUSEPORT
    HAS_REUSEPORT = True
except (AttributeError, NameError):
    HAS_REUSEPORT = False

try:
    DEFAULT_FLAGS = socket.AI_V4MAPPED | socket.AI_ADDRCONFIG
except (AttributeError, NameError):
    DEFAULT_FLAGS = 0

try:
    DEFAULT_FLAGS = socket.AI_V4MAPPED_CFG | socket.AI_ADDRCONFIG
except (AttributeError, NameError):
    pass

try:
    DEFAULT_FLAGS = socket.AI_DEFAULT
except (AttributeError, NameError):
    pass


CachedSocket = collections.namedtuple('CachedSocket', 'socket, last_touched')


def log(priority, string):
    """Log string with priority level to syslog (or stderr if TO_STDERR)."""
    if TO_STDERR:
        sys.stderr.write(string + '\n')
    else:
        syslog.syslog(priority, string)


def evict_old_sockets():
    to_evict = []
    now = time.time()
    for key, cached in CACHE.items():
        if cached.last_touched < now - KEEPALIVE:
            to_evict.append(key)
        else:
            break
    if len(to_evict) == 0:
        return
    log(syslog.LOG_INFO,
        "Evicting %i old sockets (%s)." % (len(to_evict), to_evict))
    for key in to_evict:
        cached = CACHE[key]
        del CACHE[key]
        cached.socket.close()


def cached_bind(key):
    """Find/insert the socket object associated with key in the LRU cache."""
    cached = CACHE.get(key)
    if cached is not None:
        cached.last_touched = time.time()
        CACHE.move_to_end(key)
        return cached.socket, True

    if len(CACHE) >= CACHE_LIMIT:
        key, old = CACHE.popitem(last=False)
        log(syslog.LOG_WARNING,
            "Socket cache reached size limit %i. Evicting one entry (%s)." %
            (CACHE_LIMIT, key))
        old.close()

    uid, af, socktype, proto, canonname, sa = key
    s = None
    try:
        s = socket.socket(af, socktype, proto)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if HAS_REUSEPORT:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        else:
            # if we do not have SO_REUSEPORT, uid is meaningless.
            assert(uid == '')
        s.bind(sa)
        s.listen(128)
    except OSError:
        if s is not None:
            s.close()
        return None, False
    except:
        if s is not None:
            s.close()
        raise

    CACHE[key] = CachedSocket(s, time.time())
    return s, False


def extract_host_port(string):
    # Try to match an ipv6 without port
    match = re.match(r'^[[](.*)]$', string)
    if match is not None:
        return match.group(1), None
    # ipv6 with port/proto?
    match = re.match(r'^[[](.*)]:([^][:]*)$', string)
    if match is not None:
        return match.groups()
    # anything:port/proto
    match = re.match(r'^(.*):([^:]*)$', string)
    if match is not None:
        return match.groups()
    return string, None


def getinfo(req):
    """Parse a request string and return a list of "key" tuples.

    The request string is
    
    uid host:port [family [sock_type [proto [flags [limit]]]]],
    
    where fields are separated by exactly one space (i.e., consecutive
    spaces denote a field with the empty string value).

    The uid is an arbitrary string identifier for SO_REUSEPORT
    purposes.  It should usually be a core/socket identifier.  If the
    OS does not support SO_REUSEPORT, uid is ignored.

    host/port/family/sock_type/proto/flags correspond to the arguments
    for getaddrinfo(3).  host *or* port may be the empty string to
    pass NULL (wildcard) to getaddrinfo.  Flags defaults to the
    system-wide defaults (that try to make sense of hybrid IPv4/v6);
    everything else defaults to 0 (unspecified).

    The limit truncates the results if necessary.  If it is negative,
    the results should be shuffled randomly before returning the first
    "limit" entries.  If limit is positive, return the first "limit"
    entries found by getaddrinfo, without shuffling.
    """
    req = req.split(' ')
    uid = req[0] if HAS_REUSEPORT else ''
    host, port = extract_host_port(req[1])
    if host == '' or host == '*':
        host = None
    if port == '' or port == '*':
        port = None
    family = int(req[2]) if len(req) > 2 else socket.AF_UNSPEC
    sock_type = int(req[3]) if len(req) > 3 else 0
    proto = int(req[4]) if len(req) > 4 else 0
    flags = int(req[5]) if len(req) > 5 else 0
    flags |= socket.AI_CANONNAME # Let's be more descriptive for logs.
    flags |= socket.AI_PASSIVE # next step is bind/connect, so always passive.
    limit = int(req[6]) if len(req) > 6 else None

    results = socket.getaddrinfo(host, port, family, sock_type, proto, flags)
    if limit is not None and limit < 0:
        random.shuffle(results)
        limit = -limit
    if limit is not None and len(results) > limit:
        results = results[0:limit]
    return [(uid,) + res for res in results]


def handle(client):
    """Handle one client interaction before letting the caller close the socket.

    The client's request should be short (< 100 bytes), so the write
    should be atomic unless the system is under extreme memory
    pressure.

    Decode the request, get connection tuples from getaddrinfo, and
    bind a socket for each such tuple.  When possible, grab the socket
    from the cache instead of binding a new one.
    """
    req = client.recv(8192)
    if len(req) == 0:
        return

    try:
        keys = getinfo(req.decode(encoding='UTF-8'))
    except:
        client.sendmsg([b'getaddrinfo failed!'])
        raise

    for key in keys:
        sock, cached = cached_bind(key)
        if sock is not None:
            try:
                client.sendmsg([b'.'],
                               [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                 struct.pack('i', sock.fileno()))])
            except:
                if not cached:
                    del CACHE[key]
                    sock.close()
                raise
    client.sendmsg([b'!'])


def clear():
    """Clear the LRU cache."""
    for _, sock in CACHE:
        sock.close()
    CACHE.clear()


def work(sock):
    """Serve up to one client.

    If we received a SIGHUP, clear the cache (and the corresponding
    flag).

    Accept one client, process one request on that UNIX socket, and
    always close the socket.
    """
    global RESET
    if RESET:
        clear()
        RESET = False

    conn = None
    try:
        try:
            conn, _ = sock.accept()
        except socket.timeout:
            return
        if conn is None:
            return
        try:
            conn.settimeout(TIME_LIMIT)
            handle(conn)
        except socket.timeout:
            pass # nothing to do except cleanup.
    finally:
        if conn is not None:
            conn.close()


def handle_sig(signum, frame):
    """Generic async signal handler: set a flag and return."""
    global TERMINATED, RESET
    if signum == signal.SIGTERM:
        TERMINATED = True
    elif signum == signal.SIGHUP:
        RESET = True


def bind(path, mask):
    """Bind a stream UNIX socket to path and set it up for
    semi-synchronous accept.

    If mask is not none, temporarily set it as the umask when opening
    the socket.
    """
    old_mask = None
    try:
        if mask is not None:
            old_mask = os.umask(mask)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        except:
            return None
        sock.bind(path)
    finally:
        if old_mask is not None:
            os.umask(old_mask)

    sock.listen(128)
    sock.settimeout(1.0)
    return sock


def parse_id_string(id_string):
    match = re.match(r'^(.*):(.*)$', id_string)
    if match is None:
        return None, None
    user = match.group(1)
    group = match.group(2)
    return pwd.getpwnam(user).pw_uid, grp.getgrnam(group).gr_gid


def drop_privilege(id_string):
    os.umask(0o077)
    if id_string is None or os.getuid() != 0:
        return
    uid, gid = parse_id_string(id_string)
    if uid is None:
        return
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)


def main():
    global CACHE_LIMIT, KEEPALIVE, TERMINATED, TO_STDERR, VERBOSE
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description="""\
LRU cache for sockets.
 
Users should connect to path a SOCK_STREAM UNIX socket, and
sendmsg a query string

    "uid host:port [family [sock_type [proto [flags [limit]]]]]."

The server will respond with a series of messages with value "."
and exactly one socket as ancillary data.  The last sendmsg will have
message ".!".""")
    parser.add_argument('path', help='The path for the UNIX domain server.')
    parser.add_argument('-c', '--cache-capacity', dest='capacity',
                        type=int, default=CACHE_LIMIT,
                        help='Maximum size for the LRU cache.')
    parser.add_argument('-k', '--keepalive', dest='keepalive',
                        type=float, default=KEEPALIVE,
                        help='Keepalive period for file descriptors (sec)')
    parser.add_argument('-d', '--drop', dest='drop', default=None,
                        help='Set the user:group to drop to.')
    parser.add_argument('-e', dest='debug', action='store_true',
                        help='Log to stderr.')
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                        help='Enable verbose logging.')
    parser.add_argument('-w', '--world', dest='world', action='store_true',
                        help='Set umask to 0 before opening the socket.')
    parser.add_argument('-g', '--group', dest='group', action='store_true',
                        help='Set umask to 0007 before opening the socket.')
    parser.add_argument('-u', '--user', dest='user', action='store_true',
                        help='Set umask to 0077 before opening the socket.')
    args = parser.parse_args()

    if args.capacity > 0:
        CACHE_LIMIT = args.capacity
    VERBOSE = args.verbose
    TO_STDERR = args.debug
    if args.keepalive > 0:
        KEEPALIVE = args.keepalive
    if args.drop is not None:
        if parse_id_string(args.drop)[0] is None:
            parser.error('Invalid user:group string %s' % args.drop)
        if os.getuid() != 0:
            parser.error('Unable to drop privilege: user is not root.')

    if args.user:
        sock = bind(args.path, 0o0777)
    elif args.group:
        sock = bind(args.path, 0o007)
    elif args.world:
        sock = bind(args.path, 0)
    else:
        sock = bind(args.path, None)

    if sock is None:
        sys.stderr.write('Unable to bind to %s.\n' % args.path)
        sys.exit(1)

    if not args.drop:
        atexit.register(os.unlink, args.path)
    if not TO_STDERR:
        syslog.openlog(logoption=syslog.LOG_PID | syslog.LOG_NDELAY,
                       facility=syslog.LOG_DAEMON)

    log(syslog.LOG_INFO, "Binding socket server to %s." % args.path)
    signal.signal(signal.SIGTERM, handle_sig)
    signal.signal(signal.SIGHUP, handle_sig)

    drop_privilege(args.drop)
    failures = 0
    while not TERMINATED:
        try:
            sys.stderr.flush()
            sys.stdout.flush()
            evict_old_sockets()
            work(sock)
            failures = 0
        except KeyboardInterrupt:
            TERMINATED = True
        except:
            out = io.StringIO()
            failures += 1
            if failures == 1:
                out.write('Handled error\n')
            else:
                out.write('Handled %i consecutive errors\n' % failures)
            traceback.print_exception(*sys.exc_info(), file=out)
            log(syslog.LOG_CRIT, out.getvalue())
            out.close()
            if failures > 2:
                time.sleep(0.5)

    log(syslog.LOG_INFO, "Shutting down socket server on %s." % args.path)
    sys.exit(0)


if __name__ == '__main__':
    main()
