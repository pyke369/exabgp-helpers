#!/usr/bin/env python

from __future__ import print_function
import sys, os, re, time, select, syslog, signal
try:
   import simplejson as json
except ImportError:
   import json

if len(sys.argv) < 2:
    print('usage: %s [configuration]' % os.path.basename(sys.argv[0]), file=sys.stderr)
    sys.exit(1)
configuration_path = os.path.realpath(sys.argv[1])
try:
    configuration = json.load(open(configuration_path))
except:
    print('invalid configuration file "%s" - aborting' % configuration_path, file=sys.stderr)
    sys.exit(2)
syslog.openlog(re.sub(r'^(.+?)\..+$', r'\1', os.path.basename(sys.argv[0])), logoption=syslog.LOG_PID, facility=syslog.LOG_DAEMON)

debug = configuration.get('debug', 0)
def handle_debug(signum, frame):
    global debug
    debug = 1 - debug
    syslog.syslog('debug mode %s' % 'on' if debug else 'off')
signal.signal(signal.SIGUSR1, handle_debug)

exports = {}
for export in configuration.get('exports', []):
    exports[export.get('database', '')] = {}

last = time.time()
while True:
    try:
        ready, _, _ = select.select([sys.stdin], [], [], 10)
    except:
        continue
    if ready:
        line = sys.stdin.readline().strip()
        try:
            message = json.loads(line)
            if (message.get('type', '') == 'update'):
                neighbor    = message.get('neighbor', {})
                peer        = neighbor.get('ip', '')
                peer        = configuration.get('aliases', {}).get(peer, peer)
                prefixes    = []
                aspath      = ''
                communities = []
                atype       = ''

                for type, params in neighbor.get('message', {}).get('update', {}).items():
                    if type == 'announce':
                        atype = 'announce'
                        for family, announce in params.items():
                            if family == 'ipv4 unicast' or family == 'ipv6 unicast':
                                for target, networks in announce.items():
                                    prefixes = networks.keys()

                    elif type == 'withdraw':
                        atype = 'withdraw'
                        for family, withdraw in params.items():
                            if family == 'ipv4 unicast' or family == 'ipv6 unicast':
                                prefixes = withdraw.keys()

                    elif type == 'attribute':
                        aspath      = ' '.join(map(str, params.get('as-path', []))) + ' '
                        communities = ['%s:%s' % (x[0], x[1]) for x in params.get('community', [])]

                if atype == 'announce':
                    for path, export in exports.items():
                        for prefix in prefixes:
                            if export.get(prefix) == peer:
                                del export[prefix]
                                if debug:
                                    syslog.syslog('remove %s:%s from %s' % (prefix, peer, path))
                    matched = False
                    for export in configuration.get('exports', []):
                        filter = export.get('peer', [])
                        if len(filter) and not peer in filter:
                            continue

                        filter = export.get('community', [])
                        if len(filter) and len(set(filter) & set(communities)) == 0:
                            continue

                        filter = export.get('aspath', '')
                        if filter != '' and not re.match(filter, aspath):
                            continue

                        exports[export.get('database', '')].update(dict(zip(prefixes, [peer] * len(prefixes))))
                        matched= True
                        if debug:
                           syslog.syslog('add %s:%s to %s' % (json.dumps(prefixes), peer, export.get('database', '')))
                        break

                    if not matched and len(prefixes):
                        syslog.syslog('unmatched peer=[%s] aspath=[%s] communities=%s prefixes=[%d]' % (peer, aspath, str(communities), len(prefixes)))

                elif atype == 'withdraw':
                    for path, export in exports.items():
                        for prefix in prefixes:
                            if export.get(prefix) == peer:
                                del export[prefix]
                                if debug:
                                    syslog.syslog('withdraw %s:%s from %s' % (prefix, peer, path))

        except Exception, e:
            pass

    if time.time() - last >= configuration.get('interval', 600):
        last = time.time()
        for export, prefixes in exports.items():
            base = '%s/%s.db' % (configuration.get('basepath', '/tmp'), export)
            for backup in range(configuration.get('backups', 3), 0, -1):
                source = ('%s.%d' % (base, backup - 1)) if backup > 1 else base
                target = '%s.%d' % (base, backup)
                try:
                    os.rename(source, target)
                except:
                    pass

            try:
                os.umask(022)
                handle = open(base, 'w')
                handle.write("\n".join(sorted(prefixes.keys())) + "\n")
                handle.close()
                syslog.syslog('exported %s (%d prefixes)' % (export, len(prefixes)))
            except:
                pass
