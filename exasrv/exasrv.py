#!/usr/bin/env python

# mandatory imports
from __future__ import print_function
import sys, os, re, subprocess, time, select, fcntl, hashlib, syslog
try:
   import simplejson as json
except ImportError:
   import json

version = '1.4.3'

# log message to both syslog and stderr
syslog.openlog(re.sub(r'^(.+?)\..+$', r'\1', os.path.basename(sys.argv[0])), logoption=syslog.LOG_PID, facility=syslog.LOG_DAEMON)
def log(message):
    syslog.syslog(message)
    print(message, file=sys.stderr)

# log fatal message and exit
def abort(message):
    log('[fatal] %s' % message)
    time.sleep(1)
    sys.exit(1)

# load configuration
if len(sys.argv) < 3:
    abort('usage: %s CONFIGURATION ACTION [ARGUMENTS]' % os.path.basename(sys.argv[0]))
self_path = os.path.realpath(sys.argv[0])
conf_path = os.path.realpath(sys.argv[1])
conf_last = 0
conf_hash = ''
conf      = {}

def load_configuration():
    global conf_path, conf_last, conf_hash, conf

    now = time.time()
    if now - conf_last >= 10:
        conf_last = now
        try:
            handle  = open(conf_path, 'r')
            content = handle.read(65536)
            handle.close()
            content = re.sub(r'^\s*(#|//).+?$', '', content, flags = re.M)
            content = re.sub(r'/\*[^\*]*\*/', '', content)
            while True:
               matcher = re.match(r'(?P<before>^.*?)\{\{<\s*(?P<include>[^\}\s]+?)\s*\}\}(?P<after>.*)$', content, flags = re.S)
               if not matcher:
                   break
               include = ''
               try:
                   handle  = open(matcher.group('include'), 'r')
                   include = handle.read(65536)
                   handle.close()
               except:
                   pass
               content = matcher.group('before') + include + matcher.group('after')
            content = re.sub(r',(\s*[\}\]])', r'\1', content)
            hash = hashlib.md5(content).hexdigest()
            if hash != conf_hash:
                log('[conf] %sloaded configuration file' % ('re' if conf_hash != '' else ''))
                conf_hash = hash
                conf      = json.loads(content)
                return True
        except Exception as e:
            log('[conf] invalid configuration file "%s" / %s' % (conf_path, e))
    return False

# match address inet family
def inet4(address):
    return re.match(r'^[0-9.]+(/[0-9]+)?$', address)
def inet6(address):
    return re.match(r'^[0-9a-f:]+(/[0-9]+)?$', address)

# add local address
def add_address(address, interface):
    matcher = re.match(r'(?P<address>\d[\da-f.:]+)/(?P<netmask>\d+)', address)
    if not matcher:
        return
    address    = matcher.group('address')
    netmask    = matcher.group('netmask')
    rinterface = re.sub(r'^(vlan\d+)@.+$', r'\1', interface)
    try:
       for line in subprocess.check_output(str('ip addr show %s' % rinterface).split(), shell=False).split('\n'):
           matcher = re.match(r'^\s*inet6?\s+(?P<address>\d[\da-f.:]+)/(?P<netmask>\d+)\s+', line)
           if matcher:
               if (matcher.group('address') + '/' + matcher.group('netmask')) == (address + '/' + netmask):
                   return
               if (matcher.group('address') == address):
                   subprocess.call(str('ip addr delete %s dev %s' % (address, rinterface)).split())
                   log('[ip] removed address %s/%s from interface %s' % (address, matcher.group('netmask'), rinterface))
    except:
        pass
    matcher = re.match(r'^(?P<interface>[^\.]+?)\.(?P<vlan>\d+)$', interface)
    if matcher:
        subprocess.call(str('ip link add link %s name %s type vlan id %s' % (matcher.group('interface'), interface, matcher.group('vlan'))).split())
    matcher = re.match(r'^vlan(?P<vlan>\d+)@(?P<interface>.+)$', interface)
    if matcher:
        subprocess.call(str('ip link add link %s name vlan%s type vlan id %s' % (matcher.group('interface'), matcher.group('vlan'), matcher.group('vlan'))).split())
    subprocess.call(str('ip link set %s up' % rinterface).split())
    if inet6(address):
        subprocess.call(str('ip -6 addr add %s/%s dev %s' % (address, netmask, rinterface)).split())
    else:
        subprocess.call(str('ip addr add %s/%s broadcast + dev %s' % (address, netmask, rinterface)).split())
    log('[ip] added address %s/%s to interface %s' % (address, netmask, rinterface))

# remove local address
def remove_address(address, interface):
    for line in subprocess.check_output(str('ip addr show %s' % interface).split(), shell=False).split('\n'):
        matcher = re.match(r'^\s*inet6?\s+(?P<address>\d[\da-f.:]+/\d+)\s+', line)
        if matcher:
            if (matcher.group('address') == address):
                subprocess.call(str('ip addr delete %s dev %s' % (address, interface)).split())
                log('[ip] removed address %s from interface %s' % (address, interface))

# set local route
def set_route(prefix, nexthop, options = {}, remove = False):
    rtable = {}
    rkey   = None
    for inet in [4, 6]:
        for line in subprocess.check_output(('ip -%d route list scope global' % inet).split(), shell=False).split('\n'):
            matcher = re.match(r'^(?P<prefix>\S+)(?:\s+via\s+(?P<gateway>\S+))?(?:\s*(?P<options>.+?)\s*)?$', line)
            if matcher:
                if matcher.group('prefix') != 'default':
                   lprefix = matcher.group('prefix')
                elif inet == 6:
                   lprefix = '::/0'
                else:
                   lprefix = '0.0.0.0/0'
                lgateway = matcher.group('gateway')
                loptions = matcher.group('options').split()
                loptions = dict(zip(loptions[::2], loptions[1::2]))
                loptions.pop('dev', None)
                rkey = lprefix + '-' + str(loptions.get('metric', '0'))
                if not rtable.get(rkey, None):
                    rtable[rkey] = {'options': loptions, 'nexthops': {}}
                if lgateway:
                    rtable[rkey]['nexthops'][lgateway] = 1
                    rkey = None
            else:
                matcher = re.match(r'^\s*nexthop\s+via\s+(?P<gateway>\S+)(?:\s+(?P<options>.+?)\s*)?$', line)
                if matcher and rkey:
                    lgateway = matcher.group('gateway')
                    loptions = matcher.group('options').split()
                    loptions = dict(zip(loptions[::2], loptions[1::2]))
                    loptions.pop('dev', None)
                    rtable[rkey]['nexthops'][lgateway] = int(loptions.get('weight', 1))

    defaultmetric = '1024' if inet6(prefix) else '0'
    rkey   = prefix + '-' + (str(options.get('metric', defaultmetric)) if options else defaultmetric)
    info   = rtable.get(rkey, None)
    weight = int(options.get('weight', 1))
    if info:
        options.update(info['options'])
    options.pop('weight', None)
    options = ' '.join(str(k) + ' ' + str(v) for k, v in options.items())
    if remove:
        if not info:
            return
        if not info['nexthops'].get(nexthop, None):
            return
        if len(info['nexthops']) <= 1:
            command = 'ip route delete %s proto 57 %s' % (prefix, options)
        else:
            command = 'ip route replace %s proto 57 %s' % (prefix, options)
            for lnexthop, weight in info['nexthops'].items():
                if lnexthop != nexthop:
                    command += ' nexthop via %s weight %d' % (lnexthop, weight)
        subprocess.call(command.split())
        log("[ip] removed nexthop %s from %s %s" % (nexthop, prefix, options))
    else:
        if info and info['nexthops'].get(nexthop, None) and info['nexthops'].get(nexthop) == weight:
            return
        command = 'ip route replace %s proto 57 %s nexthop via %s weight %d' % (prefix, options, nexthop, weight)
        if info:
            for lnexthop, weight in info['nexthops'].items():
                if lnexthop != nexthop:
                    command += ' nexthop via %s weight %d' % (lnexthop, weight)
        subprocess.call(command.split())
        log("[ip] added nexthop %s to %s %s" % (nexthop, prefix, options))

# remove all local routes under exasrv control
def cleanup_exit():
    for inet in [4, 6]:
        for line in subprocess.check_output(('ip -%d route list scope global' % inet).split(), shell=False).split('\n'):
            if line.find('proto 57') >= 0 or line.find('proto exa') >= 0:
                command = 'ip -%d route delete %s' % (inet, line)
                subprocess.call(command.split())
    log('[local] exit version %s peer %s' % (version, sys.argv[3]))
    os._exit(0)

# generate ExaBGP configuration
if sys.argv[2] == 'configure':
    version = 3
    for line in subprocess.check_output('exabgp --version'.split(), shell=False).split('\n'):
        matcher = re.match(r'^ExaBGP\s+:\s+(?P<version>\d+)', line, re.IGNORECASE)
        if matcher:
            version = int(matcher.group('version'))
            break
    load_configuration()
    content   = ''
    supervise = 1
    for group in conf:
        for name, peer in group.get('peers', {}).items():
            local    = peer.get('local', {})
            remote   = peer.get('remote', {})
            if version >= 4:
                content += (
                            'process supervise%d {\n'
                            '  encoder json;\n'
                            '  run %s %s supervise %s;\n'
                            '}\n'
                            'neighbor %s {\n'
                            '  router-id %s;\n'
                            '  local-address %s;\n'
                            '  local-as %s;\n'
                            '  peer-as %s;\n'
                            '  family {\n'
                            '    ipv4 unicast;\n'
                            '    ipv6 unicast;\n'
                            '  }\n'
                            '  api {\n'
                            '    processes [ supervise%d ];\n'
                            '    neighbor-changes;\n'
                            '    receive {\n'
                            '      parsed;\n'
                            '      update;\n'
                            '    }\n'
                            '  }\n'
                            '}\n') % (
                                supervise,
                                self_path,
                                conf_path,
                                name,
                                name,
                                re.sub(r'^(.+?)(/\d+)$', r'\1',
                                str(local.get('address', '0.0.0.0'))),
                                re.sub(r'^(.+?)(/\d+)$', r'\1', str(local.get('address', '0.0.0.0'))),
                                str(local.get('asnum', '0')),
                                str(remote.get('asnum', '0')),
                                supervise,
                            )
            else:
                content += ('neighbor %s {\n'
                            '  router-id %s;\n'
                            '  local-address %s;\n'
                            '  local-as %s;\n'
                            '  peer-as %s;\n'
                            '  family {\n'
                            '    ipv4 unicast;\n'
                            '    ipv6 unicast;\n'
                            '  }\n'
                            '  process supervise%d {\n'
                            '    encoder json;\n'
                            '    peer-updates;\n'
                            '    neighbor-changes;\n'
                            '    receive-routes;\n'
                            '    run %s %s supervise %s;\n'
                            '  }\n'
                            '}\n') % (
                                name,
                                re.sub(r'^(.+?)(/\d+)$', r'\1',
                                str(local.get('address', '0.0.0.0'))),
                                re.sub(r'^(.+?)(/\d+)$', r'\1', str(local.get('address', '0.0.0.0'))),
                                str(local.get('asnum', '0')),
                                str(remote.get('asnum', '0')),
                                supervise,
                                self_path,
                                conf_path,
                                name
                            )
            supervise += 1
    if len(sys.argv) > 3:
        mcontent = ''
        try:
            mcontent = open(sys.argv[3], 'r').read(65536)
        except:
            pass
        if content != mcontent:
            log('[conf] wrote ExaBGP configuration in %s (%d bytes)' % (sys.argv[3], len(content)))
            open(sys.argv[3], 'w').write(content)
    else:
        print(content, end='')
        log('[conf] wrote ExaBGP configuration to standard output (%d bytes)' % len(content))

# supervise application, announce service addresses and add/remove routes based on peers announces
elif sys.argv[2] == 'supervise':
    if len(sys.argv) <= 3:
        abort('missing peer argument for supervise action - aborting')

    sys.exitfunc = cleanup_exit
    log('[local] start version %s peer %s' % (version, sys.argv[3]))
    name             = sys.argv[3]
    peer             = service = None
    interface_status = 'up'
    routes_last      = ip_last = service_last = service_checks = 0
    service_groups   = {}
    service_interval = 0
    routes           = {'announce':{}, 'withdraw':{}}
    addresses        = {'announce':{}, 'withdraw':{}}
    fcntl.fcntl(sys.stdin.fileno(), fcntl.F_SETFL, fcntl.fcntl(sys.stdin.fileno(), fcntl.F_GETFL) | os.O_NONBLOCK)
    while True:

        # reload configuration
        if load_configuration():
            for group in conf:
                peer = group.get('peers', {}).get(name, None)
                if peer:
                    break
            if not peer:
                abort('peer "%s" not found in configuration - aborting' % name)
            service          = group.get('service', {})
            check            = service.get('check', {})
            check_command    = str(check.get('command', ''))
            check_interval   = max(1, min(20, int(check.get('interval', 5))))
            check_finterval  = max(1, min(5,  int(check.get('finterval', 1))))
            check_timeout    = max(1, min(10, int(check.get('timeout', 2))))
            check_rise       = max(1, min(5, int(check.get('rise', 3))))
            check_fall       = max(1, min(5, int(check.get('fall', 3))))
            actions          = service.get('actions', {})
            action_up        = str(actions.get('up', ''))
            action_down      = str(actions.get('down', ''))
            addresses['announce'] = {}
            for address, options in service.get('addresses', {}).items():
                mask = '/128' if inet6(address) else '/32'
                addresses['announce'][address + ('' if re.search(r'/[0-9]+$', address) else mask)] = options
            addresses['withdraw'].update(addresses['announce'])

        # receive and interpret BGP announces/withdraws from BGP peers
        ready, _, _ = select.select([sys.stdin], [], [], 1)
        if ready:
            while True:
                try:
                    line = sys.stdin.readline().strip()
                    message  = json.loads(line)
                    neighbor = message.get('neighbor', {})
                    type     = str(message.get('type', ''))
                    if str(neighbor.get('address', {}).get('peer', '')) == name:
                        if type == 'state':
                            log('[bgp] peer %s is %s' % (name, str(neighbor.get('state', 'up'))))
                            if str(neighbor.get('state', 'up')) == 'down':
                                routes_last = 0
                                for route in routes['announce']:
                                    routes['withdraw'][route] = routes['announce'][route]
                                routes['announce'].clear()
                            else:
                                statics = {}
                                for route, options in group.get('routes', {}).items():
                                    if options.get('static', False):
                                        statics[route] = options
                                for route, options in peer.get('routes', {}).items():
                                    if options.get('static', False):
                                        statics[route] = options
                                for route in statics.keys():
                                    key = '%s-0' % route
                                    routes['announce'][key] = [name, 0]
                                    routes['withdraw'].pop(key, None)

                        elif type == 'update':
                            routes_last   = 0
                            metric        = 0
                            defaultmetric = 0
                            actions       = []
                            for key1, value1 in neighbor.get('message', {}).get('update', {}).items():
                                if key1 in ['announce', 'withdraw']:
                                    for key2, value2 in value1.items():
                                        if key2 == 'ipv6 unicast':
                                            defaultmetric = 1024
                                        if key2 in ['ipv4 unicast', 'ipv6 unicast']:
                                            for key3, value3 in value2.items():
                                                if key3 != 'null':
                                                    if key1 == 'announce':
                                                        for value4 in value3:
                                                            if isinstance(value4, dict):
                                                                value4 = value4.get('nlri', '')
                                                            actions.append([key1, value4, key3])
                                                    else:
                                                        actions.append([key1, key3, name])
                                elif key1 == 'attribute':
                                    for key2, value2 in value1.items():
                                        if key2 == 'med':
                                            metric = value2
                            for action in actions:
                                if action[0] == 'announce':
                                    if metric == 0:
                                        metric = defaultmetric
                                    key = '%s-%d' % (action[1], metric)
                                    routes['announce'][key] = [action[2], metric]
                                    routes['withdraw'].pop(key, None)
                                else:
                                    for route in routes['announce']:
                                        if action[1] == re.sub(r'^(.+?)-\d+$', r'\1', route):
                                            metric = int(re.sub(r'^.+?-(\d+)$', r'\1', route))
                                            if metric == 0:
                                                metric = defaultmetric
                                            key    = '%s-%d' % (action[1], metric)
                                            routes['withdraw'][key] = [action[2], metric]
                                            routes['announce'].pop(key, None)
                                            break
                                log('[bgp] %s %s metric %d via %s learned from peer %s' % (action[0], action[1], metric, action[2], name))

                    elif type == 'notification' and str(message.get('notification', '')) == 'shutdown':
                        routes_last = 0
                        for route in routes['announce']:
                            routes['withdraw'][route] = routes['announce'][route]
                        routes['announce'].clear()
                        log('[local] shutdown')
                        cleanup_exit()

                except:
                    break

        # check physical network interface status
        content = ''
        try:
            handle  = open('/sys/class/net/%s/operstate' % str(peer.get('local', {}).get('interface', '')), 'r')
            content = handle.read(256)
            handle.close()
        except:
            pass
        status = 'down' if content.find('down') >= 0 else 'up'
        if interface_status != status:
            log('[local] peer physical network interface is %s' % status)
            interface_status = status

        # push learned routes to local routing
        now = time.time()
        if now - routes_last >= 3:
            routes_last = now
            for action in ['announce', 'withdraw']:
                for route in routes[action]:
                    prefix  = re.sub(r'^(.+?)-\d+$', r'\1', route)
                    options = {'metric': routes[action][route][1]}
                    options.update(group.get('routes', {}).get(prefix, {}))
                    options.update(peer.get('routes', {}).get(prefix, {}))
                    if (bool(options.get('ignore', False))):
                        continue
                    options.pop('ignore', None)
                    cascade = options.get('cascade', [])
                    options.pop('cascade', None)
                    options.pop('static', None)
                    set_route(prefix, routes[action][route][0], options, action == 'withdraw' or interface_status == 'down')
                    for prefix in cascade:
                        set_route(prefix, routes[action][route][0], options, action == 'withdraw' or interface_status == 'down')

        # ensure needed local addresses are properly configured
        if now - ip_last >= 3:
            ip_last = now
            address = peer.get('local', {}).get('address', None)
            if address:
                if peer.get('local', {}).get('auto', True):
                    add_address(address, str(peer.get('local', {}).get('interface', 'lo')))
            if service:
                for address, options in addresses['announce'].items():
                    if (inet4(address) and address.endswith('/32')) or (inet6(address) and address.endswith('/128')):
                        if options.get('alwaysup', False):
                            add_address(address, options.get('interface', 'lo'))
                        else:
                            sgroup = options.get('group', 'default')
                            if sgroup in service_groups and service_groups[sgroup] != 0:
                                add_address(address, options.get('interface', 'lo'))
                            elif options.get('autoremove', False):
                                remove_address(address, options.get('interface', 'lo'))

        # announce addresses based on service healthcheck
        if service_interval == 0:
            service_interval = check_finterval
        if service and now - service_last >= service_interval:
            service_last = now

            # probe service groups using the provided command
            check_groups = ['default']
            if check_command != '':
                check_groups = ''
                try:
                    with open(os.devnull, 'w') as void:
                        command = subprocess.Popen(check_command.split(), stdout = subprocess.PIPE, stderr = void, close_fds = True)
                    now = time.time()
                    while time.time() - now < check_timeout:
                        status = command.poll()
                        if status != None:
                            if status == 57:
                                check_groups = [sgroup for sgroup in command.stdout.read().strip().replace(' ', '').split(',') if sgroup != '']
                            else:
                                check_groups = ['default'] if status == 0 else []
                                if status != 0:
                                    log('[service] probe [%s] exited with status %d' % (check_command, status))
                            break
                        time.sleep(0.1)
                    else:
                        os.kill(command.pid, 9)
                        log('[service] probe [%s] was killed after %d second(s)' % (check_command, check_timeout))
                except Exception as e:
                    pass

            # run state-machine to determine service groups statuses
            for sgroup in check_groups:
                if sgroup not in service_groups:
                    service_groups[sgroup] = 0
                if service_groups[sgroup] < check_rise:
                    service_groups[sgroup] += 1
                    log('[service] service group %s is rising (%d successful check%s sofar)' % (sgroup, service_groups[sgroup], 's' if service_groups[sgroup] > 1 else ''))
                    if service_groups[sgroup] >= check_rise:
                       log('[service] service group %s is up' % sgroup)
                       if action_up != '':
                           log('[service] running command [%s %s]' % (action_up, sgroup))
                           try:
                               subprocess.call((action_up + ' ' + sgroup).split())
                           except:
                               pass
            for sgroup in service_groups:
                if sgroup not in check_groups:
                    if service_groups[sgroup] > 0:
                        service_groups[sgroup] -= 1
                        log('[service] service group %s is falling (%d unsuccessful check%s sofar)' % (sgroup, check_rise - service_groups[sgroup], 's' if check_rise - service_groups[sgroup] > 1 else ''))
                        if service_groups[sgroup] <= check_rise - check_fall or service_groups[sgroup] == 0:
                            service_groups[sgroup] = 0
                            log('[service] service group %s is down' % sgroup)
                            if action_down != '':
                                log('[service] running command [%s %s]' % (action_down, sgroup))
                                try:
                                    subprocess.call((action_down + ' ' + sgroup).split())
                                except:
                                    pass
            service_interval = check_interval
            for sgroup in service_groups:
                if service_groups[sgroup] != 0 and service_groups[sgroup] != check_rise:
                    service_interval = check_finterval

            # announce or withdraw addresses based on service groups states
            for address, options in addresses['announce'].items():
                sgroup   = options.get('group', 'default')
                weight   = options.get('weight', 0)
                alwaysup = options.get('alwaysup', False)
                if weight == 'primary':
                    weight = 100
                elif weight == 'secondary':
                    weight = 200
                else:
                    try:
                        weight = int(weight)
                    except:
                        weight = 0
                laddress = peer.get('local', {}).get('address', None)
                nexthop  = peer.get('local', {}).get('nexthop6' if inet6(address) else 'nexthop', 'self')
                if (inet6(laddress) and inet4(address) and (nexthop == 'self' or inet6(nexthop))) or (inet4(laddress) and inet6(address) and (nexthop == 'self' or inet4(nexthop))):
                    continue
                line = 'neighbor %s %s route %s next-hop %s' % (name, 'announce' if (alwaysup or (sgroup in service_groups and service_groups[sgroup] >= check_rise)) else 'withdraw', address, nexthop)
                if weight > 0:
                    line += ' med %d' % weight
                community = str(options.get('community', ''))
                if community != '':
                    line += ' community [ %s ]' % community
                aspath = str(options.get('aspath', ''))
                if aspath != '':
                    line += ' as-path [ %s ]' % aspath
                print(line)
            for address in addresses['withdraw'].iterkeys():
                if not address in addresses['announce']:
                    line = 'neighbor %s withdraw route %s next-hop %s' % (name, address, peer.get('local', {}).get('nexthop6' if inet6(address) else 'nexthop', 'self'))
                    print(line)
            sys.stdout.flush()

else:
    abort('unknown action "%s" - aborting' % sys.argv[2])
