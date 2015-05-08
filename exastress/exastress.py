#!/usr/bin/env python
"""
example: exastress.py --peer-ip 10.140.0.1 --local-cidr 10.140.10.0/24 --local-interface eth0 --announce-cidr 10.141.10.0/24 --sessions 250
"""
import sys, os
from argparse import ArgumentParser
from ipaddr import IPAddress, IPNetwork

# parse command-line options
argparser = ArgumentParser(description='BGP stack stress-test utility')
argparser.add_argument('--peer-ip', metavar='ADDRESS', required=True, dest='peer_ip', help='BGP peer address (no default)')
argparser.add_argument('--peer-as', metavar='ASNUM', dest='peer_as', default='65500', help='BGP peer AS number (default: 65500)')
argparser.add_argument('--local-cidr', metavar='CIDR', required=True, dest='local_cidr', help='BGP sessions source addresses block (no default)')
argparser.add_argument('--local-as', metavar='ASNUM', dest='local_as', default='65501', help='BGP local AS number (default: 65501)')
argparser.add_argument('--local-interface', metavar='INTERFACE', dest='local_interface', help='local interface used for BGP sessions source addresses (default: none)')
argparser.add_argument('--announce-cidr', metavar='CIDR', dest='announce_cidr', help='BGP /32 announces block (default: none)')
argparser.add_argument('--sessions', metavar='COUNT', dest='sessions', default=1, help='number of BGP sessions to establish (default: 1)')
args = argparser.parse_args()

# validate command-line options
try:
    peer_ip = IPAddress(args.peer_ip)
except:
    print 'invalid peer address "%s" - aborting' % args.peer_ip
    sys.exit(1)
try:
    local_cidr = IPNetwork(args.local_cidr)
except:
    print 'invalid local addresses block "%s" - aborting' % args.local_cidr
    sys.exit(1)
if args.announce_cidr:
    try:
        announce_cidr = IPNetwork(args.announce_cidr)
        announce_cidr = announce_cidr.iterhosts()
    except:
        print 'invalid announce addresses block %s - aborting' % args.announce_cidr
        sys.exit(1)

# create ExaBGP configuration + setup address aliases if required
configuration = 'group peers {\n'
sessions      = 0
for address in local_cidr.iterhosts():
    configuration += ('  neighbor %s {\n'
                      '    router-id %s;\n'
                      '    local-address %s;\n'
                      '    local-as %s;\n'
                      '    peer-as %s;\n'
                      '    family {\n'
                      '      inet4 unicast;\n'
                      '    }\n') % (peer_ip, address, address, args.local_as, args.peer_as)
    if args.announce_cidr:
        try:
            configuration += ('    static {\n'
                              '      route %s/32 {\n'
                              '        next-hop %s;\n'
                              '      }\n'
                              '    }\n') % (announce_cidr.next(), address)
        except:
            pass
    configuration +=  '  }\n'
    if args.local_interface:
        os.system('ifconfig %s:%s %s netmask %s up 2>/dev/null' % (args.local_interface, IPAddress(address).__hex__()[2:], address, local_cidr.netmask))
    sessions += 1
    if sessions >= int(args.sessions):
        break
configuration += '}\n'

# start ExaBGP with temporary configuration
path   = 'exabgp-%d.conf' % os.getpid()
handle = open(path, 'w')
handle.write(configuration);
handle.close()
os.system('exabgp %s' % path);
os.remove(path)

# remove address aliases if required
if args.local_interface:
    sessions  = 0
    for address in local_cidr.iterhosts():
        os.system('ifconfig %s:%s down 2>/dev/null' % (args.local_interface, IPAddress(address).__hex__()[2:]))
        sessions += 1
        if sessions >= int(args.sessions):
            break
