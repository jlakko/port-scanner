# Found on GitHub: https://github.com/jlakko/port-scanner

import argparse

from include import my_scan, parse

# define arguments using argparse
flags = argparse.ArgumentParser(description='Port scanner.')
flags.add_argument('-hn', '--hostname', nargs=1, type=str, help="Hostname to be scanned.")
flags.add_argument('-ip', '--ip', nargs=1, type=str, help="IP(s) to be scanned.")
flags.add_argument('-p', '--port', nargs=1, type=str, help="Port(s) to be scanned.")
flags.add_argument('-t', '--tcp', action="store_true", default=False, help="Will scan hosts and ports via TCP. This is default if no flags are specified.")
flags.add_argument('-u', '--udp', action="store_true", default=False, help="Will scan hosts and ports via UDP.")
flags.add_argument('-i', '--icmp', action="store_true", default=False, help="Will scan hosts via ICMP.")
flags.add_argument('-T', '--traceroute', action="store_true", default=False, help="Will perform a traceroute on specified hosts.")
args = flags.parse_args()

# check for bad input
if args.hostname is None and args.ip is None:
    flags.error("Please specifiy a target using -ip or -hn flags.")
if args.port is None and not (args.icmp or args.traceroute):
    flags.error("Port scans require the -p or --ports flag.")

# check for flag values
if args.tcp:
    print("--- Initizing TCP scan ---")
    my_scan.tcp_scan(parse.ip(args.ip[0]),parse.port(args.port[0]))
if args.udp:
    print("--- Initizing UDP scan ---")
    print("NEEDS IMPLEMENTED")
if args.icmp:
    print("--- Initizing ICMP scan ---")
    my_scan.icmp_scan(parse.ip(args.ip[0]))
if args.traceroute:
    print("--- Initizing Traceroute ---")
    print("NEEDS IMPLEMENTED")

# run a tcp scan if no flags were specified
if not (args.tcp or args.udp or args.icmp or args.traceroute):
    print("--- Initizing TCP scan ---")
    if args.hostname is None:
        my_scan.tcp_scan(parse.ip(args.ip[0]),parse.port(args.port[0]))
    else:
        my_scan.tcp_scan(args.hostname[0],parse.port(args.port[0]))


