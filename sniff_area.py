# coding=utf-8
# !/usr/bin/python
##################################################################################
# lmao
import threading
import subprocess
import queue

q = queue.Queue()

import os
from scapy.all import *
from colors import *
import time
import sys

def sniff_area(iface):
        try:
            print '[*] Releasing the croc for packets'
            time.sleep(2)
            i = 1
            
            print fg.pink + '[*] listening for packets'
            time.sleep(1.5)
            while True:
                sniffed = sniff(iface=iface, count=1)
                for pack in sniffed:
                    if pack.haslayer(TCP):
                        print bcolors.OKGREEN + '[+] Detected TCP packets ' + fg.pink, str(
                            pack.getlayer(TCP).info), ' | ', str(pack.getlayer(TCP).addr2)

                    elif pack.haslayer(DNS):
                        print bcolors.OKBLUE + '[+] Detected DNS packets ' + bcolors.OKGREEN, str(
                            pack.getlayer(DNS).info), ' | ', \
                            str(pack.getlayer(DNS).addr2)

                    elif pack.haslayer(Dot11Beacon):
                        print fg.lightred + '[+] Detected 802.11 Beacon' + fg.orange, str(
                            pack.getlayer(Dot11Beacon).info), ' | ', str(pack.getlayer(Dot11Beacon).addr2)

                    elif pack.haslayer(Dot11ProbeReq):
                        print fg.lightcyan + '[+] Detected Probe Request'
                        if pack.info == None or len(str(pack.getlayer(Dot11ProbeReq).info)) == 0:
                            print fg.cyan + 'CLIENT ---> ', str(pack.getlayer(Dot11ProbeReq.addr2))
                        else:
                            print 'SSID ---> ', str(pack.getlayer(Dot11ProbeReq).info), ' --- CLIENT ---> ', str(
                                pack.getlayer(Dot11ProbeReq).addr2)
                    elif pack.haslayer(Dot11):
                        print fg.yellow + '[+] Detected 802.11 Packets'
                        if pack.type == 0 and pack.subtype == 12:
                            print fg.red + bg.black + '[*] Deauth Detected '
                            i = i + 1

        except Exception, e:
            print e
sniff_area('wlan0mon')
