#!/usr/bin/python
import socket
from scapy.all import *
import os


def check_area(iface):
    try:
        raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 3)
        raw_socket.bind((iface, 0x0003))
        ap_list = []
        while True:
            packet = raw_socket.recvfrom(6000)
            sniffed = packet[0]
            if sniffed[26] == '\x80' and sniffed[36:42] not in ap_list:
                s = str(sniffed[36:42].encode('hex')).upper()
                mac = s[0] + s[1] + ':' + s[2] + s[3] + ':' + s[4] + s[5] + ':' + s[6] + s[7] \
                      + ':' + s[8] + s[9] + ':' + s[10] + s[11]
                ap_list.append(sniffed[36:42])
                a = ord(sniffed[63])
                ssid = sniffed[64:64 + a]
                ch = ord(sniffed[64 + a + 12])
                print 'SSID ---> {} --- BSSID ---> {} --- CH ---> {}'.format(ssid, mac, ch)
    except Exception, e:
        print e
        exit(0)





check_area('wlan0mon')