from scapy.all import *


def letsdoit():
    lolo = []
    deep = []
    while True:

        sniffed = sniff(iface='wlan0mon', count=1)
        for pack in sniffed:
            if pack.haslayer(Dot11):
                if pack.addr2 not in lolo:
                    print 'SSID ---> {}  --- BSSID ---> {}'.format(pack.info, pack.addr2)
                    lolo.append(pack.addr2)
                    full_name = str(pack.info) + str(pack.addr2)
                    nibba = pack.info + '/' + pack.addr2
                    deep.append(str(nibba))
        for name_for_list in deep:
            name = name_for_list.split(':')[0]
            xmac = name_for_list.split(':')[1]
            name = {name:xmac}
            print name['shko']

letsdoit()
