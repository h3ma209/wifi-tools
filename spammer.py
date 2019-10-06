from scapy.all import *
import threading
import queue
from colors import *
import sys

q = queue.Queue()
names = ['dugi', 'fugi', 'Dinasour', 'shugi']


def spam_area(name):
    bc = bcolors

    mac = str(RandMAC())
    print bc.OKBLUE + '[+] Setting up a fake access point\n' + bc.END
    head = Dot11(subtype=8, type=0, addr1='ff:ff:ff:ff:ff:ff', addr2=mac, addr3=mac)
    info = Dot11Beacon(cap='ESS+privacy')
    share_it = Dot11Elt(ID='SSID', info=name, len=len(str(name)))
    all_ = RadioTap() / head / info / share_it
    print bc.OKGREEN + bc.UNDERLINE + '[+] {} started\n'.format(name), bc.END
    sendp(all_, verbose=False, iface='daddy', loop=1)


def create_worker():
    for threads in range(len(names)):
        t = threading.Thread(target=work, args=())
        t.daemon = True
        t.start()


dont_rep = []


def work():
    workers = q.get()
    for i in range(workers+1):
        for rand_name in names:
            if rand_name not in dont_rep:
                dont_rep.append(rand_name)
                spam_area(str(rand_name))

    q.task_done()


def create_jobs():
    for nums in range(len(names)):
        q.put(nums)
    q.join()


def main():
    create_worker()
    create_jobs()


if __name__ == '__main__':
    try:
        spam_area('dugi')
    except Exception, e:
        print e
        exit(0)
    except KeyboardInterrupt:
        sys.exit(1)
