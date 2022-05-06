#!/usr/bin/env python3
import argparse
import sys
import socket
import random
import struct
import time

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP

"""
usage: sudo python3 ./send.py [args]
arg1: Message
arg2: source port
arg3: destination address
arg4: destination port
arg5: number of packets to send
arg6: transmission interval
"""



def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def main():
    addr = socket.gethostbyname(sys.argv[3])
    iface = get_if()
    print(("sending on interface %s to %s" % (iface, str(addr))))
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt /IP(dst=addr, tos =0) / UDP(dport=int(sys.argv[4]) , sport= int(sys.argv[2]) ) / sys.argv[1]
    #pkt.show2()
    for i in range(int(sys.argv[5] )):
        sendp(pkt, iface=iface, verbose=False)
        time.sleep(float(sys.argv[6]))
        print("\rSent {0} Packets".format(i+1),end = "")
    print("")


if __name__ == '__main__':
    main()
