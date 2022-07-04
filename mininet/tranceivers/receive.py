#!/usr/bin/env python3
import sys
import struct
import os

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR


pkt_in = 0
def handle_pkt(pkt):
    global pkt_in
    if UDP in pkt and pkt[UDP].dport == 12345:
        pkt_in = pkt_in + 1
        print('Packet in: {}'.format(pkt_in))
        print("-------------- New Packet --------------")
        pkt.show2()
        # data = pkt[Raw].load
        # print('\n---- Telemetry Packet ----')
        # print('sw_id: {0}.{1}.{2}.{3}'.format(data[0],data[1],data[2],data[3] ) )
        # print('latency: {}'.format(int.from_bytes(data[4:10],'little') ))
        print('-------------- end --------------\n')
    #    hexdump(pkt)

    sys.stdout.flush()


def main():
    # ifaces = [i for i in os.listdir('/sys/class/net/') if 'enp1s0f0' in i]
    # iface = ifaces[0]
    iface = sys.argv[1]
    print(("sniffing on %s" % iface))
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
