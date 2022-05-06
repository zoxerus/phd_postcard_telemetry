#!/usr/bin/env python3
import sys
import struct
import os

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR



def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface
x = 0
def handle_pkt(pkt):
    global x
    telemetryPacketLengthInBytes = 20
    l = telemetryPacketLengthInBytes
    if UDP in pkt and pkt[UDP].dport == 54321:
        #pkt.show2()
        x = x + 1
        data = pkt[Raw].load
        print('\n---- Telemetry Packet: {0} ----'.format(x) )
        print('Swtich_ID: {0}.{1}.{2}.{3}'.format( data[0],data[1],data[2],data[3] ))
        print('Flow_ID:   {0}.{1}.{2}.{3}'.format( data[4],data[5],data[6],data[7] ))
        print('latency_average: {}'.format( int.from_bytes(data[8:12], 'big') ))
        print('---- end ----\n')
       #hexdump(pkt)
    sys.stdout.flush()


def main():
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    iface = ifaces[0]
    print(("sniffing on %s" % iface))
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
    print('\r Received: {} Packets'.format(x) )

