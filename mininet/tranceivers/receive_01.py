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
        for i in range(1):
            pkt.show2()
            break
            n = l*i
            print('ver:\t\t{}'.format( (data[0+n] >> 4) ) )
            print('len:\t\t{}'.format(( data[0+n] & 0b00001111) ))
            print('nproto:\t\t{}'.format( ( data[1+n] >> 5) ))
            print('rep_md_bits:\t{}'.format(  (int.from_bytes(data[1+n:3+n],byteorder = "big") & 0b0001111110000000 ) >> 7 ))
            print('d:\t\t{}'.format( ( data[2+n] & 0b01000000 ) >> 6 ))
            print('q:\t\t{}'.format( ( data[2+n] & 0b00100000 ) >> 5) )
            print('f:\t\t{}'.format( ( data[2+n] & 0b00010000 ) >> 4 ))
            print('rsvd:\t\t{}'.format( ( (int.from_bytes(data[2+n:4+n],byteorder = "big") & 0b0000111111000000 ) >> 6) ) )
            print('hw_id:\t\t{}'.format(  data[3+n] & 0b00111111  ) )
            print('sw_id:\t\t{0}.{1}.{2}.{3}'.format( data[4+n],data[5+n],data[6+n],data[7+n] ) )
            print('seq_no:\t\t{}'.format( int.from_bytes( data[8+n:12+n], "big" ) ) )
            print('ingress_tstamp:\t{}'.format(  int.from_bytes(data[12+n:16+n],"big") ) )
            print('egress_tstamp:\t{}'.format(  int.from_bytes(data[16+n:20+n],"big") ) )
            print('\n')
        print('---- end ----\n')
       #hexdump(pkt)
    sys.stdout.flush()


def main():
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth100' in i]
    iface = ifaces[0]
    print(("sniffing on %s" % iface))
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
    print('\r Received: {} Packets'.format(x) )
