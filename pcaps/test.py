import argparse
import os
import sys
from scapy.utils import RawPcapReader
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP

file_name = './ag16fx.pcap'
if not os.path.isfile(file_name):
    print('"{}" does not exist'.format(file_name), file=sys.stderr)
    sys.exit(-1)

process_pcap(file_name)
