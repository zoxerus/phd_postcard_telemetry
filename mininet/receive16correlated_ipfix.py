#!/usr/bin/env python3
import sys
import struct
import os
import time

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR

from datetime import datetime, timedelta
import os
from threading import Thread, Lock
from queue import Queue

from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

clear = lambda: os.system('clear')

#the_token = os.getenv('INFLUX_TOKEN')
the_token = "IZ_S1koYRGdIChw_HQtWsAgvPnmxuFAewwxl4E9f6ncQqgS1caJ4izFxj-co0CWBU9N3SpIT_IE8i33mobws9A=="
org = "santanna"
bucket = "postcard_sum"
db_url="http://localhost:8086"

lock = Lock()
num_packets = 0
telemetryPacketLengthInBytes = 41
l = telemetryPacketLengthInBytes
data_store = {}
switch_params = {}
class SW_Params():
    switch_id: str = None
    num_packets = 0

    latency_average = 0
    latency_max = 0
    latency_min = sys.maxsize

    enq_average = 0
    enq_max = 0
    enq_min = sys.maxsize

    deq_min = sys.maxsize
    deq_max = 0
    deq_average = 0

    def __init__(self,id):
        self.switch_id = id

    def update_values(self, new_latency, new_enq, new_deq):
        latency_sum = self.latency_average * self.num_packets
        deq_sum = self.deq_average * self.num_packets
        enq_sum = self.enq_average * self.num_packets

        self.num_packets += 1
        self.latency_average = (latency_sum + new_latency)//self.num_packets
        self.deq_average = (deq_sum + new_deq)//self.num_packets
        self.enq_average = (enq_sum + new_enq)//self.num_packets

        if (new_latency < self.latency_min):
            self.latency_min = new_latency
        if (new_latency > self.latency_max):
            self.latency_max = new_latency

        if (new_enq > self.enq_max):
            self.enq_max = new_enq
        if (new_enq < self.enq_min):
            self.enq_min = new_enq

        if (new_deq < self.deq_min):
            self.deq_min = new_deq
        if (new_deq > self.deq_max):
            self.deq_max = new_deq


        print("\n%-25s{}\n%-25s{} μs\n%-25s{} μs\n%-25s{} μs\n%-25s{} pkts\n%-25s{} pkts\n%-25s{} pkts\n%-25s{} pkts\n%-25s{} pkts\n%-25s{} pkts\n".format(self.switch_id,
                                                self.latency_average, self.latency_min, self.latency_max,
                                                self.enq_average, self.enq_min, self.enq_max,
                                                self.deq_average, self.deq_min, self.deq_max) % ('SW_ID:',
                                                'latency_average:', 'latency_min:', 'latency_max:',
                                                'enq_average:', 'enq_min:', 'enq_max:',
                                                'deq_average:', 'deq_min:', 'deq_max:' ) )

def handle_pkt_on_thread(pkt,write_api):
    t = Thread(target=handle_pkt, args=(pkt,write_api))
    t.start()


def handle_pkt(pkt,write_api):
    global num_packets
    global switch_params
    if UDP in pkt and pkt[UDP].dport == 54321:
        with lock:
            num_packets += 1
            print('\n\n\n\033[1;32m---- Telemetry Packet: {} ----\033[0m\n'.format(num_packets) )
        utcnow = datetime.utcnow()
        data = pkt[Raw].load
        arrival_delay = int.from_bytes(data[9:15], 'big')
        points = []
        for i in range(1):
            n = l*i
            ipfix_version =  int.from_bytes(data[0:2], 'big')
            ipfix_length =  int.from_bytes(data[2:4], 'big')
            ipfix_exportTime = int.from_bytes(data[4:8], 'big')
            ipfix_sequenceNumber = int.from_bytes(data[8:12], 'big')
            ipfix_observationDomain = '{0}.{1}.{2}.{3}'.format(data[12+n],
                                                               data[13+n],
                                                               data[14+n],
                                                               data[15+n])

            ipfix_setID = data[16:18].hex()
            ipfix_setLength = int.from_bytes(data[18:20], 'big')

            collector_id = '{0}.{1}.{2}.{3}'.format(data[20+n],data[21+n],data[22+n],data[23+n] )
            flow_id = int.from_bytes( data[24+n:28+n], 'big' )
            ttl = data[28]
            latency_min = int.from_bytes(data[29+n:35+n], 'big')
            latency_max = int.from_bytes(data[35+n:41+n], 'big')
            latency_average = int.from_bytes(data[41+n:47+n], 'big')
            enq_min = int.from_bytes(data[47+n:50+n], 'big')
            enq_max =  int.from_bytes(data[50+n:53+n], 'big')
            enq_avg =  int.from_bytes(data[53+n:56+n], 'big')

            deq_min = int.from_bytes(data[56+n:59+n], 'big')
            deq_max = int.from_bytes(data[59+n:62+n], 'big')
            deq_avg = int.from_bytes(data[62+n:65+n], 'big')

            # with lock:
            #     if sw_id not in switch_params:
            #         switch_params[sw_id] = SW_Params(sw_id)
            #     switch_params[sw_id].update_values(latency, enq, deq)
            with lock:
                print('\n---- Telemetry Packet: {} ----'.format(num_packets),
                    '%-25s{}'.format(ipfix_version) % ('ipfix_version:'),
                    '%-25s{}'.format(ipfix_length) % ('ipfix_length:'),
                    '%-25s{}'.format(ipfix_exportTime) % ('ipfix_exportTime:'),
                    '%-25s{}'.format(ipfix_sequenceNumber) %
                        ('ipfix_sequenceNumber:'),
                    '%-25s{}'.format(ipfix_observationDomain) %
                        ('ipfix_observationDomain:'),
                    '%-25s{}'.format(ipfix_setID) % ('ipfix_setID:'),
                    '%-25s{}'.format(ipfix_setLength) % ('ipfix_setLength:'),
                    '%-25s{}'.format(collector_id) % ('collector_id:'),
                    '%-25s{}'.format(flow_id) % ('flow_id:'),
                    '%-25s{}'.format(ttl) % ('ttl:'),
                    '%-25s{} μs'.format(latency_min) % ('latency_min:'),
                    '%-25s{} μs'.format(latency_max) % ('latency_max:'),
                    '%-25s{} μs'.format(latency_average) % ('latency_average:'),
                    '%-25s{} packets'.format(enq_min) % ('enq_min:'),
                    '%-25s{} packets'.format(enq_max) % ('enq_max:'),
                    '%-25s{} packets'.format(enq_avg) % ('enq_avg:'),
                    '%-25s{} packets'.format(deq_min) % ('deq_min:'),
                    '%-25s{} packets'.format(deq_max) % ('deq_max:'),
                    '%-25s{} packets'.format(deq_avg) % ('deq_avg:'),
                    '\n', '---- end ----\n', sep='\n')

    sys.stdout.flush()

def correlate_on_thread():
    global data_store
    while(True):
        clear()
        print("linstening ...")
        with lock:
            for key in data_store:
                sm_lc = 0
                mx_lc = 0
                mn_lc = 99999
                item_count = 0
                for item in data_store[key]:
                    sm_lc += item[2]
                    if (item[2] > mx_lc):
                        mx_lc = item[2]
                    if (item[2] < mn_lc):
                        mn_lc = item[2]
                    item_count += 1
                print('sw_id: {0},\t\tmn_lc: {1},\tvg_lc: {2},\tmx_lc: {3}'.format(key,mn_lc,sm_lc//item_count,mx_lc))
        print("updated at {}".format( datetime.utcnow() ))
        time.sleep(10)



def main(write_api):
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'enxd45d64626aa4' in i]
    iface = ifaces[0]
    print(("sniffing on %s" % iface))
    sys.stdout.flush()
    # corr_thread = Thread(target=correlate_on_thread)
    # corr_thread.start()
    sniff(iface = iface,
        prn = lambda x: handle_pkt(x,write_api))
    print('sniffin started')


if __name__ == '__main__':
    clear()
    client = InfluxDBClient(url=db_url, token=the_token, org=org)
    write_api = client.write_api(write_options=SYNCHRONOUS)
    main(write_api)
    client.close()
    print('\r Received: {} Packets'.format(num_packets) )
