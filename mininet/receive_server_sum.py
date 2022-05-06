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
bucket = "postcard_telemetry"
db_url="http://localhost:8086"

lock = Lock()
num_packets = 0
telemetryPacketLengthInBytes = 28
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


        print("\n%-20s{}\n%-20s{} μs\n%-20s{} μs\n%-20s{} μs\n%-20s{} pkts\n%-20s{} pkts\n%-20s{} pkts\n%-20s{} pkts\n%-20s{} pkts\n%-20s{} pkts\n".format(self.switch_id,
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
            print( '\n\n\n\033[1;32m---- Telemetry Packet: {} ----\033[0m\n'.format(num_packets) )
        utcnow = datetime.utcnow()
        data = pkt[Raw].load
        arrival_delay = int.from_bytes(data[9:15], "big")
        points = []
        for i in range(16):
            n = l*i
            sw_id = '{0}.{1}.{2}.{3}'.format( data[0+n],data[1+n],data[2+n],data[3+n] )
            fl_id = format( int.from_bytes( data[4+n:8+n], "big" ) )
            ttl = data[8+n]
            ingress_tstamp = int.from_bytes(data[9+n:15+n], "big")
            egress_tstamp = int.from_bytes(data[15+n:21+n], "big")
            enq = int.from_bytes(data[21+n:24+n], "big") >> 5
            deq = ( int.from_bytes(data[23+n:25+n], "big") & 0b111111111111111111100) >> 2
            in_port = ( int.from_bytes(data[25+n:27+n], "big") & 0b1111111110 ) >> 1
            ex_port = ( int.from_bytes(data[26+n:28+n], "big") & 0b111111111 )
            latency = egress_tstamp - ingress_tstamp;
            arrival_delay = ingress_tstamp - arrival_delay
            with lock:
                if sw_id not in switch_params:
                    switch_params[sw_id] = SW_Params(sw_id)
                switch_params[sw_id].update_values(latency, enq, deq)
            # with lock:
            #     if (sw_id not in data_store):
            #         data_store[sw_id] = []
            #     data_store[sw_id].append([fl_id,ttl,lc,enq,deq])
            # with lock:
                # print('\n---- Telemetry Packet: {} ----'.format(num_packets),
                #     'sw_id:\t\t' + sw_id[i],
                #     'fl_id:\t\t' + fl_id[i],
                #     'ttl:\t\t{} '.format(ttl[i]),
                #     'in_tst:\t\t{} ms'.format(ingress_tstamp[i]),
                #     'ex_tst:\t\t{} ms'.format(egress_tstamp[i]),
                #     'enq:\t\t{} pkts'.format(enq[i]),
                #     'deq:\t\t{} pkts'.format(deq[i]),
                #     'in_port:\t{} '.format(in_port[i]),
                #     'ex_port:\t{} '.format(ex_port[i]),
                #     'latency:\t{} ms'.format(latency[i]),
                #     '\n', '---- end ----\n', sep='\n')

            points.append({"measurement": "sw_params", "tags": {"host": sw_id},
                                "fields": { "flow_id": fl_id,
                                            "IPv4_TTL": ttl,
                                            "in_tstamp": ingress_tstamp,
                                            "eg_tstamp": egress_tstamp,
                                            "enq_qdepth": enq,
                                            "deq_qdepth": deq,
                                            "in_port": in_port,
                                            "out_port": ex_port,
                                            "latency": latency },
                                "time": datetime.utcnow() + timedelta(microseconds = arrival_delay) })
        write_api.write(bucket, org, points)
            # ii = 0
            # for item in points:
            #     ii += 1
            #     print('\n\033[1;36mPacket: {}\033[0m'.format(ii) )
            #     print(item,'\n')
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
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'enp0s31f6' in i]
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
