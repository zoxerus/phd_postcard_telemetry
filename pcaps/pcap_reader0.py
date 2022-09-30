import argparse
import os
import sys
import time
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.all import IP, TCP, UDP, Raw
from datetime import datetime, timedelta
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS
from threading import Thread, Lock

from packet_headers import IPFIX_Header, IPFIX_Set, IPFIX_Record

clear = lambda: os.system('clear')

the_token = "XGXw0gU2vhezI3nOMJk9Jr9NtYZhlxgArlxzzUT6hCpfMHDaWvDlS2NQLDD"      \
                "AwkOUTVWWzlZ2e5xVhINpXscMTw=="
org = "santanna"
bucket = "postcard_summary"
db_url="http://localhost:8086"

lock = Lock()

num_packets = 0
telemetryPacketLengthInBytes = 39
l = telemetryPacketLengthInBytes

data_store = {}
switch_params = {}
epoch_times = []

class SW_Params():
    switch_id: str = None
    num_packets = 0

    latency_sum = 0
    deq_sum = 0
    enq_sum = 0

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
        self.latency_sum = self.latency_sum + new_latency
        self.deq_sum = self.deq_sum + new_deq
        self.enq_sum = self.enq_sum + new_enq

        self.num_packets += 1

        self.latency_average = (self.latency_sum)//self.num_packets
        self.deq_average = (self.deq_sum)//self.num_packets
        self.enq_average = (self.enq_sum)//self.num_packets

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


        # print("\n%-25s{}\n%-25s{} μs\n%-25s{} μs\n%-25s{} μs\n%-25s{} "        \
        #         "pkts\n%-25s{} pkts\n%-25s{} pkts\n%-25s{} pkts\n%-25s{} "     \
        #         "pkts\n%-25s{} pkts\n".format(self.switch_id,
        #                                      self.latency_average,
        #                                      self.latency_min, self.latency_max,
        #                                      self.enq_average, self.enq_min,
        #                                      self.enq_max, self.deq_average,
        #                                      self.deq_min, self.deq_max) %     \
        #                                      ('SW_ID:',
        #                                         'latency_average:',
        #                                         'latency_min:', 'latency_max:',
        #                                         'enq_average:', 'enq_min:',
        #                                         'enq_max:', 'deq_average:',
        #                                         'deq_min:', 'deq_max:' ) )


def process_pcap(file_name, write_api):
    global num_packets
    global epoch_times

    for run in range (10):
        start_time = time.time()
        for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
            pkt = Ether(pkt_data)
            num_packets = num_packets + 1
            data = pkt[Raw].load
            points = []

            ipfix_version =  int.from_bytes(data[0:2], 'big')
            ipfix_length =  int.from_bytes(data[2:4], 'big')
            ipfix_exportTime = int.from_bytes(data[4:8], 'big')
            ipfix_sequenceNumber = int.from_bytes(data[8:12], 'big')
            ipfix_observationDomain = '{0}.{1}.{2}.{3}'.format(data[12],
                                                               data[13],
                                                               data[14],
                                                               data[15])

            ipfix_setID = int.from_bytes(data[16:18], 'big')
            ipfix_setLength = int.from_bytes(data[18:20], 'big')


            points = []
            ipfix_version =  int.from_bytes(data[0:2], 'big')
            ipfix_length =  int.from_bytes(data[2:4], 'big')
            ipfix_exportTime = int.from_bytes(data[4:8], 'big')
            ipfix_sequenceNumber = int.from_bytes(data[8:12], 'big')
            ipfix_observationDomain = '{0}.{1}.{2}.{3}'.format(data[12],
                                                               data[13],
                                                               data[14],
                                                               data[15])

            ipfix_setID = data[16:18].hex()
            ipfix_setLength = int.from_bytes(data[18:20], 'big')

            collector_id = '{0}.{1}.{2}.{3}'.format(data[20], data[21],
                                                    data[22], data[23])
            flow_id = int.from_bytes( data[24:28], 'big' )
            ttl = data[28]
            latency_min = int.from_bytes(data[29:35], 'big')
            latency_max = int.from_bytes(data[35:41], 'big')
            latency_average = int.from_bytes(data[41:47], 'big')
            enq_min = int.from_bytes(data[47:50], 'big')
            enq_max =  int.from_bytes(data[50:53], 'big')
            enq_avg =  int.from_bytes(data[53:56], 'big')

            deq_min = int.from_bytes(data[56:59], 'big')
            deq_max = int.from_bytes(data[59:62], 'big')
            deq_avg = int.from_bytes(data[62:65], 'big')

                #
                # point = {"measurement": "sw_params",
                #          "tags": {"host": sw_id},
                #                     "fields": { "flow_id": flow_id,
                #                                 "IPv4_TTL": ttl,
                #                                 "in_tstamp": str(ingress_tstamp),
                #                                 "eg_tstamp": str(egress_tstamp),
                #                                 "enq_qdepth": enq_qdepth,
                #                                 "deq_qdepth": deq_qdepth,
                #                                 "in_port": ingress_interface,
                #                                 "out_port": egress_interface,
                #                                 "latency": latency },
                #          "time": ingress_tstamp }
                #
                # write_api.write(bucket, org, point)

            point = {
                "measurement": "ipfix_summary",
                "tags": {"host": ipfix_observationDomain},
                "fields": { "flow_id": flow_id,
                            "collector_id": collector_id,
                            "latency_min": latency_min,
                            "latency_max": latency_max,
                            "latency_average": latency_average,
                            "deq_min": deq_min,
                            "deq_max": deq_max,
                            "deq_avg": deq_avg,
                            "enq_min": enq_min,
                            "enq_max": enq_max,
                            "enq_avg": enq_avg
                            },
                "time": datetime.utcnow() }
            write_api.write(bucket, org, point)
        epoch_time = time.time() - start_time
        print("epoch: {}, done in {} seconds".format(
                                         (run +1), epoch_time ))
        epoch_times.append(epoch_time)
    epoch_sums = 0
    for epoch in epoch_times:
            epoch_sums = epoch_sums + epoch
    print("average execution time: {} seconds".format(
                                                epoch_sums/len(epoch_times)))



            # with lock:
            #     print('\n---- Telemetry Packet: {} ----'.format(i),
            #         '%-25s{}'.format(ipfix_version) % ('ipfix_version:'),
            #         '%-25s{}'.format(ipfix_length) % ('ipfix_length:'),
            #         '%-25s{}'.format(ipfix_exportTime) % ('ipfix_exportTime:'),
            #         '%-25s{}'.format(ipfix_sequenceNumber) %
            #             ('ipfix_sequenceNumber:'),
            #         '%-25s{}'.format(ipfix_observationDomain) %
            #             ('ipfix_observationDomain:'),
            #         '%-25s{}'.format(ipfix_setID) % ('ipfix_setID:'),
            #         '%-25s{}'.format(ipfix_setLength) % ('ipfix_setLength:'),
            #         '%-25s{}'.format(flow_id) % ('flow_id:'),
            #         '%-25s{}'.format(ttl) % ('ttl:'),
            #         '%-25s{} μs'.format(ingress_tstamp) % ('ingress_tstamp:'),
            #         '%-25s{} μs'.format(egress_tstamp) % ('egress_tstamp:'),
            #         '%-25s{} packets'.format(enq_qdepth) % ('enq_qdepth:'),
            #         '%-25s{} packets'.format(deq_qdepth) % ('deq_qdepth:'),
            #         '%-25s{} '.format(ingress_interface) % (
            #                                               'ingress_interface:'),
            #         '%-25s{} '.format(egress_interface) % (
            #                                                'egress_interface:'),
            #         '%-25s{}'.format(export_time) % ('export_time:'),
            #         '%-25s{}'.format(sw_id) % ('sw_id:'),
            #         '%-25s{}'.format(seq_num) % ('seq_num:'),
            #
            #         '\n', '---- end ----\n', sep='\n')


def process_pcap_on_thread(file_name, write_api):
    t = Thread(target=process_pcap, args=(file_name, write_api))
    t.start()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap', metavar='<pcap file name>',
                        help='pcap file to parse', required=True)
    args = parser.parse_args()

    file_name = args.pcap
    if not os.path.isfile(file_name):
        print('"{}" does not exist'.format(file_name), file=sys.stderr)
        sys.exit(-1)

    client = InfluxDBClient(url=db_url, token=the_token, org=org)
    write_api = client.write_api(write_options=SYNCHRONOUS)
    process_pcap_on_thread(file_name, write_api)
    #  client.close()
    # print('\r Received: {} Packets'.format(num_packets) )
    sys.exit(0)
