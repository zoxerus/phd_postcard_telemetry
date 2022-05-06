#!/usr/bin/env python3
import sys
import struct
import os

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR

from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

#the_token = os.getenv('INFLUX_TOKEN')
the_token = "IZ_S1koYRGdIChw_HQtWsAgvPnmxuFAewwxl4E9f6ncQqgS1caJ4izFxj-co0CWBU9N3SpIT_IE8i33mobws9A=="
org = "santanna"
bucket = "postcard_telemetry"
db_url="http://localhost:8086"


def handle_pkt_on_thread(pkt,write_api):
    t = Thread(target=handle_pkt, args=(pkt,write_api))
    t.start()

num_packets = 0
def handle_pkt(pkt,write_api):
    global num_packets
    telemetryPacketLengthInBytes = 20
    l = telemetryPacketLengthInBytes
    if UDP in pkt and pkt[UDP].dport == 54321:
        num_packets += 1
        data = pkt[Raw].load
        for i in range(1):
            n = l*i
            sw_id = '{0}.{1}.{2}.{3}'.format( data[0+n],data[1+n],data[2+n],data[3+n] )
            fl_id = format( int.from_bytes( data[4+n:8+n], "big" ) )
            mn_lc = int.from_bytes(data[8+n:12+n], "big")
            mx_lc = int.from_bytes(data[12+n:16+n], "big")
            vg_lc = int.from_bytes(data[16+n:20+n], "big")
            print('\n---- Telemetry Packet: {0} ----'.format(num_packets),
            'sw_id:\t\t' + sw_id,
            'fl_id:\t\t' + fl_id,
            'mn_lc:\t\t{} ms'.format(mn_lc),
            'mx_lc:\t\t{} ms'.format(mx_lc),
            'vg_lc:\t\t{} ms'.format(vg_lc),
            'sm_of:\t\t{} pkts'.format(data[20]),
            '\n', '---- end ----\n', sep='\n')
            point = [{"measurement": "latency", "tags": {"host": sw_id},
                                "fields": { "min": mn_lc,
                                            "max": mx_lc,
                                            "avg": vg_lc },
                                "time": datetime.utcnow()}]
            write_api.write(bucket, org, point)
    sys.stdout.flush()

def main(write_api):
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'enp0s31f6' in i]
    iface = ifaces[0]
    print(("sniffing on %s" % iface))
    sys.stdout.flush()
    sniff(iface = iface,
        prn = lambda x: handle_pkt_on_thread(x,write_api))

if __name__ == '__main__':
    client = InfluxDBClient(url=db_url, token=the_token, org=org)
    write_api = client.write_api(write_options=SYNCHRONOUS)
    main(write_api)
    client.close()
    print('\r Received: {} Packets'.format(x) )
