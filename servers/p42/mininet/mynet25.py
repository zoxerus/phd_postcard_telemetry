#!/usr/bin/env python3
# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.link import TCLink

from p4_mininet import P4Switch, P4Host


import argparse
from time import sleep

parser = argparse.ArgumentParser(description='Mininet demo')
parser.add_argument('--behavioral-exe', help='Path to behavioral executable',
                    type=str, action="store", default = '../targets/simple_switch/simple_switch')
parser.add_argument('--thrift-port', help='Thrift server port for table updates',
                    type=int, action="store", default=9090)
parser.add_argument('--num-hosts', help='Number of hosts to connect to switch',
                    type=int, action="store", default=2)
parser.add_argument('--mode', choices=['l2', 'l3'], type=str, default='l3')
parser.add_argument('--json', help='Path to JSON config file',
                    type=str, action="store", default = '../../myProjects/myTelemetry/')
parser.add_argument('--pcap-dump', help='Dump packets on interfaces to pcap files',
                    type=str, action="store", required=False, default=False)
parser.add_argument('--debugger', help='Enable Debugger',
                    type=str, action="store", required=False, default=False)
parser.add_argument('--log-level', help="Set log level, vales are:'trace','debug',                      +\
                                    'info', 'warn', 'error', 'off', default is 'info' ",
                                    type = str,action='store', required=False, default='info')
args = parser.parse_args()


class MyTopo(Topo):
    "Single switch connected to n (< 256) hosts."
    def __init__(self, sw_path, json_path, thrift_port, pcap_dump, enable_debugger, n, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)

        s0 = self.addSwitch('s0',
                                sw_path = sw_path,
                                json_path = json_path + 'collector_switch_25/switch.json',
                                thrift_port = 9090,
                                pcap_dump = pcap_dump,
                                enable_debugger = enable_debugger
                                )

        s1 = self.addSwitch('s1',
                                sw_path = sw_path,
                                json_path = json_path + 'network_switch/switch.json',
                                thrift_port = 9091,
                                pcap_dump = pcap_dump,
                                enable_debugger = enable_debugger
                                )
        s2 = self.addSwitch('s2',
                                sw_path = sw_path,
                                json_path = json_path + 'network_switch/switch.json',
                                thrift_port = 9092,
                                pcap_dump = pcap_dump,
                                enable_debugger = enable_debugger
                                )
        s3 = self.addSwitch('s3',
                                sw_path = sw_path,
                                json_path = json_path + 'network_switch/switch.json',
                                thrift_port = 9093,
                                pcap_dump = pcap_dump,
                                enable_debugger = enable_debugger
                                )
        s4 = self.addSwitch('s4',
                                sw_path = sw_path,
                                json_path = json_path + 'network_switch/switch.json',
                                thrift_port = 9094,
                                pcap_dump = pcap_dump,
                                enable_debugger = enable_debugger
                                )

        h0 = self.addHost('h0',
                            ip = "10.0.0.10/24",
                            mac = '00:00:00:00:00:10')

        h1 = self.addHost('h1',
                            ip = "10.0.10.10/24",
                            mac = '00:00:00:10:00:10')
        h11 = self.addHost('h11',
                            ip = '10.0.11.10/24',
                            mac = '00:00:00:11:00:10')
        h4 = self.addHost('h4',
                            ip = "10.0.40.10/24",
                            mac = '00:00:00:40:00:10')
        h41 = self.addHost('h41',
                            ip = "10.0.41.10/24",
                            mac = '00:00:00:41:00:10')

        linkBandwidth = 0.5
        hostBW = 2
        self.addLink(h0, s0, bw = hostBW)
        self.addLink(h1, s1, bw = hostBW)
        self.addLink(s1, s2, bw = linkBandwidth)
        self.addLink(s2, s3, bw = linkBandwidth)
        self.addLink(s3, s4, bw = linkBandwidth)
        self.addLink(s4, h4, bw = hostBW)
        self.addLink(s1, s0, bw = linkBandwidth)
        self.addLink(s2, s0, bw = linkBandwidth)
        self.addLink(s3, s0, bw = linkBandwidth)
        self.addLink(s4, s0, bw = linkBandwidth)
        self.addLink(s1, h11, bw = hostBW)
        self.addLink(s4, h41, bw = hostBW)



def main():
    num_hosts = args.num_hosts
    mode = args.mode

    topo = MyTopo(args.behavioral_exe,
                            args.json,
                            args.thrift_port,
                            args.pcap_dump,
                            args.debugger,
                            num_hosts
                            )
    net = Mininet(topo = topo,
                  host = P4Host,
                  switch = P4Switch,
                  link=TCLink,
                  controller = None)
    net.start()

    h0 = net.get('h0')
    h0.setARP('10.0.0.1', '00:00:00:00:00:01')
    h0.setDefaultRoute("dev eth0 via %s" % '10.0.0.1')
    h0.describe()

    h1 = net.get('h1')
    h1.setARP('10.0.10.1', '00:00:00:10:00:01')
    h1.setDefaultRoute("dev eth0 via %s" % '10.0.10.1')
    h1.describe()

    h11 = net.get('h11')
    h11.setARP('10.0.11.1', '00:00:00:11:00:01')
    h11.setDefaultRoute("dev eth0 via %s" % '10.0.11.1')
    h11.describe()

    h4 = net.get('h4')
    h4.setARP('10.0.40.1', '00:00:00:40:00:01')
    h4.setDefaultRoute("dev eth0 via %s" % '10.0.40.1')
    h4.describe()

    h41 = net.get('h41')
    h41.setARP('10.0.41.1', '00:00:00:41:00:01')
    h41.setDefaultRoute("dev eth0 via %s" % '10.0.41.1')
    h41.describe()

    sleep(1)

    print("Ready !")

    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    main()
